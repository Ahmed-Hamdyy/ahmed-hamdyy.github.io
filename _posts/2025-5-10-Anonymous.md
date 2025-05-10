---
title: Anonymous Writeup || Tryhackme
date: 2025-5-10 00:00:00 +0800
categories: [Tryhackme]
tags: [tryhackme, writeup, walkthrough, ftp, smb, script]     # TAG names should always be lowercase
description: This is a walkthrough for Anonymous room a medium level room on Tryhackme.
---

### Scanning

Let's Start with scanning our target

```
PORT    STATE SERVICE     REASON         VERSION
21/tcp  open  ftp         syn-ack ttl 63 vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts [NSE: writeable]
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.21.105.110
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp  open  ssh         syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8b:ca:21:62:1c:2b:23:fa:6b:c6:1f:a8:13:fe:1c:68 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDCi47ePYjDctfwgAphABwT1jpPkKajXoLvf3bb/zvpvDvXwWKnm6nZuzL2HA1veSQa90ydSSpg8S+B8SLpkFycv7iSy2/Jmf7qY+8oQxWThH1fwBMIO5g/TTtRRta6IPoKaMCle8hnp5pSP5D4saCpSW3E5rKd8qj3oAj6S8TWgE9cBNJbMRtVu1+sKjUy/7ymikcPGAjRSSaFDroF9fmGDQtd61oU5waKqurhZpre70UfOkZGWt6954rwbXthTeEjf+4J5+gIPDLcKzVO7BxkuJgTqk4lE9ZU/5INBXGpgI5r4mZknbEPJKS47XaOvkqm9QWveoOSQgkqdhIPjnhD
|   256 95:89:a4:12:e2:e6:ab:90:5d:45:19:ff:41:5f:74:ce (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPjHnAlR7sBuoSM2X5sATLllsFrcUNpTS87qXzhMD99aGGzyOlnWmjHGNmm34cWSzOohxhoK2fv9NWwcIQ5A/ng=
|   256 e1:2a:96:a4:ea:8f:68:8f:cc:74:b8:f0:28:72:70:cd (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDHIuFL9AdcmaAIY7u+aJil1covB44FA632BSQ7sUqap
139/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
```

We can see that there are two ports that we need to see the ftp and the smb.

let's start with the smb, we will list the shares on our smb server

![img-description](/assets/img/Anonymous/smbListing.png)
_Shares_

We will see a share called pics so let's see it's contents

![img-description](/assets/img/Anonymous/PicsShare.png)
_pics Share_

There are two images i downloaded them and tried to see if there is any hidden files or information but i could't find anything so i think we will not get anything from the smb

### Ftp Enumeration

We will head to the ftp server now i also tried **anonymous** as the username and password and i got access to the server so let's start discovering the contents.

There is a directory called Scripts which contains three scripts in it i will download them to see their contents

![img-description](/assets/img/Anonymous/ftp.png)
_Ftp access_

Upon seeing the scripts the first one **clean.sh** is a script which clean the files in the /tmp directory and then Appends a message to the log file indicating the date and time of the file removal, along with the path of the removed file.

We can see that in the two files and the third file contain a note that he need to disable the anonymous login so i think here is our entry point.

![img-description](/assets/img/Anonymous/Scripts.png)
_Scripts contents_

### Gaining Access

From the shell script logic we can deduce that may be there is a cron job to make this script run automatically and also we can see from the previous image for the ftp listing that we have write access to this script.

So why not putting a reverse shell into this script and wait for the script to run to get access, Let's try this out.

First go to this website [revshells](https://www.revshells.com/) for generating reverse shell to use it.

![img-description](/assets/img/Anonymous/revshell.png)
_Reverse Shell_

Edit the entries with your ip and port and then take this command and let's put it in the **"clean.sh"** script, and you should now have something that looks like this.

![img-description](/assets/img/Anonymous/editing.png)
_Script Editing_

Now connect to the ftp in the same directory that you have the edited the script at and then go to the scripts directory make sure that the script is still with the same name and then use this command to replace the script in the server with the edited one you have 

```
put clean.sh 
```

Open a listener and let's wait for the script to be executed, and voila we are in now.

![img-description](/assets/img/Anonymous/user.png)
_User access_

### Privilege Escalation

Let's see how can we get root access now, i will start with checking the files which have the SUID bit set using this command, SUID files run with the owner's privileges (often root!) instead of your user's.

```
find / -type f -perm -4000 -o -perm -6000 2>/dev/null
```

![img-description](/assets/img/Anonymous/suid.png)
_SUID_

you will find that **/usr/bin/env** is in our list which i think is an important one so let's head to [GTFOBins](https://gtfobins.github.io/#%20+suid) and search for env

![img-description](/assets/img/Anonymous/gtfo.png)
_GTFO_

we will find that it do exists in the list, now all we need is to execute the command highlighted in the image to gain root access so let's try it

![img-description](/assets/img/Anonymous/root.png)
_Root Flag_

We got our root access and we can now access the root flag.