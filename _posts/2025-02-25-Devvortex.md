---
title: "Devvortex"
date: 25-02-2025
categories: [Linux, Easy]
tags: [Easy, CVE, Joomla]
---

I found this machine fun. It is pretty easy if you are able to enumerate the website properly. The main website does not have anything interesting but the **dev** subdomain has Joomla 4.2.6 running which has a major information disclosure vulnerability.

![Devvortex Info Card](images/devvortex.png)
## Enumeration 

Running **nmap** on all ports gives me just two open ports, 22 and 80. The website tries to redirect us to **devvortex.htb** after addding the domain to **/etc/hosts** we can access the page.  
```java
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
```

The website does not have anything that really sticks out. It is just a static page with a contact form. Using **ffuf** to find subdomains. AFter finding the **dev** domain, a quick look at the source code I see that the page has **Joomla**. Running **gobuster** gives me the following directories most of them being redirects. 
```java
modules                 Status: 301, Size: 178, Words: 6, Lines: 8 
administrator           Status: 301, Size: 178, Words: 6, Lines: 8 
cache                   Status: 301, Size: 178, Words: 6, Lines: 8 
images                  Status: 301, Size: 178, Words: 6, Lines: 8 
language                Status: 301, Size: 178, Words: 6, Lines: 8 
includes                Status: 301, Size: 178, Words: 6, Lines: 8 
templates               Status: 301, Size: 178, Words: 6, Lines: 8 
libraries               Status: 301, Size: 178, Words: 6, Lines: 8 
tmp                     Status: 301, Size: 178, Words: 6, Lines: 8 
media                   Status: 301, Size: 178, Words: 6, Lines: 8 
components              Status: 301, Size: 178, Words: 6, Lines: 8 
plugins                 Status: 301, Size: 178, Words: 6, Lines: 8 
api                     Status: 301, Size: 178, Words: 6, Lines: 8 
home                    Status: 200, Size: 23221, Words: 5081, Lines: 502 
layouts                 Status: 301, Size: 178, Words: 6, Lines: 8 
                        Status: 200, Size: 23221, Words: 5081, Lines: 502 
```
The most intersting directory is the **/administrator** portal which lets us sign in into Joomla. Using the default credentials  **admin:admin** does not work. I tried running some login bruteforcing in the background while enumerating some more. Running **joomscan** on the site shows that the Joomla version in use is 4.2.6. I find an exploit for this version which is an unauthenticated information disclosure vulnerability [CVE-2023-23752](https://vulncheck.com/blog/joomla-for-rce). Using this exploit I was able to find two users registerd in Joomla, Lewis and Logan. I also found some emails and the password for the database. 

```
Database info
DB type: mysqli
DB host: localhost
DB user: lewis
DB password: P4ntherg0t1n5r3c0n##
DB name: joomla
DB prefix: sd4fg_
DB encryption 0
```

## Shell Access

Using the database password I was able to login to Joomla as lewis who is a superuser. From here it is very easy to get a reverse shell I only had to edit the default template **cassiopeia**, changing **error.php** to [this](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) reverse php shell and doing a curl to the location of the php file I was able to get a shell as **www-data**. There is only one other user in this box other than root that being Logan. Logan was also registerd in Joomla thefore his information must also be in the Joomla database.

Since we already have the database password and the usernames I was able to access it. The user's table had the usernames and their passwords.
```
lewsi:$2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u
logan:$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12
```

Using hashcat in mode 3200 I was able to crack logan's password which lets me login into his account with the following credentials.
 `logan:tequieromucho`


## Privilege Escalation

Logan is allowed to run `/usr/bin/apport-cli` as root without password it has a version of 2.20 but its vulnerable to [CVE-2023-1326](https://github.com/diego-tella/CVE-2023-1326-PoC). We can view a crash report and then execute bash as root within the pager.