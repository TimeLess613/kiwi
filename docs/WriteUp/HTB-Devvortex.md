**Waiting for machine retire...**

---

## Summary

*`OS: Linux` `Difficulty: Easy`*


### Relevant Skills

- nmap
- 子域枚举
- CVE
- LINUX Signals

### Attack Path Overview

![attack-path](./AttackPath/HTB-template.png){ width='450' }


## External Recon - nmap

自用扫描脚本：[工作流](https://github.com/TimeLess613/workflow-scan4HTB/blob/main/workflow-scan4HTB.sh)  
`curl -s https://raw.githubusercontent.com/TimeLess613/workflow-scan4HTB/main/workflow-scan4HTB.sh | sudo bash -s <HTB-IP>`

开放端口：
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```


## 攻击路径规划·漏洞分析

常规简单靶机，22端口SSH优先度放低。先看80端口的Web。


## 80端口

常规扫描时发现子域，估计主战场在那边。

### 子域：dev.devvortex.htb

- robots.txt：发现一些有用的目录
- .git/config：无
- 网页信息：无特别发现
- 网页源码：无特别发现
- 网页功能：无特别发现
- 目录枚举：除上述外无特别发现

### 子域各目录

除了administrator其他目录直接访问都是一篇空白。而administrator是一个joomla的登陆界面。

![HTB-Devvortex-joomla](./evidence-img/HTB-Devvortex-joomla.png){ width='600' }

本来以为有弱凭据，搜了一下默认凭据只有说账号为admin，而密码是部署时设定的。  
简单尝试SQLi走不通。

### joomla版本

搜索“joomla exploit”，根据[hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla#version)的方法可以发现此Joomla的版本为“4.2.6”。  


## Initial Access

继续搜索“joomla 4.2.6 exploit”可发现此文章：<https://vulncheck.com/blog/joomla-for-rce>

### PoC (CVE-2023-23752)

```bash
www-data@devvortex:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```


## flag: user

```bash
www-data@devvortex:/$ su logan
Password: 
logan@devvortex:/$ id
uid=1000(logan) gid=1000(logan) groups=1000(logan)
logan@devvortex:/$ cd
logan@devvortex:~$ ls
user.txt
logan@devvortex:~$ cat user.txt 
d0a5 (...) acf4
```


## Privilege Escalation

有密码先直接看看 `sudo -l`，有一条命令，很有可能这就是突破口：
```bash
logan@devvortex:~$ sudo -l
[sudo] password for logan: 
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```

可以查看版本：
```bash
logan@devvortex:~$ /usr/bin/apport-cli -v
2.20.11
```

实践发现谷歌比 `searchsploit` 好用多了啊……“apport-cli 2.20.11 exploit”搜一波发现下面文章：
> <https://nvd.nist.gov/vuln/detail/CVE-2023-1326>  
> <https://github.com/canonical/apport/commit/e5f78cc89f1f5888b6a56b785dddcb0364c48ecb>

### PoC (CVE-2023-1326)

github提交中写了PoC，帮大忙了。那么问题就是如何生成crash文件呢？

查看[apport的文档](https://github.com/canonical/apport)可发现，当收到“SIGSEGV”等信号时可

> It currently supports  
> - Crashes from standard signals (SIGSEGV, SIGILL, etc.) through the kernel coredump handler (in piping mode)

```bash
 (...)
!id
uid=0(root) gid=0(root) groups=0(root)
!done  (press RETURN)
```


## flag: root

```bash
 (...)
!cat /root/root.txt
768c (...) 2781
!done  (press RETURN)
```


---

## 总结·后记

2023/11/28

