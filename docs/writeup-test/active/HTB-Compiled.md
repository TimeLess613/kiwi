---
tags:
  - HTB/Medium
  - HTB/Windows
---
## Summary

...

### Relevant Skills

- nmap
- git
- GIT RCE (CVE-2024-32002)
- ……

### Attack Path Overview

![attack-path](./../attackpath/HTB-template.png){ width='500' }


## External Recon - nmap

自用扫描脚本：[工作流](https://github.com/TimeLess613/workflow-scan4HTB/blob/main/workflow-scan4HTB.sh)  
`curl -s https://raw.githubusercontent.com/TimeLess613/workflow-scan4HTB/main/workflow-scan4HTB.sh | sudo bash -s <HTB-IP>`

开放端口：
```
PORT     STATE SERVICE    VERSION
3000/tcp open  ppp?
5000/tcp open  upnp?
5985/tcp open  http       Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
7680/tcp open  pando-pub?
```

## 攻击路径规划·漏洞分析

常规简单靶机，22端口SSH的版本较新，优先度放低。先看80端口的Web。


## 3000端口

- robots.txt：无
- .git/config：无
- 网页信息：无特别发现
- 网页源码：无特别发现
- 网页功能：xxxx
- 子域枚举：无域名/无特别发现
- 目录枚举：`gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.10.11.8:5000/`，无特别发现

### 研究网页功能

### 子域：

## 5000端口



## Initial Access

### PoC (CVE-2024-32002)

谷歌一波`git exploit`或`git rce`，可以发现这个仓库以及其中提到的文章：

- https://github.com/amalmurali47/git_rce
- https://amalmurali.me/posts/git-rce/


## flag: user




## Privilege Escalation

### Internal Recon

基础信息收集一把梭：

- IP、端口
- 用户家目录的隐藏文件：无
- `sudo -l`：没有sudo可执行
- SUID：无特别发现
- cron：`crontab -l`，`ls /etc/cron*`，无特别发现

### PoC (CVE-yyyy-xxxx)







## flag: root


---

## 总结·后记

YYYY/MM/DD

……