---
tags:
  - HTB/Linux
  - HTB/Easy
---
> 没写完。。。。
## Summary

...
### Relevant Skills

- nmap
- 子域枚举
- sudo提权
- ……

### Attack Path Overview

![attack-path](./../attackpath/HTB-template.png){ width='450' }


## External Recon - nmap

自用扫描脚本：[工作流](https://github.com/TimeLess613/workflow-scan4HTB/blob/main/workflow-scan4HTB.sh)  
`curl -s https://raw.githubusercontent.com/TimeLess613/workflow-scan4HTB/main/workflow-scan4HTB.sh | sudo bash -s 10.10.11.230`

开放端口：
```
PORT      STATE SERVICE VERSION
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
```

## 攻击路径规划·漏洞分析

常规简单靶机，22端口SSH的版本较新，优先度放低。先看80端口的Web。


## 80端口

- robots.txt：无
- .git/config：无
- 网页信息：无特别发现
- 网页功能：xxxx
- 网页源码：无特别发现
- 子域枚举：无特别发现
- 目录枚举：无特别发现

### 研究网页功能

### 子域：

## xx端口



## Initial Access

### PoC (CVE-yyyy-xxxx)


## flag: user




## Privilege Escalation

### Internal Recon

基础信息收集一把梭：

- 用户家目录的隐藏文件：无
- 有当前用户的凭据所以先看了眼 `sudo -l`：没有sudo可执行
- SUID：无特别发现
- cron：有个php引人注目，不过内容是清理会话。也无其他特别发现

### PoC (CVE-yyyy-xxxx)







## flag: root


---

## 总结·后记

YYYY/MM/DD
……