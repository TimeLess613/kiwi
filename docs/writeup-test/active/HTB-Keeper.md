

> 没写完。。。。


## Summary

*`OS: Linux` `Difficulty: Easy`*

xxx

### Relevant Skills

- nmap
- 子域枚举
- sudo提权
- ……

### Attack Path Overview

![attack-path](./../attackpath/HTB-template.png){ width='450' }


## External Recon - nmap

自用扫描脚本：[工作流](https://github.com/TimeLess613/workflow-scan4HTB/blob/main/workflow-scan4HTB.sh)  
`curl -s https://raw.githubusercontent.com/TimeLess613/workflow-scan4HTB/main/workflow-scan4HTB.sh | sudo bash 10.10.11.229`

开放端口：
```
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
55555/tcp open  unknown
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