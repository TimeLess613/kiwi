---
tags:
  - HTB/Easy
  - HTB/Linux
  - HTB/Medium
  - HTB/Windows
---

# Write Up 模板

（模板更新：2024/08/16）

- 基本上HTB的机器（可能只是Esay机器）都会使用这个WP模板。
- 可能我对WP这个词的理解有偏差，更应该说是我自己的打靶、学习笔记，所以会记录许多踩坑与思路等废话。
- [MetaTwo](./../retired/HTB-MetaTwo.md)之前WP模板并未成形，所以语言、格式上会略有不同。以后可能也会不断改善这个模板的不足之处。
- 对于仍在Active的机器，如果发布的话，都会在WP开头写上 **Waiting for machine retire...**，表示这边暂时不会给出详细WP。不过会列一些提示。等机器退役后，会更新出详细WP。


## （个人整理用）关于WP的图片处理步骤

1. 先直接粘贴图片
2. 更改图片名称
3. 将图片移动到`evidence-img/`
4. 更改WP中的图片链接名为新图片名称——Obsidian会自动链接，但是要注意将WP移动到mkdocs后链接是否需要加上`./../evidence-img/`前缀。

## 下面是WP模板：：


## Summary

...

### Relevant Skills

- nmap
- 子域枚举
- sudo提权
- ……

### Attack Path Overview

![attack-path](./../attackpath/HTB-template.png){ width='500' }


## External Recon - nmap

自用扫描脚本：[工作流](https://github.com/TimeLess613/workflow-scan4HTB/blob/main/workflow-scan4HTB.sh)  
`curl -s https://raw.githubusercontent.com/TimeLess613/workflow-scan4HTB/main/workflow-scan4HTB.sh | sudo bash -s <HTB-MachineName> <HTB_IP>`

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
- 网页源码：无特别发现
- 网页功能：xxxx
- 子域枚举：无域名/无特别发现
- 目录枚举：`gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.10.11.8:5000/`，无特别发现

### 研究网页功能

### 子域：

## xx端口



## Initial Access

### PoC (CVE-yyyy-xxxx)


## flag: user




## Privilege Escalation

### Internal Recon

基础信息收集一把梭：

- IP、端口
- 用户家目录的隐藏文件：无
- 环境变量：`env`
- `sudo -l`：没有sudo可执行
- SUID：无特别发现
- 可写文件：`find /etc -writable -ls 2>/dev/null`
- cron：`crontab -l`，`ls /etc/cron*`，无特别发现
- 其他目录：
	- `/interesting_folder`
	- `/var/www/interesting_folder`
	- `/var/mail/user_name`
	- `/opt/interesting_folder`
	- `/usr/local/interesting_folder`
	- `/usr/local/bin/interesting_folder`
	- `/usr/local/share/interesting_folder`
	- `/etc/hosts`
	- `/tmp`
	- `/mnt`
	- `/media`
	- `/etc`

### PoC (CVE-yyyy-xxxx)







## flag: root


---

## 总结·后记

2024/MM/DD

……