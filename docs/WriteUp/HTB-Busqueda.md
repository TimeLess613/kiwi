**Waiting for machine retire...**

*Difficulty: Easy*

---

## 扫描

常规22、80端口

## 漏洞分析

### 80端口

IP无法访问，需要写hosts文件。域名即浏览器自动替换的那个。或者可以 `curl -I <IP>` 看报头的 `Location` 字段。

- Powered by Flask and Searchor 2.4.0


## Initial Access

### PoC (CVE-yyyy-xxxx)



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


#### 发现密码和子域


### 密码重复 - SSH


### sudo探索


#### 利用sudo获得敏感信息

### gitea登陆administrator

## Privilege Escalation

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



### workflow-scan

稍微改一下扫描的工作流

```bash title="nmapscan_workflow.sh"
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

echo "[info] ==============================================="

echo "[info] Checking if there is domain for add to hosts..."
HEADER_Location=$(curl -I ${HTB_IP} | grep -q "Location:" || true)

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
