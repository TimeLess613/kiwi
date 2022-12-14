Waiting for machine retire...

---

## 扫描


## 漏洞分析

### 80端口


#### 子域枚举



## foothold
原来是NoSQL...

[MD5解码网站](../links.md#编码)

## get user flag
[Unix bin命令提权查询](https://gtfobins.github.io/)




## 提权






## get root flag



---

## 后记

原来是NoSQL...

说是多了个横向移动吧，其实和之前靶机比，从foothold开始获得的用户数量又没差。  
大概是因为这次是web打点时用了一个账户，后来用的又是两个普通用户的账户而没有应用账户吧。

以及以前一直觉得既然SSH能成功登陆，就已经知道自己登陆的是什么用户，那么 `id` 命令没啥意义。  
这次随手一打竟然能发现deploy用户属于docker组，从而发现突破口，也属实是运气了……


最后，  
联系[这个思路](../GatheringInformation/summary.md#web_info_gathering)，感觉信息搜集可以弄一个简易脚本。以后试试直接用这个：

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