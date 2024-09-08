---
tags:
  - 渗透/武器库
  - 渗透/信息收集
---


### 概要
![xmind](../static/img/MindMap/nmap_outline.png){ width='720' }

### 详细
![xmind](../static/img/MindMap/nmap.png)


## REF

- [Ignitetechnologies - Nmap for Pentester](https://github.com/Ignitetechnologies/Nmap-For-Pentester)




## NSE

脚本位置：`/usr/share/nmap/scripts/`


## SMB

### 确认是否需要SMB签名

```
nmap -p 445 --script smb-security-mode,smb2-security-mode taget
```
- 需要签名：message_signing显示required
- 不需要：message_signing显示显示disabled或supported



## NFS

-p 111,2049 nfs-ls.nse




查看扫描了哪些默认端口
- `-oG -`将 grepable 格式输出到 stdout。
```shell-session
TimeLess613@htb[/htb]$ nmap -v -oG -

# Nmap 7.80 scan initiated Wed Dec 16 23:22:26 2020 as: nmap -v -oG -

# Ports scanned: TCP(1000;1,3-4,6-7,9,13,17,19-26,30, ... ,65389) UDP(0;) SCTP(0;) PROTOCOLS(0;)

WARNING: No targets were specified, so 0 hosts scanned.

# Nmap done at Wed Dec 16 23:22:26 2020 -- 0 IP addresses (0 hosts up) scanned in 0.04 seconds
```


## LDAP

[[LDAP#RootDSE]]