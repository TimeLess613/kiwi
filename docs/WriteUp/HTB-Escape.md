**Waiting for machine retire...**

*Difficulty: Medium*

---

## 扫描

由于是Windows机器且是Medium，姑且扫一下全端口吧

```bash
└─$ export HTB_IP=10.10.11.202
└─$ sudo nmap -n -Pn -sS -p- --min-rate=10000 ${HTB_IP} | tee ${HTB_IP}_ports_all.nmap
└─$ export ports=$(cat "${HTB_IP}_ports_all.nmap" | grep ^[0-9] | cut -d / -f1 | tr '\n' ',' | sed s/,$//)
└─$ echo $ports
53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49687,49688,49705,49709,52722

└─$ sudo nmap -v -n -Pn -sV -O -p ${ports} ${HTB_IP} | tee "${HTB_IP}_baseScan.nmap"
……
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-06-01 09:36:12Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49687/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49688/tcp open  msrpc         Microsoft Windows RPC
49705/tcp open  msrpc         Microsoft Windows RPC
49709/tcp open  msrpc         Microsoft Windows RPC
52722/tcp open  msrpc         Microsoft Windows RPC

└─$ sudo nmap -n -Pn -sU --top-ports 20 ${HTB_IP} | tee "${HTB_IP}_ports_udp_top20.nmap"
PORT      STATE         SERVICE
53/udp    open          domain
67/udp    open|filtered dhcps
68/udp    open|filtered dhcpc
69/udp    open|filtered tftp
123/udp   open          ntp
135/udp   open|filtered msrpc
137/udp   open|filtered netbios-ns
138/udp   open|filtered netbios-dgm
139/udp   open|filtered netbios-ssn
161/udp   open|filtered snmp
162/udp   open|filtered snmptrap
445/udp   open|filtered microsoft-ds
500/udp   open|filtered isakmp
514/udp   open|filtered syslog
520/udp   open|filtered route
631/udp   open|filtered ipp
1434/udp  open|filtered ms-sql-m
1900/udp  open|filtered upnp
4500/udp  open|filtered nat-t-ike
49152/udp open|filtered unknown
```


## 端口分析、攻击路径规划

有Kerberos、LDAP感觉是个域控？

感觉可以参考这个[APT靶机](./HTB-APT.md)。先看看445和135有什么信息。


## 445端口




## 135端口



## Initial Access

### PoC (CVE-yyyy-xxxx)


## flag: user



## 探索



## Privilege Escalation

### PoC (CVE-yyyy-xxxx)


## flag: root


---

## 总结·后记

YYYY/MM/DD
……