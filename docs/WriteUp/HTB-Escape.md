**Waiting for machine retire...**

*Difficulty: Medium*

第一次打Windows的靶机……也是边打边学了。

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

有DNS、Kerberos、LDAP，应该是个域控？  
域名疑似这个：sequel.htb0（后确认为“sequel.htb”）

感觉可以参考这个[APT靶机](./HTB-APT.md)。先看看445和135有什么信息。  
然后有1433的SQL，打进去之后可能可以枚举LDAP？


## 445端口




## 135端口



## Initial Access

### 记住：获得有效凭据就尝试横向移动

回顾了一下[APT靶机的过程](./HTB-APT.md#_3)，到底是怎么get shell的……

### evil-winrm使用域凭据get shell


## flag: user

```bash
└─$ evil-winrm -i ${HTB_IP} -u Ryan.Cooper -p Nu…………o3

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                                                                                 

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> whoami
sequel\ryan.cooper


*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> cat user.txt
de9e……cb29
```


## Privilege Escalation

### CA模板漏洞


## flag: root

```
└─$ evil-winrm -i ${HTB_IP} -u Administrator -H A52F…………F4EE

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                                                                                 

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
sequel\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         6/4/2023   4:49 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
9384……db0c
```

---

## 总结·后记

2023/06/04

挺有意思的，这次该好好总结一下了。Certify之后都是跟着github照葫芦画瓢，要好好琢磨一下各个地方的知识点。

首先是关于总体流程，RPC的优先度其实不该这么高。  
SMB → MSSQL，捕获NTLMv2，由于是msf模块所以不太清楚具体细节，不过看手动也有用`xp_dirtree`强制NTLM认证的样子。  
因为不熟悉MSSQL，进行了大量无意义的枚举。还总想着是否要登陆进去，结果登进去也没什么意义。早在hacktricks的最开头就写着关于获取Net-NTLM的信息了，不过因为想着不太可能破解NTLMv2所以就放置到最后才处理这步了。还是经验太少。

破解后获得域凭据 → 由于是域凭据所以尝试初始连接，根据以前APT的笔记，有很多工具，不过这次都是使用`Evil-WinRM`。

然后就是横向移动，感觉没什么技术含量，就略过吧。其实至今不明白为什么会想到组合err log里的两个username报错。是期待用户误操作将密码当用户名输入？

最后的提权算是我印象中域渗透的精华部分了。首先自己该有枚举什么信息的思路，当思路走到`Certify`时，将会发现CA模板漏洞，这个也是前阵子接触到的一个概念。将是我接下来需要好好琢磨的地方。  
特别是“Getting credentials using U2U”这里的U2U十分陌生。 