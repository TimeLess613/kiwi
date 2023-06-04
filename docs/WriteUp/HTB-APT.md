*此靶机并非自己所打，这篇WP只是看[红队笔记的靶机实操](https://www.bilibili.com/video/BV1FR4y1r7Do)做的一点笔记。*

---

## 漏洞分析

### 80端口 

唯一一个动态功能POST连接不上web后端。源码发现这个网页就是那个web后端的镜像。搜一波镜像工具没发现利用。

### 135端口（提供web服务时是593）

- 一般RPC协议上会跑DCOM服务，以解决基于网络的互操作，各组件/方法以UUID识别。
- `rpcclient`（默认连接端口139而不是135，所以要指定）
- ([impacket](https://www.secureauth.com/labs/open-source-tools/impacket/)) `rpcdump.py`（可以直接把impacket路径加入PATH：`export PATH=/usr/share/doc/python3-impacket/examples:$PATH`）
- ([impacket](https://www.secureauth.com/labs/open-source-tools/impacket/)) `rpcmap.py`：rpcdump后不知道各组件是干嘛的——暴破/映射UUID的信息。找到对应方法能枚举出（哪里的？）网卡ip——IPv6——再次nmap扫端口

### 445 

- `smbclient` 下载backup.zip
- `unzip -l file` 列出，里面有ntds和注册表
- （`updatedb` 更新locate命令数据库）


## 补充一点端口知识

### 47001端口 winrm  
    如果部署了winrm就会有47001；  
    如果设置完成就有5985 wsman；  
    如果加了ssl就有5986。  

### 49152～ 动态端口。不太看


## 域渗透固定思路

1. `(impacket) secretdump.py -ntds ntds.dit -system register/SYSTEM LOCAL`（可在线也可本地转储）【？查一下为什么需要注册表信息？】
1. 由于5985 wsman是开放的，有了hash可直接用 `evil-winrm` 尝试高权限用户的pth（注意hash格式，因为第一段可能是空的LMhash）。其他很具体的普通人名账户估计都是低权限
1. 备份文件的时效性低，不知道当前时间点哪些账户有用——hash碰撞（因为不同密码生成的hash有可能相同）
    - 而由于用户太多，直接碰撞的话计算量太大——用户筛选，看看哪个用户有效（如靶机本来2000用户→3用户）——**预认证机制**——用 `kerbrute` 或者nmap脚本 `krb5-enum-users`（后者快很多）
    筛选完用户后，去碰撞本来的2000个hash
    - `crackmapexec` 多次尝试后被ban 【？但是其实应该首先尝试ntds里有效用户对应的hash？】
    - `getTGT.py` 【？getTGT认证错误次数过多的话不知道会不会也会被ban？】
        - （`watch` 命令，此处用于监视getTGT保存到本地的有效用户信息）
1. 找到一个有效用户（该用户能获取TGT即说明该账户&hash的组合是对的）
1. 回到 `evil-winrm` 尝试连接（**有hash了就尝试横向移动**）
1. 不行再试试其他横向移动工具——`psexec`，`wmiexec`，`dcomexec`，impacket里的`各种exec` 【有微妙的区别。留坑，以及以后实验看看日志区别】
1. 用户无权限执行各种exec的话，`reg.py` (即Windows的reg.exe)收集注册表信息。 **渗透中HKU根键及software等较常被利用（都因为这里通常保存用户/应用凭据相关的信息）**


## get shell

拿到明文密码，尝试 `evil-winrm (-p)`


## 提权

### 搜集敏感文件

一个挺聪明的方法：看文件包含是利用的什么文件。清单资源：[Auto_Wordlists](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_windows.txt)

发现powershell历史命令将NTLM改成了v1（易破解）。

### Responder

> [内网渗透之Responder攻防（上）](https://www.freebuf.com/articles/network/256844.html)

开启Responder，然后根据[LOLBAS](https://lolbas-project.github.io/)在目标机利用Windows Defender的 `MpCmdRun.exe` 访问kali的IP【？应该也能用powershell？实验看看生成的日志区别】，捕获ntlmv1（APT$用户）

*Responder可以监听多个端口，使用多个协议，所以不一定需要投毒、名字解析才能捕获hash。对于直接访问IP，走HTTP、用SMB的UNC路径等都是可以捕获的*

`ntlmv1-multi`（或 `hashcat` 等） 破解得到hash——《**怎么去使用**》

- 再用 `evil-winrm`，可以，但做的事估计和之前没什么区别。
- 除了想到用各种横向移动工具获得更多资产之外，我们还要想到能否通过APT$账户做更高权限的事、拿到整个系统权限。如：之前只拿到了备份的用户&hash，能否拿到目前的用户库呢。

所以:  
`secretdump.py`（事实上，这个工具的功能是和DC同步）  
成功获取最新用户&hash（里面有admin账户，前文说的获取整个系统权限即这个）
