---
tags:
  - IT/网络
---


## 名称解析顺序

以浏览器举例，输入URL后，名称解析的顺序如下：

1. 本地hosts文件
2. OS的DNS缓存
	- Windows的叫做DNSClient。可用 `ipconfig /displaydns` 查看
3. 指定的DNS服务器的缓存【当有配置DNS后缀/加入域时，会将DNS后缀组合hostname去找DNS】
4. [[LLMNR]]和[[NetBIOS#137/UDP|NBNS]]【没有配置DNS后缀时，就用NBNS解析名称】
5. 递归解析




## Zone file

> https://en.wikipedia.org/wiki/Zone_file

> see also [Microsoft DNS](https://en.wikipedia.org/wiki/Microsoft_DNS "Microsoft DNS") with [Active Directory](https://en.wikipedia.org/wiki/Active_Directory "Active Directory")-database integration.


### File format


指令：以 `$` 开头 + 一个关键字。（一共有3个？）

- `$ORIGIN`：指示域名。一般在第一行。`@`也指代`$ORIGIN`
- `$TTL`：指定默认TTL。


[Resource records](https://en.wikipedia.org/wiki/Domain_Name_System#Resource_records) (RR) 的字段格式（两种都可，就是TTL位置变了）：

|  1   |      2       |      3       |      4      |      5      |
| :--: | :----------: | :----------: | :---------: | :---------: |
| name |     ttl      | record class | record type | record data |
| name | record class |     ttl      | record type | record data |

- 分隔符、结束符：

> fields separated by any combination of white space (tabs and spaces), and ends at a line boundary except inside a quoted string field value or a pair of enclosing formatting parentheses.

- name：可以留空，此时继承上一条RR的name。也可以用`@`指代`$ORIGIN`。

---

利用：[[DNS#域传输]]



## DNS记录（record type）

- SOA：start of authority record
- CNAME：别名
- PTR：Pointer，域名反查
- MX：Mail Exchange
- TXT：text
- SRV：服务（指定服务的服务器）
- RP：负责人
- HINFO：host信息



### SOA

在域文件RR的第一行，其他RR的顺序随意。

- 指示主要权威DNS，也可以用于列出 DNS 缓存的内容。
- 还包含负责管理DNS的人员的电子邮件地址（表示为域名，因为带有句号字符代替通常的@符号）
- 还指定计时和过期参数列表（序列号、从属刷新周期、从属重试时间、从属过期时间以及缓存记录的最大时间）。


### CNAME


### PTR


### MX

邮件交换记录，域名和邮件服务器的映射（找对应域里的邮件主机）。  

- `用户名@域名` → `用户名@邮件SVR的主机名.域名`
- 由于域名不代表特定主机，所以要查询DNS里的MX记录，通过域名对应邮件服务器，再找邮件SVR的A记录——即ip

例如：  
当Internet上的某用户要发一封信给 user@mydomain.com 时，  
该用户的邮件系统通过DNS查找 `mydomain.com` 这个域名的MX记录，如果MX记录存在，得到邮件SVR的host名（`mail.mydomain.com`），  
然后DNS根据host名查A记录找到IP，送信OK。


当SMTP服务器接收到不属于自己域的邮件地址时，将邮件转发给其他SMTP服务器。  
而如何决定去哪个SMTP服务器 → 查询DNS的MX记录。

关于优先级：MX 记录有一个优先编号（preference number），告诉 SMTP 客户端按顺序尝试（并重试）列表中的每个相关地址，直到投递尝试成功。 偏号小的优先级高。(在许多情况下，邮件服务器记录配置为相同的值，以确保邮件均匀地流向每个服务器)





### TXT

一般指某个主机名或域名的说明，或者联系方式，或者标注提醒等等。

不过有应用于[[Email安全]]。


### SRV

> an example of an SRV record response:  
> `_ldap._tcp.example.com. 86400 IN SRV 0 5 389 ldap-server.example.com.`  
> In this example, the service is "_ldap" using the TCP protocol, with a priority of 0, a weight of 5, and a port of 389. The target host is "ldap-server.example.com".






## DNS攻击


### 域传输

副DNS向主DNS发送 `AXFR`(Asynchronous Full Zone Transfer) 的请求。主DNS返回[[DNS#SOA|SOA]]。

```bash
# 如果成功，可能会暴露 HTTP server names
target_domain='mysite.test'
target_ip='10.10.100.44'
host -T -l $target_domain $target_ip

# 如果失败，可手动枚举
gobuster dns -r $target_ip -d $target_domain -w $dns_wordlist -t 100
```




### DNS污染（联系Pharming）

利用条件：

1. 对目标DNS请求其未注册的域名
	- 以前：可以将cache的TTL设置很长以防御
	- 后来：Kaminsky's attack使上述防御失效
2. 向目标DNS对上级DNS发请求时的源端口发送响应——一般都是53
3. 目标DNS对上级DNS发送请求与收到响应时的transactionID（DNS请求的一位标识符）需要一致——ID长度为16bit（最大65535），所以可以枚举
4. 比合法DNS更早返回响应

另外：入侵（客户端/服务器）后更改hosts文件


### DoS

过去有过事件。不过都是因为漏洞，所以更新打补丁就解决了。

### DNS反射/增幅（DNS amp）


### 随机子域攻击、Water Torture（水責め）

对目标域名发送大量随机子域，让其权威DNS过载


### DNS隧道



### DNS cache snooping




## 工具



### dig (Domain Information Groper)

- `dig tryhackme.com @1.1.1.1`

能从域名的官方DNS查到权威解答，而nslookup是从cache中得到的非权威解答。（?）

- 要获取电子邮件记录，请指定`-t MX`：`dig <target> -t MX`
- 要获得区[[DNS#域传输|域传输]]，请指定 `axfr`：`dig axfr @nsztm1.digi.ninja zonetransfer.me`。
	- **`@nsztm1.digi.ninja`**：这是指定的 DNS 服务器地址，`@` 后面的部分表示要向 `nsztm1.digi.ninja` 这个 DNS 服务器发送查询请求。
	- **`zonetransfer.me`**：这是要查询的域名，也就是请求的 DNS 区域。`zonetransfer.me` 是一个用于演示区域传输风险的域名。

### nslookup命令

- Professional Toolset ([https://tools.dnsstuff.com](https://tools.dnsstuff.com))
- DNS Records ([https://network-tools.com](https://network-tools.com))

DNS历史解析： [https://www.kancloud.cn/noahs/src_hacker/2120650](https://www.kancloud.cn/noahs/src_hacker/2120650)

### DNS域名反查（IP2Domain）

> [[tool-links#have IP/Domain]]

目标是虚拟主机时很有用，虚拟主机有不同域名，但往往共用一个IP。  
找到哪些网站共用这台服务器，就可通过该服务器上的其他网站的漏洞进行渗透——旁注。

- [www.ip-adress.com/reverse_ip/](http://www.ip-adress.com/reverse_ip/)
- 【工具网】 [https://www.yougetsignal.com](https://www.yougetsignal.com) （Reverse IP Domain Check）
- DNSRecon命令：`dnsrecon -r 162.241.216.0-162.241.216.255`
	- -r: range







## DNS服务器配置

### BIND

> Berkeley Internet Name Domain

> [如何在局域网中搭建LINUX服务器版本的DNS服务](https://mp.weixin.qq.com/s?__biz=MzUxNzg5MzM2Mg==&mid=2247485306&idx=1&sn=3e66fa7b52e63c3840723a08ef98bb45)

