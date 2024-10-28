---
tags:
  - IT/网络
  - 渗透/信息收集
---

## type&code

- 各Type的code0即该Type的主要类型，若有详细分类，则从1开始编号——即理解为：0是根目录
- type0 code0：echo响应
- type8 code0：echo请求

- type3 code0：目标网络不可达
	- code1：目标主机不可达
	- code2：协议不可达
	- code3：port不可达（即关闭）【UDP扫描返回这个则说明端口关闭】
	- code9：
	- code10：
	- code13：表示无法路由数据包，因为它在管理上被禁止（防火墙或路由器 ACL）。探测FW用（不过似乎需要FW配置好了才会显示）

- type4 code0：网络拥堵（限制发送）
- type11 code0：TTL超过



## nmap中利用的type

![[Pasted image 20240328001258.png]]


## port0

#渗透/CPTS 

> Port 0 is a reserved port in TCP/IP networking and is not used in TCP or UDP messages. If anything attempts to bind to port 0 (such as a service), it will bind to the next available port above port 1,024 because port 0 is treated as a "wild card" port.