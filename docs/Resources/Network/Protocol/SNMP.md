---
tags:
  - IT/网络
  - 渗透/信息收集
  - 渗透/CPTS
  - 渗透/CEH
---
161/UDP

![[Pasted image 20240618231614.png]]

> In SNMP versions 1 and 2c, access is controlled using a plaintext community string, and if we know the name, we can gain access to it. 
> Encryption and authentication were only added in SNMP version 3.

> [!NOTE] Community（不是密码）似乎是相当于域的东西，在这个域范围内共享信息
> 默认值：
> - public：read用
> - private：读写用



![[Pasted image 20240618231736.png]]



## 工具

### snmpwalk
```shell-session
snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0
```
- 这里的`public`即Community



### [onesixtyone](https://github.com/trailofbits/onesixtyone)
```shell-session
onesixtyone -c dict.txt 10.129.42.254
```



## MIB

> IBM知识中心： [https://www.ibm.com/docs/en/aix/7.3?topic=management-information-base](https://www.ibm.com/docs/en/aix/7.3?topic=management-information-base)


### MIB类别

- DHCP.MIB：监控DHCP服务器和远程主机之间的网络流量
- HOSTMIB.MIB：存储有关管理和监视资源的信息
- LMMIB2.MIB：存储工作站和服务器服务数据
- MIB_II.MIB：存储有关主机上 TCP/IP 的信息
- WINS.MIB：对于 Windows Internet 名称服务 (WINS)


## 参考

https://milestone-of-se.nesuke.com/sv-basic/system-monitoring/snmp-summary/