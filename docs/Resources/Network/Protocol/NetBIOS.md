---
tags:
  - IT/网络
  - 渗透/内网
  - 渗透/信息收集
---


## 137/UDP

- NetBIOS Name Service
- NBNS：NetBIOS名称服务
- 或NBT-NS：NetBIOS over TCP

NetBIOS就是用NBNS解析名称（抓包看似乎NBNS也有用mDNS（组播DNS））


## 138/UDP

- NBND
- NetBIOS Datagram


## 139/TCP

- NBSS
- NetBIOS Session Service

- 和[[SMB]]不同。是一个单独的会话层协议/服务
- 而NBT（NetBIOSoverTPC），139/TCP是向后兼容的。所以一般才139和445都扫。

> Port 139: This port is used for NetBIOS. NetBIOS is an acronym for Network Basic Input/Output System.  
> It provides services related to the session layer of the OSI model allowing applications on separate computers to communicate over a local area network. As strictly an API, NetBIOS is not a networking protocol. Older operating systems ran NetBIOS over IEEE 802.2 and IPX/SPX using the NetBIOS Frames (NBF) and NetBIOS over IPX/SPX (NBX) protocols, respectively.  
> In modern networks, NetBIOS normally runs over TCP/IP via the NetBIOS over TCP/IP (NBT) protocol. This results in each computer in the network having both an IP address and a NetBIOS name corresponding to a (possibly different) host name. NetBIOS is also used for identifying system names in TCP/IP(Windows).  
> Simply saying, it is a protocol that allows communication of files and printers through the Session Layer of the OSI Model in a LAN.