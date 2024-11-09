---
tags:
  - IT/Linux
---

## 刷新DHCP

*[[Kali搭建#Hyper-V]]常用*

`ip a && sudo dhclient -r && sudo dhclient && ip a`


## GUI方式

> NetworkManager 将只处理未在/etc/network/interfaces中声明的接口（即：CLI配置一般优先于GUI）

[https://wiki.debian.org/NetworkManager](https://wiki.debian.org/NetworkManager)

GUI改IP是用API，没有直接修改什么文件。可以断开网络重连就应用配置了。


## Debian/Ubuntu 上的网络文件

`/etc/network/interfaces`，编辑后重启网卡服务：`sudo service networking restart`

静态IP：
```bash
# 环回地址
auto lo
iface lo inet loopback
# 将eth0设置为静态IP
auto eth0
iface eth0 inet static
address 10.10.10.10/24  # 换行 netmask 255.255.255.0 一样。
gateway 10.10.10.2
```

DHCP：
```bash
# 环回地址
auto lo
iface lo inet loopback
# 将eth0设置为DHCP
auto eth0
iface eth0 inet dhcp
```


## CentOS

- /etc/sysconfig/network-scripts
- 用init做服务管理器的OS：service networking restart
- 用systemd做服务管理器的OS：systemctl restart network
- CentOS8之后用：systemctl restart NetworkManager
	- [https://i-think-it.net/rhel8-network-restart/](https://i-think-it.net/rhel8-network-restart/)