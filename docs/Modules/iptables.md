
2023/07/08

### 背景

玩TryHackMe时需要用Windows，然而在Windows上使用openvpn不知道为何无法连接目标网络。于是尝试依旧用kali连接THM，然后将Windows访问THM的流量转发到kali，由kali转发至THM。相当于让kali充当一个路由器/防火墙。

拓扑：Windows(10.10.10.20) —— kali(eth0:10.10.10.10 —— enumad:10.50.47.202) —— THM目标网络(10.200.49.0/24)

### 启用IP转发功能

命令行写入：`sysctl [-w] net.ipv4.ip_forward=1`

- 使用 `-w` 即和修改 `/etc/sysctl.conf` 文件里的 `net.ipv4.ip_forward=1` 一样
- 若是修改配置文件，执行此命令使更改生效：`sysctl -p`

### 确认配置

确认是否为1：`sysctl net.ipv4.ip_forward`

### 配置转发规则

#### 方法1

tracert的第一跳直接目标，且“显示”无延迟。

```bash
sudo iptables -t nat -A PREROUTING -i eth0 -s 10.10.10.20 -j DNAT --to-destination 10.50.47.202
sudo iptables -t nat -A POSTROUTING -o enumad -s 10.10.10.20 -j MASQUERADE
```

- `-j MASQUERADE`：动态地对源地址进行网络地址转换（SNAT），用于实现源地址伪装，使其看起来好像是从转发规则出口的接口发送的。*在一个网络中，当你有多个主机通过一个公共IP地址连接到互联网时，你需要使用NAT来转换网络数据包的源地址和目标地址。这使得数据包在从私有网络传输到公共网络时，看起来好像是由NAT设备（通常是路由器）发送的，而不是来自于原始的主机。*
- 似乎Linux上的 `IP MASQUERADE` 就是一般意义上的 `NAPT`

#### 方法2

```bash
sudo iptables -t nat -A PREROUTING -s 10.10.10.20 -d 10.10.10.10 -j DNAT --to-destination 10.50.47.202
sudo iptables -t nat -A POSTROUTING -s 10.10.10.20 -j SNAT --to-source 10.50.47.202
```

#### 方法3

```bash
sudo iptables -A FORWARD -i eth0 -o enumad -s 10.10.10.20 -j ACCEPT
sudo iptables -A FORWARD -i enumad -o eth0 -d 10.10.10.20 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -t nat -A POSTROUTING -o enumad -s 10.10.10.20 -j MASQUERADE
```

### 其他命令

- 确认配置的NAT表：`sudo iptables -t nat -L`
- 确认filter表：`sudo iptables -L` *（因为iptables默认filter表所以不用`-t`选项）*
- 清除配置：`sudo iptables -F [-t nat]`

### 注意

- 需要在Windows添加路由：`route add 10.200.49.0 mask 255.255.255.0 10.10.10.10`
- 这些规则将在当前会话中生效，但不会在系统重启后持久生效。如果你希望在系统重启后仍然生效，你需要将这些命令添加到适当的启动脚本中（如/etc/rc.local）。*（也有其他方式）*