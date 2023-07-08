
2023/07/08

背景：玩TryHackme时需要使用Windows，然而在Windows上使用openvpn不知道为何无法连接目标网络。于是尝试依旧用kali连接THM，然后将Windows访问THM的流量转发到kali。

拓扑：Windows(10.10.10.20) —— KALI(eth0:10.10.10.10) —— KALI(enumad) —— THM目标网络(10.200.49.0/24)

### 启用IP转发功能

#### 方法1

命令行写入：`sysctl -w net.ipv4.ip_forward=1`

#### 方法2

1. 确保以下内容添加到/etc/sysctl.conf文件中：`net.ipv4.ip_forward=1`
1. 保存文件后，执行以下命令以使更改生效：`sysctl -p`

### 确认配置

确认是否为1：`sysctl net.ipv4.ip_forward`

### 配置

#### 方法1

```bash
sudo iptables -t nat -A PREROUTING -s 10.10.10.20 -d 10.10.10.10 -j DNAT --to-destination 10.50.47.202
sudo iptables -t nat -A POSTROUTING -s 10.10.10.20 -j SNAT --to-source 10.50.47.202
```

#### 方法2

```bash
sudo iptables -A FORWARD -i eth0 -o enumad -s 10.10.10.20 -j ACCEPT
sudo iptables -A FORWARD -i enumad -o eth0 -d 10.10.10.20 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -t nat -A POSTROUTING -o enumad -s 10.10.10.20 -j MASQUERADE
```

### 其他命令

- 确认配置的NAT表：`sudo iptables -t nat -L`
- 确认filter表：`sudo iptables -L` *（因为iptables默认filter表所以不用`-t`选项）*

### 注意

- 需要在Windows添加路由：`route add 10.200.49.0 mask 255.255.255.0 10.10.10.10`
- 这些规则将在当前会话中生效，但不会在系统重启后持久生效。如果你希望在系统重启后仍然生效，你需要将这些命令添加到适当的启动脚本中（如/etc/rc.local）。