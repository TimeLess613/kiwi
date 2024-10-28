---
tags:
  - IT/Linux
---

## 命令解释网址

<https://explainshell.com/>

## 终端快捷键

- `ctrl+w` 删左词
- `alt+d` 删右词
- `ctrl+u` 删到头
- `ctrl+k` 删到尾


## 环境变量

- `env`：显示环境变量
- `set`：显示环境变量和shell变量

- 环境变量：继承给子进程的变量。子进程的环境变量与父进程无关。
- shell变量：只在当前shell有效的变量，不继承给子进程。

### 查看指定进程的环境变量

- `cat /proc/{pid}/environ`
- `cat /proc/1229/environ | sed -e 's/\x00/\n/g'`
	- 把默认的间隔NULL (\x00) 替换成换行



## 未分类
---




### jar

列出JAR文件的内容：`jar tf myapp.jar`

在JAR文件中的文本文件中搜索关键字：

- `jar xf myapp.jar some/text/file.txt`
- `grep "search_term" some/text/file.txt`



### iconv

- iconv：即"字符集转换"。
- 语法：`iconv -f source_encoding -t target_encoding input_file > output_file`
- 对Windows实用（转为UTF-16LE）：`echo -en "[Command]" | iconv -t UTF-16LE | base64 -w 0` ^f44db6





### man

| 部分  | 内容              |
| :-: | --------------- |
|  1  | 用户指令            |
|  2  | 内核系统调用的编程接口     |
|  3  | C库的编程接口         |
|  4  | 特殊文件。如设备节点和驱动程序 |
|  5  | 档案格式            |
|  6  | 屏幕保护程序等游戏和娱乐    |
|  7  | 杂               |
|  8  | 系统管理命令          |

### [dollar sign](https://unix.stackexchange.com/questions/48106/what-does-it-mean-to-have-a-dollarsign-prefixed-string-in-a-script)

`$'…'`

`echo $'{\"username\":\"a\",\"password\":\"a\"}'`

![[static/img/ATTACHMENTS/Pasted image 20240310160123.png]]



## 文件和目录管理
---


### mv

> [!NOTE] 注意覆盖权限 #渗透/利用 
> 文件是否能被覆盖，不是取决于文件的权限，而是目标文件的目录权限。目录权限能写入的话，则用户能选择是否覆盖目标文件。

### realpath

用于将相对路径或符号链接转换成绝对路径。


### stat

可用`stat <文件名>`查询inode信息。

文件时间戳

- atime：Access，文件打开
- mtime：Modify，文件内容变动 ^fda64b
- ctime：**Change**，inode变动——即文件属性（权限、所有权等）变动时ctime会变。一般来说文件创建的时间也差不多是inode创建的时间
	- ls -l 默认显示的是ctime
	- 由于是贴上**系统时间**，所以可以用 `date -s` 改系统时间后再操作

- [[Linux命令#^64f8c7|查看块大小：`stat file.txt | grep IO`]]



### touch

touch已存在的文件或目录时会刷新时间。`touch /*` 刷新所有。


### mkdir

`mkdir -p`：递归创建


### 提取文件名/文件夹名

- `basename [pathname] [suffix]`
- `dirname [pathname]`


### 软链接

`ln -s <目标文件> <链接名>`

如：`ln -s /etc/passwd the_symlink`



### find

`find / -name '*.c'`

- `-name`：搜索文件名
- `-i`：不区分大小写
- `-type d`：找文件夹
- `-user`：按文件属主查找

#### 根据时间查找

##### 相对时间

- find [[Linux命令#^fda64b|-mtime]] [+/-] n：从当前时刻开始推，
	- 0：当前时间往前推，过去24h内
	- n：当前时间往前推，n天前的过去24h内
	- 正负表示指定时刻的方向的全部：+为左（以外，过去的过去），-为右（以内，过去的将来）
		- +n：**超过**n天前的
		-  -n：n天**内的**（包括今天）

```
+2 ←---|--2--|--------→ -2
 
--|-----|-----|-----|-----|
  4     3     2     1     0(现在)
```

##### 绝对时间（特定时间）

- `find /path/to/search -type f -newermt "YYYY-MM-DD HH:MM:SS"`

> [!NOTE] 关于排查
> 黑客可能只修改了mtime，而忘了ctime。



#### 排除搜索

仅将输出结果过滤，依旧会遍历所有不需要的目录。

- `find -name "*.js" -not -path "./directory/*"`
	- `-not`可以替换为感叹号（`!`）
	- **需要指定排除多个则用如下命令**（使用转义的小括号）

```bash
find / \( -path /proc -o -path /run \) -prune -o \( -user $(id -un) -o -group $(id -gn) \) -type f -ls 2>/dev/null
```

- `-path`：匹配路径pattern，可以用通配符。
- `-o`：或
- `-prune`：排除
- **`-ls`：原来这个可以列出详细信息，不用`-exec`的方式了。**


#### 找设置了SUID的文件

- `find / -perm -u=s -type f 2>/dev/null`
- `find / -user root -perm -4000 2>/dev/null` (但是注意有时候可能可以横向移动所以不只找root)
	- 常用：`find / -perm -4000 2>/dev/null -exec ls -l {} \;`
		- **进化/简写：**`find / -perm -4000 -ls 2>/dev/null`

根据man手册：

- 尽量用 `/` 代替 `+`
- -perm 664：精准查找664
- -perm -664：查找权限**至少**为664的，如会匹配出0777
- -perm /222：查找**任意一个**权限为2的（即-perm /220结果也一样）


#### -exec

`-exec COMMAND "{}" \; -quit`

- 花括号两边也可以不用双引号
- 以分号表示命令结束，但避免意外所以一般加上反斜杠转义
- 花括号里为-exec前面命令的结果
- 只有部分命令后有-exec选项。如find
- -quit：匹配到一个结果就停止

`find /Documents -type f -exec grep -H Milledgeville {} \;`






### grep

- 仅输出匹配内容而非整行：`grep -o`
- 将匹配pattern写在文件：`grep -f <pattern_file>`
- 显示匹配行之后的n行：`grep -A n "pattern" file`

- `egrep  {pattern} {文件}`：同grep -E
> [!NOTE] 有时egrep比grep快（egrep按原样处理meta字符而无需转义）

- `fgrep`是单纯搜字符串（效率高些），而不会把特殊符号看做正则表达。
	- 和 "grep -F" 一样
	- 没有`{文件}`则读取标准输入

**要grep带两个短横线`--`的（如help页面），不能直接搜`"--"`而需要`grep -- "--"`：**  
![[static/img/ATTACHMENTS/Pasted image 20240311163220.png]]

- 可对压缩文件的grep（对未压缩文件也有效）：`zgrep  {pattern} {文件}`。
 ^02828b
- 过滤空行(`^$`)和`#`：`egrep -vn "^$|#"`、`grep -Evn "^$|#"`
	- `^$|#`的`|`两边不能有空格！会被识别进pattern里
	- `$`表示结尾，空行的话实际上有个`$`（`cat -e`可知）
	- `|`是逻辑或
	- `-n`输出对应的行号


**踩坑：**

- grep搜不到结果则rc为1，所以要小心使用`set -e`（不过应该可以用命令替换——子shell）
- `grep -f`无结果。考虑f文件是否从window传输而来。即使用awk整理，但换行符未处理：：[[换行符#转换与删除]]
- `tail -f`的多个grep有时无法输出部分结果——用行缓冲解决`grep --line-buffered`（默认情况下，当标准输出是终端时输出是行缓冲的，否则是块缓冲——即达到一定的数据量，一般是4~64KB，如grep命令在中间时）
	- [x] [piping-of-grep-is-not-working-with-tail](https://stackoverflow.com/questions/26362450/piping-of-grep-is-not-working-with-tail)
	- [ ] [how-to-grep-a-continuous-stream](https://stackoverflow.com/questions/7161821/how-to-grep-a-continuous-stream)


### zipgrep

搜索包含在ZIP文件中的文本文件，它会解压缩ZIP文件并在其中搜索文本。

- 对比：[[Linux命令#^02828b|zgrep]]不会解压整个文件，而是在压缩文件（`.gz`）中直接搜索文本。
- 对于在JAR文件内搜索文本，应该使用`zipgrep`命令，因为JAR文件实际上是ZIP格式的压缩文件，其中包含Java类文件和其他资源。

> [!NOTE] .gz和.zip
> 1. **压缩算法**：
> 	- `.gz`文件使用的是GZIP压缩算法，这是一种广泛使用的压缩技术，特别是在Unix和Linux系统中。GZIP旨在提供高效的数据压缩，而不是打包或归档多个文件。
> 	- `.zip`文件不仅使用不同的压缩算法（通常是DEFLATE），还支持打包和压缩多个文件和目录到一个单独的`.zip`文件中。这意味着`.zip`文件可以包含文件系统的结构信息，如目录和文件属性。
> 1. **用途**：
> 	- `.gz`格式通常用于压缩单个文件。当需要压缩多个文件或目录时，通常会先使用`tar`命令将它们打包成一个`.tar`文件，然后再使用`gzip`压缩，形成`.tar.gz`或`.tgz`文件。
> 	- `.zip`格式则更加灵活，可以直接在一个`.zip`文件中压缩和打包多个文件和目录。这使得`.zip`文件非常适合跨平台共享，因为`.zip`格式被大多数操作系统原生支持。




### tail

- `-n 2`：指定显示2行
- `-n +2`： 指从第2行开始





### 文件比较

#### comm

`comm [-n] <file1> <file2>`

- 输出3列，分别是：仅file1有的行、仅file2有的行、file1和2都有的行
- -n：n可以是1、2、3。“-”可理解为减号，指定不显示哪些列。

#### diff

输出：用“-”表示仅file1有的行，用“+”表示仅file2有的行。

两个常用option：

- -u：unified格式，统合着看
- -c：context格式，显示上下文，输出就比unified格式多很多。

#### vimdiff

多个文件打开vim。像winmerge。

### locate

与find不同，find是去硬盘找，而locate是在`/var/lib/slocate/slocate.db`中找，所以locate快。而这个数据库不是实时更新的，手动更新数据库命令：`updatedb`（似乎默认每天`cron`跑一次）。

### file

确认文件类型。

### exiftool

> [!NOTE] EXIF: EXchangeable Image File Format

读取、写入和处理图像、音频、视频和PDF 元数据。

`exiftool -a -u brochure.pdf`

### strings

隐写、确认2进制文件中的字符串。

### binwalk

• 可查看文件有无捆绑：`binwalk <file>`

### strace

追踪2进制运行的系统调用。

**经验：**

- 当出现“read(0,”并卡住时，很有可能是等待用户输入
- 重点关注openat——与文件的交互
- 似乎可以用`-e trace=open,read`

### hexeditor

查看16进制。




### 统计目录大小

`du -sh`









## 文本处理和编辑
---

### echo

解析[[编码#转义序列|转义序列]]：`echo -e`

如：
```bash
$ echo -e 'hello \nworld'
hello 
world
```



### vi/vim

| 输入           | 效果                        |
| ------------ | ------------------------- |
| `x`          | vim: Cut character        |
| `dw`         | vim: Cut word             |
| `dd`         | vim: Cut full line        |
| `yw`         | vim: Copy word            |
| `yy`         | vim: Copy full line       |
| `p`          | vim: Paste                |
| `:1`         | vim: Go to line number 1. |
| `dd`         | 删除光标所在行                   |
| `## dd {数字}` | 删除指定行                     |
| `u`          | 撤回                        |
| `:set nu`    | 显示行号                      |
| `:set nonu`  | 不显示行号                     |


**注释快捷键**

- 快速注释一行：大写字母"I"进入行首插入模式，输入注释符号（如“#”）。
- 快速取消注释一行：按下小写字母“x”删除注释符号。
- 快速注释多行：将光标移动到要注释的第一行上，按下大写字母“V”进入可视行模式，移动光标到要注释的最后一行，按下大写字母“I”进入行首插入模式，输入注释符号（如“#”）。
- 快速取消注释多行：将光标移动到要取消注释的第一行上，按下大写字母“V”进入可视行模式，移动光标到要取消注释的最后一行，按下小写字母“x”删除注释符号。



### tee

命名源于一种T型管道（tee）。表示可以分岔——即可以将命令的标准输出流也分出一部分到其他地方（如文件）。

- `tee`：`>`（即覆盖）
- `tee -a`：`>>`（即追加）

### wc

`wc`结果输出统计的3个数：文件中的行数、单词数、字符数。

- -l：行数
- -w：单词数
- -c：字符数

### sort

按第5列进行数字排序（降序）：`sort -t= -k3,3 -nr <file>`

- -t：分隔符。默认为空格，此处指定为等号
- -k：指定key，有许多形式。在这里以数字3表示第3列开始，到第3列结束。单列的话也可简写作：-k3
- -n：以数字排序
- -r：降序

**去重：sort -u**


### uniq

去重&统计：`uniq -c`

> [!NOTE] 要先sort一遍再uniq
> 因为uniq是每次都检查连续的行然后取第一行

`grep "Edg" $logFile | awk '{ print $10 }' |  sort -n | uniq -c | sort -rn | head`

- -n：数字排序（不然字符排序的话，会`[1, 11, 2, 3, ...]`这样排）
- -r：逆序
- -c：显示count数（即统计，**否则只是去重还不如用`sort -u`**）


### paste

`paste -sd ','`：多行数据合并为单行，以逗号分隔

- -s：将 `paste` 命令的处理方式**从并行改为串行**（**默认**情况下，`paste` 会**并行合并多个文件的对应行**）。串行模式下，`paste` 会将单个文件的所有行合并成一行
- -d：指定分隔符

### tr

替换或删除文件中的字符

- 换行替换：`tr "\n" " "`
	- 可用单引号
- 删除回车符：`tr -d "\r"`
	- 等同于 `sed "s/^M//"、sed "s/\r//"`。注意：这个“^M”不是手打的，是`Ctrl+V+Ctrl+M`输入的“回车符”
	- `-d`：即`--delete`，删除指令字符（注意：以字符而不是整个单词为单位）



### cut

`cut -d " " -f 4`


### sed

处理多行可用cut，而文本流可用sed命令。

- 默认选项：`-e`，只输出在终端，而不改变文件
- `-i`：直接修改文件，而不输出在终端

![[static/img/ATTACHMENTS/Pasted image 20240310224233.png]]

- $表示最后一行
- ‘$aString’表示最后一行增加。必须用单引号！因为双引号会以为是调用变量？
	- a和String之间可以用空格、反斜杠、或者不空。（反斜杠的话注意是否有特殊转义）
	- **踩坑**：可能涉及权限不够问题，因为sed是首先编辑好临时文件然后用临时文件替换源文件。

**正则**
![[static/img/ATTACHMENTS/Pasted image 20240310224318.png]]


### awk

相比于sed处理一行的数据流，awk倾向把每行按字段分割处理。对格式化的文本处理能力强。

> 详细：[awk的基本使用方法](https://www.linuxprobe.com/basic-usage-awk.html "awk的基本使用方法")

**例：**
`awk -F',' '{print $1,$2}'   log.txt`

- 使用","分割（默认空格）
- 写成一行要用单引号

**实用（第4列去重）：**
`zfgrep 'xxx/' ./*/httpaccess-vpn.log* | awk '!seen[$4]++ { print $4, $7, $8, $10 }'`

- 定义一个seen数组。
- 数组的值如果未定义，默认是0——false
- 然后递增将值加1——true
- 然后感叹号取非
- debug：`'!seen[$4]++ { print $4, $7, $8,$10; print "seen["$4"]= ", seen[$4] }'`

#### 条件可用【/PATTERN/】正则匹配


#### NR与FNR

![[static/img/ATTACHMENTS/Pasted image 20240311172420.png]]

#### 指定输出分隔符（OFS）

`… | awk -F '|' '{OFS=":"; print $11,$14}' | tr -d ' '`

#### 转大写

`echo "Hello World" | awk '{print toupper($0)}'`




### [[json#jq命令]]




### xargs

理解xargs与管道符的区别：

- `echo '--help' | cat`
- `echo '--help' | xargs cat`

xargs的默认命令是echo，这意味着通过管道传递给xargs的输入将会包含换行和空白，不过通过xargs的处理，换行和空白将被空格取代。



## 系统信息和服务管理
---

### history

- 保存在用户主目录的 `.bash_history` 文件里
- `!<命令行号>`：执行目标命令

**相关环境变量：**

- `HISTSIZE`和`HISTFILESIZE` 可控制大小
- `HISTTIMEFORMAT`：时间戳
	- 可用`export HISTTIMEFORMAT="[%F %T] "`显示历史命令时间
	- %F：ISO8601格式
	- %T：24小时制
	- 其他格式参照strftime手册


### date

用`+`指定格式：`date '+<format>'`，或`date +'<format>'`。`+`字符在引号内外都可，因为`+`字符在这里不需要特殊处理，**重点是加号和format之间不能有空格**。

赋值（[[Linux各种括号#^97ed2e|命令替换]]）：`DATE=$(date +%Y%m%d)`

- `-d 'N days ago'`：获取N日前的时间。
- `-d 'N days'`：获取N日后的时间。

-s：修改系统时间

- 重启系统可以恢复
- 如果配置了NTP，似乎会逐渐同步时间
- 立即强制同步时间：
	- 如果使用chronyd：`sudo systemctl restart chronyd`
	- 如果使用ntpd：`sudo systemctl restart ntp`



### 服务管理器

#### init

- 旧
- 用service系列命令（是对`/etc/init.d`目录下服务脚本的封装）

#### systemd

- 新
- 用[[Linux命令#systemctl|systemctl]]系列命令

### 运行级别

#### init方式

**`init <runlevel>`命令切换运行级别**

- 0：关机
- 6：重启
- 3：命令行界面
- 5：图形界面

#### systemctl方式

**查看当前运行级别（下面结果表示从3级别切换到了5级别）**
```bash
$ sudo runlevel
3 5
```

**查看当前默认启动级别**
```bash
$ sudo systemctl get-default
graphical.target
```

**设置默认第3/5运行级别（命令行/图形）**
```bash
$ sudo systemctl set-default multi-user-target
$ sudo systemctl set-default graphical-targete
```


#### 桌面环境

**查看**

- 可用的：ls /usr/share/xsessions/
- 当前的：echo $XDG_CURRENT_DESKTOP

**安装**：[[配置Linux图形桌面连接#^32a346|安装桌面环境]]


### systemctl

注意：修改服务单元文件（如下面的`/etc/systemd/system/k3s.service`）后，需要**重启daemon**：
```bash
$ sudo systemctl daemon-reload
$ sudo systemctl restart k3s
$ sudo cat /etc/systemd/system/k3s.service
```


### 更改主机名

#### 临时

`hostname xxx`

#### 永久

```bash
vi /etc/hostname
reboot
```

#### 查看hostname详细信息

`hostnamectl`


### uname

即unix name。

- `-a`：显示所有信息：主机名、内核版本、硬件等。
- `-r`：内核信息。可以确认是否有内核漏洞。
	- 如：`5.10.0-kali3-amd64`，版本号对应：`主版本号.次版本号.修订版本号`。
		- *Linux3.0版本之前，次版本号的奇数是开发版、偶数是稳定版*
		- *之后放弃了这种标识，改用LTS、RC等*
	- 内核详细信息：`cat /proc/version`

#### arch

显示架构。即`uname -a`结果中`x86_64`那个部分。


### OS版本

`cat /etc/os-release` 或 `cat /etc/lsb-release`（红帽）


### CPU信息

`cat /proc/cpuinfo`


### top

`top -n 1`：n1即指刷新一次。

> [界面解释](https://milestone-of-se.nesuke.com/sv-basic/linux-basic/top-command/)
> - `load average` が高い状態というのは「プロセスからディスクへの書き込みが積滞している」状態を示していることが多く

*n个CPU——则load average的最大负荷为“n”。*



### watch

- 命令监控。
- `watch -n <刷新秒数> <被监控命令>`


### shell环境

- 查看当前用户使用的shell：`echo $SHELL`
- 查看本机可用shell：`cat /etc/shells`

#### `/bin/sh -c`

**必要场景：**  
比如，一般用户执行`echo "hello" > test.txt`，是OK的。但是把test.txt设置为root后，就算用`sudo echo "hello" > test.txt`再写入就没权限了。  
因为重定向符号也是bash命令，而sudo只是让echo提权，没有提升重定向符号的权限。（关于报错的时间点，其实有个shell解析命令的问题：不是写入的时候报错。shell解析一行的每个命令程序，而重定向或pipe也是命令，且会暂时打开文件，是在此时触发权限问题）

**两种解决方法：**

1. `sudo sh -c 'command'`。让bash将一个字符串作为完整命令，sudo的影响范围就可以扩展到整条命令。
2. `echo "hello" | sudo tee <file>`。因为echo并不需要sudo，将sudo的提权给tee命令进行文件写入。


理解shell进程： [https://blog.csdn.net/renzhentinghai/article/details/82662024](https://blog.csdn.net/renzhentinghai/article/details/82662024)

- exec和source一样不新建子进程，而区别为：**调用exec是以新的进程去代替原来的进程，但进程的PID保持不变。** 替换了原来进程上下文的内容。原进程的代码段，数据段，堆栈段被新的进程所代替。


### 终端环境

> 不同的终端类型可能支持不同的颜色方案、字符集、以及特殊功能（如光标移动）。

- 查看当前环境：`echo $TERM`
- 常用终端类型：`xterm`、`xterm-256color`


## 网络和通信
---

### 路由表

`netstat -rn`


### dhclient

`dhclient`：获取新的IP地址。如果已经有IP，则需要先释放：

- `dhclient -r`：释放当前的IP地址（的租约）

`-v`：详细

- log文件路径：`/var/lib/dhcp/dhclient.leases`

> [!NOTE] [[Kali搭建#Hyper-V]]的虚拟机还原快照后可能网络不通。原因：可能是ARP表（新旧快照MAC和IP不对应了）。所以重新分配DHCP：`dhclient -r && sudo dhclient`


### 修改IP

#### [[Linux发行版#Redhat系列]]

- `/etc/sysconfig/network-scripts`
- 用init做服务管理器的OS：`service networking restart`
- 用systemd做服务管理器的OS：`systemctl restart network`
- CentOS8之后用：`systemctl restart NetworkManager`
	[https://i-think-it.net/rhel8-network-restart/](https://i-think-it.net/rhel8-network-restart/)


#### [[Linux发行版#Debain系列]]

![[static/img/ATTACHMENTS/Pasted image 20240311181744.png]]

**重启命令2：**`sudo service networking restart`

> [!NOTE] 上述两种重启命令
> 总的来说，这两个命令实际上是等效的，它们都用于重启网络服务。
> `sudo service networking restart`是一种更推荐的方式，因为它是一种通用的命令形式，适用于多个服务和操作系统。
> 而`/etc/init.d/networking restart`则直接指向网络服务的启动脚本文件，是一种更具体的方式。


### netstat

参照[[Linux命令#ss]]

### ss

netstat的替代。

- -a：正在使用的所有port/socket
- -n：显示端口数字而不解析为服务名
- -o：显示timer（如果有的话）
- -p：显示进程
- -t：显示TCP
- -l：显示正在监听的端口


**状态**

- UNCONN：unconnected の意味で、UDPにおける待ち受けポートを表します。
- ESTAB：3way handshakeが成功した状態、つまりTCPコネクションが確立した状態を意味します。


### nmtui




### iptables

iptables是Linux系统流行的防火墙软件，在大部分发行版中都自带。而容器的访问控制主要通过iptables来进行管理和实现。
CentOS6及之前都在用这个，CentOS7开始用新的命令：[[Linux命令#firewalld|firewalld]]（但是原理还是iptables，算是封装了）。

- `iptables -t 表名 --list --line-numbers`
- `iptables -t 表名 -L 链名`
	- `iptables -t nat -L -n`

> 关于linux转发windows流量以实现windows与THM、HTB的VPN互通：<https://timeless613.github.io/kiwi/Resources/iptables/>


**（Netfilter5表5链）**


理解：
![[static/img/ATTACHMENTS/Pasted image 20240311165707.png]]



### firewalld

实际使用命令：`firewall-cmd`

CentOS7默认这个而不是iptables了。

- 主要因为虚拟化趋势使得Linux的网络非常复杂，用iptables配置太困难。且iptables的设置还可能和应用程序设置冲突，管理混乱。
- 特点：可以为每个NIC配置设定

相关配置文件：`/usr/lib/firewalld`

#### 默认9个zone的默认配置

1. trusted：允许所有包通过（允许进出）。【如果添加了端口等配置，则只允许配置的规则通过。其他zone估计一样】
2. drop：丢弃所有外部进来的包（内部的包可以出去，但是丢弃了返回的包，所以实际上就是无法通信）
3. block：block基本会屏蔽外部进来的包——除了从内部出去的包的返回包（对比drop）
4. public：默认仅允许ssh和dhcpv6-client通信
5. dmz：默认仅允许ssh
6. external：
7. internal：
8. work：
9. home：

通常，命令行配置的是入站规则。出站通信通常不需要额外配置，因为大多数防火墙默认情况下会允许出站通信。

#### 基本命令

`firewall-cmd [--zone=trusted] --list-all`

- 不指定zone的话会显示默认zone（firewall-cmd --get-default-zone）
- 默认zone：当网络数据包到达系统上的接口时，如果没有明确指定要分配给哪个区域时，数据包将被分配到的默认区域。默认区域的作用是定义了对于未知来源的数据包应该应用哪些防火墙规则。

`firewall-cmd --list-all-zones`：也会显示未活动的zone

`--permanent`：持久设置


#### 项目理解firewalld

SOAR EdgeGW server:
```bash
sudo dnf install firewalld -y

sudo systemctl start firewalld

sudo firewall-cmd --permanent --zone=trusted --add-interface=cni0 &&
sudo firewall-cmd --permanent --zone=trusted --add-interface=flannel.1 &&
sudo firewall-cmd --permanent --zone=trusted --add-port=443/tcp &&
sudo firewall-cmd --permanent --zone=trusted --add-port=6443/tcp &&
sudo firewall-cmd --permanent --zone=trusted --add-port=10250/tcp

sudo firewall-cmd --permanent --zone=public --add-port=22/tcp

sudo firewall-cmd --reload && sudo systemctl restart firewalld
```





## 用户和权限管理
---

### su

切换用户。

`su`和`su -`：

- su命令不指定user名则默认root
- `su -`是用户和[[Linux命令#shell环境]]都切换，所以**环境变量会不同**
- `su`只切换了用户，就可能出现PATH错误


### useradd

- `-m`：自动添加家目录（似乎默认）
- `-s /bin/bash`： 创建时指定shell（默认/bin/sh或bash?），或者可以之后编辑passed文件修改

> [!NOTE] 添加新用户后，要用`passwd`命令给他加密码，否则无法登陆。

### passwd

`passwd [user]`：更改（当前/指定）用户密码



### sudo

#### sudo流程

sudo 执行命令的流程是当前用户切换到其他用户（`-u`指定，不指定则**默认root**），然后**以指定身份执行命令，执行完成后，直接退回到当前用户**。

**例子： `-u` 指定用户**
```bash
www-data@misdirection:/var/www/html/wordpress$ sudo -l
…
User www-data may run the following commands on localhost:
    (brexit) NOPASSWD: /bin/bash
www-data@misdirection:/var/www/html/wordpress$ sudo -u brexit /bin/bash
```


#### `sudo -l`

查看是否有sudo权限。

- 会要求当前用户的密码
- 但是，只要sudoers配置有任意一条`NOPASSWD`，那么就可以无密码执行`sudo -l`（有可能只显示配置了`NOPASSWD`的命令，未测试）

#### 配置sudoers

尽量别动 `/etc/sudoers` 文件，而是**往 `/etc/sudoers.d/` 里添加**。
其格式为：`<用户名/%组名>   主机名=(可切换的用户:可切换的组) [NOPASSWD: ]ALL`

**发现**

- 即使sudoers文件里配置了绝对路径，命令行依然可以用相对路径——只要参照$PATH后的绝对路径和sudoers文件里的一样就行

**例子**
```bash
testuser        ALL=(ALL:ALL) /bin/bash
%kali-trusted   ALL=(ALL:ALL) NOPASSWD: ALL
```


### pam

pam：Pluggable Authentication Modules，可插拔式认证模块。

`/etc/pam.d/`：

- system-auth
- password-auth
- fingerprint-auth
- smartcard-auth

### wheel

源于big wheel：大人物。



### chmod

![[Linux文件权限]]


### chown

`chown -R user:group`

* -R：递归


### chgrp



### chage

修改密码策略。

`chage -l <user>`：确认用户密码策略。






## 软件包管理
---

### [[Linux发行版#Debain系列]]

#### apt（Advanced Packaging Tool）

- DEB 包格式

检查更新&安装更新（即更新库和更新软件）：`apt update && apt upgrade <包名>`

- `apt update` 只是检查更新（应用更新的软件源 `/etc/apt/sources.list`）
- 还有`remove`命令

> apt 需要单独运行 apt update 命令来检查更新的原因在于其设计哲学和工作方式的不同。 
> apt 使用的是 Debian 软件包管理系统，而 yum 使用的是 RPM 软件包管理系统。这两者的设计和原理不同，导致了它们在更新软件包列表方面有所不同。
> 在 apt 中，软件包列表和软件包信息存储在本地缓存中（通常位于 /var/lib/apt/lists/ 目录下），而不是每次运行 apt 命令时都会实时从远程存储库下载。因此，需要定期运行 apt update 来更新本地缓存，以确保您获得最新的软件包信息。
> 与之不同，yum 使用的是元数据缓存，它会定期从远程存储库下载最新的元数据信息，而不需要用户手动运行额外的命令来更新软件包列表。这意味着 yum 在运行 yum update 时会自动检查并使用最新的软件包信息。
> 这种设计差异是因为apt 和 yum 的设计哲学和背后的发行版之间的差异，它们的目标是为不同的 Linux 发行版提供软件包管理。

**列出（已安装）的软件包：`apt list [--installed]`**

### [[Linux发行版#Redhat系列]]

#### rpm（**Red-Hat P**ackage Manager）

- RPM 包格式
- **推荐用yum（后被`dnf`替代）**——YUM是建立在 RPM 基础之上的高级包管理工具

#### yum（Yellowdog Updater Modified）

解决rpm繁琐的包依赖。

配置文件：/etc/yum.conf

**列出（已安装）的软件包：`yum list [installed]`**
更新包：`yum upgrade <包名>`。等价于`yum update --obsoletes`，而由于 /etc/yum.conf 里默认有obsoletes=1，所以和yum update没区别。

##### **报错解决**

> This system is not registered with an entitlement server. You can use subscription-manager to register.

```bash
vi /etc/yum/pluginconf.d/subscription-manager.conf
enabled=0
yum clean all
```

#### dnf（Dandified YUM）

yum进化版。基本上系统都配置了yum与dnf命令的互换。

#### 拓展

##### EPEL（Extra Packages for Enterprise Linux）

- epel源（是基于Fedora的一个项目，为“红帽系”的操作系统提供额外的软件包)
- 企业版Linux附加软件包

`dnf install epel-release -y`

##### pip（Pip Installs Packages）

- python
- **列出已安装的软件包：`pip list`**





## 磁盘、分区、文件系统管理
---

![[分区#基础概念]]

### lsblk

list block。

- 块是**文件系统中**的最小存储单位
- 而扇区是**磁盘中**的最小存储单位

> [!NOTE] 那为什么有了扇区，还要用块描述？
> 因为系统读取硬盘时是一次读取多个扇区，即块。块的大小常见的是1KB（即两个扇区）或4KB。

查看块大小：`stat file.txt | grep IO` ^64f8c7



### fdisk

查看/管理（指定）磁盘**分区**。

- `fdisk -l [/dev/disk_name]`
- `fdisk -l`显示的内容即`fdisk <硬盘，如/dev/sda>`进入控制台后按“p”打印的内容。

#### gdisk

主要用来划分容量大于4T的硬盘（fdisk搞不定）

- 两种分区表：[[分区#GPT分区表|GPT]]、[[分区#MRB分区表|MBR]]。
	- MBR不支持4T以上


### mkfs

`mkfs.xfs /dev/<分区名>`：即`mkfs -t xfs`，如在sda1分区上创建/格式化xfs**文件系统**。

创建文件系统后将此分区挂载到目录树，便可通过访问目录使用分区（的文件系统）。

### mount

**查看**

`mount`：显示目前挂载的所有文件系统（其中有挂载点信息）。

> [!note] 推荐[[Linux命令#findmnt|findmnt]]命令更易读，或者 `df -hT` 更简洁。


**挂载**

将分区的文件系统映射到挂载点（目录）。

临时挂载：`mount <分区名> <目录名/挂载点>`

永久挂载：需要修改 `/etc/fstab` 文件，具体修改格式参照：[[Linux命令#fstab|fstab]]。修改后可以用 `mount -a` 应用配置，用 `df -hT` **确认挂载成功后**再重启（好习惯，否则可能重启后发生进不去等问题）。

- `mount -a`：尝试挂载 `/etc/fstab` 中**尚未挂载**的文件系统。系统启动时通常会自动执行 `mount -a` 来挂载 `/etc/fstab` 中定义的文件系统。


**卸载**

`umount /mnt/my_mount_point`


#### findmnt

`findmnt [/path/to/mountpoint | /dev/sdX]`：树形图显示挂载点的信息



### fstab

**配置开机自动挂载（持久化）**

可用 `blkid` 命令确认UUID。  
也可以用分区名编写配置文件（**但是要注意如果磁盘重插的话可能系统识别的分区名会变，而UUID不会**）。

**语法、格式：**

| 要挂载的分区设备  | 挂载点   | 文件系统类型 | 挂载选项     | 是否备份 | 是否检测 |
| --------- | ----- | ------ | -------- | ---- | ---- |
| /dev/sdb1 | /sdb1 | xfs    | defaults | 0    | 0    |
- 弄完重启——担心重启有问题的话，可以先 `mount -a` 看看挂载成功没再配置 `fstab`。


### df

`df -hT`：查看文件系统使用、挂载状况

- 文件系统：是用于组织和管理存储数据的方式，通常建立在逻辑卷或标准分区之上。
- tmpfs 是一种虚拟文件系统，它通常用于将数据存储在内存中而不是硬盘上，以提高访问速度。







## 压缩和解压
---

### tar

- -f 必须，且在最后。指定包的文件名。

- -c 创建归档/压缩
	例：tar -cvf <归档后文件名> <要归档的文件> 【tar -cvf jpg.tar *.jpg //将目录里所有jpg文件打包成tar.jpg 】

- -x 解压
	解压选项：
	- 解压【.tar.xz】时：`tar -xvf <filename>`
	- 解压【.tar.gz】时：`tar -zxvf <filename>`
		- -z 用gzip压缩

- -t 列出包中文件（不释放包内文件）
- -r 追加到指定包末尾



### zip

`zip -r  --symlinks <compressed_file.zip> <file_or_directory>`

- 如果zip文件不存在，则创建
- 如果zip文件存在，则是添加文件/目录到zip文件里
- --symlinks：即“-y”，用于确保符号链接被正确处理。如果不使用这个选项，zip 默认会将符号链接指向的实际文件添加到压缩文件中，而不是符号链接本身。

查看ZIP文件内容：`unzip -l file.zip`

### gz

- 压缩命令不保留源文件
- 解压：gunzip

查看未压缩大小不用先解压：`gzip -l <file>`  
不解压zip文件查看行数：`gzip -dc <file> | wc -l`

- -d：解压

> [!NOTE] `zcat`与`gunzip -c`命令等效

## 进程管理
---

### ps

#### BSD[[命令风格]]的参数

**前面不加短横线。**
（ax为必须的，因为它们解除了“仅限您自己”和“必须有 tty”限制）

- `ps aux`
- `ps axjf`
	- `f`：表示森林，会显示进程树
	- `j`：jobs format

#### Unix[[命令风格]]的参数

**前面加短横线。**

- `ps -ef`
- `ps -Cf`
	- `-e`：所有进程
	- `-f`：完整format列表（UID、PID、PPID等）
	- `-C`：命令名称选择
	- `-l`：长格式


### kill

`kill <pid>`


## 日志和监控
---

- 日志查看：`dmesg`, `tail`, `journalctl`

- 性能监控：`vmstat`, `iostat`

## 备份和恢复
---

- 备份工具：`rsync`, `dump`, `dd`

- 恢复工具：`restore`

## 调度和计划任务
---

### corn

使用`crontab -e`命令编辑当前用户的crontab文件时，实际上编辑的文件通常存储在`/var/spool/cron/crontabs/`目录下，并以该用户的用户名命名。

> 在计算机术语中，"spool"是一个历史悠久的词汇，原意是"Simultaneous Peripheral Operations On-line"的缩写，它描述了一种处理数据的方法，这种方法涉及到将数据或任务临时存储在一个中间区域（通常是硬盘上），以便稍后按顺序处理。这个概念最初是为了解决早期计算机输入输出设备速度与计算速度之间的不匹配问题。
> 在当今的使用中，spool这个词主要关联于打印作业的缓冲（打印机spooling）和邮件系统，以及其他需要队列管理的任务，比如cron作业的管理。在这些上下文中，spooling指的是将作业存储到一个队列中，然后按照一定的顺序（通常是先进先出）进行处理。


**用事先定义好的cron任务文本替换当前用户的crontab：**
`corntab [-u username] <crontask.txt>`

 - `-u`：如果有权限，可指定替换其他用户。
