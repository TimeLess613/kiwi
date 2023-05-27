**Waiting for machine retire...**

*Difficulty: Easy*

---

## 扫描

- 22/tcp: OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
- 8080/tcp: Nagios NSCA


## 漏洞分析

- 22端口这个版本似乎无法利用
- 关注8080，curl连接了一下没有Location字段。打开浏览器直接访问目标的8080端口

### 8080端口

- robots.txt：无
- 网页源码：无特别发现
- 子域枚举：无域名所以对象外
- 目录枚举：

#### 研究网页功能



#### 目录遍历


#### pom.xml

仔细看看这个pom.xml，里面还挺多版本信息的。

- pom: 4.0.0
- spring-boot-starter-parent: 2.6.5
- WebApp(?): 0.0.1-SNAPSHOT
- java: 11
- javax.activation: 1.2.0
- spring-cloud-function-web: 3.2.2
- bootstrap: 5.1.3


## Initial Access

### PoC (CVE-2022-xxxxx)



### 发现phil用户密码

发现隐藏文件夹

## flag: user

移动到用户phil：
```bash

id
uid=1001(phil) gid=1001(phil) groups=1001(phil),50(staff)

cat ~/user.txt
1bf3……3bf1
```

*一开始 `su` 输入命令之后看终端没什么显示，还以为不行……然后SSH也连接失败。整得我以为卡了还直接Ctrl+C退出了*  
*不管咋的切换用户之后还是得id看一下啊……*  
*后来才知道原来简单执行 `bash -i` 就行*
```bash
bash -i
bash: cannot set terminal process group (789): Inappropriate ioctl for device
bash: no job control in this shell
phil@inject:~$ 
```


## Privilege Escalation

注意phil用户有个不寻常的组“50(staff)”。

直接find一下属于staff组的文件：
```bash
find / -group staff 2>/dev/null
/opt/automation/tasks
/root
/var/local
/usr/local/lib/python3.8
……
```



### 升级为交互shell

在这之前，目前的非交互shell在使用vim的时候好像会怪怪的，将其转成交互shell：
```bash
phil@inject:/opt/automation/tasks$ which python python3
which python python3
/usr/bin/python3
phil@inject:/opt/automation/tasks$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<sks$ python3 -c 'import pty;pty.spawn("/bin/bash")'
phil@inject:/opt/automation/tasks$ export TERM=xterm
export TERM=xterm
phil@inject:/opt/automation/tasks$ ^Z
zsh: suspended  nc -lvnp 4444
                                                                        
└─$ stty raw -echo; fg
[1]  + continued  nc -lvnp 4444

phil@inject:/opt/automation/tasks$ 
```

### 编写ansible playbook


## flag: root


> df13……7ceb


---

## 总结·后记

2023/05/26

root算是阴差阳错了……    
后来看[WP](https://hyperbeast.es/inject-htb/)提到，可以上传[pspy64](https://github.com/DominicBreuker/pspy)扫描会找到那个自动运行的进程？但是ps为啥看不了？不是很懂……有空试试这个。