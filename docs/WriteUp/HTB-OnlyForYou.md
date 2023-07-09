**Waiting for machine retire...**

*Difficulty: Medium*

---

## 扫描

自用脚本：[工作流](./HTB-Busqueda.md#workflow-scan)

```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```


## 漏洞分析

## 80端口：only4you.htb

- robots.txt：无
- 网页功能：能发送反馈？
- 子域枚举：beta.only4you.htb

### 子域：beta.only4you.htb

能下载到一个flask项目源码。可能是这个beta，也可能是主站？总之先看看源码。


#### 发现子域LFI


**注意这里面导入了 `subprocess.run()`。关于run函数，默认是python执行命令，但是也有个参数 `shell=True`，可以让它用shell执行，则可以使用shell的功能：通配符、重定向符等。**  
> subprocess.run(["ls", "-l"])  
> subprocess.run("ls -l", shell=True)  
> shell=True，默认是用“/bin/sh”


### 转战主站表单注入

burp里首先用ping验证一下，收到ping。

## Initial Access



```bash
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.xx.xx.xx] from (UNKNOWN) [10.10.11.210] 33262
bash: cannot set terminal process group (1014): Inappropriate ioctl for device
bash: no job control in this shell
www-data@only4you:~/only4you.htb$  id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

看了下用户flag不在这个用户。home目录有两个用户：dev、john。  
姑且看了下SUID等，没发现能提权。继续探索期望进行横向移动。


## 探索

枚举到本地开放端口时，发现开着挺多服务：


都curl看看。先 `curl -I` 看看响应报头

- **127.0.0.1:8001，302，不过Location字段会重定向到 `/login`，那边会响应200。**
- 127.0.0.1:33060，`curl: (1) Received HTTP/0.9 when not allowed`，报错？
- 127.0.0.1:3306，同上。不过一般都是mysql。
- **127.0.0.1:3000，200。**
- 127.0.0.1:7687，`curl: (52) Empty reply from server`
- **127.0.0.1:7474，200。**


### 端口转发

- 之前一直听说[frp](https://github.com/fatedier/frp)、Ngrok等
- 最近还知道有个[Sliver C2](https://github.com/BishopFox/sliver)好像是对标CS的？
- 后来看WP有人用[chisel](https://github.com/jpillora/chisel)
- 以及群里有师傅说原生metasploit有点鸡肋，推荐[Viper - 炫彩蛇](https://www.yuque.com/vipersec/help/olg1ua)
- 自己比较熟悉的是metasploit就先试试这个


### 初步浏览各个本地端口

#### 3000

是个叫Gogs的什么git服务。

发现两个用户  
![HTB-OnlyForYou-lport3000](./evidence-img/HTB-OnlyForYou-lport3000.png){ width='720' }


#### 8001

又一个登陆界面  
![HTB-OnlyForYou-lport8001](./evidence-img/HTB-OnlyForYou-lport8001.png){ width='450' }


#### 7474

没怎么见过，似乎叫Neo4j。查了下是个NoSQL图形数据库  
![HTB-OnlyForYou-lport7474](./evidence-img/HTB-OnlyForYou-lport7474.png){ width='720' }

也搞清楚了另一个端口7687  
> [Neo4j is a graph database management system developed by Neo4j. Default ports are 6362 (Backup), 7474 (HTTP), 7473 (HTTPS), 7687 (Bolt).](https://exploit-notes.hdks.org/exploit/database/neo4j-pentesting/)

hacktricks也有相关文章，[hacktricks - Cypher Injection (neo4j)](https://book.hacktricks.xyz/pentesting-web/sql-injection/cypher-injection-neo4j)，不过没看懂……

没懂怎么注入，就想着油管看看实操，然后看[youtube - Cypher Query Injection](https://www.youtube.com/watch?v=SIqKo7xiPVA)这个视频才明白原来这个“Cypher”不是密码，而是“[Open Cypher](http://opencypher.org/)”……  
简单看了下就是类似SQLi。但是参数在哪啊……

### 弱密码登陆本地端口3000


### Cypher Query Injection

参照上面几篇文章，用python在本地开个简单的http服务进行测试。  


### 获得凭据



## SSH登陆

```bash
Last login: Tue Apr 18 07:46:32 2023 from 10.10.14.40
john@only4you:~$ id
uid=1000(john) gid=1000(john) groups=1000(john)
```



## flag: user

```bash
john@only4you:~$ cat user.txt 
94ad……e03a
```


## Privilege Escalation



## flag: root

```bash
john@only4you:~$ bash -p
bash-5.0# id
uid=1000(john) gid=1000(john) euid=0(root) groups=1000(john)       
bash-5.0# cat /root/root.txt 
156a……3d3a
```

---

## 总结·后记

2023/05/31


难……已经啥都不想说了。想吐槽的以及不太懂的地方都边打边写了（斜体）……