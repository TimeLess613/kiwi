**Waiting for machine retire...**

*Difficulty: Easy*

---

## 扫描

将自己侦查时常用的命令写了个脚本：[工作流](./HTB-Busqueda.md#workflow-scan)

- 22/tcp open  ssh &nbsp; &nbsp; &nbsp; &nbsp; OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
- 80/tcp open  http &nbsp; &nbsp; &nbsp; nginx 1.18.0 (Ubuntu)

## 漏洞分析

### 80端口

- robots.txt：无
- 网页信息
    - staff：**Angoose Garden**, Head of IT at Stockers Ltd.
    - Made by templatedeck.com
- 网页功能：无发现
- 网页源码：无发现
- 子域枚举
    - > Found: dev.stocker.htb Status: 302 [Size: 28] [--> /login]
- 目录枚举：由于发现子域，且是个登陆界面，所以似乎并不需要

#### 子域：dev.stocker.htb


- 网页源码
    - Hugo 0.84.0（搜了下似乎没漏洞）
    - bootstrap@5.0.2
    - name="username" placeholder="jsmith"
    - name="password" placeholder="Password"
- 目录枚举
    - > /stock &nbsp; &nbsp; &nbsp; &nbsp; (Status: 302) [Size: 48] [--> /login?error=auth-required]

 
*后来了解到似乎sqlmap似乎不能测试NoSQLi？而对于NoSQLi另有个[NoSQLMap](https://github.com/codingo/NoSQLMap) 0.0*  
*不懂了……然后看了眼官方论坛说[IppSec解说的Shoppy](https://www.youtube.com/watch?v=AJc53DUdt1M&t=220s)十分具有参考性 0.0*

#### 拦截、修改订单请求发现注入点

#### 下载、分析pdf订单



#### 动态PDF的XSS



## Initial Access

看了眼官方论坛，说可以看看 `/var/www/dev/index.js` 这个文件？不知道怎么知道要找这个文件的……


## flag: user

SSH连接后，获得用户flag：

```
└─$ ssh angoose@10.10.11.196
……
Last login: Sat May 27 18:56:20 2023 from 10.10.14.8
angoose@stocker:~$ id
uid=1001(angoose) gid=1001(angoose) groups=1001(angoose)
angoose@stocker:~$ ls
exploit.js  user.txt
angoose@stocker:~$ cat user.txt 
e014……850c
```


## Privilege Escalation

知道当前用户的密码，所以先看看 `sudo -l`：
```bash
angoose@stocker:~$ sudo -l
[sudo] password for angoose: 
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js
```

可以执行.js脚本，虽然看上去指定了目录，不过由于通配符，我们可以自由控制目录移动。


## flag: root

```bash
angoose@stocker:~$ sudo /usr/bin/node /usr/local/scripts/../../../home/angoose/exploit.js 
[sudo] password for angoose: 
a6c0……e3b1
```

---

## 总结·后记

2023/05/28

……

完全是js系列的靶机