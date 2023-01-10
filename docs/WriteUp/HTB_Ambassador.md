Waiting for machine retire...  

---

## 扫描

果然用之前写的[对Easy机器的扫描脚本](../WriteUp/active_HTB_Shoppy.md#htb_easy_firstscaning)不大好使了啊……  
自己 `curl -I` 看了眼HTTP响应头真没有域名信息。开浏览器和Burp访问一下目标IP，竟然没有拦截到请求（不过访问 `/robots.txt` 又能拦截）？不是很懂……

还是先回到通常的流程吧，先进行扫描。  
以防Medium难度的机器会开启大端口，就扫一下所有端口吧：
```
$ nmap -p- --min-rate=5000 10.10.11.183 -oN allPortScan.nmap

$ cat allPortScan.nmap | grep open | awk -F '/' '{print $1}' | tr '\n' ',' | sed "s/,$//" 
22,80,3000,3306
```

然后详细扫描这几个open端口：
```
sudo nmap -v -n -Pn -p 22,80,3000,3306 -sV -O --script=vuln 10.10.11.183 -oN 10.10.11.183.nmap
```


## 漏洞分析

- 22/TCP: SSH优先度最低，先不看。
- 80/TCP: HTTP，优先度1。
- 3000/TCP: nmap扫出“ppp?”，不过看vuln脚本扫出HTTP头的样子，优先度2。
- 3306/TCP: MySQL，估计有了账号密码之后是另一个突破口，优先度3。


## Initial Access

## flag: user



## Privilege Escalation

惯例收集几个基础信息：  

- sudo：无sudo执行权限
- SUID：粗略看了几个短的命令不像是能利用的  
- 用户家目录：有 `.gitconfig` 文件。

### 探索git


## flag: root

### 方法一：Github上的exp脚本



### 方法二：metasploit+端口转发


---

## 后记

2022/12/25  
竟然在年内打完这台啦，不愧是Medium里用户评分最简单的一台www  
也算是赶上了好时候，一直都是只敢玩玩THM，（大概一年前左右刚入门时玩了一下HTB完全不懂严重受挫于是没想着自己能打HTB……）12月初因为各种契机，开始琢磨着捡起号玩玩HTB时看到有这台似乎较简单的Medium，又看了下Rank的计算就是打6台升到Hacker。于是12月有空就打靶，功夫不负有心人吧！

也该准备准备复习CEH了。等考完继续愉快打靶~


2022/01/10  
补充了一下方法二（metasploit+端口转发）。  
主要是想弄清为什么打靶过程中用metasploit失败了，之前琢磨着应该是要做个端口转发。如果想法正确，那么正好可以借此验证一下，顺带着把端口转发的理论知识转化为实践。
结果实验成功~