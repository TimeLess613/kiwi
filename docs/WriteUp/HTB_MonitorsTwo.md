Waiting for machine retire...

考完CEH，久违地回来打一打靶。都有点忘了怎么操作了……

---

## 扫描

```
sudo nmap -n -Pn -sS -p 1-10000 --min-rate=5000 10.10.11.211
sudo nmap -v -n -Pn -sV -O -p 22,80 --script=vuln 10.10.11.211 -oA 10.10.11.211
```

*不知道为什么这次NSE脚本扫描非常非常慢，然后其实也没太多有用的信息。*

- 22
- 80


## 漏洞分析

### 80端口


## Initial Access


#### 方法1：ExploitDB 脚本


#### 方法2：metasploit


## docker容器


### SUID提权（不需要）


### 探索DB


### 密码暴破


## flag: user



## Privilege Escalation


### 探索



## flag: root


---

## 总结·后记

2023/05/15

虽然也有卡住的地方，但是总体来说确实不难。  
初始访问很容易就能顺着web服务的版本号去找exp，不过还是感受到了自己这个脚本小子的水平，拿着exp就想直接用，没太考虑了解漏洞原理。不过自己确实web方面较弱，代码的阅读量也少，感觉看CVE文章啃很久都不一定反应过来原来是用X-Forwarded-For等于环回IP去绕过验证。

一开始在kali搜漏洞的时候没搜出来觉得很奇怪，才想起来应该是有个数据库之类的需要更新？于是也顺便更新了ExploitDB和metasplit：

- `searchsploit -u`
- `apt update; apt install metasploit-framework`

然后就是docker容器，最初进去的时候想看IP发现没有安装`ifconfig`命令，然后搜了些替代命令如`ip a`也没有。直接开摆，要不是偶然连上Meterpreter跑了下`sysinfo`，也不知道自己会过多久才发现身处容器中……  
以及一直都是走一步想一步，由于没有好好地探索信息而被骗进兔子洞，白白在docker里拿了没用的root权限。

最后一个提权的利用实际上不难。感觉所有难点都在如何发现那条提示……SSH登陆后的信息，一直以来都是无视的啊……这台机器的创作者简直就是利用了人的这个习惯（笑）。以及如官方论坛有人说的那样，“What happens in Vegas does not always stay in Vegas”，有点意思。

总的来说，信息收集要仔细！