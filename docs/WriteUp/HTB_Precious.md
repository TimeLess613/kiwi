Waiting for machine retire...

---

## 扫描

```bash
ports=$(nmap -n -Pn -sS  -p- <ip> --max-retries=1 | grep ^[0-9] | cut -d / -f1 | tr '\n' ',' | sed s/,$//)
nmap -v -n -sC -sV -p ${ports} <ip> -oN Precious.nmap
```


## 漏洞分析

22端口（openssh 8.4p1 debian 5+deb11u1 (protocol 2.0)）找了一下似乎无漏洞。

### 80端口

访问网页无显示，URL会跳转到 `precious.htb`，将其加入hosts文件后即可访问。

- 无robots  
- 网页源码无发现  
- 目录枚举无发现  
- 网页功能似乎是将网页转pdf  

#### 研究网页功能

尝试几个网址无特别反应，似乎一定要 `http://` 或 `https://` 开头，且一直报错说不能用remote URL。

*迷茫……看了眼Forum说既然不能用remote那可以试试local……*

尝试本地用python开启http服务，随便建立一个文本，回到网页输入自己的URL。  
会弹网页新标签显示刚刚文本的pdf。  
又试了下将文本改为html，里面插入js的 `alert(1)`。再次访问，弹出pdf顺便js也有反映。不过XSS不大熟，止步于此……

*看Forum的提示，似乎要下载pdf看看属性。*

下载pdf，属性里没找到啥。  
`strings` 命令看到 **pdfkit**，搜了下有[PoC](https://security.snyk.io/vuln/SNYK-RUBY-PDFKIT-2869795)。
        
尝试 `` http://<ip>/?name=#{'%20`sleep 5`'} ``。有效，5秒后会直接显示web根目录下的内容。  


## foothold

### 升级为交互式shell


## get user flag

## 提权

`sudo -l` 一般是我首先会尝试的。  

### PoC

### 方法1：sudo反弹root shell

### 方法2：给bash命令添加SUID

### 方法3：命令执行




## get root flag

---

## 后记

2022/12/4  
其实算是第一次正经打HTB，以前稍微试了下还是觉得Web渗透知识不够的话有点难。  
主要是看这两天群友讨论Precious，然后也有大佬们给出提示，所以想着既然有提示那么我也想要尝试一下……  

想想这个靶机打了好几个小时，还是有点超出自己的实力范围了。不过回顾起来又觉得其实没那么难，很多知识都有接触过，还是实战经验太少了吧。  
围观群里讨论也学到了很多细节，比如get shell前应该先判断环境（如用 `which python python2 python3`）。自己这次就是乱试了几个偶然用python3反弹到了。  

不过[pdfkit这个PoC](https://security.snyk.io/vuln/SNYK-RUBY-PDFKIT-2869795)的命令执行似乎有限，有些命令并无/或者自己不知道哪里有回显（如 `id`）。后来搜wp时发现[另一个类似的注入方式](https://0xdedinfosec.vercel.app/blog/hackthebox-precious-writeup)（`` http://10.10.XX.XX/?name=%20`id` ``），在用local URL时会在网页回显。  
也不知道为何明明看的是同一个[pdfkit这个PoC](https://security.snyk.io/vuln/SNYK-RUBY-PDFKIT-2869795)，为什么会想到把 `#{}` 删掉……