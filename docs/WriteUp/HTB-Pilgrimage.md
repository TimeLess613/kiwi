**Waiting for machine retire...**

*Difficulty: Easy*

---


## Summary



### Attack Path Overview




## 扫描

自用扫描脚本：[工作流](./HTB-Busqueda.md#workflow-scan)

开放端口：
```
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    nginx 1.18.0
```


## 攻击路径规划·漏洞分析

常规简单靶机，22端口SSH的版本较新，优先度放低。先看80端口的Web。


## 80端口

- robots.txt：无
- 网页信息：“Design: TemplateMo”，查了下没啥特别的感觉
- 网页功能：将上传的图片缩小
- 网页源码：无特别发现
- 子域枚举：无特别发现
- 目录枚举：无特别发现

### 研究网页功能

是个能将上传的图片缩小的网站。  
因为有上传所以尝试了好久上传绕过，看看能不能传个webshell啥的。不过以失败告终。

能注册以及登陆，所以也尝试了SQLi。不过也以失败告终。  
用注册的号登陆进去的话，也只是会将上传历史列出来。

又想起来如[HTB-Stocker](./HTB-Stocker.md)那样，下载通过网页生成的pdf，可用 `exiftool` 工具分析生成器是否有漏洞。  
于是上传图片后下载，但是没有找到图片是用什么工具转换的，也无其他特别信息。

### .git泄露



## Initial Access

### PoC (CVE-2022-xxxxx)



#### 获取SQL数据库文件



#### 获得用户凭据



## flag: user

SSH连接后获得用户flag：
```bash
└─$ ssh emily@10.10.11.219
……
emily@pilgrimage:~$ id
uid=1000(emily) gid=1000(emily) groups=1000(emily)
emily@pilgrimage:~$ cat user.txt 
468e…………5945
```


## 探索

基础探索一把梭：

- 有当前用户的凭据所以先看了眼 `sudo -l`：没有sudo可执行
- SUID：无特别发现
- cron：有个php引人注目，不过内容是清理会话。也无其他特别发现
- 注意到emily的家目录有 `.gitconfig`，而我们就是通过.git泄露进来的，估计没什么其他有用信息了。姑且确认了一下，里面只写了git项目的文件路径
- emily的家目录还有个 `.config`，里面有个binwalk。这个好像是分析二进制的工具




## Privilege Escalation

### PoC (CVE-2022-xxxx)
 




## flag: root


---

## 总结·后记

2023/06/26

这次是.git泄露啊，还是第一次听说。所以网站根目录下不能放.git文件夹。  
以及后来看了一下各个目录暴破的字典，都没有看.git下的文件的。看来以后也需要将其作为一个攻击向量，在最开始就一并尝试。