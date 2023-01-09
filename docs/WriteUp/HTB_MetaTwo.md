Waiting for machine retire...  

---

## 扫描

先用自己写的[这个脚本](./HTB_Shoppy.md#htb_easy_firstscaning)进行首先的基础扫描

- 开放端口：21, 22, 80
- 没发现子域


## 漏洞分析

21端口试了下匿名连接失败。  

22端口先不考虑。

### 80端口

- robots.txt
- 网页源码


#### W○○○○扫描

由于最开始没加参数漏了很多信息，


#### 研究网页功能

- 页面下方的搜索框。简单试了下SQLi、XSS似乎行不通
- 页面中央的链接 `http://metapress.htb/events/`。似乎是个注册、订阅events的东西。没发现有什么用 **（暂时）**




### PoC1（CVE-xxxx）



#### john暴破hash



#### 登陆WordPress

成功登入后第一想法就是找上传点，本来以为可以简单地传个php的webshell就行，不过这个网站的上传似乎不能传php。



### PoC2（CVE-xxxx）



## Initial Access
*get shell简介*

---




## flag: user





## Privilege Escalation
*提权简介*

---

john






## flag: root


---

## 后记

2022/12/22  
因为准备考CEH，上完课觉得以前的学习太过理论了，于是想着以实践复习一下，顺便冲一下Rank。  
至此，终于打完了5台Esay（Photobomb的WP没写），再打一台Medium就要脱离Script Kiddie，走向Hacker啦~

这台也是这段时间活跃的5台Easy里用户评价最难的一台。  
不过有了前几台的经验，似乎稍微领悟到一点套路，于是WP的格式也逐渐改善，最后定下一个大体上的[WP模板](../WriteUp/WriteUp_template.md)。  
一是方便今后写WP，另一个是提醒自己把握渗透流程，时刻都要明白自己处于哪个阶段、目的是什么。