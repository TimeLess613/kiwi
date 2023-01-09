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
