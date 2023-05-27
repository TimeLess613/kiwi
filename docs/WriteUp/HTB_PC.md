**Waiting for machine retire...**

*Difficulty: Easy*


---

## 扫描

一开始惯例只扫了1-10000端口，发现只有22就感觉不对。于是索性扫了全TCP和UDP端口。结果只有TCP端口开放了。

- 22
- 50051

## 漏洞分析

### 50051端口

谷歌了一下似乎是gRPC的默认端口。

在群里师傅的提点下了解到了 `grpcui` 这个工具，不过没咋弄懂……  
倒是给我打开了思路。就像postman，原来找到和grpc服务器交互、调试的方法就好，于是谷歌搜了下“grpc debug”，在[这篇文章](https://medium.com/@EdgePress/how-to-interact-with-and-debug-a-grpc-server-c4bc30ddeb0b)中看到许多工具。  


#### grpcurl枚举信息


#### grpcurl调用方法


#### grpc登陆的admin账户



#### 发现SQLi


#### 暴库





## Initial Access



## flag: user

```bash
sau@pc:~$ pwd
/home/sau
sau@pc:~$ ls
snap  user.txt
sau@pc:~$ cat user.txt 
4eef…………0835
```


## 探索


### 本地端口8000：pyLoad




## Privilege Escalation



## flag: root

```bash

root@pc:~/.pyload/data# cat /root/root.txt
cat /root/root.txt
bec6…………7110
```


---

## 总结·后记

2023/05/25
……