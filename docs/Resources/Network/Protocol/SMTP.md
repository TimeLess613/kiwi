---
tags:
  - IT/网络
---


客户端用SMTP将邮件发送到服务器。

## SMTP命令

> [!NOTE] 连接SMTP服务器：可用telnet或nc连接25、587端口。
> - `telnet` 客户端把所有键盘输入，包括控制字符，都当作会话数据发送给远端服务器，而不是在本地处理——断开连接用 `QUIT` 命令。
> ---
> - **587端口**：被定义为邮件提交端口（MSA，Mail Submission Agent），专门用于客户端向邮件服务器提交邮件。这是IETF（互联网工程任务组）推荐的标准做法（详见RFC 6409）。端口587比25多了`STARTTLS`功能。
> - **25端口**：虽然仍然是标准的SMTP传输端口，但主要用于服务器之间的通信，不推荐用于客户端提交邮件。
> ---
> - 在使用 `MAIL FROM` 和 `RCPT TO` 命令时，需要用尖括号 `<>` 括住电子邮件地址。这是SMTP协议的规范做法，确保电子邮件地址被正确解析。

EHLO是HELO的扩展，所以能有更多命令。如认证。
认证信息需要用base64编码。
```
└─$ telnet 10.10.11.14 25 
Trying 10.10.11.14...
Connected to 10.10.11.14.
Escape character is '^]'.
220 mailing.htb ESMTP
EHLO mailing.htb
250-mailing.htb
250-SIZE 20480000
250-AUTH LOGIN PLAIN
250 HELP
AUTH LOGIN
334 VXNlcm5hbWU6
QWRtaW5pc3RyYXRvckBtYWlsaW5nLmh0Yg==
334 UGFzc3dvcmQ6
aG9tZW5ldHdvcmtpbmdhZG1pbmlzdHJhdG9y
235 authenticated.
MAIL FROM:<Administrator@mailing.htb>           
250 OK
RCPT TO:<maya@mailing.htb>
```


![[Pasted image 20240328000245.png]]
- 注意：上面说的email address都是指信封的。而信的内容是DATA，且本身信件的抬头和署名也算是信件的内容。
- 但一般，From和To是设置到MUA中的。
![[Pasted image 20240328000312.png]]


### 枚举用户

#渗透/信息收集 

![[Pasted image 20240328000406.png]]
- EXPN - shows the actual delivery addresses of aliases and mailing lists




## 枚举工具

- NetScanTools Pro：SMTP Email Generator，可通过SMTP服务器测试Email发送
- smtp-user-enum ：通过SMTP服务（sendmail），枚举Solaris的OS level的账户
- Telnet



