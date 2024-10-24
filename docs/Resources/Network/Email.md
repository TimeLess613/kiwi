---
tags:
  - IT/网络
---

## 端口

[Email-client-protocols-and-port-numbers](https://help.dreamhost.com/hc/en-us/articles/215612887-Email-client-protocols-and-port-numbers)

### [[SMTP]]

发送。

- 25：已过时且不推荐。如果使用此端口，必须启用用户名/密码身份验证。
- 465：启用SSL功能。
- 587（据说比25更常用）：MSA（message submission agent）。虽然是不安全传输，但可以使用 STARTTLS 升级为安全连接。

### POP3

下载、删除。

- 110：未加密
- 995：加密（SSL，下同）

### IMAP

将邮件存储在服务器上并同步多个设备之间的协议。

- 143：IMAP4 Unencrypted
- 993：IMAP4 Encrypted




## 两种方式访问Email

- Email客户端：如Outlook。
- WebMail：如GMail。使用的不是POP3/IMAP，而是HTTPS。


## 实现Email的各个功能组件

### 用户端

MUA（User）：收发信件。如Outlook等的Email客户端。

### 服务端

MTA（Mail Transfer Agent）：[[SMTP]]服务器。可看做MailSrv间最主要的功能，在各服务器间转发信件。如Postfix、Exchange服务器。
端点MailSrv另有：
- MSA（Submission）：受理客户端发信、用户认证。如Postfix、Exchange服务器
- MDA（Delivery）：放入MailBox。如mail.local、Qpopper
- MRA（Retrieval）：取出信件、用户认证。如Qpopper、uw-imap【POP、IMAP】

## 流程

MUA——MSA——MTA——MTA(边界网关)——MTA——MDA—（MailBox）—MRA——MUA

- 收信方的MTA信息（域名、IP等）都注册在收信方DNS的MX记录、A记录。所以发信方的MTA可以根据这个信息发送信件到对方MTA。

详细： [https://mailtrap.io/blog/smtp-commands-and-responses/#Essential-SMTP-commands-in-the-order-they-may-be-used](https://mailtrap.io/blog/smtp-commands-and-responses/#Essential-SMTP-commands-in-the-order-they-may-be-used)

1. 查MX
2. 建立TCP连接（netcat或telnet）
3. `HELO`或`EHLO`命令，向MailSrv提供**自己的域名**
4. `MAIL FROM`命令，向MailSrv提供**发件人地址**
	SMTP是一个很简单的协议，本身没规定如何验证邮件来源。后来MailSrv用的方法：
	- 查MX
	- DNS反向解析（memo：nslookup -qt=ptr ）
	- 验证邮件地址是否存在
	- ……
5. `RCPT TO`，验证邮件地址是否存在
6. `QUIT`命令，关闭TCP连接





## Email报头

> [!NOTE] 参照[[SMTP#SMTP命令|SMTP命令]]更容易理解

### MAIL FROM (Envelope From)

SMTP服务器地址——相当于信封。

- 用户是看不到信封的 `MAIL FROM` 的——这是给SMTP服务器看的，用于SMTP服务器之间转发——**报头的 `From` 字段**
- 容易伪造——所以有[[Email安全#SPF|SPF]]或[[Email安全#DKIM|DKIM]]等防御技术
	- SPF：向对方DNS确认这个地址是否来自指定IP
	- DKIM：验证公钥签名
- 送信失败的话发回给这里，并发送non-delivery report (NDR)

### From (Header From)

邮件客户端（Mailer）上显示的发件人——相当于信件抬头，其实算是信件内容了——可随意伪造，所以才要验证。

### Received：经由的MailSrv

- 最上面的received是收信人的MailSrv
- 最下面的received是送信人的MailSrv，可以whois，判断spam
	- **from：送信MailSrv【`HELO`命令】**
	- **by：收信MailSrv**
	- with：mail传输协议
	- **for：收信人mailaddr【`RCPT TO`命令】**
	- id：MailSrv的ID
	- via：经过地的环境&协议

### Return-Path：发信失败时的返回地址

- 一般，给Envelope From（即由 `MAIL FROM` 命令通知的发信人），不过也可以用Return-Path特别指定。
- 优点：管理送信失败mail（弹回邮件，一直对不可送达的目的地发信的话，影响信誉）

### Reply-To：（点击）回信的地址




## 关于raw data（MIME数据）

### 报头：Encoded-Word格式

> 邮件标题（Subject）和其他头部字段（如发件人、收件人等）通常使用 **MIME 编码**（如 =?UTF-8?B?...?=。有Base64或Quoted-Printable）来处理特殊字符或非 ASCII 字符。**这种编码方式被称为“Encoded-Word”格式**，定义在 MIME（多用途互联网邮件扩展）标准中。
> Encoded-Word 格式允许邮件头部字段包含非 ASCII 字符，如中文、日文、韩文等字符。这种格式通常以 =?charset?encoding?encoded text?= 的形式出现，其中：
> - charset 是字符集，如 UTF-8、ISO-8859-1 等。
> - encoding 是编码方式，通常是 B （表示 base64 编码）或 Q （表示 quoted-printable 编码）。
> 	- 等号（“=”）用作称为“引用打印（Quoted-printabl）”的编码机制的一部分。是一种用于以主要为电子邮件设计的文本格式表示不可打印或特殊字符的方法。
> - encoded text 是按照指定的字符集和编码方式编码后的文本。


> 在 Python 中，使用 `email.header.decode_header()` 函数时，通常不需要指定编码格式。`decode_header()` 函数的目的是解码邮件头部字段中的 MIME 编码（Encoded-Word）文本，它会自动处理编码和字符集的识别。 #IT/Python 


### 正文

- 编码：`Content-Transfer-Encoding` 报头指定邮件正文（body）的编码方式。
- 字符集：邮件正文的字符集通常在 `Content-Type` 头部字段中指定。




## IMF?

[The syntax for email messages is known as the Internet Message Format](https://datatracker.ietf.org/doc/html/rfc5322)



## 钓鱼

- Defang：如在URL、IP的点两边加上中括号，`[.]`。 #IT/蓝队 
- Pixel tracking： [email-pixel-trackers-how-to-stop-images-automatic-download](https://www.theverge.com/22288190/email-pixel-trackers-how-to-stop-images-automatic-download)