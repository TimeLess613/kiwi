---
tags:
  - IT/网络
  - IT/蓝队
---
> https://github.com/nicanorflavier/spf-dkim-dmarc-simplified
> - **Phishing Attacks** → SPF
> - **Brand Impersonation** → DKIM
> - **Business Email Compromise (BEC)** → DMARC

例子：
> 如果银行没有实施 SPF/DKIM/DMARC，攻击者冒充该银行发送钓鱼邮件，而邮件可能会**通过收件服务器的检查并进入用户的收件箱**。用户则认为该电子邮件来自他们的银行。


SPF/DKIM/DMARC 都算是用于验证发信人的正当性。

## SPF

> Sender Policy Framework

算是一个授权/许可清单，指定谁可以代表我/域发送邮件。别人（收件方）可以来查看我的清单确认邮件的发件人是否有我的授权。

在DNS的[[DNS#TXT|TXT记录]]中定义。格式通常如下：
```
v=spf1 ip4:123.123.123.123 ~all
```
> Here's the command I usually run to fetch that:
```
dig TXT example.com
```

> [2. What's the difference between ~all, -all, ?all, and +all in an SPF record?](https://github.com/nicanorflavier/spf-dkim-dmarc-simplified?tab=readme-ov-file#faqs-with-spf-dkim-and-dmarc)

## DKIM

> Domain Keys Identified Mail

还是应用公钥基盘——在TXT记录中发布公钥，发信时在里面添加一段摘要（私钥签名）。收件方可以查找送信方DNS的公钥确认邮件是否被篡改。

[[DNS#TXT|TXT记录]]中的格式通常如下：
```
v=DKIM1; k=rsa; p=NICfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBolTXCqbxwoRBffyg2efs+Dtlc+CjxKz9grZGBaISRvN7EOZNoGDTyjbDIG8CnEK479niIL4rPAVriT54MhUZfC5UU4OFXTvOW8FWzk6++a0JzYu+FAwYnOQE9R8npKNOl2iDK/kheneVcD4IKCK7IhuWf8w4lnR6QEW3hpTsawIDAQ0B"
```
> Here's the command I usually run to fetch that:
```
dig TXT selector1._domainkey.example.com
```


> [https://milestone-of-se.nesuke.com/l7protocol/smtp/dkim-spf-senderid/](https://milestone-of-se.nesuke.com/l7protocol/smtp/dkim-spf-senderid/)



## DMARC标准

> Domain-based Message Authentication Reporting and Conformance

结合了（DNS的）SPF或DKIM。它允许域名所有者设置一个策略，指示接收邮件服务器如何处理未通过 SPF 和 DKIM 验证的邮件。比如发送报告。

[[DNS#TXT|TXT记录]]中的格式通常如下：
```
v=DMARC1; p=none; rua=mailto:postmaster@example.com
```
> Here's the command I usually run to fetch that:
```
dig TXT _dmarc.example.com
```


