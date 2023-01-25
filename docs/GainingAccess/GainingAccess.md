## 方法

- 漏洞利用
- 密码破解


## 漏洞利用

- 参考漏洞网站


## 密码破解

没漏洞时，找认证服务获取访问权。所以：破解密码。

- 为什么成功：弱密码（ → 人的弱点）

### 理解认证协议

### 密码攻击的类型

#### 非电子/非技术攻击

- 社会工程：问
- ショルダー サーフィン（shoulder surfing）：偷看
- ダンプスター ダイビング（dumpster diving）：找纸上记录

#### 主动online攻击

不太使用，易被检测、暴露IP、速度慢（上限为网速，所以用offline）、账户被锁定

- 暴破、推测、字典
- 木马、键盘记录
- LLMNR/NBT-NS毒化：类比ARP毒化
- Hash Injection（Pass the Hash）：因为是将hash注入到本地会话中
- Internal Monologue（内部独白）：利用应用程序的SSPI调用NTLM认证，用如彩虹表等工具破解NetNTLM响应获得hash（之后便可PtH）
- Kerberos密码攻击
    - 针对TGT：AS-REP Roasting
    - 针对TGS：Kerberoasting

#### 被动online攻击

- 中间人攻击。较难落地
- 反射攻击

#### offline攻击

- 彩虹表
- 默认密码查询（都未尝试过，很多时候直接谷歌/文档）
    - <https://www.fortypoundhead.com>
    - <https://cirt.net>
    - <https://www.routerpasswords.com>
    - <https://default-password.info>

密码加盐：在明文密码里加入随机字符后再计算hash。由系统加的所以攻击者难以入手。不过Windows认证系统不会加盐。