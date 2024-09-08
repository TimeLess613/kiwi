---
tags:
  - IT/网络
---
[https://infosecwriteups.com/server-side-request-forgery-to-internal-smtp-access-dea16fe37ed2](https://infosecwriteups.com/server-side-request-forgery-to-internal-smtp-access-dea16fe37ed2)

“SMTP 讨厌 HTTP”，因为由于 SMTP 服务器本身的限制，HTTP 无法走私(smuggle，携带)到 SMTP 中——将 HTTP 走私到 SMTP 是绝对不可能的，因为肯定会被拒绝，但是可以利用 Gopher 和 HTTPS 协议走私到 SMTP 协议，这样就可以解决这个问题了。

> [!NOTE] HTTPS 不支持像 gopher 那样的多行请求，因此如果您想通过 HTTPS 查询 SMTP，则需要 CRLF 注入漏洞。

## SMTP 查询的 Gopher 语法

`gopher://<Intranet_IP>:25/_<Command_SMTP>`

> [!NOTE] `<Command_SMTP>`前面的 `_`（下划线）表示gophertype
> 因此必须包含它，因为如果不包含该字符，则负载将被截断1个字符。例如负载为HelloWorld，如果`_`符号为不包含的有效负载将变成 ElloWorld..


