---
tags:
  - 渗透/武器库
  - 渗透/信息收集
---

## 基本用法

> 搜索 LDAP 的最简单方法是使用带有 `-x` 选项的 `ldapsearch` 进行简单身份验证，并使用 `-b` 指定搜索库。

`$ ldapsearch -LLL -x -H <ldap_host> -D <bind_dn> -w "pw" -b <base_dn> "(<object_type>)=(<object_value>)" <optional_attributes>`

- 上述构造式优点：只用修改最后两部分
- `()` 括号处为过滤表达式，可以不要
- 可先查当前账户的LDAP树：`(sAMAccountName=username)`
- `optional_attributes`：需要返回的属性。如用`*`、`dn`


### 例子

![[Pasted image 20240908153829.png]]


## 选项

| 选项   | 简介                                                                                                                                                                                                                                 |
| ---- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| -x   | 使用简单认证，而不是[[SASL]]。<br><br>如果允许匿名登录，也可以不输入账号密码（即省略-D和密码选项）                                                                                                                                                                         |
| -b   | ![[LDAP#Base DN]]<br><br>有默认，但是不知道是啥？`base`的话即[[ldapsearch#RootDSE]]                                                                                                                                                               |
| -H   | 格式为“ldap://hostname-or-ip:port”<br><br>- 算-h和-p的合并<br><br>如果您不直接在 LDAP 服务器上运行搜索，则必须使用“-H”选项指定主机<br><br>如果您的服务器接受匿名身份验证，您将能够在不绑定管理员帐户的情况下执行 LDAP 搜索查询                                                                               |
| -D   | ![[LDAP#Bind DN]]<br><br>**不用这个就是匿名登陆**。服务器将忽略该值。<br><br>然而在某些情况下，您可能希望以管理员帐户运行 LDAP 查询，以便向您显示其他信息。为此，您需要使用 LDAP 树的管理员帐户发出绑定请求。`-D` 和 `-W` 选项执行 `ldapsearch` 查询，以便提示输入密码。<br><br>当以管理员帐户运行 LDAP 搜索时，您可能会接触到用户加密的密码，因此请确保您以私密方式运行查询 |
| -W   | 【密码-交互式】簡易認証のためのプロンプトを出す（与 `-w` 2选1）                                                                                                                                                                                               |
| -w   | 【密码-直接指定】簡易認証のためのパスワードを指定（与 `-W` 2选1）                                                                                                                                                                                              |
| -y   | 使用密码文件。<br>实践中有不生效的时候。代替方案：可以用 `cat` 子命令传递文件内容等。                                                                                                                                                                                   |
| -L   | 検索結果を LDAP データ交換フォーマット(LDIF) で表示する                                                                                                                                                                                                 |
| -LL  | コメントアウト行を出力しない                                                                                                                                                                                                                     |
| -LLL | LDIF バージョンを出力しない                                                                                                                                                                                                                   |
| -t   | write binary values to files in temporary directory                                                                                                                                                                                |
| -o   | output文件名                                                                                                                                                                                                                          |

- LDIF（LDAP 数据交换格式）将目录内容定义为一组记录。它还可以表示更新请求（添加、修改、删除、重命名）
	- 几个L没太大差别。可以直接 `-LLL`。



## RootDSE

```
# RootDSE
ldapsearch -h ldap-srv -p port -s base -b "" objectclass="*"

# 如果只想获取域名信息，经过实践可简化为：
ldapsearch -x -H ldap://<ldap-srv> -s base namingcontexts
```



## LDAP过滤器

- 基础：[win32/adsi/search-filter-syntax](https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax)
- 应用实例：
	- [active-directory-ldap-syntax-filters.aspx](https://qa.social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx)
	- [an-introduction-to-manual-active-directory-queryingwith-dsquery-and-ldapsearch](https://posts.specterops.io/an-introduction-to-manual-active-directory-queryingwith-dsquery-and-ldapsearch-84943c13d7eb)
- 有用集合：[useful-ldap-queries-for-windows-active-directory-pentesting/](https://podalirius.net/en/articles/useful-ldap-queries-for-windows-active-directory-pentesting/)
	- `ldapsearch "(&(objectClass=user)(memberof:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,DC=J,DC=DS,DC=NIC,DC=COM))" *,ntsecuritydescriptor -1 ad.j.ds.nic.com`

### 语法

LDAP 过滤器具有一个或多个子句，每个子句都用括号括起来。每个子句的计算结果为 True 或 False。 LDAP 语法过滤子句采用该形式：`(<AD Attribute><comparison operator><value>)`

- `AD Attribute`：即AD属性
- `comparison operator`（不支持仅用">"和"<"）
	- =：Equality
	- >=：Greater than or equal to (lexicographical)
	- <=：Less than or equal to (lexicographical)
- `value`
	- 不区分大小写（not case sensitive）
	- 且不应加引号！！
	- 允许通配符，除了DN属性
		- 使用通配符的另一个好处是您可以使用部分单词来模糊您要查找的内容。例如，您可以搜索 `*sword*` 或 `*minis*` ，而不是搜索 `password` 或 `administrator` 。
	- DN属性只能用等号运算符，不应将DN值放在括号中

#### 布尔运算符

- &
- |
- !

#### 5个特殊字符（需要“反斜杠+两个字符的ASCII 十六进制表示”转译）

- `*`：`\2A`
- `(`：`\28`
- `)`：`\29`
- `\`：`\5C`
- `Nul`：`\00`



## 踩坑

用 `域\账户` 时报错：
```
ldap_bind: Invalid credentials (49)
        additional info: 80090308: LdapErr: DSID-0C090436, comment: AcceptSecurityContext error, data 52e, v23f0
```

解决：  
用 `账户@域` 的形式。




## 参考资料

> https://devconnected.com/how-to-search-ldap-using-ldapsearch-examples/