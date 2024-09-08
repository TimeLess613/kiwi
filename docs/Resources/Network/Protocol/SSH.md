---
tags:
  - IT/网络
  - 渗透
---






## know_hosts和authorized_keys


- know_hosts: 自己登录过的主机。
- authorized_keys: 允许登录自己的主机，其中加入许可的公钥——[[SSH#密钥登陆]]




## 连接流程


### 一般

1. 我的机器（本机）连接SRV
2. 本机跳提醒——不认识这个SRV的指纹（公钥的哈希），是否连接
3. 所有连接过的公钥指纹都存在本机的 `~/.ssh/know_hosts` 文件
	- 目标公钥和本机存档不匹配的情况下会跳警告。


### 密钥登陆

1. 别人连我，请求ssh登录
2. 我看 `authorized_keys` 文件里有没有他的公钥，有就用他的公钥加密随机数口令发回去
3. 别人用自己的私钥解密
4. SRV公钥解密对比——完成验证


### 证书登陆

[[SSH#首先需要生成证书：]]

流程：

1. 用户请求登录SRV，ssh自动把用户证书发给SRV
2. SRV检查证书&是否由可信的CA颁发
3. 没问题的话ssh自动把SRV证书给用户
4. 用户检查
5. 双方建立连接，SRV允许用户登录


## 配置密钥登陆

免密码输入

### 生成密钥

客户端用`ssh-keygen`生成自己的密钥对：`ssh-keygen [-t rsa -b 2048 -f keypair]`

- -t：默认rsa。
	- rsa：非对称，能加/解密签名
	- dsa：对称，只能用来签名
- -b：密钥长度（bits）。如RSA算法就是其模数（n）的长度。
- -f：指定输出文件（私钥）名，公钥为添加`.pub`后缀。

### 配置使用

将客户端的公钥放入远程SRV的指定位置（`~/.ssh/authorized_keys`）

#### 手动

`$ cat ~/.ssh/id_rsa.pub | ssh user@host "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"`

#### 自动

`$ ssh-copy-id -i pubkey_file user@host`

- 会提示输入目标host的密码
- 注意：目标host的`authorized_keys`需要以换行符结尾。因为该命令直接将公钥添加到目标host的`authorized_keys`文件的末尾，如果该文件本身不是以换行符结尾，将导致格式错误而配置无效。




## 配置证书登陆

证书即[[公钥证书]]

> https://www.ruanyifeng.com/blog/2020/07/ssh-certificate.html

密钥登陆的缺点：服务端需要保存用户公钥，客户端也要保存服务端公钥指纹。对于大型组织来说不便管理，如员工离职后还需要将其公钥从每台服务器中删除。  
证书登陆就是为了解决上述问题。  

引入CA，对信任的服务器颁发**服务器证书**，对信任的用户颁发**用户证书**。  
登录时，用户和服务器不需要提前知道彼此的公钥，只需交换各自的证书，验证是否可信即可。

主要优点：

- 双方不用交换公钥
- 证书可配置有效期，而公钥不行

### 首先需要生成证书

1. 用户和SRV都将自己的公钥给CA（CA本质上是一对密钥，CA就用这对密钥去签发证书。实际上有分SRV用/用户用）
2. CA给各自的公钥签名以颁发对应的证书（服务器证书、用户证书）
3. SRV和用户之后还要安装证书和CA签发证书的公钥



## [[SSH Tunneling]]


---
## ssh配置

### sshd

`/etc/ssh/sshd_config`

```bash
# 允许root用ssh登陆：
#PermitRootLogin prohibit-password
PermitRootLogin yes

# 允许公钥认证
PubkeyAuthentication yes
```

配置修改后重启sshd服务。


### 详细控制

如不同目标自动用不同秘钥进行连接：
```bash
# cat .ssh/config
Host *
IdentityFile ~/.ssh/id_rsa

Host 10.10.10.10（域名也行，也能用通配符）
IdentityFile ~/.ssh/id_rsa_git
```
