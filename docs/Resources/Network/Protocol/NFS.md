---
tags:
  - 渗透/信息收集
  - IT/网络
---
2049/TCP

- NFS：网络文件系统
- NFS通常与Unix系统一起用


## 工具

### RDPScan

（简单扫描，check共享配置错误）

关于为什么是RDP扫描：  
> [Portmapper](https://en.wikipedia.org/wiki/Portmap) 和 [RPCbind](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/storage_administration_guide/s2-nfs-methodology-portmap) 都在 TCP 端口 111 上运行。  
> RPCbind 将 RPC 服务映射到它们所监听的端口。 RPC 进程在启动时通知 rpcbind，注册它们正在侦听的端口和它们期望服务的 RPC 程序编号。  
> 然后，客户端系统使用特定的 RPC 程序编号联系服务器上的 rpcbind。  
> rpcbind 服务将客户端重定向到正确的端口号（通常是 TCP 端口 2049），以便它可以与请求的服务进行通信。


### nmap

![[Pasted image 20241028221136.png]]


### Filesnarf

是专门为 NFS 而设计的，它将从 NFS 流量中嗅探到的文件保存到当前工作目录中。