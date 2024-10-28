---
tags:
  - 渗透/信息收集
  - IT/网络
---
## 远程过程调用

- RPC是一种特定类型的IPC（进程间通信，Interprocess Communication）技术。可实现分布式系统。
- 存根（Stub）是一种用于实现RPC的关键组件。存根充当本地进程和远程进程之间的代理，它们分别存在于客户端和服务器端。
- 通过使用存根，RPC 可以将本地过程调用（函数调用）在客户端和服务器之间进行透明的通信，使得客户端能够像调用本地函数一样调用远程过程，而不必关心通信细节和网络传输。存根的存在简化了远程过程调用的实现，使得分布式系统中的进程能够进行互相之间的通信。


## How RPC Works

[https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc738291(v=ws.10)?redirectedfrom=MSDN](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc738291(v=ws.10)?redirectedfrom=MSDN)

基本上RPC可以理解为：

1. 客户端和服务器都有相同的函数接口的声明，包括函数名称、参数列表和返回值类型。
2. 当客户端想进行RPC时，通过客户端存根（Client Stub）这个本地代理，它知道如何将本地函数调用转换为网络消息，并将消息发送给服务器。客户端存根会在消息中包含函数的标识符（IFID）、参数和其他相关信息。
3. 而服务器存根接收、解析请求，找到对应IFID和参数，然后调用服务器上的对应函数，将运行结果返回。


### IFID："Interface Identifier"（接口标识符）

- 可用rpcdump枚举IFID
- 著名IFID： [https://book.hacktricks.xyz/network-services-pentesting/135-pentesting-msrpc#notable-rpc-interfaces](https://book.hacktricks.xyz/network-services-pentesting/135-pentesting-msrpc#notable-rpc-interfaces)

## 4种协议序列访问RPC locator service

- ncacn_ip_tcp and ncadg_ip_udp (TCP and UDP port 135)
- ncacn_np (the \pipe\epmapper named pipe via SMB)
- ncacn_http (RPC over HTTP via TCP port 80, 593, and others)

协议序列：用于标识和指定 RPC 通信使用的底层传输协议的标记。（protocol指抽象的通信协议）

### ncacn：Network Computing Architecture Connection Network

- Network Computing Architecture（网络计算架构，简称NCA）是由 Open Software Foundation（OSF）开发的一种分布式计算架构。在 NCA 中，RPC 是一种通信模式，允许在分布式计算环境中的不同进程之间进行通信，使得它们可以像调用本地过程一样调用远程过程。
- 在 Microsoft Windows 中，"ncacn" 前缀被用于指定使用哪种网络协议来实现 RPC 通信。

## COM/DCOM

Microsoft’s foundational COM and DCOM technologies are built on top of RPC. The service’s name is RpcSs and it runs inside the shared services host process, svchost.exe. This is one of the main processes in any Windows operating system & it should not be terminated.


DCOM：Distributed Component Object Model。 [https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/4a893f3d-bd29-48cd-9f43-d9777a4415b0?redirectedfrom=MSDN](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/4a893f3d-bd29-48cd-9f43-d9777a4415b0?redirectedfrom=MSDN)

与 DCOM 的交互是通过 TCP 端口 135 上的 RPC 执行的，并且需要本地管理员访问权限才能调用 DCOM 服务控制管理器（本质上是一个 API）。

利用条件：本地管理员

各种横向利用： [https://www.cybereason.com/blog/dcom-lateral-movement-techniques](https://www.cybereason.com/blog/dcom-lateral-movement-techniques)



## 工具


### RPCclient

`rpcclient -U "" <ip>`

进入之后的命令：  
```
srvinfo
enumdomusers
enumalsgroups domain|builtin
lookupnames <user or group name>
```

