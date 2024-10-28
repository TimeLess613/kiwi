---
tags:
  - 渗透/利用
  - IT/Windows
  - 渗透/CPTS
  - 渗透/内网
  - IT/网络
---
WinRM：在后端，它利用WMI，因此您可以将其视为WMI的基于HTTP的API。WinRM 使用 XML 格式的 SOAP（简单对象访问协议）请求通过 HTTP 进行通信。所以其ST可能是访问HTTP的SPN。

- 5985/tcp (HTTP)
- 5986/tcp (HTTPS)

> 如果部署了winrm就会有47001；如果设置完成就有5985 wsman；如果加了ssl就有5986。

> [PowerShell Remoting](https://docs.microsoft.com/en-us/powershell/scripting/learn/ps101/08-powershell-remoting?view=powershell-7.2) - also referred to as PSRemoting or Windows Remote Management (WinRM) access, is a remote access protocol that allows us to run commands or enter an interactive command-line session on a remote host using PowerShell

---


> there may be scenarios where HTTP, HTTPS, or SMB are unavailable. If that's the case, we can use [PowerShell Remoting](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.2), aka WinRM, to perform file transfer operations.


权限条件3选1：

- administrative access
- a member of the `Remote Management Users` group
- have explicit permissions for PowerShell Remoting in the session configuration




```powershell
# 确认目标是否开启WinRM
PS C:\htb> Test-NetConnection -ComputerName DATABASE01 -Port 5985
ComputerName     : DATABASE01
RemoteAddress    : 192.168.1.101
RemotePort       : 5985
InterfaceAlias   : Ethernet0
SourceAddress    : 192.168.1.100
TcpTestSucceeded : True

# 已登录的话不需要凭据
PS C:\htb> $Session = New-PSSession -ComputerName DATABASE01

PS C:\htb> Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\
## 反方向
PS C:\htb> Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
```