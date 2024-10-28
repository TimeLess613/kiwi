---
tags:
  - 渗透/内网
  - 渗透/信息收集
  - IT/网络
---
WinRM：在后端，它利用WMI，因此您可以将其视为WMI的基于HTTP的API。WinRM 使用 XML 格式的 SOAP（简单对象访问协议）请求通过 HTTP 进行通信。所以其ST可能是访问HTTP的SPN。

- 5985/tcp (HTTP)
- 5986/tcp (HTTPS)

> 如果部署了winrm就会有47001；如果设置完成就有5985 wsman；如果加了ssl就有5986。

> [PowerShell Remoting](https://docs.microsoft.com/en-us/powershell/scripting/learn/ps101/08-powershell-remoting?view=powershell-7.2) - also referred to as PSRemoting or Windows Remote Management (WinRM) access, is a remote access protocol that allows us to run commands or enter an interactive command-line session on a remote host using PowerShell

