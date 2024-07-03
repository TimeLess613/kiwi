---
tags:
  - IT/Linux
---

## 共同步骤

安装桌面环境 ^32a346

```bash
sudo dnf/apt-get update
## xfce4：kali默认
sudo dnf/apt-get install xfce4

## 基本的 GNOME 桌面组件
sudo yum groupinstall "X Window System" "GNOME"。然后运行“startx”启动。
## 完整桌面环境
sudo yum groupinstall "Server with GUI"
```

## X11方案

### Linux端

```bash
/etc/ssh/sshd_config
X11Forwarding yes
sudo systemctl reload sshd
```

### Windows端

<aside> ❓ 下载并安装X服务器：VcXsrv或Xming</aside>

`ssh -X user@192.168.1.100`

#### 运行XFCE或其他图形界面程序

一旦连接，就可以在SSH会话中启动XFCE桌面或任何其他图形界面程序。 例如，运行 xfce4-terminal 来打开XFCE终端。

> 它适合运行单个应用程序，而不是整个桌面环境。如果需要远程访问整个桌面，可能需要考虑使用VNC或XRDP等其他解决方案。



## XRDP方案

> [!NOTE] [[Kali搭建#Hyper-V|Hyper-V]]的增强会话模式就是这个，所以不要杀xrdp的进程！！

### Linux端

```bash
sudo dnf/apt-get install xrdp
sudo systemctl start xrdp
sudo systemctl enable xrdp
```

#### 配置XFCE桌面环境

```bash
echo xfce4-session > ~/.xsession
echo "startxfce4" > ~/.xsession：确保了当您通过XRDP连接时，会启动XFCE桌面环境
```

#### 配置FW

```bash
sudo firewall-cmd --add-port=3389/tcp --permanent
sudo firewall-cmd --reload
```

### Windows端

RDP连接。注意linux端需要开启3389。