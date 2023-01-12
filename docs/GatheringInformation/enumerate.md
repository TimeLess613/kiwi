## NetBIOS（NBNS UDP/137）

- `nbtstat -a <remote IP>` 获取远程机器的NetBIOS表
- `nbtstat -c` 获得NetBIOS表、解析cache。

    > It is possible to extract this information without creating a null session (an unauthenticated session).

- `net use`
- `nmap --script nbstat.nse`
- `net view \\<computer name> [/ALL]` 远程主机或者工作组所有的共享资源（share）列表
- `net view /domain:<domain name>`


## SNMP



## LDAP（TCP/389 or 396?）



## NTP（UDP/123）

能收集的信息：

- 连接NTP服务器的host清单
- 客户端IP、系统名、OS
- 如果NTP服务器在DMZ，还能获得内部IP

---

- `ntptrace`
- `ntpdc` 监视ntpd的操作，获取NTP服务器的信息
- `ntpq` 监视ntpd的操作、性能，获取NTP服务器的信息
- nmap


## NFS（TCP/2049）

能收集的信息：

- 连接了NFS服务器的客户端清单、IP、共享资源

---

- `showmount -e <ip>`

工具：

- RDPScan（简单扫描，check共享配置错误）
- SuperEnum（有脚本）


## SMTP（TCP/25）



## DNS

目标：域传送有效的DNS

- `nslookup (ls -d <DNS hostname>)??`
- dig

## other

### Telnet
### FTP/TFTP
### SMB（overNetBIOS TCP/139, overTCP TCP/445 = CIFS）
### RPC（TCP/UDP/111? or 135）
### IPv6
### IPsec
### VoIP
### BGP（TCP/179）