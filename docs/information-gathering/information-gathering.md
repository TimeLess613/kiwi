## [Footprinting（踩点）](./footprinting.md)

目的：攻击者事先汇集目标的信息，确定入侵方法、发掘漏洞

- 了解安全态势——收集的数据将帮助我们了解公司的安全态势，例如有关防火墙存在情况、应用程序安全配置等的详细信息。
- 缩小攻击区域——可以识别特定范围的系统并仅专注于特定目标。这将大大减少我们关注的系统数量。
- 识别漏洞——我们可以建立一个信息数据库，包含目标组织系统中可用的漏洞、威胁、漏洞。
- 绘制网络图——帮助绘制目标组织中网络的网络图，包括拓扑、可信路由器、服务器的存在和其他信息。

### 可收集3个方面的信息

- 网络：域名/子域、网段、IP、whois记录、DNS，正在运行的IDS、服务、网站、VPN、ACL等
- 系统（Host）：OS、server的位置、user/pass等、SNMP信息等
- 组织（人）：员工详细信息、电话、场地、组织背景、安全策略、技术栈等。其他思路：股市/金融信息网、招聘网（企业的软硬件）

### 注意

- 此过程是周期性的而非线性的
- 记笔记

### 分类

- 主动
- 被动



## [Scanning（扫描）](./scanning.md)

目的：踩点获得了一定信息之后，确认目标网络范围内有哪些系统是活跃的，以及提供什么服务——从哪里入侵、找入口

- 对比踩点：踩点就是搜集信息、看周围环境；扫描就像确认建筑物位置、有哪些门窗可进入


## [Enumerate（枚举）](./enumerate.md)

为了进一步获取目标的相关信息，**实施query**。  
对识别出来的服务进行更加充分更具针对性的探查，来寻找真正可以攻击的入口，以及攻击过程中可能需要的关键数据。  

主要是枚举**有效账号、网络资源（主机、设备、共享）、路由、SNMP、配置等**。  
*枚举技术在内网环境中执行（没懂这句的原意，可能是CEH的定义）*，用的技术依操作系统而定。

- 与踩点的关键区别：攻击者的入侵程度。
- 与扫描的关键区别：攻击者的针对性与信息搜集的目标性。 