---
tags:
  - IT/Linux
  - 渗透
---

**权限概览：**

- “读”位：用户可以列出文件
- “写”位：用户可以删除和创建新文件
- “执行”位：用户可以“cd”进入该文件夹

**两种表示法：**

- bit方式则对整个文件各角色的设置
- ugo（user，group，other）的方式一般针对特定角色

![[static/img/ATTACHMENTS/Pasted image 20240310160451.png]]


## SUID

背景： [https://www.jianshu.com/p/2c374f9522bd](https://www.jianshu.com/p/2c374f9522bd)

- RUID（即我们登陆时的ID）
- EUID（如给root的某文件设置了SUID，那么我们-RUID-运行这个文件时，进程的EUID就是root）
- SUID（设置给文件的）

默认情况下用户发起一个进程，进程的属主是进程的发起者（RUID），也就是说这个进程是以发起者的身份运行。**但如果该程序有SUID权限，那么程序运行为进程时，进程的属主不是发起者，而是该程序文件的属主（EUID）。**

好处：对某些文件临时赋予普通用户以root权限，避免切换到root这么危险的权限来执行操作（比如普通用户要改密码），方便管理。

> [!NOTE] 大写的S
> 表示虽然设置了SUID权限，但是没有赋予“执行(x)”权限。

![[static/img/ATTACHMENTS/Pasted image 20240310160947.png]]

- SUID：4xxx
- GUID：2xxx
- sticky bits：1xxx

### Sticky 目录权限

属性flag为：t

- 只能给目录，如/tmp就有
- 任何用户都可以在sticky目录里增改文件，但只有创建者和root可删。

**例：**

- `chmod 4777 file`：设置SUID以及full权限
- `chmod +rwx file` 或 `chmod a+rwx file`：给file的"所有用户"增加读、写、执行权限
- `chmod u+srw file`：给file的"user"增加SUID、读、写权限


### ![[Linux命令#找设置了SUID的文件]]









