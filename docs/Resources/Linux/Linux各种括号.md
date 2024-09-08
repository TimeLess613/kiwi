---
tags:
  - IT/Linux
---
https://pikesaku.hatenablog.com/entry/2016/11/23/160156


![[Pasted image 20240311173533.png]]


### 大括号

变量替换——原型变量。`${var}`这种，无法替换cat到的变量，因为这是“变量”替换。

### 小括号

命令替换：`$(ls)`——只有标准输出（stdout）才能被替换，错误输出不行。
进程替换：`<(CMD)` ^97ed2e


![[Pasted image 20240311173640.png]]




### 双括号 

流程控制常用

- `$(())` 算数、数学计算

- 0为false

- `[[]]` 当作整体判断