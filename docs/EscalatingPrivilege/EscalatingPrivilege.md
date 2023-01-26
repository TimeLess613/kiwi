## 提权的类型

- 水平：横向移动
- 垂直：获取更高权限


## 方法

### 漏洞

- CVSS的AV分类（网络/本地），一般网络的分数较高。

### 命名管道

### DLL劫持

可利用原因：大部分Windows应用程序调用外部DLL时，都不会使用绝对路径。

工具：搜索可劫持的DLL

- Robber
- PowerSploit

> 一般权限编辑DLL文件，等待admin权限调用目标DLL也可。

### Dylib劫持（OS X）

工具：Dylib Hijack Scanner