# Write Up 模板

（模板更新：2023/06/27）

- 基本上HTB的机器（可能只是Esay机器）都会使用这个WP模板
- [MetaTwo](../WriteUp/HTB-MetaTwo.md)之前WP模板并未成形，所以语言、格式上会略有不同。以后可能也会不断改善这个模板的不足之处
- 对于仍在Active的机器，都会在WP开头写上 **Waiting for machine retire...**，表示这边暂时不会给出详细WP。不过会列一些提示，大致上是看官方Forum的话会有的程度。等机器退役后，会更新出详细WP


下面是WP模板：
----------------------------

**Waiting for machine retire...**

*Difficulty: Easy*

---

## Summary

xxx

### Attack Path Overview

![attack-path](../static/img/WP/AttackPath/HTB-template.png){ width='360' }


## 扫描

自用扫描脚本：[工作流](./HTB-Busqueda.md#workflow-scan)

```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

## 攻击路径规划·漏洞分析

常规简单靶机，22端口SSH的版本较新，优先度放低。先看80端口的Web。


## 80端口

- robots.txt
- .git/config
- 网页信息
- 网页功能
- 网页源码
- 子域枚举
- 目录枚举

### 研究网页功能

### 子域：

## xx端口



## Initial Access

### PoC (CVE-yyyy-xxxx)


## flag: user



## 探索



## Privilege Escalation

### PoC (CVE-yyyy-xxxx)


## flag: root


---

## 总结·后记

YYYY/MM/DD
……