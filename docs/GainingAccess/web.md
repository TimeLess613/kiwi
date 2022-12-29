## 文件上传

### 思路
![xmind](../static/img/MindMap/UploadVulns.png){ width='1024' }

> Magic Number：<https://en.wikipedia.org/wiki/List_of_file_signatures>

### 绕过

**黑名单：**  

- 大小写
- 空格
- 双后缀
- .htaccess

**白名单：**  

- MIME绕过
- %00截断
- 0x0a截断