Waiting for machine retire...

---

## 后记
2022/12/4  
其实算是第一次正经打HTB，以前稍微试了下还是觉得Web渗透知识不够的话有点难。  
主要是看这两天群友讨论Precious，然后也有大佬们给出提示，所以想着既然有提示那么我也想要尝试一下……  

想想这个靶机打了好几个小时，还是有点超出自己的实力范围了。不过回顾起来又觉得其实没那么难，很多知识都有接触过，还是实战经验太少了吧。  
围观群里讨论也学到了很多细节，比如get shell前应该先判断环境（如用 `which python python2 python3`）。自己这次就是乱试了几个偶然用python3反弹到了。  

不过[pdfkit这个PoC](https://security.snyk.io/vuln/SNYK-RUBY-PDFKIT-2869795)的命令执行似乎有限，有些命令并无/或者自己不知道哪里有回显（如 `id`）。后来搜wp时发现[另一个类似的注入方式](https://0xdedinfosec.vercel.app/blog/hackthebox-precious-writeup)， `` http://10.10.XX.XX/?name=%20`id` `` 可在用local URL时在网页回显。也不知道为何明明看的是同一个[pdfkit这个PoC](https://security.snyk.io/vuln/SNYK-RUBY-PDFKIT-2869795)，为什么会想到把 `#{}` 删掉……