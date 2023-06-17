## Viper(炫彩蛇)

github: <https://github.com/FunnyWolf/Viper>

可简单理解为图形化msf。然后有团队协作。


## 首次安装

- 跟着[官方文档](https://www.yuque.com/vipersec/help/olg1ua)就行
- 一键安装失败的话，可以中途手动继续配置docker-compose.yml
    - 注意防火墙配置
    - 可调整一下docker-compose.yml里的image源
- 首次启动可以 `docker compose up` 不后台启动。由于pull image有1GB左右。直接后台启动可能等15s依旧无法访问也不知道实际发生了什么问题。
    - 当然可以看docker的log