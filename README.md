webqq-console
=============

webqq 3.0协议的实现,比较完整的实现了主要的核心功能

基于Python语言的gevent实现, 单线程,比较省资源


`2014年7月25日更新登录部分代码`

如何使用？
-------

1. 首先安装依赖(**以Ubuntu12.04为例**)
   安装显示通知的插件和用于存储联系人资料的redis
   `apt-get install python-notify redis-server`
2. 安装pywebqq以来的python库
    `pip install redis requests colorama gevent readline`

3. `pip install pywebqq`

4. 使用**pywebqq.server**运行webqq服务端
   使用**pywebqq.client**运行webqq聊天窗口

5. `pywebqq.client`如何使用？
    请先运行 pywebqq.client, 然后输入`:`回车可查看使用帮助.


