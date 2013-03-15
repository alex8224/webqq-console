webqq3.0 协议分析
===================

生成密码
----------
    
访问如下的url **http://check.ptlogin2.qq.com/check?uin=qqnumber&appid=1003903&r=0.09714xxxx** 得到如下信息

.. code-block:: javascript

  pt_checkVC('0', '!B55', '\x00\x00\x00\x00\xa6\xce\xef\xfe')

1. 当前用户是否需要使用验证码登陆

2. 提取第二三个字段作为加密的salt
       
生成密码的步骤如下:

1. 得到uin 的字节数组

2. 将密码md5 后转换为字节数组
 
3. 组合密码的字节数组和uin 的字节数组，密码在前

4. 将组合后的字节数组进行md5

5. 将最后一次md5 的hexstr+vcode,在进行一次 md5

qq 密码的计算方法如下

.. code-block:: python

  md5(md5((md5("1234567890").digest()+uin)).hexdigest().upper()+"!B55").hexdigest().upper()

.. _2ndlogin:

使用生成的密码二次登陆
------------------------

使用上次生成的密码字符串拼接如下url,进行二次登陆:
  
**http://ptlogin2.qq.com/login?u=10897944&p=07B8A85663FAB28A25CEFEC495AD15CB&verifycode=!WD3&webqq_type=10&remember_uin=1&login2qq=1&aid=1003903&u1=http%3A%2F%2Fwebqq.qq.com%2Floginproxy.html%3Flogin2qq%3D1%26webqq_type%3D10&h=1&ptredirect=0&ptlang=2052&from_ui=1&pttype=1&dumy=&fp=loginerroralert&action=1-20-8656&mibao_css=m_webqq&t=1&g=1**

1. 发送上面的请求后，从返回的cookie中获取 `ptwebqq` 参数, 保存起来

2. 发送过来的cookie都要保存起来，后面在请求的时候发送给 webqq

3. 组装二次登陆的 http://d.web2.qq.com/channel/login2,里面用到了ptwebqq参数, 需要注意的是本次需要发送的是 `POST` 请求:

**r=%7B%22status%22%3A%22online%22%2C%22ptwebqq%22%3A%2272541a7b79772b8f09f72261b30e82b27e7712f44fa76884231d47b4d2894dc3%22%2C%22passwd_sig%22%3A%22%22%2C%22clientid%22%3A%2232383579%22%2C%22psessionid%22%3Anull%7D&clientid=32383579&psessionid=null**


实际的内容其实是两个字段，如下

.. code-block:: haskell

    clientid: xxxxxxx

    psessionid: null

    r: {"status":"online","ptwebqq":"72541a7b79772b8f09f72261b30e82b27e7712f44fa76884231d47b4d2894dc3","passwd_sig":"","clientid":"32383579","psessionid":null}


对上面的内容进行urlencode 后发送到服务器

4. 发送请求之前需要在请求中增加 http header Referer: http://d.web2.qq.com/proxy.html?v=20110331002&callback=2   

5. 从返回的json值中提取登陆的结果， 并把 `psessionid` 和 `vfwebqq` 保存起来，后面发送请求的时候要使用, 返回值如下

.. code-block:: javascript

  {"retcode":0,
    "result":
        {
         "uin":10897944,"cip":1959559061,"index":1075,"port":40036,"status":"online",
         "vfwebqq":"963856c05954b2f1a0b1f4efff16cc605ce3a1b84792ac678dee4b919c1a",
         "psessionid":"c53856c05954b2f1a0b1f4efff16cc605ce3a1b84792ac678dee4b919c1a","user_state":0,"f":0
        }
  }


获取朋友的列表
----------------

登陆成功后获取自己的朋友列表，需要组装下列 **POST** 请求发送到 http://s.web2.qq.com/api/get_user_friend2

需要设置 Referer 参数为 http://d.web2.qq.com/proxy.html?v=20110331002&callback=2

.. code-block:: javascript

 r={"h":"hello","vfwebqq":"9635b7bdfb20a7d08f43c53856c05954b2f1a0b1f4efff16cc605ce3a1b84792ac678dee4b919c1a"}
  
需要使用将上面的参数编码后发送，

**r=%7B%22h%22%3A%22hello%22%2C%22vfwebqq%22%3A%229635b7bdfb20a7d08f43c53856c05954b2f1a0b1f4efff16cc605ce3a1b84792ac678dee4b919c1a%22%7D**


得到的返回值为json格式，基本结构如下 

.. code-block:: javascript

  {"retcode":0, "result":{"marknames",[], "info":[], "vipinfo":[], "categories":[]}}

``参数的解释:``

+-------------------+-----------------------------+---------------------------------------------+
| 参数名称          | 参数描述                    | 返回值结构                                  |
+===================+=============================+=============================================+
| returncode        | 返回码，为 0 时表示成功     | 无                                          |
+-------------------+-----------------------------+---------------------------------------------+
| marknames         | 表示加了备注的好友,结构如下 | {"markname":"", "uin":""}                   |
|                   | {'markname':"", "uin":}     |                                             |
+-------------------+-----------------------------+---------------------------------------------+
| info              | 存放所有好友和uin的对应关系 | [{"nick":"", "flag":"","uin":"","face":""}] |
+-------------------+-----------------------------+---------------------------------------------+
| vipinfo           | 存放所有好友的vip级别       | 不做描述                                    |
+-------------------+-----------------------------+---------------------------------------------+
| categories        | 好友和uin 的对应关系，用户  | {"sort":1, "index":1,"name":""}             |
|                   | 分组信息                    |                                             |
+-------------------+-----------------------------+---------------------------------------------+


.. _receivemsg:

接收消息
---------
使用链接 http://d.web2.qq.com/channel/poll2 发送 `POST` 请求轮询好友发送的消息

**clientid** 是一个long型的整数，一般写一个就行了，后面可以重复使用

**POST 过去的参数都必须先进行编码后发送**

必须设置http header **Referer:http://d.web2.qq.com/proxy.html?v=20110331002&callback=1&id=3** 这个值目前是固定的

轮询消息也不需要有cookies的支持

.. code-block:: haskell

  clientid=32383579
  psessionid=54b2f1a0b1f4efff16cc605ce3a1b84792ac678dee4b919c1a
  r={"clientid":"32383579","psessionid":"54b2f1a0b1f4efff16cc605ce3a1b84792ac678dee4b919c1a","key":0,"ids":[]}

返回值为json格式

.. code-block:: javascript

  {"retcode":0,"result":[{"poll_type":"buddies_status_change","value":{"uin":3983012188,"status":"online","client_type":1}}]}

retcode 为 0 才可以获取后续的值， 具体的消息类型通过result字段的 **poll_type** 的值决定， **poll_type** 的可选值如下表:

+-------------------------+------------------------------------------------------------------+
| poll_type               | 描述                                                             |
+=========================+==================================================================+
| buddies_status_change   | 用户的在线状态发生改变                                           |
+-------------------------+------------------------------------------------------------------+
| message                 | 收到用户发送的消息                                               |
+-------------------------+------------------------------------------------------------------+
| kick_message            | 同一个账号在另外的地方登陆,客户端收到后应该断开与服务器的连接    |
+-------------------------+------------------------------------------------------------------+

result 是一个数组，所以里面可以包含多个不同 **poll_type** 的消息

buddies_status_change 消息的结构如下:

.. code-block:: javascript
  
  {"poll_type":"buddies_status_change", "value":{"uin":xxxxxxx,"status":"online","client_type":1}}

message 消息的结构如下:

.. code-block:: javascript

  {'poll_type': 'message', 
    'value': 
        {
            'reply_ip': 176498310, 'msg_type': 9, 'msg_id': 10171, 
            'content': [
                         [
                          'font', {'color': '000000', 'style': [0, 0, 0], 'name': '\u5b8b\u4f53', 'size': 9}
                         ] , '\u4e2d\u5348\u5462\r'
                       ], 
             'msg_id2': 158459, 'from_uin': 3898449591L, 'time': 1348566488, 'to_uin': 10897944
        }
  }

kick_message 消息的结构如下:

.. code-block:: javascript

  {
   'poll_type': 'kick_message', 
    'value': 
        {
        'reply_ip': 0, 
        'msg_type': 48,
        'msg_id': 30519, 
        'reason': 'xxxx for force logout', 
        'msg_id2': 30520, 
        'from_uin': 10000, 
        'show_reason': 1,
        'to_uin': 10897944
        }
 }


发送消息给好友
---------------
发送 `POST` 请求到链接 http://d.web2.qq.com/channel/send_buddy_msg2 ，并提交以下内容到服务器即可, 需要注意的是发送的内容要进行 ``url编码`` 之后发送

发送消息时不需要cookie的支持，服务器只识别clientid和psessionid这两个参数

必须设置http header **Referer:http://d.web2.qq.com/proxy.html?v=20110331002&callback=1&id=3** 这个值目前是固定的

.. code-block:: javascript

  clientid=44597165
  psessionid=8304fbcd9008992d818c910636a81146633f3bdd6b8e0a53b910d59b40e521dd924fb9
  r={"to":2481546577,
    "face":177,
    "content":"[\"好快，就到中午了\\n\",[\"font\",{\"name\":\"宋体\",\"size\":\"10\",\"style\":[0,0,0],\"color\":\"000000\"}]]",
    "msg_id":85970004,
    "clientid":"44597165",
    "psessionid":"8304fbcd9008992d818c910636a81146633f3bdd6b8e0a53b910d59b40e521dd924fb9"}

clientid 的解释参考 :ref:`receivemsg` 小节的解释

psessionid 是 :ref:`2ndlogin` 成功之后服务器返回的唯一参数，会话的过程中都要带上这个参数

content 的基础结构如下:

.. code-block:: javascript

    ["msgbody", 
        ["font",
            {"name":"宋体", "size":"10", "style":[0,0,0], "color":"000000"}
        ]
    ]

r 参数的详细解释如下表:

+-------------------+-------------------------------+
| 参数名称          | 参数描述                      | 
+===================+===============================+
| to                | 发送消息给朋友，uin 在这里    |
|                   | 不是指朋友的qq号码,每次不同   |
+-------------------+-------------------------------+
| face              | 可能是表情的编号，具体意思未知|
+-------------------+-------------------------------+
| content           | 发送给朋友的消息和格式描述    |
+-------------------+-------------------------------+
| clientid          | 参考 :ref:`receivemsg`        |
+-------------------+-------------------------------+
| psessionid        | 参考 :ref:`2ndlogin`          |
+-------------------+-------------------------------+


发送群消息
------------


获取好友的详细信息
-------------------


心跳维护
-----------
周期性的发送 `GET` 请求到 url http://webqq.qq.com/web2/get_msg_tip?uin=&tp=1&id=0&retype=1&rc=1&lv=3&t=1348458711542 维持与qq服务器的连接

改变登陆状态
-------------
发送 `GET` 请求到 url http://d.web2.qq.com/channel/change_status2?newstatus=hidden&clientid=44597165&psessionid=aac22e218a25034e1e1d9ed142c52168005f5983&t=1348482231366

这个也不需要cookie的支持，但是clientid和psessionid要正确填写

参数解释:

+-------------------+-------------------------------+
| 参数名称          | 参数描述                      | 
+===================+===============================+
| newstatus         |  要改变的状态，可选值：       |
|                   | 1. hidden 2. online 3. away   |
|                   | 4. busy 5. offline            |
+-------------------+-------------------------------+
| clientid          | 参考 :ref:`receivemsg`        |
+-------------------+-------------------------------+
| psessionid        | 参考 :ref:`2ndlogin`          |
+-------------------+-------------------------------+
| t                 | 基于时间的随机数              |
+-------------------+-------------------------------+


返回的是 json 格式数据

.. code-block:: javascript

  {"retcode":0,"result":"ok"}


注销登陆
------------


webqq返回码解释
----------------

+------------+-----------------------------------------------+
| 返回码     | 意义                                          |
+============+===============================================+
| 102        | 轮询消息超时                                  |
+------------+-----------------------------------------------+
| 0          | 成功                                          |
+------------+-----------------------------------------------+
| 116        | 通知更新ptwebqq的值                           |
+------------+-----------------------------------------------+

