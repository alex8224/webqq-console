# -*- coding:utf-8 -*-

'''
webqq-cli v0.1
author: alex8224@gmail.com

'''


import struct
import qqsetting
import gevent, greenlet
import random, json, time, os
import logging,logging.config
from urllib2 import BaseHandler
import urllib, urllib2, cookielib
from colorama import init, Fore;init()
from gevent import monkey, queue, pool;monkey.patch_all(dns = False)

def rmfile(filepath):
    if os.path.exists(filepath):
        os.unlink(filepath)

def processopen(param):
    import subprocess
    handler = subprocess.Popen(param, 
            shell = True, 
            stdout = subprocess.PIPE 
            )
    retcode = handler.wait()
    return retcode, handler

def formatdate(millseconds):
    return time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.localtime(long(millseconds))
            )

def getLogger(loggername = "root"):
    logging.config.fileConfig( os.path.join( os.getcwd(),"chatloggin.conf") )
    return logging.getLogger()

def ctime():
    return str( int( time.time() ) )

def localetime():
    return time.strftime("%Y-%m-%d %H:%M:%S")

def textoutput(msgtype, messagetext):
    import re
    highlightre = re.match('(.+ )\[(.+)\](.+)', messagetext)
    if highlightre:
        prefix, who, message = highlightre.groups()

        if msgtype == 1:
            getLogger().info(
                    Fore.GREEN + 
                    prefix + 
                    who + 
                    Fore.YELLOW+ 
                    message + 
                    Fore.RESET + "\n")

        if msgtype == 2:
            getLogger().info(
                    Fore.BLUE + 
                    who + 
                    Fore.RESET + 
                    message )

        if msgtype == 3:
            getLogger().info(
                   Fore.GREEN + 
                   prefix + 
                   Fore.RED + 
                   who + 
                   Fore.RESET + 
                   message )

        if msgtype == 4:
            getLogger().info(
                    Fore.YELLOW + 
                    prefix + 
                    who + 
                    Fore.GREEN + 
                    message + 
                    Fore.RESET + "\n")

    else:
        getLogger().info(messagetext)

class NotifyOsd(object):
    def __init__(self):
        try:
            self.pynotify = __import__("pynotify")
        except ImportError:
            pass

    def notify(self, notifytext, timeout = 3, icon = None, title = "通知"):
        if not self.pynotify:
            return

        reload(qqsetting)
        if qqsetting.ENABLE_OSD:
            notifyins = self.pynotify.Notification(title, notifytext, icon)
            notifyins.set_timeout(timeout*1000)
            notifyins.show()

notifyer = NotifyOsd()

class MsgCounter(object):

    def __init__(self):
        self.msgindex = random.randint(1, 99999999)

    def get(self):
        self.msgindex+=1
        return self.msgindex

MessageIndex = MsgCounter()

class WebqqFaceHandler(BaseHandler):

    def http_request(self, request):
        request.add_header("Referer", "http://s.web2.qq.com/proxy.html?v=20110412001&callback=1&id=1")

class WebqqHandler(BaseHandler):
   
    def __init__(self, refurl = None):
        self.refurl = refurl
        if not self.refurl:
            self.refurl = "http://d.web2.qq.com/proxy.html?v=20110331002&callback=2"
            # self.refurl = "http://s.web2.qq.com/proxy.html?v=20110412001&callback=1&id=1"

    def http_request(self, request):

        request.add_header("Referer", self.refurl)

        return request

class WebQQException(Exception):pass

class MessageHandner(object):
    ''' 对消息进行处理 '''

    def __init__(self, context):

        self.context = context
        self.logger = getLogger(loggername = "buddies_status")

    def dispatch(self, msgtype, message):

        prefixfunc= "on_" + msgtype
        func = getattr(self, prefixfunc) if hasattr(self, prefixfunc) else None

        if func:
            func(message)

    def __joinmessage(self, message):

        messagebody = "".join(
                map(
                    lambda item:
                        ":face" + str(item[1]) + ": " 
                        if isinstance(item, list) else item, message)
                )

        return messagebody.encode("utf-8")

    def on_message(self, message):

        fromwho = self.context.get_user_info(message["from_uin"])
        mess = message["content"][1:]

        sendtime = formatdate(message["time"])

        messagebody = self.__joinmessage(mess)
        for msg in mess:
            if isinstance(msg, list):
                msgtype = msg[0]
                if msgtype == "offpic":
                    content = msg[1]
                    picpath = content["file_path"]

                    self.context.spawn(
                            picpath, 
                            str(message["from_uin"]), 
                            task = self.context.downoffpic
                            )

                elif msgtype == "cface":    
                    to, guid, _ = str(message["from_uin"]), msg[1], msg[2]
                    self.context.spawn(to, guid, task = self.context.downcface)

        faceuri = self.context.getface(message["from_uin"])
        
        notifyer.notify(
                "".join(messagebody).encode("utf-8"), 
                title = fromwho, 
                timeout= 5,
                icon = faceuri 
                )

        textoutput(1,"%s [%s] 说 %s" % ( sendtime, fromwho, messagebody ) )

    def on_group_message(self, message):

        groupcode = message["group_code"] 
        # fromwho = self.context.get_user_info(message["send_uin"]) 
        fromwho = self.context.get_member_by_code(message["send_uin"])
        mess = message["content"][1:]

        sendtime = formatdate(message["time"])

        messagebody = self.__joinmessage(mess)
        messagebody = "%s [%s] 说 %s" % (
                sendtime + " " + self.context.get_groupname_by_code(groupcode),
                fromwho,
                messagebody
                )

        for msg in mess:
            if isinstance(msg, list):
                msgtype = msg[0]
                msgcontent = msg[1]
                if msgtype == "cface":    
                    gid, uin = message["group_code"], message["send_uin"]
                    fid = message["info_seq"]
                    filename = msgcontent["name"]
                    pichost, hostport = msgcontent["server"].split(":")
                    vfwebqq = self.context.vfwebqq
                    self.context.spawn(
                            str(gid), str(uin), pichost, hostport,
                            str(fid), filename, vfwebqq,
                            task = self.__downgrppic
                            )


        textoutput(3,messagebody) 

    def __downgrppic(self, gin, uin, host, port, fid, filename,vfwebqq):
        '''下载群图片'''

        grouppicurl = "http://webqq.qq.com/cgi-bin/get_group_pic?type=0&gid=%s&uin=%s&rip=%s&rport=%s&fid=%s=&pic=%s&vfwebqq=&%s&t=%s"
        grouppicurl = grouppicurl % (gin, uin, host, port, fid, urllib2.quote(filename), vfwebqq, ctime())
        fullpath = os.path.abspath(os.path.join(qqsetting.FILEDIR, filename.replace("{","").replace("}","")))
        cmd = "wget -q -O '%s' '%s'" % (fullpath, grouppicurl)
        retcode, handler = processopen(cmd)

        if retcode == 0:
            print("\nfile://" + fullpath)

    def on_shake_message(self, message):

        fromwho = self.context.get_user_info(message["from_uin"])
        textoutput(3, "朋友 [%s] 给你发送一个窗口抖动 :)" % fromwho)
        self.context.write_message(ShakeMessage(message["from_uin"]))

    def on_kick_message(self, message):

        self.context.logger.info("当前账号已经在别处登陆！")
        notifyer.notify("当前账号已经在别处登陆！")
        self.context.stop()

    def on_buddies_status_change(self, message):

        fromwho = self.context.get_user_info(message["uin"])
        status  = message["status"].encode("utf-8")

        reload(qqsetting)
        if status == "offline":
            self.context.redisconn.hdel("onlineguys", fromwho)
        else:
            self.context.redisconn.hset("onlineguys",fromwho, status)

        if qqsetting.CARE_ALL or fromwho in qqsetting.CARE_FRIENDS:
            faceuri = self.context.getface(message["uin"])
            logmessage = "%s %s" % (fromwho, status)
            notifyer.notify(logmessage, timeout = 2, icon = faceuri)

    def on_input_notify(self, message):

        fromwho = self.context.get_user_info(message["from_uin"])
        textoutput(3, "朋友 [%s] 正在打字......" % fromwho)

    def on_file_message(self, message):

        fromwho = self.context.get_user_info(message["from_uin"])
        if message["mode"] == 'recv':
            filename = message["name"].encode("utf-8")
            textoutput(2, "朋友 [%s] 发送文件 %s 给你" % (fromwho, filename))
            to, guid = str(message["from_uin"]), urllib.quote(filename)
            lcid = str(message["session_id"])

            self.on_start_transfile(filename)
            self.context.spawn(
                    lcid, 
                    to, 
                    guid, 
                    filename, 
                    task = self.context.recvfile,
                    linkok = self.on_end_transfile
                    )

        elif message["mode"] == "refuse":
            textoutput(2, "朋友 [%s] 取消了发送文件" % (fromwho, ))

    def on_start_transfile(self, filename):
        notifyer.notify("正在接收文件 %s" % filename)

    def on_end_transfile(self, result):
        filename = result.get()
        if filename:
            notifyer.notify("文件 %s 接收完成" % filename)
        else:
            notifyer.notify("文件 %s 接收失败 " % filename)

    def __downofflinefile(self, url, filename):
        rmfile(filename)
        cmd = "wget -q -O '%s' '%s'" % (filename, url)

        retcode, _ = processopen(cmd)
        if retcode == 0:
            notifyer.notify("离线文件 %s 下载完成 " % filename)
        else:
            notifyer.notify("离线文件 %s 下载失败" % filename)
            rmfile(filename)



    def on_push_offfile(self, message):

        rkey, ip, port = message["rkey"], message["ip"], message["port"]
        fromwho = self.context.get_user_info(message["from_uin"])
        filename = message["name"]
        downurl = "http://%s:%d/%s?ver=2173&rkey=%s" % (ip, port, filename, rkey)
        notifyer.notify("开始接受 %s 发的离线文件 %s" % (fromwho, filename))
        self.context.spawn(
                downurl, 
                filename,
                task = self.__downofflinefile)

class QQMessage(object):

    def __init__(self, to, messagetext, context = None):
        self.msgtype = 1
        self.to = to 
        self.messagetext = messagetext.encode("utf-8")
        self.retrycount = 0
        self.context = context
        self.url = "http://d.web2.qq.com/channel/send_buddy_msg2"
    
    def encode(self, clientid, psessionid):

        content = '''["%s",[]]'''
        r = json.dumps(
                {
                    "to":self.to,
                    "face":570,
                    "content":content % self.messagetext,
                    "msg_id":MessageIndex.get(),
                    "clientid":clientid,
                    "psessionid":psessionid
                } )

        rdict = urllib.quote(r)
        return "r=%s&clientid=%s&psessionid=%s" % (rdict, clientid, psessionid)

    def decode(self):
        return self.to, self.messagetext

    def sendOk(self, result):
        pass

    def sendFailed(self, result):
        if self.retrycount <3:
            self.context.write_message(self)
            self.retrycount += 1
        elif self.retrycount == 3:
            print str(self), "发送失败"

    def send(self, context, clientid, psessionid):
        qqrawmsg = self.encode(clientid, psessionid)

        return context.spawn(
                self.url, 
                qqrawmsg,
                task = context.sendpost,
                linkok = self.sendOk,
                linkfailed = self.sendFailed )

    def __str__(self):
        return "send message to %s, message = %s" % (self.to, self.messagetext)

class ImageMessage(QQMessage):
    '''发送图片'''
    
    def __init__(self, to, imagefile, context = None):
        super(ImageMessage, self).__init__(to, "", context)
        self.context = context
        self.imagefile = imagefile

    def uploadpic(self):
        uploadurl = "http://weboffline.ftn.qq.com/ftn_access/upload_offline_pic?time="+ctime()
        formdata = {
                "skey"            : self.context.skey,
                "callback"        : "parent.EQQ.Model.ChatMsg.callbackSendPic",
                "locallangid"     : 2052,
                "clientversion"   : 1409,
                "uin"             : self.context.qq,
                "appid"           : 1002101,
                "peeruin"         : self.to,
                "fileid"          : 1,
                "vfwebqq"         : self.context.vfwebqq,
                "senderviplevel"  : 0,
                "reciverviplevel" : 0,
                "filename"        : os.path.basename(self.imagefile)
                }
       
        self.formdata = " ".join(
                (
                    "--form-string '%s=%s'" % (k, str(v))
                    for k, v in formdata.iteritems()
                )
                )

        cmd = "curl -s %s -F 'file=@%s' '%s'" % (
                self.formdata, 
                self.imagefile, 
                uploadurl )

        retcode, uploadhandler = processopen(cmd)

        if retcode == 0:
            response = uploadhandler.stdout.read()
            print(response)
            jsonstart, jsonend = response.find("{"), response.find("}") + 1
            return json.loads(response[jsonstart:jsonend])
        else:
            print cmd
            print uploadhandler.stdout.read()

    def encode(self, clientid, psessionid):
        upinfo= self.uploadpic()
        picpath = upinfo["filepath"]
        picname = upinfo["filename"]
        picsize = upinfo["filesize"]
        
        content = '''[["offpic","%s","%s",%d],[]]'''
        r = json.dumps(
                {
                    "to":self.to,
                    "face":570,
                    "content":content % (picpath, picname, picsize),
                    "msg_id":MessageIndex.get(),
                    "clientid":clientid,
                    "psessionid":psessionid
                } )
        rdict = urllib.quote(r)
        return "r=%s&clientid=%s&psessionid=%s" %(rdict, clientid, psessionid)

class GroupMessage(QQMessage):
    '''
    群消息
    '''
    def __init__(self, to, messagetext, context=None):

        super(GroupMessage, self).__init__(to, messagetext, context)
        self.url = "http://d.web2.qq.com/channel/send_qun_msg2"

    def encode(self, clientid, psessionid):

        groupuin = self.context.get_uin_by_groupname(self.to)
        content = '''["%s"]''' % self.messagetext
        r = json.dumps(
                {
                    "group_uin":groupuin,
                    "content": content,
                    "msg_id":MessageIndex.get(),
                    "clientid":clientid,
                    "psessionid":psessionid
                })
        rdict = urllib.quote(r)        
        return "r=" + rdict + "&clientid=" + clientid + "&psessionid=" + psessionid

    def __str__(self):
        return "send group message %s to %s " % (self.messagetext, self.to)

class ShakeMessage(QQMessage):
    '''
    发送窗口抖动消息
    '''
    def __init__(self, to):
        self.msgtype = 2
        self.to = to
        self.retrycount = 0
   
    def sendFailed(self, *args):
        print "shake message send failed!"

    def send(self, context, clientid, psessionid):
        url = "http://d.web2.qq.com/channel/shake2?to_uin="+str(self.to)\
                +"&clientid="+clientid+"&psessionid="+psessionid+"&t="+ctime()

        return context.spawn(
                url, 
                task = context.sendget, 
                linkfailed = self.sendFailed )

    def __str__(self):
        return "send shake message to %s" % self.to

class KeepaliveMessage(QQMessage):
    ''' 心跳消息 '''

    def __init__(self):
        self.msgtype = 3

    def sendFailed(self, result):pass

    def send(self, context):
        url = "http://webqq.qq.com/web2/get_msg_tip?uin=&tp=1&id=0&retype=1&rc=2&lv=3&t="+ctime()
        return context.spawn(
                url, 
                task = context.sendget, 
                linkfailed = self.sendFailed )

class LogoutMessage(QQMessage):
    '''
    注销消息
    '''
    def __init__(self):
        self.msgtype = 4

    def send(self, context, clientid, psessionid):
        logouturl = "http://d.web2.qq.com/channel/logout2?ids=&clientid="\
                +clientid+"&psessionid="+psessionid+"&t="+str(time.time())

        return context.spawn(
                logouturl,
                task = context.sendget )

class StatusChangeMessage(QQMessage):
    '''状态变更消息'''

    def __init__(self, status, who):
        self.msgtype = 5
        self.status = status
        self.who = who

    def encode(self):
        pass

class MessageFactory(object):
   
    @staticmethod
    def getMessage(webcontext, message):

        msgtype = struct.unpack("i", message[:4])[0]

        sendtime = localetime()
        if msgtype == 1:
            tolen, bodylen = struct.unpack("ii", message[4:12])
            to, body = struct.unpack("%ss%ss" % (tolen, bodylen), message[12:])
            uin = webcontext.get_uin_by_name(to)
            textoutput(4, "%s [对%s] 说 %s" % (sendtime, to, body))
            return QQMessage(uin, body.decode("utf-8"), context = webcontext)

        if msgtype == 2:
            tolen = struct.unpack("i", message[4:8])
            to = struct.unpack("%ss" % tolen, message[8:])
            to = to[0]
            uin = webcontext.get_uin_by_name(to)
            return ShakeMessage(uin)

        if msgtype == 3:
            tolen, bodylen = struct.unpack("ii", message[4:12])
            to, body = struct.unpack("%ss%ss" % (tolen, bodylen), message[12:])
            textoutput(4,"%s [对%s] 说 %s" % (sendtime, to, body))
            to = to[to.find("_")+1:]
            return GroupMessage(to, body.decode("utf-8"), context = webcontext)

        if msgtype == 4:
            return LogoutMessage()

        if msgtype == 5:
            tolen, bodylen = struct.unpack("ii", message[4:12])
            to, body = struct.unpack("%ss%ss" % (tolen, bodylen), message[12:])
            uin = webcontext.get_uin_by_name(to)
            return ImageMessage(uin, body.decode("utf-8"), context = webcontext)

class WebQQ(object):

    def __init__(self, qqno, qqpwd, handler=None):
        self.handler = handler if handler else MessageHandner(self)
        self.qq = qqno
        self.qqpwd = qqpwd
        self.ptwebqq = ""
        self.psessionid = ""
        self.clientid = str(random.randint(1,99999999))
        self.vfwebqq = ""
        self.vcode = ""
        self.uin = ""
        self.cookiesfile = "/tmp/cookies.txt"
        self.ckjar = cookielib.MozillaCookieJar(self.cookiesfile)
        self.cookiejar = urllib2.HTTPCookieProcessor(self.ckjar)
        self.opener = urllib2.build_opener(self.cookiejar, WebqqHandler)
        self.fakeid = ""
        self.friends = None
        self.friendindex = 1
        self.uintoqq = {}
        self.referurl = "http://d.web2.qq.com/proxy.html?v=20110331002&callback=1&id=2"
        # self.referurl = "http://s.web2.qq.com/proxy.html?v=20110412001&callback=1&id=1"
        self.useragent = "Mozilla/5.0 (X11; Linux i686; rv:16.0) Gecko/20100101 Firefox/16.0"

        self.mq = queue.Queue(20)
        self.taskpool = pool.Pool(10)
        self.runflag = False
        from redis import Redis
        self.redisconn = Redis(host="localhost")
        self.logger = getLogger()

    def build_userinfo(self):
        self.friendinfo = {}
        self.redisconn.delete("friends")
        for friend in self.friends["result"]["marknames"]:
            self.redisconn.lpush("friends", friend["markname"])
            self.friendinfo[friend["markname"]] = friend["uin"]
            self.friendinfo[friend["uin"]] = friend["markname"]
        
        for friend in self.friends["result"]["info"]:
            if not self.friendinfo.has_key(friend["uin"]):
                self.redisconn.lpush("friends", friend["nick"])
                self.friendinfo[friend["nick"]] = friend["uin"]
                self.friendinfo[friend["uin"]] = friend["nick"]
        
    
    def build_groupinfo(self):
        getgroupurl = "http://s.web2.qq.com/api/get_group_name_list_mask2"
        encodeparams = "r=" + urllib.quote(json.dumps({"vfwebqq":self.vfwebqq}))
        response = self.sendpost(
                getgroupurl,
                encodeparams,
                {"Referer":"http://s.web2.qq.com/proxy.html"}
                )

        self.logger.debug("获取群信息......")
        self.groupinfo = {}
        if response["retcode"] !=0:
            raise WebQQException("get group info failed!")

        grouplist = response["result"]["gnamelist"]
        self.redisconn.delete("groups")
        self.groupmemsinfo = {}
        for group in grouplist:
            self.groupinfo[group["code"]] = group
            self.groupinfo[group["name"]] = group
            self.redisconn.lpush("groups","%d_%s" % (self.friendindex, group["name"]))
            self.friendindex +=1
            getgroupinfourl = "http://s.web2.qq.com/api/get_group_info_ext2?gcode=%s&vfwebqq=%s&t=%s"
            header = {"Referer":"http://s.web2.qq.com/proxy.html?v=20110412001&callback=1&id=1"}
            groupinfo = self.sendget(getgroupinfourl % (group["code"], self.vfwebqq, ctime()), headers = header)
            try:
                membersinfo =  groupinfo["result"]["minfo"]
                [self.groupmemsinfo.update({member["uin"]:member["nick"].decode("utf-8")}) for member in membersinfo]
            except:
                pass

        return self

    def gethashpwd(self):
        from hashlib import md5
        return md5(
                md5(
                    (
                    md5(self.qqpwd).digest() + self.uin)
                    ).hexdigest().upper() + self.vcode
                ).hexdigest().upper()

    def login1(self):
        login1url = "http://ptlogin2.qq.com/login?u="+self.qq+"&p="+\
                self.gethashpwd()+"&verifycode="+self.vcode+\
                "&webqq_type=10&remember_uin=1&login2qq=1&aid=1003903&u1"+\
                "=http%3A%2F%2Fwebqq.qq.com%2Floginproxy.html%3Flogin2qq%3D1%26"+\
                "webqq_type%3D10&h=1&ptredirect=0&ptlang=2052&from_ui=1&pttype=1"+\
                "&dumy=&fp=loginerroralert&action=1-20-8656&mibao_css=m_webqq&t=1&g=1"

        response = self.opener.open(login1url).read()
        retcode, _, _, _, tip, nickname = eval(response[6:-3])
        if retcode != '0':
           raise WebQQException(tip)

        self.ckjar.save()
        self.ptwebqq = self.ckjar._cookies[".qq.com"]["/"]["ptwebqq"].value
        self.uincode = self.ckjar._cookies[".qq.com"]["/"]["uin"].value[1:]
        self.skey = self.ckjar._cookies[".qq.com"]["/"]["skey"].value
        return self

    def login(self):

        loginurl = "http://check.ptlogin2.qq.com/check?uin=%s&appid=1003903&r=%s"
        response = self.opener.open(loginurl % (self.qq,random.random())).read()
        retcode, vcode, uin = eval(response[12:-1]) 
        if retcode !='0':
            raise WebQQException("Get VCODE Failed!")

        self.vcode = vcode
        self.uin = uin
        return self

    def login2(self):
        login2url = "http://d.web2.qq.com/channel/login2"
        rdict = json.dumps({
                "status"     : "online",
                "ptwebqq"    : self.ptwebqq,
                "passwd_sig" : "",
                "clientid"   : self.clientid,
                "psessionid" : None}
                )

        encodedata = "r=%s&clientid=%s&psessionid=null" %(
                urllib.quote(rdict),
                self.clientid
                )
        try:
            with gevent.Timeout(30):
                response = json.loads(self.opener.open(login2url, encodedata).read())
                if response["retcode"] !=0:
                    raise WebQQException(
                            "login2 failed! errcode=%s, errmsg=%s" %
                            ( response["retcode"], response["errmsg"] ) 
                            )
                
                self.vfwebqq = response["result"]["vfwebqq"]
                self.psessionid = response["result"]["psessionid"]
                self.fakeid = response["result"]["uin"]
                self.logger.info("登陆成功！")
            return self

        except ValueError:
            raise WebQQException("login2 json format error")

        except gevent.timeout.Timeout:
            raise WebQQException("login2 timeout")

    def get_friends(self):

        getfriendurl = "http://s.web2.qq.com/api/get_user_friends2"
        encodeparams = "r=%7B%22h%22%3A%22hello%22%2C%22vfwebqq%22%3A%22"+self.vfwebqq+"%22%7D"
        headers = {"Referer":"http://s.web2.qq.com/proxy.html?v=20110412001&callback=1&id=1"}
        self.friends = self.sendpost(getfriendurl, encodeparams, headerdict = headers)
        self.build_userinfo()

        if self.friends["retcode"]!=0:
            raise WebQQException("get_friends failed")
        self.logger.info("获取朋友列表...")
        return self

    def write_message(self, qqmsg):
        try:
            self.mq.put_nowait(qqmsg)
        except gevent.queue.Full:
            self.logger.error("%s 发送失败, 队列已满" % str(qqmsg))

    def sendpost(self, url, message,headerdict = None, timeoutsecs = 60):
        sendrequest = urllib2.Request(url, message)
        sendrequest.add_header("Referer",self.referurl)
        sendrequest.add_header("User-Agent",self.useragent)

        if headerdict:
            for k,v in headerdict.iteritems():
                sendrequest.add_header(k,v)

        try:
            with gevent.Timeout(timeoutsecs):
                return json.loads( urllib2.urlopen(sendrequest).read() )

        except urllib2.URLError, urlex:
            raise WebQQException(urlex)

        except ValueError:
            raise WebQQException("json format error")

        except gevent.timeout.Timeout:
            raise WebQQException("sendpost timeout")

    def requestwithcookie(self):
        ckjar = cookielib.MozillaCookieJar(self.cookiesfile)
        cookiejar = urllib2.HTTPCookieProcessor(ckjar)
        return urllib2.build_opener(cookiejar, WebqqHandler)

    def sendget(self, url, headers = {}):
        from httplib import BadStatusLine
        with gevent.Timeout(30, False):
            try:
                # response = self.requestwithcookie().open(url).read()
                request = urllib2.Request(url)
                for headername, headervalue in headers.iteritems():
                    request.add_header(headername, headervalue)
                return json.loads(urllib2.urlopen(request).read())
                # return json.loads(response)
            except ValueError:
                raise WebQQException("json format error")
            except BadStatusLine:
                raise WebQQException("http statu code error")

    def recvfile(self, lcid, to, guid, filename):
        recvonlineurl = "http://d.web2.qq.com/channel/get_file2?lcid=" + lcid + \
                "&guid=" + guid+"&to=" + to + "&psessionid=" + self.psessionid + \
                "&count=1&time=1349864752791&clientid=" + self.clientid
        basefilename = filename
        filename = filename.replace("(","[").replace(")","]")
        filename = os.path.abspath(os.path.join(qqsetting.FILEDIR, filename))
        cmd = "wget -q -O '%s' --referer='%s' --cookies=on --load-cookies=%s --keep-session-cookies '%s'"

        retcode, wgethandler = processopen(
                cmd % (
                    filename.decode("utf-8"),
                    self.referurl, 
                    self.cookiesfile, 
                    recvonlineurl
                ))
                
        return basefilename if retcode == 0 else False

    def poll_online_friends(self):
        geturl = "http://d.web2.qq.com/channel/get_online_buddies2?clientid=%s&psessionid=%s&t=1349932882032"
        try:
            onlineguys = json.loads(self.requestwithcookie().open(geturl % (self.clientid, self.psessionid)).read())
            if not onlineguys:
                return

            retcode, result = onlineguys["retcode"], onlineguys["result"]
            if retcode == 0 and result:
                batch = self.redisconn.pipeline(transaction = False)
                self.redisconn.delete("onlineguys")
                for guy in result:
                    markname = self.get_user_info(guy["uin"])
                    self.redisconn.hset("onlineguys", markname, guy["status"])
                batch.execute()

        except WebQQException:
            pass

    def downcface(self, to, guid):
        lcid = str(MessageIndex.get())
        getcfaceurl = "http://d.web2.qq.com/channel/get_cface2?lcid="+ lcid +\
                "&guid=" + guid + "&to=" + to + "&count=5&time=1&clientid=" + \
                self.clientid + "&psessionid=" + self.psessionid
        def sendrequest():
            response = ""
            try:
                response = self.requestwithcookie().open(
                        getcfaceurl, 
                        timeout = 300
                        ).read()
                try:
                    print json.loads(response) 
                    return False
                except:
                    pass

                filename = os.getcwd() + "/" + qqsetting.FILEDIR + "/" + guid
                with open(filename, "w") as cface:
                    cface.write(response)

                textoutput(3, "file://%s " % filename)    
                return True
            except:
                return False

        for count in range(3):
            if sendrequest():break
            else:
                self.logger.debug("retry downcface %d times"  % count)
            gevent.sleep(0)    

    def getqqnumber(self, uin):

        qqnumber = self.uintoqq.get(uin, None)
        if qqnumber:
            return qqnumber

        geturl = "http://s.web2.qq.com/api/get_friend_uin2?tuin=%s&verifysession=&type=1&code=&vfwebqq=%s&t=%s"
        try:
            geturl = geturl % (uin, self.vfwebqq, str(time.time()))
            header = {"Referer":"http://s.web2.qq.com/proxy.html?v=20110412001&callback=1&id=1"}
            response = self.sendget(geturl,headers = header)
            if response["retcode"] == 0:
                qqnumber = response["result"]["account"]
                self.uintoqq[uin] = qqnumber
                return qqnumber
        except Exception:
            import traceback;traceback.print_exc()
            

    def getface(self, uin):
        qqnumber = self.getqqnumber(uin)
        if qqnumber:
            face = "%s/%s.jpg" % (os.getcwd()+"/"+qqsetting.FACEDIR, qqnumber)
            if os.path.exists(face):
                return face

            getfaceurl = "http://face4.qun.qq.com/cgi/svr/face/getface?cache=0&type=1&fid=0&uin=%s&vfwebqq=%s"
            try:
                response = self.opener.open(getfaceurl % (uin, self.vfwebqq)).read()
                with open(face, "w") as facefile:
                    facefile.write(response)
                return face    
            except:
                pass

    def downoffpic(self, url, fromuin):
        getoffpicurl = "http://d.web2.qq.com/channel/get_offpic2?file_path=" + \
                urllib.quote(url) + "&f_uin=" + fromuin + "&clientid=" + \
                self.clientid + "&psessionid=" + self.psessionid
        try:

            response = self.opener.open(getoffpicurl).read()
            filename = os.getcwd() + "/" + qqsetting.FILEDIR + "/" + url[1:] + ".jpg"
            with open(filename, "w") as offpic:
                offpic.write(response)

            textoutput(3, "file://%s " % filename)    

        except:
            import traceback

            traceback.print_exc()
            self.logger.error("download %s failed" % getoffpicurl)

    def send_message(self):

         while self.runflag:
            try:
                message = self.redisconn.lpop("messagepool")
                if message:
                    qqmesg = MessageFactory.getMessage(self, message)

                    if isinstance(qqmesg, LogoutMessage):
                        print "logout message"
                        self.stop()
                        continue

                    qqmesg.send(self, self.clientid, self.psessionid)    

                innermsg = self.mq.get_nowait()

                if isinstance(innermsg, KeepaliveMessage):
                    innermsg.send(self)
                else:
                    innermsg.send(self, self.clientid, self.psessionid)

                gevent.sleep(0.1)    

            except gevent.queue.Empty: 
                gevent.sleep(0.1)

            except greenlet.GreenletExit:
                self.logger.info("send_message exitting......")
                break
            except:
                import traceback
                traceback.print_exc()
                self.stop()
               
    def poll_message(self):
        poll_url = "http://d.web2.qq.com/channel/poll2"
        rdict = json.dumps(
                    {
                    "clientid":self.clientid,
                    "psessionid":self.psessionid, 
                    "key":0,"ids":[]
                    }
                )

        encodeparams = "r=" + urllib.quote(rdict) + "&clientid=" +\
                self.clientid + "&psessionid=" + self.psessionid

        while self.runflag:
            try:
                response = self.sendpost(poll_url, encodeparams, timeoutsecs=30)
                retcode = response["retcode"]

                if retcode == 0:
                    result = response["result"]
                    for message in result:
                        poll_type, value = message["poll_type"], message["value"]
                        self.handler.dispatch(poll_type, value)

                elif retcode == 102:
                    print "没收到消息，超时..."

                # gevent.sleep(0)

            except WebQQException:
                pass

            except greenlet.GreenletExit:
                self.logger.info("poll_message exitting......")
                break

            except Exception:
                import traceback;traceback.print_exc()

    def keepalive(self):

        gevent.sleep(0)

        while self.runflag:
            gevent.sleep(60)
            try:

                self.write_message(KeepaliveMessage())

            except greenlet.GreenletExit:
                self.logger.info("Keepalive exitting......")
                break

    def get_user_info(self, uin):
        return self.friendinfo.get(uin, str(uin)).encode("utf-8")

    def get_uin_by_name(self, name):
        return self.friendinfo.get(name.decode("utf-8"), None)

    def get_groupname_by_code(self, code):
        groupinfo = self.groupinfo.get(code, None)
        if groupinfo:
            return groupinfo["name"].encode("utf-8")
        else:
            return code

    def get_member_by_code(self, code):
        return self.groupmemsinfo.get(code, code)

    def get_uin_by_groupname(self, groupname):
        groupinfo = self.groupinfo.get(groupname.decode("utf-8"), None)

        if groupinfo:
            return groupinfo["gid"]

    def start(self):

        self.runflag = True
        self.login().login1().login2().get_friends().build_groupinfo()
        self.taskpool.spawn(self.send_message)
        self.taskpool.spawn(self.poll_message)
        self.taskpool.spawn(self.poll_online_friends)

        self.installsignal()
        self.taskpool.join()
    
    def stop(self):
        self.logout()
        self.runflag = False
        self.taskpool.kill()
        self.taskpool.join()

    def spawn(self, *args, **kwargs):

        glet = gevent.spawn(kwargs["task"], *args)

        if kwargs.get("linkok"):
            glet.link(kwargs["linkok"])
        if kwargs.get("linkfailed"):
            glet.link_exception(kwargs["linkfailed"])

        return glet

    def installsignal(self):
        import signal
        gevent.signal(signal.SIGTERM, self.stop)
        gevent.signal(signal.SIGINT, self.stop)

    def logout(self):
        LogoutMessage().send(self, self.clientid, self.psessionid).get()

if __name__ == '__main__':
    os.system("stty -echo")
    username = raw_input("Username:")
    print ""
    password = raw_input("Password:")
    os.system("stty echo")
    print ""
    qq = WebQQ(username, password)
    try:
        qq.start()
    except WebQQException, ex:
        print(str(ex))
