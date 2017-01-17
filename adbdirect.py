#!/usr/bin/python
#coding=utf-8
"""
Date: 2015-11-07
"""
import Queue
import os
import socket
import stat
import struct
import threading
import time

try:
    from cStringIO import StringIO
except ImportError,e:
    from StringIO import StringIO


DEBUG_SHUXIN = False


MAX_ADB_DATA = 4096
VERSION = 0x01000000
AUTH_TOKEN = 1
AUTH_SIGNATURE = 2
AUTH_RSAPUBLICKEY = 3


DEFAULT_PUSH_MODE = stat.S_IFREG | stat.S_IRWXU | stat.S_IRWXG
MAX_PUSH_DATA = 2048


def __MakeWireIDs__(ids):
    id_to_wire = {
        cmd_id: sum(ord(c) << (i * 8) for i, c in enumerate(cmd_id))
        for cmd_id in ids
    }
    wire_to_id = {wire: cmd_id for cmd_id, wire in id_to_wire.items()}
    return id_to_wire, wire_to_id

class __AdbMessage__(object):

    format = '<6I'
    commands, constants = __MakeWireIDs__(['SYNC', 'CNXN', 'AUTH', 'OPEN', 'OKAY', 'CLSE', 'WRTE'])
    id_to_wire, wire_to_id = __MakeWireIDs__(['STAT', 'LIST', 'SEND', 'RECV', 'DENT', 'DONE', 'DATA', 'OKAY', 'FAIL', 'QUIT',])

    @classmethod
    def hash_message(cls,data):
        return sum(map(ord, data)) & 0xFFFFFFFF

    @classmethod
    def send_message(cls,sock,cmd,arg0,arg1,data):
        command = cls.commands[cmd]
        if DEBUG_SHUXIN: print ">>  ",[cmd,arg0,arg1,data]
        sock.sendall(struct.pack(cls.format, command, arg0, arg1, len(data), cls.hash_message(data), command ^ 0xFFFFFFFF))
        sock.sendall(data)
        #print "send",repr(struct.pack(cls.format, command, arg0, arg1, len(data), cls.hash_message(data), command ^ 0xFFFFFFFF))
        #print "send",repr(data)
        return None

    @classmethod
    def recv_message(cls,sock):
        #cmd, arg0, arg1, data_length, data_checksum, unused_magic = struct.unpack(cls.format, data)
        msg = sock.recv(24)
        #print "recv",repr(msg)
        cmd, arg0, arg1, data_length, data_checksum, unused_magic = struct.unpack(cls.format, msg)
        command = cls.constants.get(cmd)
        if not command:
            return
        if data_length > 0:
            data = ''
            while data_length > 0:
                temp = sock.recv(data_length)
                #print "recv",repr(temp)
                data += temp
                data_length -= len(temp)
            actual_checksum = cls.hash_message(data)
            if actual_checksum != data_checksum:
                return
                #raise InvalidChecksumError('Received checksum %s != %s', (actual_checksum, data_checksum))
        else:
            data = ''
        if DEBUG_SHUXIN: print "  <<",[command, arg0, arg1, data]
        return (command, arg0, arg1, data,)

    @classmethod
    def msg_hello(cls,sock,banner='fireeye'):
        data = 'host::%s\0' % banner
        sock.settimeout(5)
        cls.send_message(sock,'CNXN', VERSION, MAX_ADB_DATA, data)
        while True:
            cmd, arg0, arg1, data, = cls.recv_message(sock)
            if cmd in ['CNXN', 'AUTH']:
                break
        if cmd == 'AUTH' and arg0 == AUTH_TOKEN:
            import M2Crypto
            rsa = M2Crypto.RSA.load_key("cert.key")
            signed_token = rsa.sign(data, 'sha1')
            cls.send_message(sock,'AUTH',AUTH_SIGNATURE, 0, signed_token)
            while True:
                cmd, arg0, arg1, data, = cls.recv_message(sock)
                if cmd in ['CNXN', 'AUTH']:
                    break
            if cmd == 'AUTH':
                cls.send_message(sock, 'AUTH', AUTH_RSAPUBLICKEY, 0, rsa.GetPublicKey() + '\0')
                while True:
                    cmd, arg0, arg1, data, = cls.recv_message(sock)
                    if cmd in ['CNXN', 'AUTH']:
                        break
                if cmd ==  'AUTH':
                    raise Exception(cmd,data)
        sock.settimeout(None)
        return data

    @classmethod
    def msg_receiver(cls, sock, event, sender_queue, receiver_queue_for_queue, receiver_queue_for_control):
        d = {}
        while event.isSet():
            try:
                cmd, arg0, arg1, data, = cls.recv_message(sock)
                if cmd == 'WRTE':
                    sender_queue.put(('OKAY', arg1, arg0, '',))
                    k = "%d-%d" % (arg1,arg0)
                    #if DEBUG_SHUXIN: print [cmd,k,data]
                    while not d.has_key(k):
                        x,y = receiver_queue_for_queue.get()
                        if y is not None:
                            d[x] = y
                        else:
                            if d.has_key(x):
                                d.pop(x,None)
                    d[k].put(data)
                else:
                    receiver_queue_for_control.put((cmd, arg0, arg1, data,))
            except Exception,e:
                if DEBUG_SHUXIN: print "msg_receiver",str(e)
                continue
        if DEBUG_SHUXIN: print "msg_receiver","stop"
        return None

    @classmethod
    def msg_sender(cls, sock, event, sender_queue):
        while event.isSet():
            try:
                cmd, arg0, arg1, data = sender_queue.get()
                cls.send_message(sock, cmd, arg0, arg1, data)
            except Exception,e:
                if DEBUG_SHUXIN: print "msg_sender",str(e)
                continue
        if DEBUG_SHUXIN: print "msg_sender","stop"
        return None

    @classmethod
    def msg_trigger(cls,event,trigger_queue,trigger_on_receive,trigger_finish):
        while event.isSet():
            try:
                trigger_on_receive(trigger_queue.get())
            except Exception,e:
                if DEBUG_SHUXIN: print "msg_trigger",str(e)
                continue
        if DEBUG_SHUXIN: print "msg_trigger","stop"
        trigger_finish()
        return None

class TRIGGER():
    def on_receive(self,data):
        if data:
            pass
    def finish(self):
        pass

class ADB_DIRECT():
    def __init__(self,ip,port):
        self.ip = ip
        self.port = port
        self.sock = None
        self.local_id = 7
        self.device_state = None
        self.trigger_id_pairs = {}
        self.trigger_flags = {}
        self.trigger_queue = {}
        self.trigger_thread = {}
        self.sender_flag = None
        self.sender_thread = None
        self.sender_queue = Queue.Queue()#["key",quere]
        self.receiver_flag = None
        self.receiver_thread = None
        self.receiver_queue_for_control = Queue.Queue()#["key",quere]
        self.receiver_queue_for_queue = Queue.Queue()#["key",quere]
    def __del__(self):
        self.close()
    def close(self):
        if self.sock:
            try:
                if self.sender_flag:
                    self.sender_flag.clear()
                if self.receiver_flag:
                    self.receiver_flag.clear()
                self.sender_queue.put(None)
            except Exception,e:
                pass
            try:
                self.sock.close()
            except Exception,e:
                pass
            self.sock = None
        return None
    def connect(self):
        self.close()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.ip,self.port))
            #sock = socket.create_connection((self.ip,self.port),timeout=2.5)
            self.sock = sock
            self.sock.settimeout(None)
            self.device_state = __AdbMessage__.msg_hello(self.sock)
            self.sock.settimeout(None)
            self.__start_threads__()
            return True
        except Exception,e:
            self.device_state = None
            self.close()
            return False
    def __start_threads__(self):
        self.receiver_flag = threading.Event()
        self.receiver_flag.set()
        self.receiver_thread = threading.Thread(target=__AdbMessage__.msg_receiver,args=(self.sock, self.receiver_flag, self.sender_queue, self.receiver_queue_for_queue, self.receiver_queue_for_control),name="msg_receiver")
        self.receiver_thread.start()
        self.sender_flag = threading.Event()
        self.sender_flag.set()
        self.sender_thread = threading.Thread(target=__AdbMessage__.msg_sender,args=(self.sock, self.sender_flag, self.sender_queue),name="msg_receiver")
        self.sender_thread.start()
        return None
    def __get_local_id__(self):
        self.local_id += 1
        return self.local_id
    def __get_control__(self,local_id):
        while True:
            cmd, arg0, arg1, data, = self.receiver_queue_for_control.get()
            if local_id != arg1:
                if self.trigger_id_pairs.has_key(arg1) and cmd == 'CLSE':
                    k = "%d-%d" % (arg1,arg0 if arg0 != 0 else self.trigger_id_pairs[arg1])
                    #if DEBUG_SHUXIN: print [cmd,k,data]
                    #a = threading.Thread()
                    #a.start()
                    #b = threading.Event()
                    #b.set()
                    #b.clear()
                    if self.trigger_flags.has_key(k):
                        self.trigger_flags[k].clear()
                    if self.trigger_queue.has_key(k):
                        self.trigger_queue[k].put('')
                    if self.trigger_thread.has_key(k):
                        self.trigger_thread.pop(k)
                    self.receiver_queue_for_queue.put((k,None,))
                    self.sender_queue.put(('CLSE', arg1, arg0, ''))
                continue
            return cmd, arg0, arg1, data,
    def __adb_service__(self, service, command):
        local_id = self.__get_local_id__()
        self.sender_queue.put(('OPEN', local_id, 0, '%s:%s\0' % (service, command),))
        while True:
            cmd, arg0, arg1, data, = self.__get_control__(local_id)
            if cmd in ['CLSE', 'OKAY']:
                break
        their_remote_id, their_local_id = arg0, arg1,
        if local_id != their_local_id:
            "something happend"
        if cmd == 'CLSE':
            return None
        k = "%d-%d" % (arg1,arg0)
        #if DEBUG_SHUXIN: print [cmd,k,data]
        q = Queue.Queue()
        self.receiver_queue_for_queue.put((k,q))
        while True:
            cmd, arg0, arg1, data, = self.__get_control__(local_id)
            if cmd in ['CLSE']:
                break
        if cmd == 'CLSE':
            self.sender_queue.put(('CLSE', arg1, arg0, ''))
        ret = ''
        while not q.empty():
            ret += q.get()
        self.receiver_queue_for_queue.put((k,None,))
        del q
        return ret

    def __adb__sync__(self,command,filename,fd=None,mode_if_push=None,time_if_push=None):
        ret = None
        service = "sync"
        local_id = self.__get_local_id__()
        self.sender_queue.put(('OPEN', local_id, 0, '%s:%s\0' % (service, ""),))
        while True:
            cmd, arg0, arg1, data, = self.__get_control__(local_id)
            if cmd in ['CLSE', 'OKAY']:
                break
        their_remote_id, their_local_id = arg0, arg1,
        if cmd == 'CLSE':
            return None
        k = "%d-%d" % (arg1,arg0)
        #if DEBUG_SHUXIN: print [cmd,k,data]
        if command == 'SEND':
            st_mode = mode_if_push if mode_if_push else (stat.S_IFREG | stat.S_IRWXU | stat.S_IRWXG)
            filename = '%s,%s' % (filename, st_mode)
        r_fd = StringIO(struct.pack('<2I', __AdbMessage__.id_to_wire[command], len(filename)) + filename)
        while True:
            frag = r_fd.read(MAX_ADB_DATA)
            if not frag:
                break
            self.sender_queue.put(('WRTE', arg1, arg0, frag,),)
            while True:
                cmd, arg0, arg1, data, = self.__get_control__(local_id)
                if cmd in ['CLSE', 'OKAY']:
                    break
        q = Queue.Queue()
        self.receiver_queue_for_queue.put((k,q))
        if command == "STAT":
            x,y = 'STAT','<4I'
            z = struct.calcsize(y)
            buff = ''
            while len(buff) < z:
                buff += q.get()
            head = buff[:z]
            #buff = buff[z:]
            xxxx, fmode, fsize, fmtime = struct.unpack(y, head)
            command_id = __AdbMessage__.wire_to_id[xxxx]
            if command_id != x:
                if command_id == 'FAIL':
                    return None
            ret = (fmode, fsize, fmtime,)
        elif command == "LIST":
            x,y = 'DENT','<5I'
            z = struct.calcsize(y)
            ret = []
            buff = ''
            while True:
                while len(buff) < z:
                    buff += q.get()
                head = buff[:z]
                buff = buff[z:]
                xxxx, fmode, fsize, fmtime, size = struct.unpack(y, head)
                command_id = __AdbMessage__.wire_to_id[xxxx]
                if command_id == 'DONE':
                    break
                if command_id != x:
                    if command_id == 'FAIL':
                        return None
                while len(buff) < size:
                    buff += q.get()
                cont = buff[:size]
                buff = buff[size:]
                ret.append((cont, fmode, fsize, fmtime))
        elif command == "RECV":
            x,y = 'DATA','<2I'
            z = struct.calcsize(y)
            w_fd = fd if fd else StringIO()
            buff = ''
            while True:
                while len(buff) < z:
                    buff += q.get()
                head = buff[:z]
                buff = buff[z:]
                xxxx, size = struct.unpack(y, head)
                command_id = __AdbMessage__.wire_to_id[xxxx]
                if command_id == 'DONE':
                    break
                if command_id != x:
                    if command_id == 'FAIL':
                        return None
                while len(buff) < size:
                    buff += q.get()
                cont = buff[:size]
                buff = buff[size:]
                w_fd.write(cont)
        elif command == "SEND":
            r_fd = fd if fd else StringIO()
            while True:
                frag = r_fd.read(MAX_PUSH_DATA)
                if not frag:
                    break
                buff = struct.pack('<2I', __AdbMessage__.id_to_wire['DATA'], len(frag)) + frag
                self.sender_queue.put(('WRTE', arg1, arg0, buff,))
                while True:
                    cmd, arg0, arg1, data, = self.__get_control__(local_id)
                    if cmd in ['CLSE', 'OKAY']:
                        break
            mtime = time_if_push if time_if_push else int(time.time())
            buff = struct.pack('<2I', __AdbMessage__.id_to_wire['DONE'], mtime)
            self.sender_queue.put(('WRTE', arg1, arg0, buff,),)
            x,y = 'OKAY','<2I'
            z = struct.calcsize(y)
            buff = ''
            while len(buff) < z:
                buff += q.get()
            head = buff[:z]
            buff = buff[z:]
            xxxx, size = struct.unpack(y, head)
            command_id = __AdbMessage__.wire_to_id[xxxx]
            while len(buff) < size:
                buff += q.get()
            cont = buff[:size]
            ret = (True if command_id == x else False,cont)
        else:
            pass
        self.sender_queue.put(('CLSE', arg1, arg0, ''))
        self.receiver_queue_for_queue.put((k,None))
        del q
        return ret
    def stat(self,filename):
        ret = self.__adb__sync__('STAT',filename)
        if ret is not None:
            return ret
        return None
    def list(self,dirname):
        ret = self.__adb__sync__('LIST',dirname)
        if ret is not None:
            return ret
        return None
    def pull(self,filename_inside, fd_or_filename_outsize=None):
        ret = None
        if isinstance(fd_or_filename_outsize, basestring):
            fd = open(fd_or_filename_outsize, 'wb')
            ret = self.__adb__sync__('RECV',filename_inside,fd)
            fd.close()
        elif not fd_or_filename_outsize:
            fd = StringIO()
            ret = self.__adb__sync__('RECV',filename_inside,fd)
            return fd.getvalue()
        else:
            fd = fd_or_filename_outsize
            ret = self.__adb__sync__('RECV',filename_inside,fd)
        return ret
    def push(self,filename_inside, fd_or_filename_outsize, fmode = None, fmtime=None):
        ret = None
        fmode = fmode if fmode else (stat.S_IFREG | stat.S_IRWXU | stat.S_IRWXG)
        fmtime = fmtime if fmtime else int(time.time())
        if isinstance(fd_or_filename_outsize, basestring):
            if os.path.exists(fd_or_filename_outsize):
                fd = open(fd_or_filename_outsize, 'rb')
                ret = self.__adb__sync__('SEND',filename_inside,fd,fmode,fmtime)
                fd.close()
            else:
                fd = StringIO(fd_or_filename_outsize)
                ret = self.__adb__sync__('SEND',filename_inside,fd,fmode,fmtime)
        elif not fd_or_filename_outsize:
            fd = StringIO()
            ret = self.__adb__sync__('SEND',filename_inside,fd,fmode,fmtime)
            return fd.getvalue()
        else:
            fd = fd_or_filename_outsize
            ret = self.__adb__sync__('SEND',filename_inside,fd,fmode,fmtime)
        return ret
    def reboot(self,destination=''):
        return self.__adb_service__('reboot', destination,)
    def reboot_bootloader(self):
        self.reboot('bootloader')
    def root(self):
        return self.__adb_service__('root','')
    def remount(self):
        return self.__adb_service__('remount','')
    def shell(self,command):
        #print command,
        ret = self.__adb_service__('shell', command)
        #print repr(ret)
        return ret
    def add_trigger(self,command,trigger):#=TRIGGER("","",Queue.Queue())):
        trig = trigger.on_receive
        trih = trigger.finish
        #evt = threading.Event()
        #evt.set()
        #evt.isSet()
        service = "shell"
        local_id = self.__get_local_id__()
        self.sender_queue.put(('OPEN', local_id, 0, '%s:%s\0' % (service, command),))
        while True:
            cmd, arg0, arg1, data, = self.__get_control__(local_id)
            if cmd in ['CLSE', 'OKAY']:
                break
        their_remote_id, their_local_id = arg0, arg1,
        if local_id != their_local_id:
            "something happend"
        if cmd == 'CLSE':
            return None
        #while True:
        #    cmd, arg0, arg1, data, = self.__get_control__()
        #    if cmd in ['CLSE']:
        #        break
        #if cmd == 'CLSE':
        #    self.send_queue.put_nowait(('CLSE', arg1, arg0, ''))
        self.trigger_id_pairs[arg1] = arg0
        k = "%d-%d" % (arg1,arg0)
        #if DEBUG_SHUXIN: print [cmd,k,data]
        if not self.trigger_queue.has_key(k):
            self.trigger_queue[k] = Queue.Queue()
            self.receiver_queue_for_queue.put((k,self.trigger_queue[k]))
        if not self.trigger_flags.has_key(k):
                self.trigger_flags[k] = threading.Event()
                self.trigger_flags[k].set()
                #b.clear()
        t = threading.Thread(target=__AdbMessage__.msg_trigger,args=(self.trigger_flags[k],self.trigger_queue[k],trig,trih),name=str(trig))
        t.start()
        self.trigger_thread[k] = t
        return None
    def stop_all_triggers(self):
        for k,v in self.trigger_flags.items():
            v.clear()
            x,y = k.split("-")
            self.sender_queue.put(('CLSE', int(x), int(y), ''))
        for k,v in self.trigger_queue.items():
            v.put('')
        #for k,v in self.trigger_thread.items():
        #    self.trigger_thread[k].join()
        #    pass
    def get_window_list(self):
        return self.shell("dumpsys window list")
    def get_window_focus(self):
        return self.shell("dumpsys window get_focus")
    def get_window_detail(self):
        return self.shell("dumpsys window policy")
    def get_window_list_detail(self):
        return self.shell("dumpsys window windows")
    def get_window_focus_detail(self):
        return self.shell("dumpsys window displays")
    def get_window_xml(self):
        self.rmall("/data/local/tmp/cmuidump.xml")
        self.shell('/system/bin/uiautomator dump /data/local/tmp/cmuidump.xml')
        return self.pull("/data/local/tmp/cmuidump.xml")
    def get_screenshot(self,fnm=""):
        self.rmall("/data/local/tmp/screenshot.png")
        ret = self.shell('/system/bin/screencap -p /data/local/tmp/screenshot.png')
        self.pull("/data/local/tmp/screenshot.png",fnm)
        return ret
    def input_tap_point(self,x,y):
        ret = self.shell('input tap %s %s '%(x,y))  #
        return ret
    def input_touch_postion(self,x,y):
        ret = self.shell('input tap %s %s '%(x,y))  #
        return ret
    def input_button_home(self):
        ret = self.shell('input keyevent 3 ')  #   --longpress
        return ret
    def input_button_back(self):
        ret = self.shell('input keyevent 4 ')  #Run_Comeback
        return ret
    def input_button_appswitch(self):
        ret = self.shell('input keyevent 187 ')  #KEYCODE_APP_SWITCH
        return ret
    def input_button_power(self):
        ret = self.shell('input keyevent 26 ')
        return ret
    def input_button_menu(self):
        ret = self.shell('input keyevent 82 ')
        return ret
    def input_button_volup(self):
        ret = self.shell('input keyevent 24 ')
        return ret
    def input_button_voldown(self):
        ret = self.shell('input keyevent 25 ')
        return ret
    def airplane_mode_start(self):
        ret = self.shell('service call connectivity 59 i32 1')
        return ret
    def airplane_mode_stop(self):
        ret = self.shell('service call connectivity 59 i32 0')
        return ret
    def svc_wifi_enable(self):
        ret = self.shell('svc wifi enable')
        return ret

class trig_sample(TRIGGER):
    def __init__(self,name,filename,queun_callback):
        self.name = name
        self.fd = open(filename,"wb")
        self.queue = queun_callback
    def on_receive(self,data):
        self.fd.write(data)
        #print data
        self.fd.flush()
        if "ril" in data:
            self.queue.put((self.name,"fount ril in log",))
    def finish(self):
        self.fd.close()

def filemode(mode):
    _filemode_table = (
        ((stat.S_IFLNK,              "l"),
         (stat.S_IFREG,              "-"),
         (stat.S_IFBLK,              "b"),
         (stat.S_IFDIR,              "d"),
         (stat.S_IFCHR,              "c"),
         (stat.S_IFIFO,              "p")),
        ((stat.S_IRUSR,              "r"),),
        ((stat.S_IWUSR,              "w"),),
        ((stat.S_IXUSR|stat.S_ISUID, "s"),
         (stat.S_ISUID,              "S"),
         (stat.S_IXUSR,              "x")),
        ((stat.S_IRGRP,              "r"),),
        ((stat.S_IWGRP,              "w"),),
        ((stat.S_IXGRP|stat.S_ISGID, "s"),
         (stat.S_ISGID,              "S"),
         (stat.S_IXGRP,              "x")),
        ((stat.S_IROTH,              "r"),),
        ((stat.S_IWOTH,              "w"),),
        ((stat.S_IXOTH|stat.S_ISVTX, "t"),
         (stat.S_ISVTX,              "T"),
         (stat.S_IXOTH,              "x"))
    )
    perm = []
    for table in _filemode_table:
        for bit, char in table:
            if mode & bit == bit:
                perm.append(char)
                break
        else:
            perm.append("-")
    return "".join(perm)


def test():

    adb = ADB_DIRECT("127.0.0.1",5555)
    c = 30
    while c:
        c -= 1
        if adb.connect():
            break
        else:
            time.sleep(1)
    tgmsg = Queue.Queue()
    tgmsg.put(["test","hello message"])
    tg1 = trig_sample("trig1",r"g:\trig1.txt",tgmsg)
    tg2 = trig_sample("trig2",r"g:\trig2.txt",tgmsg)
    adb.add_trigger("logcat",tg1)
    adb.add_trigger("top -m 5",tg2)
    print [adb.shell("ps")]
    print [adb.shell("pwd")]
    print [adb.root()]
    print [adb.remount()]

    time1 = time.time()
    print adb.push("/data/local/tmp/a.apk",r"g:\test.apk",stat.S_IFREG | stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
    print time.time() - time1

    print [adb.stat("/data/local/tmp/a.apk")]
    print [adb.stat("/data/local/tmp/")]
    print [adb.stat("/data/local/tmd/")]
    y = adb.list("/data/local/tmp/")
    if y:
        for x in y:
            a,b,c,d = x
            print filemode(b),'%15d' % c,time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(d)),a
    else:
        print ['']
    print [adb.stat("/data/local/tmd/b.apk")]
    print [adb.list("/data/local/tmd/")]
    print adb.pull("/data/local/tmp/a.apk",r"g:\test.apk")



    time1 = time.time()
    print [adb.shell('pm install -r /data/local/tmp/a.apk')]
    print time.time() - time1




    time.sleep(10)
    adb.stop_all_triggers()
    adb.close()
    print "end"

if __name__ == "__main__":
    while True:
        test()
