#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys, time, socket, copy, json
import prettytable as pt
import threading
from threading import Thread

__author__ = 'mingkwind'
'''
addr2rName字典为建立地址和路由器名的一一对应
'''
addr2rName = {}
addr2rName[("192.168.126.65", 20000)] = 'A'
addr2rName[("192.168.126.66", 20000)] = 'B'
addr2rName[("192.168.126.67", 20000)] = 'C'
addr2rName[("192.168.126.68", 20000)] = 'D'
addr2rName[("192.168.126.69", 20000)] = 'E'


class Router(socket.socket):
    '''
    这是一个继承socket.socket的类，用于实现路由器功能：
    该路由器可用于有更新定时器（update）下DV路由算法，模拟路由表收敛的过程，
    对于无穷计数和路由回路，采用逆向毒化（poison reverse）加以解决。
    对于链路变化过程，可模拟linkChange（邻居链路建立和距离改变）
    和linkDown（邻居链路断开）功能

    '''
    def __init__(self, router_address, neighbor, addr2rName, MaxHop=15):
        #用父类socket.socket的初始化方法来初始化继承的属性
        #初始化包含五个参数：
        #router_address：路由器地址，形式为（ip,port）
        #neighbor：邻居路由器，类型为字典，(key,value) = (rName, {addr, cost})
        #addr2rName:字典为建立地址和路由器名的一一对应
        #MaxHop:最大跳数，缺省值为15，MaxHop+1(16)表示不可达
        super(Router, self).__init__(
            socket.AF_INET,
            socket.SOCK_DGRAM)  #该路由器采用UDP传输，socket.SOCK_DGRAM用于UDP协议
        self.__addr = router_address
        self.__neighbor = neighbor
        self.__addr2rName = addr2rName
        self.__MaxHop = MaxHop

        self.__name = self.__addr2rName[self.__addr]  #所创建的路由器名
        self.__rName2addr = {}  #字典建立addr2rName的反向查找
        for addr in self.__addr2rName:
            self.__rName2addr[self.__addr2rName[addr]] = addr
        #路由表字典，(key,value)=(dest,{nextHop,cost})，初始时，路由表仅有邻居节点
        self.__rtrTable = {}
        for dest in self.__neighbor:
            self.__rtrTable[dest] = {}
            self.__rtrTable[dest]['nextHop'] = dest
            self.__rtrTable[dest]['cost'] = self.__neighbor[dest]['cost']
        self.__neighCost = {}  #邻居链路的开销，(key, value) = (nextHop, cost)
        for nextHop in self.__neighbor:
            self.__neighCost[nextHop] = self.__neighbor[nextHop]['cost']

        #改变链路距离的一方发送距离改变信息在头部加上的标记
        self.__linkChangeFlag = '*'
        #链路断开的一方发送连接断开信息在头部加上的标记
        self.__linkDownFlag = '#'

        self.__rtrTable_history = None  #上次更新的路由表
        self.__convergedPrintTimes = 0  #路由表收敛后控制其只输出一次

        #逆向毒化(poison reverse)算法的开启标志，默认为开启状态
        self.__PoisonReverse = True

    def __updateTimer(self):
        '''为了方便观察,此处更新定时器的目标函数将打印路由表，
        向邻居发送路由表结合在一起。'''
        self.__showrt()
        self.__sendRtrTable()

    def __showrt(self):
        '''此处当相邻两次
        的路由表相同，则认为路由收敛（实际可能未收敛）'''
        '''打印样例
        Distance vector list is:
        +-------------+---------+------+
        | destination | nexthop | cost |
        +-------------+---------+------+
        |      B      |    B    |  2   |
        |      E      |    E    |  2   |
        |      C      |    B    |  10  |
        |      D      |    E    |  8   |
        +-------------+---------+------+
        '''

        if str(self.__rtrTable) != str(self.__rtrTable_history):
            #路由表如果有更新就输出新路由表信息
            print('Distance vector list is:')
            tb = pt.PrettyTable()
            tb.field_names = ['destination', 'nexthop', 'cost']
            for dest in self.__rtrTable:
                if self.__rtrTable[dest]['cost'] > self.__MaxHop:
                    self.__rtrTable[dest]['cost'] = self.__MaxHop + 1
                tb.add_row([
                    dest, self.__rtrTable[dest]['nextHop']
                    if self.__rtrTable[dest]['cost'] <= self.__MaxHop else ' ',
                    self.__rtrTable[dest]['cost'] if
                    self.__rtrTable[dest]['cost'] <= self.__MaxHop else 'inf'
                ])
            print(tb)
            #更新历史路由表，注意此处必须用深拷贝，否则会出错
            self.__rtrTable_history = copy.deepcopy(self.__rtrTable)
            self.__convergedPrintTimes = 0
        else:
            if self.__convergedPrintTimes == 0:
                #如果是第一次打印就输出路由表收敛信息，否则不打印路由表
                print('The network has converged:')
                tb = pt.PrettyTable()
                tb.field_names = ['destination', 'nexthop', 'cost']
                for dest in self.__rtrTable:
                    if self.__rtrTable[dest]['cost'] > self.__MaxHop:
                        self.__rtrTable[dest]['cost'] = self.__MaxHop + 1
                    tb.add_row([
                        dest, self.__rtrTable[dest]['nextHop']
                        if self.__rtrTable[dest]['cost'] <= self.__MaxHop else
                        ' ', self.__rtrTable[dest]['cost']
                        if self.__rtrTable[dest]['cost'] <= self.__MaxHop else
                        'inf'
                    ])
                print(tb)
                self.__convergedPrintTimes = 1  #控制其只打印一次

    def __recvRtrTable(self):
        '''用于接受邻居发来的距离向量，并更新距离向量表'''
        while True:
            try:
                data, addr = self.recvfrom(1024)  #接收的最大数据量bufsize = 1024
                data = data.decode(encoding='UTF-8', errors='ignore')
                '''首字节判断是否为linkChange和linkDown信息'''
                if data[0] == self.__linkChangeFlag:
                    self.__linkChange(addr, int(data[1:]), needSend=False)
                elif data[0] == self.__linkDownFlag:
                    self.__linkDown(addr, needSend=False)
                else:
                    self.__updatertrTable(addr, json.loads(data))
            except ConnectionError as e:
                print(e)
                pass

    def __sendRtrTable(self):
        '''向所有邻居发送距离向量信息'''
        for nextHop in self.__neighbor:
            rtrtable = copy.deepcopy(self.__rtrTable)
            if self.__PoisonReverse:  #使用逆向毒化算法
                ''' 若向目的邻居发送的距离向量中某个最佳路由下一跳为该邻居，则将跳数
                设置为最大跳数+1（不可达）'''
                for dest in self.__rtrTable:
                    if dest != nextHop and self.__rtrTable[dest][
                            'nextHop'] == nextHop:
                        rtrtable[dest]['cost'] = self.__MaxHop + 1
                    else:
                        pass
            else:  #不使用逆向毒化算法
                pass
            data = json.dumps(rtrtable)
            self.sendto(data.encode(encoding='UTF-8', errors='ignore'),
                        self.__rName2addr[nextHop])

    def __updatertrTable(self, addr, rtrtable):
        '''更新路由表，采用距离向量算法，对于相邻路由器X发来的路由表rtrtable，
        根据其的每一个项目（目的路由器为N）进行以下步骤：
        若 N是自己，则什么也不做，跳过
        否则 进行以下判断
            若 原来的路由表没有N，则将其添加到路由表中，距离为c[X]+rtrtable[N]
            否则 根据其自己的下一跳路由器做如下判断：
                若 N对于自己的下一跳是X,则用c[X]+rtrtable[N]替换路由表中项目(*)，
                否则 进行以下判断:
                    若 c[X]+rtrtable[N]<自己到N的距离，则更新路由器
                    否则 什么也不做
        (*)替换原因：这是最新的消息，以最新消息为准，无论替换后是变大还是变小
        '''
        From = self.__addr2rName[addr]
        for dest in rtrtable:
            if dest == self.__name:
                continue
            elif dest not in self.__rtrTable:
                self.__rtrTable[dest] = {}
                self.__rtrTable[dest]['nextHop'] = From
                self.__rtrTable[dest]['cost'] = min(
                    self.__neighCost[From] + rtrtable[dest]['cost'],
                    self.__MaxHop + 1)
            elif self.__rtrTable[dest]['nextHop'] == From:
                self.__rtrTable[dest]['cost'] = min(
                    self.__neighCost[From] + rtrtable[dest]['cost'],
                    self.__MaxHop + 1)
            elif self.__neighCost[From] + rtrtable[dest][
                    'cost'] < self.__rtrTable[dest]['cost']:
                self.__rtrTable[dest]['cost'] = min(
                    self.__neighCost[From] + rtrtable[dest]['cost'],
                    self.__MaxHop + 1)
                self.__rtrTable[dest]['nextHop'] = From
            else:
                pass

    def __parseUserInput(self):
        '''输入相应命令并选择相应功能'''
        while True:
            try:
                order = input().split()
                if order[0] == 'linkchange':
                    addr = (order[1], int(order[2]))
                    dist = int(order[3])
                    self.__linkChange(addr, dist, needSend=True)
                elif order[0] == 'linkdown':
                    addr = (order[1], int(order[2]))
                    self.__linkDown(addr, needSend=True)
                else:
                    print("InputError")
            except:
                print("InputError")

    def __linkChange(self, addr, dist, needSend):
        '''链路改变函数，输入要改变的目的邻居的addr以及改变后的跳数，其中布尔变量
        needSend表示是否向目的邻居发送改变信息，对于主动改变的一方，needSend=True，
        对于被动接受改变的一方，needSend=False。请注意，此函数也可以用于建立邻居关系。
        在距离改变后，立即重置self.__convergedPrintTimes和self.__rtrTable_history，
        使其在下个周期将更新后的路由表打印出来'''
        rName = self.__addr2rName[addr]
        '''如果目的addr不是其邻居，会将其加入本路由器的邻居中'''
        self.__neighbor[rName] = {}
        self.__neighbor[rName]['addr'] = addr
        self.__neighbor[rName]['cost'] = dist
        self.__neighCost[rName] = dist
        self.__rtrTable[rName] = {}
        self.__rtrTable[rName]['nextHop'] = rName
        self.__rtrTable[rName]['cost'] = dist
        self.__convergedPrintTimes = 0
        self.__rtrTable_history = None
        if needSend:
            data = self.__linkChangeFlag + str(dist)
            self.sendto(data.encode(encoding='UTF-8', errors='ignore'), addr)

    def __linkDown(self, addr, needSend):
        '''链路断开函数，输入要断开连接的目的邻居的addr，其中布尔变量needSend表示
        是否向目的邻居发送改变信息，对于主动改变的一方，needSend=True，对于被动接受
        改变的一方，needSend=False。在与邻居断开连接后，将链路距离设置为最大跳数+1
        （不可达），立即重置self.__convergedPrintTimes和self.__rtrTable_history，
        使其在下个周期更新后的路由表打印出来'''
        rName = self.__addr2rName[addr]
        self.__neighbor.pop(rName)
        self.__neighCost.pop(rName)
        self.__rtrTable[rName] = {}
        self.__rtrTable[rName]['nextHop'] = rName
        self.__rtrTable[rName]['cost'] = self.__MaxHop + 1
        self.__convergedPrintTimes = 0
        self.__rtrTable_history = None
        if needSend:
            data = self.__linkDownFlag
            self.sendto(data.encode(encoding='UTF-8', errors='ignore'), addr)

    def setPoisonReverse(self, openState):
        '''逆向毒化算法开启状态'''
        self.__PoisonReverse = openState

    def start(self):
        '''路由表开启，包含两个子线程，一个每隔时间T更新路由表，打印一次路由表，向邻居
        发送距离向量，此处为了方便观察，将其设置为10s，另一个接受用户的输入命令。主线
        程用于接收邻居发来的距离向量并对rtrTable做更新。'''
        self.bind(self.__addr)

        th1 = RepeatTimer(10, self.__updateTimer)
        th1.start()
        th2 = RepeatTimer(0, self.__parseUserInput)
        th2.start()

        self.__recvRtrTable()


class RepeatTimer(threading.Thread):
    '''定时器类，继承于threading.Thread类，interval为时间间隔'''
    def __init__(self, interval, target):
        Thread.__init__(self)
        self.interval = interval
        self.daemon = True
        self.stopped = False
        self.target = target

    def run(self):
        while not self.stopped:
            time.sleep(self.interval)
            self.target()


def parse_argv():
    '''解析运行时的参数（第一次运行时），其输入格式为
    "python3 DVroute.py listening_port ip1 port1 dist1 ip2 port2 dist2···"，
    后面每个三元组代表每个邻居的距离信息'''
    s = sys.argv[1:]
    parsed = {}
    listening_port = s.pop(0)
    parsed['listening_port'] = int(listening_port)
    neighbor = {}
    for i in range(len(s) // 3):
        rName = addr2rName[(s[i * 3], int(s[i * 3 + 1]))]
        neighbor[rName] = {}
        neighbor[rName]['addr'] = (s[i * 3], int(s[i * 3 + 1]))
        neighbor[rName]['cost'] = int(s[i * 3 + 2])
    parsed['neighbor'] = neighbor
    return parsed


def get_host_ip():
    '''用于查询本机ip地址，返回值为ip'''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


def main():
    '''主函数调用该路由器，生成一个最大跳数为15的路由器'''
    ip = get_host_ip()
    parsed = parse_argv()
    rt = Router(router_address=(ip, parsed['listening_port']),
                neighbor=parsed['neighbor'],
                addr2rName=addr2rName,
                MaxHop=15)
    #此处设置为逆向毒化算法为关闭状态，若要使用，将其注释即可
    rt.setPoisonReverse(openState=False)
    rt.start()


if __name__ == '__main__':
    main()
