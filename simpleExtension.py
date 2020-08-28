from burp import IBurpExtender
from java.net import URL

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks( self, callbacks):
        u = URL('http://portswigger-labs.net')
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Check Spider")

        callbacks.sendToSpider(u) # triggers a crawl of portswigger-labs.net

        str = "GET / HTTP/1.1\r\nHost: portswigger-labs.net\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.125 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-GB,en-US;q=0.9,en;q=0.8\r\nConnection: close\r\n\r\n"
        arr = self._helpers.stringToBytes(str)

        callbacks.makeHttpRequest("portswigger-labs.net", 80, False, arr) #sends an http request to portswigger-labs.net only visible using flow/logger++ but may get caught by processHttpMessage?
        callbacks.doActiveScan("portswigger-labs.net", 80, False, arr) # starts an extension driven audit of portswigger-labs.net same effect as right-clicking an item in sitemap, audit selected item.

        return
