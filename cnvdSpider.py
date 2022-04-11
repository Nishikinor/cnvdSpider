import re
import ast
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import requests
import time
import random

class CnvdSpider:
    def __init__(self):
        self.url = "https://www.cnvd.org.cn/"
        self.headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
        }
    
    def get_cookies(self):
        options = Options()
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--headless')
        options.add_argument('user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36')
        options.add_argument('--disable-gpu')
        driver = webdriver.Chrome(options=options)
        driver.get(self.url)

        page_source = driver.page_source
        page_source = page_source.split("<script>")[1]
        page_source = page_source.split("</script>")[0]

        page_source = "var t;" + page_source
        temp_page_source = page_source.split("setTimeout");
        temp_page_source[-1]  = re.sub(r'location\[.*?\](.*?)location\[.*?\](.*?)location\[.*?\](\;|\)\;|\;\}|\)\;\}),_0x(\w{3,7})\)\;', '',temp_page_source[-1])
        page_source = 'setTimeout'.join(temp_page_source)
        page_source = re.sub(r'_0x(\w{0,6})\[_0x(\w{0,6})\(\'0x(\w{0,6})\'\,\'.{0,6}\'\)\+\'\w{0,6}\'\]\(setTimeout\,function\(\)\{', '', page_source)
        page_source = re.sub(r'setTimeout\(function\(\)\{','', page_source)
        page_source = page_source.replace("return!![];","")

        ccc = driver.execute_script(page_source + ";return document.cookie")
        
        cj = driver.get_cookies()
        cookie = ''
        for c in cj:
            cookie += "'"+c['name'] + "':'" + c['value'] + "',"
        cookie = ast.literal_eval('{'+cookie+'}')
        cookie['__jsl_clearance_s']=ccc.split("=")[1]

        return cookie

    def vuln_spider(self):
        vuln_list_url = self.url + "flaw/list?flag=true"
        time.sleep(random.randint(1, 4))
        self.cookie = self.get_cookies()
        r = requests.get(url=vuln_list_url, cookies=self.cookie, headers=self.headers)
        print(r.text)
        

def run():
    spider = CnvdSpider()
    cookie = spider.get_cookies()
    print(f"cookie:{cookie}")

    spider.vuln_spider()

if __name__ == '__main__':
    run()