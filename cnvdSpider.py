# -*-coding:utf-8-*- 
import re
import ast
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import requests
import time
import random
import json

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
        self.cookie = ""
        self.vuln_dict = {} # format: {"cnvdid": {"attr": "description"}}
    
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

    def vuln_spider(self, offset):
        vuln_list_url = self.url + "flaw/list?flag=true"

        form_data = {
            "number": "请输入精确编号",
            "startDate": "",
            "endDate": "",
            "field": "",
            "order": "",
            "numPerPage": 10,
            "offset": offset,
            "max": 10,
        }
        time.sleep(random.randint(1, 4))
        self.cookie = self.get_cookies()
        r = requests.post(url=vuln_list_url, cookies=self.cookie, headers=self.headers, data=form_data)
        return r.text

    def page_vuln_parser(self, content):
        pattern = r'<li><a href="(.*)" title="(.*)">'
        matches = re.finditer(pattern, content, flags=re.MULTILINE)
        for match in matches:
            cnvd_id = match.group(1).lstrip("/flaw/show")
            self.vuln_dict[cnvd_id] = {}

    def _vuln_details_parser(self, cnvd_id):
        vuln_url = self.url + "flaw/show/" + cnvd_id
        details = {}
        vuln_res = requests.get(vuln_url, cookies=self.cookie, headers=self.headers)
        content = vuln_res.text

        pattern = r"<td class=\"alignRight\">(.*?)</td>[\n\s]*?(?:(?:<td>([\n\s\w\uff0c\uff1a\u3002\D]*?)</td>)|(?:<td class=.*>[\s\S]*?([\u4e00-\u9fa5]+)[\s\S]*?</td>))"

        matches = re.finditer(pattern, content, re.MULTILINE | re.UNICODE)
        
        # Clean up the whitespace and escape chars
        clean_string = lambda s: s.replace('\r', '').replace('\t', '').replace('<br/>', ' ')
        
        for match in matches:
            description = clean_string(match.group(2).strip()) if match.group(2) else match.group(3) # 描述匹配
                
            details[match.group(1)] = description # log file

        self.vuln_dict[cnvd_id] = details
        
        return details

    def update_vuln_details(self):
        ''' Update vuln details in vuln_dict structure
        '''
        for cnvd_id in self.vuln_dict.keys():
            time.sleep(random.uniform(1.0, 3.0))
            self._vuln_details_parser(cnvd_id)

    def write_vuln_to_json(self, filename):
        j = json.dumps(self.vuln_dict)
        with open(filename, "w") as f:
            f.write(j)

def run():
    spider = CnvdSpider()
    content = spider.vuln_spider(20)
    spider.page_vuln_parser(content) 
    spider.update_vuln_details()
    spider.write_vuln_to_json(filename="vuln.json")

if __name__ == '__main__':
    run()