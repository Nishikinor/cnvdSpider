# -*-coding:utf-8-*- 
import re
import ast
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import requests
import time
import random
import json
from http.client import HTTPConnection
import logging
import contextlib

def debug_requests_on():
    """Switches on logging of the requests module.
    """
    HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger('requests.packages.urllib3')
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True

def debug_requests_off():
    """Switches off logging of the requests module, might be some side-effects
    """
    HTTPConnection.debuglevel = 0
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.Warning)
    root_logger.handlers = []
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.WARNING)
    requests_log.propagate = False
    
@contextlib.contextmanager
def debug_requests():
    debug_requests_on()
    yield
    debug_requests_off()
    
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
        self.session = requests.Session()
        self.session.headers.update(self.headers)
    
    def get_cookies(self):
        options = Options()
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--headless')
        options.add_argument('user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36')
        options.add_argument('--disable-gpu')
        driver = webdriver.Chrome(options=options)
        driver.get(self.url + "flaw/list.htm")

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

        self.session.cookies.update(cookie)

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
        
        time.sleep(random.uniform(2.0, 6.0))
        if offset == 0:
            r = self.session.get(url=self.url+"flaw/list")
        else:   
            r = self.session.post(url=vuln_list_url, data=form_data)
            
        return r.text

    def page_vuln_parser(self, content):
        pattern = r'<a[\s\n]+?href=\"/flaw/show/(.*)\"[\s\n]+title=\"(.*)\"'
        matches = re.finditer(pattern, content, flags=re.MULTILINE)
        for match in matches:
            cnvd_id = match.group(1)
            self.vuln_dict[cnvd_id] = {}

    def _vuln_details_parser(self, cnvd_id):
        """Parse the vulnerablity details which presented on the current page.
        """
        vuln_url = self.url + "flaw/show/" + cnvd_id
        details = {}
        vuln_res = self.session.get(vuln_url)
        content = vuln_res.text
        status_code = vuln_res.status_code

        pattern = r"<td class=\"alignRight\">(.*?)</td>[\n\s]*?(?:(?:<td>([\n\s\w\uff0c\uff1a\u3002\D]*?)</td>)|(?:<td class=.*>[\s\S]*?([\u4e00-\u9fa5]+)[\s\S]*?</td>))"

        matches = re.finditer(pattern, content, re.MULTILINE | re.UNICODE)
        
        # Clean up the whitespace and escape chars
        handle_string = lambda s: s.replace('\r', '').replace('\t', '').replace('<br/>', ' ').replace('\n\n', '\n')
        
        for match in matches:
            description = handle_string(match.group(2).strip()) if match.group(2) else match.group(3) # 描述匹配
                
            details[match.group(1)] = description # log file

        self.vuln_dict.update({cnvd_id: details})
        
        return status_code

    def update_vuln_details(self):
        """ Update vuln details in vuln_dict structure
        """
        start_time = time.time()
        for cnvd_id, details in self.vuln_dict.items():
            if not details:
                time.sleep(random.uniform(3.0, 10.0))
                status_code = self._vuln_details_parser(cnvd_id)
                if status_code != 200:
                    break
                end_time = time.time()
                if end_time - start_time > 3500:
                    self.get_cookies()

    def write_vuln_to_json(self, filename):
        j = json.dumps(self.vuln_dict, ensure_ascii=False, indent=4)
        with open(filename, "w", encoding="utf-8") as f:
            f.write(j)

def vuln_list_spider():
    spider = CnvdSpider()
    spider.get_cookies()

    debug_requests_on()
    for offset in range(0, 100, 10):
        content = spider.vuln_spider(offset)
        spider.page_vuln_parser(content) 

    spider.update_vuln_details()

    spider.write_vuln_to_json(filename="vuln.json")

def run():
    vuln_list_spider()

if __name__ == '__main__':
    run()