from http import cookies
from config import (
    username, password, code, login_url
)
import requests
import time
from cnvdSpider import debug_requests_on

def get_content_length(form_data: dict):
    length = len(form_data.keys()) * 2 - 1
    total = ''.join(list(form_data.keys()) + list(form_data.values())).encode()
    length += len(total)
    return str(length)

def login(session: requests.Session):

    login_form = {
        "name": username,
        "password": password,
        "code": str(code),
    }

    header = {
        "Host": "threat.fire369.com",
        "Content-Length": get_content_length(login_form),
        # "Content-Length": "47",
        "Accept": "application/json, text/plain, */*",
        "ts": str(int(time.time()*1000)),
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "http://threat.fire369.com",
        "Referer": "http://threat.fire369.com/",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Cookie": "JSESSIONID=5B938D7B27D490F521F33F0279700077",
        "Connection": "close",
    }

    r = session.post(url=login_url, data=login_form, headers=header)
    print(r.text)

def run():
    ss = requests.Session()
    
    login(ss)
    
    ss.close()
    
if __name__ == "__main__":
    run()