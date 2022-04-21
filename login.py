from http import cookies
from config import (
    username, password, code, login_url
)
import requests
import time

def login(session: requests.Session):

    login_form = {
        "username": username,
        "password": password,
        "code": code,
    }

    header = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36",
        "ts": str(int(time.time()*1000)),
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": "http://threat.fire369.com/",
        "Cookie": "td_cookie=737348907; JSESSIONID=5C9FED7FBA3186B05BC3909281180B02; sidebarStatus=0",
    }

    r = session.post(url=login_url, data=login_form, headers=header)
    print(r.text)
    
if __name__ == "__main__":
    ss = requests.Session()

    login(ss)
    ss.close()