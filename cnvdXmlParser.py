import xml.etree.ElementTree as ET 
import pathlib
import requests
from config import (
    username, password, login_url, code
)

def get_xml_files(dirname):
    xml_folder = pathlib.Path(dirname) 
    for xml in xml_folder.glob('*.xml'):
        yield xml

def findattr_wrap(item, element):
    if item.findtext(element):
        return item.findtext(element)
    else:
        return "暂无"

def login(session):

    login_form = {
        "username": username,
        "password": password,
        "code": code,
    }

    r = session.post(login_url, data=login_form)

def xml_parser(xml_file, session):
    with open(xml_file, 'r', encoding='utf-8') as f:
        tree = ET.parse(f)
        for item in tree.iterfind("vulnerability"):
            cnvdnumber = findattr_wrap(item, "number")
            cvenumber = findattr_wrap(item, 'cves/cve/cveNumber')
            title = findattr_wrap(item, "title")
            serverity = findattr_wrap(item, 'serverity')
            products = findattr_wrap(item, 'products/product')
            vuln_type = findattr_wrap(item, 'isEvent')
            open_time = findattr_wrap(item, 'openTime')
            referencelink = findattr_wrap(item, 'referenceLink')
            patch_method = findattr_wrap(item, 'formalWay')
            
            print(cnvdnumber)
            print(cvenumber)
            print(title)
            print(serverity)
            print(products)
            print(vuln_type)
            print(open_time)
            print(referencelink)
            print(patch_method)
            print()

def get_cvss(cveNumber):
    pass
    

def main():
    with requests.Session() as ss:
        for xml_file in get_xml_files("vulns/xml"):
            xml_parser(xml_file, ss)

if __name__ == "__main__":
    main()