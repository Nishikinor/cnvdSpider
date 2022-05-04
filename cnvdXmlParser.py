import xml.etree.ElementTree as ET 
import pathlib
import requests
import re
from config import (
    username, password, login_url, code
)
import json

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

def write_vuln_to_json(details: dict):
    j = json.dumps(details, ensure_ascii=False, indent=4) 
    json_path = pathlib.Path("vulns/xml2json")
    json_path.mkdir(parents=True, exist_ok=True)
    filename = details['cnvdnumber'] + ".json"
    with open(json_path / filename, mode="w", encoding="utf-8") as f:
        f.write(j)



def xml_parser(xml_file):
    details = {}
    with open(xml_file, 'r', encoding='utf-8') as f:
        tree = ET.parse(f)
        for item in tree.iterfind("vulnerability"):
            details['cnvdnumber'] = findattr_wrap(item, "number")
            details['cvenumber'] = findattr_wrap(item, 'cves/cve/cveNumber')
            details['title'] = findattr_wrap(item, "title")
            details['serverity'] = findattr_wrap(item, 'serverity')
            details['products'] = findattr_wrap(item, 'products/product')
            details['vuln_type'] = findattr_wrap(item, 'isEvent')
            details['open_time'] = findattr_wrap(item, 'openTime')
            details['referencelink'] = findattr_wrap(item, 'referenceLink')
            details['patch_method'] = findattr_wrap(item, 'formalWay')
            write_vuln_to_json(details)

            
def get_cvss(cve_number: str):
    nvd_url = "https://nvd.nist.gov/vuln/detail/" + cve_number
    text = requests.get(nvd_url)
    cvss2_pattern = re.compile(r'\"Cvss2CalculatorAnchor\"[\s\n]+.*?\label.*?>(\d.\d) (\w+)', re.MULTILINE)

    matches = re.finditer(cvss2_pattern, text)
    for match in matches:
        cvss_number = match.group(1)
        cvss_level = match.group(2)
            
    return cvss_number, cvss_level
    
def main():
    with requests.Session() as ss:
        # login(ss)
        for xml_file in get_xml_files("vulns/xml"):
            xml_parser(xml_file)

if __name__ == "__main__":
    main()