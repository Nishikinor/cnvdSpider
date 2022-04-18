import xml.etree.ElementTree as ET
import pathlib

def main():
    xml_folder = pathlib.Path("vulns/xml")
    for xml in xml_folder.glob('*.xml'):
        with xml.open(encoding='utf-8') as f:
            tree = ET.parse(f)
            vulnerablitys = tree.getroot()
            for vulnerablity in vulnerablitys:
                for child in vulnerablity:
                    print(f"child.tag={child.tag}, child.text={child.text}")

if __name__ == "__main__":
    main()