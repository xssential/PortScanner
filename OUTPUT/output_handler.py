import json
import xml.etree.ElementTree as ET
from xml.dom import minidom
from colors import *
def save_result_as_json(ip:str, results:tuple, scanMethod:str, outputFile:str, osInfo=None, portCveList=None)->None:
    """
    Create output from the scan result as Json

    Args:
        ip (str): target ip
        results (tuple): port, state(open or closed ...), service name, service banner
        scanMethod (str): scan method (SYN, ACK, NULL, XMAS, Service Version)
        outputFile (str): name of the outputfile (default=scanResult.json/xml)
        osInfo (str): If OS detection is executed str else None
        portCveList (list): If CVE search is executed list else None
    """
    if scanMethod == 'version':  # 서비스와 배너 정보를 포함
        resultsJson = [
            {
                'port': port,
                'state': state,
                'service': service,
                'banner': banner,
            }
            for port, state, service, banner in results
        ]
    else:  # SYN 스캔 또는 다른 스캔 옵션의 경우
        resultsJson = [
            {
                'port': port,
                'state': state,
            }
            for port, state in results
        ]
        
    if portCveList:
        for result in resultsJson:
            result.update({'cve':portCveList.get(result['port'],[])})
        
            
    data = {
        'scanMethod': scanMethod,
        'results': resultsJson
    }

    if osInfo:
        data['osInfo'] = osInfo['OS']

    with open(f'{ip}_{outputFile}', 'w', encoding='utf-8') as f:  # utf-8로 파일 쓰기
        json.dump(data, f, indent=4)
    print(f'{GREEN}[INFO]{RESET} Results saved as JSON to {YELLOW}{ip}_{outputFile}{RESET}')  
    
def save_result_as_xml(ip:str, results:tuple, scanMethod:str, outputFile:str, osInfo=None, portCveList=None):
    """
    Create output from the scan result as XML

    Args:
        ip (str): target ip
        results (tuple): port, state(open or closed ...), service name, service banner
        scanMethod (str): scan method (SYN, ACK, NULL, XMAS, Service Version)
        outputFile (str): name of the outputfile (default=scanResult.json/xml)
        osInfo (str): If OS detection is executed str else None
        portCveList (list): If CVE search is executed list else None
    """
    # 루트 엘리먼트 생성
    root = ET.Element('ScanResults', scanMethod=scanMethod)

    # 결과 데이터를 XML로 추가
    for result in results:
        port = result[0]
        state = result[1]

        resultElement = ET.SubElement(root, 'Result')
        ET.SubElement(resultElement, 'Port').text = str(port)
        ET.SubElement(resultElement, 'State').text = state
        
        if scanMethod == 'version':
            service = result[2] if len(result) > 2 else None
            banner = result[3] if len(result) > 3 else None
            if service:
                ET.SubElement(resultElement, 'Service').text = service
            if banner:
                ET.SubElement(resultElement, 'Banner').text = banner

        # CVE 리스트 추가
        if portCveList:
            cveListElement = ET.SubElement(resultElement, 'CVEList')
            for cve in portCveList.get(port, []):
                ET.SubElement(cveListElement, 'CVE').text = cve

    if osInfo:
        osElement = ET.SubElement(root, 'OSInfo')
        ET.SubElement(osElement, 'OS').text = osInfo['OS']

    rough_string = ET.tostring(root, encoding='utf-8')
    reparsed = minidom.parseString(rough_string)
    pretty_xml = reparsed.toprettyxml(indent='    ')

    # XML 파일 저장
    with open(f'{ip}_{outputFile}', 'w', encoding='utf-8') as f:
        f.write(pretty_xml)
    print(f'{GREEN}[INFO]{RESET} Results saved as XML to {YELLOW}{ip}_{outputFile}{RESET}')
    
    ###########minidom.parseString 사용: ET.tostring으로 생성된 XML 문자열을 minidom으로 포맷팅.