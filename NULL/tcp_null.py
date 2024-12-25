from scapy.all import IP, TCP, sr1
import random

def scan_null_port(targetIp:str, port:int, timeout:int, maxTries:int)->str:
    """
    Performing TCP Null Scan on a Single Port

    Args:
        targetIP (str): one of IP listed in the IP list
        port (int): one of Port listed in the Port list
        timeout (int): Response Time
        maxTries (int): Number of attempts made by the tool

    Return:
        str: port, result of the scan or just str None

    """
    for i in range(maxTries):
        srcPort = random.randint(10000, 65535) # 랜덤 소스 포트 설정
        nullPacket = IP(dst=targetIp) / TCP(sport=srcPort, dport=port, flags='') # Null 패킷 생성
        response = sr1(nullPacket, timeout=timeout, verbose=0) # 패킷 전송 및 응답 대기
        if response is None:
            continue
        else:
            break

    # 스캔 결과 
    if response:
        if response.haslayer(TCP) and response[TCP].flags == 'RA':
            return port, 'Closed'
    else:
        return port, 'Open or Filtered'
    return 'None'