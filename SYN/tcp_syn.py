from scapy.all import IP, TCP, sr1, send
import random

def scan_syn_port(targetIp:str, port:int, timeout:int, maxTries:int):
    """
    Execute TCP SYN Scan at single port

    Args:
        targetIP (str): one of IP listed in the IP list
        port (int): one of Port listed in the Port list
        timeout (int): Response Time
        maxTries (int): Number of attempts made by the tool

    Return:
        tuple: port and result of the scan
    """
    for i in range(maxTries):
        srcPort = random.randint(10000, 65535) # 랜덤 소스 포트 설정
        synPacket = IP(dst=targetIp) / TCP(sport=srcPort, dport=port, flags='S') # SYN 플래그를 설정한 TCP 패킷 생성
        response = sr1(synPacket, timeout=timeout, verbose=0) # 패킷 전송 및 응답 대기
        if response is None:
            continue
        else:
            break

    # 스캔 결과
    if response:
        if response.haslayer(TCP) and response[TCP].flags == 'SA':
            send(IP(dst=targetIp) / TCP(dport=port, flags='R'), verbose=0)
            return port, 'Open'
        elif response.haslayer(TCP) and response[TCP].flags == 'RA':
            return port, 'Closed'
    return port, 'Filtered'