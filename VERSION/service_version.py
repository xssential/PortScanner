import socket
from SYN.tcp_syn import *
import ssl

def get_service_name(port:int)->str:  # 포트 번호로 서비스 이름 반환
    """
    Return Service name of the port

    Args:
        port (int): Target port

    Return:
        str: Service name or str unknown
    """
    try:
        return socket.getservbyport(port, 'tcp')
    except OSError:
        return 'unknown'
    
def get_basic_banner(targetIp:str, port:int, timeout:int)->str:  # TCP 연결 후 배너 수집
    """
    Collect banner after establishing TCP connection

    Args:
        targetIp (str): Target ip address
        port (int): Target port
        timeout (int): Response time
        
    Return:
        set: service banner or No Banner
    """
    try:
        with socket.create_connection((targetIp, port), timeout) as sock:  # 서비스 응답을 읽음
            sock.sendall(b'\r\n')  # 간단한 핑 신호 전송
            banner = sock.recv(1024).decode(errors='ignore').strip()
            return banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return 'No Banner'
    
def get_ssl_banner(targetIp:str, port:int, timeout:int)->str:  # SSL 연결로 배너 수집
    """
    Collect banner with SSL connection

    Args:
        targetIp (str): Target ip address
        port (int): Target port
        timeout (int): Response time

    Return:
        set: service banner or No Banner
    """
    try:
        with socket.create_connection((targetIp, port), timeout) as sock:
            if port == 443:
                context = ssl.create_default_context()
                with context.wrap_socket(sock, server_hostname=targetIp) as sslConn:
                    sslConn.sendall(b'HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % targetIp.encode())
                    banner = sslConn.recv(1024).decode(errors='ignore').strip()
                    return banner
            sock.sendall(b'HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % targetIp.encode())  # 간단한 핑 신호 전송
            response = sock.recv(1024).decode(errors='ignore').strip()
            banner = extract_server_header(response)
            return banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return 'No Banner'

def extract_server_header(response:str):  # 응답에서 "Server" 헤더 추출
    """
    Ectract response from the header Server

    Args:
        response (str): response header of the server
    
    Return:
        If there is server in header -> server information or None

    """
    headers = response.split('\r\n')
    for header in headers:
        if header.lower().startswith('server:'):
            return header
    return None
    
def scan_service_version(targetIp:str, port:int, timeout:int, maxTries:int)->tuple:    # SYN 스캔 후 서비스 이름과 배너 정보 반환
    """
    Return service name and banner information after SYN scan

    Args:
        targetIp (str): Target ip address
        port (int): Target port
        timeout (int): Response time
        maxTries (int): Number of attempts made by the tool

    Return:
        tuple: SYN scan result (service name, service banner)
    """
    result = scan_syn_port(targetIp, port, timeout, maxTries)
    if result[1] == 'Open':
        if port == 80 or port == 443:
            return result[0], result[1], get_service_name(port), get_ssl_banner(targetIp, port, timeout)
        else:
            return result[0], result[1], get_service_name(port), get_basic_banner(targetIp, port, timeout)
    return result[0], result[1], None, None