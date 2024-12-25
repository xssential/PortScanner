def usage_msg()->str:
    """
    Return the option of this tool
    """
    return 'python3 main.py <ip> [-sV] [-S] [-A] [-N] [-X] -P PORT [-T THREADS] [-t TIMEOUT] [-M TRIES] [-O] [-oj] [-ox] [-v]'

def add_options(parser:object)->None:
    """
    Functions that add command line factors
    If you want to add or modify the features use this function

    Args:
        argparse.ArgumentParser <object>
    """
    parser.add_argument('-S', dest='syn', action='store_true', help='TCP SYN scan')
    parser.add_argument('-A', dest='ack', action='store_true', help='TCP ACK scan')
    parser.add_argument('-N', dest='Null', action='store_true', help='TCP Null scan')
    parser.add_argument('-X', dest='Xmas', action='store_true', help='TCP X-mas scan')
    parser.add_argument('-sV', dest='service_version', action='store_true', help='Service version scan')

    parser.add_argument('ip', help='Target IP address')
    parser.add_argument('-P', dest='port', required=True, help="Specify port range (e.g., '22,80,443' or '20-30')")
    
    parser.add_argument('-T', dest='threads', type=int, default=1, help='Specify number of threads (default: 1)')
    parser.add_argument('-t', dest='time', type=float, default=1, help='Response Time')
    parser.add_argument('-M', dest='tries', type=int, default=1, help='Maximum tries')
    parser.add_argument('-O', dest='os', action='store_true', help='Detection OS')
    parser.add_argument('-v', dest='cve', action='store_true', help="Search CVE")
    
    parser.add_argument('-oj', dest='output_json', type=str, nargs='?', const='scanResult.json', help='Output JSON file')
    parser.add_argument('-ox', dest='output_xml', type=str, nargs='?', const='scanResult.xml', help='Output XML file')

def option(options:object)->str:  # 사용자가 선택한 스캔 옵션을 처리하는 함수
    """
    Return the scan method received by the user

    Args:
        argparse.ArgumentParser <object>

    Return:
        str: scan method
    """
    if options.service_version:
        return 'version'
    elif options.syn:
        return 'syn'
    elif options.ack:
        return 'ack'
    elif options.Null:
        return 'Null'
    elif options.Xmas:
        return 'Xmas'