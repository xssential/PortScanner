from OPTION.option import *
from thread import *
import argparse
import time
from BANNER.banner import *

def main():
    print_banner()
    parser = argparse.ArgumentParser(usage=usage_msg())     #명령줄 파서 생성
    add_options(parser)
    if hasattr(parser, 'parse_intermixed_args'):        # 파서가 parse_intermixed_args 메서드를 지원하는지 확인
        options = parser.parse_intermixed_args()
    else:
        options = parser.parse_args()

    thread = Thread(
        ip=options.ip,
        port=options.port,
        timeout=options.time,
        numThread=options.threads,
        maxTries=options.tries,
        os=options.os,
        scanMethod=option(options),
        cve = options.cve,
        outputFile=options.output_json,
        outputXml=options.output_xml)
    
    startTime = time.time()
    thread.start_thread()
    elapsedTime = time.time() - startTime
    print(f'\nScan Completed. Elapsed Time: {elapsedTime:.2f}s')

if __name__=='__main__':
    main()