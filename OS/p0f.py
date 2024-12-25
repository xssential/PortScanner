from pathlib import Path
from colors import *
import subprocess
import time
import sys
import os

def run_docker_p0f(logDir:str, targetIp:str)->dict:
    """
    Run the docker image p0f for detect OS of the service
    p0f: p0f is a passive TCP/IP stack fingerprinting tool. p0f can attempt to identify the system running on machines that send network traffic 
        to the box it is running on, or to a machine that shares a medium with the machine it is running on.
        More info: https://lcamtuf.coredump.cx/p0f3/

    Steps:
    1. Run the docker image p0f with target ip
    2. The entrypoint of the docker (run_p0f.sh) will get the target ip
    3. p0f in the docker container will execute curl to the target ip
    4. If the target ip send request the p0f will sniff the response
    5. If the fingerprint of the target ip OS is in the p0f.fp it will notice you the OS of the target
    6. If p0f.fp doesn't have the fingerprint of the target OS it will print ???

    Args:
        loDir (str): Current path (os.getcwd())
        targetIP (str): Target IP address
    
    Return:
        dict: {"IP":<target ip>, "OS":<os info detected by p0f>}
    """
    logDirPath = Path(logDir).resolve()
    logDirDocker = str(logDirPath).replace('\\', '/')
    
    docker_command = [
        'docker', 'run', '--rm', '--cap-add=NET_ADMIN',
        '-v', f'{logDirDocker}:/var/log/p0f',
        'p0f',targetIp
    ]
    
    print(f'{BLUE}[*]{RESET} Executing  Docker Container {YELLOW}p0f{RESET} for {YELLOW}{targetIp}{RESET}')
    
    try:  # 도커 실행
        subprocess.Popen(docker_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, universal_newlines=True)
    except FileNotFoundError:
        print(f'{RED}[-]{RESET} There is no Docker or Not included in {RED}$PATH{RESET}')
        return 'Unknown'
    except Exception as e:
        print(f'{RED}[-]{RESET} Error while ececuting Docker Container: {e}')
        return 'Unknown'
    time.sleep(3)
    logFile = logDirPath / f'{targetIp}_p0f_output.log'
    osInfo = extract_os_info(logFile)
    return dict(ip=targetIp, OS=osInfo)

def extract_os_info(logFilePath:str)->str:
    """
    Parse information of the OS from the logfile(<target ip>_p0f_output.log)
    If the process is slow the log may created after the tool search the log file
    In this case give sleep or contact us

    Args:
        logFilePath (str): path of the logfile
    
    Return:
        str: OS information from the p0f
    """
    osInfo = 'Unknown'
    try:
        with open(logFilePath, 'r') as logFile:
            lines = logFile.readlines()
            count = 0
            for line in lines:
                if '|os' in line:
                    count += 1
                    if count == 2:
                        osInfo = line.split('=')[5].strip().split('|')[0]
                        break
    except FileNotFoundError:
        print(f"{RED}[-]{RESET} Can't find log file: {YELLOW}{logFilePath}{RESET}")
    except Exception as e:
        print(f'{RED}[-]{RESET} Error while reading log file: {e}')
    try:
        os.remove(logFilePath)
        print(f'{BLUE}[*]{RESET} {YELLOW}{logFilePath}{RESET} deleted')
    except FileNotFoundError:
        print(f"{RED}[-]{RESET} Can't delete log file: {YELLOW}{logFilePath}{RESET}")
    
    return osInfo

def print_os_info(osInfo:list)->None:
    """
    print target OS information

    Args:
        osInfo (list): list of target OS
    """
    for OS in osInfo:
        print(f"{BLUE}[*]{RESET} OS detected at {YELLOW}{OS['ip']}{RESET} : {YELLOW}{OS['OS']}{RESET}")