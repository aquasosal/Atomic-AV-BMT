#!/usr/bin/env python3
import yaml
import os
import subprocess
import sys
import argparse
import datetime
import time

# 색상 정의
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[0;33m'
CYAN = '\033[0;36m'
NC = '\033[0m'  # No Color

# 결과 저장 디렉토리 - 홈 디렉토리에 저장
HOME_DIR = os.path.expanduser("~")
RESULTS_DIR = os.path.join(HOME_DIR, "AtomicTestResults")
RESULTS_FILE = f"{RESULTS_DIR}/Linux_Test_Results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

# 디렉토리 생성
os.makedirs(RESULTS_DIR, exist_ok=True)

# 테스트할 Linux 테크닉 목록 (확장된 목록)
linux_techniques = {
    # 기존 테크닉
    "T1059.004": "Linux Bash Commands;1,2,5,6,7,8,9,11,13,14",
    "T1053.003": "Linux Cron;1,2,3,4",
    "T1136.001": "Local Account Creation;1,6",
    "T1027": "Obfuscated Files;1",
    "T1222.002": "Linux File Permissions;1,2,3,4,5,6,7,8,9,13",
    "T1070.004": "File Deletion;1,2,3",
    "T1497.003": "Time Based Evasion;1",
    "T1036.005": "Match Legitimate Name;1",
    "T1552.001": "Credentials in Files;1, 3, 6, 15, 16, 17",
    "T1082": "System Information Discovery;3, 4, 5, 8, 12, 24",
    "T1016": "Network Configuration Discovery;3",
    "T1033": "System Owner/User Discovery;2",
    "T1057": "Process Discovery;1",
    "T1560.001": "Archive Collected Data;6",
    "T1071.001": "Web Protocols;3",
        
    # 새로 추가된 테크닉
    "T1140": "Deobfuscate Files or Information;3,4,5,7,8,9",
    "T1217": "Browser Bookmark Discovery;1,4",
    "T1562.004": "Disable or Modify System Firewall;7,9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19",
    "T1003.008": "OS Credential Dumping;1,2,3",
    "T1007": "System Service Discovery;3",
    "T1036.003": "Masquerading;2",
    "T1059.006": "Python;1,2,3",
    "T1083": "File and Directory Discovery;3,4",
    "T1087.001": "Account Discovery;1, 2, 3, 4, 5, 6",
    "T1574.006": "Dynamic Linker Hijacking;1",
    "T1014": "Rootkit;3,4",
    "T1486": "Data Encrypted for Impact;1,3,4",
    "T1553.004": "Install Root Certificate;3",
    "T1564.001": "Process Argument Spoofing;1",
    
    #2rd 추가된 테크닉
    "T1110.001": "Brute Force - Password Guessing;5",
    "T1552.004": "Unsecured Credentials - Private Keys;2,3,5,7",
    "T1040": "Network Sniffing;1",
    "T1016.001": "System Network Configuration Discovery;2",
    "T1069.001": "Permission Groups Discovery - Local Groups;1",
    "T1049": "System Network Connections Discovery;3",
    "T1562.001": "Disable or Modify Tools;1,3,4,5",
    "T1562.003": "Impair Defenses - Histories;1,3,5,6,7,8,10",
    "T1036.004": "Masquerade Task or Service;3,4",
    "T1113": "Screen Capture;3",
    "T1056.001": "Keylogging;2,3",
    "T1115": "Clipboard Data;5",
    "T1074.001": "Local Data Staging;2",
    "T1485": "Data Destruction;2",

}

# 랜섬웨어 관련 테크닉 목록
ransomware_techniques = [
    "T1486",  # Data Encrypted for Impact
    "T1561",  # Disk Wipe
    "T1561.001",  # Disk Content Wipe
    "T1561.002",  # Disk Structure Wipe
    "T1485"   # Data Destruction
]

# 변수 대체 함수
def replace_variables(command, input_args=None):
    if not input_args:
        input_args = {}
    
    # 기본 변수 값 설정
    default_vars = {
        "#{script_path}": "/tmp/atomic_script.sh",
        "#{host}": "8.8.8.8",  # Google DNS
        "#{domain}": "example.com",
        "#{remote_host}": "example.com",
        "#{username}": "atomic_user",
        "#{password}": "atomic_pass",
        "#{file_name}": "atomic_test.txt",
        "#{file_path}": "/tmp/atomic_test.txt",
        "#{directory_path}": "/tmp/atomic_test_dir",
        "#{url}": "https://example.com",
        "#{port}": "8080",
        "#{ip_address}": "127.0.0.1",
        "#{ping_target}": "8.8.8.8",
        "#{interface}": "ens33",
        # 추가 변수들
        "#{exe_path}": "/tmp/prctl_rename",
        "#{command}": "/usr/bin/touch /tmp/cron_test_file",
        "#{tmp_cron}": "/tmp/fake_crontab",
        "#{local_path}": "/tmp/atomic_local.txt",
        "#{remote_path}": "/tmp/atomic_remote.txt",
        "#{exe_file}": "/tmp/atomic_test.sh",
        "#{process_name}": "bash",
        "#{file_or_folder}": "/tmp/AtomicRedTeam/atomics/T1222.002",
        "#{owner}": "root",
        "#{group}": "root",
        "#{file_to_modify}": "/var/spool/cron/root",
        "#{numeric_mode}": "755",  # 또는 777, 644 등 적절한 퍼미션
        "#{symbolic_mode}": "a+w",
        "#{user_account}": os.getenv('USER', 'atomic_user'),
        "#{command_path}": "/usr/bin/whoami",
        "#{command_string}": "whoami",
        "#{output_file}": "/tmp/atomic_output.txt",
        "#{seconds_to_sleep}": "5",
        "#{source_file}": "/tmp/AtomicRedTeam/atomics/T1222.002/src/T1222.002.c",
        "#{compiled_file}": "/tmp/T1222002",
        "#{source_file}": "/tmp/AtomicRedTeam/atomics/T1222.002/src/chown.c",
        "#{compiled_file}": "/tmp/T1222002own",
        "#{destination_file}": "/tmp/atomic_destination.txt",
        "#{python_script}": "/tmp/atomic_script.py",
        "#{python_command}": "print('Hello, Atomic!')",
        "#{bash_script}": "/tmp/atomic_script.sh",
        "#{bash_command}": "echo 'Hello, Atomic!'",
        "#{temp_folder}": "/tmp/atomic_temp",
        "#{zip_file}": "/tmp/atomic_archive.zip",
        "#{tar_file}": "/tmp/atomic_archive.tar.gz",
        "#{mount_point}": "/mnt/atomic_mount",
        "#{script_url}": "https://github.com/carlospolop/PEASS-ng/releases/download/20220214/linpeas.sh",
        "#{python_script_name}": "T1059.006.py",
        "#{python_binary_name}": "T1059.006.pyc",
        "#{payload_file_name}": "T1059.006-payload",
        "#{executor}": "sh",
        "#{script_args}": "-q -o SysI, Devs, AvaSof, ProCronSrvcsTmrsSocks, Net, UsrI, SofI, IntFiles",
        "#{rootkit_path}": "/tmp/atomic_rootkit",
        "#{rootkit_name}": "T1014",
        "#{rootkit_source_path}": "atomics/T1014/src/Linux",
        # T1486 테스트용 변수
        # 테스트 1: GPG
        "#{pwd_for_encrypted_file}": "passwd",
        "#{encrypted_file_path}": "/tmp/passwd.gpg",
        "#{input_file_path}": "/etc/passwd",
        "#{encryption_alg}": "AES-256",
        "#{which_gpg}": "/usr/bin/gpg",  # gpg 실행 파일 경로 (which gpg 결과값)

    }
    
    # 사용자 제공 값이 있으면 기본값 덮어쓰기
    for key, value in input_args.items():
        default_vars[key] = value
    
    # 변수 대체
    result = command
    for var, value in default_vars.items():
        result = result.replace(var, value)
    
    return result

def run_command(command, log_file=None, specific_vars=None):
    """명령어 실행 및 결과 처리"""
    # 변수 대체
    command = replace_variables(command, specific_vars)
    
    print(f"{CYAN}[*] 실행 명령어: {command}{NC}")
    if log_file:
        log_file.write(f"실행 명령어: {command}\n")
    
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        if result.stdout:
            print(result.stdout)
            if log_file:
                log_file.write(f"출력:\n{result.stdout}\n")
        
        if result.stderr:
            print(f"{RED}오류: {result.stderr}{NC}")
            if log_file:
                log_file.write(f"오류:\n{result.stderr}\n")
        
        return result.returncode
    except Exception as e:
        print(f"{RED}예외 발생: {str(e)}{NC}")
        if log_file:
            log_file.write(f"예외 발생: {str(e)}\n")
        return 1

def find_yaml_file(technique_id):
    """주어진 테크닉 ID에 해당하는 YAML 파일 찾기"""
    # 직접 경로 시도
    direct_path = f"atomics/{technique_id}/{technique_id}.yaml"
    if os.path.exists(direct_path):
        return direct_path
    
    # 서브 ID가 있는 경우 기본 테크닉 시도
    if '.' in technique_id:
        base_id = technique_id.split('.')[0]
        base_path = f"atomics/{base_id}/{base_id}.yaml"
        if os.path.exists(base_path):
            return base_path
    
    # atomics 폴더 내에서 테크닉 ID에 해당하는 폴더 검색
    for root, dirs, files in os.walk("atomics"):
        for dir_name in dirs:
            if dir_name == technique_id:
                yaml_path = os.path.join(root, dir_name, f"{dir_name}.yaml")
                if os.path.exists(yaml_path):
                    return yaml_path
    
    return None

def check_linux_compatible_tests():
    """모든 YAML 파일을 스캔하여 Linux 호환 테스트 목록 생성"""
    compatible_tests = {}
    
    print(f"{CYAN}[*] Linux 호환 테스트 스캔 중...{NC}")
    
    for technique_id in linux_techniques.keys():
        yaml_path = find_yaml_file(technique_id)
        
        if not yaml_path:
            print(f"{YELLOW}[!] YAML 파일을 찾을 수 없음: {technique_id}{NC}")
            continue
        
        try:
            with open(yaml_path, 'r') as file:
                data = yaml.safe_load(file)
            
            # 테스트 확인
            linux_tests = []
            for i, test in enumerate(data.get('atomic_tests', []), 1):
                platforms = test.get('supported_platforms', [])
                if any(platform in ['linux', 'macos', 'ubuntu', 'centos', 'rhel', 'debian'] for platform in platforms):
                    linux_tests.append(str(i))
            
            if linux_tests:
                test_name = data.get('display_name', technique_id)
                compatible_tests[technique_id] = f"{test_name};{','.join(linux_tests)}"
                print(f"{GREEN}[+] 발견: {technique_id} - {test_name} (테스트: {', '.join(linux_tests)}){NC}")
        except Exception as e:
            print(f"{RED}[X] {technique_id} 스캔 중 오류: {str(e)}{NC}")
    
    return compatible_tests

def run_atomic_test(technique_id, technique_info):
    """특정 테크닉의 테스트 실행"""
    # 테크닉 이름과 테스트 번호 분리
    parts = technique_info.split(';')
    technique_name = parts[0]
    test_numbers_str = parts[1] if len(parts) > 1 else "1"
    
    # 랜섬웨어 테스트 확인
    is_ransomware = False
    for r_technique in ransomware_techniques:
        if technique_id.startswith(r_technique):
            is_ransomware = True
            break
    
    # 랜섬웨어 테스트인 경우 사용자 확인
    if is_ransomware:
        print(f"\n{RED}[!] 경고: {technique_id} - {technique_name}은(는) 랜섬웨어 동작을 시뮬레이션하는 테스트입니다.{NC}")
        print(f"{RED}[!] 이 테스트는 파일을 암호화하거나 시스템 복구 기능을 비활성화할 수 있습니다.{NC}")
        print(f"{RED}[!] 중요한 데이터가 없는 격리된 테스트 환경에서만 실행하십시오.{NC}")
        
        confirmation = input(f"{YELLOW}이 랜섬웨어 테스트를 계속 진행하시겠습니까? (Y/N): {NC}")
        if confirmation.lower() != 'y':
            print(f"{YELLOW}[!] 랜섬웨어 테스트 {technique_id}을(를) 건너뜁니다.{NC}")
            
            with open(RESULTS_FILE, "a") as log_file:
                log_file.write("\n------------------------------------------------------\n")
                log_file.write(f"테스트 건너뜀: {technique_id} - {technique_name} (랜섬웨어 테스트)\n")
                log_file.write("------------------------------------------------------\n")
                log_file.write("사용자에 의해 건너뜀: 랜섬웨어 시뮬레이션 테스트\n")
            
            return
    
    print(f"\n{GREEN}[+] 테스트 실행: {technique_id} - {technique_name}{NC}")
    
    with open(RESULTS_FILE, "a") as log_file:
        log_file.write("\n------------------------------------------------------\n")
        log_file.write(f"테스트 실행: {technique_id} - {technique_name}\n")
        log_file.write("------------------------------------------------------\n")
        
        # YAML 파일 경로
        yaml_path = find_yaml_file(technique_id)
        
        if not yaml_path:
            print(f"{RED}[X] YAML 파일을 찾을 수 없습니다: {technique_id}{NC}")
            log_file.write(f"YAML 파일을 찾을 수 없습니다: {technique_id}\n")
            return
        
        print(f"{CYAN}[*] YAML 파일 경로: {yaml_path}{NC}")
        log_file.write(f"YAML 파일 경로: {yaml_path}\n")
        
        # YAML 파일 로드
        try:
            with open(yaml_path, 'r') as file:
                data = yaml.safe_load(file)
        except Exception as e:
            print(f"{RED}[X] YAML 파일 로드 실패: {str(e)}{NC}")
            log_file.write(f"YAML 파일 로드 실패: {str(e)}\n")
            return
        
        # T1222.002 테스트를 위한 파일 및 폴더 준비
        if technique_id == "T1222.002":
            prepare_t1222_files(test_numbers_str, log_file)
        
        # 테스트 번호 파싱
        test_numbers = [int(num) for num in test_numbers_str.split(',')]
        
        # T1552.001 테스트를 위한 파일 준비 (AWS, Azure, GCP 자격 증명 파일)
        if technique_id == "T1552.001":
            prepare_credentials_files(test_numbers, log_file)
        
        # 각 테스트 실행
        atomic_tests = data.get('atomic_tests', [])
        
        for i, test in enumerate(atomic_tests, 1):
            if i in test_numbers:
                test_name = test.get('name', 'Unnamed test')
                print(f"\n{CYAN}[*] 테스트 {i} 실행 중: {test_name}{NC}")
                log_file.write(f"\n테스트 {i} 실행: {test_name}\n")
                
                # 지원되는 플랫폼 확인
                supported_platforms = test.get('supported_platforms', [])
                if not any(platform in ['linux', 'macos', 'ubuntu', 'centos', 'rhel', 'debian'] for platform in supported_platforms):
                    print(f"{YELLOW}[!] 이 테스트는 Linux를 지원하지 않습니다. 지원 플랫폼: {supported_platforms}{NC}")
                    log_file.write(f"지원하지 않는 플랫폼: {supported_platforms}\n")
                    continue
                
                # 의존성 확인
                dependencies = test.get('dependencies', [])
                if dependencies:
                    print(f"{CYAN}[*] 의존성 확인 중...{NC}")
                    log_file.write("의존성 확인 중...\n")
                    
                    for dep in dependencies:
                        if 'prereq_command' in dep:
                            prereq_result = run_command(dep['prereq_command'], log_file)
                            
                            if prereq_result != 0 and 'get_prereq_command' in dep:
                                dep_desc = dep.get('description', '')
                                print(f"{YELLOW}[!] 의존성 설치 중: {dep_desc}{NC}")
                                log_file.write(f"의존성 설치 중: {dep_desc}\n")
                                
                                run_command(dep['get_prereq_command'], log_file)
                
                # 테스트 입력 파라미터 처리
                input_args = {}
                if 'input_arguments' in test:
                    for arg_name, arg_info in test['input_arguments'].items():
                        if 'default' in arg_info:
                            var_name = f"#{{{arg_name}}}"
                            input_args[var_name] = str(arg_info['default'])
                
                # T1222.002의 경우 테스트 번호에 따라 특수 변수 추가
                if technique_id == "T1222.002":
                    t1222_vars = get_t1222_specific_vars(i)
                    input_args.update(t1222_vars)
                
                # 명령어 실행
                if 'executor' in test and 'command' in test['executor']:
                    print(f"{CYAN}[*] 명령어 실행 중...{NC}")
                    log_file.write("명령어 실행 중...\n")
                    
                        # T1529 테스트를 위한 특별 처리
                    if technique_id == "T1529":
                            original_command = test['executor']['command']
        	
       	 		# 원래 명령어 기록
                            print(f"{YELLOW}[!] 원래 실행될 명령어: {original_command}{NC}")
                            log_file.write(f"원래 실행될 명령어: {original_command}\n")
        
        		   # 모의 명령어로 대체
                            if "shutdown" in original_command or "reboot" in original_command or "halt" in original_command or "poweroff" in original_command:
            			# 시스템 실제 종료/재시작 명령 대신 메시지만 출력
                                  mock_command = f'echo "[모의 실행] 다음 명령을 실행하려고 했습니다: {original_command}"'
                                  print(f"{GREEN}[*] 시스템 종료/재시작 명령을 모의 실행으로 대체했습니다.{NC}")
                                  log_file.write("시스템 종료/재시작 명령을 모의 실행으로 대체했습니다.\n")
            
                                  exit_code = run_command(mock_command, log_file, input_args)
                            else:
            				# 다른 명령은 정상 실행
                                  exit_code = run_command(original_command, log_file, input_args)
            
                    # T1552.001 테스트를 위한 특별 처리
                    elif technique_id == "T1552.001":
                        if i == 1:  # AWS credentials
                            # 직접 AWS 자격 증명 파일 검색 명령 실행
                            command_text = f"find {HOME_DIR}/.aws -name \"credentials\" -type f 2>/dev/null"
                            exit_code = run_command(command_text, log_file)
                        
                        elif i == 3:  # Extract passwords with grep
                            # 테스트 파일 생성 및 grep 실행
                            run_command("echo 'password=test123' > /tmp/atomic_test.txt", log_file)
                            command_text = "grep -ri password /tmp/atomic_test.txt"
                            exit_code = run_command(command_text, log_file)
                        
                        elif i == 6:  # Github 자격 증명
                            # Github 자격 증명 검색
                            command_text = test['executor']['command'].replace("#{file_path}", "/home")
                            exit_code = run_command(command_text, log_file)
                        
                        elif i == 15:  # Azure credentials
                            # 직접 Azure 자격 증명 파일 검색 명령 실행
                            command_text = f"find {HOME_DIR}/.azure -name \"msal_token_cache.json\" -o -name \"accessTokens.json\" -type f 2>/dev/null"
                            exit_code = run_command(command_text, log_file)
                        
                        elif i == 16:  # GCP credentials
                            # 직접 GCP 자격 증명 파일 검색 명령 실행
                            command_text = f"find {HOME_DIR}/.config/gcloud -name \"credentials.db\" -o -name \"access_tokens.db\" -type f 2>/dev/null"
                            exit_code = run_command(command_text, log_file)
                        
                        else:
                            # 다른 자격 증명 테스트는 기본 실행
                            exit_code = run_command(test['executor']['command'], log_file, input_args)
                        
                        if exit_code == 0:
                            print(f"{GREEN}[✓] 테스트 {i} 성공{NC}")
                            log_file.write("테스트 결과: 성공\n")
                        else:
                            print(f"{YELLOW}[!] 테스트 {i} 실패 또는 일부 성공{NC}")
                            log_file.write("테스트 결과: 실패 또는 일부 성공\n")
                        
                        continue
                    
                    # 다른 테크닉의 기본 실행 방식
                    exit_code = run_command(test['executor']['command'], log_file, input_args)
                    
                    if exit_code == 0:
                        print(f"{GREEN}[✓] 테스트 {i} 성공{NC}")
                        log_file.write("테스트 결과: 성공\n")
                    else:
                        print(f"{YELLOW}[!] 테스트 {i} 실패 또는 일부 성공{NC}")
                        log_file.write("테스트 결과: 실패 또는 일부 성공\n")
                
                # 정리 작업
                if 'executor' in test and 'cleanup_command' in test['executor']:
                    print(f"{CYAN}[*] 정리 작업 실행 중...{NC}")
                    log_file.write("정리 작업 실행 중...\n")
                    
                    run_command(test['executor']['cleanup_command'], log_file)
                
                # 테스트 간 대기
                time.sleep(2)

def prepare_credentials_files(test_numbers, log_file):
    """T1552.001 자격 증명 테스트를 위한 파일 및 폴더 준비"""
    print(f"{CYAN}[*] T1552.001 테스트를 위한 자격 증명 파일 준비 중...{NC}")
    log_file.write("T1552.001 테스트를 위한 자격 증명 파일 준비 중...\n")
    
    # /tmp/atomic_test.txt 파일 생성 (테스트 3용)
    if 3 in test_numbers:
        print(f"{CYAN}[*] 패스워드 추출 테스트를 위한 파일 준비...{NC}")
        run_command("echo 'password=test123' > /tmp/atomic_test.txt", log_file)
    
    # AWS 자격 증명 파일 생성 (테스트 1용)
    if 1 in test_numbers:
        print(f"{CYAN}[*] AWS 자격 증명 테스트를 위한 파일 준비...{NC}")
        aws_dir = f"{HOME_DIR}/.aws"
        run_command(f"mkdir -p {aws_dir}", log_file)
        run_command(f"echo '[default]' > {aws_dir}/credentials", log_file)
        run_command(f"echo 'aws_access_key_id=AKIAIOSFODNN7EXAMPLE' >> {aws_dir}/credentials", log_file)
        run_command(f"echo 'aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' >> {aws_dir}/credentials", log_file)
    
    # Azure 자격 증명 파일 생성 (테스트 15용)
    if 15 in test_numbers:
        print(f"{CYAN}[*] Azure 자격 증명 테스트를 위한 파일 준비...{NC}")
        azure_dir = f"{HOME_DIR}/.azure"
        run_command(f"mkdir -p {azure_dir}", log_file)
        run_command(f"echo '{{ \"accessToken\": \"eyJ0eXA...\" }}' > {azure_dir}/accessTokens.json", log_file)
        run_command(f"echo '{{ \"accessToken\": \"test_token\" }}' > {azure_dir}/msal_token_cache.json", log_file)
    
    # GCP 자격 증명 파일 생성 (테스트 16용)
    if 16 in test_numbers:
        print(f"{CYAN}[*] GCP 자격 증명 테스트를 위한 파일 준비...{NC}")
        gcp_dir = f"{HOME_DIR}/.config/gcloud"
        run_command(f"mkdir -p {gcp_dir}", log_file)
        run_command(f"touch {gcp_dir}/credentials.db", log_file)
        run_command(f"touch {gcp_dir}/access_tokens.db", log_file)
    
    print(f"{GREEN}[✓] T1552.001 테스트 파일 및 폴더 준비 완료{NC}")
    log_file.write("T1552.001 테스트 파일 및 폴더 준비 완료\n")

def get_t1552_specific_vars(test_number):
    """테스트 번호에 맞는 T1552.001 관련 변수 반환"""
    if test_number == 1:  # AWS credentials
        return {
            "#{file_path}": f"{HOME_DIR}/.aws",
        }
    elif test_number == 3:  # Extract passwords with grep
        return {
            "#{file_path}": "/tmp/atomic_test.txt",
        }
    elif test_number == 6:  # GitHub credentials
        return {
            "#{file_path}": "/home",
        }
    elif test_number == 15:  # Azure credentials
        return {
            "#{file_path}": f"{HOME_DIR}/.azure",
        }
    elif test_number == 16:  # GCP credentials
        return {
            "#{file_path}": f"{HOME_DIR}/.config/gcloud",
        }
    return {}

def prepare_t1222_files(test_numbers_str, log_file):
    """T1222.002 테스트를 위한 파일 및 폴더 준비"""
    print(f"{CYAN}[*] T1222.002 테스트를 위한 파일 및 폴더 준비 중...{NC}")
    log_file.write("T1222.002 테스트를 위한 파일 및 폴더 준비 중...\n")
    
    test_numbers = [int(num) for num in test_numbers_str.split(',')]
    
    # T1222.002 테스트 파일 및 폴더 생성
    base_folder = "/tmp/AtomicRedTeam/atomics/T1222.002"
    
    # 기본 폴더 구조 생성
    run_command(f"mkdir -p {base_folder}", log_file)
    run_command(f"mkdir -p {base_folder}/src", log_file)
    
    # 기본 테스트 파일 생성
    run_command(f"touch {base_folder}/T1222.002.yaml", log_file)
    run_command(f"echo 'T1222.002 Test File' > {base_folder}/T1222.002.yaml", log_file)
    
    # 테스트 3: chmod - Change file or folder mode (numeric mode) recursively
    if 3 in test_numbers:
        print(f"{CYAN}[*] 테스트 #3을 위한 파일 준비...{NC}")
        run_command(f"mkdir -p {base_folder}/test3", log_file)
        run_command(f"touch {base_folder}/test3/file.txt", log_file)
    
    # 테스트 6: chown - Change file or folder ownership and group recursively
    if 6 in test_numbers:
        print(f"{CYAN}[*] 테스트 #6을 위한 파일 준비...{NC}")
        run_command(f"mkdir -p {base_folder}/test6", log_file)
        run_command(f"touch {base_folder}/test6/file.txt", log_file)
    
    # 테스트 9: chattr - Remove immutable file attribute
    if 9 in test_numbers:
        print(f"{CYAN}[*] 테스트 #9을 위한 파일 준비...{NC}")
        run_command(f"mkdir -p /var/spool/cron", log_file)
        run_command(f"touch /var/spool/cron/root", log_file)
        run_command(f"chattr +i /var/spool/cron/root 2>/dev/null || true", log_file)
    
    # 테스트 11: Chmod through c script
    if 11 in test_numbers:
        print(f"{CYAN}[*] 테스트 #11을 위한 C 소스 파일 준비...{NC}")
        c_source = '''
#include <stdio.h>
#include <sys/stat.h>

int main(int argc, char *argv[]) {
    if(argc != 3) {
        printf("Usage: %s <directory> <file_name>\\n", argv[0]);
        return 1;
    }
    
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", argv[1], argv[2]);
    
    // Create the file if it doesn't exist
    FILE *fp = fopen(path, "w");
    if(fp) {
        fprintf(fp, "T1222.002 Test\\n");
        fclose(fp);
    }
    
    // Change permissions to read, write, execute for all
    chmod(path, 0777);
    printf("Changed permissions for %s\\n", path);
    
    return 0;
}
'''
        with open(f"{base_folder}/src/T1222.002.c", "w") as f:
            f.write(c_source)
    
    # 테스트 13: Chown through c script
    if 13 in test_numbers:
        print(f"{CYAN}[*] 테스트 #13을 위한 C 소스 파일 준비...{NC}")
        c_source = '''
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if(argc != 2) {
        printf("Usage: %s <file_path>\\n", argv[0]);
        return 1;
    }
    
    // Change ownership to root
    if(chown(argv[1], 0, 0) == 0) {
        printf("Changed ownership of %s to root\\n", argv[1]);
    } else {
        perror("chown failed");
        return 1;
    }
    
    return 0;
}
'''
        with open(f"{base_folder}/src/chown.c", "w") as f:
            f.write(c_source)
    
    print(f"{GREEN}[✓] T1222.002 테스트 파일 및 폴더 준비 완료{NC}")
    log_file.write("T1222.002 테스트 파일 및 폴더 준비 완료\n")

def get_t1222_specific_vars(test_number):
    """테스트 번호에 맞는 T1222.002 관련 변수 반환"""
    if test_number == 11:  # Chmod through c script
        return {
            "#{source_file}": "/tmp/AtomicRedTeam/atomics/T1222.002/src/T1222.002.c",
            "#{compiled_file}": "/tmp/T1222002"
        }
    elif test_number == 13:  # Chown through c script
        return {
            "#{source_file}": "/tmp/AtomicRedTeam/atomics/T1222.002/src/chown.c",
            "#{compiled_file}": "/tmp/T1222002own"
        }
    return {}

def create_summary_report():
    """결과 파일에서 요약 보고서 생성"""
    summary_file = f"{RESULTS_DIR}/Linux_Test_Summary_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    print(f"{CYAN}[*] 요약 보고서 생성 중...{NC}")
    
    try:
        with open(RESULTS_FILE, 'r') as result_file, open(summary_file, 'w') as summary:
            summary.write(f"Linux Atomic Red Team 테스트 요약 - {datetime.datetime.now()}\n\n")
            summary.write("테크닉 ID - 이름                                 | 결과\n")
            summary.write("--------------------------------------------------------\n")
            
            content = result_file.read()
            lines = content.split('\n')
            
            technique_results = {}
            current_technique = ""
            
            for line in lines:
                # 정규식과 같은 역할: "테스트 실행: T1234(T1234.001) - 테크닉 이름" 패턴 인식
                if "테스트 실행: T" in line and " - " in line:
                    parts = line.split("테스트 실행: ")[1].split(" - ")
                    if len(parts) >= 2:
                        technique_id = parts[0]
                        technique_name = parts[1]
                        current_technique = f"{technique_id} - {technique_name}"
                        technique_results[current_technique] = "알 수 없음"
                elif "테스트 건너뜀: T" in line and " - " in line:
                    parts = line.split("테스트 건너뜀: ")[1].split(" - ")
                    if len(parts) >= 2:
                        technique_id = parts[0]
                        technique_name = parts[1].split(" (")[0]  # (랜섬웨어 테스트) 부분 제거
                        current_technique = f"{technique_id} - {technique_name}"
                        technique_results[current_technique] = "건너뜀"
                elif "테스트 결과: " in line and current_technique:
                    result = line.split("테스트 결과: ")[1]
                    technique_results[current_technique] = result
                elif "사용자에 의해 건너뜀" in line and current_technique:
                    technique_results[current_technique] = "건너뜀 (사용자)"
                elif "YAML 파일을 찾을 수 없습니다" in line and current_technique:
                    technique_results[current_technique] = "실패 (YAML 없음)"
            
            # 요약 작성
            for technique, result in sorted(technique_results.items()):
                padded_technique = technique.ljust(50)
                summary.write(f"{padded_technique}| {result}\n")
            
            # 통계 작성
            total_tests = len(technique_results)
            successful_tests = list(technique_results.values()).count("성공")
            failed_tests = list(technique_results.values()).count("실패 또는 일부 성공") + list(technique_results.values()).count("실패 (YAML 없음)")
            skipped_tests = list(technique_results.values()).count("건너뜀") + list(technique_results.values()).count("건너뜀 (사용자)")
            unknown_tests = total_tests - successful_tests - failed_tests - skipped_tests
            
            success_rate = 0
            if total_tests - skipped_tests > 0:
                success_rate = (successful_tests / (total_tests - skipped_tests)) * 100
            
            summary.write("\n--------------------------------------------------------\n")
            summary.write(f"총 테스트:      {total_tests}\n")
            summary.write(f"성공한 테스트:  {successful_tests}\n")
            summary.write(f"실패한 테스트:  {failed_tests}\n")
            summary.write(f"건너뛴 테스트:  {skipped_tests}\n")
            summary.write(f"결과 불명:      {unknown_tests}\n")
            summary.write(f"성공률:         {success_rate:.2f}%\n")
        
        print(f"{GREEN}[✓] 요약 보고서 생성 완료: {summary_file}{NC}")
        return summary_file
    
    except Exception as e:
        print(f"{RED}[X] 요약 보고서 생성 중 오류: {str(e)}{NC}")
        return None

def separate_ransomware_tests():
    """일반 테스트와 랜섬웨어 테스트 분리"""
    normal_techniques = {}
    ransomware_techniques_dict = {}
    
    for tech_id, tech_info in linux_techniques.items():
        is_ransomware = False
        for r_technique in ransomware_techniques:
            if tech_id.startswith(r_technique):
                is_ransomware = True
                ransomware_techniques_dict[tech_id] = tech_info
                break
        
        if not is_ransomware:
            normal_techniques[tech_id] = tech_info
    
    return normal_techniques, ransomware_techniques_dict

def main():
    """메인 함수"""
    parser = argparse.ArgumentParser(description='Atomic Red Team Linux 테스트 실행')
    parser.add_argument('--scan-only', action='store_true', help='Linux 호환 테스트만 스캔')
    parser.add_argument('--technique', help='특정 테크닉만 실행 (예: T1059.004)')
    parser.add_argument('--skip-ransomware', action='store_true', help='랜섬웨어 테스트 건너뛰기')
    args = parser.parse_args()
    
    print(f"{CYAN}=================================================={NC}")
    print(f"{CYAN}Linux Atomic Red Team 테스트 시작{NC}")
    print(f"{CYAN}결과 파일: {RESULTS_FILE}{NC}")
    print(f"{CYAN}=================================================={NC}")
    
    # 결과 파일 헤더
    with open(RESULTS_FILE, "w") as f:
        f.write(f"Linux Atomic Red Team 테스트 결과 - {datetime.datetime.now()}\n")
    
    # Linux 호환 테스트 스캔
    if args.scan_only:
        compatible_tests = check_linux_compatible_tests()
        print(f"\n{GREEN}[+] Linux 호환 테스트 스캔 완료. {len(compatible_tests)}개 테크닉 발견{NC}")
        
        with open(os.path.join(RESULTS_DIR, "linux_compatible_tests.txt"), "w") as f:
            for technique_id, technique_info in compatible_tests.items():
                f.write(f"{technique_id}: {technique_info}\n")
        
        print(f"{CYAN}Linux 호환 테스트 목록이 저장되었습니다: {os.path.join(RESULTS_DIR, 'linux_compatible_tests.txt')}{NC}")
        return
    
    # 특정 테크닉만 실행
    if args.technique:
        if args.technique in linux_techniques:
            # 해당 테크닉이 랜섬웨어 관련인지 확인
            is_ransomware = False
            for r_technique in ransomware_techniques:
                if args.technique.startswith(r_technique):
                    is_ransomware = True
                    break
            
            if is_ransomware:
                print(f"{RED}[!] 경고: {args.technique}은(는) 랜섬웨어 동작을 시뮬레이션하는 테스트입니다.{NC}")
            
            confirmation = input(f"테크닉 {args.technique}의 테스트를 시작하시겠습니까? (Y/N): ")
            if confirmation.lower() == 'y':
                run_atomic_test(args.technique, linux_techniques[args.technique])
                summary_file = create_summary_report()
                if summary_file:
                    print(f"{CYAN}요약 보고서: {summary_file}{NC}")
            else:
                print(f"{YELLOW}테스트가 취소되었습니다.{NC}")
        else:
            print(f"{RED}[X] 테크닉 {args.technique}을(를) 찾을 수 없습니다.{NC}")
        return
    
    # 일반 테스트와 랜섬웨어 테스트 분리
    normal_techniques, ransomware_techniques_dict = separate_ransomware_tests()
    
    # 사용자 확인 (일반 테스트)
    confirmation = input("Linux 테스트를 시작하시겠습니까? (Y/N): ")
    if confirmation.lower() != 'y':
        print(f"{YELLOW}테스트가 취소되었습니다.{NC}")
        return
    
    # 추가 옵션 제공
    print(f"\n{CYAN}옵션:{NC}")
    print(f"1: 모든 테스트 실행")
    print(f"2: 일반 테스트만 실행 (랜섬웨어 테스트 제외)")
    print(f"3: 단일 테스트 선택 실행")
    
    option = input("옵션을 선택하세요 (1/2/3): ")
    
    if option == "3":
        # 테크닉 목록 출력
        print(f"\n{CYAN}사용 가능한 테크닉:{NC}")
        all_techniques = list(linux_techniques.items())
        for i, (tech_id, tech_info) in enumerate(all_techniques, 1):
            name = tech_info.split(';')[0]
            
            # 랜섬웨어 테스트 표시
            is_ransomware = False
            for r_tech in ransomware_techniques:
                if tech_id.startswith(r_tech):
                    is_ransomware = True
                    break
            
            if is_ransomware:
                print(f"{i}. {tech_id} - {name} {RED}[랜섬웨어]{NC}")
            else:
                print(f"{i}. {tech_id} - {name}")
        
        # 테크닉 선택
        try:
            choice = int(input("\n실행할 테크닉 번호를 입력하세요: "))
            if 1 <= choice <= len(all_techniques):
                selected_id, selected_info = all_techniques[choice-1]
                run_atomic_test(selected_id, selected_info)
            else:
                print(f"{RED}[X] 잘못된 선택입니다.{NC}")
        except ValueError:
            print(f"{RED}[X] 숫자를 입력하세요.{NC}")
    
    elif option == "2" or args.skip_ransomware:
        # 일반 테스트만 실행
        print(f"\n{CYAN}일반 테스트만 실행합니다 (랜섬웨어 테스트 제외)...{NC}")
        for technique_id, technique_info in normal_techniques.items():
            run_atomic_test(technique_id, technique_info)
        
        # 랜섬웨어 테스트 건너뛰기 메시지
        print(f"\n{YELLOW}[!] 다음 랜섬웨어 테스트들을 건너뛰었습니다:{NC}")
        for technique_id, technique_info in ransomware_techniques_dict.items():
            name = technique_info.split(';')[0]
            print(f"{YELLOW}   - {technique_id}: {name}{NC}")
            
            # 결과 파일에 건너뛴 테스트 기록
            with open(RESULTS_FILE, "a") as log_file:
                log_file.write("\n------------------------------------------------------\n")
                log_file.write(f"테스트 건너뜀: {technique_id} - {name} (랜섬웨어 테스트)\n")
                log_file.write("------------------------------------------------------\n")
                log_file.write("사용자 옵션에 의해 건너뜀: 랜섬웨어 시뮬레이션 테스트\n")
    
    else:  # option == "1"
        # 일반 테스트 실행
        print(f"\n{CYAN}일반 테스트 실행 중...{NC}")
        for technique_id, technique_info in normal_techniques.items():
            run_atomic_test(technique_id, technique_info)
        
        # 랜섬웨어 테스트 확인
        if ransomware_techniques_dict:
            print(f"\n{RED}=================================================={NC}")
            print(f"{RED}경고: 랜섬웨어 시뮬레이션 테스트{NC}")
            print(f"{RED}=================================================={NC}")
            print(f"{YELLOW}다음 테스트들은 랜섬웨어 동작을 시뮬레이션합니다:{NC}")
            
            for technique_id, technique_info in ransomware_techniques_dict.items():
                name = technique_info.split(';')[0]
                print(f"{YELLOW}   - {technique_id}: {name}{NC}")
            
            print(f"\n{RED}이러한 테스트는 파일을 암호화하거나 시스템 복구 기능을 비활성화할 수 있습니다.{NC}")
            print(f"{RED}중요한 데이터가 없는 격리된 테스트 환경에서만 실행하십시오.{NC}")
            print(f"{GREEN}일반 테스트는 이미 완료되었으며 결과가 저장되었습니다.{NC}")
            
            ransomware_confirm = input(f"\n{YELLOW}랜섬웨어 시뮬레이션 테스트를 계속 진행하시겠습니까? (Y/N): {NC}")
            
            if ransomware_confirm.lower() == 'y':
                print(f"\n{RED}랜섬웨어 시뮬레이션 테스트 실행 중...{NC}")
                
                for technique_id, technique_info in ransomware_techniques_dict.items():
                    # 각 랜섬웨어 테스트마다 추가 확인
                    name = technique_info.split(';')[0]
                    individual_confirm = input(f"{RED}테스트 {technique_id}: {name}을(를) 실행하시겠습니까? (Y/N): {NC}")
                    
                    if individual_confirm.lower() == 'y':
                        run_atomic_test(technique_id, technique_info)
                    else:
                        print(f"{YELLOW}[!] 테스트 {technique_id}: {name}을(를) 건너뜁니다.{NC}")
                        
                        # 결과 파일에 건너뛴 테스트 기록
                        with open(RESULTS_FILE, "a") as log_file:
                            log_file.write("\n------------------------------------------------------\n")
                            log_file.write(f"테스트 건너뜀: {technique_id} - {name} (랜섬웨어 테스트)\n")
                            log_file.write("------------------------------------------------------\n")
                            log_file.write("사용자에 의해 건너뜀: 랜섬웨어 시뮬레이션 테스트\n")
            else:
                print(f"{YELLOW}랜섬웨어 시뮬레이션 테스트를 건너뜁니다.{NC}")
                
                # 결과 파일에 건너뛴 테스트들 기록
                for technique_id, technique_info in ransomware_techniques_dict.items():
                    name = technique_info.split(';')[0]
                    with open(RESULTS_FILE, "a") as log_file:
                        log_file.write("\n------------------------------------------------------\n")
                        log_file.write(f"테스트 건너뜀: {technique_id} - {name} (랜섬웨어 테스트)\n")
                        log_file.write("------------------------------------------------------\n")
                        log_file.write("사용자에 의해 건너뜀: 랜섬웨어 시뮬레이션 테스트\n")
    
    # 요약 보고서 생성
    summary_file = create_summary_report()
    if summary_file:
        print(f"{CYAN}요약 보고서: {summary_file}{NC}")
    
    # 완료 메시지
    print(f"\n{CYAN}=================================================={NC}")
    print(f"{CYAN}Linux Atomic Red Team 테스트 완료{NC}")
    print(f"{CYAN}결과 파일: {RESULTS_FILE}{NC}")
    print(f"{CYAN}=================================================={NC}")

if __name__ == "__main__":
    main()