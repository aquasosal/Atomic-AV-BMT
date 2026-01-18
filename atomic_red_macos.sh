#!/bin/bash
# macOS용 자동화 테스트 스크립트
# 실행 전: chmod +x macos_atomic_tests.sh
# 실행: sudo ./macos_atomic_tests.sh

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 결과 저장 디렉토리
RESULTS_DIR="/tmp/AtomicTestResults"
RESULTS_FILE="$RESULTS_DIR/MacOS_Test_Results_$(date +%Y%m%d_%H%M%S).txt"

# 디렉토리 생성
mkdir -p $RESULTS_DIR

echo -e "${CYAN}==================================================${NC}"
echo -e "${CYAN}macOS Atomic Red Team 테스트 시작${NC}"
echo -e "${CYAN}결과 파일: $RESULTS_FILE${NC}"
echo -e "${CYAN}==================================================${NC}"

# 결과 파일 헤더
echo "macOS Atomic Red Team 테스트 결과 - $(date)" > $RESULTS_FILE

# Atomic Red Team 저장소가 있는지 확인하고 없으면 클론
if [ ! -d "atomic-red-team" ]; then
    echo -e "${YELLOW}Atomic Red Team 저장소 클론 중...${NC}"
    git clone https://github.com/redcanaryco/atomic-red-team.git
    if [ $? -ne 0 ]; then
        echo -e "${RED}Atomic Red Team 저장소 클론 실패${NC}"
        exit 1
    fi
fi

cd atomic-red-team/atomics

# 테스트할 macOS 테크닉 목록
declare -A macos_techniques=(
    ["T1059.002"]="AppleScript;1,2"
    ["T1059.004"]="Bash Commands;1,2"
    ["T1053.003"]="Cron;1,2"
    ["T1136.001"]="Local Account Creation;1"
    ["T1027"]="Obfuscated Files;1"
    ["T1070.004"]="File Deletion;1"
    ["T1497.003"]="Time Based Evasion;1"
    ["T1036.005"]="Match Legitimate Name;1"
    ["T1555.003"]="Credentials from Web Browsers;1"
    ["T1552.001"]="Credentials in Files;1"
    ["T1082"]="System Information Discovery;1"
    ["T1016"]="Network Configuration Discovery;1"
    ["T1033"]="System Owner/User Discovery;1"
    ["T1057"]="Process Discovery;1"
    ["T1113"]="Screen Capture;1"
for technique_id in "${!macos_techniques[@]}"; do
    run_atomic_test "$technique_id" "${macos_techniques[$technique_id]}"
done

# 완료 메시지
echo -e "\n${CYAN}==================================================${NC}"
echo -e "${CYAN}macOS Atomic Red Team 테스트 완료${NC}"
echo -e "${CYAN}결과 파일: $RESULTS_FILE${NC}"
echo -e "${CYAN}==================================================${NC}"