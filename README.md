# Atomic AV BMT (Antivirus Benchmark Test)

MITRE ATT&CK 기법을 활용한 안티바이러스 솔루션 탐지 능력 평가 자동화 스크립트 모음입니다.

## 개요

이 프로젝트는 Atomic Red Team 프레임워크를 기반으로 안티바이러스 제품의 탐지 성능을 체계적으로 평가하기 위한 자동화 도구입니다. Windows, Linux, macOS 환경에서 각각 MITRE ATT&CK 기법을 실행하여 보안 제품의 탐지율을 측정합니다.

### Atomic Red Team이란?

Atomic Red Team은 MITRE ATT&CK 프레임워크의 각 공격 기법을 시뮬레이션할 수 있는 테스트 케이스 라이브러리입니다. 보안 팀이 방어 체계를 검증하고 개선하기 위해 사용합니다.

## 스크립트 목록

### Windows 스크립트

#### 1. atomic_red_windows.ps1
**Windows 환경 자동화 테스트 스크립트 (메인)**

100개 이상의 MITRE ATT&CK 기법을 자동으로 실행합니다.

**주요 기능:**
- Atomic Red Team PowerShell 모듈 자동 설치
- 100+ MITRE ATT&CK 기법 테스트
- 상세한 로그 및 요약 보고서 생성
- 실시간 진행 상황 표시

**테스트 항목 예시:**
- T1059.001: PowerShell 실행
- T1059.003: Windows 명령 프롬프트
- T1003.001: LSASS 메모리 덤프
- T1055: 프로세스 인젝션
- T1547.001: 레지스트리 Run Keys
- 기타 100+ 기법

**사용법:**
```powershell
# 관리자 권한 PowerShell 실행
Set-ExecutionPolicy Bypass -Scope Process -Force
.\atomic_red_windows.ps1
```

**결과 파일:**
- `C:\AtomicTestResults\Windows_Test_Results_[timestamp].txt`
- `C:\AtomicTestResults\Windows_Command_Logs_[timestamp].txt`
- `C:\AtomicTestResults\Windows_Test_Summary_[timestamp].txt`

#### 2. redatom_test.ps1
**Windows 테스트 스크립트 (간소화 버전)**

기본적인 MITRE ATT&CK 기법 테스트에 사용됩니다.

#### 3. old_script.ps1
**레거시 Windows 테스트 스크립트**

이전 버전의 테스트 스크립트입니다.

### Linux 스크립트

#### 1. atomic_red_linux_filnal.py (권장)
**Linux 환경 자동화 테스트 스크립트 (최종 버전)**

Python 기반 자동화 스크립트로 70개 이상의 Linux 관련 MITRE ATT&CK 기법을 테스트합니다.

**주요 기능:**
- YAML 기반 Atomic Red Team 테스트 자동 실행
- 변수 자동 치환 및 사전 요구사항 설치
- 랜섬웨어 관련 기법 안전 스킵 기능
- 컬러 터미널 출력 및 상세 로그

**테스트 항목 예시:**
- T1059.004: Linux Bash 명령
- T1053.003: Cron 작업
- T1136.001: 로컬 계정 생성
- T1222.002: Linux 파일 권한 변경
- T1003.008: OS 자격 증명 덤프
- T1486: 데이터 암호화 (스킵 가능)

**사용법:**
```bash
# 실행 권한 부여
chmod +x atomic_red_linux_filnal.py

# 전체 테스트 실행 (랜섬웨어 제외)
sudo python3 atomic_red_linux_filnal.py

# 랜섬웨어 포함 실행
sudo python3 atomic_red_linux_filnal.py --include-ransomware

# 특정 기법만 테스트
sudo python3 atomic_red_linux_filnal.py --techniques T1059.004,T1053.003
```

**결과 파일:**
- `~/AtomicTestResults/Linux_Test_Results_[timestamp].txt`

#### 2. atomic_red_linux.py
**Linux 테스트 스크립트 (이전 버전)**

초기 버전의 Linux 테스트 스크립트입니다.

### macOS 스크립트

#### 1. atomic_red_macos1.ps1
**macOS 환경 PowerShell 테스트 스크립트**

PowerShell Core를 사용하여 macOS에서 Atomic Red Team 테스트를 실행합니다.

**주요 기능:**
- 60개 이상의 macOS 관련 MITRE ATT&CK 기법
- Atomic Red Team PowerShell 모듈 자동 설치
- 상세한 실행 로그 및 요약 생성

**테스트 항목 예시:**
- T1059.002: AppleScript 실행
- T1059.004: Bash 명령
- T1555.003: 웹 브라우저 자격 증명 탈취
- T1113: 화면 캡처
- T1547.011: Plist 수정

**사용법:**
```bash
# PowerShell Core 설치 필요
brew install --cask powershell

# 실행
sudo pwsh -File atomic_red_macos1.ps1
```

#### 2. atomic_red_macos.sh
**macOS Bash 스크립트 (간소화 버전)**

Bash 기반의 간단한 macOS 테스트 스크립트입니다.

**사용법:**
```bash
chmod +x atomic_red_macos.sh
sudo ./atomic_red_macos.sh
```

#### 3. atomic_red_macos.ps1
**macOS PowerShell 스크립트 (기본 버전)**

이전 버전의 macOS PowerShell 테스트 스크립트입니다.

## 설치 및 사전 요구사항

### Windows

```powershell
# PowerShell 실행 정책 설정
Set-ExecutionPolicy Bypass -Scope Process -Force

# 스크립트가 자동으로 Atomic Red Team을 설치합니다
```

### Linux

```bash
# Python 3 및 필수 패키지
sudo apt-get update
sudo apt-get install python3 python3-yaml git

# Atomic Red Team 저장소 (스크립트가 자동 클론)
```

### macOS

```bash
# PowerShell Core 설치
brew install --cask powershell

# Git 설치
brew install git

# Python 3 (Bash 스크립트용)
brew install python3
```

## 사용 시나리오

### 1. 신규 안티바이러스 제품 평가

```bash
# 테스트 환경 준비
1. 격리된 테스트 VM 준비
2. 평가 대상 AV 제품 설치
3. 스크립트 실행
4. 결과 파일에서 탐지율 분석
```

### 2. 보안 제품 업데이트 후 성능 비교

```bash
# 업데이트 전
- 스크립트 실행 → 결과 저장

# AV 제품 업데이트

# 업데이트 후
- 스크립트 재실행 → 결과 비교
```

### 3. EDR/XDR 솔루션 탐지 능력 검증

```bash
# EDR/XDR 설치 후
- 스크립트 실행
- SIEM/콘솔에서 탐지 이벤트 확인
- 미탐지 기법 식별 및 룰 개선
```

## 결과 해석

### 출력 예시

```
=================================================================
테스트 진행 중: T1059.001 - PowerShell (Test #1)
-----------------------------------------------------------------
테스트 명령어: powershell.exe -Command "Write-Host 'Test'"
결과: 성공 ✓
탐지 여부: [AV 제품에서 확인]
=================================================================
```

### 요약 보고서

각 스크립트는 다음 정보를 포함한 요약을 생성합니다:
- 총 테스트 수
- 성공한 테스트 수
- 실패한 테스트 수
- 스킵된 테스트 수 (랜섬웨어 등)
- 실행 시간

## 안전 수칙

1. **격리된 환경에서만 실행**: 프로덕션 시스템에서 절대 실행하지 마세요
2. **VM/샌드박스 사용**: 전용 테스트 VM 또는 샌드박스 환경 권장
3. **백업**: 테스트 전 시스템 스냅샷 생성
4. **네트워크 격리**: 외부 네트워크 연결 차단 권장
5. **관리자 권한**: 대부분의 테스트는 관리자 권한 필요
6. **랜섬웨어 주의**: 데이터 암호화/삭제 기법은 신중히 실행

## 윤리적 사용 가이드

이 도구는 **인가된 보안 테스트 목적으로만** 사용해야 합니다:

- ✅ 자사 보안 제품 성능 평가
- ✅ SOC/보안팀 탐지 능력 검증
- ✅ EDR/XDR 솔루션 벤치마킹
- ✅ 보안 교육 및 훈련
- ❌ 무단 공격 또는 악의적 목적
- ❌ 프로덕션 시스템 테스트
- ❌ 허가되지 않은 네트워크 침투

## MITRE ATT&CK 매핑

이 프로젝트는 다음 MITRE ATT&CK 전술(Tactics)을 포함합니다:

- **Initial Access**: T1566 (피싱)
- **Execution**: T1059 (명령 및 스크립트 인터프리터)
- **Persistence**: T1053, T1547 (스케줄링, 자동 시작)
- **Privilege Escalation**: T1055 (프로세스 인젝션)
- **Defense Evasion**: T1027, T1070 (난독화, 흔적 제거)
- **Credential Access**: T1003, T1552, T1555 (자격 증명 덤프)
- **Discovery**: T1082, T1016, T1057 (시스템 정보 수집)
- **Lateral Movement**: T1021 (원격 서비스)
- **Collection**: T1113, T1560 (화면 캡처, 데이터 압축)
- **Exfiltration**: T1041, T1048 (데이터 유출)
- **Impact**: T1486, T1485 (랜섬웨어, 데이터 파괴)

## 참고 파일

### T1059.001
특정 MITRE ATT&CK 기법에 대한 추가 문서 또는 페이로드 파일입니다.

## 문제 해결

### Windows

**문제**: "실행 정책 오류"
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```

**문제**: "Atomic Red Team 모듈을 찾을 수 없음"
```powershell
# 수동 설치
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -Force
```

### Linux

**문제**: "권한 거부"
```bash
sudo python3 atomic_red_linux_filnal.py
```

**문제**: "YAML 모듈 없음"
```bash
pip3 install pyyaml
```

### macOS

**문제**: "pwsh 명령을 찾을 수 없음"
```bash
brew install --cask powershell
```

## 라이선스

이 프로젝트는 보안 테스트 및 교육 목적으로 제공됩니다.

## 기여

버그 리포트 및 개선 제안은 이슈로 등록해주세요.

## 참고 자료

- [Atomic Red Team GitHub](https://github.com/redcanaryco/atomic-red-team)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam)

---

**면책조항**: 이 도구는 인가된 보안 테스트 목적으로만 사용되어야 합니다. 무단 사용으로 인한 법적 책임은 사용자에게 있습니다.
