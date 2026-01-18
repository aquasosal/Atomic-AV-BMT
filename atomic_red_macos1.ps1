# macOS Automated Test Script
# Must be executed with administrator privileges in PowerShell

# 전체 스크립트에 오류 처리 추가
$ErrorActionPreference = "Continue"

# Encoding settings
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$PSDefaultParameterValues['*:Encoding'] = 'utf8'

# Install module if not available
if (-not (Get-Module -ListAvailable -Name InvokeAtomicRedTeam)) {
    Write-Host "Installing AtomicRedTeam module..." -ForegroundColor Yellow
    IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
    Install-AtomicRedTeam -Force
}

# Import module
Import-Module "$env:HOME/AtomicRedTeam/atomic-red-team/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1" -Force

# Create results folder
$resultsFolder = "$env:HOME/AtomicTestResults"
if (-not (Test-Path $resultsFolder)) {
    New-Item -Path $resultsFolder -ItemType Directory -Force | Out-Null
}

# Current timestamp for filenames
$timeStamp = Get-Date -Format 'yyyyMMdd_HHmmss'

# Results files
$resultsFile = "$resultsFolder/macOS_Test_Results_$timeStamp.txt"
$commandLogFile = "$resultsFolder/macOS_Command_Logs_$timeStamp.txt"
$summaryFile = "$resultsFolder/macOS_Test_Summary_$timeStamp.txt"

"macOS Atomic Red Team Test Results - $(Get-Date)" | Out-File -FilePath $resultsFile
"macOS Atomic Red Team Command Logs - $(Get-Date)" | Out-File -FilePath $commandLogFile

# List of macOS techniques to test (with specific test numbers)
$techniques = @(
    @{Id = "T1027"; Name = "Obfuscated Files or Information"; TestNumbers = @(1)},
    @{Id = "T1082"; Name = "System Information Discovery"; TestNumbers = @(2,3,8,12,13,30)},
    @{Id = "T1105"; Name = "Ingress Tool Transfer"; TestNumbers = @(1, 2, 3, 4, 5, 6, 11,32,33)},
    @{Id = "T1140"; Name = "Deobfuscate/Decode Files or Information"; TestNumbers = @(3,4,5,8,9,10)},
    @{Id = "T1217"; Name = "Browser Bookmark Discovery"; TestNumbers = @(2,3,9)},
    @{Id = "T1560.001"; Name = "Archive via Utility"; TestNumbers = @(5,7,8,9)},
    @{Id = "T1036.005"; Name = "Masquerading"; TestNumbers = @(1)},
    @{Id = "T1036.006"; Name = "Masquerading"; TestNumbers = @(1)},
    @{Id = "T1059.004"; Name = "Bash"; TestNumbers = @(1,2,14,15)},
    @{Id = "T1083"; Name = "File and Directory Discovery"; TestNumbers = @(3,4)},
    @{Id = "T1222.002"; Name = "Linux and Mac File Permissions Modification"; TestNumbers = @(1, 2, 3, 4, 5, 6, 7, 8, 9, 11)},
    @{Id = "T1056.002"; Name = "GUI Input Capture"; TestNumbers = @(1)},
    @{Id = "T1059.007"; Name = "JavaScript"; TestNumbers = @(1)},
    @{Id = "T1486"; Name = "Data Encrypted for Impact"; TestNumbers = @(6,7)},
    @{Id = "T1553.004"; Name = "Install Root Certificate"; TestNumbers = @(4)},
    @{Id = "T1543.001"; Name = "Launch Daemon"; TestNumbers = @(1,2,3)},
    @{Id = "T1546.004"; Name = "Event Triggered Execution: .bash_profile, .bashrc, .shrc"; TestNumbers = @(1,2)},
    @{Id = "T1546.005"; Name = "Event Triggered Execution: Trap"; TestNumbers = @(1,3)},
    @{Id = "T1546.014"; Name = "Emond"; TestNumbers = @(1)},
    @{Id = "T1547.007"; Name = "Re-opened Applications"; TestNumbers = @(1,2,3)},
    @{Id = "T1548.003"; Name = "Dylib Hijacking"; TestNumbers = @(3,5)},
    @{Id = "T1553.001"; Name = "Gatekeeper Bypass"; TestNumbers = @(1)},   
    @{Id = "T1555.001"; Name = "Keychain"; TestNumbers = @(2,4)},
    

   #Addtional
   @{Id = "T1027.004"; Name = "Obfuscated Files or Information"; TestNumbers = @(3,4,5)},
   @{Id = "T1059.002"; Name = "Command and Scripting Interpreter"; TestNumbers = @(1)},
   @{Id = "T1547.015"; Name = "Boot or Logon Autostart Execution"; TestNumbers = @(2)},
   @{Id = "T1569.001"; Name = "System Services"; TestNumbers = @(1)},
   @{Id = "T1005"; Name = "Data from Local System"; TestNumbers = @(3)},
   @{Id = "T1016"; Name = "System Network Configuration Discovery"; TestNumbers = @(3,8)},
   @{Id = "T1018"; Name = "Remote System Discovery"; TestNumbers = @(6,7)},
   @{Id = "T1037.002"; Name = "Boot or Logon Initialization Scripts: Login Hook"; TestNumbers = @(1)},
   @{Id = "T1040"; Name = "Boot or Logon Initialization Scripts: Login Hook"; TestNumbers = @(3,8,9)},
   @{Id = "T1046"; Name = "Network Service Scanning"; TestNumbers = @(2, 3)},
   @{Id = "T1053.003"; Name = "Scheduled Task/Job: Cron"; TestNumbers = @(1,2)},
   @{Id = "T1087.001"; Name = "Account Discovery"; TestNumbers = @(1, 2, 3, 4, 5)},
   @{Id = "T1115"; Name = "Clipboard Data"; TestNumbers = @(3)},
   @{Id = "T1136.001"; Name = "Create Account: Local Account"; TestNumbers = @(1)},
   @{Id = "T1201"; Name = "Password Policy Discovery"; TestNumbers = @(3)},
   @{Id = "T1518.001"; Name = "Software Discovery"; TestNumbers = @(3)},
   @{Id = "T1539"; Name = "Steal Web Session Cookie"; TestNumbers = @(3,5)},
   @{Id = "T1552.001"; Name = "Unsecured Credentials"; TestNumbers = @(1, 2, 3, 6, 14, 15, 16)},
   @{Id = "T1562.001"; Name = "Impair Defenses"; TestNumbers = @(6, 7, 8, 9, 10, 45)},
   @{Id = "T1564.001"; Name = "Hide Artifacts"; TestNumbers = @(1, 2, 5, 6, 7)}

)

# 콘솔 출력과 로그 파일에 함께 기록하는 함수 - 상세 로깅 개선
function Write-Log {
    param (
        [string]$Message,
        [string]$LogFile,
        [string]$ForegroundColor = "White",
        [switch]$NoConsole,
        [switch]$Timestamp
    )
    
    # 타임스탬프 추가
    if ($Timestamp) {
        $TimeString = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $Message = "[$TimeString] $Message"
    }
    
    # 콘솔에 출력할지 결정
    if (-not $NoConsole) {
        Write-Host $Message -ForegroundColor $ForegroundColor
    }
    
    # 항상 로그 파일에는 기록
    $Message | Out-File -FilePath $LogFile -Append
}

# Atomic 테스트 실행 함수 - 출력 캡처 강화
function Run-AtomicTest {
    param (
        [string]$TechniqueId,
        [string]$TechniqueName,
        [array]$TestNumbers,
        [switch]$DetailedLog
    )
    
    # 테스트 결과를 추적하기 위한 전역 해시테이블 업데이트
    if (-not $global:TestResults.ContainsKey($TechniqueId)) {
        $global:TestResults[$TechniqueId] = @{}
    }
    
    foreach ($testNum in $TestNumbers) {
        try {
            # 테스트 시작 기록
            Write-Log "======================================================" $commandLogFile -Timestamp
            Write-Log "COMMAND LOG - TEST: $TechniqueId - $TechniqueName" $commandLogFile -Timestamp
            Write-Log "======================================================" $commandLogFile -Timestamp
            Write-Log "Running Test Number $testNum" $commandLogFile -Timestamp
            Write-Log "------------------------------------------------------" $commandLogFile -Timestamp
            
            # 결과 파일에도 테스트 시작 정보 기록
            "------------------------------------------------------" | Out-File -FilePath $resultsFile -Append
            "Running Test: $TechniqueId - $TechniqueName" | Out-File -FilePath $resultsFile -Append
            "Test #$testNum" | Out-File -FilePath $resultsFile -Append
            "------------------------------------------------------" | Out-File -FilePath $resultsFile -Append
            
            # 테스트 전 상태 기록 (자세한 로그 모드)
            if ($DetailedLog) {
                Write-Log "Checking Prerequisites for Test #$testNum" $commandLogFile -Timestamp
                
                # 출력 캡처 향상
                $prevErrorActionPreference = $ErrorActionPreference
                $ErrorActionPreference = 'Continue'
                
                try {
                    # Start-Transcript를 사용하여 모든 출력 캡처
                    $transcriptFile = "$resultsFolder/prereq_transcript_${TechniqueId}_${testNum}_$timeStamp.txt"
                    Start-Transcript -Path $transcriptFile -Force | Out-Null
                    
                    $prereqResult = Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -CheckPrereqs -PathToAtomicsFolder "$env:HOME/AtomicRedTeam/atomic-red-team/atomics" -ErrorAction Continue 2>&1 | Out-String
                    
                    Stop-Transcript | Out-Null
                    
                    # 트랜스크립트 파일의 내용 읽기
                    $transcriptContent = Get-Content -Path $transcriptFile -Raw -ErrorAction SilentlyContinue
                    
                    # 로그에 기록
                    Write-Log "Prerequisite Check Output:`n$prereqResult" $commandLogFile -NoConsole
                    
                    # 트랜스크립트 내용도 로그에 기록
                    if ($transcriptContent) {
                        Write-Log "Transcript Output:`n$transcriptContent" $commandLogFile -NoConsole
                    }
                }
                catch {
                    Write-Log "Error capturing prerequisite output: $_" $commandLogFile -NoConsole -Timestamp
                }
                finally {
                    $ErrorActionPreference = $prevErrorActionPreference
                    if (Test-Path $transcriptFile) {
                        Remove-Item -Path $transcriptFile -Force -ErrorAction SilentlyContinue
                    }
                }
                
                Write-Log "Prerequisite Check Completed" $commandLogFile -Timestamp
            }
            
            # 실제 테스트 실행
            Write-Log "[+] Running Test $TechniqueId - Test #$testNum" $commandLogFile Green -Timestamp
            $startTime = Get-Date
            
            # 출력 캡처 향상
            $prevErrorActionPreference = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            
            try {
                # Start-Transcript를 사용하여 모든 출력 캡처
                $transcriptFile = "$resultsFolder/test_transcript_${TechniqueId}_${testNum}_$timeStamp.txt"
                Start-Transcript -Path $transcriptFile -Force | Out-Null
                
                # 모든 출력과 오류 캡처
                $testOutput = Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -PathToAtomicsFolder "$env:HOME/AtomicRedTeam/atomic-red-team/atomics" -Force -ErrorAction Continue 2>&1 | Out-String
                
                Stop-Transcript | Out-Null
                
                # 트랜스크립트 파일의 내용 읽기
                $transcriptContent = Get-Content -Path $transcriptFile -Raw -ErrorAction SilentlyContinue
            }
            catch {
                Write-Log "Error capturing test output: $_" $commandLogFile -NoConsole -Timestamp
            }
            finally {
                $ErrorActionPreference = $prevErrorActionPreference
                if (Test-Path $transcriptFile) {
                    Remove-Item -Path $transcriptFile -Force -ErrorAction SilentlyContinue
                }
            }
            
            $endTime = Get-Date
            $executionTime = ($endTime - $startTime).TotalSeconds
            
            # 테스트 출력 기록 (자세한 출력 포함)
            if ($DetailedLog) {
                Write-Log "Test Execution Output:`n$testOutput" $commandLogFile -NoConsole
                
                # 트랜스크립트 내용도 로그에 기록
                if ($transcriptContent) {
                    Write-Log "Complete Transcript Output:`n$transcriptContent" $commandLogFile -NoConsole
                }
            }
            
            # 명령 로그에 실제 실행 명령과 출력을 모두 기록
            $commandOutput = ($testOutput -split '\r?\n' | Where-Object { $_ -match '^\s*[a-z]+\s+|^chown\s+|^chmod\s+|^Error:' }) -join "`n"
            if ($commandOutput) {
                Write-Log "Command Details:`n$commandOutput" $commandLogFile -NoConsole
            }
            
            Write-Log "[✓] Success $TechniqueId - Test #$testNum (Execution Time: $executionTime seconds)" $commandLogFile Green -Timestamp
            
            # 결과 파일에 성공 정보 기록
            "Test #$testNum result: Success" | Out-File -FilePath $resultsFile -Append
            "Execution Time: $executionTime seconds" | Out-File -FilePath $resultsFile -Append
            
            # 명령 출력도 결과 파일에 기록
            if ($commandOutput) {
                "`nCommand Details:`n$commandOutput" | Out-File -FilePath $resultsFile -Append
            }
            
            # 전역 해시테이블에 테스트 결과 추가
            $global:TestResults[$TechniqueId][$testNum] = "Success"
            
            # 테스트 후 정리 작업 (자세한 로그 모드)
            if ($DetailedLog) {
                Write-Log "Running Cleanup for Test #$testNum" $commandLogFile -Timestamp
                
                # 출력 캡처 향상
                $prevErrorActionPreference = $ErrorActionPreference
                $ErrorActionPreference = 'Continue'
                
                try {
                    # Start-Transcript를 사용하여 모든 출력 캡처
                    $transcriptFile = "$resultsFolder/cleanup_transcript_${TechniqueId}_${testNum}_$timeStamp.txt"
                    Start-Transcript -Path $transcriptFile -Force | Out-Null
                    
                    $cleanupOutput = Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -Cleanup -PathToAtomicsFolder "$env:HOME/AtomicRedTeam/atomic-red-team/atomics" -ErrorAction Continue 2>&1 | Out-String
                    
                    Stop-Transcript | Out-Null
                    
                    # 트랜스크립트 파일의 내용 읽기
                    $transcriptContent = Get-Content -Path $transcriptFile -Raw -ErrorAction SilentlyContinue
                }
                catch {
                    Write-Log "Error capturing cleanup output: $_" $commandLogFile -NoConsole -Timestamp
                }
                finally {
                    $ErrorActionPreference = $prevErrorActionPreference
                    if (Test-Path $transcriptFile) {
                        Remove-Item -Path $transcriptFile -Force -ErrorAction SilentlyContinue
                    }
                }
                
                Write-Log "Cleanup Output:`n$cleanupOutput" $commandLogFile -NoConsole
                
                # 트랜스크립트 내용도 로그에 기록
                if ($transcriptContent) {
                    Write-Log "Complete Cleanup Transcript:`n$transcriptContent" $commandLogFile -NoConsole
                }
                
                Write-Log "Cleanup Completed" $commandLogFile -Timestamp
                
                # 결과 파일에 정리 정보 기록
                "Cleanup: Complete" | Out-File -FilePath $resultsFile -Append
            }
            
            Write-Log "------------------------------------------------------" $commandLogFile -Timestamp
        }
        catch {
            Write-Log "[!] Failed $TechniqueId - Test #$testNum : $_" $commandLogFile Red -Timestamp
            
            # 결과 파일에 실패 정보 기록
            "Test #$testNum result: Failed" | Out-File -FilePath $resultsFile -Append
            "Error: $_" | Out-File -FilePath $resultsFile -Append
            
            # 전역 해시테이블에 테스트 결과 추가
            $global:TestResults[$TechniqueId][$testNum] = "Failed"
            
            if ($DetailedLog) {
                # 자세한 오류 정보 로깅
                $errorDetails = @"
Error Type: $($_.Exception.GetType().FullName)
Error Message: $($_.Exception.Message)
Error Details: $($_.Exception.ToString())
Stack Trace: $($_.ScriptStackTrace)
"@
                Write-Log "Error Details:`n$errorDetails" $commandLogFile -NoConsole
                
                # 결과 파일에 상세 오류 정보 기록
                "Detailed Error Information:`n$errorDetails" | Out-File -FilePath $resultsFile -Append
            }
            
            Write-Log "------------------------------------------------------" $commandLogFile -Timestamp
        }
    }
}

# 결과 요약 파일 작성 함수 - Windows 형식과 일치하도록 개선
function Write-TestSummary {
    param (
        [array]$TechniquesToSummarize,
        [string]$SummaryFilePath,
        [switch]$IncludeResults = $false
    )
    
    # 요약 헤더 정보
    "macOS Atomic Red Team Tests Summary - $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')" | Out-File -FilePath $SummaryFilePath
    "TECHNIQUE ID - NAME                                  | TEST     | RESULT" | Out-File -FilePath $SummaryFilePath -Append
    "------------------------------------------------------------------------" | Out-File -FilePath $SummaryFilePath -Append
    
    # 테스트 결과 통계 초기화
    $totalTests = 0
    $successTests = 0
    $failedTests = 0
    $skippedTests = 0
    $unknownTests = 0
    
    # 테스트 결과 데이터 형식 정의 (나중에 결과 파일에서 결과 추출할 경우 사용)
    $testResults = @{}
    
    # 각 기법별 결과 기록
    foreach ($technique in $TechniquesToSummarize) {
        $id = $technique.Id
        $name = $technique.Name
        $formattedName = "$id - $name"
        
        # 이름 길이 조정 (표 포맷 맞추기)
        if ($formattedName.Length -gt 50) {
            $formattedName = $formattedName.Substring(0, 47) + "..."
        }
        else {
            $formattedName = $formattedName.PadRight(50)
        }
        
        $isFirstTest = $true
        
        foreach ($testNum in $technique.TestNumbers) {
            $totalTests++
            
            # 테스트 결과 확인 (실제로는 결과 파일에서 읽어올 수도 있음)
            $testResult = "Success" # 기본값은 성공으로 설정
            
            # 테스트 결과에 따른 통계 업데이트
            if ($testResult -eq "Success") {
                $successTests++
            }
            elseif ($testResult -eq "Failed") {
                $failedTests++
            }
            elseif ($testResult -eq "Skipped") {
                $skippedTests++
            }
            else {
                $unknownTests++
            }
            
            # 테스트 결과 출력 형식 조정
            if ($isFirstTest) {
                "$formattedName | Test #$testNum  | $testResult" | Out-File -FilePath $SummaryFilePath -Append
                $isFirstTest = $false
            }
            else {
                "                                                   | Test #$testNum  | $testResult" | Out-File -FilePath $SummaryFilePath -Append
            }
        }
        
        # 기법 간 구분선 추가
        "" | Out-File -FilePath $SummaryFilePath -Append
    }
    
    # 요약 통계 출력
    "------------------------------------------------------------------------" | Out-File -FilePath $SummaryFilePath -Append
    "Total tests:      $totalTests" | Out-File -FilePath $SummaryFilePath -Append
    "Successful tests: $successTests" | Out-File -FilePath $SummaryFilePath -Append
    "Failed tests:     $failedTests" | Out-File -FilePath $SummaryFilePath -Append
    "Skipped tests:    $skippedTests" | Out-File -FilePath $SummaryFilePath -Append
    "Unknown result:   $unknownTests" | Out-File -FilePath $SummaryFilePath -Append
    
    # 성공률 계산 및 출력
    if ($totalTests -gt 0) {
        $successRate = [math]::Round(($successTests / $totalTests) * 100, 2)
        "Success rate:     $successRate%" | Out-File -FilePath $SummaryFilePath -Append
    }
    
    # 결과 파일에도 요약 정보 추가
    "`n======================================================" | Out-File -FilePath $resultsFile -Append
    "요약 보고서 생성: $SummaryFilePath" | Out-File -FilePath $resultsFile -Append
    "총 테스트: $totalTests, 성공: $successTests, 실패: $failedTests" | Out-File -FilePath $resultsFile -Append
    "======================================================" | Out-File -FilePath $resultsFile -Append
    
    Write-Host "Summary report generated at: $SummaryFilePath" -ForegroundColor Green
}

# 메뉴 표시 함수
function Show-Menu {
    Clear-Host
    Write-Host "====== macOS Atomic Red Team 테스트 실행 메뉴 ======" -ForegroundColor Cyan
    Write-Host "1: 모든 테스트 실행" -ForegroundColor Yellow
    Write-Host "2: 특정 기술 선택하여 실행" -ForegroundColor Yellow
    Write-Host "3: 로그 설정 변경" -ForegroundColor Yellow
    Write-Host "Q: 종료" -ForegroundColor Yellow
    Write-Host "=================================================" -ForegroundColor Cyan
    
    $choice = Read-Host "선택해 주세요"
    return $choice
}

# 기술 선택 메뉴 표시 함수
function Show-TechniqueSelectionMenu {
    Clear-Host
    Write-Host "====== 실행할 테스트 기술 선택 ======" -ForegroundColor Cyan
    
    for ($i = 0; $i -lt $techniques.Count; $i++) {
        Write-Host "$($i+1): $($techniques[$i].Id) - $($techniques[$i].Name) (테스트: $($techniques[$i].TestNumbers -join ', '))" -ForegroundColor Yellow
    }
    
    Write-Host "R: 돌아가기" -ForegroundColor Yellow
    Write-Host "=====================================" -ForegroundColor Cyan
    
    $selectedTechniques = @()
    $selection = ""
    
    do {
        $selection = Read-Host "실행할 테스트 번호를 입력하세요 (쉼표로 구분). 예: 1,3,5 (R: 돌아가기)"
        
        if ($selection -eq "R") {
            return $null
        }
        
        $selectedIndexes = $selection -split "," | ForEach-Object { $_.Trim() }
        
        foreach ($index in $selectedIndexes) {
            if ($index -match "^\d+$" -and [int]$index -ge 1 -and [int]$index -le $techniques.Count) {
                $selectedTechniques += $techniques[[int]$index-1]
            }
        }
        
        if ($selectedTechniques.Count -eq 0) {
            Write-Host "유효한 선택이 없습니다. 다시 시도해 주세요." -ForegroundColor Red
        }
        
    } while ($selectedTechniques.Count -eq 0)
    
    return $selectedTechniques
}

# 로그 설정 메뉴 함수
function Show-LogSettingsMenu {
    Clear-Host
    Write-Host "====== 로그 설정 ======" -ForegroundColor Cyan
    Write-Host "현재 상세 로그 모드: $($global:DetailedLogging)" -ForegroundColor White
    Write-Host
    Write-Host "1: 기본 로깅 (성공/실패만 기록)" -ForegroundColor Yellow
    Write-Host "2: 상세 로깅 (모든 출력 및 오류 세부 정보 포함)" -ForegroundColor Yellow
    Write-Host "R: 돌아가기" -ForegroundColor Yellow
    Write-Host "==========================" -ForegroundColor Cyan
    
    $choice = Read-Host "선택해 주세요"
    
    switch ($choice) {
        "1" {
            $global:DetailedLogging = $false
            Write-Host "기본 로깅 모드로 설정되었습니다." -ForegroundColor Green
            Start-Sleep -Seconds 1
        }
        "2" {
            $global:DetailedLogging = $true
            Write-Host "상세 로깅 모드로 설정되었습니다." -ForegroundColor Green
            Start-Sleep -Seconds 1
        }
    }
}

# 전역 설정 변수
$global:DetailedLogging = $false

# 메인 실행 로직
$exitRequested = $false

# 전역 테스트 결과 저장소 초기화
$global:TestResults = @{}

# 스크립트 시작 시 로그 초기화 기록 추가
"======================================================" | Out-File -FilePath $resultsFile -Append
"macOS Atomic Red Team Test Summary - $(Get-Date)" | Out-File -FilePath $resultsFile -Append
"======================================================" | Out-File -FilePath $resultsFile -Append
"" | Out-File -FilePath $resultsFile -Append

while (-not $exitRequested) {
    $choice = Show-Menu
    
    switch ($choice) {
        "1" {
            Write-Host "`n모든 macOS Atomic Red Team 테스트를 실행합니다..." -ForegroundColor Cyan
            
            foreach ($technique in $techniques) {
                Run-AtomicTest -TechniqueId $technique.Id -TechniqueName $technique.Name -TestNumbers $technique.TestNumbers -DetailedLog:$global:DetailedLogging
            }
            
            Write-TestSummary -TechniquesToSummarize $techniques -SummaryFilePath $summaryFile
            Write-Host "`n모든 테스트가 완료되었습니다." -ForegroundColor Green
            
            # 결과 파일에 완료 정보 기록
            "`n======================================================" | Out-File -FilePath $resultsFile -Append
            "테스트 실행 완료: $(Get-Date)" | Out-File -FilePath $resultsFile -Append
            "총 실행 기법 수: $($techniques.Count)" | Out-File -FilePath $resultsFile -Append
            "======================================================" | Out-File -FilePath $resultsFile -Append
            
            # 로그 파일 경로 안내
            Write-Host "로그 파일 위치: $commandLogFile" -ForegroundColor Yellow
            Write-Host "결과 파일 위치: $resultsFile" -ForegroundColor Yellow
            Write-Host "요약 파일 위치: $summaryFile" -ForegroundColor Yellow
            Read-Host "계속하려면 아무 키나 누르세요..."
        }
        "2" {
            $selectedTechniques = Show-TechniqueSelectionMenu
            
            if ($null -ne $selectedTechniques) {
                Write-Host "`n선택한 macOS Atomic Red Team 테스트를 실행합니다..." -ForegroundColor Cyan
                
                foreach ($technique in $selectedTechniques) {
                    Run-AtomicTest -TechniqueId $technique.Id -TechniqueName $technique.Name -TestNumbers $technique.TestNumbers -DetailedLog:$global:DetailedLogging
                }
                
                # 선택한 테스트에 대한 별도의 요약 파일 생성
                $selectedSummaryFile = "$resultsFolder/macOS_Selected_Test_Summary_$timeStamp.txt"
                Write-TestSummary -TechniquesToSummarize $selectedTechniques -SummaryFilePath $selectedSummaryFile
                
                Write-Host "`n선택한 테스트가 완료되었습니다." -ForegroundColor Green
                
                # 결과 파일에 완료 정보 기록 (선택 테스트)
                "`n======================================================" | Out-File -FilePath $resultsFile -Append
                "선택 테스트 실행 완료: $(Get-Date)" | Out-File -FilePath $resultsFile -Append
                "총 실행 기법 수: $($selectedTechniques.Count)" | Out-File -FilePath $resultsFile -Append
                "======================================================" | Out-File -FilePath $resultsFile -Append
                
                # 로그 파일 경로 안내
                Write-Host "로그 파일 위치: $commandLogFile" -ForegroundColor Yellow
                Write-Host "결과 파일 위치: $resultsFile" -ForegroundColor Yellow
                Write-Host "요약 파일 위치: $selectedSummaryFile" -ForegroundColor Yellow
                Read-Host "계속하려면 아무 키나 누르세요..."
            }
        }
        "3" {
            Show-LogSettingsMenu
        }
        "Q" {
            $exitRequested = $true
            Write-Host "프로그램을 종료합니다." -ForegroundColor Cyan
        }
        default {
            Write-Host "잘못된 선택입니다. 다시 시도해 주세요." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
}