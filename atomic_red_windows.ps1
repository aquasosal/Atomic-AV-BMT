# Windows Automated Test Script
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
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force

# Create results folder
$resultsFolder = "C:\AtomicTestResults"
if (-not (Test-Path $resultsFolder)) {
    New-Item -Path $resultsFolder -ItemType Directory -Force | Out-Null
}

# Current timestamp for filenames
$timeStamp = Get-Date -Format 'yyyyMMdd_HHmmss'

# Results files
$resultsFile = "$resultsFolder\Windows_Test_Results_$timeStamp.txt"
$commandLogFile = "$resultsFolder\Windows_Command_Logs_$timeStamp.txt"
$summaryFile = "$resultsFolder\Windows_Test_Summary_$timeStamp.txt"

"Windows Atomic Red Team Test Results - $(Get-Date)" | Out-File -FilePath $resultsFile
"Windows Atomic Red Team Command Logs - $(Get-Date)" | Out-File -FilePath $commandLogFile

# List of Windows techniques to test (with specific test numbers)
$windowsTechniques = @(
    # Original techniques
    @{Id = "T1059.001"; Name = "PowerShell"; TestNumbers = @(1, 3, 5)},
    @{Id = "T1059.003"; Name = "Windows Command Shell"; TestNumbers = @(3,5,6)},
    @{Id = "T1059.005"; Name = "Visual Basic"; TestNumbers = @(2,3)},
    @{Id = "T1053.005"; Name = "Scheduled Task"; TestNumbers = @(8,9,11)},
    @{Id = "T1547.001"; Name = "Registry Run Keys"; TestNumbers = @(9,14,16,17,18)},
    @{Id = "T1543.003"; Name = "Windows Service"; TestNumbers = @(1,4,6)},
    @{Id = "T1136.001"; Name = "Local Account"; TestNumbers = @(5,8,9)},
    @{Id = "T1055.001"; Name = "Process Injection"; TestNumbers = @(2)},
    @{Id = "T1027"; Name = "Obfuscated Files"; TestNumbers = @(2,3,7,9)},
    @{Id = "T1218.005"; Name = "Mshta"; TestNumbers = @(1, 2,3,4,5,6,7,8,9,10)},
    @{Id = "T1218.011"; Name = "Rundll32"; TestNumbers = @(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16)},
    @{Id = "T1140"; Name = "Deobfuscate/Decode Files"; TestNumbers = @(1,2)},
    @{Id = "T1070.004"; Name = "File Deletion"; TestNumbers = @(4, 5, 6, 7, 9, 10, 11)},
    @{Id = "T1036.005"; Name = "Match Legitimate Name"; TestNumbers = @(2)},
    @{Id = "T1003.001"; Name = "LSASS Memory"; TestNumbers = @(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14)},
    @{Id = "T1082"; Name = "System Information Discovery"; TestNumbers = @(1, 7, 9, 10, 11)},
    @{Id = "T1016"; Name = "Network Configuration Discovery"; TestNumbers = @(1, 2, 4, 5, 6, 7, 9)},
    @{Id = "T1033"; Name = "System Owner/User Discovery"; TestNumbers = @(5)},
    @{Id = "T1057"; Name = "Process Discovery"; TestNumbers = @(3)},
    @{Id = "T1021.001"; Name = "Remote Desktop Protocol"; TestNumbers = @(2,4)},
    @{Id = "T1021.002"; Name = "SMB/Windows Admin Shares"; TestNumbers = @(3,4)},
    @{Id = "T1113"; Name = "Screen Capture"; TestNumbers = @(7,8)},
    @{Id = "T1560.001"; Name = "Archive Collected Data"; TestNumbers = @(1,2,4)},
    @{Id = "T1105"; Name = "Ingress Tool Transfer"; TestNumbers = @(7,10)},
    @{Id = "T1071.001"; Name = "Web Protocols"; TestNumbers = @(1,2)},
    @{Id = "T1048.003"; Name = "Exfiltration Over Unencrypted Protocol"; TestNumbers = @(4)},
    
    # Additional techniques from the list
    @{Id = "T1001.002"; Name = "Data Obfuscation"; TestNumbers = @(1,2)},
    @{Id = "T1003.003"; Name = "NTDS"; TestNumbers = @(4)},
    @{Id = "T1036.004"; Name = "Masquerade Task or Service"; TestNumbers = @(1,2)},
    @{Id = "T1041"; Name = "Exfiltration Over C2 Channel"; TestNumbers = @(1,2)},
    @{Id = "T1047"; Name = "Windows Management Instrumentation"; TestNumbers = @(1, 2,3,4,5,6,7)},
    @{Id = "T1055.002"; Name = "Portable Executable Injection"; TestNumbers = @(1)},

    @{Id = "T1055.011"; Name = "Extra Window Memory Injection"; TestNumbers = @(1)},
    @{Id = "T1055.012"; Name = "Process Hollowing"; TestNumbers = @(1,2,3,4)},
    @{Id = "T1070.006"; Name = "Timestomp"; TestNumbers = @(5,6,7,8,10)},
    @{Id = "T1112"; Name = "Modify Registry"; TestNumbers = @(3,4,7,8,9,10,11,12,38,46,47,92,93)},
    @{Id = "T1217"; Name = "Browser Bookmark Discovery"; TestNumbers = @(5,6,10,11)},
    @{Id = "T1218.007"; Name = "Msiexec"; TestNumbers = @(1,2,3,4,5,11)},
    @{Id = "T1218.010"; Name = "Regsvr32"; TestNumbers = @(2,4)},
    @{Id = "T1220"; Name = "XSL Script Processing"; TestNumbers = @(1)},
    @{Id = "T1552.001"; Name = "Credentials In Files"; TestNumbers = @(4,5)},
    @{Id = "T1555.003"; Name = "Credentials from Web Browsers"; TestNumbers = @(10,17)},
    @{Id = "T1562.001"; Name = "Disable or Modify Tools"; TestNumbers = @(15,17,22,31)},
    @{Id = "T1562.004"; Name = "Disable or Modify System Firewall"; TestNumbers = @(2,21)},
    @{Id = "T1566.001"; Name = "Spearphishing Attachment"; TestNumbers = @(2)},
    @{Id = "T1546.001"; Name = "Change Default File Association"; TestNumbers = @(1)},
    @{Id = "T1216.001"; Name = "PubPrn"; TestNumbers = @(1)},
    @{Id = "T1074.001"; Name = "Local Data Staging"; TestNumbers = @(1,3)},
    @{Id = "T1137.006"; Name = "Add-ins"; TestNumbers = @(2,3)},
    @{Id = "T1110.001"; Name = "Password Guessing"; TestNumbers = @(1,2)},

    @{Id = "T1040"; Name = "Network Sniffing"; TestNumbers = @(4,5,6,7,15)},
    @{Id = "T1090.003"; Name = "Multi-hop Proxy"; TestNumbers = @(1,2)},
    @{Id = "T1546.012"; Name = "Printer Drivers"; TestNumbers = @(1,2,3)},
    @{Id = "T1547.014"; Name = "Active Setup"; TestNumbers = @(1,2,3)},
    @{Id = "T1558.003"; Name = "Kerberoasting"; TestNumbers = @(1,2,3,4,5,6,7)},
    @{Id = "T1558.004"; Name = "AS-REP Roasting"; TestNumbers = @(1,2,3)},
    @{Id = "T1559.002"; Name = "Dynamic Data Exchange"; TestNumbers = @(1,2,3)},
    @{Id = "T1562.009"; Name = "Safe Boot Mode"; TestNumbers = @(1)},
    @{Id = "T1563.002"; Name = "RDP Hijacking"; TestNumbers = @(1)},
    @{Id = "T1547.006"; Name = "Boot or Logon Autostart Execution"; TestNumbers = @(4)},
    @{Id = "T1056.002"; Name = "GUI Input Capture"; TestNumbers = @(2)},
    @{Id = "T1059.007"; Name = "JavaScript"; TestNumbers = @(1,2)},
    @{Id = "T1120"; Name = "Peripheral Device Discovery"; TestNumbers = @(1,3,4)},
    @{Id = "T1219"; Name = "Remote Access Software"; TestNumbers = @(1,2,5,6,8,10,12,15)},
    @{Id = "T1486"; Name = "Data Encrypted for Impact"; TestNumbers = @(5,8,9,10)},
    @{Id = "T1490"; Name = "Inhibit System Recovery"; TestNumbers = @(1,2,3,4,5,6,7,8,9,10,11)},
    @{Id = "T1553.004"; Name = "Install Root Certificate"; TestNumbers = @(5,6,7)},
    @{Id = "T1620"; Name = "Reflective Code Loading"; TestNumbers = @(1)}
)

# 콘솔 출력과 로그 파일에 함께 기록하는 함수
function Write-Log {
    param (
        [string]$Message,
        [string]$LogFile,
        [string]$ForegroundColor = "White"
    )
    
    # 콘솔에 출력
    Write-Host $Message -ForegroundColor $ForegroundColor
    
    # 로그 파일에 기록
    $Message | Out-File -FilePath $LogFile -Append
}

# Enhanced test execution function with command logging
function Run-AtomicTest {
    param (
        [string]$TechniqueId,
        [string]$TechniqueName,
        [array]$TestNumbers
    )
    
    # 결과 파일에 테스트 헤더 기록
    "`n------------------------------------------------------" | Out-File -FilePath $resultsFile -Append
    "Running Test: $TechniqueId - $TechniqueName" | Out-File -FilePath $resultsFile -Append
    "------------------------------------------------------" | Out-File -FilePath $resultsFile -Append
    
    Write-Host "`n[+] Running Test: $TechniqueId - $TechniqueName" -ForegroundColor Green
    
    # 명령 로그 파일에 테스트 헤더 기록
    "`n======================================================" | Out-File -FilePath $commandLogFile -Append
    "COMMAND LOG - TEST: $TechniqueId - $TechniqueName" | Out-File -FilePath $commandLogFile -Append
    "======================================================" | Out-File -FilePath $commandLogFile -Append
    
    # First check if the YAML file exists
    $techniqueFolder = "C:\AtomicRedTeam\atomics\$TechniqueId"
    $yamlFile = "$techniqueFolder\$TechniqueId.yaml"
    
    # For techniques without sub-techniques (e.g. T1027), also check the base folder
    if (-not (Test-Path $yamlFile) -and $TechniqueId -match "^T\d+\.\d+$") {
        $baseTechnique = $TechniqueId.Split('.')[0]
        $baseFolder = "C:\AtomicRedTeam\atomics\$baseTechnique"
        $baseYaml = "$baseFolder\$baseTechnique.yaml"
        
        if (Test-Path $baseYaml) {
            # Use the base technique instead
            Write-Host "  [*] Using base technique $baseTechnique instead of $TechniqueId" -ForegroundColor Yellow
            $TechniqueId = $baseTechnique
            $yamlFile = $baseYaml
        }
    }
    
    # Special handling for techniques without sub-techniques directly
    if (-not (Test-Path $yamlFile)) {
        # Try to check if base technique exists
        $basePath = "C:\AtomicRedTeam\atomics"
        $potentialFolders = Get-ChildItem -Path $basePath -Directory -ErrorAction SilentlyContinue |
                            Where-Object { $_.Name -eq $TechniqueId }
        
        if ($potentialFolders) {
            $yamlFile = "$basePath\$TechniqueId\$TechniqueId.yaml"
        }
    }
    
    # 명령 로그 파일에 YAML 파일 경로 기록
    "YAML File Path: $yamlFile" | Out-File -FilePath $commandLogFile -Append
    
    # Skip test if YAML file still doesn't exist
    if (-not (Test-Path $yamlFile)) {
        Write-Host "  [!] YAML file not found for $TechniqueId. Skipping test." -ForegroundColor Yellow
        "YAML file not found for $TechniqueId. Test skipped." | Out-File -FilePath $resultsFile -Append
        "ERROR: YAML file not found. Test skipped." | Out-File -FilePath $commandLogFile -Append
        return
    }
    
    # Start processing each test number separately for better debugging
    foreach ($testNum in $TestNumbers) {
        "------------------------------------------------------" | Out-File -FilePath $commandLogFile -Append
        "Running Test Number $testNum" | Out-File -FilePath $commandLogFile -Append
        "------------------------------------------------------" | Out-File -FilePath $commandLogFile -Append
        
        try {
            # Check prerequisites
            Write-Host "  [*] Checking prerequisites for test #$testNum..." -ForegroundColor Cyan
            "Checking Prerequisites for Test #${testNum}" | Out-File -FilePath $commandLogFile -Append
            
            # 경로 정보 추가
            "PathToAtomicsFolder = C:\AtomicRedTeam\atomics" | Out-File -FilePath $commandLogFile -Append
            
            $captureStart = Get-Date -Format 'HH:mm:ss'
            "Command Started at: $captureStart" | Out-File -FilePath $commandLogFile -Append
            
            # 직접 출력 캡처를 위한 트랜스크립트 시작
            Start-Transcript -Path "$resultsFolder\temp_transcript.txt" -Force | Out-Null
            
            # 실행 중인 명령을 사용자에게 표시
            $prereqCmd = "Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -CheckPrereqs -ErrorAction Continue -WarningAction Continue"
            "Running command: $prereqCmd" | Out-File -FilePath $commandLogFile -Append
            
            # 실제 실행
            $prereqs = Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -CheckPrereqs -ErrorAction Continue -WarningAction Continue -InformationAction Continue
            
            # 트랜스크립트 중지 및 내용 가져오기
            Stop-Transcript | Out-Null
            $transcriptContent = Get-Content -Path "$resultsFolder\temp_transcript.txt" -Raw
            
            # 트랜스크립트에서 필요한 부분만 추출
            "Prerequisite Check Complete Output:" | Out-File -FilePath $commandLogFile -Append
            $transcriptContent | Out-File -FilePath $commandLogFile -Append
            
            # prereqs 변수 내용도 기록
            "Prerequisite Check Results:" | Out-File -FilePath $commandLogFile -Append
            $prereqs | Out-String -Width 4096 | Out-File -FilePath $commandLogFile -Append
            $prereqs | Out-File -FilePath $resultsFile -Append
            
            $captureEnd = Get-Date -Format 'HH:mm:ss'
            "Command Completed at: $captureEnd" | Out-File -FilePath $commandLogFile -Append
            
            # Attempt to install prerequisites
            Write-Host "  [*] Installing prerequisites for test #$testNum..." -ForegroundColor Cyan
            "Installing Prerequisites for Test #${testNum}" | Out-File -FilePath $commandLogFile -Append
            
            # 경로 정보 추가
            "PathToAtomicsFolder = C:\AtomicRedTeam\atomics" | Out-File -FilePath $commandLogFile -Append
            
            $captureStart = Get-Date -Format 'HH:mm:ss'
            "Command Started at: $captureStart" | Out-File -FilePath $commandLogFile -Append
            
            # 직접 출력 캡처를 위한 트랜스크립트 시작
            Start-Transcript -Path "$resultsFolder\temp_transcript.txt" -Force | Out-Null
            
            # 실행 중인 명령을 사용자에게 표시
            $prereqInstallCmd = "Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -GetPrereqs -ErrorAction Continue -WarningAction Continue"
            "Running command: $prereqInstallCmd" | Out-File -FilePath $commandLogFile -Append
            
            # 실제 실행
            $prereqInstall = Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -GetPrereqs -ErrorAction Continue -WarningAction Continue -InformationAction Continue
            
            # 트랜스크립트 중지 및 내용 가져오기
            Stop-Transcript | Out-Null
            $transcriptContent = Get-Content -Path "$resultsFolder\temp_transcript.txt" -Raw
            
            # 트랜스크립트에서 필요한 부분만 추출
            "Prerequisite Installation Complete Output:" | Out-File -FilePath $commandLogFile -Append
            $transcriptContent | Out-File -FilePath $commandLogFile -Append
            
            # prereqInstall 변수 내용도 기록
            "Prerequisite Installation Results:" | Out-File -FilePath $commandLogFile -Append
            $prereqInstall | Out-String -Width 4096 | Out-File -FilePath $commandLogFile -Append
            
            $captureEnd = Get-Date -Format 'HH:mm:ss'
            "Command Completed at: $captureEnd" | Out-File -FilePath $commandLogFile -Append
            
            # Execute test
            Write-Host "  [*] Executing test #$testNum..." -ForegroundColor Cyan
            "Executing Test #${testNum}" | Out-File -FilePath $commandLogFile -Append
            
            # 경로 정보 추가
            "PathToAtomicsFolder = C:\AtomicRedTeam\atomics" | Out-File -FilePath $commandLogFile -Append
            
            $captureStart = Get-Date -Format 'HH:mm:ss'
            "Command Started at: $captureStart" | Out-File -FilePath $commandLogFile -Append
            
            # 직접 출력 캡처를 위한 트랜스크립트 시작
            Start-Transcript -Path "$resultsFolder\temp_transcript.txt" -Force | Out-Null
            
            # 실행 중인 명령을 사용자에게 표시
            $testCmd = "Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -ErrorAction Continue -WarningAction Continue"
            "Running command: $testCmd" | Out-File -FilePath $commandLogFile -Append
            
            # 실제 테스트 실행
            $testResult = Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -ErrorAction Continue -WarningAction Continue -InformationAction Continue
            
            # 트랜스크립트 중지 및 내용 가져오기
            Stop-Transcript | Out-Null
            $transcriptContent = Get-Content -Path "$resultsFolder\temp_transcript.txt" -Raw
            
            # 트랜스크립트에서 필요한 부분만 추출
            "Test Execution Complete Output:" | Out-File -FilePath $commandLogFile -Append
            $transcriptContent | Out-File -FilePath $commandLogFile -Append
            
            # testResult 변수 내용도 기록
            "Test Execution Results:" | Out-File -FilePath $commandLogFile -Append
            $testResult | Out-String -Width 4096 | Out-File -FilePath $commandLogFile -Append
            $testResult | Out-File -FilePath $resultsFile -Append
            
            $captureEnd = Get-Date -Format 'HH:mm:ss'
            "Command Completed at: $captureEnd" | Out-File -FilePath $commandLogFile -Append
            
            # Evaluate test results
            $testStatus = $?
            if ($testStatus) {
                Write-Host "  [✓] Test #$testNum successful" -ForegroundColor Green
                "Test #$testNum result: Success" | Out-File -FilePath $resultsFile -Append
                "Test #$testNum result: Success" | Out-File -FilePath $commandLogFile -Append
            }
            else {
                Write-Host "  [!] Test #$testNum failed or partially successful" -ForegroundColor Yellow
                "Test #$testNum result: Failed or partially successful" | Out-File -FilePath $resultsFile -Append
                "Test #$testNum result: Failed or partially successful" | Out-File -FilePath $commandLogFile -Append
            }
            
            # Run cleanup
            Write-Host "  [*] Running cleanup for test #$testNum..." -ForegroundColor Cyan
            "Running Cleanup for Test #${testNum}" | Out-File -FilePath $commandLogFile -Append
            
            # 경로 정보 추가
            "PathToAtomicsFolder = C:\AtomicRedTeam\atomics" | Out-File -FilePath $commandLogFile -Append
            
            $captureStart = Get-Date -Format 'HH:mm:ss'
            "Command Started at: $captureStart" | Out-File -FilePath $commandLogFile -Append
            
            # 직접 출력 캡처를 위한 트랜스크립트 시작
            Start-Transcript -Path "$resultsFolder\temp_transcript.txt" -Force | Out-Null
            
            try {
                # 실행 중인 명령을 사용자에게 표시
                $cleanupCmd = "Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -Cleanup -ErrorAction Continue -WarningAction Continue"
                "Running command: $cleanupCmd" | Out-File -FilePath $commandLogFile -Append
                
                # 실제 정리 작업 실행
                $cleanupResult = Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -Cleanup -ErrorAction Continue -WarningAction Continue -InformationAction Continue
                
                # 트랜스크립트 중지 및 내용 가져오기
                Stop-Transcript | Out-Null
                $transcriptContent = Get-Content -Path "$resultsFolder\temp_transcript.txt" -Raw
                
                # 트랜스크립트에서 필요한 부분만 추출
                "Cleanup Complete Output:" | Out-File -FilePath $commandLogFile -Append
                $transcriptContent | Out-File -FilePath $commandLogFile -Append
                
                # cleanupResult 변수 내용도 기록
                "Cleanup Results:" | Out-File -FilePath $commandLogFile -Append
                $cleanupResult | Out-String -Width 4096 | Out-File -FilePath $commandLogFile -Append
                "Cleanup: Complete" | Out-File -FilePath $resultsFile -Append
                "Cleanup: Complete" | Out-File -FilePath $commandLogFile -Append
            }
            catch {
                # 트랜스크립트 중지
                Stop-Transcript | Out-Null
                
                Write-Host "  [X] Cleanup error for test #${testNum}: $_" -ForegroundColor Red
                "Cleanup error: $_" | Out-File -FilePath $resultsFile -Append
                "Cleanup error: $_" | Out-File -FilePath $commandLogFile -Append
                "Error Stack Trace: $($_.ScriptStackTrace)" | Out-File -FilePath $commandLogFile -Append
            }
            
            $captureEnd = Get-Date -Format 'HH:mm:ss'
            "Command Completed at: $captureEnd" | Out-File -FilePath $commandLogFile -Append
            
            # 임시 트랜스크립트 파일 삭제
            if (Test-Path "$resultsFolder\temp_transcript.txt") {
                Remove-Item -Path "$resultsFolder\temp_transcript.txt" -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            # 트랜스크립트가 활성화된 경우 중지
            try { Stop-Transcript | Out-Null } catch { }
            
            Write-Host "  [X] Error occurred during test #${testNum}: $_" -ForegroundColor Red
            "Error occurred during test #${testNum}: $_" | Out-File -FilePath $resultsFile -Append
            "ERROR during test #${testNum}: $_" | Out-File -FilePath $commandLogFile -Append
            "Stack Trace: $($_.ScriptStackTrace)" | Out-File -FilePath $commandLogFile -Append
            
            # 임시 트랜스크립트 파일 삭제
            if (Test-Path "$resultsFolder\temp_transcript.txt") {
                Remove-Item -Path "$resultsFolder\temp_transcript.txt" -Force -ErrorAction SilentlyContinue
            }
        }
        
        # 테스트 간 구분선 추가
        "------------------------------------------------------" | Out-File -FilePath $commandLogFile -Append
        
        # Wait between tests
        Start-Sleep -Seconds 2
    }
}

# 요약 보고서 생성 함수
function Create-SummaryReport {
    Write-Host "Generating summary report..." -ForegroundColor Cyan
    "Windows Atomic Red Team Tests Summary - $(Get-Date)" | Out-File -FilePath $summaryFile
    
    # Parse results file to create summary
    $content = Get-Content -Path $resultsFile
    $techniqueResults = @{}
    $currentTechnique = ""
    $testResults = @{}
    
    foreach ($line in $content) {
        # Match technique headers
        if ($line -match "Running Test: (T\d+(\.\d+)?) - (.+)") {
            # 이전 테크닉 결과 저장
            if ($currentTechnique -ne "") {
                $techniqueResults[$currentTechnique] = $testResults
                $testResults = @{}
            }
            
            $techniqueId = $matches[1]
            $techniqueName = $matches[3]
            $currentTechnique = "$techniqueId - $techniqueName"
        }
        # Match test results for specific test numbers
        elseif ($line -match "Test #(\d+) result: (.+)" -and $currentTechnique -ne "") {
            $testNumber = $matches[1]
            $result = $matches[2]
            $testResults["Test #$testNumber"] = $result
        }
        # Match generic test results (for compatibility with old log format)
        elseif ($line -match "Test result: (.+)" -and $currentTechnique -ne "") {
            $testResults["All Tests"] = $matches[1]
        }
        # Match skipped tests
        elseif ($line -match "Test skipped" -and $currentTechnique -ne "") {
            $testResults["All Tests"] = "Skipped"
        }
    }
    
    # 마지막 테크닉 결과 저장
    if ($currentTechnique -ne "") {
        $techniqueResults[$currentTechnique] = $testResults
    }
    
    # Write summary to file
    "TECHNIQUE ID - NAME                                  | TEST     | RESULT" | Out-File -FilePath $summaryFile -Append
    "------------------------------------------------------------------------" | Out-File -FilePath $summaryFile -Append
    
    $overallResults = @{
        Total = 0
        Success = 0
        Failed = 0
        Skipped = 0
        Unknown = 0
    }
    
    foreach ($technique in $techniqueResults.Keys | Sort-Object) {
        $paddedTechnique = $technique.PadRight(50)
        
        $testData = $techniqueResults[$technique]
        if ($testData.Count -eq 0) {
            "$paddedTechnique | All      | Unknown" | Out-File -FilePath $summaryFile -Append
            $overallResults.Unknown++
            $overallResults.Total++
        }
        else {
            $isFirst = $true
            foreach ($test in $testData.Keys | Sort-Object) {
                $result = $testData[$test]
                
                if ($isFirst) {
                    "$paddedTechnique | $($test.PadRight(8)) | $result" | Out-File -FilePath $summaryFile -Append
                    $isFirst = $false
                }
                else {
                    "$(' ' * 50) | $($test.PadRight(8)) | $result" | Out-File -FilePath $summaryFile -Append
                }
                
                $overallResults.Total++
                switch ($result) {
                    "Success" { $overallResults.Success++ }
                    "Failed or partially successful" { $overallResults.Failed++ }
                    "Skipped" { $overallResults.Skipped++ }
                    default { $overallResults.Unknown++ }
                }
            }
        }
    }
    
    # Calculate success rate (excluding skipped tests)
    $testsExecuted = $overallResults.Total - $overallResults.Skipped
    $successRate = if ($testsExecuted -gt 0) { ($overallResults.Success / $testsExecuted) * 100 } else { 0 }
    
    # Write statistics
    "`n------------------------------------------------------------------------" | Out-File -FilePath $summaryFile -Append
    "Total tests:      $($overallResults.Total)" | Out-File -FilePath $summaryFile -Append
    "Successful tests: $($overallResults.Success)" | Out-File -FilePath $summaryFile -Append
    "Failed tests:     $($overallResults.Failed)" | Out-File -FilePath $summaryFile -Append
    "Skipped tests:    $($overallResults.Skipped)" | Out-File -FilePath $summaryFile -Append
    "Unknown result:   $($overallResults.Unknown)" | Out-File -FilePath $summaryFile -Append
    "Success rate:     $($successRate.ToString("0.00"))%" | Out-File -FilePath $summaryFile -Append
    
    Write-Host "Summary report generated: $summaryFile" -ForegroundColor Green
    
    return $summaryFile
}

# Start testing
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "Starting Windows Atomic Red Team Tests" -ForegroundColor Cyan
Write-Host "Results file: $resultsFile" -ForegroundColor Cyan
Write-Host "Command logs: $commandLogFile" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# Try-catch 블록으로 전체 스크립트 감싸기
try {
    # Add option to run a single technique
    Write-Host "`nOptions:" -ForegroundColor Yellow
    Write-Host "1: Run all tests" -ForegroundColor Yellow
    Write-Host "2: Run a single test" -ForegroundColor Yellow
    $runOption = Read-Host "Select an option (1/2)"
    
    if ($runOption -eq "2") {
        # List all available techniques
        Write-Host "`nAvailable techniques:" -ForegroundColor Cyan
        $count = 1
        foreach ($technique in $windowsTechniques) {
            Write-Host "$count. $($technique.Id) - $($technique.Name)"
            $count++
        }
        
        # Ask which technique to run
        $techniqueIndex = [int](Read-Host "`nEnter the number of the technique to run")
        
        if ($techniqueIndex -ge 1 -and $techniqueIndex -le $windowsTechniques.Count) {
            $selectedTechnique = $windowsTechniques[$techniqueIndex - 1]
            
            Write-Host "`nSelected technique: $($selectedTechnique.Id) - $($selectedTechnique.Name)" -ForegroundColor Green
            $confirmation = Read-Host "Do you want to run this test? (Y/N)"
            
            if ($confirmation -eq 'Y' -or $confirmation -eq 'y') {
                # Set windowsTechniques to only the selected technique
                $windowsTechniques = @($selectedTechnique)
            }
            else {
                Write-Host "Test cancelled." -ForegroundColor Yellow
                exit
            }
        }
        else {
            Write-Host "Invalid selection. Exiting." -ForegroundColor Red
            exit
        }
    }
    else {
        # User confirmation for running all tests
        $confirmation = Read-Host "Do you want to start all tests? (Y/N)"
        if ($confirmation -ne 'Y' -and $confirmation -ne 'y') {
            Write-Host "Tests cancelled." -ForegroundColor Yellow
            exit
        }
    }
    
    # Separate ransomware-related techniques from other techniques
    $ransomwareTechniques = @()
    $normalTechniques = @()
    
    foreach ($technique in $windowsTechniques) {
        # Identify known ransomware-related techniques
        if ($technique.Id -eq "T1486" -or $technique.Id -eq "T1490" -or 
            $technique.Id -eq "T1561.002" -or $technique.Id -match "T1561") {
            $ransomwareTechniques += $technique
        } 
        else {
            $normalTechniques += $technique
        }
    }
    
    # Execute normal tests first
    Write-Host "`n====================================================" -ForegroundColor Cyan
    Write-Host "Running standard (non-ransomware) tests..." -ForegroundColor Cyan
    Write-Host "====================================================" -ForegroundColor Cyan
    
    foreach ($technique in $normalTechniques) {
        Run-AtomicTest -TechniqueId $technique.Id -TechniqueName $technique.Name -TestNumbers $technique.TestNumbers
    }
    
    # Ask for confirmation before running ransomware tests
    if ($ransomwareTechniques.Count -gt 0) {
        Write-Host "`n====================================================" -ForegroundColor Red
        Write-Host "WARNING: RANSOMWARE SIMULATION TESTS" -ForegroundColor Red
        Write-Host "====================================================" -ForegroundColor Red
        Write-Host "The following techniques simulate ransomware behavior:" -ForegroundColor Yellow
        
        foreach ($technique in $ransomwareTechniques) {
            Write-Host "  - $($technique.Id): $($technique.Name)" -ForegroundColor Yellow
        }
        
        Write-Host "`nThese tests can encrypt files and disable system recovery features." -ForegroundColor Red
        Write-Host "Only run these in isolated test environments with no important data." -ForegroundColor Red
        Write-Host "`nAll other tests have been completed. Results so far are saved." -ForegroundColor Green
        
        $ransomwareConfirm = Read-Host "`nDo you want to proceed with ransomware simulation tests? (Y/N)"
        
        if ($ransomwareConfirm -eq 'Y' -or $ransomwareConfirm -eq 'y') {
            Write-Host "`nRunning ransomware simulation tests..." -ForegroundColor Red
            
            foreach ($technique in $ransomwareTechniques) {
                # Extra confirmation for each ransomware test
                $individualConfirm = Read-Host "Run $($technique.Id): $($technique.Name)? (Y/N)"
                
                if ($individualConfirm -eq 'Y' -or $individualConfirm -eq 'y') {
                    Run-AtomicTest -TechniqueId $technique.Id -TechniqueName $technique.Name -TestNumbers $technique.TestNumbers
                } else {
                    Write-Host "Skipping $($technique.Id): $($technique.Name)" -ForegroundColor Yellow
                    
                    # Log skipped test in results file
                    "`n------------------------------------------------------" | Out-File -FilePath $resultsFile -Append
                    "Test skipped by user: $($technique.Id) - $($technique.Name) (Ransomware Test)" | Out-File -FilePath $resultsFile -Append
                    "------------------------------------------------------" | Out-File -FilePath $resultsFile -Append
                    "Skipped by user: Ransomware simulation test" | Out-File -FilePath $resultsFile -Append
                }
            }
        } else {
            Write-Host "Ransomware simulation tests skipped." -ForegroundColor Yellow
            
            foreach ($technique in $ransomwareTechniques) {
                # Log all skipped ransomware tests
                "`n------------------------------------------------------" | Out-File -FilePath $resultsFile -Append
                "Test skipped by user: $($technique.Id) - $($technique.Name) (Ransomware Test)" | Out-File -FilePath $resultsFile -Append
                "------------------------------------------------------" | Out-File -FilePath $resultsFile -Append
                "Skipped by user: Ransomware simulation test" | Out-File -FilePath $resultsFile -Append
            }
        }
    }
    
    # Generate the summary report
    $summaryFilePath = Create-SummaryReport
    
    # Completion message
    Write-Host "`n====================================================" -ForegroundColor Cyan
    Write-Host "Windows Atomic Red Team Tests Completed" -ForegroundColor Cyan
    Write-Host "Results file: $resultsFile" -ForegroundColor Cyan
    Write-Host "Command logs: $commandLogFile" -ForegroundColor Cyan
    Write-Host "Summary report: $summaryFilePath" -ForegroundColor Cyan
    Write-Host "====================================================" -ForegroundColor Cyan
    
    # Done!
    Write-Host "Testing procedure complete." -ForegroundColor Green
}
catch {
    # 트랜스크립트가 활성화된 경우 중지
    try { Stop-Transcript | Out-Null } catch { }
    
    # 전체 스크립트에서 발생한 오류 표시
    Write-Host "`n====================================================" -ForegroundColor Red
    Write-Host "ERROR OCCURRED DURING SCRIPT EXECUTION" -ForegroundColor Red
    Write-Host "====================================================" -ForegroundColor Red
    Write-Host "Error: $_" -ForegroundColor Red
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    
    # 오류 로그 파일에 기록
    "`n====================================================" | Out-File -FilePath $commandLogFile -Append
    "SCRIPT ERROR" | Out-File -FilePath $commandLogFile -Append
    "====================================================" | Out-File -FilePath $commandLogFile -Append
    "Error: $_" | Out-File -FilePath $commandLogFile -Append
    "Stack Trace: $($_.ScriptStackTrace)" | Out-File -FilePath $commandLogFile -Append
    
    # 임시 트랜스크립트 파일 삭제
    if (Test-Path "$resultsFolder\temp_transcript.txt") {
        Remove-Item -Path "$resultsFolder\temp_transcript.txt" -Force -ErrorAction SilentlyContinue
    }
    
    # 계속하기 위한 프롬프트
    Read-Host "Press Enter to exit"
}