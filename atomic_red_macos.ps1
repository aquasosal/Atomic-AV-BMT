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
    @{Id = "T1497.003"; Name = "Time Based Evasion"; TestNumbers = @(1)},
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
    @{Id = "T1555.001"; Name = "Keychain"; TestNumbers = @(1,2,3,4)},
    @{Id = "T1647"; Name = "Plist File Modification"; TestNumbers = @(1)},


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

   @{Id = "T1046"; Name = "Network Service Scanning"; TestNumbers = @(1, 2, 3)},
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

# 콘솔 출력과 로그 파일에 함께 기록하는 함수
function Write-Log {
    param (
        [string]$Message,
        [string]$LogFile,
        [string]$ForegroundColor = "White"
    )
    
    Write-Host $Message -ForegroundColor $ForegroundColor
    $Message | Out-File -FilePath $LogFile -Append
}

# Atomic 테스트 실행 함수 (간략 버전)
function Run-AtomicTest {
    param (
        [string]$TechniqueId,
        [string]$TechniqueName,
        [array]$TestNumbers
    )
    foreach ($testNum in $TestNumbers) {
        try {
            Write-Log "[+] Running Test $TechniqueId - Test #$testNum" $commandLogFile Green
            Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -PathToAtomicsFolder "$env:HOME/AtomicRedTeam/atomic-red-team/atomics" -Force
            Write-Log "[✓] Success $TechniqueId - Test #$testNum" $commandLogFile Green
        }
        catch {
            Write-Log "[!] Failed $TechniqueId - Test #$testNum : $_" $commandLogFile Red
        }
    }
}

# 전체 실행
Write-Host "`nStarting macOS Atomic Red Team Tests" -ForegroundColor Cyan

foreach ($technique in $techniques) {
    Run-AtomicTest -TechniqueId $technique.Id -TechniqueName $technique.Name -TestNumbers $technique.TestNumbers
}

Write-Host "`nAll macOS Atomic Red Team Tests Completed" -ForegroundColor Cyan

# 결과 요약 파일 작성
"Summary of Atomic Tests - $(Get-Date)" | Out-File -FilePath $summaryFile
foreach ($technique in $techniques) {
    $id = $technique.Id
    $name = $technique.Name
    $tests = ($technique.TestNumbers -join ", ")
    "$id - $name (Tests: $tests)" | Out-File -FilePath $summaryFile -Append
}

Write-Host "Summary report generated at: $summaryFile" -ForegroundColor Green
Write-Host "`nTesting Completed Successfully." -ForegroundColor Green
