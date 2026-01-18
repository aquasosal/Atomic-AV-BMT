# Windows Automated Test Script
# Must be executed with administrator privileges in PowerShell

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

# Results file
$resultsFile = "$resultsFolder\Windows_Test_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
"Windows Atomic Red Team Test Results - $(Get-Date)" | Out-File -FilePath $resultsFile

# List of Windows techniques to test (with specific test numbers)
$windowsTechniques = @(
    # Original techniques
    @{Id = "T1059.001"; Name = "PowerShell"; TestNumbers = @(1, 3, 5)},
    @{Id = "T1059.003"; Name = "Windows Command Shell"; TestNumbers = @(1, 2)},
    @{Id = "T1059.005"; Name = "Visual Basic"; TestNumbers = @(1)},
    @{Id = "T1053.005"; Name = "Scheduled Task"; TestNumbers = @(1, 3)},
    @{Id = "T1547.001"; Name = "Registry Run Keys"; TestNumbers = @(1, 4)},
    @{Id = "T1543.003"; Name = "Windows Service"; TestNumbers = @(1)},
    @{Id = "T1136.001"; Name = "Local Account"; TestNumbers = @(1)},
    @{Id = "T1055.001"; Name = "Process Injection"; TestNumbers = @(1)},
    @{Id = "T1027"; Name = "Obfuscated Files"; TestNumbers = @(1, 3)},
    @{Id = "T1027.002"; Name = "Software Packing"; TestNumbers = @(1)},
    @{Id = "T1218.005"; Name = "Mshta"; TestNumbers = @(1, 2)},
    @{Id = "T1218.011"; Name = "Rundll32"; TestNumbers = @(1)},
    @{Id = "T1140"; Name = "Deobfuscate/Decode Files"; TestNumbers = @(1)},
    @{Id = "T1070.004"; Name = "File Deletion"; TestNumbers = @(1)},
    @{Id = "T1497.003"; Name = "Time Based Evasion"; TestNumbers = @(1)},
    @{Id = "T1036.005"; Name = "Match Legitimate Name"; TestNumbers = @(1, 2)},
    @{Id = "T1003.001"; Name = "LSASS Memory"; TestNumbers = @(1)},
    @{Id = "T1082"; Name = "System Information Discovery"; TestNumbers = @(1)},
    @{Id = "T1016"; Name = "Network Configuration Discovery"; TestNumbers = @(1, 2)},
    @{Id = "T1033"; Name = "System Owner/User Discovery"; TestNumbers = @(1)},
    @{Id = "T1057"; Name = "Process Discovery"; TestNumbers = @(1)},
    @{Id = "T1021.001"; Name = "Remote Desktop Protocol"; TestNumbers = @(1)},
    @{Id = "T1021.002"; Name = "SMB/Windows Admin Shares"; TestNumbers = @(1)},
    @{Id = "T1113"; Name = "Screen Capture"; TestNumbers = @(1, 2)},
    @{Id = "T1560.001"; Name = "Archive Collected Data"; TestNumbers = @(1)},
    @{Id = "T1105"; Name = "Ingress Tool Transfer"; TestNumbers = @(1, 3)},
    @{Id = "T1071.001"; Name = "Web Protocols"; TestNumbers = @(1)},
    @{Id = "T1048.003"; Name = "Exfiltration Over Unencrypted Protocol"; TestNumbers = @(1)},
    
    # Additional techniques from the list
    @{Id = "T1001.003"; Name = "Data Obfuscation"; TestNumbers = @(1)},
    @{Id = "T1003.003"; Name = "NTDS"; TestNumbers = @(1)},
    @{Id = "T1036.004"; Name = "Masquerade Task or Service"; TestNumbers = @(1)},
    @{Id = "T1041"; Name = "Exfiltration Over C2 Channel"; TestNumbers = @(1)},
    @{Id = "T1047"; Name = "Windows Management Instrumentation"; TestNumbers = @(1, 2)},
    @{Id = "T1055.002"; Name = "Portable Executable Injection"; TestNumbers = @(1)},
    @{Id = "T1055.011"; Name = "Extra Window Memory Injection"; TestNumbers = @(1)},
    @{Id = "T1055.012"; Name = "Process Hollowing"; TestNumbers = @(1)},
    @{Id = "T1070.006"; Name = "Timestomp"; TestNumbers = @(1)},
    @{Id = "T1112"; Name = "Modify Registry"; TestNumbers = @(1, 2)},
    @{Id = "T1217"; Name = "Browser Bookmark Discovery"; TestNumbers = @(1)},
    @{Id = "T1218.007"; Name = "Msiexec"; TestNumbers = @(1)},
    @{Id = "T1218.010"; Name = "Regsvr32"; TestNumbers = @(1, 2)},
    @{Id = "T1220"; Name = "XSL Script Processing"; TestNumbers = @(1)},
    @{Id = "T1552.001"; Name = "Credentials In Files"; TestNumbers = @(1)},
    @{Id = "T1555.003"; Name = "Credentials from Web Browsers"; TestNumbers = @(1)},
    @{Id = "T1562.001"; Name = "Disable or Modify Tools"; TestNumbers = @(1)},
    @{Id = "T1562.004"; Name = "Disable or Modify System Firewall"; TestNumbers = @(1)},
    @{Id = "T1566.001"; Name = "Spearphishing Attachment"; TestNumbers = @(1)},
    @{Id = "T1546.001"; Name = "Change Default File Association"; TestNumbers = @(1)},
    @{Id = "T1059.008"; Name = "Network Device CLI"; TestNumbers = @(1)},
    @{Id = "T1216.001"; Name = "PubPrn"; TestNumbers = @(1)},
    @{Id = "T1074.001"; Name = "Local Data Staging"; TestNumbers = @(1)},
    @{Id = "T1137.006"; Name = "Add-ins"; TestNumbers = @(1)},
    @{Id = "T1110.001"; Name = "Password Guessing"; TestNumbers = @(1)},
    @{Id = "T1040"; Name = "Network Sniffing"; TestNumbers = @(1)},
    @{Id = "T1090.003"; Name = "Multi-hop Proxy"; TestNumbers = @(1)},
    @{Id = "T1573.001"; Name = "Symmetric Cryptography"; TestNumbers = @(1)},
    @{Id = "T1218.014"; Name = "MMC"; TestNumbers = @(1)},
    @{Id = "T1546.016"; Name = "Printer Drivers"; TestNumbers = @(1)},
    @{Id = "T1547.014"; Name = "Active Setup"; TestNumbers = @(1)},
    @{Id = "T1558.003"; Name = "Kerberoasting"; TestNumbers = @(1)},
    @{Id = "T1558.004"; Name = "AS-REP Roasting"; TestNumbers = @(1)},
    @{Id = "T1559.002"; Name = "Dynamic Data Exchange"; TestNumbers = @(1)},
    @{Id = "T1562.009"; Name = "Safe Boot Mode"; TestNumbers = @(1)},
    @{Id = "T1562.010"; Name = "Downgrade Attack"; TestNumbers = @(1)},
    @{Id = "T1563.002"; Name = "RDP Hijacking"; TestNumbers = @(1)},
    @{Id = "T1014"; Name = "Rootkit"; TestNumbers = @(1)},
    @{Id = "T1056.002"; Name = "GUI Input Capture"; TestNumbers = @(1)},
    @{Id = "T1059.007"; Name = "JavaScript"; TestNumbers = @(1)},
    @{Id = "T1120"; Name = "Peripheral Device Discovery"; TestNumbers = @(1)},
    @{Id = "T1219"; Name = "Remote Access Software"; TestNumbers = @(1)},
    @{Id = "T1486"; Name = "Data Encrypted for Impact"; TestNumbers = @(1)},
    @{Id = "T1490"; Name = "Inhibit System Recovery"; TestNumbers = @(1)},
    @{Id = "T1553.004"; Name = "Install Root Certificate"; TestNumbers = @(1)},
    @{Id = "T1564.010"; Name = "Process Argument Spoofing"; TestNumbers = @(1)},
    @{Id = "T1620"; Name = "Reflective Code Loading"; TestNumbers = @(1)}
)

# Test execution function
function Run-AtomicTest {
    param (
        [string]$TechniqueId,
        [string]$TechniqueName,
        [array]$TestNumbers
    )
    
    "`n------------------------------------------------------" | Out-File -FilePath $resultsFile -Append
    "Running Test: $TechniqueId - $TechniqueName" | Out-File -FilePath $resultsFile -Append
    "------------------------------------------------------" | Out-File -FilePath $resultsFile -Append
    
    Write-Host "`n[+] Running Test: $TechniqueId - $TechniqueName" -ForegroundColor Green
    
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
    
    # Skip test if YAML file still doesn't exist
    if (-not (Test-Path $yamlFile)) {
        Write-Host "  [!] YAML file not found for $TechniqueId. Skipping test." -ForegroundColor Yellow
        "YAML file not found for $TechniqueId. Test skipped." | Out-File -FilePath $resultsFile -Append
        return
    }
    
    try {
        # Check and install prerequisites
        Write-Host "  [*] Checking prerequisites..." -ForegroundColor Cyan
        $prereqs = Invoke-AtomicTest $TechniqueId -TestNumbers $TestNumbers -CheckPrereqs -ErrorAction SilentlyContinue
        $prereqs | Out-File -FilePath $resultsFile -Append
        
        # Attempt to install prerequisites
        Write-Host "  [*] Installing prerequisites..." -ForegroundColor Cyan
        Invoke-AtomicTest $TechniqueId -TestNumbers $TestNumbers -GetPrereqs -ErrorAction SilentlyContinue | Out-Null
        
        # Execute test
        Write-Host "  [*] Executing test..." -ForegroundColor Cyan
        $testResult = Invoke-AtomicTest $TechniqueId -TestNumbers $TestNumbers -ErrorAction SilentlyContinue
        $testResult | Out-File -FilePath $resultsFile -Append
        
        # Evaluate test results
        if ($?) {
            Write-Host "  [✓] Test successful" -ForegroundColor Green
            "Test result: Success" | Out-File -FilePath $resultsFile -Append
        }
        else {
            Write-Host "  [!] Test failed or partially successful" -ForegroundColor Yellow
            "Test result: Failed or partially successful" | Out-File -FilePath $resultsFile -Append
        }
    }
    catch {
        Write-Host "  [X] Error occurred: $_" -ForegroundColor Red
        "Error occurred: $_" | Out-File -FilePath $resultsFile -Append
    }
    finally {
        # Run cleanup
        Write-Host "  [*] Running cleanup..." -ForegroundColor Cyan
        try {
            Invoke-AtomicTest $TechniqueId -TestNumbers $TestNumbers -Cleanup -ErrorAction SilentlyContinue | Out-Null
            "Cleanup: Complete" | Out-File -FilePath $resultsFile -Append
        }
        catch {
            Write-Host "  [X] Cleanup error: $_" -ForegroundColor Red
            "Cleanup error: $_" | Out-File -FilePath $resultsFile -Append
        }
    }
    
    # Wait between tests
    Start-Sleep -Seconds 5
}

# Start testing
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "Starting Windows Atomic Red Team Tests" -ForegroundColor Cyan
Write-Host "Results file: $resultsFile" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

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
                "Test skipped by user: $($technique.Id) - $($technique.Name)" | Out-File -FilePath $resultsFile -Append
            }
        }
    } else {
        Write-Host "Ransomware simulation tests skipped." -ForegroundColor Yellow
        
        foreach ($technique in $ransomwareTechniques) {
            "Test skipped by user: $($technique.Id) - $($technique.Name)" | Out-File -FilePath $resultsFile -Append
        }
    }
}

# Completion message
Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host "Windows Atomic Red Team Tests Completed" -ForegroundColor Cyan
Write-Host "Results file: $resultsFile" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# Add summary report generation
Write-Host "Generating summary report..." -ForegroundColor Cyan
$summaryFile = "$resultsFolder\Windows_Test_Summary_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
"Windows Atomic Red Team Tests Summary - $(Get-Date)" | Out-File -FilePath $summaryFile

# Parse results file to create summary
$content = Get-Content -Path $resultsFile
$techniqueResults = @{}
$currentTechnique = ""

foreach ($line in $content) {
    # Match both formats: "T1059.001 - Name" and "T1027 - Name"
    if ($line -match "Running Test: (T\d+(\.\d+)?) - (.+)") {
        $techniqueId = $matches[1]
        $techniqueName = $matches[3]
        $currentTechnique = "$techniqueId - $techniqueName"
        $techniqueResults[$currentTechnique] = "Unknown"
    }
    elseif ($line -match "Test result: (.+)" -and $currentTechnique -ne "") {
        $techniqueResults[$currentTechnique] = $matches[1]
    }
    elseif ($line -match "Test skipped" -and $currentTechnique -ne "") {
        $techniqueResults[$currentTechnique] = "Skipped"
    }
}

# Write summary to file
"TECHNIQUE ID - NAME                                  | RESULT" | Out-File -FilePath $summaryFile -Append
"--------------------------------------------------------" | Out-File -FilePath $summaryFile -Append
foreach ($technique in $techniqueResults.Keys | Sort-Object) {
    $result = $techniqueResults[$technique]
    $paddedTechnique = $technique.PadRight(50)
    "$paddedTechnique | $result" | Out-File -FilePath $summaryFile -Append
}

# Final stats
$totalTests = $techniqueResults.Count
$successfulTests = ($techniqueResults.Values | Where-Object { $_ -eq "Success" }).Count
$failedTests = ($techniqueResults.Values | Where-Object { $_ -eq "Failed or partially successful" }).Count
$skippedTests = ($techniqueResults.Values | Where-Object { $_ -eq "Skipped" }).Count
$unknownTests = $totalTests - $successfulTests - $failedTests - $skippedTests

"`n--------------------------------------------------------" | Out-File -FilePath $summaryFile -Append
"Total tests:      $totalTests" | Out-File -FilePath $summaryFile -Append
"Successful tests: $successfulTests" | Out-File -FilePath $summaryFile -Append
"Failed tests:     $failedTests" | Out-File -FilePath $summaryFile -Append
"Skipped tests:    $skippedTests" | Out-File -FilePath $summaryFile -Append
"Unknown result:   $unknownTests" | Out-File -FilePath $summaryFile -Append
"Success rate:     $(($successfulTests / ($totalTests - $skippedTests)) * 100)%" | Out-File -FilePath $summaryFile -Append

Write-Host "Summary report generated: $summaryFile" -ForegroundColor Green
Write-Host "Testing procedure complete." -ForegroundColor Green