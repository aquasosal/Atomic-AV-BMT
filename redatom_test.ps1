# Windows Automated Test Script
# Must be executed with administrator privileges in PowerShell

# Encoding settings
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$PSDefaultParameterValues['*:Encoding'] = 'utf8'

# Define colors for console output
$colorRed = @{ForegroundColor = "Red"}
$colorGreen = @{ForegroundColor = "Green"}
$colorYellow = @{ForegroundColor = "Yellow"}
$colorCyan = @{ForegroundColor = "Cyan"}

# Install module if not available
if (-not (Get-Module -ListAvailable -Name InvokeAtomicRedTeam)) {
    Write-Host "Installing AtomicRedTeam module..." @colorYellow
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

# Custom function to execute and log commands
function Run-LoggedCommand {
    param (
        [string]$Command,
        [string]$Description = "Executing command"
    )
    
    # Log to command log file
    "`n--------------- $Description ---------------" | Out-File -FilePath $commandLogFile -Append
    "Command: $Command" | Out-File -FilePath $commandLogFile -Append
    
    Write-Host "  [*] $Description" @colorCyan
    Write-Host "      $Command"
    
    # Execute command and capture output
    try {
        $output = Invoke-Expression -Command $Command -ErrorVariable errorOutput 2>&1
        
        # Log the output
        if ($output) {
            "Output:" | Out-File -FilePath $commandLogFile -Append
            $output | Out-String | Out-File -FilePath $commandLogFile -Append
        }
        
        # Log any errors
        if ($errorOutput) {
            "Errors:" | Out-File -FilePath $commandLogFile -Append
            $errorOutput | Out-String | Out-File -FilePath $commandLogFile -Append
        }
        
        # Return success status and output
        return @{
            Success = $true
            Output = $output
            Error = $errorOutput
        }
    }
    catch {
        "Exception: $_" | Out-File -FilePath $commandLogFile -Append
        
        # Return failure status and error
        return @{
            Success = $false
            Output = $null
            Error = $_
        }
    }

# Execute normal tests first
Write-Host "`n====================================================" @colorCyan
Write-Host "Running standard (non-ransomware) tests..." @colorCyan
Write-Host "====================================================" @colorCyan

foreach ($technique in $normalTechniques) {
    Run-AtomicTest -TechniqueId $technique.Id -TechniqueName $technique.Name -TestNumbers $technique.TestNumbers
}

# Ask for confirmation before running ransomware tests
if ($ransomwareTechniques.Count -gt 0) {
    Write-Host "`n====================================================" @colorRed
    Write-Host "WARNING: RANSOMWARE SIMULATION TESTS" @colorRed
    Write-Host "====================================================" @colorRed
    Write-Host "The following techniques simulate ransomware behavior:" @colorYellow
    
    foreach ($technique in $ransomwareTechniques) {
        Write-Host "  - $($technique.Id): $($technique.Name)" @colorYellow
    }
    
    Write-Host "`nThese tests can encrypt files and disable system recovery features." @colorRed
    Write-Host "Only run these in isolated test environments with no important data." @colorRed
    Write-Host "`nAll other tests have been completed. Results so far are saved." @colorGreen
    
    $ransomwareConfirm = Read-Host "`nDo you want to proceed with ransomware simulation tests? (Y/N)"
    
    if ($ransomwareConfirm -eq 'Y' -or $ransomwareConfirm -eq 'y') {
        Write-Host "`nRunning ransomware simulation tests..." @colorRed
        
        foreach ($technique in $ransomwareTechniques) {
            # Extra confirmation for each ransomware test
            $individualConfirm = Read-Host "Run $($technique.Id): $($technique.Name)? (Y/N)"
            
            if ($individualConfirm -eq 'Y' -or $individualConfirm -eq 'y') {
                Run-AtomicTest -TechniqueId $technique.Id -TechniqueName $technique.Name -TestNumbers $technique.TestNumbers
            } else {
                Write-Host "Skipping $($technique.Id): $($technique.Name)" @colorYellow
                
                # Log skipped test in results file
                "`n------------------------------------------------------" | Out-File -FilePath $resultsFile -Append
                "Test skipped by user: $($technique.Id) - $($technique.Name) (Ransomware Test)" | Out-File -FilePath $resultsFile -Append
                "------------------------------------------------------" | Out-File -FilePath $resultsFile -Append
                "Skipped by user: Ransomware simulation test" | Out-File -FilePath $resultsFile -Append
            }
        }
    } else {
        Write-Host "Ransomware simulation tests skipped." @colorYellow
        
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
Write-Host "`n====================================================" @colorCyan
Write-Host "Windows Atomic Red Team Tests Completed" @colorCyan
Write-Host "Results file: $resultsFile" @colorCyan
Write-Host "Command logs: $commandLogFile" @colorCyan
Write-Host "Summary report: $summaryFilePath" @colorCyan
Write-Host "====================================================" @colorCyan

# Done!
Write-Host "Testing procedure complete." @colorGreen
}

# Function to get command details from an AtomicTest object
function Get-AtomicCommandDetails {
    param (
        [object]$AtomicTest,
        [int]$TestNumber
    )
    
    # Get the specific test
    $test = $AtomicTest.atomic_tests[$TestNumber - 1]
    if (-not $test) {
        return $null
    }
    
    # Extract commands
    $commands = @{
        Name = $test.name
        Command = $test.executor.command
        Cleanup = $test.executor.cleanup_command
        PrereqCommands = @()
        GetPrereqCommands = @()
    }
    
    # Extract prerequisite commands
    if ($test.dependencies) {
        foreach ($dep in $test.dependencies) {
            if ($dep.prereq_command) {
                $commands.PrereqCommands += $dep.prereq_command
            }
            if ($dep.get_prereq_command) {
                $commands.GetPrereqCommands += $dep.get_prereq_command
            }
        }
    }
    
    return $commands
}

# Test execution function with improved logging
function Run-AtomicTest {
    param (
        [string]$TechniqueId,
        [string]$TechniqueName,
        [array]$TestNumbers
    )
    
    # Log test header
    $testHeader = "`n------------------------------------------------------`nRunning Test: $TechniqueId - $TechniqueName`n------------------------------------------------------"
    $testHeader | Out-File -FilePath $resultsFile -Append
    
    Write-Host "`n[+] Running Test: $TechniqueId - $TechniqueName" @colorGreen
    
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
            Write-Host "  [*] Using base technique $baseTechnique instead of $TechniqueId" @colorYellow
            $TechniqueId = $baseTechnique
            $yamlFile = $baseYaml
            "Using base technique $baseTechnique instead of original TechniqueId" | Out-File -FilePath $resultsFile -Append
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
    
    # Log YAML file path
    "YAML file path: $yamlFile" | Out-File -FilePath $resultsFile -Append
    
    # Skip test if YAML file still doesn't exist
    if (-not (Test-Path $yamlFile)) {
        Write-Host "  [!] YAML file not found for $TechniqueId. Skipping test." @colorYellow
        "YAML file not found for $TechniqueId. Test skipped." | Out-File -FilePath $resultsFile -Append
        return
    }
    
    # Read YAML content directly to extract command details for logging
    $rawYamlContent = Get-Content -Path $yamlFile -Raw
    $atomicTestObject = ConvertFrom-Yaml -Yaml $rawYamlContent
    
    # Process each test number
    foreach ($testNum in $TestNumbers) {
        # Get command details from the YAML for detailed logging
        $testDetails = Get-AtomicCommandDetails -AtomicTest $atomicTestObject -TestNumber $testNum
        
        if (-not $testDetails) {
            Write-Host "  [!] Test number $testNum not found in YAML. Skipping." @colorYellow
            "Test number $testNum not found in YAML. Skipping." | Out-File -FilePath $resultsFile -Append
            continue
        }
        
        $testName = $testDetails.Name
        
        # Log the test start
        $testStartHeader = "`nRunning Test Number $testNum: $testName"
        $testStartHeader | Out-File -FilePath $resultsFile -Append
        Write-Host "`n  [+] Running Test Number $testNum: $testName" @colorGreen
        
        # Log actual command that will be executed
        "Command to be executed:" | Out-File -FilePath $resultsFile -Append
        $testDetails.Command | Out-File -FilePath $resultsFile -Append
        
        try {
            # Check prerequisites
            Write-Host "  [*] Checking prerequisites..." @colorCyan
            "Checking prerequisites..." | Out-File -FilePath $resultsFile -Append
            
            # Log the prerequisite commands
            if ($testDetails.PrereqCommands.Count -gt 0) {
                "Prerequisite checks:" | Out-File -FilePath $resultsFile -Append
                $testDetails.PrereqCommands | ForEach-Object { $_ | Out-File -FilePath $resultsFile -Append }
            }
            
            $prereqs = Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -CheckPrereqs -ErrorAction SilentlyContinue
            "Prerequisite results:" | Out-File -FilePath $resultsFile -Append
            $prereqs | Out-String | Out-File -FilePath $resultsFile -Append
            
            # Install prerequisites if needed
            if ($prereqs -match "Prereq command returned exit code" -or $prereqs -match "failed") {
                Write-Host "  [*] Installing prerequisites..." @colorCyan
                "Installing prerequisites..." | Out-File -FilePath $resultsFile -Append
                
                # Log the get prerequisite commands
                if ($testDetails.GetPrereqCommands.Count -gt 0) {
                    "Get prerequisite commands:" | Out-File -FilePath $resultsFile -Append
                    $testDetails.GetPrereqCommands | ForEach-Object { $_ | Out-File -FilePath $resultsFile -Append }
                }
                
                $prereqInstall = Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -GetPrereqs -ErrorAction SilentlyContinue
                "Prerequisite installation results:" | Out-File -FilePath $resultsFile -Append
                $prereqInstall | Out-String | Out-File -FilePath $resultsFile -Append
            }
            
            # Execute test with detailed logging
            Write-Host "  [*] Executing test..." @colorCyan
            "Executing test..." | Out-File -FilePath $resultsFile -Append
            
            # Special handling for potentially destructive commands (similar to the Python script)
            $isRansomware = $TechniqueId -eq "T1486" -or $TechniqueId -eq "T1490" -or $TechniqueId -match "T1561"
            $isSystemShutdown = $testDetails.Command -match "shutdown" -or $testDetails.Command -match "restart" -or $testDetails.Command -match "poweroff"
            
            if ($isSystemShutdown) {
                # Log original command
                Write-Host "  [!] Original command would shut down the system (simulating instead):" @colorYellow
                Write-Host "      $($testDetails.Command)"
                "Original shutdown command (not executed): $($testDetails.Command)" | Out-File -FilePath $resultsFile -Append
                
                # Run a simulated command instead
                $mockCommand = "Write-Host '[Simulated] Would have executed: $($testDetails.Command)'"
                $testResult = Run-LoggedCommand -Command $mockCommand -Description "Simulating system shutdown/restart command"
                "Command simulated instead of actual execution." | Out-File -FilePath $resultsFile -Append
            }
            else {
                # Normal test execution with standard command
                $testResult = Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -ErrorAction SilentlyContinue
                "Test execution results:" | Out-File -FilePath $resultsFile -Append
                $testResult | Out-String | Out-File -FilePath $resultsFile -Append
            }
            
            # Evaluate test results
            $testStatus = $?
            if ($testStatus) {
                Write-Host "  [✓] Test $testNum successful" @colorGreen
                "Test $testNum result: Success" | Out-File -FilePath $resultsFile -Append
            }
            else {
                Write-Host "  [!] Test $testNum failed or partially successful" @colorYellow
                "Test $testNum result: Failed or partially successful" | Out-File -FilePath $resultsFile -Append
            }
            
            # Run cleanup
            if ($testDetails.Cleanup) {
                Write-Host "  [*] Running cleanup..." @colorCyan
                "Running cleanup command:" | Out-File -FilePath $resultsFile -Append
                $testDetails.Cleanup | Out-File -FilePath $resultsFile -Append
                
                try {
                    $cleanupResult = Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -Cleanup -ErrorAction SilentlyContinue
                    "Cleanup results:" | Out-File -FilePath $resultsFile -Append
                    $cleanupResult | Out-String | Out-File -FilePath $resultsFile -Append
                    "Cleanup: Complete" | Out-File -FilePath $resultsFile -Append
                }
                catch {
                    Write-Host "  [X] Cleanup error: $_" @colorRed
                    "Cleanup error: $_" | Out-File -FilePath $resultsFile -Append
                }
            }
            else {
                "No cleanup command specified." | Out-File -FilePath $resultsFile -Append
            }
        }
        catch {
            Write-Host "  [X] Error occurred during test $testNum: $_" @colorRed
            "Error occurred during test $testNum: $_" | Out-File -FilePath $resultsFile -Append
        }
        
        # Add separator between test numbers
        "---" | Out-File -FilePath $resultsFile -Append
        
        # Wait between tests
        Start-Sleep -Seconds 2
    }
}

# Function to generate summary report
function Create-SummaryReport {
    Write-Host "Generating summary report..." @colorCyan
    
    "Windows Atomic Red Team Tests Summary - $(Get-Date)" | Out-File -FilePath $summaryFile
    
    # Parse results file to create summary
    $content = Get-Content -Path $resultsFile
    $techniqueResults = @{}
    $currentTechnique = ""
    $currentTest = ""
    
    foreach ($line in $content) {
        # Match technique headers
        if ($line -match "Running Test: (T\d+(\.\d+)?) - (.+)") {
            $techniqueId = $matches[1]
            $techniqueName = $matches[3]
            $currentTechnique = "$techniqueId - $techniqueName"
            $techniqueResults[$currentTechnique] = @{}
        }
        # Match test number headers
        elseif ($line -match "Running Test Number (\d+): (.+)" -and $currentTechnique -ne "") {
            $testNumber = $matches[1]
            $testName = $matches[2]
            $currentTest = "Test $testNumber"
            $techniqueResults[$currentTechnique][$currentTest] = "Unknown"
        }
        # Match test results
        elseif ($line -match "Test \d+ result: (.+)" -and $currentTechnique -ne "" -and $currentTest -ne "") {
            $techniqueResults[$currentTechnique][$currentTest] = $matches[1]
        }
        # Match skipped tests
        elseif ($line -match "Test skipped" -and $currentTechnique -ne "") {
            if ($currentTest -ne "") {
                $techniqueResults[$currentTechnique][$currentTest] = "Skipped"
            }
            else {
                $techniqueResults[$currentTechnique]["All Tests"] = "Skipped"
            }
        }
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
        
        $testResults = $techniqueResults[$technique]
        if ($testResults.Count -eq 0) {
            "$paddedTechnique | All      | Unknown" | Out-File -FilePath $summaryFile -Append
            $overallResults.Unknown++
            $overallResults.Total++
        }
        else {
            $isFirst = $true
            foreach ($test in $testResults.Keys | Sort-Object) {
                $result = $testResults[$test]
                
                if ($isFirst) {
                    "$paddedTechnique | $($test.PadRight(8)) | $result" | Out-File -FilePath $summaryFile -Append
                    $isFirst = $false
                }
                else {
                    "$((' ' * 50)) | $($test.PadRight(8)) | $result" | Out-File -FilePath $summaryFile -Append
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
    
    Write-Host "Summary report generated: $summaryFile" @colorGreen
    
    return $summaryFile
}

# Start testing
Write-Host "====================================================" @colorCyan
Write-Host "Starting Windows Atomic Red Team Tests" @colorCyan
Write-Host "Results file: $resultsFile" @colorCyan
Write-Host "Command logs: $commandLogFile" @colorCyan
Write-Host "====================================================" @colorCyan

# Add option to run a single technique
Write-Host "`nOptions:" @colorYellow
Write-Host "1: Run all tests" @colorYellow
Write-Host "2: Run a single test" @colorYellow
$runOption = Read-Host "Select an option (1/2)"

if ($runOption -eq "2") {
    # List all available techniques
    Write-Host "`nAvailable techniques:" @colorCyan
    $count = 1
    foreach ($technique in $windowsTechniques) {
        Write-Host "$count. $($technique.Id) - $($technique.Name)"
        $count++
    }
    
    # Ask which technique to run
    $techniqueIndex = [int](Read-Host "`nEnter the number of the technique to run")
    
    if ($techniqueIndex -ge 1 -and $techniqueIndex -le $windowsTechniques.Count) {
        $selectedTechnique = $windowsTechniques[$techniqueIndex - 1]
        
        Write-Host "`nSelected technique: $($selectedTechnique.Id) - $($selectedTechnique.Name)" @colorGreen
        $confirmation = Read-Host "Do you want to run this test? (Y/N)"
        
        if ($confirmation -eq 'Y' -or $confirmation -eq 'y') {
            # Set windowsTechniques to only the selected technique
            $windowsTechniques = @($selectedTechnique)
        }
        else {
            Write-Host "Test cancelled." @colorYellow
            exit
        }
    }
    else {
        Write-Host "Invalid selection. Exiting." @colorRed
        exit
    }
}
else {
    # User confirmation for running all tests
    $confirmation = Read-Host "Do you want to start all tests? (Y/N)"
    if ($confirmation -ne 'Y' -and $confirmation -ne 'y') {
        Write-Host "Tests cancelled." @colorYellow
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