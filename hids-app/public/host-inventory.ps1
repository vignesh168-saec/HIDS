# === Unified Inventory Script with Downloads EXE Hashes ===
# Collects Config Files, Processes, Services, and Downloads EXEs into one CSV

$outputCSV = "C:\System_Inventory.csv"
$results = @()

# --- 1) Inetpub Config Files ---
$inetpubPath = "C:\inetpub"
$filePatterns = @("*.config", "*.ini", "*.xml", "*.json")

foreach ($pattern in $filePatterns) {
    try {
        $foundFiles = Get-ChildItem -Path $inetpubPath -Recurse -Filter $pattern -ErrorAction SilentlyContinue
        foreach ($file in $foundFiles) {
            $results += [PSCustomObject]@{
                Category   = "ConfigFile"
                Name       = $file.Name
                Path       = $file.FullName
                Additional = "Size: $([math]::Round($file.Length/1KB,2)) KB"
                Status     = "Found"
                Hash       = "N/A"
            }
        }
    } catch {
        Write-Warning "Error scanning config files: $($_.Exception.Message)"
    }
}

# --- 2) Process Inventory with Hashes ---
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $processes = Get-Process | ForEach-Object {
        $pid  = $_.Id
        $name = $_.Name
        $path = $_.Path
        $cmd  = $_.CommandLine

        if ($path -and (Test-Path -LiteralPath $path)) {
            try {
                $hash = Get-FileHash -Path $path -Algorithm SHA256
                $hashVal = $hash.Hash
            } catch {
                $hashVal = "Error: $($_.Exception.Message)"
            }
        } else {
            $hashVal = if ($path) { "File Not Found" } else { "N/A" }
        }

        [PSCustomObject]@{
            Category   = "Process"
            Name       = $name
            Path       = $path
            Additional = "PID: $pid; Cmd: $cmd"
            Status     = if ($hashVal -like "Error*") { "Error" } elseif ($hashVal -eq "File Not Found") { "Missing" } else { "OK" }
            Hash       = $hashVal
        }
    }
    $results += $processes
} else {
    $processes = Get-CimInstance -ClassName Win32_Process | ForEach-Object {
        $pid  = $_.ProcessId
        $name = $_.Name
        $path = $_.ExecutablePath
        $cmd  = $_.CommandLine

        if ($path -and (Test-Path -LiteralPath $path)) {
            try {
                $hash = Get-FileHash -Path $path -Algorithm SHA256
                $hashVal = $hash.Hash
            } catch {
                $hashVal = "Error: $($_.Exception.Message)"
            }
        } else {
            $hashVal = if ($path) { "File Not Found" } else { "N/A" }
        }

        [PSCustomObject]@{
            Category   = "Process"
            Name       = $name
            Path       = $path
            Additional = "PID: $pid; Cmd: $cmd"
            Status     = if ($hashVal -like "Error*") { "Error" } elseif ($hashVal -eq "File Not Found") { "Missing" } else { "OK" }
            Hash       = $hashVal
        }
    }
    $results += $processes
}

# --- 3) Service Inventory with Hashes ---
$services = Get-CimInstance -ClassName Win32_Service | ForEach-Object {
    $serviceName = $_.Name
    $displayName = $_.DisplayName
    $state       = $_.State
    $rawPathFull = ($_.PathName -replace '"','')
    $rawPath     = $rawPathFull -replace '(^.*?\.exe).*','$1'

    if ($rawPath -like '*\svchost.exe') {
        $regPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$serviceName\Parameters"
        $serviceDll = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).ServiceDll
        $dllPath = if ($serviceDll) { [Environment]::ExpandEnvironmentVariables($serviceDll) } else { $null }

        if ($dllPath -and (Test-Path -LiteralPath $dllPath)) {
            try {
                $hash = Get-FileHash -Path $dllPath -Algorithm SHA256
                $hashVal = $hash.Hash
            } catch {
                $hashVal = "Error: $($_.Exception.Message)"
            }
            $pathUsed = $dllPath
        } else {
            $hashVal = "ServiceDll Missing"
            $pathUsed = $dllPath
        }
        $fileType = "Service DLL (svchost)"
    }
    elseif (Test-Path -LiteralPath $rawPath) {
        try {
            $hash = Get-FileHash -Path $rawPath -Algorithm SHA256
            $hashVal = $hash.Hash
        } catch {
            $hashVal = "Error: $($_.Exception.Message)"
        }
        $fileType = "Executable"
        $pathUsed = $rawPath
    }
    else {
        $hashVal = "File Not Found"
        $fileType = "Missing"
        $pathUsed = $rawPath
    }

    [PSCustomObject]@{
        Category   = "Service"
        Name       = $serviceName
        Path       = $pathUsed
        Additional = "Display: $displayName; State: $state; Type: $fileType"
        Status     = if ($hashVal -eq "File Not Found") { "Missing" } elseif ($hashVal -like "Error*") { "Error" } else { "OK" }
        Hash       = $hashVal
    }
}
$results += $services

# --- 4) Downloads EXE Inventory with Hashes ---
$downloadsPath = "$env:USERPROFILE\Downloads"
$exeFiles = Get-ChildItem -Path $downloadsPath -Recurse -Filter *.exe -ErrorAction SilentlyContinue

foreach ($file in $exeFiles) {
    try {
        $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256
        $hashVal = $hash.Hash
    } catch {
        $hashVal = "Error: $($_.Exception.Message)"
    }

    $results += [PSCustomObject]@{
        Category   = "DownloadsEXE"
        Name       = $file.Name
        Path       = $file.FullName
        Additional = "Size: {0:N2} MB; LastWrite: $($file.LastWriteTime)" -f ($file.Length / 1MB)
        Status     = if ($hashVal -like "Error*") { "Error" } else { "OK" }
        Hash       = $hashVal
    }
}

# --- Final Export ---
$results | Export-Csv -Path $outputCSV -NoTypeInformation -Encoding UTF8
Write-Host "Unified inventory saved to $outputCSV"