#requires -Version 5.1
<#
Cybertest Windows installer.

Recommended sequence:
  powershell -ExecutionPolicy Bypass -File .\install_windows.ps1 -Detect -Profile web
  powershell -ExecutionPolicy Bypass -File .\install_windows.ps1 -DryRun -Profile web
  powershell -ExecutionPolicy Bypass -File .\install_windows.ps1 -Profile web

The script is best-effort. It installs common runtimes and security tools used
by tool/*.py wrappers, then prints anything that still needs manual handling.
#>

[CmdletBinding()]
param(
    [ValidateSet("minimal", "web", "full", "reverse")]
    [string]$Profile = "full",
    [switch]$Detect,
    [switch]$DryRun,
    [switch]$UpdatePath,
    [switch]$SkipWinget,
    [switch]$SkipGoTools,
    [switch]$SkipPythonTools,
    [switch]$InstallChocolatey,
    [switch]$NoPathUpdate
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogPath = Join-Path $ScriptRoot "install_windows.log"
$ToolsBin = Join-Path $ScriptRoot ".tools\bin"
$GoBin = Join-Path $env:USERPROFILE "go\bin"

$Summary = [ordered]@{
    Installed = New-Object System.Collections.Generic.List[string]
    Present = New-Object System.Collections.Generic.List[string]
    Failed = New-Object System.Collections.Generic.List[string]
    Manual = New-Object System.Collections.Generic.List[string]
}

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Info {
    param([string]$Message)
    Write-Host "[*] $Message"
}

function Write-Ok {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-WarnLine {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Add-Summary {
    param(
        [ValidateSet("Installed", "Present", "Failed", "Manual")]
        [string]$Kind,
        [string]$Value
    )
    $Summary[$Kind].Add($Value) | Out-Null
}

function Test-Command {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Test-SelectedProfile {
    param([string[]]$Names)
    return $Names -contains $Profile
}

function Get-ProfileCommands {
    switch ($Profile) {
        "minimal" {
            return @("git", "python", "curl")
        }
        "web" {
            return @(
                "git", "python", "curl", "node", "go", "nmap", "rustscan",
                "subfinder", "dnsx", "httpx", "tlsx", "naabu", "katana",
                "nuclei", "ffuf", "waybackurls", "arjun", "wafw00f",
                "whatweb", "sqlmap", "dalfox", "kr", "zap-baseline.py"
            )
        }
        "full" {
            return @(
                "git", "python", "curl", "node", "go", "nmap", "rustscan",
                "masscan", "hashcat", "trivy", "gitleaks", "semgrep",
                "sqlmap", "wafw00f", "whatweb", "subfinder", "dnsx",
                "httpx", "tlsx", "naabu", "katana", "nuclei", "ffuf",
                "waybackurls", "arjun", "dalfox", "kr", "zap-baseline.py"
            )
        }
        "reverse" {
            return @(
                "git", "python", "curl", "java", "adb", "jadx", "apktool",
                "r2", "frida"
            )
        }
    }
}

function Test-ProfileCommand {
    param([string]$Name)
    switch ($Name) {
        "python" {
            return (Test-Command "python") -or (Test-Command "python3")
        }
        "r2" {
            return (Test-Command "r2") -or (Test-Command "radare2")
        }
        default {
            return Test-Command $Name
        }
    }
}

function Show-ProfileStatus {
    param([switch]$Plan)

    $mode = if ($Plan) { "dry-run" } else { "detect" }
    Write-Host "Cybertest dependency mode=$mode profile=$Profile"
    foreach ($commandName in (Get-ProfileCommands)) {
        if (Test-ProfileCommand $commandName) {
            Write-Host "present  $commandName"
        } elseif ($Plan) {
            Write-Host "planned  $commandName"
        } else {
            Write-Host "missing  $commandName"
        }
    }
    if ($Plan) {
        $pathMode = if ($UpdatePath -and -not $NoPathUpdate) {
            "enabled"
        } else {
            "disabled"
        }
        Write-Host "path_update=$pathMode (not applied in dry-run)"
        Write-Host "No installation, network access, PATH update, or log write was performed."
    }
}

function Invoke-Logged {
    param(
        [string]$DisplayName,
        [string[]]$Command
    )

    Write-Info $DisplayName
    Add-Content -Path $LogPath -Encoding UTF8 -Value ""
    Add-Content -Path $LogPath -Encoding UTF8 -Value ">>> $DisplayName"
    Add-Content -Path $LogPath -Encoding UTF8 -Value ($Command -join " ")

    try {
        $output = & $Command[0] @($Command[1..($Command.Count - 1)]) 2>&1
        $code = $LASTEXITCODE
        if ($null -ne $output) {
            Add-Content -Path $LogPath -Encoding UTF8 -Value ($output | Out-String)
        }
        if ($code -eq 0 -or $null -eq $code) {
            Write-Ok $DisplayName
            return $true
        }
        Write-WarnLine "$DisplayName failed with exit code $code"
        return $false
    } catch {
        Add-Content -Path $LogPath -Encoding UTF8 -Value $_.Exception.Message
        Write-WarnLine "$DisplayName failed: $($_.Exception.Message)"
        return $false
    }
}

function Ensure-PathEntry {
    param([string]$PathValue)

    if ([string]::IsNullOrWhiteSpace($PathValue) -or !(Test-Path $PathValue)) {
        return
    }

    $currentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $parts = @()
    if ($currentUserPath) {
        $parts = $currentUserPath -split ";"
    }
    if ($parts -contains $PathValue) {
        return
    }

    $newPath = if ($currentUserPath) { "$currentUserPath;$PathValue" } else { $PathValue }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    $env:Path = "$env:Path;$PathValue"
    Write-Ok "PATH updated: $PathValue"
}

function Update-CurrentPath {
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = @($machinePath, $userPath) -join ";"
    if (Test-Path $GoBin) {
        $env:Path = "$env:Path;$GoBin"
    }
    $python312 = Join-Path $env:APPDATA "Python\Python312\Scripts"
    $python311 = Join-Path $env:APPDATA "Python\Python311\Scripts"
    foreach ($path in @($python312, $python311, (Join-Path $env:APPDATA "npm"))) {
        if (Test-Path $path) {
            $env:Path = "$env:Path;$path"
        }
    }
}

function Install-WingetPackage {
    param(
        [string]$CommandName,
        [string]$PackageId,
        [string]$Label
    )

    if (Test-Command $CommandName) {
        Add-Summary Present $Label
        Write-Ok "$Label already present"
        return
    }

    if ($SkipWinget -or !(Test-Command "winget")) {
        Add-Summary Manual "$Label ($PackageId)"
        Write-WarnLine "winget unavailable or skipped: $Label"
        return
    }

    $ok = Invoke-Logged "winget install $Label" @(
        "winget", "install",
        "--id", $PackageId,
        "--exact",
        "--accept-package-agreements",
        "--accept-source-agreements",
        "--silent"
    )
    if ($ok) {
        Add-Summary Installed $Label
    } else {
        Add-Summary Failed "$Label ($PackageId)"
    }
}

function Install-ChocoIfRequested {
    if (!$InstallChocolatey -or (Test-Command "choco")) {
        return
    }

    Write-Step "Installing Chocolatey"
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString("https://community.chocolatey.org/install.ps1"))
        if (Test-Command "choco") {
            Add-Summary Installed "Chocolatey"
        } else {
            Add-Summary Failed "Chocolatey"
        }
    } catch {
        Write-WarnLine "Chocolatey install failed: $($_.Exception.Message)"
        Add-Summary Failed "Chocolatey"
    }
}

function Install-ChocoPackage {
    param(
        [string]$CommandName,
        [string]$PackageName,
        [string]$Label
    )

    if (Test-Command $CommandName) {
        Add-Summary Present $Label
        return
    }
    if (!(Test-Command "choco")) {
        Add-Summary Manual "$Label (choco:$PackageName)"
        return
    }
    $ok = Invoke-Logged "choco install $Label" @("choco", "install", $PackageName, "-y", "--no-progress")
    if ($ok) {
        Add-Summary Installed $Label
    } else {
        Add-Summary Failed "$Label (choco:$PackageName)"
    }
}

function Install-GoTool {
    param(
        [string]$CommandName,
        [string]$Module,
        [string]$Label
    )

    if (Test-Command $CommandName) {
        Add-Summary Present $Label
        Write-Ok "$Label already present"
        return
    }
    if ($SkipGoTools) {
        Add-Summary Manual "$Label ($Module)"
        return
    }
    if (!(Test-Command "go")) {
        Add-Summary Manual "$Label requires Go: $Module"
        Write-WarnLine "Go unavailable: $Label"
        return
    }

    $ok = Invoke-Logged "go install $Label" @("go", "install", $Module)
    if ($ok) {
        Add-Summary Installed $Label
    } else {
        Add-Summary Failed "$Label ($Module)"
    }
}

function Install-PipTool {
    param(
        [string]$CommandName,
        [string]$Package,
        [string]$Label
    )

    if (Test-Command $CommandName) {
        Add-Summary Present $Label
        Write-Ok "$Label already present"
        return
    }
    if ($SkipPythonTools) {
        Add-Summary Manual "$Label (pip:$Package)"
        return
    }
    if (!(Test-Command "python")) {
        Add-Summary Manual "$Label requires Python: $Package"
        Write-WarnLine "Python unavailable: $Label"
        return
    }

    $ok = Invoke-Logged "pip install $Label" @("python", "-m", "pip", "install", "--upgrade", $Package)
    if ($ok) {
        Add-Summary Installed $Label
    } else {
        Add-Summary Failed "$Label (pip:$Package)"
    }
}

function Show-Summary {
    Write-Step "Summary"
    foreach ($key in @("Installed", "Present", "Failed", "Manual")) {
        Write-Host ""
        Write-Host "${key}:" -ForegroundColor Cyan
        if ($Summary[$key].Count -eq 0) {
            Write-Host "  none"
            continue
        }
        $Summary[$key] | Sort-Object -Unique | ForEach-Object { Write-Host "  - $_" }
    }

    Write-Host ""
    Write-Host "Log: $LogPath"
    Write-Host ""
    if ($UpdatePath -and -not $NoPathUpdate) {
        Write-Host "Open a new terminal after installation so PATH changes take effect."
    } else {
        Write-Host "Persistent PATH was not changed; rerun with -UpdatePath to opt in."
    }
    Write-Host "Validate with:"
    Write-Host "  python tool\detect_capabilities.py --dry-run"
    Write-Host "  python tool\scan_pipeline.py --help"
    Write-Host "  python tool\nmap_json_scan.py --help"
}

if ($Detect -and $DryRun) {
    Write-Error "Choose only one of -Detect or -DryRun."
    exit 2
}
if ($NoPathUpdate) {
    $UpdatePath = $false
}
if ($Detect) {
    Show-ProfileStatus
    exit 0
}
if ($DryRun) {
    Show-ProfileStatus -Plan
    exit 0
}

if ($UpdatePath) {
    New-Item -ItemType Directory -Force -Path $ToolsBin | Out-Null
    New-Item -ItemType Directory -Force -Path $GoBin | Out-Null
}
Set-Content -Path $LogPath -Encoding UTF8 -Value "Cybertest Windows install log $(Get-Date -Format o)"

Write-Step "Cybertest Windows installer"
Write-Info "Profile: $Profile"
Write-Info "Working directory: $ScriptRoot"
Write-Info "Log file: $LogPath"

if ($UpdatePath -and -not $NoPathUpdate) {
    Ensure-PathEntry $ToolsBin
    Ensure-PathEntry $GoBin
    Ensure-PathEntry (Join-Path $env:APPDATA "Python\Python312\Scripts")
    Ensure-PathEntry (Join-Path $env:APPDATA "Python\Python311\Scripts")
    Ensure-PathEntry (Join-Path $env:APPDATA "npm")
}

Install-ChocoIfRequested

Write-Step "Installing base runtime packages"
Install-WingetPackage "git" "Git.Git" "Git"
Install-WingetPackage "python" "Python.Python.3.12" "Python 3.12"
Install-WingetPackage "curl" "cURL.cURL" "curl"
if (Test-SelectedProfile @("web", "full")) {
    Install-WingetPackage "node" "OpenJS.NodeJS.LTS" "Node.js LTS"
    Install-WingetPackage "go" "GoLang.Go" "Go"
}
if ($Profile -eq "reverse") {
    Install-WingetPackage "java" "Microsoft.OpenJDK.17" "OpenJDK 17"
}
Update-CurrentPath

if (Test-SelectedProfile @("web", "full")) {
    Write-Step "Installing Web security binaries"
    Install-WingetPackage "nmap" "Insecure.Nmap" "Nmap"
    Install-WingetPackage "rustscan" "RustScan.RustScan" "Rustscan"
    Update-CurrentPath

    if ($InstallChocolatey) {
        Install-ChocoPackage "sqlmap" "sqlmap" "sqlmap"
        Install-ChocoPackage "zap-baseline.py" "owasp-zap" "OWASP ZAP"
    }

    Write-Step "Upgrading pip"
    if (Test-Command "python") {
        Invoke-Logged "python -m pip install --upgrade pip" @("python", "-m", "pip", "install", "--upgrade", "pip") | Out-Null
    }

    Write-Step "Installing Python-based Web tools"
    Install-PipTool "arjun" "arjun" "Arjun"
    Install-PipTool "wafw00f" "wafw00f" "wafw00f"
    Install-PipTool "sqlmap" "sqlmap" "sqlmap"

    Write-Step "Installing Go-based ProjectDiscovery and Web tools"
    Install-GoTool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" "subfinder"
    Install-GoTool "dnsx" "github.com/projectdiscovery/dnsx/cmd/dnsx@latest" "dnsx"
    Install-GoTool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx@latest" "httpx"
    Install-GoTool "tlsx" "github.com/projectdiscovery/tlsx/cmd/tlsx@latest" "tlsx"
    Install-GoTool "naabu" "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" "naabu"
    Install-GoTool "katana" "github.com/projectdiscovery/katana/cmd/katana@latest" "katana"
    Install-GoTool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" "nuclei"
    Install-GoTool "ffuf" "github.com/ffuf/ffuf/v2@latest" "ffuf"
    Install-GoTool "waybackurls" "github.com/tomnomnom/waybackurls@latest" "waybackurls"
    Install-GoTool "dalfox" "github.com/hahwul/dalfox/v2@latest" "dalfox"
    Install-GoTool "kr" "github.com/assetnote/kiterunner/cmd/kr@latest" "Kiterunner"
    if (!(Test-Command "kr") -and !(Test-Command "kiterunner")) {
        Add-Summary Manual "Kiterunner may need manual install from https://github.com/assetnote/kiterunner"
    }
}

if ($Profile -eq "full") {
    Write-Step "Installing full-profile security tools"
    Install-WingetPackage "hashcat" "Hashcat.Hashcat" "Hashcat"
    Install-WingetPackage "trivy" "AquaSecurity.Trivy" "Trivy"
    if ($InstallChocolatey) {
        Install-ChocoPackage "masscan" "masscan" "masscan"
    }
    Install-PipTool "semgrep" "semgrep" "Semgrep"
    Install-GoTool "gitleaks" "github.com/gitleaks/gitleaks/v8@latest" "gitleaks"
}

if ($Profile -eq "reverse") {
    Write-Step "Installing reverse-engineering tools"
    Install-PipTool "frida" "frida-tools" "Frida tools"
    foreach ($commandName in @("adb", "jadx", "apktool", "r2")) {
        if (!(Test-ProfileCommand $commandName)) {
            Add-Summary Manual "${commandName}: install from the official project or package manager"
        }
    }
}

Write-Step "Manual or environment-specific tools"
if (Test-SelectedProfile @("web", "full")) {
    if ($Profile -eq "full" -and !(Test-Command "masscan")) {
        Add-Summary Manual "masscan: Windows builds vary; install with Chocolatey (-InstallChocolatey) or from the official project"
    }
    if (!(Test-Command "whatweb")) {
        Add-Summary Manual "whatweb: requires Ruby environment on Windows; install manually if needed"
    }
    if (!(Test-Command "zap-baseline.py")) {
        Add-Summary Manual "OWASP ZAP baseline: install OWASP ZAP or use Docker-based ZAP on Windows"
    }
    Add-Summary Manual "FOFA API: set FOFA_EMAIL and FOFA_KEY when using tool\fofa_query.py"
    Add-Summary Manual "Burp MCP: install/enable Burp Suite MCP extension before using tool\burp_sse_mcp_bridge.js"
    Add-Summary Manual "Nuclei templates: run nuclei -update-templates after first nuclei install"
}

Write-Step "Post-install tool update"
if ((Test-SelectedProfile @("web", "full")) -and (Test-Command "nuclei")) {
    Invoke-Logged "nuclei template update" @("nuclei", "-update-templates") | Out-Null
}

Show-Summary

if ($Summary["Failed"].Count -gt 0) {
    exit 1
}
exit 0
