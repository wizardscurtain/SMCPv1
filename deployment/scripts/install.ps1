# SMCP Security Framework - Windows PowerShell Installation Script
# Usage: iwr -useb https://get.smcp-security.dev/install.ps1 | iex

param(
    [string]$InstallDir = "$env:USERPROFILE\.smcp-security",
    [string]$PythonMinVersion = "3.11",
    [switch]$Force
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Colors for output
function Write-Info { param($Message) Write-Host "[INFO] $Message" -ForegroundColor Blue }
function Write-Success { param($Message) Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
function Write-Warning { param($Message) Write-Host "[WARNING] $Message" -ForegroundColor Yellow }
function Write-Error { param($Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

function Test-Command {
    param($Command)
    try {
        Get-Command $Command -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Compare-Version {
    param(
        [string]$Version1,
        [string]$Version2
    )
    
    $v1 = [System.Version]$Version1
    $v2 = [System.Version]$Version2
    
    return $v1.CompareTo($v2)
}

function Test-Python {
    Write-Info "Checking Python installation..."
    
    if (-not (Test-Command "python")) {
        Write-Error "Python is not installed or not in PATH. Please install Python $PythonMinVersion or later."
        return $false
    }
    
    try {
        $pythonVersion = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"
        
        if ((Compare-Version $pythonVersion $PythonMinVersion) -lt 0) {
            Write-Error "Python $pythonVersion found, but Python $PythonMinVersion or later is required."
            return $false
        }
        
        Write-Success "Python $pythonVersion found"
        return $true
    } catch {
        Write-Error "Failed to check Python version: $_"
        return $false
    }
}

function Test-Pip {
    Write-Info "Checking pip installation..."
    
    if (-not (Test-Command "pip")) {
        Write-Warning "pip not found, trying to install..."
        try {
            python -m ensurepip --upgrade
            if (-not (Test-Command "pip")) {
                Write-Error "Failed to install pip"
                return $false
            }
        } catch {
            Write-Error "Failed to install pip: $_"
            return $false
        }
    }
    
    Write-Success "pip found"
    return $true
}

function Install-SMCP {
    Write-Info "Installing SMCP Security Framework..."
    
    # Create installation directory
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }
    
    Set-Location $InstallDir
    
    # Create virtual environment
    if (-not (Test-Path "venv")) {
        Write-Info "Creating virtual environment..."
        python -m venv venv
    }
    
    # Activate virtual environment
    & ".\venv\Scripts\Activate.ps1"
    
    # Upgrade pip
    python -m pip install --upgrade pip
    
    # Install SMCP Security
    Write-Info "Installing smcp-security package..."
    pip install smcp-security
    
    Write-Success "SMCP Security Framework installed successfully"
}

function New-Config {
    Write-Info "Creating default configuration..."
    
    $configFile = Join-Path $InstallDir "config.json"
    
    $config = @{
        security = @{
            validation_strictness = "standard"
            enable_mfa = $false
            enable_rbac = $true
            enable_rate_limiting = $true
            default_rate_limit = 100
            enable_encryption = $true
            enable_ai_immune = $true
            anomaly_threshold = 0.7
            enable_audit_logging = $true
            log_level = "INFO"
        }
        server = @{
            host = "0.0.0.0"
            port = 8080
            workers = 1
        }
        api = @{
            enable_cors = $true
            cors_origins = @("*")
            enable_docs = $true
        }
    }
    
    $config | ConvertTo-Json -Depth 10 | Set-Content $configFile
    
    Write-Success "Configuration file created at $configFile"
    return $configFile
}

function New-WrapperScript {
    param($ConfigFile)
    
    Write-Info "Creating wrapper script..."
    
    $wrapperScript = Join-Path $InstallDir "smcp-security.bat"
    
    $scriptContent = @"
@echo off
REM SMCP Security Framework Wrapper Script

set SMCP_DIR=$InstallDir
set CONFIG_FILE=$ConfigFile

REM Activate virtual environment
call "%SMCP_DIR%\venv\Scripts\activate.bat"

REM Run SMCP Security CLI
python -m smcp_security.cli %* --config "%CONFIG_FILE%"
"@
    
    $scriptContent | Set-Content $wrapperScript
    
    # Add to PATH
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($currentPath -notlike "*$InstallDir*") {
        $newPath = "$InstallDir;$currentPath"
        [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
        Write-Info "Added $InstallDir to user PATH"
    }
    
    Write-Success "Wrapper script created at $wrapperScript"
}

function Test-Installation {
    param($ConfigFile)
    
    Write-Info "Running self-test..."
    
    Set-Location $InstallDir
    & ".\venv\Scripts\Activate.ps1"
    
    try {
        python -m smcp_security.cli --self-test --config $ConfigFile
        Write-Success "Self-test passed"
        return $true
    } catch {
        Write-Error "Self-test failed: $_"
        return $false
    }
}

function Show-NextSteps {
    param($ConfigFile)
    
    Write-Success "SMCP Security Framework installation completed!"
    Write-Host ""
    Write-Host "Next steps:"
    Write-Host "  1. Restart your PowerShell session or refresh PATH"
    Write-Host "  2. Test the installation: smcp-security --check-system"
    Write-Host "  3. Start the security server: smcp-security --server"
    Write-Host "  4. View documentation: https://smcp-security.dev"
    Write-Host ""
    Write-Host "Configuration file: $ConfigFile"
    Write-Host "Installation directory: $InstallDir"
    Write-Host ""
    Write-Host "Quick commands:"
    Write-Host "  smcp-security --help          # Show help"
    Write-Host "  smcp-security --server        # Start API server"
    Write-Host "  smcp-security --scan          # Security scan"
    Write-Host "  smcp-security --report        # Generate report"
    Write-Host ""
}

function Remove-Installation {
    if (Test-Path $InstallDir) {
        Write-Warning "Cleaning up failed installation..."
        Remove-Item $InstallDir -Recurse -Force
    }
}

# Main installation function
function Install-SMCPSecurity {
    try {
        Write-Host ""
        Write-Host "🛡️  SMCP Security Framework Installer" -ForegroundColor Cyan
        Write-Host "====================================="
        Write-Host ""
        
        # Check if already installed
        if ((Test-Path $InstallDir) -and (-not $Force)) {
            Write-Warning "SMCP Security Framework appears to be already installed at $InstallDir"
            $response = Read-Host "Do you want to reinstall? (y/N)"
            if ($response -ne 'y' -and $response -ne 'Y') {
                Write-Info "Installation cancelled"
                return
            }
        }
        
        # Check prerequisites
        if (-not (Test-Python)) { throw "Python check failed" }
        if (-not (Test-Pip)) { throw "Pip check failed" }
        
        # Install SMCP Security
        Install-SMCP
        
        # Create configuration
        $configFile = New-Config
        
        # Create wrapper script
        New-WrapperScript $configFile
        
        # Run self-test
        if (-not (Test-Installation $configFile)) {
            Write-Warning "Self-test failed, but installation may still work"
        }
        
        # Show next steps
        Show-NextSteps $configFile
        
    } catch {
        Write-Error "Installation failed: $_"
        Remove-Installation
        exit 1
    }
}

# Check if running as administrator (not recommended)
if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Running as Administrator is not recommended. Consider running as a regular user."
    $response = Read-Host "Continue anyway? (y/N)"
    if ($response -ne 'y' -and $response -ne 'Y') {
        exit 1
    }
}

# Run main installation
Install-SMCPSecurity
