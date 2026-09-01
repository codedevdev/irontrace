# Import pci.ids into the bundled reference database
param(
    [string]$InputPath = "tools/downloads/pci.ids",
    [string]$OutputPath = "data/reference/pci-reference.db"
)

$ErrorActionPreference = 'Stop'
$dotnet = if (Test-Path 'C:\Program Files\dotnet\dotnet.exe') { 'C:\Program Files\dotnet\dotnet.exe' } else { 'dotnet' }
Set-Location $PSScriptRoot\..

if (-not (Test-Path $InputPath)) {
    New-Item -ItemType Directory -Force -Path (Split-Path $InputPath) | Out-Null
    Invoke-WebRequest -Uri 'https://pci-ids.ucw.cz/v2.2/pci.ids' -OutFile $InputPath -UseBasicParsing
}

& $dotnet run --project tools/HardwareDbImporter -c Release -- --input $InputPath --output $OutputPath
Write-Host "Imported $InputPath -> $OutputPath"
