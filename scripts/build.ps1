# Build, test, and optionally publish IronTrace
param(
    [switch]$Publish
)

$ErrorActionPreference = 'Stop'
$dotnet = if (Test-Path 'C:\Program Files\dotnet\dotnet.exe') { 'C:\Program Files\dotnet\dotnet.exe' } else { 'dotnet' }
Set-Location $PSScriptRoot\..

& $dotnet restore IronTrace.slnx
& $dotnet build IronTrace.slnx -c Release --no-restore
& $dotnet test IronTrace.slnx -c Release --no-build

if ($Publish) {
    New-Item -ItemType Directory -Force -Path artifacts\publish\win-x64 | Out-Null
    & $dotnet publish src\IronTrace.App\IronTrace.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o artifacts\publish\win-x64
    Write-Host "Published to artifacts\publish\win-x64"
}
