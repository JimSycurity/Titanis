# Titanis.TBO.Smb2 PowerShell Module

This module provides the TBO SMB2 PowerShell provider and cmdlets for backup-operator workflows.

## Quick Start

```powershell
Import-Module .\Titanis.TBO.Smb2.psd1 -Force

Set-TBOSmbConnectOptions `
  -ServerName corp1-web01.corp1.lab.home-labs.lol `
  -HostName corp1-web01.corp1.lab.home-labs.lol `
  -UserName psx_l_backupop `
  -UserDomain corp1.lab.home-labs.lol `
  -Password 'YourSecurePassword'

New-PSDrive -Name tbo -PSProvider 'TBO.Smb2' -Root '\\corp1-web01.corp1.lab.home-labs.lol\C$'
Set-Location tbo:\
Get-ChildItem
```

## Provider (TBO.Smb2)

The `TBO.Smb2` provider exposes SMB shares through a PowerShell drive. Connections are opened on-demand and use backup intent.

```powershell
# Use dynamic parameters on New-PSDrive to set credentials or SMB options.
New-PSDrive -Name tbo -PSProvider 'TBO.Smb2' -Root '\\corp1-web01.corp1.lab.home-labs.lol\C$' `
  -UserName psx_l_backupop -UserDomain corp1.lab.home-labs.lol -Password 'YourSecurePassword'

Set-Location tbo:\
Get-ChildItem
```

Use `Get-Help about_TBO_Smb2_Provider` for supported item types, dynamic parameters, and limitations (for example, content writing is not implemented).

## Cmdlets

### Connect-TBOSmbServer

Initializes the TBO.Smb2 provider for a server name. Connections are opened on-demand by later cmdlets.

```powershell
Connect-TBOSmbServer -ServerName corp1-web01.corp1.lab.home-labs.lol -UserName psx_l_backupop -UserDomain corp1.lab.home-labs.lol -Password 'YourSecurePassword'
```

### Set-TBOSmbConnectOptions

Sets connection defaults used by TBO cmdlets and the TBO.Smb2 provider. Supports the same dynamic parameters as `New-PSDrive` (credentials, SMB dialects, ciphers, signing, name resolution, and more).

```powershell
Set-TBOSmbConnectOptions -ServerName corp1-web01.corp1.lab.home-labs.lol -HostName corp1-web01.corp1.lab.home-labs.lol -UserName psx_l_backupop -UserDomain corp1.lab.home-labs.lol -Password 'YourSecurePassword'
```

### Copy-TBOSmbItem

Copies files between local paths and SMB paths using backup intent. Supports UNC or `tbo:\` paths. Use `-Force` (alias `-Overwrite`) to overwrite existing destinations.

```powershell
Copy-TBOSmbItem -Source tbo:\Windows\System32\config\SAM -Destination C:\Temp\SAM.bak
Copy-TBOSmbItem -Source C:\Temp\local.txt -Destination tbo:\Temp\local.txt -CreateDirectories
Copy-TBOSmbItem -Source C:\Temp\local.txt -Destination tbo:\Temp\local.txt -Force
```

### Get-TBOSmbSecurityDescriptor

Reads a security descriptor from a file or directory and returns a portable `Titanis.Winterop.Security.SecurityDescriptor` by default. Use `-AsSddl` or `-AsBytes` to change output format.

```powershell
$sd = Get-TBOSmbSecurityDescriptor -Path tbo:\Windows
$sddl = Get-TBOSmbSecurityDescriptor -Path \\corp1-web01\C$\Windows -AsSddl
```

### Set-TBOSmbSecurityDescriptor

Writes a security descriptor to a file or directory from a portable `SecurityDescriptor`.

```powershell
$sd = Get-TBOSmbSecurityDescriptor -Path tbo:\Windows
Set-TBOSmbSecurityDescriptor -Path tbo:\Windows -SecurityDescriptor $sd
```

### Remote Registry Cmdlets (MS-RRP)

Remote registry cmdlets use the winreg pipe with backup/restore semantics on every open.

#### Get-TBORegKey

Gets metadata for a remote registry key.

```powershell
Get-TBORegKey -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE
```

#### Get-TBORegChildItem

Lists subkeys and values beneath a remote registry key.

```powershell
Get-TBORegChildItem -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE
Get-TBORegChildItem -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE -IncludeValues -IncludeData
Get-TBORegChildItem -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE -IncludeSubkeys
```

#### New-TBORegKey

Creates a remote registry key.

```powershell
New-TBORegKey -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE\TBO
```

#### Remove-TBORegKey

Removes a remote registry key.

```powershell
Remove-TBORegKey -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE\TBO
```

#### Get-TBORegValue

Gets values from a remote registry key.

```powershell
Get-TBORegValue -ServerName corp1-web01.corp1.lab.home-labs.lol -Path 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Get-TBORegValue -ServerName corp1-web01.corp1.lab.home-labs.lol -Path 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName
```

#### Set-TBORegValue

Sets a remote registry value.

```powershell
Set-TBORegValue -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE\TBO -Name InstallId -Type String -Value "abc123"
Set-TBORegValue -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE\TBO -Name Flags -Type DwordLE -Value 1
```

#### Remove-TBORegValue

Removes a remote registry value.

```powershell
Remove-TBORegValue -ServerName corp1-web01.corp1.lab.home-labs.lol -Path HKLM\SOFTWARE\TBO -Name InstallId
```

## Local Logging

Set `TITANIS_TBO_LOG` to `1` or to a file path. When set to `1`, logs go to
`%TEMP%\Titanis.TBO.Smb2.log`.

## Build

```powershell
# Bump the version (major|minor|patch) before commit.
.\Build\Update-Version.ps1 -Bump patch

# Build with PSPublishModule.
.\Build\Build-Module.ps1 -Configuration Release
```
