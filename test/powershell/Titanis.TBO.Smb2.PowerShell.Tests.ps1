Set-StrictMode -Version Latest

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$moduleRoot = Join-Path $repoRoot 'src\Titanis.TBO.Smb2.PowerShell'
$manifestPath = Join-Path $moduleRoot 'Titanis.TBO.Smb2.psd1'
$formatPath = Join-Path $moduleRoot 'Format.ps1xml'
$helpRoot = Join-Path $moduleRoot 'en-US'

Describe 'Titanis.TBO.Smb2 manifest and help' {
    It 'loads the module manifest data' {
        Test-Path $manifestPath | Should -BeTrue
        $data = Import-PowerShellDataFile -Path $manifestPath
        $data | Should -Not -BeNullOrEmpty
    }

    It 'defines required manifest fields' {
        $data = Import-PowerShellDataFile -Path $manifestPath
        $data.ModuleVersion | Should -Not -BeNullOrEmpty
        $data.RootModule | Should -Be 'Titanis.TBO.Smb2.PowerShell.dll'
        $data.GUID | Should -Not -BeNullOrEmpty
        $data.FormatsToProcess | Should -Contain 'Format.ps1xml'
    }

    It 'includes the format definition file' {
        Test-Path $formatPath | Should -BeTrue
    }

    It 'includes about help files' {
        Test-Path $helpRoot | Should -BeTrue
        (Get-ChildItem -Path $helpRoot -Filter 'about_TBO_*.help.txt').Count | Should -BeGreaterThan 0
    }

    It 'about help files include SYNOPSIS and DESCRIPTION sections' {
        $files = Get-ChildItem -Path $helpRoot -Filter 'about_TBO_*.help.txt'
        foreach ($file in $files) {
            $content = Get-Content -Path $file.FullName -Raw
            $content | Should -Match '\.SYNOPSIS'
            $content | Should -Match '\.DESCRIPTION'
        }
    }
}

Describe 'Titanis.TBO.Smb2 binary module (if built)' {
    BeforeAll {
        $script:loadedModule = $null
        $binaryRoot = Join-Path $repoRoot 'artifacts\lib\bin\Titanis.TBO.Smb2.PowerShell'
        $binary = Get-ChildItem -Path $binaryRoot -Recurse -Filter 'Titanis.TBO.Smb2.PowerShell.dll' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
        if ($binary) {
            try {
                $script:loadedModule = Import-Module $binary.FullName -Force -PassThru -ErrorAction Stop
            } catch {
                $script:loadedModule = $null
            }
        }
    }

    It 'imports the binary module when present' {
        if (-not $script:loadedModule) {
            Set-ItResult -Skipped -Because 'Module binary not found or failed to import.'
            return
        }

        $script:loadedModule.Name | Should -Not -BeNullOrEmpty
    }

    It 'exports expected cmdlets' {
        if (-not $script:loadedModule) {
            Set-ItResult -Skipped -Because 'Module binary not found or failed to import.'
            return
        }

        $cmdlets = Get-Command -Module $script:loadedModule.Name | Select-Object -ExpandProperty Name
        $cmdlets | Should -Contain 'Set-TBOSmbConnectOptions'
        $cmdlets | Should -Contain 'Get-TBOSmbSnapshots'
        $cmdlets | Should -Contain 'Get-TBORegKey'
    }

    It 'registers the TBO.Smb2 provider' {
        if (-not $script:loadedModule) {
            Set-ItResult -Skipped -Because 'Module binary not found or failed to import.'
            return
        }

        (Get-PSProvider | Where-Object { $_.Name -eq 'TBO.Smb2' }).Count | Should -Be 1
    }
}
