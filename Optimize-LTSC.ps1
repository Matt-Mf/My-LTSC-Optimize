#Requires -RunAsAdministrator
#Requires -Version 5
#Requires -Module Dism
<#
	.SYNOPSIS
		Optimize-Offline is a Windows Image (WIM) optimization script designed for Windows 10 builds 1803-to-1903 64-bit architectures.
		This is a forked version of the above's script, it's called Optimize-LTSC and as the name suggests it's designed only for Enterprise LTSC SKU.

	.DESCRIPTION
		Primary focus' are the removal of unnecessary bloat, enhanced privacy, cleaner aesthetics, increased performance and a significantly better user experience.

	.PARAMETER SourcePath
		The path to a Windows 10 LTSC Installation ISO or install.wim

	.PARAMETER WindowsApps
		Select = Populates and outputs a Gridview list of all Appx Provisioned Packages for selective removal.
		All = Automatically removes all Appx Provisioned Packages found in the image.
		Whitelist = Automatically removes all Appx Provisioned Packages NOT found in the AppxWhiteList.xml file.

	.PARAMETER SystemApps
		Populates and outputs a Gridview list of all System Applications for selective removal.

	.PARAMETER Packages
		Populates and outputs a Gridview list of all Windows Capability Packages for selective removal.

	.PARAMETER Features
		Populates and outputs a Gridview list of all Windows Optional Features for selective disabling or enabling.

	.PARAMETER WindowsStore
		Integrates the Microsoft Windows Store and dependencies into the image.
		
	.PARAMETER Win7GUI
		Tweaks some of the default Windows 10 GUI elements to change them into Windows 7 Style:
		-replaces the new Windows 10 'Toast' Noficiations with classical 'Balloon' Notifications from Windows 7
		-replaces the new Windows 10 'Battery Flyout Power Indicator' with classical 'Battery Flyout Power Indicator' from Windows 7
		-replaces the new Windows 10 'Volume Control' with classical 'Volume Control' from Windows 7
		-enables the small Taskbar
		-enables seconds on the Taskbar Clock
		-disables the Windows 10 tabletish 'Notification Center'

	.PARAMETER Registry
		Integrates optimized registry values into the image.

	.PARAMETER Additional
		Integrates user specific content in the "Resources/Additional" directory into the image.

	.PARAMETER ISO
		Creates a new bootable Windows Installation Media ISO.
		Applicable when a Windows Installation Media ISO image is used as the source image.

	.EXAMPLE
		.\Optimize-LTSC.ps1 -SourcePath "D:\Win10 LTSC 2019\w10ui_updated_image.iso" -SystemApps -Packages -Features -Win7GUI -WindowsStore -Registry

	.NOTES
		Four System Applications that can be removed use a GUID instead of an identifiable name:
		1527c705-839a-4832-9118-54d4Bd6a0c89 = Microsoft.Windows.FilePicker
		c5e2524a-ea46-4f67-841f-6a9465d9d515 = Microsoft.Windows.FileExplorer
		E2A4F912-2574-4A75-9BB0-0D023378592B = Microsoft.Windows.AppResolverUX
		F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE = Microsoft.Windows.AddSuggestedFoldersToLibraryDialog

	.NOTES
		===========================================================================
		Created with: 	Notepad++
		Created on:   	7/2/2019
		Forked by:      Fumagalli Matteo
		Org. author:    DrEmpiricism
		Filename:     	Optimize-LTSC.ps1
		Version:        0.0.0.1
		===========================================================================
#>
[CmdletBinding(HelpUri = 'https://rentry.co/ltsc_optimize')]
Param
(
    [Parameter(Mandatory = $true,
        HelpMessage = 'The path to a Windows 10 Enterprise LTSC Installation ISO or install.wim')]
    [ValidateScript( {
            If ((Test-Path $(Resolve-Path -Path $_)) -and ($_ -ilike "*.iso")) { $_ }
            ElseIf ((Test-Path $(Resolve-Path -Path $_)) -and ($_ -ilike "*.wim")) { $_ }
            Else { Write-Warning ('Image path is invalid: "{0}"' -f $($_)); Break }
        })]
    [IO.FileInfo]$SourcePath,
    [Parameter(HelpMessage = 'Determines the method used for the removal of Appx Provisioned Packages.')]
    [ValidateSet('Select', 'All', 'Whitelist')]
    [string]$WindowsApps,
    [Parameter(HelpMessage = 'Populates and outputs a Gridview list of all System Applications for selective removal.')]
    [switch]$SystemApps,
    [Parameter(HelpMessage = 'Populates and outputs a Gridview list of all Windows Capability Packages for selective removal.')]
    [switch]$Packages,
    [Parameter(HelpMessage = 'Populates and outputs a Gridview list of all Windows Optional Features for selective disabling or enabling.')]
    [switch]$Features,
    [Parameter(HelpMessage = 'Integrates the Microsoft Windows Store and dependencies into the image.')]
    [switch]$WindowsStore,
    [Parameter(HelpMessage = 'Tweaks the default Windows 10 GUI to turn it into more Windows 7 Style.')]
    [switch]$Win7GUI,
    [Parameter(HelpMessage = 'Integrates optimized registry values into the image.')]
    [switch]$Registry,
    [Parameter(HelpMessage = 'Integrates user specific content in the "Resources/Additional" directory into the image.')]
    [switch]$Additional,
    [Parameter(HelpMessage = 'Creates a new bootable Windows Installation Media ISO.')]
    [switch]$ISO
)

#region Script Variables
$Host.UI.RawUI.BackgroundColor = 'Black'; Clear-Host
$ProgressPreference = 'SilentlyContinue'
$ScriptName = 'Optimize-LTSC'
$ScriptVersion = '0.0.0.1'
$AdditionalPath = Join-Path -Path $PSScriptRoot -ChildPath "Resources\Additional"
$StoreAppPath = Join-Path -Path $PSScriptRoot -ChildPath "Resources\WindowsStore"
$AppxWhiteListPath = Join-Path -Path $PSScriptRoot -ChildPath "Resources\AppxWhiteList.xml"
$AppAssocListPath = Join-Path -Path $PSScriptRoot -ChildPath "Resources\CustomAppAssociations.xml"
#endregion Script Variables

#region Helper Functions
Function Out-Log
{
    [CmdletBinding(DefaultParameterSetName = 'Info')]
    Param
    (
        [Parameter(ParameterSetName = 'Info')]
        [string]$Info,
        [Parameter(ParameterSetName = 'Error')]
        [string]$Error,
        [Parameter(ParameterSetName = 'Error',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    Process
    {
        $Timestamp = Get-Date -Format 's'
        $LogMutex = New-Object System.Threading.Mutex($false, 'SyncLogMutex')
        Switch ($PSBoundParameters.Keys)
        {
            'Info'
            {
                [void]$LogMutex.WaitOne()
                Add-Content -Path $ScriptLog -Value "$Timestamp [INFO]: $Info" -Encoding UTF8 -Force -ErrorAction SilentlyContinue
                [void]$LogMutex.ReleaseMutex()
                Write-Host $Info -ForegroundColor Cyan
            }
            'Error'
            {
                [void]$LogMutex.WaitOne()
                Add-Content -Path $ScriptLog -Value "$Timestamp [ERROR]: $Error" -Encoding UTF8 -Force -ErrorAction SilentlyContinue
                [void]$LogMutex.ReleaseMutex()
                Write-Host $Error -ForegroundColor Red
                If ($PSBoundParameters.ContainsKey('ErrorRecord'))
                {
                    $ExceptionMessage = '{0} ({1}: {2}:{3} char:{4})' -f $ErrorRecord.Exception.Message,
                    $ErrorRecord.FullyQualifiedErrorId,
                    $ErrorRecord.InvocationInfo.ScriptName,
                    $ErrorRecord.InvocationInfo.ScriptLineNumber,
                    $ErrorRecord.InvocationInfo.OffsetInLine
                    [void]$LogMutex.WaitOne()
                    Add-Content -Path $ScriptLog -Value "$Timestamp [ERROR]: $ExceptionMessage" -Encoding UTF8 -Force -ErrorAction SilentlyContinue
                    [void]$LogMutex.ReleaseMutex()
                    Write-Host $ExceptionMessage -ForegroundColor Red
                }
            }
        }
    }
}

Function Stop-Optimize
{
    [CmdletBinding()]
    Param ()

    $Host.UI.RawUI.WindowTitle = "Dismounting and discarding the image."
    Out-Log -Info "Dismounting and discarding the image."
    If (Get-OfflineHives -Process Test) { Get-OfflineHives -Process Unload }
    $QueryHives = Invoke-Expression -Command ('REG QUERY HKLM | FINDSTR Optimize-LTSC') -ErrorAction SilentlyContinue
    If ($QueryHives) { $QueryHives | ForEach-Object { Start-Process -FilePath REG -ArgumentList ('UNLOAD {0}' -f $($_)) -WindowStyle Hidden -Wait } }
    [void](Dismount-WindowsImage -Path $MountFolder -Discard -ErrorAction SilentlyContinue)
    [void](Clear-WindowsCorruptMountPoint)
    Add-Content -Path $ScriptLog -Value ""
    Add-Content -Path $ScriptLog -Value "***************************************************************************************************"
    Add-Content -Path $ScriptLog -Value "Optimizations failed at [$(Get-Date -UFormat "%d/%m/%Y %r")]"
    Add-Content -Path $ScriptLog -Value "***************************************************************************************************"
    [void]($SaveFolder = New-OfflineDirectory -Directory Save)
    If ($Error.Count -gt 0) { $Error.ToArray() | Out-File -FilePath (Join-Path -Path $WorkFolder -ChildPath ErrorRecord.log) -Force -ErrorAction SilentlyContinue }
    Remove-Container -Path $DISMLog
    Remove-Container -Path "$Env:SystemRoot\Logs\DISM\dism.log"
    [void](Get-ChildItem -Path $WorkFolder -Include *.txt, *.log -Recurse -ErrorAction SilentlyContinue | Compress-Archive -DestinationPath "$SaveFolder\OptimizeLogs.zip" -CompressionLevel Fastest -ErrorAction SilentlyContinue)
    Get-ChildItem -Path $PSScriptRoot -Filter "OptimizeLTSCTemp_*" -Directory -ErrorAction SilentlyContinue | Remove-Container
}

Function New-OfflineDirectory
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Scratch', 'Image', 'Work', 'InstallMount', 'BootMount', 'RecoveryMount', 'Save')]
        [string]$Directory
    )

    Switch ($Directory)
    {
        'Scratch'
        {
            $ScratchDirectory = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ParentDirectory -ChildPath 'ScratchOffline'))
            $ScratchDirectory = Get-Item -LiteralPath (Join-Path -Path $ParentDirectory -ChildPath $ScratchDirectory) -Force -ErrorAction SilentlyContinue
            $ScratchDirectory.FullName; Break
        }
        'Image'
        {
            $ImageDirectory = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ParentDirectory -ChildPath 'ImageOffline'))
            $ImageDirectory = Get-Item -LiteralPath (Join-Path -Path $ParentDirectory -ChildPath $ImageDirectory) -Force -ErrorAction SilentlyContinue
            $ImageDirectory.FullName; Break
        }
        'Work'
        {
            $WorkDirectory = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ParentDirectory -ChildPath 'WorkOffline'))
            $WorkDirectory = Get-Item -LiteralPath (Join-Path -Path $ParentDirectory -ChildPath $WorkDirectory) -Force -ErrorAction SilentlyContinue
            $WorkDirectory.FullName; Break
        }
        'InstallMount'
        {
            $InstallMountDirectory = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ParentDirectory -ChildPath 'MountInstallOffline'))
            $InstallMountDirectory = Get-Item -LiteralPath (Join-Path -Path $ParentDirectory -ChildPath $InstallMountDirectory) -Force -ErrorAction SilentlyContinue
            $InstallMountDirectory.FullName; Break
        }
        'BootMount'
        {
            $BootMountDirectory = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ParentDirectory -ChildPath 'MountBootOffline'))
            $BootMountDirectory = Get-Item -LiteralPath (Join-Path -Path $ParentDirectory -ChildPath $BootMountDirectory) -Force -ErrorAction SilentlyContinue
            $BootMountDirectory.FullName; Break
        }
        'RecoveryMount'
        {
            $RecoveryMountDirectory = [System.IO.Directory]::CreateDirectory((Join-Path -Path $ParentDirectory -ChildPath 'MountRecoveryOffline'))
            $RecoveryMountDirectory = Get-Item -LiteralPath (Join-Path -Path $ParentDirectory -ChildPath $RecoveryMountDirectory) -Force -ErrorAction SilentlyContinue
            $RecoveryMountDirectory.FullName; Break
        }
        'Save'
        {
            $SaveDirectory = [System.IO.Directory]::CreateDirectory((Join-Path -Path $PSScriptRoot -ChildPath Optimize-LTSC"_[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]"))
            $SaveDirectory = Get-Item -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath $SaveDirectory) -Force -ErrorAction SilentlyContinue
            $SaveDirectory.FullName; Break
        }
    }
}

Function Get-OfflineHives
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Load', 'Unload', 'Test')]
        [string]$Process
    )

    Switch ($Process)
    {
        'Load'
        {
            @(('HKLM\WIM_HKLM_SOFTWARE "{0}"' -f "$($MountFolder)\Windows\System32\config\software"), ('HKLM\WIM_HKLM_SYSTEM "{0}"' -f "$($MountFolder)\Windows\System32\config\system"), ('HKLM\WIM_HKCU "{0}"' -f "$($MountFolder)\Users\Default\NTUSER.DAT")) | ForEach-Object { Start-Process -FilePath REG -ArgumentList ("LOAD $($_)") -WindowStyle Hidden -Wait }; Break
        }
        'Unload'
        {
            [System.GC]::Collect()
            @('HKLM\WIM_HKLM_SOFTWARE', 'HKLM\WIM_HKLM_SYSTEM', 'HKLM\WIM_HKCU') | ForEach-Object { Start-Process -FilePath REG -ArgumentList ('UNLOAD {0}' -f $($_)) -WindowStyle Hidden -Wait }; Break
        }
        'Test'
        {
            @('HKLM:\WIM_HKLM_SOFTWARE', 'HKLM:\WIM_HKLM_SYSTEM', 'HKLM:\WIM_HKCU') | ForEach-Object { If (Test-Path -Path $($_)) { $true } }; Break
        }
    }
}

Function New-Container
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$Path
    )

    Process
    {
        If (!(Test-Path -LiteralPath $Path)) { [void](New-Item -Path $Path -ItemType Directory -Force -ErrorAction SilentlyContinue) }
    }
}

Function Remove-Container
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string[]]$Path
    )

    Process
    {
        ForEach ($Item In $Path) { If (Test-Path -LiteralPath $Item) { Remove-Item -LiteralPath $Item -Recurse -Force -ErrorAction SilentlyContinue } }
    }
}
#endregion Helper Functions

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Warning "Elevation is required to process optimizations. Relaunch $ScriptName as an administrator."
    Break
}

If (((Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Caption) -notlike "Microsoft Windows 10*") -and ((Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Caption) -notlike "Microsoft Windows Server 2016*"))
{
    Write-Warning "$ScriptName requires a Windows 10 or Windows Server 2016 environment."
    Break
}

If (Get-WindowsImage -Mounted)
{
    $Host.UI.RawUI.WindowTitle = "Performing clean-up of current mount path."
    Write-Host "Performing clean-up of current mount path." -ForegroundColor Cyan
    $MountPath = (Get-WindowsImage -Mounted).MountPath
    If (Get-OfflineHives -Process Test) { Get-OfflineHives -Process Unload }
    $QueryHives = Invoke-Expression -Command ('REG QUERY HKLM | FINDSTR Optimize-LTSC') -ErrorAction SilentlyContinue
    If ($QueryHives) { $QueryHives | ForEach-Object { Start-Process -FilePath REG -ArgumentList ('UNLOAD {0}' -f $($_)) -WindowStyle Hidden -Wait } }
    [void](Dismount-WindowsImage -Path $MountPath -Discard -ErrorAction SilentlyContinue)
    Remove-Variable MountPath; Clear-Host
}

Try
{
    Set-Location -Path $PSScriptRoot
    [void](Clear-WindowsCorruptMountPoint)
    Get-ChildItem -Path $PSScriptRoot -Filter "OptimizeLTSCTemp_*" -Directory -ErrorAction SilentlyContinue | Remove-Container
    $ParentDirectory = [System.IO.Directory]::CreateDirectory((Join-Path -Path $PSScriptRoot -ChildPath "OptimizeLTSCTemp_$(Get-Random)"))
    $ParentDirectory = Get-Item -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath $ParentDirectory) -Force
    [void]($MountFolder = New-OfflineDirectory -Directory InstallMount)
    [void]($ImageFolder = New-OfflineDirectory -Directory Image)
    [void]($WorkFolder = New-OfflineDirectory -Directory Work)
    [void]($ScratchFolder = New-OfflineDirectory -Directory Scratch)
    $Timer = New-Object System.Diagnostics.Stopwatch
}
Catch
{
    Write-Warning $($_.Exception.Message)
    Get-ChildItem -Path $PSScriptRoot -Filter "OptimizeLTSCTemp_*" -Directory -ErrorAction SilentlyContinue | Remove-Container
    Break
}

If ($SourcePath.Extension -eq '.ISO')
{
    $ISOMount = (Mount-DiskImage -ImagePath $($SourcePath.FullName) -StorageType ISO -PassThru | Get-Volume).DriveLetter + ':'
    If (!(Test-Path -Path "$($ISOMount)\sources\install.wim"))
    {
        Write-Warning ('"{0}" does not contain valid Windows Installation media.' -f $($SourcePath.Name))
        [void](Dismount-DiskImage -ImagePath $($SourcePath.FullName) -StorageType ISO)
        Remove-Container -Path $ParentDirectory
        Break
    }
    Else
    {
        $ISOName = [System.IO.Path]::GetFileNameWithoutExtension($SourcePath)
        $ISOMedia = Join-Path -Path $ParentDirectory -ChildPath $ISOName
        New-Container -Path $ISOMedia
        Try
        {
            Write-Host ('Exporting media from "{0}"' -f $($SourcePath.Name)) -ForegroundColor Cyan
            ForEach ($Item In Get-ChildItem -Path $ISOMount -Recurse)
            {
                $ISOExport = $ISOMedia + $Item.FullName.Replace($ISOMount, $null)
                Copy-Item -Path $($Item.FullName) -Destination $ISOExport
            }
            Get-ChildItem -Path "$($ISOMedia)\sources" -Include install.wim, boot.wim -Recurse | Move-Item -Destination $ImageFolder
            $InstallWim = Get-ChildItem -Path $ImageFolder -Filter install.wim | Select-Object -ExpandProperty FullName
            $BootWim = Get-ChildItem -Path $ImageFolder -Filter boot.wim | Select-Object -ExpandProperty FullName
            @($InstallWim, $BootWim) | ForEach-Object { Set-ItemProperty -Path $($_) -Name IsReadOnly -Value $false }
        }
        Catch
        {
            Write-Error $($_.Exception.Message)
            Remove-Container -Path $ParentDirectory
            Break
        }
        Finally
        {
            [void](Dismount-DiskImage -ImagePath $($SourcePath.FullName) -StorageType ISO)
        }
    }
}
ElseIf ($SourcePath.Extension -eq '.WIM')
{
    If ($SourcePath.Name -ne 'install.wim')
    {
        Write-Warning ('Image is not an install.wim: "{0}"' -f $($SourcePath.Name))
        Remove-Container -Path $ParentDirectory
        Break
    }
    Else
    {
        Try
        {
            Write-Host ('Copying WIM from "{0}"' -f $($SourcePath.DirectoryName)) -ForegroundColor Cyan
            Copy-Item -Path $($SourcePath.FullName) -Destination $ImageFolder
            $InstallWim = Get-ChildItem -Path $ImageFolder -Filter install.wim | Select-Object -ExpandProperty FullName
            Set-ItemProperty -Path $InstallWim -Name IsReadOnly -Value $false
        }
        Catch
        {
            Write-Error $($_.Exception.Message)
            Remove-Container -Path $ParentDirectory
            Break
        }
    }
}

If ((Get-WindowsImage -ImagePath $InstallWim).Count -gt 1)
{
    Do
    {
        $EditionList = Get-WindowsImage -ImagePath $InstallWim | Select-Object -Property @{ Label = 'Index'; Expression = { ($_.ImageIndex) } }, @{ Label = 'Name'; Expression = { ($_.ImageName) } }, @{ Label = 'Size (GB)'; Expression = { '{0:N2}' -f ($_.ImageSize / 1GB) } } | Out-GridView -Title "Select Windows 10 Edition." -OutputMode Single
        $ImageIndex = $EditionList.Index
    }
    While ($EditionList.Length -eq 0)
}
Else { $ImageIndex = 1 }

Try
{
    $WimImage = (Get-WindowsImage -ImagePath $InstallWim -Index $ImageIndex)
    $WimInfo = [PSCustomObject]@{
        Name     = $($WimImage.ImageName)
        Edition  = $($WimImage.EditionID)
        Version  = $($WimImage.Version)
        Build    = $($WimImage.Build.ToString())
        Language = $($WimImage.Languages)
    }
    If ($WimImage.Architecture -eq 9) { $WimInfo | Add-Member -MemberType NoteProperty -Name Architecture -Value $($WimImage.Architecture -replace '9', 'amd64') }
    ElseIf ($WimImage.Architecture -eq 0) { $WimInfo | Add-Member -MemberType NoteProperty -Name Architecture -Value $($WimImage.Architecture -replace '0', 'x86') }
}
Catch
{
    Write-Error $($_.Exception.Message)
    Remove-Container -Path $ParentDirectory
    Break
}

If ($WimInfo.Architecture -ne 'amd64')
{
    Write-Warning "$($ScriptName) currently only supports 64-bit architectures."
    Remove-Container -Path $ParentDirectory
    Break
}

If ($WimInfo.Edition.Contains('Server'))
{
    Write-Warning "Unsupported Image Edition: [$($WimInfo.Edition)]"
    Remove-Container -Path $ParentDirectory
    Break
}

If ($WimInfo.Version.StartsWith(10))
{
    If ($WimInfo.Build -lt '17134' -or $WimInfo.Build -gt '18362')
    {
        Write-Warning "Unsupported Image Build: [$($WimInfo.Build)]"
        Remove-Container -Path $ParentDirectory
        Break
    }
}
Else
{
    Write-Warning "Unsupported Image Version: [$($WimInfo.Version)]"
    Remove-Container -Path $ParentDirectory
    Break
}

If ($WimInfo.Name -like "*LTSC*")
{
    $IsLTSC = $true
    If ($WindowsApps) { Remove-Variable WindowsApps }
}
Else
{
    If ($WindowsStore.IsPresent) { $WindowsStore = $false }
}

Try
{
    Remove-Container -Path "$Env:SystemRoot\Logs\DISM\dism.log"
    $DISMLog = Join-Path -Path $WorkFolder -ChildPath DISM.log
    $ScriptLog = Join-Path -Path $WorkFolder -ChildPath Optimize-LTSC.log
    $AppxPackageList = Join-Path -Path $WorkFolder -ChildPath AppxProvisionedPackages.txt
    $WindowsFeatureList = Join-Path -Path $WorkFolder -ChildPath WindowsFeatures.txt
    $IntegratedPackageList = Join-Path -Path $WorkFolder -ChildPath IntegratedPackages.txt
    $CapabilityPackageList = Join-Path -Path $WorkFolder -ChildPath CapabilityPackages.txt
    $InjectedDriverList = Join-Path -Path $WorkFolder -ChildPath InjectedDrivers.txt
    Add-Content -Path $ScriptLog -Value "***************************************************************************************************"
    Add-Content -Path $ScriptLog -Value ""
    Add-Content -Path $ScriptLog -Value "$ScriptName v$ScriptVersion starting on [$(Get-Date -UFormat "%d/%m/%Y %r")]"
    Add-Content -Path $ScriptLog -Value ""
    Add-Content -Path $ScriptLog -Value "***************************************************************************************************"
    Add-Content -Path $ScriptLog -Value "Optimizing image: $($WimInfo.Name)"
    Add-Content -Path $ScriptLog -Value "***************************************************************************************************"
    Add-Content -Path $ScriptLog -Value ""
    Out-Log -Info "Supported Image Build: [$($WimInfo.Build)]"
    $Timer.Start(); Start-Sleep 3; $Error.Clear()
    Out-Log -Info "Mounting $($WimInfo.Name)"
    $MountWindowsImage = @{
        ImagePath        = $InstallWim
        Index            = $ImageIndex
        Path             = $MountFolder
        ScratchDirectory = $ScratchFolder
        LogPath          = $DISMLog
        ErrorAction      = 'Stop'
    }
    [void](Mount-WindowsImage @MountWindowsImage)
}
Catch
{
    Out-Log -Error ('Failed to Mount {0}' -f $($WimInfo.Name)) -ErrorRecord $Error[0]
    Stop-Optimize; Throw
}

If ((Repair-WindowsImage -Path $MountFolder -CheckHealth).ImageHealthState -eq 'Healthy')
{
    Out-Log -Info "Pre-Optimization Image Health State: [Healthy]"
}
Else
{
    Out-Log -Error "The image has been flagged for corruption. Further servicing is required before the image can be optimized."
    Stop-Optimize; Throw
}

If ((Test-Path -Path "Variable:\WindowsApps") -and (Get-AppxProvisionedPackage -Path $MountFolder).Count -gt 0)
{
    Clear-Host
    $Host.UI.RawUI.WindowTitle = "Removing Appx Provisioned Packages."
    $RemovedAppxPackages = [System.Collections.ArrayList]@()
    $AppxPackages = Get-AppxProvisionedPackage -Path $MountFolder
    Try
    {
        Switch ($WindowsApps)
        {
            'Select'
            {
                $SelectedAppxPackages = [System.Collections.ArrayList]@()
                Get-AppxProvisionedPackage -Path $MountFolder | ForEach-Object {
                    $AppxPackages = [PSCustomObject]@{
                        DisplayName = $_.DisplayName
                        PackageName = $_.PackageName
                    }
                    [void]$SelectedAppxPackages.Add($AppxPackages)
                }
                $SelectedAppxPackages = $SelectedAppxPackages | Out-GridView -Title "Remove Appx Provisioned Packages." -PassThru
                $PackageName = $SelectedAppxPackages.PackageName
                If ($PackageName)
                {
                    $PackageName | ForEach-Object {
                        Out-Log -Info ('Removing Appx Provisioned Package: {0}' -f $($_.Split('_')[0]))
                        $RemoveSelectAppx = @{
                            Path             = $MountFolder
                            PackageName      = $($_)
                            ScratchDirectory = $ScratchFolder
                            LogPath          = $DISMLog
                            ErrorAction      = 'Stop'
                        }
                        [void](Remove-AppxProvisionedPackage @RemoveSelectAppx)
                        [void]$RemovedAppxPackages.Add($_.Split('_')[0])
                    }
                    Remove-Variable PackageName
                }; Break
            }
            'All'
            {
                Get-AppxProvisionedPackage -Path $MountFolder | ForEach-Object {
                    Out-Log -Info ('Removing Appx Provisioned Package: {0}' -f $($_.DisplayName))
                    $ParamsAppx = @{
                        Path             = $MountFolder
                        PackageName      = $($_.PackageName)
                        ScratchDirectory = $ScratchFolder
                        LogPath          = $DISMLog
                        ErrorAction      = 'Stop'
                    }
                    [void](Remove-AppxProvisionedPackage @ParamsAppx)
                    [void]$RemovedAppxPackages.Add($_.DisplayName)
                }; Break
            }
            'Whitelist'
            {
                If (Test-Path -Path $AppxWhitelistPath)
                {
                    [XML]$Whitelist = Get-Content -Path $AppxWhitelistPath
                    Get-AppxProvisionedPackage -Path $MountFolder | ForEach-Object {
                        If ($_.DisplayName -notin $Whitelist.Appx.DisplayName)
                        {
                            Out-Log -Info ('Removing Appx Provisioned Package: {0}' -f $($_.DisplayName))
                            $ParamsAppx = @{
                                Path             = $MountFolder
                                PackageName      = $($_.PackageName)
                                ScratchDirectory = $ScratchFolder
                                LogPath          = $DISMLog
                                ErrorAction      = 'Stop'
                            }
                            [void](Remove-AppxProvisionedPackage @ParamsAppx)
                            [void]$RemovedAppxPackages.Add($_.DisplayName)
                        }
                    }
                }; Break
            }
        }
        Clear-Host
    }
    Catch
    {
        Out-Log -Error "Failed to Remove Appx Provisioned Packages." -ErrorRecord $Error[0]
        Stop-Optimize; Throw
    }
    If ((Get-AppxProvisionedPackage -Path $MountFolder).Count -eq 0)
    {
        $Host.UI.RawUI.WindowTitle = "Removing Windows App Program Files."
        Out-Log -Info "Removing Windows App Program Files."
        $WindowsAppsPath = "$MountFolder\Program Files\WindowsApps"
        Start-Process -FilePath TAKEOWN -ArgumentList ('/F "{0}" /R' -f $WindowsAppsPath) -WindowStyle Hidden -Wait
        Start-Process -FilePath ICACLS -ArgumentList ('"{0}" /INHERITANCE:E /GRANT "{1}":(OI)(CI)F /T /C' -f $WindowsAppsPath, $Env:USERNAME) -WindowStyle Hidden -Wait
        Get-ChildItem -Path $WindowsAppsPath -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Start-Process -FilePath ICACLS -ArgumentList ('"{0}" /SETOWNER *S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' -f $WindowsAppsPath) -WindowStyle Hidden -Wait
        Start-Process -FilePath ICACLS -ArgumentList ('"{0}" /INHERITANCE:R /REMOVE "{1}"' -f $WindowsAppsPath, $Env:USERNAME) -WindowStyle Hidden -Wait
        Remove-Variable WindowsAppsPath
    }
    Else
    {
        Get-AppxProvisionedPackage -Path $MountFolder | Select-Object -ExpandProperty DisplayName | Out-File -FilePath $AppxPackageList -Append -ErrorAction SilentlyContinue
    }
}

If (Test-Path -Path $AppAssocListPath)
{
    $Host.UI.RawUI.WindowTitle = "Importing Custom App Associations."
    Out-Log -Info "Importing Custom App Associations."
    Start-Process -FilePath DISM -ArgumentList ('/Image:"{0}" /Import-DefaultAppAssociations:"{1}"' -f $MountFolder, $AppAssocListPath) -WindowStyle Hidden -Wait
}

If ($SystemApps.IsPresent)
{
    Clear-Host
    $Host.UI.RawUI.WindowTitle = "Removing System Applications."
    Write-Warning "Do NOT remove any System Application if you are unsure of its impact on a live installation."
    Start-Sleep 5
    $RemovedSystemApps = [System.Collections.ArrayList]@()
    $InboxAppsKey = "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications"
    Get-OfflineHives -Process Load
    $InboxAppPackages = Get-ChildItem -Path $InboxAppsKey -Name -ErrorAction SilentlyContinue | Select-Object -Property @{ Label = 'Name'; Expression = { ($_.Split('_')[0]) } }, @{ Label = 'Package'; Expression = { ($_) } } | Out-GridView -Title "Remove System Applications." -PassThru
    $InboxAppsList = $InboxAppPackages.Package
    If ($InboxAppsList)
    {
        Try
        {
            Clear-Host
            $InboxAppsList | ForEach-Object {
                $FullKeyPath = Join-Path -Path $InboxAppsKey -ChildPath $($_)
                $FullKeyPath = $FullKeyPath -replace 'HKLM:', 'HKLM'
                Out-Log -Info "Removing System Application: $($_.Split('_')[0])"
                Start-Process -FilePath REG -ArgumentList ('DELETE "{0}" /F' -f $FullKeyPath) -WindowStyle Hidden -Wait -ErrorAction Stop
                [void]$RemovedSystemApps.Add($_.Split('_')[0])
                Start-Sleep 2
            }
        }
        Catch
        {
            Out-Log -Error "Failed to Remove System Applications." -ErrorRecord $Error[0]
            Stop-Optimize; Throw
        }
    }
    Get-OfflineHives -Process Unload; Clear-Host
}

If ($Packages.IsPresent)
{
    Clear-Host
    $CapabilityPackages = [System.Collections.ArrayList]@()
    $Host.UI.RawUI.WindowTitle = "Removing Windows Capability Packages."
    Get-WindowsCapability -Path $MountFolder | Where-Object -Property State -EQ Installed | ForEach-Object {
        $Capabilities = [PSCustomObject]@{
            PackageName  = $_.Name
            PackageState = $_.State
        }
        [void]$CapabilityPackages.Add($Capabilities)
    }
    $CapabilityPackages = $CapabilityPackages | Out-GridView -Title "Remove Windows Capability Packages." -PassThru
    $PackageName = $CapabilityPackages.PackageName
    If ($PackageName)
    {
        Try
        {
            $PackageName | ForEach-Object {
                Out-Log -Info ('Removing Windows Capability Package: {0}' -f $($_.Split('~')[0]))
                $ParamsCapability = @{
                    Path             = $MountFolder
                    Name             = $($_)
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    ErrorAction      = 'Stop'
                }
                [void](Remove-WindowsCapability @ParamsCapability)
            }
            Get-WindowsCapability -Path $MountFolder | Where-Object -Property State -EQ Installed | Select-Object -Property Name, State | Out-File -FilePath $CapabilityPackageList -ErrorAction SilentlyContinue
        }
        Catch
        {
            Out-Log -Error "Failed to Remove Windows Capability Packages." -ErrorRecord $Error[0]
            Stop-Optimize; Throw
        }
    }
    Remove-Variable PackageName; Clear-Host
}

If ($RemovedSystemApps -contains 'Microsoft.LockApp')
{
    $Host.UI.RawUI.WindowTitle = "Removing Lock Screen Remnants."
    Out-Log -Info "Disabling the Lock Screen and its Remnants."
    Get-OfflineHives -Process Load
	New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Personalization"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings"
	Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Value 1 -Type DWord -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData" -Name "AllowLockScreen" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" -Value 0 -Type DWord -ErrorAction SilentlyContinue
}

If ($RemovedAppxPackages -like "*Xbox*" -or $RemovedSystemApps -contains 'Microsoft.XboxGameCallableUI')
{
    $Host.UI.RawUI.WindowTitle = "Removing Xbox Remnants."
    Out-Log -Info "Disabling Xbox Services and Drivers."
    Get-OfflineHives -Process Load
    @("xbgm", "XblAuthManager", "XblGameSave", "xboxgip", "XboxGipSvc", "XboxNetApiSvc") | ForEach-Object {
        If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$($_)") { Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\$($_)" -Name "Start" -Value 4 -Type DWord -ErrorAction SilentlyContinue }
    }
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\GameDVR"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\GameBar"
    New-Container -Path "HKLM:\WIM_HKCU\System\GameConfigStore"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AudioCaptureEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "CursorCaptureEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\GameBar" -Name "UseNexusForGameBarEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Value 2 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Value 2 -Type DWord -ErrorAction SilentlyContinue
    If ($Visibility)
    {
        If ($WimInfo.Build -lt '17763') { $Visibility += ';gaming-gamebar;gaming-gamedvr;gaming-broadcasting;gaming-gamemode;gaming-xboxnetworking;quietmomentsgame;gaming-trueplay' }
        Else { $Visibility += ';gaming-gamebar;gaming-gamedvr;gaming-broadcasting;gaming-gamemode;gaming-xboxnetworking;quietmomentsgame' }
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "SettingsPageVisibility" -Value $Visibility -Type String -ErrorAction SilentlyContinue
    }
    Get-OfflineHives -Process Unload
}

If ((Get-WindowsOptionalFeature -Path $MountFolder -FeatureName *SMB1*).State -eq 'Enabled')
{
    Try
    {
        $Host.UI.RawUI.WindowTitle = "Disabling the SMBv1 Protocol Windows Feature."
        Out-Log -Info "Disabling the SMBv1 Protocol Windows Feature."
        [void](Get-WindowsOptionalFeature -Path $MountFolder | Where-Object FeatureName -Like *SMB1* | Disable-WindowsOptionalFeature -Path $MountFolder -ScratchDirectory $ScratchFolder -LogPath $DISMLog -ErrorAction Stop)
        Get-WindowsOptionalFeature -Path $MountFolder | Select-Object -Property FeatureName, State | Sort-Object -Property State -Descending | Out-File -FilePath $WindowsFeatureList -Force -ErrorAction SilentlyContinue
    }
    Catch
    {
        Out-Log -Error "Failed to Disable the SMBv1 Protocol Windows Feature." -ErrorRecord $Error[0]
        Stop-Optimize; Throw
    }
}

If ($Features.IsPresent)
{
    Clear-Host
    $OptionalFeatures = [System.Collections.ArrayList]@()
    $Host.UI.RawUI.WindowTitle = "Disabling Windows Features."
    Get-WindowsOptionalFeature -Path $MountFolder | Where-Object State -EQ Enabled | ForEach-Object {
        $EnabledFeatures = [PSCustomObject]@{
            FeatureName = $_.FeatureName
            State       = $_.State
        }
        [void]$OptionalFeatures.Add($EnabledFeatures)
    }
    $OptionalFeatures = $OptionalFeatures | Out-GridView -Title "Disable Windows Features." -PassThru
    $FeatureName = $OptionalFeatures.FeatureName
    If ($FeatureName)
    {
        Try
        {
            $FeatureName | ForEach-Object {
                Out-Log -Info "Disabling Windows Feature: $($_)"
                $ParamsFeature = @{
                    Path             = $MountFolder
                    FeatureName      = $($_)
                    ScratchDirectory = $ScratchFolder
                    LogPath          = $DISMLog
                    ErrorAction      = 'Stop'
                }
                [void](Disable-WindowsOptionalFeature @ParamsFeature)
            }
            Remove-Variable FeatureName
        }
        Catch
        {
            Out-Log -Error "Failed to Disable Windows Features." -ErrorRecord $Error[0]
            Stop-Optimize; Throw
        }
        Clear-Host
        $OptionalFeatures = [System.Collections.ArrayList]@()
        $Host.UI.RawUI.WindowTitle = "Enabling Windows Features."
        Get-WindowsOptionalFeature -Path $MountFolder | Where-Object FeatureName -NotLike *SMB1* | Where-Object FeatureName -NE Windows-Defender-Default-Definitions | Where-Object State -EQ Disabled | ForEach-Object {
            $DisabledFeatures = [PSCustomObject]@{
                FeatureName = $_.FeatureName
                State       = $_.State
            }
            [void]$OptionalFeatures.Add($DisabledFeatures)
        }
        $OptionalFeatures = $OptionalFeatures | Out-GridView -Title "Enable Windows Features." -PassThru
        $FeatureName = $OptionalFeatures.FeatureName
        If ($FeatureName)
        {
            Try
            {
                $FeatureName | ForEach-Object {
                    Out-Log -Info "Enabling Windows Feature: $($_)"
                    $EnableFeature = @{
                        Path             = $MountFolder
                        FeatureName      = $($_)
                        All              = $true
                        LimitAccess      = $true
                        NoRestart        = $true
                        ScratchDirectory = $ScratchFolder
                        LogPath          = $DISMLog
                        ErrorAction      = 'Stop'
                    }
                    [void](Enable-WindowsOptionalFeature @EnableFeature)
                }; Clear-Host
            }
            Catch
            {
                Out-Log -Error "Failed to Enable Windows Features." -ErrorRecord $Error[0]
                Stop-Optimize; Throw
            }
        }
    }
    Get-WindowsOptionalFeature -Path $MountFolder | Select-Object -Property FeatureName, State | Sort-Object -Property State -Descending | Out-File -FilePath $WindowsFeatureList -Force -ErrorAction SilentlyContinue
}

If ($WindowsStore.IsPresent -and (Test-Path -Path $StoreAppPath -Filter Microsoft.WindowsStore*.appxbundle))
{
    $Host.UI.RawUI.WindowTitle = "Integrating the Microsoft Store Application Packages."
    Out-Log -Info "Integrating the Microsoft Store Application Packages."
    Try
    {
        $StoreBundle = Get-ChildItem -Path $StoreAppPath -Filter Microsoft.WindowsStore*.appxbundle | Select-Object -ExpandProperty FullName
        $PurchaseBundle = Get-ChildItem -Path $StoreAppPath -Filter Microsoft.StorePurchaseApp*.appxbundle | Select-Object -ExpandProperty FullName
        $XboxBundle = Get-ChildItem -Path $StoreAppPath -Filter Microsoft.XboxIdentityProvider*.appxbundle | Select-Object -ExpandProperty FullName
        $InstallerBundle = Get-ChildItem -Path $StoreAppPath -Filter Microsoft.DesktopAppInstaller*.appxbundle | Select-Object -ExpandProperty FullName
        $StoreLicense = Get-ChildItem -Path $StoreAppPath -Filter Microsoft.WindowsStore*.xml | Select-Object -ExpandProperty FullName
        $PurchaseLicense = Get-ChildItem -Path $StoreAppPath -Filter Microsoft.StorePurchaseApp*.xml | Select-Object -ExpandProperty FullName
        $IdentityLicense = Get-ChildItem -Path $StoreAppPath -Filter Microsoft.XboxIdentityProvider*.xml | Select-Object -ExpandProperty FullName
        $InstallerLicense = Get-ChildItem -Path $StoreAppPath -Filter Microsoft.DesktopAppInstaller*.xml | Select-Object -ExpandProperty FullName
        $DepAppx = @()
        $DepAppx += Get-ChildItem -Path $StoreAppPath -Filter Microsoft.VCLibs*.appx | Select-Object -ExpandProperty FullName
        $DepAppx += Get-ChildItem -Path $StoreAppPath -Filter *Native.Framework*.appx | Select-Object -ExpandProperty FullName
        $DepAppx += Get-ChildItem -Path $StoreAppPath -Filter *Native.Runtime*.appx | Select-Object -ExpandProperty FullName
        Get-OfflineHives -Process Load
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Get-OfflineHives -Process Unload
        $StorePackage = @{
            Path                  = $MountFolder
            PackagePath           = $StoreBundle
            DependencyPackagePath = $DepAppx
            LicensePath           = $StoreLicense
            ScratchDirectory      = $ScratchFolder
            LogPath               = $DISMLog
            ErrorAction           = 'Stop'
        }
        [void](Add-AppxProvisionedPackage @StorePackage)
        $PurchasePackage = @{
            Path                  = $MountFolder
            PackagePath           = $PurchaseBundle
            DependencyPackagePath = $DepAppx
            LicensePath           = $PurchaseLicense
            ScratchDirectory      = $ScratchFolder
            LogPath               = $DISMLog
            ErrorAction           = 'Stop'
        }
        [void](Add-AppxProvisionedPackage @PurchasePackage)
        $IdentityPackage = @{
            Path                  = $MountFolder
            PackagePath           = $XboxBundle
            DependencyPackagePath = $DepAppx
            LicensePath           = $IdentityLicense
            ScratchDirectory      = $ScratchFolder
            LogPath               = $DISMLog
            ErrorAction           = 'Stop'
        }
        [void](Add-AppxProvisionedPackage @IdentityPackage)
        $DepAppx = @()
        $DepAppx += Get-ChildItem -Path $StoreAppPath -Filter *Native.Runtime*.appx | Select-Object -ExpandProperty FullName
        $InstallerPackage = @{
            Path                  = $MountFolder
            PackagePath           = $InstallerBundle
            DependencyPackagePath = $DepAppx
            LicensePath           = $InstallerLicense
            ScratchDirectory      = $ScratchFolder
            LogPath               = $DISMLog
            ErrorAction           = 'Stop'
        }
        [void](Add-AppxProvisionedPackage @InstallerPackage)
        Get-AppxProvisionedPackage -Path $MountFolder | Select-Object -ExpandProperty DisplayName | Out-File -FilePath $AppxPackageList -Append -ErrorAction SilentlyContinue
    }
    Catch
    {
        Out-Log -Error "Failed to Integrate the Microsoft Store Application Packages." -ErrorRecord $Error[0]
        Stop-Optimize; Throw
    }
}

If ($Win7GUI.IsPresent)
{
    $Host.UI.RawUI.WindowTitle = "Tweaking the Windows 10 GUI."
    Out-Log -Info "Changing the Windows 10 GUI elements to a Windows 7 Style ones."
    Get-OfflineHives -Process Load
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
	New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer"
	New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer"
	New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC"
	New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Value 0 -Type DWord -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Value 1 -Type DWord -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSecondsInSystemClock" -Value 1 -Type DWord -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "EnableLegacyBalloonNotifications" -Value 1 -Type DWord -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Value 1 -Type DWord -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC" -Name "EnableMtcUvc" -Value 0 -Type DWord -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" -Name "UseWin32BatteryFlyout" -Value 1 -Type DWord -ErrorAction SilentlyContinue
	Get-OfflineHives -Process Unload
}

#region Registry Optimizations.
If ($Registry.IsPresent)
{
    $Host.UI.RawUI.WindowTitle = "Applying Optimizations to the Offline Registry Hives."
    Out-Log -Info "Applying Optimizations to the Offline Registry Hives."
    $RegLog = Join-Path -Path $WorkFolder -ChildPath Registry-Optimizations.log
	Get-OfflineHives -Process Load
    #****************************************************************
    Write-Output "Disabling Cortana and Search Bar Web Connectivity." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\InputPersonalization"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Personalization\Settings"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Speech_OneCore\Preferences"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\OOBE"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CanCortanaBeEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaInAmbientMode" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "HistoryViewEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "DeviceHistoryEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "HasAboveLockTips" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "AllowSearchToUseLocation" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "AcceptedPrivacyPolicy" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -Name "VoiceActivationEnableAboveLockscreen" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -Name "DisableVoice" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling Cortana Outgoing Network Traffic." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
    $FirewallRule = @{
        Path        = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        Name        = "Block Cortana ActionUriServer.exe"
        Value       = "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\ActionUriServer.exe|Name=Block Cortana ActionUriServer.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|"
        Type        = 'String'
        ErrorAction = 'SilentlyContinue'
    }
    Set-ItemProperty @FirewallRule
    $FirewallRule = @{
        Path        = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        Name        = "Block Cortana PlacesServer.exe"
        Value       = "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\PlacesServer.exe|Name=Block Cortana PlacesServer.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|"
        Type        = 'String'
        ErrorAction = 'SilentlyContinue'
    }
    Set-ItemProperty @FirewallRule
    $FirewallRule = @{
        Path        = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        Name        = "Block Cortana RemindersServer.exe"
        Value       = "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\RemindersServer.exe|Name=Block Cortana RemindersServer.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|"
        Type        = 'String'
        ErrorAction = 'SilentlyContinue'
    }
    Set-ItemProperty @FirewallRule
    $FirewallRule = @{
        Path        = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        Name        = "Block Cortana RemindersServer.exe"
        Value       = "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\RemindersServer.exe|Name=Block Cortana RemindersServer.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|"
        Type        = 'String'
        ErrorAction = 'SilentlyContinue'
    }
    Set-ItemProperty @FirewallRule
    $FirewallRule = @{
        Path        = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        Name        = "Block Cortana RemindersShareTargetApp.exe"
        Value       = "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\RemindersShareTargetApp.exe|Name=Block Cortana RemindersShareTargetApp.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|"
        Type        = 'String'
        ErrorAction = 'SilentlyContinue'
    }
    Set-ItemProperty @FirewallRule
    $FirewallRule = @{
        Path        = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        Name        = "Block Cortana SearchUI.exe"
        Value       = "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe|Name=Block Cortana SearchUI.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|"
        Type        = 'String'
        ErrorAction = 'SilentlyContinue'
    }
    Set-ItemProperty @FirewallRule
    $FirewallRule = @{
        Path        = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        Name        = "Block Cortana Package"
        Value       = "v2.26|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|Name=Block Cortana Package|Desc=Block Cortana Outbound UDP/TCP Traffic|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|Platform=2:6:2|Platform2=GTEQ|"
        Type        = 'String'
        ErrorAction = 'SilentlyContinue'
    }
    Set-ItemProperty @FirewallRule
    #****************************************************************
    Write-Output "Disabling System Telemetry and Data Collecting." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat"
    New-Container -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\WOW"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\AppV\CEIP"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\SQMClient\Windows"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\TabletPC"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe"
    New-Container -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableEngine" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisablePCA" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "SbEnable" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "VDMDisallowed" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\WOW" -Name "DisallowedPolicyDefault" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" -Name "value" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -Name "Debugger" -Value "%windir%\System32\taskkill.exe" -Type String -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" -Name "Debugger" -Value "%windir%\System32\taskkill.exe" -Type String -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" -Name "Start" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Blocking Telemetry IPs in Windows Firewall." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
    $FirewallRule = @{
        Path        = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        Name        = "Block Windows Telemetry IPs"
        Value       = "v2.28|Action=Block|Active=TRUE|Dir=Out|RA4=13.66.56.243|RA4=13.68.31.193|RA4=13.68.82.8|RA4=13.76.218.117|RA4=13.76.219.191|RA4=13.76.219.210|RA4=13.78.130.220|RA4=13.78.232.226|RA4=13.78.233.133|RA4=13.92.194.212|RA4=20.44.86.43|RA4=23.97.61.137|RA4=23.97.209.97|RA4=23.99.10.11|RA4=23.99.49.121|RA4=23.99.109.44|RA4=23.99.109.64|RA4=23.99.116.116|RA4=23.99.121.207|RA4=23.102.4.253|RA4=23.102.21.4|RA4=23.102.155.140|RA4=23.103.182.126|RA4=40.68.222.212|RA4=40.69.153.67|RA4=40.70.220.248|RA4=40.70.221.249|RA4=40.76.1.176|RA4=40.76.12.4|RA4=40.76.12.162|RA4=40.77.228.47|RA4=40.77.228.87|RA4=40.77.228.92|RA4=40.77.232.101|RA4=40.79.85.125|RA4=40.83.189.49|RA4=40.90.221.9|RA4=40.113.8.255|RA4=40.113.10.78|RA4=40.113.11.93|RA4=40.113.14.159|RA4=40.113.22.47|RA4=40.113.84.53|RA4=40.114.149.220|RA4=40.115.1.44|RA4=40.115.3.210|RA4=40.115.119.185|RA4=40.117.144.240|RA4=40.117.151.29|RA4=40.121.144.182|RA4=51.140.40.236|RA4=51.141.13.164|RA4=51.143.111.7|RA4=51.143.111.81|RA4=52.109.8.19|RA4=52.109.8.20|RA4=52.109.8.21|RA4=52.109.12.18|RA4=52.109.12.19|RA4=52.109.12.20|RA4=52.109.12.21|RA4=52.109.12.22|RA4=52.109.12.23|RA4=52.109.12.24|RA4=52.109.76.30|RA4=52.109.76.31|RA4=52.109.76.32|RA4=52.109.76.33|RA4=52.109.76.34|RA4=52.109.76.35|RA4=52.109.76.36|RA4=52.109.76.40|RA4=52.109.88.6|RA4=52.109.88.34|RA4=52.109.88.35|RA4=52.109.88.36|RA4=52.109.88.37|RA4=52.109.88.38|RA4=52.109.88.39|RA4=52.109.88.40|RA4=52.109.120.17|RA4=52.109.120.18|RA4=52.109.120.19|RA4=52.109.120.20|RA4=52.109.120.21|RA4=52.109.120.22|RA4=52.109.120.23|RA4=52.109.124.18|RA4=52.109.124.19|RA4=52.109.124.20|RA4=52.109.124.21|RA4=52.109.124.22|RA4=52.109.124.23|RA4=52.109.124.24|RA4=52.114.6.46|RA4=52.114.6.47|RA4=52.114.7.37|RA4=52.114.32.6|RA4=52.114.32.7|RA4=52.114.32.8|RA4=52.114.74.43|RA4=52.114.74.44|RA4=52.114.74.45|RA4=52.114.75.78|RA4=52.114.75.79|RA4=52.114.75.150|RA4=52.114.76.34|RA4=52.114.76.35|RA4=52.114.76.37|RA4=52.114.77.33|RA4=52.114.77.34|RA4=52.114.77.137|RA4=52.114.88.20|RA4=52.114.88.28|RA4=52.114.88.29|RA4=52.114.128.8|RA4=52.114.128.9|RA4=52.114.128.10|RA4=52.114.128.43|RA4=52.114.128.44|RA4=52.114.128.58|RA4=52.114.132.21|RA4=52.114.132.22|RA4=52.114.132.23|RA4=52.114.132.73|RA4=52.114.132.74|RA4=52.114.158.50|RA4=52.114.158.52|RA4=52.114.158.53|RA4=52.114.158.91|RA4=52.114.158.92|RA4=52.114.158.102|RA4=52.138.204.217|RA4=52.138.216.83|RA4=52.155.172.105|RA4=52.158.208.111|RA4=52.158.238.42|RA4=52.164.240.33|RA4=52.164.240.59|RA4=52.164.241.205|RA4=52.169.189.83|RA4=52.170.83.19|RA4=52.174.22.246|RA4=52.178.38.151|RA4=52.178.147.240|RA4=52.178.151.212|RA4=52.178.178.16|RA4=52.178.223.23|RA4=52.183.114.173|RA4=52.229.39.152|RA4=52.230.85.180|RA4=52.236.42.239|RA4=52.236.43.202|RA4=65.52.26.28|RA4=65.52.100.7|RA4=65.52.100.9|RA4=65.52.100.11|RA4=65.52.100.91|RA4=65.52.100.92|RA4=65.52.100.93|RA4=65.52.100.94|RA4=65.52.161.64|RA4=65.52.219.207|RA4=65.55.29.238|RA4=65.55.44.51|RA4=65.55.44.54|RA4=65.55.44.108|RA4=65.55.44.109|RA4=65.55.83.120|RA4=65.55.113.11|RA4=65.55.113.12|RA4=65.55.113.13|RA4=65.55.176.90|RA4=65.55.252.43|RA4=65.55.252.63|RA4=65.55.252.70|RA4=65.55.252.71|RA4=65.55.252.72|RA4=65.55.252.93|RA4=65.55.252.190|RA4=65.55.252.202|RA4=66.119.147.131|RA4=104.41.207.73|RA4=104.43.137.66|RA4=104.43.139.21|RA4=104.43.140.223|RA4=104.43.228.53|RA4=104.43.228.202|RA4=104.43.237.169|RA4=104.45.11.195|RA4=104.45.214.112|RA4=104.46.1.211|RA4=104.46.38.64|RA4=104.210.4.77|RA4=104.210.40.87|RA4=104.210.212.243|RA4=104.214.35.244|RA4=131.253.6.87|RA4=131.253.6.103|RA4=131.253.40.37|RA4=134.170.30.202|RA4=134.170.30.203|RA4=134.170.30.204|RA4=134.170.30.221|RA4=134.170.52.151|RA4=134.170.235.16|RA4=157.56.74.250|RA4=157.56.91.77|RA4=157.56.106.184|RA4=157.56.106.185|RA4=157.56.106.189|RA4=157.56.113.217|RA4=157.56.121.89|RA4=157.56.124.87|RA4=157.56.149.250|RA4=157.56.194.72|RA4=157.56.194.73|RA4=157.56.194.74|RA4=168.61.24.141|RA4=168.61.146.25|RA4=168.61.149.17|RA4=168.61.172.71|RA4=168.62.187.13|RA4=168.63.100.61|RA4=168.63.108.233|RA4=191.236.155.80|RA4=191.237.218.239|RA4=191.239.50.18|RA4=191.239.50.77|RA4=191.239.52.100|RA4=191.239.54.52|RA4=207.46.41.202|RA4=207.46.134.255|RA4=207.68.166.254|Name=Block Windows Telemetry IPs|Desc=Block Windows Telemetry IPs|"
        Type        = 'String'
        ErrorAction = 'SilentlyContinue'
    }
    Set-ItemProperty @FirewallRule
    #****************************************************************
    Write-Output "Disabling System Location Sensors." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -Type String -ErrorAction SilentlyContinue
    If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc") { Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc" -Name "Start" -Value 4 -Type DWord -ErrorAction SilentlyContinue }
    If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc\Service\Configuration") { Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\lfsvc\Service\Configuration" -Name "Status" -Value 0 -Type DWord -ErrorAction SilentlyContinue }
    #****************************************************************
    Write-Output "Disabling Websites Accessing Language Lists." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\Control Panel\International\User Profile"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling Clipboard History and Service." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Clipboard"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCrossDeviceClipboard" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\cbdhsvc") { Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\cbdhsvc" -Name "Start" -Value 4 -Type DWord -ErrorAction SilentlyContinue }
    #****************************************************************
    Write-Output "Disabling Windows Update Peer-to-Peer Distribution and Delivery Optimization." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Value 100 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling WiFi Sense." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "value" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "value" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    If ($RemovedSystemApps -contains 'Microsoft.BioEnrollment')
    {
        #****************************************************************
        Write-Output "Disabling Biometric and Microsoft Hello Service." >> $RegLog
        #****************************************************************
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Biometrics"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\Credential Provider"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\Credential Provider" -Name "Domain Accounts" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        If (Test-Path -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WbioSrvc") { Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services\WbioSrvc" -Name "Start" -Value 4 -Type DWord -ErrorAction SilentlyContinue }
    }
    #****************************************************************
    Write-Output "Disabling Windows Asking for Feedback." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Siuf\Rules"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling Explorer Documents, Programs and History Tracking." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DontUsePowerShellOnWinX" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NoRecentDocsMenu" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ClearRecentProgForNewUserInStartMenu" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoSearchInternetInStartMenu" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoSearchCommInStartMenu" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoRemoteDestinations" -Value 1 -Type DWord -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Enabling More Details in File Transfer Dialog." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Hiding the 'Snip & Sketch' advertising banner in the classical Win32 'Snipping Tool'." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\TabletPC\Snipping Tool"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\TabletPC\Snipping Tool" -Name "IsScreenSketchBannerExpanded" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Enabling Known File Extensions in the Explorer." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Enabling Hidden Files, Folders, and Drives in the Explorer." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling Automatic Expanding to Current Folder in Explorer." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneExpandToCurrentFolder" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling 'Sharing Wizard' in the Explorer." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SharingWizardOn" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling 'Let Windows 10 Manage Default Printer'." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name "LegacyDefaultPrinterMode" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #***************************************************************
    Write-Output "Disabling the Windows Insider Program and its Telemetry." >> $RegLog
    #***************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableConfigFlighting" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableExperimentation" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" -Name "HideInsiderPage" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling WSUS 'Feature Updates' for LTSC 2019 in order to prevent a bug that causes 1903 Update being wrongly offered to some LTSC 2019 SKU installations." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade" -Name "BlockFeatureUpdates" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling Remote Assistance Connections." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\Remote Assistance"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling Activity History." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling System Advertisements and Windows Spotlight." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling Ink Workspace and Suggested Ink Workspace Apps." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling Live Tiles." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Microsoft\Windows\CurrentVersion\PushNotifications"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoCloudApplicationNotification" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling the Sets Feature." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "TurnOffSets" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling Connected Drive Autoplay and Autorun." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling Typing Data Telemetry." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Input\TIPC"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling Windows 10 Tablet Keyboard Autocorrection, Spellchecking, Textprediction and AI Prediction." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\TabletTip\1.7"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Input\Settings"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\TabletTip\1.7" -Name "EnableAutocorrection" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\TabletTip\1.7" -Name "EnableSpellchecking" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\TabletTip\1.7" -Name "EnableTextPrediction" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\TabletTip\1.7" -Name "EnablePredictionSpaceInsertion" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\TabletTip\1.7" -Name "EnableDoubleTapSpace" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\TabletTip\1.7" -Name "TipbandDesiredVisibility" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\TabletTip\1.7" -Name "EnableEmbeddedInkControl" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\TabletTip\1.7" -Name "EdgeTargetDockedState" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Input\Settings" -Name "InsightsEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling Automatic Download of Content, Ads and Suggestions." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    @("SubscribedContent-202914Enabled", "SubscribedContent-280810Enabled", "SubscribedContent-280811Enabled", "SubscribedContent-280813Enabled", "SubscribedContent-280815Enabled", "SubscribedContent-310091Enabled",
        "SubscribedContent-310092Enabled", "SubscribedContent-310093Enabled", "SubscribedContent-314381Enabled", "SubscribedContent-314559Enabled", "SubscribedContent-314563Enabled", "SubscribedContent-338380Enabled",
        "SubscribedContent-338387Enabled", "SubscribedContent-338388Enabled", "SubscribedContent-338389Enabled", "SubscribedContent-338393Enabled", "SubscribedContent-353698Enabled", "ContentDeliveryAllowed",
        "FeatureManagementEnabled", "OemPreInstalledAppsEnabled", "PreInstalledAppsEnabled", "PreInstalledAppsEverEnabled", "RemediationRequired", "RotatingLockScreenEnabled", "RotatingLockScreenOverlayEnabled",
        "SilentInstalledAppsEnabled", "SoftLandingEnabled", "SystemPaneSuggestionsEnabled", "SubscribedContentEnabled") | ForEach-Object { Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name $($_) -Value 0 -Type DWord -ErrorAction SilentlyContinue }
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling Automatic Download File Blocking." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling Automatic Map Updates." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SYSTEM\Maps"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\Maps" -Name "AutoUpdateEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling Advertising ID for Apps." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling WSUS Advertising and Metadata Collection." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling WSUS Featured Ads, Auto-Update and Auto-Reboot." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "EnableFeaturedSoftware" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling Modern UI Swap File." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\Session Manager\Memory Management"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\Session Manager\Memory Management" -Name "SwapfileControl" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling 'Recently Added Apps' list from the Start Menu." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling 'Most Used Apps' list from the Start Menu." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMFUprogramsList" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling Error Reporting." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\Windows Error Reporting"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling First Log-on Animation." >> $RegLog
    #****************************************************************
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Enabling Windows Start-up Sound." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" -Name "DisableStartupSound" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Changing Search Bar Icon to Magnifying Glass Icon." >> $RegLog
    #****************************************************************
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Increasing Taskbar and Theme Transparency." >> $RegLog
    #****************************************************************
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "UseOLEDTaskbarTransparency" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling Wallpaper .JPEG Quality Reduction." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\Control Panel\Desktop"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\Control Panel\Desktop" -Name "JPEGImportQuality" -Value 100 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Removing the '-Shortcut' Trailing Text for Shortcuts." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates" -Name "ShortcutNameTemplate" -Value "%s.lnk" -Type String -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Enabling Explorer Opens to This PC." >> $RegLog
    #****************************************************************
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling Windows Store Icon from Taskbar." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoPinningStoreToTaskbar" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling Windows Mail Icon from Taskbar." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" -Name "MailPin" -Value 2 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling the Windows Mail Application." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Mail"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Mail" -Name "ManualLaunchAllowed" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling People Icon from Taskbar." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling 'How do you want to open this file?' prompt." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Adding 'This PC' and 'Control Panel' Icons to Desktop." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling Internet Explorer First Run Wizard." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Internet Explorer\Main"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************	
    Write-Output "Disabling Internet Explorer Edge Button." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Internet Explorer\Main"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Internet Explorer\Main" -Name "HideNewEdgeButton" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************	
    Write-Output "Disabling Internet Explorer Smiley Button." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\Restrictions"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\Restrictions" -Name "NoHelpItemSendFeedback" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************	
    Write-Output "Changing Default Internet Explorer Search Engine to Google." >> $RegLog
    #****************************************************************
    Remove-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{0633EE93-D776-472f-A0FF-E1416B8B2E3A}"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Internet Explorer\SearchScopes"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{0BBF48E6-FF9D-4FAA-AA4D-BDBB423B2BE1}"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Internet Explorer\SearchScopes" -Name "DefaultScope" -Value "{0BBF48E6-FF9D-4FAA-AA4D-BDBB423B2BE1}" -Type String -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Internet Explorer\SearchScopes" -Name "DownloadUpdates" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Internet Explorer\SearchScopes" -Name "Version" -Value 4 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Internet Explorer\SearchScopes" -Name "ShowSearchSuggestionsInAddressGlobal" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{0BBF48E6-FF9D-4FAA-AA4D-BDBB423B2BE1}" -Name "DisplayName" -Value "Google" -Type String -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{0BBF48E6-FF9D-4FAA-AA4D-BDBB423B2BE1}" -Name "URL" -Value "https://www.google.com/search?q={searchTerms}" -Type String -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{0BBF48E6-FF9D-4FAA-AA4D-BDBB423B2BE1}" -Name "ShowSearchSuggestions" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{0BBF48E6-FF9D-4FAA-AA4D-BDBB423B2BE1}" -Name "SuggestionsURL_JSON" -Value "https://suggestqueries.google.com/complete/search?output=firefox&client=firefox&qu={searchTerms}" -Type String -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{0BBF48E6-FF9D-4FAA-AA4D-BDBB423B2BE1}" -Name "FaviconURL" -Value "https://www.google.com/favicon.ico" -Type String -ErrorAction SilentlyContinue
    #****************************************************************	
    Write-Output "Changing Default Internet Explorer Homepage to Google and Disabling Annoyances." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Internet Explorer\Main"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Internet Explorer\Main"
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\TabbedBrowsing"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Internet Explorer\Suggested Sites"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Internet Explorer\Main" -Name "Start Page" -Value "https://www.google.com/" -Type String -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Internet Explorer\Main" -Name "Search Page" -Value "https://www.google.com/" -Type String -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Internet Explorer\Main" -Name "Default_Page_URL" -Value "https://www.google.com/" -Type String -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Internet Explorer\Main" -Name "Default_Search_URL" -Value "https://www.google.com/" -Type String -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Internet Explorer\Main" -Name "EnableAutoUpgrade" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "Start Page" -Value "https://www.google.com/" -Type String -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "Search Page" -Value "https://www.google.com/" -Type String -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "SmoothScroll" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\TabbedBrowsing" -Name "NewTabPageShow" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\TabbedBrowsing" -Name "WarnOnClose" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\TabbedBrowsing" -Name "OpenAllHomePages" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\TabbedBrowsing" -Name "Groups" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\TabbedBrowsing" -Name "PopupsUseNewWindow" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" -Name "EnabledV9" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Policies\Microsoft\Internet Explorer\Suggested Sites" -Name "Enabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Removing 'Edit with Paint 3D and 3D Print' from the Context Menu." >> $RegLog
    #****************************************************************
    @('.3mf', '.bmp', '.fbx', '.gif', '.jfif', '.jpe', '.jpeg', '.jpg', '.png', '.tif', '.tiff') | ForEach-Object { Remove-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\$($_)\shell\3D Edit" }
    @('.3ds', '.3mf', '.dae', '.dxf', '.obj', '.ply', '.stl', '.wrl') | ForEach-Object { Remove-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\SystemFileAssociations\$($_)\shell\3D Print" }
    #****************************************************************
    Write-Output "Restoring Windows Photo Viewer." >> $RegLog
    #****************************************************************
    @(".bmp", ".cr2", ".gif", ".ico", ".jfif", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".wdp") | ForEach-Object {
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Classes\$($_)"
        New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$($_)\OpenWithProgids"
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Classes\$($_)" -Name "(default)" -Value "PhotoViewer.FileAssoc.Tiff" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$($_)\OpenWithProgids" -Name "PhotoViewer.FileAssoc.Tiff" -Value (New-Object Byte[] 0) -Type Binary -ErrorAction SilentlyContinue
    }
    @("Paint.Picture", "giffile", "jpegfile", "pngfile") | ForEach-Object {
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\$($_)\shell\open"
        New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\$($_)\shell\open\command"
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\$($_)\shell\open" -Name "MuiVerb" -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043" -Type ExpandString -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\$($_)\shell\open\command" -Name "(Default)" -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1" -Type String -ErrorAction SilentlyContinue
    }
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\command"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\DropTarget"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open" -Name "MuiVerb" -Value "@photoviewer.dll,-3043" -Type String -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1" -Type String -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\DropTarget" -Name "Clsid" -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" -Type String -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling Recently and Frequently Used Items in Explorer." >> $RegLog
    #****************************************************************
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling Automatic Sound Reduction." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Multimedia\Audio"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\SOFTWARE\Microsoft\Multimedia\Audio" -Name "UserDuckingPreference" -Value 3 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Enabling the Fraunhofer IIS MPEG Layer-3 (MP3) Codec (Professional)." >> $RegLog
    #****************************************************************
    If (Test-Path -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\drivers.desc")
    {
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\drivers.desc" -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\drivers.desc" -Force -ErrorAction SilentlyContinue
    }
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\drivers.desc"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\drivers.desc"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32"
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\drivers.desc" -Name "%SystemRoot%\System32\l3codecp.acm" -Value "Fraunhofer IIS MPEG Layer-3 Codec (professional)" -Type String -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32" -Name "msacm.l3acm" -Value "%SystemRoot%\System32\l3codecp.acm" -Type String -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\drivers.desc" -Name "%SystemRoot%\System32\l3codecp.acm" -Value "Fraunhofer IIS MPEG Layer-3 Codec (professional)" -Type String -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32" -Name "msacm.l3acm" -Value "%SystemRoot%\System32\l3codecp.acm" -Type String -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Increasing Icon Cache Size." >> $RegLog
    #****************************************************************
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "Max Cached Icons" -Value 8192 -Type String -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling Sticky Keys Prompt." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\StickyKeys"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value 506 -Type String -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Disabling Enhanced Pointer Precision." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKCU\Control Panel\Mouse"
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\Control Panel\Mouse" -Name "MouseSpeed" -Value 0 -Type String
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\Control Panel\Mouse" -Name "MouseThreshold1" -Value 0 -Type String
    Set-ItemProperty -Path "HKLM:\WIM_HKCU\Control Panel\Mouse" -Name "MouseThreshold2" -Value 0 -Type String
    #****************************************************************
    Write-Output "Enabling Long File Paths." >> $RegLog
    #****************************************************************
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Removing 'Give Access To' from the Context Menu." >> $RegLog
    #****************************************************************
    @("HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shellex\ContextMenuHandlers\Sharing", "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers\Sharing",
        "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\Sharing", "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shellex\CopyHookHandlers\Sharing",
        "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shellex\PropertySheetHandlers\Sharing", "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\Sharing",
        "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shellex\PropertySheetHandlers\Sharing", "HKLM:\WIM_HKLM_SOFTWARE\Classes\LibraryFolder\background\shellex\ContextMenuHandlers\Sharing",
        "HKLM:\WIM_HKLM_SOFTWARE\Classes\UserLibraryFolder\shellex\ContextMenuHandlers\Sharing") | ForEach-Object { Remove-Container -Path $($_) }
    #****************************************************************
    Write-Output "Removing 'Share' from the Context Menu." >> $RegLog
    #****************************************************************
    Remove-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\*\shellex\ContextMenuHandlers\ModernSharing"
    #****************************************************************
    Write-Output "Removing 'Cast To Device' from the Context Menu." >> $RegLog
    #****************************************************************
    New-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"
    Set-ItemProperty -Path "HKLM:\WIM_HKLM_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" -Value "Play to Menu" -Type String -ErrorAction SilentlyContinue
    #****************************************************************
    Write-Output "Removing 'Restore Previous Versions' from the Context Menu." >> $RegLog
    #****************************************************************
    Remove-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}"
    Remove-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}"
    Remove-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}"
    Remove-Container -Path "HKLM:\WIM_HKLM_SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}"
    #****************************************************************
    Get-OfflineHives -Process Unload
}
#endregion Registry Optimizations

If ($Additional.IsPresent -and (Get-ChildItem -Path $AdditionalPath -Directory | Measure-Object).Count -gt 0)
{
    $Host.UI.RawUI.WindowTitle = "Copying Additional Setup Content."
    Out-Log -Info "Copying Additional Setup Content."
    If (Test-Path -Path "$AdditionalPath\Unattend\unattend.xml")
    {
        [XML]$XML = Get-Content -Path "$AdditionalPath\Unattend\unattend.xml"
        If ($XML.unattend.settings.pass -contains 'offlineServicing' -or $XML.unattend.servicing)
        {
            [void](Use-WindowsUnattend -UnattendPath "$AdditionalPath\Unattend\unattend.xml" -Path $MountFolder -ScratchDirectory $ScratchFolder -LogPath $DISMLog -ErrorAction SilentlyContinue)
        }
        New-Container -Path "$MountFolder\Windows\Panther"
        Copy-Item -Path "$AdditionalPath\Unattend\unattend.xml" -Destination "$MountFolder\Windows\Panther" -ErrorAction SilentlyContinue
    }
    If (Test-Path -Path "$AdditionalPath\Setup\Scripts\*")
    {
        New-Container -Path "$MountFolder\Windows\Setup\Scripts"
		New-Container -Path "$MountFolder\Windows\Setup\Files"
        Get-ChildItem -Path "$AdditionalPath\Setup\Scripts" -ErrorAction SilentlyContinue | Copy-Item -Destination "$MountFolder\Windows\Setup\Scripts" -Recurse -ErrorAction SilentlyContinue
		Get-ChildItem -Path "$AdditionalPath\Setup\Files" -ErrorAction SilentlyContinue | Copy-Item -Destination "$MountFolder\Windows\Setup\Files" -Recurse -ErrorAction SilentlyContinue
    }
    If (Test-Path -Path "$AdditionalPath\Wallpaper\*")
    {
        Get-ChildItem -Path "$AdditionalPath\Wallpaper" -Directory -ErrorAction SilentlyContinue | Copy-Item -Destination "$MountFolder\Windows\Web\Wallpaper" -Recurse -ErrorAction SilentlyContinue
        Get-ChildItem -Path "$AdditionalPath\Wallpaper\*" -Include *.jpg, *.png, *.bmp, *.gif -File -ErrorAction SilentlyContinue | Copy-Item -Destination "$MountFolder\Windows\Web\Wallpaper" -ErrorAction SilentlyContinue
    }
    If (Test-Path -Path "$AdditionalPath\Logo\*.bmp")
    {
        New-Container -Path "$MountFolder\Windows\System32\oobe\info\logo"
        Copy-Item -Path "$AdditionalPath\Logo\*.bmp" -Destination "$MountFolder\Windows\System32\oobe\info\logo" -Recurse -ErrorAction SilentlyContinue
    }
    If (Get-ChildItem -Path "$AdditionalPath\Drivers" -Filter *.inf -Recurse)
    {
        Try
        {
            $Host.UI.RawUI.WindowTitle = "Injecting Driver Packages."
            Out-Log -Info "Injecting Driver Packages."
            $DriverParams = @{
                Path             = $MountFolder
                Driver           = "$AdditionalPath\Drivers"
                Recurse          = $true
                ForceUnsigned    = $true
                ScratchDirectory = $ScratchFolder
                LogPath          = $DISMLog
                ErrorAction      = 'Stop'
            }
            [void](Add-WindowsDriver @DriverParams)
            Get-WindowsDriver -Path $MountFolder | Out-File -FilePath $InjectedDriverList -ErrorAction SilentlyContinue
        }
        Catch
        {
            Out-Log -Error "Failed to Inject Driver Packages." -ErrorRecord $Error[0]
            Stop-Optimize; Throw
        }
    }
}

If ((Repair-WindowsImage -Path $MountFolder -CheckHealth).ImageHealthState -eq 'Healthy')
{
    Out-Log -Info "Post-Optimization Image Health State: [Healthy]"
    @"
This $($WimInfo.Name) installation was optimized with Optimize-LTSC.ps1 version $ScriptVersion
on $(Get-Date -UFormat "%d/%m/%Y at %r")
"@ | Out-File -FilePath (Join-Path -Path $MountFolder -ChildPath Optimize-LTSC.txt) -Encoding Unicode -Force
    Start-Sleep 3
}
Else
{
    Out-Log -Error "The image has been flagged for corruption. Discarding optimizations."
    Stop-Optimize; Throw
}

Try
{
    $Host.UI.RawUI.WindowTitle = "Saving and Dismounting $($WimInfo.Name)"
    Out-Log -Info "Saving and Dismounting $($WimInfo.Name)"
    Remove-Container -Path "$MountFolder\PerfLogs"
    Remove-Container -Path ("$MountFolder\" + '$Recycle.Bin')
    If (Get-OfflineHives -Process Test) { Get-OfflineHives -Process Unload }
    $DismountWindowsImage = @{
        Path             = $MountFolder
        Save             = $true
        CheckIntegrity   = $true
        ScratchDirectory = $ScratchFolder
        LogPath          = $DISMLog
        ErrorAction      = 'Stop'
    }
    [void](Dismount-WindowsImage @DismountWindowsImage)
    Remove-Container -Path $MountFolder
    Clear-Host
}
Catch
{
    Out-Log -Error "Failed to Save and Dismount $($WimInfo.Name)" -ErrorRecord $Error[0]
    Stop-Optimize; Throw
}

Do
{
    $CompressionList = @('Solid', 'Maximum', 'Fast', 'None') | Select-Object -Property @{ Label = 'Compression'; Expression = { ($_) } } | Out-GridView -Title "Select Final Image Compression." -OutputMode Single
    $CompressionType = $CompressionList | Select-Object -ExpandProperty Compression
}
While ($CompressionList.Length -eq 0)

If ($CompressionType -eq 'Solid') { Write-Warning "Solid compression can take quite a while. Please be patient until it completes."; Start-Sleep 3 }

Try
{
    $Host.UI.RawUI.WindowTitle = "Exporting $($WimInfo.Name) using $($CompressionType) compression."
    Out-Log -Info "Exporting $($WimInfo.Name) using $($CompressionType) compression."
    If ($CompressionType -eq 'Solid')
    {
        $ExportInstall = Start-Process -FilePath DISM -ArgumentList @('/Export-Image /SourceImageFile:"{0}" /SourceIndex:{1} /DestinationImageFile:"{2}" /Compress:Recovery /CheckIntegrity' -f $InstallWim, $ImageIndex, "$($ImageFolder)\install.esd") -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop
        If ($ExportInstall.ExitCode -eq 0) { Remove-Container -Path $InstallWim; $ImageFiles = @('install.esd', 'boot.wim') }
        Else { Out-Log -Error "Failed to export $($WimInfo.Name) using $($CompressionType) compression."; $ImageFiles = @('install.wim', 'boot.wim') }
    }
    Else
    {
        $ExportInstall = @{
            SourceImagePath      = $InstallWim
            SourceIndex          = $ImageIndex
            DestinationImagePath = "$($ImageFolder)\tmp_install.wim"
            CompressionType      = $CompressionType
            CheckIntegrity       = $true
            ScratchDirectory     = $ScratchFolder
            LogPath              = $DISMLog
            ErrorAction          = 'Stop'
        }
        [void](Export-WindowsImage @ExportInstall)
        Remove-Container -Path $InstallWim
        Rename-Item -Path "$($ImageFolder)\tmp_install.wim" -NewName install.wim -Force -ErrorAction Stop
        $ImageFiles = @('install.wim', 'boot.wim')
    }
}
Catch
{
    Out-Log -Error "Failed to Export $($WimInfo.Name)" -ErrorRecord $Error[0]
    Stop-Optimize; Throw
}

If ($ISOMedia)
{
    $Host.UI.RawUI.WindowTitle = "Optimizing the Windows Media File Structure."
    Out-Log -Info "Optimizing the Windows Media File Structure."
    Get-ChildItem -Path $ISOMedia -Filter *.dll | Remove-Container
    @("$ISOMedia\autorun.inf", "$ISOMedia\setup.exe", "$ISOMedia\ca", "$ISOMedia\NanoServer", "$ISOMedia\support", "$ISOMedia\upgrade", "$ISOMedia\sources\dlmanifests", "$ISOMedia\sources\etwproviders",
        "$ISOMedia\sources\inf", "$ISOMedia\sources\hwcompat", "$ISOMedia\sources\migration", "$ISOMedia\sources\replacementmanifests", "$ISOMedia\sources\servicing", "$ISOMedia\sources\servicingstackmisc",
        "$ISOMedia\sources\sxs", "$ISOMedia\sources\uup", "$ISOMedia\sources\vista", "$ISOMedia\sources\xp") | ForEach-Object { Remove-Container -Path $($_) }
    @('.adml', '.mui', '.rtf', '.txt') | ForEach-Object { Get-ChildItem -Path "$ISOMedia\sources\$($WimInfo.Language)" -Filter *$($_) -Exclude 'setup.exe.mui' -Recurse | Remove-Container }
    @('.dll', '.gif', '.xsl', '.bmp', '.mof', '.ini', '.cer', '.exe', '.sdb', '.txt', '.nls', '.xml', '.cat', '.inf', '.sys', '.bin', '.ait', '.admx', '.dat', '.ttf', '.cfg',
        '.xsd', '.rtf', '.xrm-ms') | ForEach-Object { Get-ChildItem -Path "$ISOMedia\sources" -Filter *$($_) -Exclude @('EI.cfg', 'gatherosstate.exe', 'setup.exe', 'lang.ini', 'pid.txt', '*.clg') -Recurse | Remove-Container }
    Get-ChildItem -Path $ImageFolder -Include $ImageFiles -Recurse | Move-Item -Destination "$($ISOMedia)\sources" -Force -ErrorAction SilentlyContinue
    If ($ISO.IsPresent)
    {
        [IO.FileInfo]$Oscdimg = @("HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots") | ForEach-Object {
            Get-ItemProperty -Path $($_) -Name KitsRoot10 -ErrorAction Ignore
        } | Select-Object -First 1 -ExpandProperty KitsRoot10 | Join-Path -ChildPath "Assessment and Deployment Kit\Deployment Tools\$Env:PROCESSOR_ARCHITECTURE\Oscdimg\oscdimg.exe"
        If (!$Oscdimg)
        {
            [void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
            $OpenFile = New-Object -TypeName System.Windows.Forms.OpenFileDialog
            $OpenFile.Title = "Select the Oscdimg executable for ISO creation."
            $OpenFile.InitialDirectory = [System.IO.Directory]::GetCurrentDirectory()
            $OpenFile.Filter = "oscdimg.exe|oscdimg.exe|All files|*.*"
            If ($OpenFile.ShowDialog() -eq 'OK') { [IO.FileInfo]$Oscdimg = $OpenFile.FileName }
        }
        If (Test-Path -Path $($Oscdimg.FullName) -PathType Leaf -ErrorAction Ignore)
        {
            Try
            {
                $ISOName = $($WimInfo.Edition).Replace(' ', '') + "_$($WimInfo.Build).iso"
                $ISOPath = Join-Path -Path $WorkFolder -ChildPath $ISOName
                $BootData = ('2#p0,e,b"{0}"#pEF,e,b"{1}"' -f "$($ISOMedia)\boot\etfsboot.com", "$($ISOMedia)\efi\Microsoft\boot\efisys.bin")
                $OscdimgArgs = @('-bootdata:{0}', '-u2', '-udfver102', '-l"{1}"', '"{2}"', '"{3}"' -f $BootData, $($WimInfo.Name), $ISOMedia, $ISOPath)
                $Host.UI.RawUI.WindowTitle = "Creating a Bootable Windows Installation Media ISO."
                Out-Log -Info "Creating a Bootable Windows Installation Media ISO."
                $RunOscdimg = Start-Process -FilePath $($Oscdimg.FullName) -ArgumentList $OscdimgArgs -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop
                If ($RunOscdimg.ExitCode -eq 0) { $ISOIsCreated = $true }
                Else { Out-Log -Error "ISO creation failed. Oscdimg returned exit code: $($RunOscdimg.ExitCode)" }
            }
            Catch
            {
                Out-Log -Error "ISO creation failed." -ErrorRecord $Error[0]
                Start-Sleep 3
            }
        }
        Else
        {
            Out-Log -Error "No oscdimg.exe was selected. Skipping ISO creation."
            Start-Sleep 3
        }
    }
}

Try
{
    $Host.UI.RawUI.WindowTitle = "Finalizing Optimizations."
    Out-Log -Info "Finalizing Optimizations."
    [void]($SaveFolder = New-OfflineDirectory -Directory Save)
    If ($ISOIsCreated) { Move-Item -Path $ISOPath -Destination $SaveFolder -ErrorAction SilentlyContinue }
    Else
    {
        If ($ISOMedia) { Move-Item -Path $ISOMedia -Destination $SaveFolder -ErrorAction SilentlyContinue }
        Else { Get-ChildItem -Path $ImageFolder -Include $ImageFiles -Recurse | Move-Item -Destination $SaveFolder -ErrorAction SilentlyContinue }
    }
}
Finally
{
    $Timer.Stop()
    Out-Log -Info "$ScriptName completed in [$($Timer.Elapsed.Minutes.ToString())] minutes with [$($Error.Count)] errors."
    If ($Error.Count -gt 0) { $Error.ToArray() | Out-File -FilePath (Join-Path -Path $WorkFolder -ChildPath ErrorRecord.log) -Force -ErrorAction SilentlyContinue }
    Add-Content -Path $ScriptLog -Value ""
    Add-Content -Path $ScriptLog -Value "***************************************************************************************************"
    Add-Content -Path $ScriptLog -Value "Optimizations finalized on [$(Get-Date -UFormat "%d/%m/%Y %r")]"
    Add-Content -Path $ScriptLog -Value "***************************************************************************************************"
    Remove-Container -Path $DISMLog
    Remove-Container -Path "$Env:SystemRoot\Logs\DISM\dism.log"
    [void](Get-ChildItem -Path $WorkFolder -Include *.txt, *.log -Recurse -ErrorAction SilentlyContinue | Compress-Archive -DestinationPath "$SaveFolder\OptimizeLogs.zip" -CompressionLevel Fastest -ErrorAction SilentlyContinue)
    Get-ChildItem -Path $PSScriptRoot -Filter "OptimizeLTSCTemp_*" -Directory -Name -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    [void](Clear-WindowsCorruptMountPoint)
    $Host.UI.RawUI.WindowTitle = "Optimizations Complete."
}
# The end