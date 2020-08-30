# Last Update: 5/31/2020
# More to come!

Write-Host -ForegroundColor Yellow "||||||||||||||||||||"
Write-Host -ForegroundColor Yellow "HardenMe-W10 Level 2"
Write-Host -ForegroundColor Yellow "||||||||||||||||||||"
Write-Host ""

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable Cortana ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
	Reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" /t REG_SZ /d  "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search and Cortana application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable Game Bar Features ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowgameDVR /t REG_DWORD /d 0 /f
	Reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
	Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f
	Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v  HistoricalCaptureEnabled /t REG_DWORD /d 0 /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable OneDrive Everywhere ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\Software\Policies\Microsoft\Windows" /v  DisableFileSyncNGSC /t REG_DWORD /d 1 /f
    $exists = Get-ItemProperty -Path "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -ErrorAction SilentlyContinue
        If (($exists -ne $null) -and ($exists.Length -ne 0)) 
        {
            Reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
        }
        else 
        {
        Write-Host -ForegroundColor White "Nice Job! Registry value not present! - No action was taken"
        }
    $exists = Get-ItemProperty -Path "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6" -ErrorAction SilentlyContinue
        If (($exists -ne $null) -and ($exists.Length -ne 0)) 
        {Reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /fWrite-Host -ForegroundColor White "The operation completed successfully."
        }
        else 
        {
        Write-Host -ForegroundColor White "Nice Job! Registry value not present! - No action was taken"
        }
	#
    if ( Test-Path -Path '%UserProfile%\OneDrive' -PathType Container ) { Remove-Item -path "%UserProfile%\OneDrive" -recurse -force }
    else
     {Write-Host -ForegroundColor White "Nice Job! Directory not present! - No action was taken"
     }
    if ( Test-Path -Path '%LocalAppData%\Microsoft\OneDrive' -PathType Container ) { Remove-Item -path "%LocalAppData%\Microsoft\OneDrive" -recurse -force}
    else
     {Write-Host -ForegroundColor White "Nice Job! Directory not present! - No action was taken"
     }

    if ( Test-Path -Path '%ProgramData%\Microsoft OneDrive' -PathType Container ) { Remove-Item -path "%ProgramData%\Microsoft OneDrive" -recurse -force}
    else
     {Write-Host -ForegroundColor White "Nice Job! Directory not present! - No action was taken"
     }

    if ( Test-Path -Path 'C:\OneDriveTemp' -PathType Container ) { Remove-Item -path "C:\OneDriveTemp" -recurse -force }
    else
     {Write-Host -ForegroundColor White "Nice Job! Directory not present! - No action was taken"
     }	


Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "No More Forced Updates ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 2 /f
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallDay /t REG_DWORD /d 0 /f
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallTime /t REG_DWORD /d 3 /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable Web Search in Start Menu ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWeb /t REG_DWORD /d 0 /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Remove Telemetry ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
 	#Connect User Experiences and Telemetry Service
 	Set-Service DiagTrack -StartupType Disabled
 	#Device Management Wireless Application Protocol Service
	Set-Service dmwappushservice -StartupType Disabled
	#Windows Error Reporting Service Service
	Set-Service WerSvc -StartupType Disabled
	#Sync Host Service
	Set-Service OneSyncSvc -StartupType Disabled
	#Messaging Service
	Set-Service MessagingService -StartupType Disabled
	#Problem Reports and Solutions Control Panel Support Service
	Set-Service wercplsupport -StartupType Disabled
	#Program Compatibility Assistant Service
	Set-Service PcaSvc -StartupType Disabled
	#Microsoft Account Sign-in Assistant Service
	Set-Service wlidsvc -StartupType Disabled
	#Windows Insider Service
	Set-Service wisvc -StartupType Disabled
	#Retail Demo Service
	Set-Service RetailDemo -StartupType Disabled
	#Diagnostic Executution Service
	Set-Service diagsvc -StartupType Disabled
	#Shared PC Account Manager Service
	Set-Service shpamsvc -StartupType Disabled
	#Remote Desktops Services Service
	Set-Service TermService -StartupType Disabled
	#Remote Desktop Services UserMode Service
	Set-Service UmRdpService -StartupType Disabled
	#Remote Desktop Configuration Service
	Set-Service SessionEnv -StartupType Disabled
	#Recommended Troubleshooting Service
	Set-Service TroubleshootingSvc -StartupType Disabled
	#Microsoft Diagnostic Hub Standard Collector Service
	Set-Service diagnosticshub.standardcollector.service -StartupType Disabled

	Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
	#Reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
    $exists = Get-ItemProperty -Path "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" -ErrorAction SilentlyContinue
        If (($exists -ne $null) -and ($exists.Length -ne 0)) 
        {
            Reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
        }
        else 
        {
        Write-Host -ForegroundColor White "Nice Job! Registry value not present! - No action was taken"
        }

	Reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 1 /f
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f
	Reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
	Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f
	Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
	Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable App Access to Account info ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v Value /t REG_SZ /d "Deny" /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable App Access to Calendar ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v Value /t REG_SZ /d "Deny" /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable App Access to Call History ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v Value /t REG_SZ /d "Deny" /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable App Access to Call ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v Value /t REG_SZ /d "Deny" /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable App Access to Contacts ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v Value /t REG_SZ /d "Deny" /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable App Access to Diagnostic Information ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v Value /t REG_SZ /d "Deny" /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable App Access to Documents ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v Value /t REG_SZ /d "Deny" /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable App Access to Email ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v Value /t REG_SZ /d "Deny" /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable App Access to File System ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v Value /t REG_SZ /d "Deny" /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable App Access to Location ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v Value /t REG_SZ /d "Deny" /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable App Access to Messaging ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v Value /t REG_SZ /d "Deny" /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable App Access to Microphone ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v Value /t REG_SZ /d "Deny" /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable App Access to Motion ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v Value /t REG_SZ /d "Deny" /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable App Access to Notifications ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v Value /t REG_SZ /d "Deny" /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable App Access to Other Devices ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" /v Value /t REG_SZ /d "Deny" /f
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v Value /t REG_SZ /d "Deny" /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable App Access to Pictures ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v Value /t REG_SZ /d "Deny" /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable App Access to Radios ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v Value /t REG_SZ /d "Deny" /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable App Access to Tasks ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v Value /t REG_SZ /d "Deny" /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable App Access to Videos ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v Value /t REG_SZ /d "Deny" /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable app access to webcam ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v Value /t REG_SZ /d "Deny" /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable App Notifications ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v NoToastApplicationNotification /t REG_DWORD /d 1 /f
	Reg add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v NoToastApplicationNotificationOnLockScreen /t REG_DWORD /d 1 /f
	#Windows Push Notification System Service
	Set-Service WpnService -StartupType Disabled

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable Apps from Running in Background ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
 	Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable user data synchronization ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
 	#User Data Access Service
 	Set-Service UnistoreSvc -StartupType Disabled

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable Microsoft Windows Live ID service ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
 	Reg add "HKLM\SYSTEM\CurrentControlSet\services\wlidsvc" /v Start /t REG_DWORD /d 4 /f
 	# Microsoft Account Sign-in Assistant Service
 	Set-Service wlidsvc -StartupType Disabled

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable Compatibility Telemetry ((Level 2))"
Write-Host -ForegroundColor DarkGreen "====================================================="
 	Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f 	Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f

Write-Host -ForegroundColor DarkGreen "============================================================"
Write-Host -ForegroundColor DarkGreen "Disable Windows Script Host - Blocks scripts VBS ((Level 2))"
Write-Host -ForegroundColor DarkGreen "============================================================"
 	Reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows Script Host\Settings" /v Enabled /t REG_DWORD /d 0 /f
   	Reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Script Host\Settings" /v Enabled /t REG_DWORD /d 0 /f