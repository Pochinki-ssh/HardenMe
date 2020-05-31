# Last Update: 5/31/2020
# More to come!

Write-Host -ForegroundColor Yellow "||||||||||||||||||||"
Write-Host -ForegroundColor Yellow "HardenMe-W10 Level 1"
Write-Host -ForegroundColor Yellow "||||||||||||||||||||"
Write-Host ""

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Turn off ads in Settings ((Level 1))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338393Enabled /t REG_DWORD /d 0 /f
	Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353694Enabled /t REG_DWORD /d 0 /f
	Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353696Enabled /t REG_DWORD /d 0 /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable Location Tracking ((Level 1))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v Value /t REG_SZ /d Deny /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable Bing in Start Menu ((Level 1))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
	Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 0 /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable Input Personalization ((Level 1))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v AllowInputPersonalization /t REG_DWORD /d 0 /f
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v PreventHandwritingErrorReports /t REG_DWORD /d 1 /f
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v PreventHandwritingDataSharing /t REG_DWORD /d 1 /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable Microsoft Office telemetry ((Level 1))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\osm" /v "Enablelogging" /t REG_DWORD /d 0 /f
	Reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\osm" /v "EnableUpload" /t REG_DWORD /d 0 /f
	Reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm" /v "Enablelogging" /t REG_DWORD /d 0 /f
	Reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm" /v "EnableUpload" /t REG_DWORD /d 0 /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable Media Player Telemetry ((Level 1))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d 0 /f
	Reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventCDDVDMetadataRetrieval" /t REG_DWORD /d 1 /f
	Reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventMusicFileMetadataRetrieval" /t REG_DWORD /d 1 /f
	Reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventRadioPresetsRetrieval" /t REG_DWORD /d 1 /f
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d 1 /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable System Restore ((Level 1))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v DisableConfig /t REG_DWORD /d 1 /f
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v DisableSR /t REG_DWORD /d 1 /f
	Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v DisableConfig /t REG_DWORD /d "1" /f
	Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v DisableSR /t REG_DWORD /d 1 /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable Telemetry ((Level 1))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	#Connected User Experiences and Telemetry Service
	Set-Service DiagTrack -StartupType Disabled
	#Set-Service dmwappushsvc -StartupType Disabled
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f
	Reg add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v Start /t REG_DWORD /d 4 /f
	Reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushsvc" /v Start /t REG_DWORD /d 4 /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable Timeline History ((Level 1))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable Wi-Fi Sense ((Level 1))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable Windows Error Reporting ((Level 1))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Turn Off Ad Tracking ((Level 1))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
	Reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Turn off Windows Updates Sharing ((Level 1))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Turn off Windows Spotlight Features ((Level 1))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ContentDeliveryAllowed /t REG_DWORD /d 0 /f
	Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenEnabled /t REG_DWORD /d 0 /f
	Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenOverlayEnabled /t REG_DWORD /d 0 /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Opt-out nVidia Telemetry ((Level 1))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v EnableRID44231 /t REG_DWORD /d 0 /f
	Reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v EnableRID64640 /t REG_DWORD /d 0 /f
	Reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v EnableRID66610 /t REG_DWORD /d 0 /f
	Reg add "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v OptInOrOutPreference /t REG_DWORD /d 0 /f
	Reg add "HKLM\SYSTEM\CurrentControlSet\services\NvTelemetryContainer" /v Start /t REG_DWORD /d 4 /f
	Reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\Startup\SendTelemetryData" /v "(default)" /t REG_DWORD /d 0 /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "No Windows Tips ((Level 1))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f
	Reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
	Reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
	Reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
	Reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "No License Checking ((Level 1))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v NoGenTicket /t REG_DWORD /d 1 /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "No More Forced Driver Updates((Level 1))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Update" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d 1 /f
	Reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Update" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d 1 /f
	Reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Update\ExcludeWUDriversInQualityUpdates" /v Value /t REG_DWORD /d 1 /f
	Reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d 1 /f
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d 1 /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable Performance Tracking Tool ((Level 1))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" /v ScenarioExecutionEnabled /t REG_DWORD /d 0 /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Disable Tracking of App Starts ((Level 1))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackProgs /t REG_DWORD /d 0 /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Opt-Out of Help Experience Improvement Program (HEIP) ((Level 1))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKCU\Software\Microsoft\Assistance\Client\1.0\Settings" /v ImplicitFeedback /t REG_DWORD /d 0 /f

Write-Host -ForegroundColor DarkGreen "====================================================="
Write-Host -ForegroundColor DarkGreen "Opt-Out of Customer Experience Improvement Program (CEIP) ((Level 1))"
Write-Host -ForegroundColor DarkGreen "====================================================="
	Reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v CEIPEnable /t REG_DWORD /d 0 /f