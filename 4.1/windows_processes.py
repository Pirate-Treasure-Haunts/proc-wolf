#!/usr/bin/env python3
"""
Windows System Process Whitelist
---------------------------------
Comprehensive list of legitimate Windows processes and services
"""

# Core Windows System Processes (NEVER touch these)
WINDOWS_CORE_PROCESSES = [
    'System',
    'System Idle Process',
    'Registry',
    'smss.exe',
    'csrss.exe',
    'wininit.exe',
    'services.exe',
    'lsass.exe',
    'lsaiso.exe',           # Credential Guard
    'winlogon.exe',
    'explorer.exe',
    'svchost.exe',
    'taskhost.exe',
    'taskhostw.exe',
    'dwm.exe',              # Desktop Window Manager
    'conhost.exe',
    'cmd.exe',
    'powershell.exe',
    'pwsh.exe',
]

# Windows Service Processes
WINDOWS_SERVICE_PROCESSES = [
    'spoolsv.exe',          # Print Spooler
    'wlanext.exe',          # Wireless LAN
    'WUDFHost.exe',         # Windows Driver Foundation
    'audiodg.exe',          # Audio Device Graph
    'SearchIndexer.exe',    # Windows Search
    'SearchProtocolHost.exe',
    'SearchFilterHost.exe',
    'WmiPrvSE.exe',         # WMI Provider
    'dllhost.exe',          # COM Surrogate
    'RuntimeBroker.exe',    # Runtime Broker
    'backgroundTaskHost.exe',
    'ApplicationFrameHost.exe',
    'SystemSettings.exe',
    'UserOOBEBroker.exe',
    'ShellExperienceHost.exe',
    'StartMenuExperienceHost.exe',
    'SearchHost.exe',       # Windows 11 Search
    'SearchApp.exe',        # Windows 10 Search
    'TextInputHost.exe',    # Text input
    'ctfmon.exe',           # CTF Loader
    'TabTip.exe',           # Touch Keyboard
    'TabTip32.exe',
    'wisptis.exe',          # Pen and Touch
    'MoUsoCoreWorker.exe',  # Windows Update
    'TrustedInstaller.exe', # Windows Modules Installer
    'TiWorker.exe',         # Windows Modules Installer Worker
    'wuauclt.exe',          # Windows Update
    'sihclient.exe',        # Server Initiated Healing
    'SgrmBroker.exe',       # System Guard Runtime Broker
    'SecurityHealthService.exe',
    'SecurityHealthSystray.exe',
]

# Windows 10/11 Modern App Processes
WINDOWS_MODERN_PROCESSES = [
    'MemCompression',       # Memory Compression (CRITICAL!)
    'sihost.exe',           # Shell Infrastructure Host
    'taskhostw.exe',        # Task Host Window
    'fontdrvhost.exe',      # Font Driver Host
    'winlogon.exe',
    'LogonUI.exe',          # Login UI
    'LockApp.exe',          # Lock Screen
    'CredentialEnrollmentManager.exe',
    'CredentialUIBroker.exe',
    'AuthHost.exe',
    'UserNotificationCenter.exe',
    'CompPkgSrv.exe',       # Component Package Support
    'ClipSVC.exe',          # Client License Service
    'AppVShNotify.exe',     # App-V
    'wsqmcons.exe',         # Windows SQM Consolidator
    'CompatTelRunner.exe',  # Compatibility Telemetry
    'DeviceEnroller.exe',   # Device Enrollment
    'DeviceCensus.exe',     # Device Census
    'SpeechRuntime.exe',    # Speech Runtime
    'SpeechModelDownload.exe',
    'WidgetService.exe',    # Windows 11 Widgets
    'Widgets.exe',
    'PhoneExperienceHost.exe',
    'YourPhone.exe',
    'YourPhoneServer.exe',
    'CrossDeviceService.exe',
    'CrossDeviceResume.exe',
]

# Windows Defender / Security Processes
WINDOWS_DEFENDER_PROCESSES = [
    'MsMpEng.exe',          # Windows Defender Antimalware Service
    'NisSrv.exe',           # Network Inspection Service
    'MpDefenderCoreService.exe', # Defender Core Service
    'MpCmdRun.exe',         # Defender Command Line
    'MsCmdRun.exe',         # Microsoft Command Run
    'MSASCuiL.exe',         # Windows Defender UI
    'SecurityHealthHost.exe',
    'SecHealthUI.exe',
    'SenseCncProxy.exe',    # Windows Defender ATP
    'SenseIR.exe',          # Windows Defender ATP IR
    'SenseNdr.exe',         # Windows Defender ATP NDR
    'SenseTray.exe',        # Windows Defender ATP Tray
]

# Network and Communication
WINDOWS_NETWORK_PROCESSES = [
    'dasHost.exe',          # Device Association Service
    'DeviceAssociationBrokerSvc.exe',
    'IpOverUsbSvc.exe',     # IP over USB
    'NetSetupSvc.exe',      # Network Setup Service
    'NcbService.exe',       # Network Connection Broker
    'netsh.exe',            # Network Shell
    'NetworkUXBroker.exe',  # Network UX Broker
    'WiFiCloudStore.exe',   # WiFi Cloud Store
    'WlanExtAP.exe',        # WLAN Extensibility
]

# Graphics and Display Drivers
GRAPHICS_PROCESSES = [
    'igfxEM.exe',           # Intel Graphics
    'igfxHK.exe',           # Intel Graphics Hotkey
    'igfxTray.exe',         # Intel Graphics Tray
    'igfxext.exe',          # Intel Graphics Extension
    'igfxsrvc.exe',         # Intel Graphics Service
    'igfxpers.exe',         # Intel Graphics Persistence
    'GfExperienceService.exe', # NVIDIA GeForce Experience
    'NvBackend.exe',        # NVIDIA Backend
    'nvcontainer.exe',      # NVIDIA Container
    'nvdisplay.container.exe',
    'nvspcaps64.exe',       # NVIDIA Capture
    'nvsphelper64.exe',     # NVIDIA Helper
    'nvtray.exe',           # NVIDIA Tray
    'RadeonSoftware.exe',   # AMD Radeon Software
    'RadeonSettings.exe',   # AMD Settings
    'atieclxx.exe',         # AMD External Events
    'atiesrxx.exe',         # AMD External Events Service
]

# Common Legitimate Third-Party Software
LEGITIMATE_SOFTWARE = [
    # Browsers
    'chrome.exe',
    'firefox.exe',
    'msedge.exe',
    'msedgewebview2.exe',
    'brave.exe',
    'vivaldi.exe',
    'opera.exe',
    'iexplore.exe',
    
    # Development Tools
    'code.exe',             # VS Code
    'devenv.exe',           # Visual Studio
    'python.exe',
    'pythonw.exe',
    'node.exe',
    'git.exe',
    'git-bash.exe',
    'sh.exe',
    'bash.exe',
    'wsl.exe',
    'wslhost.exe',
    'wslservice.exe',
    'docker.exe',
    'Docker Desktop.exe',
    'com.docker.service',
    
    # Communication
    'Discord.exe',
    'DiscordPTB.exe',
    'DiscordCanary.exe',
    'slack.exe',
    'Teams.exe',
    'ms-teams.exe',
    'zoom.exe',
    'ZoomMeeting.exe',
    'Skype.exe',
    'Signal.exe',
    'Telegram.exe',
    'WhatsApp.exe',
    
    # Cloud Storage
    'Dropbox.exe',
    'DropboxUpdate.exe',
    'OneDrive.exe',
    'OneDriveStandaloneUpdater.exe',
    'googledrivesync.exe',
    'GoogleDriveFS.exe',
    'iCloudServices.exe',
    'iCloudDrive.exe',
    
    # Media
    'spotify.exe',
    'SpotifyWebHelper.exe',
    'vlc.exe',
    'obs64.exe',
    'obs.exe',
    'obs-browser-page.exe',
    'streamlabs_obs.exe',
    'iTunes.exe',
    'AppleMobileDeviceService.exe',
    
    # Productivity
    'EXCEL.EXE',
    'WINWORD.EXE',
    'POWERPNT.EXE',
    'OUTLOOK.EXE',
    'ONENOTE.EXE',
    'MSACCESS.EXE',
    'AcroRd32.exe',
    'Acrobat.exe',
    'FoxitReader.exe',
    'SumatraPDF.exe',
    
    # Security/VPN
    'ProtonVPN.exe',
    'ProtonVPN.Service.exe',
    'ProtonVPNService.exe',
    'ProtonVPN.Client.exe',
    'openvpn.exe',
    'openvpn-gui.exe',
    'NordVPN.exe',
    'ExpressVPN.exe',
    'Malwarebytes.exe',
    'mbam.exe',
    'mbamservice.exe',
    
    # System Utilities
    'Everything.exe',
    'EverythingServer.exe',
    'PowerToys.exe',
    'PowerToysRunner.exe',
    '7zFM.exe',
    '7zG.exe',
    'WinRAR.exe',
    'CCleaner64.exe',
    'CCleaner.exe',
    
    # Hardware/OEM
    'ibmpmsvc.exe',         # IBM Power Management
    'ibmpmctl.exe',         # IBM Power Management Control
    'LITSSvc.exe',          # Lenovo IT Support Service
    'LenovoVantageService.exe',
    'DellSupportAssist.exe',
    'HPSupportAssist.exe',
    'AsusSystemControlInterface.exe',
    'AsusCertService.exe',
    'MSIService.exe',
    'PowerMgr.exe',         # Power Management
    'EasyResume.exe',       # Resume utility
    'nviewMain.exe',        # NVIDIA nView
    'nviewMain64.exe',
    'AbletonAudioCpl.exe',  # Ableton Audio
    
    # PROC-WOLF ITSELF!
    'ProcWolf.exe',
    'ProcWolfService.exe',
    'ProcWolfCLI.exe',
    'proc_wolf.exe',
    'proc-wolf.exe',
]

# Paths that indicate legitimate software
SAFE_PATHS = [
    'C:\\Windows\\',
    'C:\\Windows\\System32\\',
    'C:\\Windows\\SysWOW64\\',
    'C:\\Windows\\WinSxS\\',
    'C:\\Windows\\Microsoft.NET\\',
    'C:\\Program Files\\',
    'C:\\Program Files (x86)\\',
    'C:\\ProgramData\\Microsoft\\',
]

# Microsoft signature subjects
MICROSOFT_SIGNATURES = [
    'Microsoft Corporation',
    'Microsoft Windows',
    'Microsoft Windows Publisher',
    'Microsoft Windows Hardware Compatibility Publisher',
]

def is_system_process(process_name):
    """Check if a process is a Windows system process"""
    if not process_name:
        return False
    
    name_lower = process_name.lower()
    
    # Check all our lists
    all_system = (
        WINDOWS_CORE_PROCESSES +
        WINDOWS_SERVICE_PROCESSES +
        WINDOWS_MODERN_PROCESSES +
        WINDOWS_DEFENDER_PROCESSES +
        WINDOWS_NETWORK_PROCESSES +
        GRAPHICS_PROCESSES +
        LEGITIMATE_SOFTWARE
    )
    
    for proc in all_system:
        if name_lower == proc.lower():
            return True
    
    return False

def is_safe_path(path):
    """Check if a path is in a safe location"""
    if not path:
        return False
    
    for safe_path in SAFE_PATHS:
        if path.lower().startswith(safe_path.lower()):
            return True
    
    return False

def get_all_whitelisted_processes():
    """Get complete list of all whitelisted processes"""
    return (
        WINDOWS_CORE_PROCESSES +
        WINDOWS_SERVICE_PROCESSES +
        WINDOWS_MODERN_PROCESSES +
        WINDOWS_DEFENDER_PROCESSES +
        WINDOWS_NETWORK_PROCESSES +
        GRAPHICS_PROCESSES +
        LEGITIMATE_SOFTWARE
    )
