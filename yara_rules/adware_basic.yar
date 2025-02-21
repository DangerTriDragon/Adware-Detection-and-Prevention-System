/*
    Enhanced Adware Detection Rules
    Includes broader detection for browser modifications, tracking, autorun persistence, and aggressive ad behaviors.
*/

rule AdwareBasic {
    meta:
        description = "Detects basic adware patterns"
        severity = "medium"
    strings:
        $ad1 = "advertisement" nocase
        $ad2 = "popup" nocase
        $ad3 = "clicktrack" nocase
        $suspicious1 = "AutoStart" nocase
        $suspicious2 = "TaskScheduler" nocase
    condition:
        2 of ($ad*) or any of ($suspicious*)
}

rule BrowserModification {
    meta:
        description = "Detects browser settings modifications"
        severity = "high"
    strings:
        // Registry modifications
        $browser1 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" nocase
        $browser2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Internet Explorer\\Main" nocase
        $browser3 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Google\\Chrome" nocase
        $browser4 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Mozilla\\Firefox" nocase
        $browser5 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Edge\\Main" nocase
        
        // Homepage and search modifications
        $home1 = "SetHomePage" nocase
        $home2 = "default_search_provider" nocase
        $home3 = "URLSearchHooks" nocase
        $home4 = "NewTabPageLocation" nocase
        
        // Extensions and plugins
        $ext1 = "chrome/extension" nocase
        $ext2 = "firefox/extensions" nocase
        $ext3 = "addons" nocase
    condition:
        2 of them
}

rule UnwantedInstaller {
    meta:
        description = "Detects unwanted software installers"
        severity = "high"
    strings:
        $bundle1 = "bundled" nocase
        $bundle2 = "special offer" nocase
        $bundle3 = "recommended" nocase
        $bundle4 = "partner software" nocase
        $bundle5 = "opt-out" nocase
        
        // Installation paths
        $install1 = "Program Files" nocase
        $install2 = "AppData\\Local" nocase
        $install3 = "Temp\\" nocase
        
        // Installer behaviors
        $behavior1 = "InstallService" nocase
        $behavior2 = "RunOnStartup" nocase
        $behavior3 = "RegisterService" nocase
        $behavior4 = "SilentInstall" nocase
    condition:
        (2 of ($bundle*) and any of ($install*)) or
        (any of ($bundle*) and 2 of ($behavior*))
}

rule TrackingBehavior {
    meta:
        description = "Detects tracking and data collection behavior"
        severity = "medium"
    strings:
        $track1 = "tracking_pixel" nocase
        $track2 = "beacon.js" nocase
        $track3 = "analytics" nocase
        $track4 = "google-analytics.com" nocase
        $track5 = "facebook.com/tr" nocase
        $track6 = "session-replay" nocase
        
        // Fingerprinting techniques
        $fingerprint1 = "canvas.toDataURL" nocase
        $fingerprint2 = "navigator.plugins" nocase
        $fingerprint3 = "device_fingerprint" nocase
        
        // Cookies and storage
        $storage1 = "localStorage" nocase
        $storage2 = "sessionStorage" nocase
        $storage3 = "setCookie" nocase
    condition:
        2 of ($track*) or
        2 of ($fingerprint*) or
        (any of ($track*) and any of ($storage*))
}

rule AggressiveAds {
    meta:
        description = "Detects aggressive advertising behavior"
        severity = "high"
    strings:
        $popup1 = "window.open" nocase
        $popup2 = "popupwindow" nocase
        $popup3 = "showModalDialog" nocase
        
        // Ad injection
        $inject1 = "innerHTML" nocase
        $inject2 = "document.write" nocase
        $inject3 = "createElement" nocase
        
        // Ad networks
        $network1 = "adsystem" nocase
        $network2 = "adserver" nocase
        $network3 = "adnetwork" nocase
        $network4 = "sponsored_ads" nocase
        
        // Aggressive behaviors
        $aggressive1 = "notification.requestPermission" nocase
        $aggressive2 = "Notification.permission" nocase
        $aggressive3 = "push_subscription" nocase
    condition:
        (2 of ($popup*) and any of ($inject*)) or
        (2 of ($network*) and any of ($aggressive*)) or
        3 of them
}

rule SuspiciousAutorun {
    meta:
        description = "Detects suspicious autorun behaviors"
        severity = "critical"
    strings:
        // Registry autorun locations
        $reg1 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg2 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $reg3 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" nocase
        $reg4 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" nocase
        $reg5 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce" nocase
        
        // Startup folders
        $startup1 = "\\Start Menu\\Programs\\Startup" nocase
        $startup2 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" nocase
        
        // Task scheduling
        $task1 = "schtasks" nocase
        $task2 = "TaskScheduler" nocase
        $task3 = "at.exe" nocase
        $task4 = "wmic process call create" nocase
        $task5 = "powershell -command" nocase
    condition:
        any of ($reg*) or
        any of ($startup*) or
        2 of ($task*)
}