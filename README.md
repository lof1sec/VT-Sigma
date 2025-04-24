# VT-Sigma
Retrieves crowdsourced Sigma rules for hash detection from VirusTotal and converts them into Kusto (KQL) or Crowdstrike (CQL - Logscale) queries.

Required Libraries:
- colorist
- argparse
- pysigma
- pysigma-backend-kusto
- pysigma-backend-crowdstrike

Required API:
- Virustotal API Token (standard free end-user account)

Usage:
`python .\VT-Sigma.py -H <SHA-256|SHA-1|MD5> -D "FolderName" -Q {all, kusto, crowdstrike}`

---
Example:
```bash
PS C:\> python .\VT-Sigma.py -H 5ed6eb40580f8a5e3983936c51a00ae8f6081c63ce62ac84abb269da7b5fe01e -D "Generic-Malware-5" -Q all
[+] Valid SHA-256 hash
[+] Exporting Hash results "5ed6eb40580f8a5e3983936c51a00ae8f6081c63ce62ac84abb269da7b5fe01e"
[+] Exporting IOC behaviour...
[+] Sigma rules found: 5
[1] Exporting Sigma rule "Suspicious Volume Shadow Copy Vsstrace.dll Load"
[2] Exporting Sigma rule "Wow6432Node CurrentVersion Autorun Keys Modification"
[3] Exporting Sigma rule "DNS Query To Remote Access Software Domain From Non-Browser App"
[4] Exporting Sigma rule "CurrentVersion Autorun Keys Modification"
[5] Exporting Sigma rule "Potential Raspberry Robin Registry Set Internet Settings ZoneMap"
[+] Exporting Kusto query... "Potential Raspberry Robin Registry Set Internet Settings ZoneMap"
[+] Exporting Kusto query... "CurrentVersion Autorun Keys Modification"
[+] Exporting Kusto query... "Suspicious Volume Shadow Copy Vsstrace.dll Load"
[!] Error exporting Kusto query... "DNS Query To Remote Access Software Domain From Non-Browser App", Error:"Unable to determine table name for category: dns_query, category is not yet supported by the pipeline.  Please provide the 'query_table' parameter to the pipeline instead."
[+] Exporting Kusto query... "Wow6432Node CurrentVersion Autorun Keys Modification"
[+] Exporting CQL(Crowdstrike) query... "Potential Raspberry Robin Registry Set Internet Settings ZoneMap"
[+] Exporting CQL(Crowdstrike) query... "CurrentVersion Autorun Keys Modification"
[+] Exporting CQL(Crowdstrike) query... "Suspicious Volume Shadow Copy Vsstrace.dll Load"
[!] Error exporting CQL(Crowdstrike) query... "DNS Query To Remote Access Software Domain From Non-Browser App", Error:"Only file name of image is available in CrowdStrike Query Language events."
[+] Exporting CQL(Crowdstrike) query... "Wow6432Node CurrentVersion Autorun Keys Modification"
```
Sigma Rule:
```xml
title: Potential Raspberry Robin Registry Set Internet Settings ZoneMap
id: 16a4c7b3-4681-49d0-8d58-3e9b796dcb43
status: experimental
description: |
    Detects registry modifications related to the proxy configuration of the system, potentially associated with the Raspberry Robin malware, as seen in campaigns running in Q1 2024.
    Raspberry Robin may alter proxy settings to circumvent security measures, ensuring unhindered connection with Command and Control servers for maintaining control over compromised systems if there are any proxy settings that are blocking connections.
references:
    - https://tria.ge/240225-jlylpafb24/behavioral1/analog?main_event=Registry&op=SetValueKeyInt
    - https://tria.ge/240307-1hlldsfe7t/behavioral2/analog?main_event=Registry&op=SetValueKeyInt
    - https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.InternetExplorer::IZ_ProxyByPass
    - https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.InternetExplorer::IZ_UNCAsIntranet
    - https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.InternetExplorer::IZ_IncludeUnspecifiedLocalSites
    - https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.InternetExplorer::SecurityPage_AutoDetect
    - https://bazaar.abuse.ch/browse/signature/RaspberryRobin/
author: Swachchhanda Shrawan Poudel
date: 2024-07-31
tags:
    - detection.emerging-threats
    - attack.t1112
    - attack.defense-evasion
logsource:
    category: registry_set
    product: windows
    definition: 'Requirements: The registry key "\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\" and its sub keys must be monitored'
detection:
    selection_registry_image:
        - Image|contains:
              - '\AppData\Local\Temp\'
              - '\Downloads\'
              - '\Users\Public\'
              - '\Windows\Temp\'
        - Image|endswith: '\control.exe'
    selection_registry_object:
        TargetObject|contains: '\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\'
    selection_value_enable:
        TargetObject|endswith:
            - '\IntranetName'
            - '\ProxyByPass'
            - '\UNCAsIntranet'
        Details|contains: 'DWORD (0x00000001)'
    selection_value_disable:
        TargetObject|endswith: '\AutoDetect'
        Details|contains: 'DWORD (0x00000000)'
    condition: all of selection_registry_* and 1 of selection_value_*
falsepositives:
    - Unknown
# Note: can be upgraded to medium after an initial baseline
level: low
```
Kusto query:
```
//Kusto query: Potential Raspberry Robin Registry Set Internet Settings ZoneMap
DeviceRegistryEvents
| where (((InitiatingProcessFolderPath contains "\\AppData\\Local\\Temp\\" or InitiatingProcessFolderPath contains "\\Downloads\\" or InitiatingProcessFolderPath contains "\\Users\\Public\\" or InitiatingProcessFolderPath contains "\\Windows\\Temp\\") or InitiatingProcessFolderPath endswith "\\control.exe") and RegistryKey endswith "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap*") and (((RegistryKey endswith "\\IntranetName" or RegistryKey endswith "\\ProxyByPass" or RegistryKey endswith "\\UNCAsIntranet") and RegistryValueData contains "DWORD (0x00000001)") or (RegistryKey endswith "\\AutoDetect" and RegistryValueData contains "DWORD (0x00000000)"))
```
Crowdstrike query (LogScale):
```
//CQL query: Potential Raspberry Robin Registry Set Internet Settings ZoneMap
Image=/\\AppData\\Local\\Temp\\/i or Image=/\\Downloads\\/i or Image=/\\Users\\Public\\/i or Image=/\\Windows\\Temp\\/i or Image=/\\control\.exe$/i TargetObject=/\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\/i (TargetObject=/\\IntranetName$/i or TargetObject=/\\ProxyByPass$/i or TargetObject=/\\UNCAsIntranet$/i Details=/DWORD \(0x00000001\)/i) or (TargetObject=/\\AutoDetect$/i Details=/DWORD \(0x00000000\)/i)
```
