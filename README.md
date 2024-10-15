# VT-Sigma
Retrieves crowdsourced Sigma rules for hash detection from VirusTotal and converts them into Kusto queries.

Required Libraries:
- colorist
- argparse
- pysigma
- pysigma-backend-kusto

Usage:
`python .\VT-Sigma.py -H <SHA-256|SHA-1|MD5>`

---
Example:
```
PS C:\> python .\VT-Sigma.py -H d9a8c4fc94655f47a127b45c71e426d0f2057b6faf78fb7b86ee2995f7def41d
[+] Valid SHA-256 hash
[+] Exporting Hash results "d9a8c4fc94655f47a127b45c71e426d0f2057b6faf78fb7b86ee2995f7def41d"
[+] Exporting IOC behaviour...
[+] Sigma rules found: 1
[1] Exporting Sigma rule "PUA - Rclone Execution"
[+] Exporting Kusto queries... "PUA - Rclone Execution"
```
Sigma Rule:
```
title: PUA - Rclone Execution
id: e37db05d-d1f9-49c8-b464-cee1a4b11638
related:
    - id: a0d63692-a531-4912-ad39-4393325b2a9c
      type: obsolete
    - id: cb7286ba-f207-44ab-b9e6-760d82b84253
      type: obsolete
status: test
description: Detects execution of RClone utility for exfiltration as used by various ransomwares strains like REvil, Conti, FiveHands, etc
references:
    - https://research.nccgroup.com/2021/05/27/detecting-rclone-an-effective-tool-for-exfiltration/
    - https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware
    - https://us-cert.cisa.gov/ncas/analysis-reports/ar21-126a
    - https://labs.sentinelone.com/egregor-raas-continues-the-chaos-with-cobalt-strike-and-rclone
    - https://www.splunk.com/en_us/blog/security/darkside-ransomware-splunk-threat-update-and-detections.html
author: Bhabesh Raj, Sittikorn S, Aaron Greetham (@beardofbinary) - NCC Group
date: 2021-05-10
modified: 2023-03-05
tags:
    - attack.exfiltration
    - attack.t1567.002
logsource:
    product: windows
    category: process_creation
detection:
    selection_specific_options:
        CommandLine|contains|all:
            - '--config '
            - '--no-check-certificate '
            - ' copy '
    selection_rclone_img:
        - Image|endswith: '\rclone.exe'
        - Description: 'Rsync for cloud storage'
    selection_rclone_cli:
        CommandLine|contains:
            - 'pass'
            - 'user'
            - 'copy'
            - 'sync'
            - 'config'
            - 'lsd'
            - 'remote'
            - 'ls'
            - 'mega'
            - 'pcloud'
            - 'ftp'
            - 'ignore-existing'
            - 'auto-confirm'
            - 'transfers'
            - 'multi-thread-streams'
            - 'no-check-certificate '
    condition: selection_specific_options or all of selection_rclone_*
fields:
    - CommandLine
    - ParentCommandLine
    - Details
falsepositives:
    - Unknown
level: high
```
Kusto query:
```
//Kusto query: PUA - Rclone Execution
DeviceProcessEvents
| where (ProcessCommandLine contains "--config " and ProcessCommandLine contains "--no-check-certificate " and ProcessCommandLine contains " copy ") or ((FolderPath endswith "\\rclone.exe" or ProcessVersionInfoFileDescription =~ "Rsync for cloud storage") and (ProcessCommandLine contains "pass" or ProcessCommandLine contains "user" or ProcessCommandLine contains "copy" or ProcessCommandLine contains "sync" or ProcessCommandLine contains "config" or ProcessCommandLine contains "lsd" or ProcessCommandLine contains "remote" or ProcessCommandLine contains "ls" or ProcessCommandLine contains "mega" or ProcessCommandLine contains "pcloud" or ProcessCommandLine contains "ftp" or ProcessCommandLine contains "ignore-existing" or ProcessCommandLine contains "auto-confirm" or ProcessCommandLine contains "transfers" or ProcessCommandLine contains "multi-thread-streams" or ProcessCommandLine contains "no-check-certificate "))
```
