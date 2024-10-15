# VT-Sigma
This script retrieves crowdsourced Sigma rules for hash detection from VirusTotal and converts them into Kusto queries.

Required Libraries:
- colorist
- argparse
- pysigma
- pysigma-backend-kusto

Usage:
`python .\VT-Sigma.py -H <SHA-256|SHA-1|MD5>`

Example:
```
PS C:\> python .\VT-Sigma.py -H d9a8c4fc94655f47a127b45c71e426d0f2057b6faf78fb7b86ee2995f7def41d
[+] Valid SHA-256 hash
[+] Extracting Hash results "d9a8c4fc94655f47a127b45c71e426d0f2057b6faf78fb7b86ee2995f7def41d"
[+] Exporting IOC behaviour...
[+] Sigma rules found: 1
[1] Exporting Sigma rule "PUA - Rclone Execution"
[+] Exporting Kusto queries... "PUA - Rclone Execution"
```
