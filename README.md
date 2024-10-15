# VT-Sigma
This script retrieves crowdsourced Sigma rules for hash detection from VirusTotal and converts them into Kusto queries.

Required Libraries:
- colorist
- argparse
- pysigma
- pysigma-backend-kusto

Usage:
`python .\VT-Sigma.py -H <SHA-256|SHA-1|MD5>`
