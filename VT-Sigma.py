import requests, json, argparse, os, sys, re, sigma
from colorist import Color, BrightColor
from sigma.rule import SigmaRule
from sigma.backends.kusto import KustoBackend
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
from sigma.backends.crowdstrike import LogScaleBackend
from sigma.pipelines.crowdstrike import crowdstrike_falcon_pipeline

# JLC - 2024
# Virustotal API token
token = "API Token Here"

# DO NOT MODIFY FROM HERE!!...
# Script arguments and variables
parser = argparse.ArgumentParser("python VT.py")
parser.add_argument("--hash","-H", required=True, type=str,  help="SHA-256, SHA-1 or MD5 identifying the file", metavar="HASH")
parser.add_argument("--dirname","-D", required=True, type=str,  help="A folder created by the script to store hash analysis, rules, and behavior data.", metavar="FOLDER")
parser.add_argument("--query","-Q", choices=["all", "kusto", "crowdstrike"], required=True, help='Choose one of the following query transformation: all, kusto, or crowdstrike')
args = parser.parse_args()
ioc = args.hash
folder = args.dirname
sigma_query = args.query
url =  "https://www.virustotal.com/api/v3/"
headers = {"accept": "application/json","x-apikey": token}
directory = f'{folder}'
directory_sigma = f'{directory}/sigma'
directory_kusto = f'{directory}/querys'

# Hash type validation
def hash_validator(*args):
    if len(ioc) == 64:
        print(f'{Color.GREEN}[+]{Color.OFF} Valid SHA-256 hash')
    elif len(ioc) == 40:
        print(f'{Color.GREEN}[+]{Color.OFF} Valid SHA-1 hash')
    elif len(ioc) == 32:
        print(f'{Color.GREEN}[+]{Color.OFF} Valid MD5 hash')
    else:
        print(f'{Color.RED}[!]{Color.OFF} Invalid hash')
        sys.exit(1)

# Sigma rule to Kusto query transformation
def sigma_kusto():
    yml_list = os.listdir(directory_sigma)
    os.makedirs(directory_kusto, exist_ok=True)
    for rules in yml_list:
        with open(directory_sigma + '/' + rules, 'r') as file:
            data = file.read()
            sigma_name = re.search("title: (.+)", data)
            sigma_title = sigma_name.group(1)
            rule = SigmaRule.from_yaml(data)
            xdr_pipeline = microsoft_xdr_pipeline()
            backend = KustoBackend(processing_pipeline=xdr_pipeline)
            try:
                file_path = os.path.join(directory_kusto, 'kusto.kql')
                backend.convert_rule(rule)[0]
                f = open(file_path, "a")
                f.write(f'//Kusto query: {sigma_title}\n')
                f.write(backend.convert_rule(rule)[0])
                f.write('\n')
                f.write('\n')
                f.close()
                print(f'{Color.GREEN}[+]{Color.OFF} Exporting Kusto query... {Color.YELLOW}"{sigma_title}"{Color.OFF}')
            except Exception as sigma_error:
                print(f'{Color.RED}[!]{Color.OFF} Error exporting Kusto query... {Color.YELLOW}"{sigma_title}"{Color.OFF}, {Color.RED}Error:{Color.OFF}"{sigma_error}"')

# Sigma rule to CQL (crowdstrike) query transformation
def sigma_crwd():
    yml_list = os.listdir(directory_sigma)
    os.makedirs(directory_kusto, exist_ok=True)
    for rules in yml_list:
        with open(directory_sigma + '/' + rules, 'r') as file:
            data = file.read()
            sigma_name = re.search("title: (.+)", data)
            sigma_title = sigma_name.group(1)
            rule = SigmaRule.from_yaml(data)
            crowd_pipeline = crowdstrike_falcon_pipeline()
            backend_crwd = LogScaleBackend(processing_pipeline=crowd_pipeline)
            try:
                file_path = os.path.join(directory_kusto, 'crowdstrike.cql')
                backend_crwd.convert_rule(rule)[0]
                f = open(file_path, "a")
                f.write(f'//CQL query: {sigma_title}\n')
                f.write(backend_crwd.convert_rule(rule)[0])
                f.write('\n')
                f.write('\n')
                f.close()
                print(f'{Color.GREEN}[+]{Color.OFF} Exporting CQL(Crowdstrike) query... {Color.YELLOW}"{sigma_title}"{Color.OFF}')
            except Exception as sigma_error:
                print(f'{Color.RED}[!]{Color.OFF} Error exporting CQL(Crowdstrike) query... {Color.YELLOW}"{sigma_title}"{Color.OFF}, {Color.RED}Error:{Color.OFF}"{sigma_error}"')

# Extracting hash results from VT
def analysis(*args):
    urla = url + "files/" + ioc
    r = requests.get(urla, headers=headers)
    try:
        analysis = json.loads(r.text)
        analysis["data"]["attributes"]
    except KeyError:
        print(f'{Color.RED}[!]{Color.OFF} Hash not found in Virustotal')
        sys.exit(1)
    filename = f'Analysis-{ioc}.json'
    file_path = os.path.join(directory, filename)
    os.makedirs(directory, exist_ok=True)
    f = open(file_path, "w")
    f.write(r.text)
    f.close()
    print(f'{Color.GREEN}[+]{Color.OFF} Exporting Hash results "{ioc}"')
    return r.text

# Sigma rule identification
def sigma_summary(sigma):
    sigma = json.loads(sigma)
    try:
        sigma_len = len(sigma["data"]["attributes"]["sigma_analysis_results"])
        print(f'{Color.GREEN}[+]{Color.OFF} Sigma rules found: {sigma_len}')
    except Exception:
        print(f'{Color.RED}[!]{Color.OFF} Sigma rules found: 0')
        sys.exit(1)

# Sigma Rules Extraction in YAML Format
def sigma_extract(sigma):
    sigma = json.loads(sigma)
    sigma_len = len(sigma["data"]["attributes"]["sigma_analysis_results"])
    os.makedirs(directory_sigma, exist_ok=True)
    for x in range(sigma_len):
        sigma_id = sigma["data"]["attributes"]["sigma_analysis_results"][x]["rule_id"]
        urle = url + "sigma_rules/" + sigma_id
        r = requests.get(urle, headers=headers)
        sigma_json = json.loads(r.text)
        sigma_name_space = sigma_json["data"]["attributes"]["title"]
        sigma_name = re.sub(' ','_', sigma_name_space)
        sigma_rule = sigma_json["data"]["attributes"]["rule"]
        sigma_rule_id_group = re.search('id: ([0-9a-z-]+)', sigma_rule)
        sigma_rule_id = sigma_rule_id_group.group(1)
        filename = f'SIGMA_{sigma_rule_id}_{sigma_name}.yml'
        file_path = os.path.join(directory_sigma, filename)
        f = open(file_path, "w")
        f.write(sigma_rule)
        f.close()
        print(f'{Color.YELLOW}[{x + 1}]{Color.OFF} Exporting Sigma rule {BrightColor.CYAN}"{sigma_name_space}"{BrightColor.OFF}')

# Hash behaviour report
def behaviour(*args):
    urlb = url + "files/" + ioc + "/behaviour_summary"
    r = requests.get(urlb, headers=headers)
    filename = f'Behaviour-{ioc}.json'
    file_path = os.path.join(directory, filename)
    f = open(file_path, "w")
    f.write(r.text)
    f.close()
    print(f'{Color.GREEN}[+]{Color.OFF} Exporting IOC behaviour...')

# Main flow execution
def main():
    hash_validator(ioc)
    sigma = analysis(ioc)
    behaviour(ioc)
    sigma_summary(sigma)
    sigma_extract(sigma)
    if sigma_query == "all":
        sigma_kusto()
        sigma_crwd()
        sys.exit(0)
    elif sigma_query == "kusto":
        sigma_kusto()
        sys.exit(0)
    elif sigma_query == "crowdstrike":
        sigma_crwd()
        sys.exit(0)

if __name__ == '__main__':
	main()
