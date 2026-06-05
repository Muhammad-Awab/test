import boto3
import socket
import csv
import os
import ssl
import glob
import json
import subprocess
from datetime import datetime

os.environ["PYTHONHTTPSVERIFY"] = "0"
ssl._create_default_https_context = ssl._create_unverified_context

HOSTNAMES_FILE = "hostnames.txt"
ROLE_NAME      = "G-ROLE-AWS-ENT-WAFADMIN-RO"
OUT_FILE       = "waf_apigw_report_" + datetime.now().strftime("%Y%m%d_%H%M") + ".csv"

REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "ap-southeast-1", "ap-northeast-1"
]

# Exact columns from your screenshot
FIELDS = [
    "Custom_Domain_Name",
    "Account_ID",
    "Account_Name",
    "API_Name",
    "API_ID",
    "API_Type",
    "WebACL_Name",
    "WebACL_ARN",
    "Region",
    "WAF_Protected",
    "Notes"
]

def empty_result(hostname):
    r = {f: "" for f in FIELDS}
    r["Custom_Domain_Name"] = hostname
    r["WAF_Protected"]      = "NO"
    r["Notes"]              = "Not found in any account"
    return r

def get_sso_token():
    files = glob.glob(os.path.expanduser("~/.aws/sso/cache/*.json"))
    for f in files:
        try:
            with open(f) as fh:
                data = json.load(fh)
                if "accessToken" in data:
                    return data["accessToken"]
        except:
            pass
    return None

def run_cmd(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.stdout.strip():
            return json.loads(r.stdout)
        return {}
    except:
        return {}

def get_all_accounts(token):
    print("Fetching all accounts...")
    accounts = []
    next_tok = None
    while True:
        cmd = ["aws", "sso", "list-accounts",
               "--access-token", token,
               "--region", "us-east-1",
               "--no-verify-ssl", "--output", "json"]
        if next_tok:
            cmd += ["--next-token", next_tok]
        data     = run_cmd(cmd)
        batch    = data.get("accountList", [])
        accounts.extend(batch)
        next_tok = data.get("nextToken")
        if not next_tok:
            break
    print("  Found " + str(len(accounts)) + " accounts")
    return accounts

def get_creds(token, account_id):
    data = run_cmd([
        "aws", "sso", "get-role-credentials",
        "--account-id", account_id,
        "--role-name",  ROLE_NAME,
        "--access-token", token,
        "--region", "us-east-1",
        "--no-verify-ssl", "--output", "json"
    ])
    return data.get("roleCredentials")

def make_session(creds):
    return boto3.Session(
        aws_access_key_id     = creds["accessKeyId"],
        aws_secret_access_key = creds["secretAccessKey"],
        aws_session_token     = creds["sessionToken"]
    )

def get_waf_acls(session, region, scope="REGIONAL"):
    acls = {}
    try:
        waf  = session.client("wafv2", region_name=region, verify=False)
        resp = waf.list_web_acls(Scope=scope, Limit=100)
        for acl in resp.get("WebACLs", []):
            acls[acl["ARN"]] = acl["Name"]
    except:
        pass
    return acls

def get_apigw_custom_domains(session, acc_id, acc_name):
    found = []

    for region in REGIONS:
        # REST API (v1) custom domains
        try:
            client  = session.client("apigateway", region_name=region, verify=False)
            resp    = client.get_domain_names(limit=500)
            domains = resp.get("items", [])

            if domains:
                print("    API GW v1 domains in " + region + ": " + str(len(domains)))

            for domain in domains:
                dn = domain.get("domainName", "")

                # Get the WAF WebACL if any
                waf_arn  = ""
                waf_name = ""
                try:
                    tags = client.get_tags(
                        resourceArn="arn:aws:apigateway:" + region + "::/domainnames/" + dn
                    )
                except:
                    pass

                # Get mappings to find API ID and name
                api_id   = ""
                api_name = ""
                api_type = "REST"
                try:
                    mappings = client.get_base_path_mappings(
                        domainName=dn, limit=500
                    )
                    for mapping in mappings.get("items", []):
                        a_id = mapping.get("restApiId", "")
                        if a_id:
                            try:
                                api_info = client.get_rest_api(restApiId=a_id)
                                api_id   = a_id
                                api_name = api_info.get("name", "")
                            except:
                                api_id = a_id
                            break
                except:
                    pass

                # Check WAF association via WebACL
                waf_acls = get_waf_acls(session, region, "REGIONAL")
                waf_cf   = get_waf_acls(session, "us-east-1", "CLOUDFRONT")
                all_acls = {**waf_acls, **waf_cf}

                # Check if domain is protected by any WAF
                for arn, name in all_acls.items():
                    try:
                        waf_client = session.client(
                            "wafv2",
                            region_name=region if "CLOUDFRONT" not in arn else "us-east-1",
                            verify=False
                        )
                        res = waf_client.list_resources_for_web_acl(WebACLArn=arn)
                        for r_arn in res.get("ResourceArns", []):
                            if dn in r_arn or api_id in r_arn:
                                waf_arn  = arn
                                waf_name = name
                                break
                    except:
                        pass
                    if waf_arn:
                        break

                found.append({
                    "Custom_Domain_Name": dn,
                    "Account_ID":         acc_id,
                    "Account_Name":       acc_name,
                    "API_Name":           api_name,
                    "API_ID":             api_id,
                    "API_Type":           api_type,
                    "WebACL_Name":        waf_name,
                    "WebACL_ARN":         waf_arn,
                    "Region":             region,
                    "WAF_Protected":      "YES" if waf_name else "NO",
                    "Notes":              ""
                })

        except Exception as e:
            pass

        # HTTP API (v2) custom domains
        try:
            client  = session.client("apigatewayv2", region_name=region, verify=False)
            resp    = client.get_domain_names()
            domains = resp.get("Items", [])

            if domains:
                print("    API GW v2 domains in " + region + ": " + str(len(domains)))

            for domain in domains:
                dn = domain.get("DomainName", "")

                api_id   = ""
                api_name = ""
                api_type = "HTTP"

                # Get mappings
                try:
                    mappings = client.get_api_mappings(DomainName=dn)
                    for mapping in mappings.get("Items", []):
                        a_id = mapping.get("ApiId", "")
                        if a_id:
                            try:
                                api_info = client.get_api(ApiId=a_id)
                                api_id   = a_id
                                api_name = api_info.get("Name", "")
                            except:
                                api_id = a_id
                            break
                except:
                    pass

                # Check WAF
                waf_name = ""
                waf_arn  = ""
                waf_acls = get_waf_acls(session, region, "REGIONAL")
                for arn, name in waf_acls.items():
                    try:
                        waf_client = session.client(
                            "wafv2", region_name=region, verify=False
                        )
                        res = waf_client.list_resources_for_web_acl(WebACLArn=arn)
                        for r_arn in res.get("ResourceArns", []):
                            if api_id in r_arn or dn in r_arn:
                                waf_arn  = arn
                                waf_name = name
                                break
                    except:
                        pass
                    if waf_arn:
                        break

                found.append({
                    "Custom_Domain_Name": dn,
                    "Account_ID":         acc_id,
                    "Account_Name":       acc_name,
                    "API_Name":           api_name,
                    "API_ID":             api_id,
                    "API_Type":           api_type,
                    "WebACL_Name":        waf_name,
                    "WebACL_ARN":         waf_arn,
                    "Region":             region,
                    "WAF_Protected":      "YES" if waf_name else "NO",
                    "Notes":              ""
                })

        except:
            pass

    return found

# MAIN
print("=" * 60)
print("API Gateway WAF Coverage Report")
print("Output columns: Custom Domain | Account | API Name | API ID | WebACL | Region")
print("=" * 60)

# Load hostnames
with open(HOSTNAMES_FILE, encoding="utf-8-sig") as f:
    hostnames = [l.strip().lower() for l in f if l.strip()]
print("Loaded " + str(len(hostnames)) + " hostnames\n")

token = get_sso_token()
if not token:
    print("ERROR: Run: aws sso login --profile waf-search1 --no-verify-ssl")
    exit(1)
print("SSO token OK")

accounts = get_all_accounts(token)
if not accounts:
    print("ERROR: No accounts found!")
    exit(1)

# Collect ALL API Gateway custom domains across all accounts
all_domains = []

for i, account in enumerate(accounts):
    acc_id   = account["accountId"]
    acc_name = account.get("accountName", "unknown")

    if i % 20 == 0:
        print("[" + str(i) + "/" + str(len(accounts)) + "] Scanning...")

    creds = get_creds(token, acc_id)
    if not creds:
        continue

    session = make_session(creds)
    domains = get_apigw_custom_domains(session, acc_id, acc_name)

    if domains:
        print("  Account " + acc_name + " has " + str(len(domains)) + " API GW custom domains")
        all_domains.extend(domains)

print("\nTotal API GW custom domains found: " + str(len(all_domains)))

# Match to hostnames
print("\nMatching to your hostnames list...")
matched   = []
unmatched = []

for hostname in hostnames:
    match = None
    for domain in all_domains:
        if hostname == domain["Custom_Domain_Name"].lower():
            match = domain
            break

    if match:
        matched.append(match)
        status = "YES" if match["WAF_Protected"] == "YES" else "NO"
        print("  MATCHED: " + hostname + " -> WAF:" + status + " | " + match["API_Name"])
    else:
        row = empty_result(hostname)
        unmatched.append(row)
        print("  NOT FOUND: " + hostname)

# Write CSV — matched first then unmatched
rows = matched + unmatched

with open(OUT_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=FIELDS)
    writer.writeheader()
    for row in rows:
        writer.writerow({field: row.get(field, "") for field in FIELDS})

protected = sum(1 for r in matched if r["WAF_Protected"] == "YES")

print("\n" + "=" * 60)
print("FINAL SUMMARY")
print("  Total hostnames   : " + str(len(hostnames)))
print("  Matched to API GW : " + str(len(matched)))
print("  WAF protected     : " + str(protected))
print("  NOT protected     : " + str(len(matched) - protected))
print("  Not found         : " + str(len(unmatched)))
print("  Report saved      : " + OUT_FILE)
print("=" * 60)
