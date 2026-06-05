import boto3
import socket
import csv
import os
import ssl
import glob
import json
import subprocess
import urllib3
from datetime import datetime

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
os.environ["PYTHONHTTPSVERIFY"] = "0"
ssl._create_default_https_context = ssl._create_unverified_context

HOSTNAMES_FILE = "hostnames.txt"
ROLE_NAME      = "G-ROLE-AWS-ENT-WAFADMIN-RO"
OUT_FILE       = "waf_apigw_report_" + datetime.now().strftime("%Y%m%d_%H%M") + ".csv"

REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "ap-southeast-1", "ap-northeast-1"
]

FIELDS = [
    "Custom_Domain_Name",
    "Account_ID",
    "Account_Name",
    "API_Name",
    "API_ID",
    "API_Type",
    "Stage_Name",
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

def get_all_waf_acls(session, region):
    """Get all WAF WebACLs in a region with their associated resources."""
    waf_map = {}
    try:
        waf  = session.client("wafv2", region_name=region, verify=False)
        resp = waf.list_web_acls(Scope="REGIONAL", Limit=100)
        for acl in resp.get("WebACLs", []):
            try:
                res = waf.list_resources_for_web_acl(WebACLArn=acl["ARN"])
                for r_arn in res.get("ResourceArns", []):
                    waf_map[r_arn] = {
                        "name": acl["Name"],
                        "arn":  acl["ARN"]
                    }
            except:
                pass
    except:
        pass
    return waf_map

def get_cf_waf_acls(session):
    """Get all CloudFront WAF WebACLs."""
    waf_map = {}
    try:
        waf  = session.client("wafv2", region_name="us-east-1", verify=False)
        resp = waf.list_web_acls(Scope="CLOUDFRONT", Limit=100)
        for acl in resp.get("WebACLs", []):
            try:
                res = waf.list_resources_for_web_acl(WebACLArn=acl["ARN"])
                for r_arn in res.get("ResourceArns", []):
                    waf_map[r_arn] = {
                        "name": acl["Name"],
                        "arn":  acl["ARN"]
                    }
            except:
                pass
    except:
        pass
    return waf_map

def check_waf_for_api(session, region, api_id, api_type="REST"):
    """
    Check WAF for an API Gateway at multiple levels:
    1. Direct resource ARN
    2. Stage ARN
    3. Any ACL containing the API ID
    """
    waf_name = ""
    waf_arn  = ""
    stages   = []

    try:
        waf     = session.client("wafv2", region_name=region, verify=False)
        acl_resp = waf.list_web_acls(Scope="REGIONAL", Limit=100)

        for acl in acl_resp.get("WebACLs", []):
            acl_name = acl["Name"]
            acl_arn  = acl["ARN"]
            try:
                res = waf.list_resources_for_web_acl(WebACLArn=acl_arn)
                for r_arn in res.get("ResourceArns", []):
                    # Match by API ID in ARN
                    if api_id in r_arn:
                        waf_name = acl_name
                        waf_arn  = acl_arn
                        # Extract stage from ARN if present
                        parts = r_arn.split("/stages/")
                        if len(parts) > 1:
                            stages.append(parts[1])
                        return waf_name, waf_arn, stages
            except:
                pass
    except:
        pass

    # Also check stage-level for REST APIs
    if api_type == "REST":
        try:
            client = session.client("apigateway", region_name=region, verify=False)
            stage_resp = client.get_stages(restApiId=api_id)
            for stage in stage_resp.get("item", []):
                stage_name = stage.get("stageName", "")
                stages.append(stage_name)
                # Stage ARN format for WAF
                stage_arn = (
                    "arn:aws:apigateway:" + region +
                    "::/restapis/" + api_id +
                    "/stages/" + stage_name
                )
                try:
                    waf    = session.client("wafv2", region_name=region, verify=False)
                    acl_resp = waf.list_web_acls(Scope="REGIONAL", Limit=100)
                    for acl in acl_resp.get("WebACLs", []):
                        try:
                            res = waf.list_resources_for_web_acl(
                                WebACLArn=acl["ARN"]
                            )
                            for r_arn in res.get("ResourceArns", []):
                                if r_arn == stage_arn or api_id in r_arn:
                                    waf_name = acl["Name"]
                                    waf_arn  = acl["ARN"]
                                    return waf_name, waf_arn, [stage_name]
                        except:
                            pass
                except:
                    pass
        except:
            pass

    return waf_name, waf_arn, stages

def get_apigw_domains(session, acc_id, acc_name):
    """
    Get ALL API Gateway custom domains from this account
    across all regions, with WAF association details.
    """
    found = []

    for region in REGIONS:

        # REST API v1
        try:
            client = session.client(
                "apigateway", region_name=region, verify=False
            )
            resp   = client.get_domain_names(limit=500)
            domains = resp.get("items", [])

            if domains:
                print("    [" + region + "] REST domains: " + str(len(domains)))

            for domain in domains:
                dn       = domain.get("domainName", "")
                api_id   = ""
                api_name = ""
                stage_name = ""

                # Get base path mappings to find API ID
                try:
                    mappings = client.get_base_path_mappings(
                        domainName=dn, limit=500
                    )
                    for m in mappings.get("items", []):
                        a_id = m.get("restApiId", "")
                        if a_id:
                            stage_name = m.get("stage", "")
                            try:
                                api_info = client.get_rest_api(restApiId=a_id)
                                api_id   = a_id
                                api_name = api_info.get("name", "")
                            except:
                                api_id = a_id
                            break
                except:
                    pass

                # Check WAF
                waf_name = ""
                waf_arn  = ""
                if api_id:
                    waf_name, waf_arn, stg = check_waf_for_api(
                        session, region, api_id, "REST"
                    )
                    if stg and not stage_name:
                        stage_name = ", ".join(stg)

                found.append({
                    "Custom_Domain_Name": dn,
                    "Account_ID":         "'" + acc_id,
                    "Account_Name":       acc_name,
                    "API_Name":           api_name,
                    "API_ID":             api_id,
                    "API_Type":           "REST",
                    "Stage_Name":         stage_name,
                    "WebACL_Name":        waf_name,
                    "WebACL_ARN":         waf_arn,
                    "Region":             region,
                    "WAF_Protected":      "YES" if waf_name else "NO",
                    "Notes":              ""
                })

                status = "WAF:YES" if waf_name else "WAF:NO"
                print("      " + dn + " -> " + api_name + " | " + status)

        except Exception as e:
            pass

        # HTTP API v2
        try:
            client  = session.client(
                "apigatewayv2", region_name=region, verify=False
            )
            resp    = client.get_domain_names()
            domains = resp.get("Items", [])

            if domains:
                print("    [" + region + "] HTTP domains: " + str(len(domains)))

            for domain in domains:
                dn         = domain.get("DomainName", "")
                api_id     = ""
                api_name   = ""
                stage_name = ""

                # Get mappings
                try:
                    mappings = client.get_api_mappings(DomainName=dn)
                    for m in mappings.get("Items", []):
                        a_id = m.get("ApiId", "")
                        if a_id:
                            stage_name = m.get("Stage", "")
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
                if api_id:
                    waf_name, waf_arn, stg = check_waf_for_api(
                        session, region, api_id, "HTTP"
                    )
                    if stg and not stage_name:
                        stage_name = ", ".join(stg)

                found.append({
                    "Custom_Domain_Name": dn,
                    "Account_ID":         "'" + acc_id,
                    "Account_Name":       acc_name,
                    "API_Name":           api_name,
                    "API_ID":             api_id,
                    "API_Type":           "HTTP",
                    "Stage_Name":         stage_name,
                    "WebACL_Name":        waf_name,
                    "WebACL_ARN":         waf_arn,
                    "Region":             region,
                    "WAF_Protected":      "YES" if waf_name else "NO",
                    "Notes":              ""
                })

                status = "WAF:YES" if waf_name else "WAF:NO"
                print("      " + dn + " -> " + api_name + " | " + status)

        except:
            pass

    return found

# MAIN
print("=" * 60)
print("API Gateway WAF Coverage Report")
print("=" * 60)

# Load hostnames
if not os.path.exists(HOSTNAMES_FILE):
    print("ERROR: hostnames.txt not found!")
    exit(1)

with open(HOSTNAMES_FILE, encoding="utf-8-sig") as f:
    hostnames = [l.strip().lower() for l in f if l.strip()]

if not hostnames:
    print("ERROR: hostnames.txt is empty!")
    exit(1)

print("Loaded " + str(len(hostnames)) + " hostnames")

# SSO token
token = get_sso_token()
if not token:
    print("ERROR: No SSO token!")
    print("Run: aws sso login --profile waf-search1 --no-verify-ssl")
    exit(1)
print("SSO token OK")

# Get accounts
accounts = get_all_accounts(token)
if not accounts:
    print("ERROR: No accounts found!")
    exit(1)

# Scan all accounts
all_domains = []

for i, account in enumerate(accounts):
    acc_id   = account["accountId"]
    acc_name = account.get("accountName", "unknown")

    if i % 20 == 0:
        found_count = len(all_domains)
        print("\n[" + str(i) + "/" + str(len(accounts)) + "] Scanning... Domains found so far: " + str(found_count))

    creds = get_creds(token, acc_id)
    if not creds:
        continue

    session = make_session(creds)
    domains = get_apigw_domains(session, acc_id, acc_name)

    if domains:
        print("  Account " + acc_name + " (" + acc_id + "): " + str(len(domains)) + " domains found")
        all_domains.extend(domains)

print("\n\nTotal API GW custom domains found: " + str(len(all_domains)))

# Match to hostnames
print("\nMatching to your hostnames list...")
print("-" * 60)

matched   = []
unmatched = []

for hostname in hostnames:
    match = None

    # Exact match first
    for domain in all_domains:
        if hostname == domain["Custom_Domain_Name"].lower():
            match = domain
            break

    # Partial match if no exact match
    if not match:
        for domain in all_domains:
            dn = domain["Custom_Domain_Name"].lower()
            if hostname in dn or dn in hostname:
                match = domain
                match["Notes"] = "Partial match"
                break

    if match:
        matched.append(match)
        status = "YES" if match["WAF_Protected"] == "YES" else "NO"
        print("MATCHED   : " + hostname)
        print("           Account : " + match["Account_Name"])
        print("           API     : " + match["API_Name"])
        print("           WAF     : " + status + (" (" + match["WebACL_Name"] + ")" if match["WebACL_Name"] else ""))
        print("")
    else:
        row = empty_result(hostname)
        unmatched.append(row)
        print("NOT FOUND : " + hostname)

# Write CSV
print("\nWriting report: " + OUT_FILE)
rows = matched + unmatched

with open(OUT_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=FIELDS)
    writer.writeheader()
    for row in rows:
        writer.writerow({field: row.get(field, "") for field in FIELDS})

# Summary
protected     = sum(1 for r in matched if r["WAF_Protected"] == "YES")
not_protected = sum(1 for r in matched if r["WAF_Protected"] == "NO")

print("\n" + "=" * 60)
print("FINAL SUMMARY")
print("  Total hostnames   : " + str(len(hostnames)))
print("  Matched to API GW : " + str(len(matched)))
print("  WAF protected     : " + str(protected))
print("  Found - NO WAF    : " + str(not_protected))
print("  Not found         : " + str(len(unmatched)))
print("  Report saved      : " + OUT_FILE)
print("=" * 60)
