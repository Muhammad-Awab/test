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

# Suppress all SSL warnings
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

# Final columns as agreed
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
    "WAF_Region",
    "WAF_Managed_By",
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
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
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
        cmd = [
            "aws", "sso", "list-accounts",
            "--access-token", token,
            "--region", "us-east-1",
            "--no-verify-ssl", "--output", "json"
        ]
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

def get_all_waf_acls_in_region(session, region):
    """
    Get ALL WAF WebACLs in region with full details.
    Returns dict: acl_arn -> {name, arn, resources, managed_by}
    """
    acls = {}
    try:
        waf  = session.client("wafv2", region_name=region, verify=False)
        resp = waf.list_web_acls(Scope="REGIONAL", Limit=100)
        for acl in resp.get("WebACLs", []):
            acl_arn  = acl["ARN"]
            acl_name = acl["Name"]

            # Get all resources this WAF protects
            resources = []
            try:
                res = waf.list_resources_for_web_acl(WebACLArn=acl_arn)
                resources = res.get("ResourceArns", [])
            except:
                pass

            # Check if managed by Firewall Manager
            managed_by = "Direct"
            try:
                tags_resp = waf.list_tags_for_resource(ResourceARN=acl_arn)
                tags = tags_resp.get("TagInfoForResource", {}).get("TagList", [])
                for tag in tags:
                    key = tag.get("Key", "").lower()
                    val = tag.get("Value", "").lower()
                    if "firewall" in key or "fms" in key or "firewall" in val:
                        managed_by = "Firewall Manager"
                        break
                    if "third" in key or "external" in key or "third" in val:
                        managed_by = "Third Party"
                        break
            except:
                pass

            # Check FMS policy association
            if managed_by == "Direct":
                try:
                    fms = session.client("fms", region_name="us-east-1", verify=False)
                    policies = fms.list_policies()
                    for policy in policies.get("PolicyList", []):
                        if policy.get("SecurityServiceType") == "WAFV2":
                            managed_by = "Firewall Manager"
                            break
                except:
                    pass

            acls[acl_arn] = {
                "name":       acl_name,
                "arn":        acl_arn,
                "resources":  resources,
                "managed_by": managed_by,
                "region":     region
            }
    except:
        pass
    return acls

def get_cf_waf_acls(session):
    """Get CloudFront WAF ACLs."""
    acls = {}
    try:
        waf  = session.client("wafv2", region_name="us-east-1", verify=False)
        resp = waf.list_web_acls(Scope="CLOUDFRONT", Limit=100)
        for acl in resp.get("WebACLs", []):
            acl_arn  = acl["ARN"]
            acl_name = acl["Name"]
            resources = []
            try:
                res = waf.list_resources_for_web_acl(WebACLArn=acl_arn)
                resources = res.get("ResourceArns", [])
            except:
                pass
            acls[acl_arn] = {
                "name":       acl_name,
                "arn":        acl_arn,
                "resources":  resources,
                "managed_by": "Direct",
                "region":     "CLOUDFRONT"
            }
    except:
        pass
    return acls

def find_waf_for_api(session, region, api_id, acc_id):
    """
    Find WAF for an API Gateway using ALL possible methods:
    1. list_resources_for_web_acl — standard check
    2. FMS compliance check — for FMS-managed WAFs
    3. Stage ARN check
    4. Web ACL association on API GW directly
    """
    waf_name   = ""
    waf_arn    = ""
    waf_region = ""
    managed_by = ""

    # Method 1 — Get all WAF ACLs and check resources
    regional_acls = get_all_waf_acls_in_region(session, region)

    for acl_arn, acl_info in regional_acls.items():
        for r_arn in acl_info["resources"]:
            if api_id in r_arn:
                waf_name   = acl_info["name"]
                waf_arn    = acl_arn
                waf_region = region
                managed_by = acl_info["managed_by"]
                return waf_name, waf_arn, waf_region, managed_by

    # Method 2 — Check stage ARNs for REST APIs
    try:
        client = session.client("apigateway", region_name=region, verify=False)
        stages = client.get_stages(restApiId=api_id)
        for stage in stages.get("item", []):
            stage_name = stage.get("stageName", "")
            stage_arn  = (
                "arn:aws:apigateway:" + region +
                "::/restapis/" + api_id +
                "/stages/" + stage_name
            )
            for acl_arn, acl_info in regional_acls.items():
                if stage_arn in acl_info["resources"]:
                    waf_name   = acl_info["name"]
                    waf_arn    = acl_arn
                    waf_region = region
                    managed_by = acl_info["managed_by"]
                    return waf_name, waf_arn, waf_region, managed_by
    except:
        pass

    # Method 3 — FMS compliance check
    try:
        fms = session.client("fms", region_name="us-east-1", verify=False)
        policies = fms.list_policies()
        for policy in policies.get("PolicyList", []):
            if policy.get("SecurityServiceType") in ["WAFV2", "WAF"]:
                policy_id = policy["PolicyId"]
                try:
                    compliance = fms.list_compliance_status(PolicyId=policy_id)
                    for status in compliance.get("PolicyComplianceStatusList", []):
                        if status.get("MemberAccount") == acc_id:
                            eval_results = status.get("EvaluationResults", [])
                            for ev in eval_results:
                                if ev.get("ComplianceStatus") == "COMPLIANT":
                                    waf_name   = policy.get("PolicyName", "FMS Policy")
                                    waf_arn    = policy.get("PolicyArn", "")
                                    waf_region = region
                                    managed_by = "Firewall Manager"
                                    return waf_name, waf_arn, waf_region, managed_by
                except:
                    pass
    except:
        pass

    # Method 4 — Direct WAF association on API GW stage
    try:
        client = session.client("apigateway", region_name=region, verify=False)
        stages = client.get_stages(restApiId=api_id)
        for stage in stages.get("item", []):
            web_acl_arn = stage.get("webAclArn", "")
            if web_acl_arn:
                # Extract WAF name from ARN
                waf_name   = web_acl_arn.split("/")[-1]
                waf_arn    = web_acl_arn
                waf_region = region
                managed_by = "Direct (Stage)"
                return waf_name, waf_arn, waf_region, managed_by
    except:
        pass

    return waf_name, waf_arn, waf_region, managed_by

def get_apigw_domains(session, acc_id, acc_name):
    """
    Scan all API Gateway custom domains in all regions.
    Returns list of domain records with WAF details.
    """
    found = []

    for region in REGIONS:

        # REST API v1 custom domains
        try:
            client  = session.client(
                "apigateway", region_name=region, verify=False
            )
            resp    = client.get_domain_names(limit=500)
            domains = resp.get("items", [])

            if domains:
                print("    [" + region + "] " + str(len(domains)) + " REST domains")

            for domain in domains:
                dn         = domain.get("domainName", "")
                api_id     = ""
                api_name   = ""
                stage_name = ""

                # Get base path mappings
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

                # Find WAF
                waf_name   = ""
                waf_arn    = ""
                waf_region = ""
                managed_by = ""

                if api_id:
                    waf_name, waf_arn, waf_region, managed_by = find_waf_for_api(
                        session, region, api_id, acc_id
                    )

                status = "YES" if waf_name else "NO"
                print("      " + dn + " | " + api_name + " | WAF:" + status +
                      (" (" + managed_by + ")" if managed_by else ""))

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
                    "WAF_Region":         waf_region,
                    "WAF_Managed_By":     managed_by,
                    "Region":             region,
                    "WAF_Protected":      "YES" if waf_name else "NO",
                    "Notes":              ""
                })

        except:
            pass

        # HTTP API v2 custom domains
        try:
            client  = session.client(
                "apigatewayv2", region_name=region, verify=False
            )
            resp    = client.get_domain_names()
            domains = resp.get("Items", [])

            if domains:
                print("    [" + region + "] " + str(len(domains)) + " HTTP domains")

            for domain in domains:
                dn         = domain.get("DomainName", "")
                api_id     = ""
                api_name   = ""
                stage_name = ""

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

                # Find WAF
                waf_name   = ""
                waf_arn    = ""
                waf_region = ""
                managed_by = ""

                if api_id:
                    waf_name, waf_arn, waf_region, managed_by = find_waf_for_api(
                        session, region, api_id, acc_id
                    )

                status = "YES" if waf_name else "NO"
                print("      " + dn + " | " + api_name + " | WAF:" + status)

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
                    "WAF_Region":         waf_region,
                    "WAF_Managed_By":     managed_by,
                    "Region":             region,
                    "WAF_Protected":      "YES" if waf_name else "NO",
                    "Notes":              ""
                })

        except:
            pass

    return found

# ══════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════
print("=" * 60)
print("API Gateway WAF Coverage Report — Final Version")
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

# Get all accounts
accounts = get_all_accounts(token)
if not accounts:
    print("ERROR: No accounts found!")
    exit(1)

# Scan all accounts
print("\nScanning all " + str(len(accounts)) + " accounts...")
print("=" * 60)
all_domains = []

for i, account in enumerate(accounts):
    acc_id   = account["accountId"]
    acc_name = account.get("accountName", "unknown")

    if i % 20 == 0:
        print("\n[" + str(i) + "/" + str(len(accounts)) + "] Progress — Domains found: " + str(len(all_domains)))

    creds = get_creds(token, acc_id)
    if not creds:
        continue

    session = make_session(creds)
    domains = get_apigw_domains(session, acc_id, acc_name)

    if domains:
        print("  -> " + acc_name + ": " + str(len(domains)) + " domains")
        all_domains.extend(domains)

print("\n\nTotal API GW domains found across all accounts: " + str(len(all_domains)))

# Match hostnames to found domains
print("\nMatching hostnames...")
print("=" * 60)

matched   = []
unmatched = []

for hostname in hostnames:
    match      = None
    match_type = ""

    # 1. Exact match
    for domain in all_domains:
        if hostname == domain["Custom_Domain_Name"].lower():
            match      = domain
            match_type = "exact"
            break

    # 2. Partial match
    if not match:
        for domain in all_domains:
            dn = domain["Custom_Domain_Name"].lower()
            if hostname in dn or dn in hostname:
                match            = dict(domain)
                match["Notes"]   = "Partial match to: " + domain["Custom_Domain_Name"]
                match_type       = "partial"
                break

    if match:
        matched.append(match)
        status = "YES" if match["WAF_Protected"] == "YES" else "NO"
        print("MATCHED   [" + match_type + "]: " + hostname)
        print("           Account    : " + match["Account_Name"] + " (" + match["Account_ID"].lstrip("'") + ")")
        print("           API        : " + match["API_Name"] + " (" + match["API_ID"] + ")")
        print("           WAF        : " + status)
        if match["WebACL_Name"]:
            print("           WebACL     : " + match["WebACL_Name"])
            print("           Managed by : " + match["WAF_Managed_By"])
        print("")
    else:
        row = empty_result(hostname)
        unmatched.append(row)
        print("NOT FOUND : " + hostname)

# Write CSV
print("\nWriting: " + OUT_FILE)
rows = matched + unmatched

with open(OUT_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=FIELDS)
    writer.writeheader()
    for row in rows:
        writer.writerow({field: row.get(field, "") for field in FIELDS})

# Summary
protected     = sum(1 for r in matched if r["WAF_Protected"] == "YES")
not_protected = sum(1 for r in matched if r["WAF_Protected"] == "NO")
fms_managed   = sum(1 for r in matched if "Firewall Manager" in r.get("WAF_Managed_By", ""))
third_party   = sum(1 for r in matched if "Third" in r.get("WAF_Managed_By", ""))

print("\n" + "=" * 60)
print("FINAL SUMMARY")
print("  Total hostnames        : " + str(len(hostnames)))
print("  Matched to API GW      : " + str(len(matched)))
print("  WAF protected          : " + str(protected))
print("  Found - NO WAF         : " + str(not_protected))
print("  FMS managed            : " + str(fms_managed))
print("  Third party            : " + str(third_party))
print("  Not found in any acct  : " + str(len(unmatched)))
print("  Report saved           : " + OUT_FILE)
print("=" * 60)
