import subprocess
import json
import socket
import csv
from datetime import datetime

# ── CONFIG ──
SSO_START_URL = "https://truist.awsapps.com/start"
SSO_REGION = "us-east-1"
ROLE_NAME = "G-ROLE-AWS-ENT-WAFADMIN-RO"
REGIONS = ["us-east-1", "us-east-2", "us-west-2"]
HOSTNAMES_FILE = "hostnames.txt"
OUTPUT_FILE = f"waf_coverage_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"

def run_cmd(cmd):
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
        return json.loads(result.stdout) if result.stdout else {}
    except:
        return {}

# ── STEP 1: Get SSO access token from cache ──
def get_sso_token():
    import glob, os
    cache_files = glob.glob(
        os.path.expanduser("~/.aws/sso/cache/*.json")
    )
    for f in cache_files:
        try:
            with open(f) as fh:
                data = json.load(fh)
                if "accessToken" in data:
                    return data["accessToken"]
        except:
            continue
    return None

# ── STEP 2: Get ALL 358 account IDs from SSO ──
def get_all_accounts(token):
    print("Fetching all accounts from SSO...")
    accounts = []
    next_token = None

    while True:
        cmd = [
            "aws", "sso", "list-accounts",
            "--access-token", token,
            "--region", SSO_REGION,
            "--no-verify-ssl",
            "--output", "json"
        ]
        if next_token:
            cmd += ["--next-token", next_token]

        data = run_cmd(cmd)
        accounts.extend(data.get("accountList", []))
        next_token = data.get("nextToken")
        if not next_token:
            break

    print(f"Found {len(accounts)} accounts")
    return accounts

# ── STEP 3: Get temp credentials for each account ──
def get_account_creds(token, account_id):
    data = run_cmd([
        "aws", "sso", "get-role-credentials",
        "--account-id", account_id,
        "--role-name", ROLE_NAME,
        "--access-token", token,
        "--region", SSO_REGION,
        "--no-verify-ssl",
        "--output", "json"
    ])
    return data.get("roleCredentials")

# ── STEP 4: Run AWS command with temp creds ──
def run_aws(cmd, creds):
    env_creds = {
        "AWS_ACCESS_KEY_ID": creds["accessKeyId"],
        "AWS_SECRET_ACCESS_KEY": creds["secretAccessKey"],
        "AWS_SESSION_TOKEN": creds["sessionToken"],
        "AWS_DEFAULT_REGION": "us-east-1"
    }
    import os
    env = {**os.environ, **env_creds}
    try:
        result = subprocess.run(
            cmd + ["--no-verify-ssl"],
            capture_output=True, text=True,
            timeout=30, env=env
        )
        return json.loads(result.stdout) if result.stdout else {}
    except:
        return {}

# ── STEP 5: Get WAF associations for one account ──
def get_waf_associations(creds):
    associations = {}
    for region in REGIONS:
        data = run_aws([
            "aws", "wafv2", "list-web-acls",
            "--scope", "REGIONAL",
            "--region", region,
            "--output", "json"
        ], creds)
        for acl in data.get("WebACLs", []):
            arn = acl["ARN"]
            resources = run_aws([
                "aws", "wafv2", "list-resources-for-web-acl",
                "--web-acl-arn", arn,
                "--region", region,
                "--output", "json"
            ], creds)
            for r in resources.get("ResourceArns", []):
                associations[r] = {
                    "WebACLName": acl["Name"],
                    "WebACLArn": arn,
                    "Region": region
                }
    # CloudFront scope
    data = run_aws([
        "aws", "wafv2", "list-web-acls",
        "--scope", "CLOUDFRONT",
        "--region", "us-east-1",
        "--output", "json"
    ], creds)
    for acl in data.get("WebACLs", []):
        arn = acl["ARN"]
        resources = run_aws([
            "aws", "wafv2", "list-resources-for-web-acl",
            "--web-acl-arn", arn,
            "--region", "us-east-1",
            "--output", "json"
        ], creds)
        for r in resources.get("ResourceArns", []):
            associations[r] = {
                "WebACLName": acl["Name"],
                "WebACLArn": arn,
                "Region": "CLOUDFRONT"
            }
    return associations

# ── STEP 6: Get CloudFront + ALB for one account ──
def get_cf_and_alb(creds):
    cf_map = {}
    alb_map = {}

    # CloudFront
    data = run_aws([
        "aws", "cloudfront", "list-distributions",
        "--output", "json"
    ], creds)
    for dist in data.get("DistributionList", {}).get("Items", []):
        arn = dist.get("ARN", "")
        for alias in dist.get("Aliases", {}).get("Items", []):
            cf_map[alias.lower()] = arn
        cf_map[dist.get("DomainName", "").lower()] = arn

    # ALBs
    for region in REGIONS:
        data = run_aws([
            "aws", "elbv2", "describe-load-balancers",
            "--region", region,
            "--output", "json"
        ], creds)
        for lb in data.get("LoadBalancers", []):
            alb_map[lb.get("DNSName", "").lower()] = {
                "arn": lb["LoadBalancerArn"],
                "region": region
            }

    return cf_map, alb_map

# ── STEP 7: DNS lookup ──
def dns_lookup(hostname):
    try:
        return socket.gethostbyname(hostname)
    except:
        return "DNS_FAILED"

# ── MAIN ──
print("=" * 60)
print("WAF Coverage — All 358 Accounts")
print("=" * 60)

# Load hostnames
with open(HOSTNAMES_FILE) as f:
    hostnames = [l.strip() for l in f if l.strip()]
print(f"Loaded {len(hostnames)} hostnames\n")

# Get SSO token
token = get_sso_token()
if not token:
    print("ERROR: No SSO token found!")
    print("Run first: aws sso login --profile waf-search1 --no-verify-ssl")
    exit(1)
print("SSO token found OK\n")

# Get all accounts
accounts = get_all_accounts(token)

# DNS resolve all hostnames once
print("Resolving DNS for all hostnames...")
hostname_ips = {h: dns_lookup(h) for h in hostnames}

# Master results dict
results = {h: {
    "Hostname": h,
    "IP": hostname_ips[h],
    "Account_ID": "",
    "Account_Name": "",
    "Resource_Type": "Not Found",
    "Resource_ARN": "",
    "WAF_Protected": "NO",
    "WAF_Name": "",
    "WAF_Region": "",
    "Notes": "Not found in any account"
} for h in hostnames}

# Loop every account
for i, account in enumerate(accounts):
    account_id = account["accountId"]
    account_name = account.get("accountName", "")
    print(f"\n[{i+1}/{len(accounts)}] Checking: {account_name} ({account_id})")

    # Get creds
    creds = get_account_creds(token, account_id)
    if not creds:
        print(f"  Skipping — no credentials available")
        continue

    # Get WAF associations, CF, ALB
    waf_assoc = get_waf_associations(creds)
    cf_map, alb_map = get_cf_and_alb(creds)

    if not waf_assoc and not cf_map and not alb_map:
        continue

    # Check each hostname against this account
    for hostname in hostnames:
        h_lower = hostname.lower()

        # Already found with WAF — skip
        if results[hostname]["WAF_Protected"] == "YES":
            continue

        # Check CloudFront
        if h_lower in cf_map:
            arn = cf_map[h_lower]
            results[hostname].update({
                "Account_ID": account_id,
                "Account_Name": account_name,
                "Resource_Type": "CloudFront",
                "Resource_ARN": arn,
                "Notes": ""
            })
            if arn in waf_assoc:
                w = waf_assoc[arn]
                results[hostname].update({
                    "WAF_Protected": "YES",
                    "WAF_Name": w["WebACLName"],
                    "WAF_Region": w["Region"]
                })
                print(f"  FOUND+WAF: {hostname}")
            else:
                results[hostname]["Notes"] = "CloudFront found — NO WAF"
                print(f"  FOUND no WAF: {hostname}")

        # Check ALB
        for alb_dns, alb_info in alb_map.items():
            if alb_dns in h_lower or h_lower in alb_dns:
                arn = alb_info["arn"]
                results[hostname].update({
                    "Account_ID": account_id,
                    "Account_Name": account_name,
                    "Resource_Type": "ALB",
                    "Resource_ARN": arn,
                    "Notes": ""
                })
                if arn in waf_assoc:
                    w = waf_assoc[arn]
                    results[hostname].update({
                        "WAF_Protected": "YES",
                        "WAF_Name": w["WebACLName"],
                        "WAF_Region": w["Region"]
                    })
                    print(f"  FOUND+WAF: {hostname}")
                else:
                    results[hostname]["Notes"] = "ALB found — NO WAF"

# Write CSV
rows = list(results.values())
with open(OUTPUT_FILE, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)

# Summary
protected = sum(1 for r in rows if r["WAF_Protected"] == "YES")
print("\n" + "=" * 60)
print(f"SUMMARY")
print(f"  Total hostnames : {len(rows)}")
print(f"  WAF protected   : {protected}")
print(f"  NOT protected   : {len(rows) - protected}")
print(f"  Report saved to : {OUTPUT_FILE}")
print("=" * 60)
