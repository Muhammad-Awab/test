import boto3
import socket
import csv
import os
import ssl
import glob
import json
import subprocess
from datetime import datetime

# ── SSL FIX ──
os.environ["PYTHONHTTPSVERIFY"] = "0"
ssl._create_default_https_context = ssl._create_unverified_context

# ── CONFIG ──
PROFILE  = "waf-search1"
REGIONS  = ["us-east-1", "us-east-2", "us-west-2"]
OUT_FILE = f"waf_report_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
HOSTNAMES_FILE = "hostnames.txt"
ROLE_NAME = "G-ROLE-AWS-ENT-WAFADMIN-RO"

FIELDS = [
    "Hostname", "IP", "Resource_Type", "Resource_Name",
    "Resource_ARN", "WAF_Protected", "WAF_Name",
    "WAF_Region", "Account_ID", "Account_Name", "Notes"
]

def empty_result(hostname, ip=""):
    return {f: "" for f in FIELDS} | {
        "Hostname":      hostname,
        "IP":            ip,
        "Resource_Type": "Not Found",
        "WAF_Protected": "NO",
        "Notes":         "Not found in any account"
    }

def dns_lookup(hostname):
    try:
        return socket.gethostbyname(hostname)
    except:
        return "DNS_FAILED"

def get_sso_token():
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

def run_cmd(cmd):
    try:
        r = subprocess.run(
            cmd, capture_output=True,
            text=True, timeout=30
        )
        return json.loads(r.stdout) if r.stdout.strip() else {}
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
            "--no-verify-ssl",
            "--output", "json"
        ]
        if next_tok:
            cmd += ["--next-token", next_tok]
        data     = run_cmd(cmd)
        batch    = data.get("accountList", [])
        accounts.extend(batch)
        next_tok = data.get("nextToken")
        if not next_tok:
            break
    print(f"  Found {len(accounts)} accounts")
    return accounts

def get_creds(token, account_id):
    data = run_cmd([
        "aws", "sso", "get-role-credentials",
        "--account-id", account_id,
        "--role-name", ROLE_NAME,
        "--access-token", token,
        "--region", "us-east-1",
        "--no-verify-ssl",
        "--output", "json"
    ])
    return data.get("roleCredentials")

def make_session(creds):
    return boto3.Session(
        aws_access_key_id     = creds["accessKeyId"],
        aws_secret_access_key = creds["secretAccessKey"],
        aws_session_token     = creds["sessionToken"]
    )

def get_waf_assoc(session):
    assoc = {}
    for region in REGIONS:
        try:
            waf  = session.client("wafv2", region_name=region, verify=False)
            resp = waf.list_web_acls(Scope="REGIONAL", Limit=100)
            for acl in resp.get("WebACLs", []):
                try:
                    res = waf.list_resources_for_web_acl(WebACLArn=acl["ARN"])
                    for r in res.get("ResourceArns", []):
                        assoc[r] = {"WAF_Name": acl["Name"], "WAF_Region": region}
                except:
                    pass
        except:
            pass
    try:
        waf  = session.client("wafv2", region_name="us-east-1", verify=False)
        resp = waf.list_web_acls(Scope="CLOUDFRONT", Limit=100)
        for acl in resp.get("WebACLs", []):
            try:
                res = waf.list_resources_for_web_acl(WebACLArn=acl["ARN"])
                for r in res.get("ResourceArns", []):
                    assoc[r] = {"WAF_Name": acl["Name"], "WAF_Region": "CLOUDFRONT"}
            except:
                pass
    except:
        pass
    return assoc

def get_cf_map(session):
    cf_map = {}
    try:
        cf   = session.client("cloudfront", verify=False)
        resp = cf.list_distributions()
        for dist in resp.get("DistributionList", {}).get("Items", []):
            arn = dist.get("ARN", "")
            cf_map[dist.get("DomainName", "").lower()] = arn
            for alias in dist.get("Aliases", {}).get("Items", []):
                cf_map[alias.lower()] = arn
    except:
        pass
    return cf_map

def get_alb_map(session):
    alb_map = {}
    for region in REGIONS:
        try:
            elb  = session.client("elbv2", region_name=region, verify=False)
            resp = elb.describe_load_balancers()
            for lb in resp.get("LoadBalancers", []):
                alb_map[lb.get("DNSName","").lower()] = {
                    "arn":    lb["LoadBalancerArn"],
                    "region": region,
                    "name":   lb.get("LoadBalancerName","")
                }
        except:
            pass
    return alb_map

def check_host(hostname, cf_map, alb_map, waf_assoc, acc_id, acc_name):
    h  = hostname.lower()
    ip = dns_lookup(hostname)
    r  = empty_result(hostname, ip)
    r["Account_ID"]   = acc_id
    r["Account_Name"] = acc_name

    # CloudFront
    if h in cf_map:
        arn = cf_map[h]
        r.update({"Resource_Type": "CloudFront", "Resource_ARN": arn})
        if arn in waf_assoc:
            w = waf_assoc[arn]
            r.update({"WAF_Protected": "YES", "WAF_Name": w["WAF_Name"], "WAF_Region": w["WAF_Region"]})
        else:
            r["Notes"] = "CloudFront found — NO WAF"
        return r

    # ALB
    for alb_dns, info in alb_map.items():
        if alb_dns in h or h in alb_dns:
            r.update({
                "Resource_Type": "ALB",
                "Resource_Name": info["name"],
                "Resource_ARN":  info["arn"]
            })
            if info["arn"] in waf_assoc:
                w = waf_assoc[info["arn"]]
                r.update({"WAF_Protected": "YES", "WAF_Name": w["WAF_Name"], "WAF_Region": w["WAF_Region"]})
            else:
                r["Notes"] = "ALB found — NO WAF"
            return r

    # API GW hint
    if "execute-api" in h:
        r.update({"Resource_Type": "API Gateway", "Notes": "API GW — check WAF manually"})

    return r

# ══════════════════════════════════════════
print("=" * 60)
print("WAF Coverage — All Truist Accounts")
print("=" * 60)

# Load hostnames
if not os.path.exists(HOSTNAMES_FILE):
    print(f"ERROR: {HOSTNAMES_FILE} not found!")
    print("Create it first with your hostnames list")
    exit(1)

with open(HOSTNAMES_FILE) as f:
    hostnames = [l.strip() for l in f if l.strip()]

if not hostnames:
    print("ERROR: hostnames.txt is empty!")
    exit(1)

print(f"Loaded {len(hostnames)} hostnames")

# SSO token
token = get_sso_token()
if not token:
    print("\nERROR: No SSO token!")
    print("Run this first:")
    print("  aws sso login --profile waf-search1 --no-verify-ssl")
    exit(1)
print("SSO token OK")

# Get accounts
accounts = get_all_accounts(token)
if not accounts:
    print("ERROR: No accounts found!")
    exit(1)

# Pre-populate results
results = {h: empty_result(h, dns_lookup(h)) for h in hostnames}
print(f"DNS resolved for all hostnames\n")

# Loop accounts
for i, account in enumerate(accounts):
    acc_id   = account["accountId"]
    acc_name = account.get("accountName", "unknown")
    print(f"[{i+1}/{len(accounts)}] {acc_name} ({acc_id})", end=" ")

    creds = get_creds(token, acc_id)
    if not creds:
        print("— no creds, skip")
        continue

    session  = make_session(creds)
    waf_assoc = get_waf_assoc(session)
    cf_map    = get_cf_map(session)
    alb_map   = get_alb_map(session)

    found_something = False
    for hostname in hostnames:
        if results[hostname]["WAF_Protected"] == "YES":
            continue
        r = check_host(hostname, cf_map, alb_map, waf_assoc, acc_id, acc_name)
        if r["Resource_Type"] != "Not Found":
            results[hostname] = r
            found_something   = True
            status = "YES" if r["WAF_Protected"] == "YES" else "NO"
            print(f"\n  FOUND: {hostname} → WAF:{status} | {r['Resource_Type']}")

    if not found_something:
        print("— nothing found")

# Write CSV — always write even if empty
print(f"\nWriting report to {OUT_FILE}...")
rows = [results[h] for h in hostnames]

with open(OUT_FILE, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=FIELDS)
    writer.writeheader()
    for row in rows:
        clean = {field: row.get(field, "") for field in FIELDS}
        writer.writerow(clean)

# Summary
protected = sum(1 for r in rows if r["WAF_Protected"] == "YES")
print("\n" + "=" * 60)
print("FINAL SUMMARY")
print(f"  Accounts scanned : {len(accounts)}")
print(f"  Hostnames checked: {len(rows)}")
print(f"  WAF protected    : {protected}")
print(f"  NOT protected    : {len(rows) - protected}")
print(f"  Report saved     : {OUT_FILE}")
print("=" * 60)
