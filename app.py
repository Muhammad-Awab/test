cat > waf_app.py << 'EOF'
import boto3
import socket
import csv
import os
import ssl
from datetime import datetime

# ── SSL FIX for corporate network ──
os.environ["PYTHONHTTPSVERIFY"] = "0"
ssl._create_default_https_context = ssl._create_unverified_context

# ── CONFIG ──
PROFILE  = "waf-search1"
REGIONS  = ["us-east-1", "us-east-2", "us-west-2"]
OUT_FILE = f"waf_report_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
HOSTNAMES_FILE = "hostnames.txt"

# ── FIELDNAMES — always consistent ──
FIELDS = [
    "Hostname", "IP", "Resource_Type", "Resource_Name",
    "Resource_ARN", "WAF_Protected", "WAF_Name",
    "WAF_Region", "Notes"
]

def empty_result(hostname, ip="", notes="Not found"):
    return {
        "Hostname":      hostname,
        "IP":            ip,
        "Resource_Type": "Not Found",
        "Resource_Name": "",
        "Resource_ARN":  "",
        "WAF_Protected": "NO",
        "WAF_Name":      "",
        "WAF_Region":    "",
        "Notes":         notes
    }

def dns_lookup(hostname):
    try:
        return socket.gethostbyname(hostname)
    except:
        return "DNS_FAILED"

def get_sso_token():
    import glob
    cache_files = glob.glob(
        os.path.expanduser("~/.aws/sso/cache/*.json")
    )
    import json
    for f in cache_files:
        try:
            with open(f) as fh:
                data = json.load(fh)
                if "accessToken" in data:
                    print(f"  SSO token found: {f}")
                    return data["accessToken"]
        except:
            continue
    return None

def get_all_accounts(token):
    print("Fetching all accounts from SSO...")
    import subprocess, json
    accounts = []
    next_token = None
    while True:
        cmd = [
            "aws", "sso", "list-accounts",
            "--access-token", token,
            "--region", "us-east-1",
            "--no-verify-ssl",
            "--output", "json"
        ]
        if next_token:
            cmd += ["--next-token", next_token]
        try:
            result = subprocess.run(
                cmd, capture_output=True,
                text=True, timeout=30
            )
            data = json.loads(result.stdout)
            accounts.extend(data.get("accountList", []))
            next_token = data.get("nextToken")
            if not next_token:
                break
        except:
            break
    print(f"  Found {len(accounts)} accounts")
    return accounts

def get_account_creds(token, account_id, role_name):
    import subprocess, json
    cmd = [
        "aws", "sso", "get-role-credentials",
        "--account-id", account_id,
        "--role-name", role_name,
        "--access-token", token,
        "--region", "us-east-1",
        "--no-verify-ssl",
        "--output", "json"
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True,
            text=True, timeout=30
        )
        data = json.loads(result.stdout)
        return data.get("roleCredentials")
    except:
        return None

def get_session_from_creds(creds):
    return boto3.Session(
        aws_access_key_id     = creds["accessKeyId"],
        aws_secret_access_key = creds["secretAccessKey"],
        aws_session_token     = creds["sessionToken"]
    )

def get_waf_associations(session):
    associations = {}
    for region in REGIONS:
        try:
            waf = session.client(
                "wafv2", region_name=region,
                verify=False
            )
            resp = waf.list_web_acls(
                Scope="REGIONAL", Limit=100
            )
            for acl in resp.get("WebACLs", []):
                try:
                    res = waf.list_resources_for_web_acl(
                        WebACLArn=acl["ARN"]
                    )
                    for r in res.get("ResourceArns", []):
                        associations[r] = {
                            "WAF_Name":   acl["Name"],
                            "WAF_Region": region
                        }
                except:
                    pass
        except:
            pass

    # CloudFront
    try:
        waf = session.client(
            "wafv2", region_name="us-east-1",
            verify=False
        )
        resp = waf.list_web_acls(
            Scope="CLOUDFRONT", Limit=100
        )
        for acl in resp.get("WebACLs", []):
            try:
                res = waf.list_resources_for_web_acl(
                    WebACLArn=acl["ARN"]
                )
                for r in res.get("ResourceArns", []):
                    associations[r] = {
                        "WAF_Name":   acl["Name"],
                        "WAF_Region": "CLOUDFRONT"
                    }
            except:
                pass
    except:
        pass
    return associations

def get_cloudfront_map(session):
    cf_map = {}
    try:
        cf   = session.client("cloudfront", verify=False)
        resp = cf.list_distributions()
        for dist in resp.get(
            "DistributionList", {}
        ).get("Items", []):
            arn = dist.get("ARN", "")
            cf_map[dist.get("DomainName","").lower()] = arn
            for alias in dist.get(
                "Aliases", {}
            ).get("Items", []):
                cf_map[alias.lower()] = arn
    except:
        pass
    return cf_map

def get_alb_map(session):
    alb_map = {}
    for region in REGIONS:
        try:
            elb  = session.client(
                "elbv2", region_name=region,
                verify=False
            )
            resp = elb.describe_load_balancers()
            for lb in resp.get("LoadBalancers", []):
                dns = lb.get("DNSName","").lower()
                alb_map[dns] = {
                    "arn":    lb["LoadBalancerArn"],
                    "region": region,
                    "name":   lb.get("LoadBalancerName","")
                }
        except:
            pass
    return alb_map

def check_hostname(hostname, cf_map, alb_map, waf_assoc):
    h  = hostname.lower()
    ip = dns_lookup(hostname)
    r  = empty_result(hostname, ip)

    # CloudFront
    if h in cf_map:
        arn = cf_map[h]
        r.update({
            "Resource_Type": "CloudFront",
            "Resource_ARN":  arn,
            "Notes":         ""
        })
        if arn in waf_assoc:
            w = waf_assoc[arn]
            r.update({
                "WAF_Protected": "YES",
                "WAF_Name":      w["WAF_Name"],
                "WAF_Region":    w["WAF_Region"]
            })
        else:
            r["Notes"] = "CloudFront — NO WAF"
        return r

    # ALB
    for alb_dns, info in alb_map.items():
        if alb_dns in h or h in alb_dns:
            r.update({
                "Resource_Type": "ALB",
                "Resource_Name": info["name"],
                "Resource_ARN":  info["arn"],
                "Notes":         ""
            })
            if info["arn"] in waf_assoc:
                w = waf_assoc[info["arn"]]
                r.update({
                    "WAF_Protected": "YES",
                    "WAF_Name":      w["WAF_Name"],
                    "WAF_Region":    w["WAF_Region"]
                })
            else:
                r["Notes"] = "ALB — NO WAF"
            return r

    # Hints
    if "execute-api" in h:
        r.update({
            "Resource_Type": "API Gateway",
            "Notes": "API Gateway — check WAF manually"
        })
    elif "cloudfront.net" in str(ip):
        r.update({
            "Resource_Type": "CloudFront (by IP)",
            "Notes": "Resolves to CF — not in this account"
        })
    return r

# ══════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════
print("=" * 60)
print("WAF Coverage — All Truist Accounts")
print("=" * 60)

# Load hostnames
with open(HOSTNAMES_FILE) as f:
    hostnames = [l.strip() for l in f if l.strip()]
print(f"Loaded {len(hostnames)} hostnames\n")

# Get SSO token
token = get_sso_token()
if not token:
    print("ERROR: No SSO token found!")
    print("Run: aws sso login --profile waf-search1 --no-verify-ssl")
    exit(1)
print("SSO token OK\n")

# Get all accounts
accounts = get_all_accounts(token)
if not accounts:
    print("ERROR: No accounts found!")
    exit(1)

# Get available role from first working account
ROLE_NAME = "G-ROLE-AWS-ENT-WAFADMIN-RO"

# Master results — pre-populate all hostnames
results = {h: empty_result(h, dns_lookup(h)) for h in hostnames}

# ── Loop every account ──
for i, account in enumerate(accounts):
    acc_id   = account["accountId"]
    acc_name = account.get("accountName", "unknown")
    print(f"[{i+1}/{len(accounts)}] {acc_name} ({acc_id})")

    creds = get_account_creds(token, acc_id, ROLE_NAME)
    if not creds:
        print(f"  No creds — skipping")
        continue

    session   = get_session_from_creds(creds)
    waf_assoc = get_waf_associations(session)
    cf_map    = get_cloudfront_map(session)
    alb_map   = get_alb_map(session)

    if not waf_assoc and not cf_map and not alb_map:
        continue

    for hostname in hostnames:
        # Skip already confirmed protected
        if results[hostname]["WAF_Protected"] == "YES":
            continue

        r = check_hostname(hostname, cf_map, alb_map, waf_assoc)

        if r["Resource_Type"] != "Not Found":
            r["Notes"] = (
                r.get("Notes","") +
                f" | Account: {acc_name} ({acc_id})"
            ).strip(" |")
            results[hostname] = r

            status = "YES" if r["WAF_Protected"] == "YES" else "NO"
            print(f"  {hostname} → WAF:{status} | {r['Resource_Type']}")

# ── Write CSV ──
rows = list(results.values())

# Safety check — ensure all rows have correct fields
clean_rows = []
for row in rows:
    clean = {f: row.get(f, "") for f in FIELDS}
    clean_rows.append(clean)

with open(OUT_FILE, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=FIELDS)
    writer.writeheader()
    writer.writerows(clean_rows)

# ── Summary ──
protected = sum(1 for r in clean_rows if r["WAF_Protected"] == "YES")
print("\n" + "=" * 60)
print("FINAL SUMMARY")
print(f"  Accounts scanned : {len(accounts)}")
print(f"  Hostnames checked: {len(clean_rows)}")
print(f"  WAF protected    : {protected}")
print(f"  NOT protected    : {len(clean_rows) - protected}")
print(f"  Report saved     : {OUT_FILE}")
print("=" * 60)
EOF
