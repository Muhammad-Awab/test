import boto3
import socket
import csv
import os
import ssl
import glob
import json
import subprocess
from datetime import datetime

# SSL FIX for corporate network
os.environ["PYTHONHTTPSVERIFY"] = "0"
ssl._create_default_https_context = ssl._create_unverified_context

# CONFIG
REGIONS   = ["us-east-1", "us-east-2", "us-west-2",
             "us-west-1", "eu-west-1", "ap-southeast-1"]
OUT_FILE  = "waf_report_" + datetime.now().strftime("%Y%m%d_%H%M") + ".csv"
HOSTNAMES_FILE = "hostnames.txt"
ROLE_NAME = "G-ROLE-AWS-ENT-WAFADMIN-RO"

FIELDS = [
    "Hostname", "IP", "CNAME",
    "Resource_Type", "Resource_Name", "Resource_ARN",
    "WAF_Protected", "WAF_Name", "WAF_Region",
    "Account_ID", "Account_Name", "Notes"
]

def empty_result(hostname, ip="", cname=""):
    result = {}
    for f in FIELDS:
        result[f] = ""
    result["Hostname"]      = hostname
    result["IP"]            = ip
    result["CNAME"]         = cname
    result["Resource_Type"] = "Not Found"
    result["WAF_Protected"] = "NO"
    result["Notes"]         = "Not found in any account"
    return result

def dns_lookup(hostname):
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return "DNS_FAILED"

def dns_cname(hostname):
    try:
        import dns.resolver
        answers = dns.resolver.resolve(hostname, "CNAME")
        return str(answers[0].target).rstrip(".")
    except Exception:
        return ""

def get_full_dns_chain(hostname):
    """
    Resolve full DNS chain to find underlying AWS resource.
    Returns (ip, cname) where cname is the final AWS endpoint.
    """
    ip    = "DNS_FAILED"
    cname = ""
    try:
        results = socket.getaddrinfo(hostname, None)
        if results:
            ip = results[0][4][0]
    except Exception:
        pass

    # Try to get CNAME via nslookup (works without dnspython)
    try:
        r = subprocess.run(
            ["nslookup", hostname],
            capture_output=True, text=True, timeout=10
        )
        lines = r.stdout.lower().split("\n")
        for line in lines:
            if "canonical name" in line or "aliases" in line:
                parts = line.split("=")
                if len(parts) > 1:
                    cname = parts[1].strip().rstrip(".")
                    break
            # Also check for cloudfront/amazonaws patterns in output
            if "cloudfront.net" in line:
                cname = "cloudfront"
                break
            if "execute-api" in line:
                cname = "api-gateway"
                break
            if "elb.amazonaws.com" in line:
                cname = line.strip()
                break
    except Exception:
        pass

    return ip, cname

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
        except Exception:
            continue
    return None

def run_cmd(cmd):
    try:
        r = subprocess.run(
            cmd, capture_output=True,
            text=True, timeout=30
        )
        if r.stdout.strip():
            return json.loads(r.stdout)
        return {}
    except Exception:
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
    print("  Found " + str(len(accounts)) + " accounts")
    return accounts

def get_creds(token, account_id):
    data = run_cmd([
        "aws", "sso", "get-role-credentials",
        "--account-id", account_id,
        "--role-name",  ROLE_NAME,
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
    """Get all WAF WebACL associations in this account."""
    assoc = {}
    for region in REGIONS:
        try:
            waf  = session.client("wafv2", region_name=region, verify=False)
            resp = waf.list_web_acls(Scope="REGIONAL", Limit=100)
            for acl in resp.get("WebACLs", []):
                try:
                    res = waf.list_resources_for_web_acl(
                        WebACLArn=acl["ARN"]
                    )
                    for r in res.get("ResourceArns", []):
                        assoc[r] = {
                            "WAF_Name":   acl["Name"],
                            "WAF_Region": region
                        }
                except Exception:
                    pass
        except Exception:
            pass

    # CloudFront WAFs
    try:
        waf  = session.client(
            "wafv2", region_name="us-east-1", verify=False
        )
        resp = waf.list_web_acls(Scope="CLOUDFRONT", Limit=100)
        for acl in resp.get("WebACLs", []):
            try:
                res = waf.list_resources_for_web_acl(
                    WebACLArn=acl["ARN"]
                )
                for r in res.get("ResourceArns", []):
                    assoc[r] = {
                        "WAF_Name":   acl["Name"],
                        "WAF_Region": "CLOUDFRONT"
                    }
            except Exception:
                pass
    except Exception:
        pass

    return assoc

def get_cf_map(session):
    """
    Get CloudFront distributions with ALL aliases.
    These catch hostnames like api.truistassist.truist.com
    that are CNAME'd to CloudFront.
    """
    cf_map = {}
    try:
        cf   = session.client("cloudfront", verify=False)
        resp = cf.list_distributions()
        items = resp.get(
            "DistributionList", {}
        ).get("Items", [])
        for dist in items:
            arn    = dist.get("ARN", "")
            domain = dist.get("DomainName", "").lower()
            cf_map[domain] = {
                "arn":    arn,
                "name":   domain,
                "domain": domain
            }
            # Map every custom alias
            for alias in dist.get(
                "Aliases", {}
            ).get("Items", []):
                cf_map[alias.lower()] = {
                    "arn":    arn,
                    "name":   alias,
                    "domain": domain
                }
    except Exception:
        pass
    return cf_map

def get_alb_map(session):
    """Get all ALBs with their DNS names."""
    alb_map = {}
    for region in REGIONS:
        try:
            elb  = session.client(
                "elbv2", region_name=region, verify=False
            )
            resp = elb.describe_load_balancers()
            for lb in resp.get("LoadBalancers", []):
                dns = lb.get("DNSName", "").lower()
                alb_map[dns] = {
                    "arn":    lb["LoadBalancerArn"],
                    "region": region,
                    "name":   lb.get("LoadBalancerName", ""),
                    "type":   lb.get("Type", "")
                }
        except Exception:
            pass
    return alb_map

def get_apigw_map(session):
    """
    Get all API Gateways.
    Catches execute-api URLs and custom domain names.
    """
    apigw_map = {}
    for region in REGIONS:
        try:
            # REST APIs
            apigw = session.client(
                "apigateway", region_name=region, verify=False
            )
            resp  = apigw.get_rest_apis(limit=500)
            for api in resp.get("items", []):
                api_domain = (
                    api["id"] +
                    ".execute-api." +
                    region +
                    ".amazonaws.com"
                )
                apigw_map[api_domain.lower()] = {
                    "id":     api["id"],
                    "name":   api.get("name", ""),
                    "region": region,
                    "type":   "REST"
                }

            # Custom domain names
            try:
                domains = apigw.get_domain_names(limit=500)
                for d in domains.get("items", []):
                    dn = d.get("domainName", "").lower()
                    apigw_map[dn] = {
                        "id":     dn,
                        "name":   dn,
                        "region": region,
                        "type":   "Custom Domain"
                    }
            except Exception:
                pass

        except Exception:
            pass

        try:
            # HTTP APIs (API GW v2)
            apigw2 = session.client(
                "apigatewayv2", region_name=region, verify=False
            )
            resp   = apigw2.get_apis()
            for api in resp.get("Items", []):
                api_domain = (
                    api["ApiId"] +
                    ".execute-api." +
                    region +
                    ".amazonaws.com"
                )
                apigw_map[api_domain.lower()] = {
                    "id":     api["ApiId"],
                    "name":   api.get("Name", ""),
                    "region": region,
                    "type":   "HTTP"
                }

            # Custom domain names v2
            try:
                domains = apigw2.get_domain_names()
                for d in domains.get("Items", []):
                    dn = d.get("DomainName", "").lower()
                    apigw_map[dn] = {
                        "id":     dn,
                        "name":   dn,
                        "region": region,
                        "type":   "Custom Domain v2"
                    }
            except Exception:
                pass

        except Exception:
            pass

    return apigw_map

def check_host(hostname, cf_map, alb_map, apigw_map,
               waf_assoc, acc_id, acc_name):
    h          = hostname.lower()
    ip, cname  = get_full_dns_chain(hostname)
    r          = empty_result(hostname, ip, cname)
    r["Account_ID"]   = acc_id
    r["Account_Name"] = acc_name

    # ── 1. Exact CloudFront alias match ──
    if h in cf_map:
        info = cf_map[h]
        arn  = info["arn"]
        r.update({
            "Resource_Type": "CloudFront",
            "Resource_Name": info["name"],
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
            r["Notes"] = "CloudFront found — NO WAF attached"
        return r

    # ── 2. CNAME resolves to CloudFront ──
    if cname and "cloudfront.net" in cname:
        # Try to match cname to a distribution
        for cf_domain, info in cf_map.items():
            if info.get("domain", "") in cname:
                arn = info["arn"]
                r.update({
                    "Resource_Type": "CloudFront (via CNAME)",
                    "Resource_Name": cf_domain,
                    "Resource_ARN":  arn,
                    "Notes":         "CNAME: " + cname
                })
                if arn in waf_assoc:
                    w = waf_assoc[arn]
                    r.update({
                        "WAF_Protected": "YES",
                        "WAF_Name":      w["WAF_Name"],
                        "WAF_Region":    w["WAF_Region"]
                    })
                else:
                    r["Notes"] = "CloudFront via CNAME — NO WAF"
                return r
        # CloudFront detected but distribution not in this account
        r.update({
            "Resource_Type": "CloudFront (other account)",
            "Notes":         "CNAME to CloudFront: " + cname
        })
        return r

    # ── 3. Exact ALB DNS match ──
    if h in alb_map:
        info = alb_map[h]
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
            r["Notes"] = "ALB found — NO WAF attached"
        return r

    # ── 4. CNAME resolves to ALB ──
    if cname and "elb.amazonaws.com" in cname:
        alb_cname = cname.lower()
        if alb_cname in alb_map:
            info = alb_map[alb_cname]
            r.update({
                "Resource_Type": "ALB (via CNAME)",
                "Resource_Name": info["name"],
                "Resource_ARN":  info["arn"],
                "Notes":         "CNAME: " + cname
            })
            if info["arn"] in waf_assoc:
                w = waf_assoc[info["arn"]]
                r.update({
                    "WAF_Protected": "YES",
                    "WAF_Name":      w["WAF_Name"],
                    "WAF_Region":    w["WAF_Region"]
                })
            else:
                r["Notes"] = "ALB via CNAME — NO WAF"
            return r

    # ── 5. API Gateway custom domain ──
    if h in apigw_map:
        info = apigw_map[h]
        r.update({
            "Resource_Type": "API Gateway (" + info["type"] + ")",
            "Resource_Name": info["name"],
            "Notes":         "API GW custom domain — WAF via usage plan"
        })
        return r

    # ── 6. execute-api pattern ──
    if "execute-api" in h:
        r.update({
            "Resource_Type": "API Gateway",
            "Notes":         "Direct API GW URL — check WAF manually"
        })
        return r

    # ── 7. IP-based fallback — compare resolved IPs ──
    if ip and ip != "DNS_FAILED":
        # Check against ALB IPs
        for alb_dns, info in alb_map.items():
            alb_ip = dns_lookup(alb_dns)
            if alb_ip == ip and alb_ip != "DNS_FAILED":
                r.update({
                    "Resource_Type": "ALB (by IP match)",
                    "Resource_Name": info["name"],
                    "Resource_ARN":  info["arn"],
                    "Notes":         "Matched by IP: " + ip
                })
                if info["arn"] in waf_assoc:
                    w = waf_assoc[info["arn"]]
                    r.update({
                        "WAF_Protected": "YES",
                        "WAF_Name":      w["WAF_Name"],
                        "WAF_Region":    w["WAF_Region"]
                    })
                else:
                    r["Notes"] = "ALB by IP — NO WAF"
                return r

    return r

# ══════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════
print("=" * 60)
print("WAF Coverage — All Truist Accounts")
print("=" * 60)

# Load hostnames
if not os.path.exists(HOSTNAMES_FILE):
    print("ERROR: hostnames.txt not found!")
    exit(1)

with open(HOSTNAMES_FILE, encoding="utf-8-sig") as f:
    hostnames = [l.strip() for l in f if l.strip()]

if not hostnames:
    print("ERROR: hostnames.txt is empty!")
    exit(1)

print("Loaded " + str(len(hostnames)) + " hostnames")

# SSO token
token = get_sso_token()
if not token:
    print("\nERROR: No SSO token!")
    print("Run: aws sso login --profile waf-search1 --no-verify-ssl")
    exit(1)
print("SSO token OK")

# Get accounts
accounts = get_all_accounts(token)
if not accounts:
    print("ERROR: No accounts found — re-run SSO login")
    exit(1)

# Pre-populate results with DNS info
print("Resolving DNS for all hostnames...")
results = {}
for h in hostnames:
    ip, cname    = get_full_dns_chain(h)
    results[h]   = empty_result(h, ip, cname)
    print("  " + h + " -> " + ip)

print("")

# Loop every account
for i, account in enumerate(accounts):
    acc_id   = account["accountId"]
    acc_name = account.get("accountName", "unknown")
    print(
        "[" + str(i+1) + "/" + str(len(accounts)) + "] " +
        acc_name + " (" + acc_id + ")",
        end=" "
    )

    creds = get_creds(token, acc_id)
    if not creds:
        print("-- no creds, skip")
        continue

    session   = make_session(creds)
    waf_assoc = get_waf_assoc(session)
    cf_map    = get_cf_map(session)
    alb_map   = get_alb_map(session)
    apigw_map = get_apigw_map(session)

    # Skip account if nothing found at all
    if not waf_assoc and not cf_map and not alb_map and not apigw_map:
        print("-- empty, skip")
        continue

    found_in_account = False
    for hostname in hostnames:
        # Already confirmed with WAF — skip
        if results[hostname]["WAF_Protected"] == "YES":
            continue

        r = check_host(
            hostname, cf_map, alb_map,
            apigw_map, waf_assoc, acc_id, acc_name
        )

        if r["Resource_Type"] != "Not Found":
            results[hostname] = r
            found_in_account  = True
            status = "YES" if r["WAF_Protected"] == "YES" else "NO"
            print(
                "\n  FOUND: " + hostname +
                " -> WAF:" + status +
                " | " + r["Resource_Type"] +
                " | " + r.get("Notes", "")
            )

    if not found_in_account:
        print("-- nothing found")

# Write CSV
print("\nWriting report: " + OUT_FILE)
rows = [results[h] for h in hostnames]

with open(OUT_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=FIELDS)
    writer.writeheader()
    for row in rows:
        clean = {field: row.get(field, "") for field in FIELDS}
        writer.writerow(clean)

# Summary
protected     = sum(1 for r in rows if r["WAF_Protected"] == "YES")
not_protected = sum(
    1 for r in rows
    if r["WAF_Protected"] == "NO" and r["Resource_Type"] != "Not Found"
)
not_found     = sum(1 for r in rows if r["Resource_Type"] == "Not Found")

print("\n" + "=" * 60)
print("FINAL SUMMARY")
print("  Accounts scanned  : " + str(len(accounts)))
print("  Hostnames checked : " + str(len(rows)))
print("  WAF protected     : " + str(protected))
print("  Found - NO WAF    : " + str(not_protected))
print("  Not found         : " + str(not_found))
print("  Report saved      : " + OUT_FILE)
print("=" * 60)
