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
REGIONS   = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "ap-southeast-1", "ap-northeast-1"
]
OUT_FILE       = "waf_report_" + datetime.now().strftime("%Y%m%d_%H%M") + ".csv"
DEBUG_FILE     = "waf_debug_"  + datetime.now().strftime("%Y%m%d_%H%M") + ".txt"
HOSTNAMES_FILE = "hostnames.txt"
ROLE_NAME      = "G-ROLE-AWS-ENT-WAFADMIN-RO"

FIELDS = [
    "Hostname", "IP", "CNAME",
    "Resource_Type", "Resource_Name", "Resource_ARN",
    "WAF_Protected", "WAF_Name", "WAF_Region",
    "Account_ID", "Account_Name", "Notes"
]

debug_lines = []

def log(msg):
    print(msg)
    debug_lines.append(str(msg))

def empty_result(hostname, ip="", cname=""):
    result = {f: "" for f in FIELDS}
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

def get_full_dns_chain(hostname):
    ip    = dns_lookup(hostname)
    cname = ""
    try:
        r = subprocess.run(
            ["nslookup", hostname],
            capture_output=True, text=True, timeout=10
        )
        output = r.stdout.lower()
        for line in output.split("\n"):
            if "canonical name" in line:
                parts = line.split("=")
                if len(parts) > 1:
                    cname = parts[1].strip().rstrip(".")
                    break
            if "cloudfront.net" in line and not cname:
                for part in line.split():
                    if "cloudfront.net" in part:
                        cname = part.strip().rstrip(".")
                        break
            if "elb.amazonaws.com" in line and not cname:
                for part in line.split():
                    if "elb.amazonaws.com" in part:
                        cname = part.strip().rstrip(".")
                        break
            if "execute-api" in line and not cname:
                cname = "api-gateway-detected"
    except Exception:
        pass
    return ip, cname

def get_sso_token():
    cache_files = glob.glob(os.path.expanduser("~/.aws/sso/cache/*.json"))
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
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.stdout.strip():
            return json.loads(r.stdout)
        return {}
    except Exception:
        return {}

def get_all_accounts(token):
    log("Fetching all accounts...")
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
    log("  Found " + str(len(accounts)) + " accounts")
    return accounts

def get_creds(token, account_id):
    data = run_cmd(["aws", "sso", "get-role-credentials",
                    "--account-id", account_id,
                    "--role-name",  ROLE_NAME,
                    "--access-token", token,
                    "--region", "us-east-1",
                    "--no-verify-ssl", "--output", "json"])
    return data.get("roleCredentials")

def make_session(creds):
    return boto3.Session(
        aws_access_key_id     = creds["accessKeyId"],
        aws_secret_access_key = creds["secretAccessKey"],
        aws_session_token     = creds["sessionToken"]
    )

def get_waf_assoc(session, acc_id):
    assoc = {}
    for region in REGIONS:
        try:
            waf  = session.client("wafv2", region_name=region, verify=False)
            resp = waf.list_web_acls(Scope="REGIONAL", Limit=100)
            acls = resp.get("WebACLs", [])
            if acls:
                log("    WAF Regional " + region + ": " + str(len(acls)) + " ACLs")
            for acl in acls:
                try:
                    res = waf.list_resources_for_web_acl(WebACLArn=acl["ARN"])
                    for r in res.get("ResourceArns", []):
                        assoc[r] = {"WAF_Name": acl["Name"], "WAF_Region": region}
                        log("      -> " + acl["Name"] + " protects: " + r)
                except Exception:
                    pass
        except Exception:
            pass
    try:
        waf  = session.client("wafv2", region_name="us-east-1", verify=False)
        resp = waf.list_web_acls(Scope="CLOUDFRONT", Limit=100)
        acls = resp.get("WebACLs", [])
        if acls:
            log("    WAF CloudFront: " + str(len(acls)) + " ACLs in " + acc_id)
        for acl in acls:
            try:
                res = waf.list_resources_for_web_acl(WebACLArn=acl["ARN"])
                for r in res.get("ResourceArns", []):
                    assoc[r] = {"WAF_Name": acl["Name"], "WAF_Region": "CLOUDFRONT"}
                    log("      -> " + acl["Name"] + " protects: " + r)
            except Exception:
                pass
    except Exception:
        pass
    return assoc

def get_cf_map(session, acc_id):
    cf_map = {}
    try:
        cf    = session.client("cloudfront", verify=False)
        resp  = cf.list_distributions()
        items = resp.get("DistributionList", {}).get("Items", [])
        if items:
            log("    CloudFront: " + str(len(items)) + " distributions in " + acc_id)
        for dist in items:
            arn    = dist.get("ARN", "")
            domain = dist.get("DomainName", "").lower()
            cf_map[domain] = {"arn": arn, "name": domain, "domain": domain}
            for alias in dist.get("Aliases", {}).get("Items", []):
                cf_map[alias.lower()] = {"arn": arn, "name": alias, "domain": domain}
                log("      CF alias: " + alias)
    except Exception:
        pass
    return cf_map

def get_alb_map(session, acc_id):
    alb_map = {}
    for region in REGIONS:
        try:
            elb  = session.client("elbv2", region_name=region, verify=False)
            resp = elb.describe_load_balancers()
            lbs  = resp.get("LoadBalancers", [])
            if lbs:
                log("    ALBs in " + region + ": " + str(len(lbs)))
            for lb in lbs:
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

def get_apigw_map(session, acc_id):
    apigw_map = {}
    for region in REGIONS:
        try:
            apigw = session.client("apigateway", region_name=region, verify=False)
            try:
                domains = apigw.get_domain_names(limit=500)
                doms = domains.get("items", [])
                if doms:
                    log("    API GW custom domains in " + region + ": " + str(len(doms)))
                for d in doms:
                    dn = d.get("domainName", "").lower()
                    apigw_map[dn] = {"id": dn, "name": dn, "region": region, "type": "Custom Domain"}
                    log("      APIGW domain: " + dn)
            except Exception:
                pass
            try:
                apis = apigw.get_rest_apis(limit=500)
                for api in apis.get("items", []):
                    api_domain = api["id"] + ".execute-api." + region + ".amazonaws.com"
                    apigw_map[api_domain.lower()] = {
                        "id": api["id"], "name": api.get("name", ""),
                        "region": region, "type": "REST"
                    }
            except Exception:
                pass
        except Exception:
            pass
        try:
            apigw2 = session.client("apigatewayv2", region_name=region, verify=False)
            try:
                domains = apigw2.get_domain_names()
                doms = domains.get("Items", [])
                if doms:
                    log("    API GWv2 custom domains in " + region + ": " + str(len(doms)))
                for d in doms:
                    dn = d.get("DomainName", "").lower()
                    apigw_map[dn] = {"id": dn, "name": dn, "region": region, "type": "Custom Domain v2"}
                    log("      APIGWv2 domain: " + dn)
            except Exception:
                pass
            try:
                apis = apigw2.get_apis()
                for api in apis.get("Items", []):
                    api_domain = api["ApiId"] + ".execute-api." + region + ".amazonaws.com"
                    apigw_map[api_domain.lower()] = {
                        "id": api["ApiId"], "name": api.get("Name", ""),
                        "region": region, "type": "HTTP"
                    }
            except Exception:
                pass
        except Exception:
            pass
    return apigw_map

def get_route53_map(session, acc_id):
    r53_map = {}
    try:
        r53   = session.client("route53", verify=False)
        zones = r53.list_hosted_zones()
        for zone in zones.get("HostedZones", []):
            zone_id = zone["Id"].split("/")[-1]
            try:
                records = r53.list_resource_record_sets(HostedZoneId=zone_id)
                for rec in records.get("ResourceRecordSets", []):
                    name  = rec.get("Name", "").lower().rstrip(".")
                    rtype = rec.get("Type", "")
                    if rtype == "CNAME":
                        for rr in rec.get("ResourceRecords", []):
                            val = rr.get("Value", "").lower()
                            r53_map[name] = {"cname": val, "type": "CNAME", "zone": zone.get("Name", "")}
                    if "AliasTarget" in rec:
                        alias_dns = rec["AliasTarget"].get("DNSName", "").lower().rstrip(".")
                        r53_map[name] = {"cname": alias_dns, "type": "ALIAS", "zone": zone.get("Name", "")}
                        if ("cloudfront" in alias_dns or "elb.amazonaws" in alias_dns or "execute-api" in alias_dns):
                            log("      R53 alias: " + name + " -> " + alias_dns)
            except Exception:
                pass
    except Exception:
        pass
    return r53_map

def check_host(hostname, cf_map, alb_map, apigw_map, r53_map, waf_assoc, acc_id, acc_name):
    h         = hostname.lower()
    ip, cname = get_full_dns_chain(hostname)
    r         = empty_result(hostname, ip, cname)
    r["Account_ID"]   = acc_id
    r["Account_Name"] = acc_name

    # 1. Exact CloudFront alias
    if h in cf_map:
        info = cf_map[h]
        arn  = info["arn"]
        r.update({"Resource_Type": "CloudFront", "Resource_Name": info["name"], "Resource_ARN": arn, "Notes": ""})
        if arn in waf_assoc:
            w = waf_assoc[arn]
            r.update({"WAF_Protected": "YES", "WAF_Name": w["WAF_Name"], "WAF_Region": w["WAF_Region"]})
        else:
            r["Notes"] = "CloudFront found - NO WAF"
        return r

    # 2. Route53 record
    if h in r53_map:
        rec    = r53_map[h]
        target = rec.get("cname", "")
        if "cloudfront.net" in target:
            for cf_domain, info in cf_map.items():
                if info.get("domain", "") in target or target in info.get("domain", ""):
                    arn = info["arn"]
                    r.update({"Resource_Type": "CloudFront (via Route53)", "Resource_Name": cf_domain, "Resource_ARN": arn, "Notes": "R53 -> " + target})
                    if arn in waf_assoc:
                        w = waf_assoc[arn]
                        r.update({"WAF_Protected": "YES", "WAF_Name": w["WAF_Name"], "WAF_Region": w["WAF_Region"]})
                    else:
                        r["Notes"] = "CloudFront via R53 - NO WAF"
                    return r
            r.update({"Resource_Type": "CloudFront (via Route53)", "Notes": "Points to CF: " + target})
            return r
        if "elb.amazonaws.com" in target:
            alb_key = target.rstrip(".")
            if alb_key in alb_map:
                info = alb_map[alb_key]
                r.update({"Resource_Type": "ALB (via Route53)", "Resource_Name": info["name"], "Resource_ARN": info["arn"], "Notes": "R53 -> " + target})
                if info["arn"] in waf_assoc:
                    w = waf_assoc[info["arn"]]
                    r.update({"WAF_Protected": "YES", "WAF_Name": w["WAF_Name"], "WAF_Region": w["WAF_Region"]})
                else:
                    r["Notes"] = "ALB via R53 - NO WAF"
                return r
        if "execute-api" in target or "amazonaws.com" in target:
            r.update({"Resource_Type": "API Gateway (via Route53)", "Notes": "R53 -> " + target})
            return r
        r.update({"Resource_Type": "Route53 Record", "Notes": rec["type"] + " -> " + target})
        return r

    # 3. CNAME to CloudFront
    if cname and "cloudfront.net" in cname:
        for cf_domain, info in cf_map.items():
            if info.get("domain", "") in cname:
                arn = info["arn"]
                r.update({"Resource_Type": "CloudFront (via CNAME)", "Resource_Name": cf_domain, "Resource_ARN": arn, "Notes": "CNAME: " + cname})
                if arn in waf_assoc:
                    w = waf_assoc[arn]
                    r.update({"WAF_Protected": "YES", "WAF_Name": w["WAF_Name"], "WAF_Region": w["WAF_Region"]})
                else:
                    r["Notes"] = "CloudFront via CNAME - NO WAF"
                return r
        r.update({"Resource_Type": "CloudFront (other account)", "Notes": "CNAME to CF: " + cname})
        return r

    # 4. Exact ALB DNS match
    if h in alb_map:
        info = alb_map[h]
        r.update({"Resource_Type": "ALB", "Resource_Name": info["name"], "Resource_ARN": info["arn"], "Notes": ""})
        if info["arn"] in waf_assoc:
            w = waf_assoc[info["arn"]]
            r.update({"WAF_Protected": "YES", "WAF_Name": w["WAF_Name"], "WAF_Region": w["WAF_Region"]})
        else:
            r["Notes"] = "ALB found - NO WAF"
        return r

    # 5. CNAME to ALB
    if cname and "elb.amazonaws.com" in cname:
        alb_key = cname.rstrip(".")
        if alb_key in alb_map:
            info = alb_map[alb_key]
            r.update({"Resource_Type": "ALB (via CNAME)", "Resource_Name": info["name"], "Resource_ARN": info["arn"], "Notes": "CNAME: " + cname})
            if info["arn"] in waf_assoc:
                w = waf_assoc[info["arn"]]
                r.update({"WAF_Protected": "YES", "WAF_Name": w["WAF_Name"], "WAF_Region": w["WAF_Region"]})
            else:
                r["Notes"] = "ALB via CNAME - NO WAF"
            return r

    # 6. API Gateway custom domain
    if h in apigw_map:
        info = apigw_map[h]
        r.update({"Resource_Type": "API Gateway (" + info["type"] + ")", "Resource_Name": info["name"], "Notes": "API GW custom domain"})
        return r

    # 7. execute-api pattern
    if "execute-api" in h:
        r.update({"Resource_Type": "API Gateway", "Notes": "Direct API GW URL"})
        return r

    # 8. IP fallback
    if ip and ip != "DNS_FAILED":
        for alb_dns, info in alb_map.items():
            try:
                alb_ip = socket.gethostbyname(alb_dns)
                if alb_ip == ip:
                    r.update({"Resource_Type": "ALB (by IP)", "Resource_Name": info["name"], "Resource_ARN": info["arn"], "Notes": "Matched by IP: " + ip})
                    if info["arn"] in waf_assoc:
                        w = waf_assoc[info["arn"]]
                        r.update({"WAF_Protected": "YES", "WAF_Name": w["WAF_Name"], "WAF_Region": w["WAF_Region"]})
                    else:
                        r["Notes"] = "ALB by IP - NO WAF"
                    return r
            except Exception:
                pass

    return r

# MAIN
log("=" * 60)
log("WAF Coverage - All Truist Accounts")
log("=" * 60)

if not os.path.exists(HOSTNAMES_FILE):
    log("ERROR: hostnames.txt not found!")
    exit(1)

with open(HOSTNAMES_FILE, encoding="utf-8-sig") as f:
    hostnames = [l.strip() for l in f if l.strip()]

if not hostnames:
    log("ERROR: hostnames.txt is empty!")
    exit(1)

log("Loaded " + str(len(hostnames)) + " hostnames")

token = get_sso_token()
if not token:
    log("ERROR: No SSO token! Run: aws sso login --profile waf-search1 --no-verify-ssl")
    exit(1)
log("SSO token OK")

accounts = get_all_accounts(token)
if not accounts:
    log("ERROR: No accounts found!")
    exit(1)

log("\nResolving DNS for all hostnames...")
results = {}
for h in hostnames:
    ip, cname  = get_full_dns_chain(h)
    results[h] = empty_result(h, ip, cname)
    log("  " + h + " -> " + ip + (" [" + cname + "]" if cname else ""))

log("")

for i, account in enumerate(accounts):
    acc_id   = account["accountId"]
    acc_name = account.get("accountName", "unknown")
    log("[" + str(i+1) + "/" + str(len(accounts)) + "] " + acc_name + " (" + acc_id + ")")

    creds = get_creds(token, acc_id)
    if not creds:
        log("  -- no creds, skip")
        continue

    session   = make_session(creds)
    waf_assoc = get_waf_assoc(session, acc_id)
    cf_map    = get_cf_map(session, acc_id)
    alb_map   = get_alb_map(session, acc_id)
    apigw_map = get_apigw_map(session, acc_id)
    r53_map   = get_route53_map(session, acc_id)

    if not waf_assoc and not cf_map and not alb_map and not apigw_map and not r53_map:
        log("  -- empty, skip")
        continue

    found_in_account = False
    for hostname in hostnames:
        if results[hostname]["WAF_Protected"] == "YES":
            continue
        r = check_host(hostname, cf_map, alb_map, apigw_map, r53_map, waf_assoc, acc_id, acc_name)
        if r["Resource_Type"] != "Not Found":
            results[hostname] = r
            found_in_account  = True
            status = "YES" if r["WAF_Protected"] == "YES" else "NO"
            log("  FOUND: " + hostname + " -> WAF:" + status + " | " + r["Resource_Type"] + " | " + r.get("Notes", ""))

    if not found_in_account:
        log("  -- nothing matched")

log("\nWriting report: " + OUT_FILE)
rows = [results[h] for h in hostnames]

with open(OUT_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=FIELDS)
    writer.writeheader()
    for row in rows:
        clean = {field: row.get(field, "") for field in FIELDS}
        writer.writerow(clean)

with open(DEBUG_FILE, "w", encoding="utf-8") as f:
    f.write("\n".join(debug_lines))

protected     = sum(1 for r in rows if r["WAF_Protected"] == "YES")
not_protected = sum(1 for r in rows if r["WAF_Protected"] == "NO" and r["Resource_Type"] != "Not Found")
not_found     = sum(1 for r in rows if r["Resource_Type"] == "Not Found")

log("\n" + "=" * 60)
log("FINAL SUMMARY")
log("  Accounts scanned  : " + str(len(accounts)))
log("  Hostnames checked : " + str(len(rows)))
log("  WAF protected     : " + str(protected))
log("  Found - NO WAF    : " + str(not_protected))
log("  Not found         : " + str(not_found))
log("  Report saved      : " + OUT_FILE)
log("  Debug log saved   : " + DEBUG_FILE)
log("=" * 60)
