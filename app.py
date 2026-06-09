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

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
os.environ["PYTHONHTTPSVERIFY"] = "0"
ssl._create_default_https_context = ssl._create_unverified_context

HOSTNAMES_FILE = "hostnames.txt"
ROLE_NAME      = "G-ROLE-AWS-ENT-WAFADMIN-RO"
OUT_FILE       = "waf_full_report_" + datetime.now().strftime("%Y%m%d_%H%M") + ".csv"

REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "ap-southeast-1", "ap-northeast-1"
]

FIELDS = [
    "Custom_Domain_Name",
    "Account_ID",
    "Account_Name",
    "Resource_Type",
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

def get_waf_by_stage_arn(session, region, api_id, stage_name):
    """Check WAF directly on API Gateway stage webAclArn property."""
    try:
        client = session.client("apigateway", region_name=region, verify=False)
        stage  = client.get_stage(restApiId=api_id, stageName=stage_name)
        web_acl = stage.get("webAclArn", "")
        if web_acl:
            return web_acl.split("/")[-1], web_acl, "Direct (Stage)"
    except:
        pass
    return "", "", ""

def get_regional_waf_map(session, region):
    waf_map = {}
    try:
        waf  = session.client("wafv2", region_name=region, verify=False)
        resp = waf.list_web_acls(Scope="REGIONAL", Limit=100)
        for acl in resp.get("WebACLs", []):
            acl_name   = acl["Name"]
            acl_arn    = acl["ARN"]
            managed_by = "Direct"
            try:
                tags_resp = waf.list_tags_for_resource(ResourceARN=acl_arn)
                for tag in tags_resp.get("TagInfoForResource", {}).get("TagList", []):
                    if "fms" in tag.get("Key","").lower():
                        managed_by = "Firewall Manager"
                        break
            except:
                pass
            try:
                res = waf.list_resources_for_web_acl(WebACLArn=acl_arn)
                for r_arn in res.get("ResourceArns", []):
                    waf_map[r_arn] = {
                        "waf_name":   acl_name,
                        "waf_arn":    acl_arn,
                        "managed_by": managed_by,
                        "waf_region": region
                    }
            except:
                pass
    except:
        pass
    return waf_map

def scan_route53_all_zones(session, acc_id, acc_name):
    """
    Scan ALL Route53 hosted zones (public AND private).
    Returns dict: hostname -> {target, zone_name, zone_type}
    This catches apicpcamue1.brnchline.connectdev.truist.com style records.
    """
    r53_map = {}
    try:
        r53   = session.client("route53", verify=False)

        # Get all hosted zones including private
        paginator = r53.get_paginator("list_hosted_zones")
        for page in paginator.paginate():
            for zone in page.get("HostedZones", []):
                zone_id   = zone["Id"].split("/")[-1]
                zone_name = zone["Name"].rstrip(".").lower()
                zone_type = "Private" if zone.get("Config",{}).get("PrivateZone") else "Public"

                try:
                    rec_paginator = r53.get_paginator("list_resource_record_sets")
                    for rec_page in rec_paginator.paginate(HostedZoneId=zone_id):
                        for rec in rec_page.get("ResourceRecordSets", []):
                            rec_name = rec.get("Name","").rstrip(".").lower()
                            rec_type = rec.get("Type","")

                            target = ""

                            # Alias record
                            if "AliasTarget" in rec:
                                target = rec["AliasTarget"].get(
                                    "DNSName",""
                                ).rstrip(".").lower()

                            # CNAME record
                            elif rec_type == "CNAME":
                                rrs = rec.get("ResourceRecords", [])
                                if rrs:
                                    target = rrs[0].get("Value","").rstrip(".").lower()

                            if target:
                                r53_map[rec_name] = {
                                    "target":    target,
                                    "zone_name": zone_name,
                                    "zone_type": zone_type,
                                    "rec_type":  rec_type,
                                    "acc_id":    acc_id,
                                    "acc_name":  acc_name
                                }
                except Exception:
                    pass
    except Exception:
        pass
    return r53_map

def get_apigw_domain_map(session, acc_id, acc_name):
    """Scan all API GW custom domains across all regions."""
    found = []

    for region in REGIONS:
        regional_waf = get_regional_waf_map(session, region)

        # REST API v1
        try:
            client  = session.client("apigateway", region_name=region, verify=False)
            domains = client.get_domain_names(limit=500).get("items", [])

            if domains:
                print("    [" + region + "] REST domains: " + str(len(domains)))

            for domain in domains:
                dn         = domain.get("domainName","")
                api_id     = ""
                api_name   = ""
                stage_name = ""

                try:
                    for m in client.get_base_path_mappings(
                        domainName=dn, limit=500
                    ).get("items", []):
                        a_id = m.get("restApiId","")
                        if a_id:
                            stage_name = m.get("stage","")
                            try:
                                api_name = client.get_rest_api(
                                    restApiId=a_id
                                ).get("name","")
                            except:
                                pass
                            api_id = a_id
                            break
                except:
                    pass

                waf_name   = ""
                waf_arn    = ""
                managed_by = ""

                # Check resource ARN map
                if api_id:
                    for r_arn, w in regional_waf.items():
                        if api_id in r_arn:
                            waf_name   = w["waf_name"]
                            waf_arn    = w["waf_arn"]
                            managed_by = w["managed_by"]
                            break

                # Direct stage webAclArn check
                if not waf_name and api_id and stage_name:
                    waf_name, waf_arn, managed_by = get_waf_by_stage_arn(
                        session, region, api_id, stage_name
                    )

                # Check all stages if still not found
                if not waf_name and api_id:
                    try:
                        stgs = client.get_stages(restApiId=api_id).get("item",[])
                        for stg in stgs:
                            sn = stg.get("stageName","")
                            wn, wa, mb = get_waf_by_stage_arn(
                                session, region, api_id, sn
                            )
                            if wn:
                                waf_name   = wn
                                waf_arn    = wa
                                managed_by = mb
                                if not stage_name:
                                    stage_name = sn
                                break
                    except:
                        pass

                found.append({
                    "dn": dn, "api_id": api_id, "api_name": api_name,
                    "api_type": "REST", "stage_name": stage_name,
                    "waf_name": waf_name, "waf_arn": waf_arn,
                    "managed_by": managed_by, "region": region,
                    "acc_id": acc_id, "acc_name": acc_name,
                    "res_type": "API Gateway"
                })

        except:
            pass

        # HTTP API v2
        try:
            client  = session.client("apigatewayv2", region_name=region, verify=False)
            domains = client.get_domain_names().get("Items", [])

            if domains:
                print("    [" + region + "] HTTP domains: " + str(len(domains)))

            for domain in domains:
                dn         = domain.get("DomainName","")
                api_id     = ""
                api_name   = ""
                stage_name = ""

                try:
                    for m in client.get_api_mappings(DomainName=dn).get("Items",[]):
                        a_id = m.get("ApiId","")
                        if a_id:
                            stage_name = m.get("Stage","")
                            try:
                                api_name = client.get_api(ApiId=a_id).get("Name","")
                            except:
                                pass
                            api_id = a_id
                            break
                except:
                    pass

                waf_name   = ""
                waf_arn    = ""
                managed_by = ""

                if api_id:
                    for r_arn, w in regional_waf.items():
                        if api_id in r_arn:
                            waf_name   = w["waf_name"]
                            waf_arn    = w["waf_arn"]
                            managed_by = w["managed_by"]
                            break

                found.append({
                    "dn": dn, "api_id": api_id, "api_name": api_name,
                    "api_type": "HTTP", "stage_name": stage_name,
                    "waf_name": waf_name, "waf_arn": waf_arn,
                    "managed_by": managed_by, "region": region,
                    "acc_id": acc_id, "acc_name": acc_name,
                    "res_type": "API Gateway"
                })
        except:
            pass

    return found

def get_cloudfront_map(session, acc_id, acc_name):
    """
    Get ALL CloudFront distributions with aliases and WAF.
    Uses list_distributions_by_web_acl_id (correct method).
    Falls back to scanning all distributions.
    """
    cf_map = {}

    # Method 1 — via WAF ACL list
    try:
        waf  = session.client("wafv2", region_name="us-east-1", verify=False)
        resp = waf.list_web_acls(Scope="CLOUDFRONT", Limit=100)

        for acl in resp.get("WebACLs", []):
            acl_name   = acl["Name"]
            acl_arn    = acl["ARN"]
            managed_by = "Direct"

            try:
                tags_resp = waf.list_tags_for_resource(ResourceARN=acl_arn)
                for tag in tags_resp.get("TagInfoForResource",{}).get("TagList",[]):
                    if "fms" in tag.get("Key","").lower():
                        managed_by = "Firewall Manager"
                        break
            except:
                pass

            # Correct method for CloudFront
            try:
                cf = session.client("cloudfront", verify=False)
                dr = cf.list_distributions_by_web_acl_id(
                    WebAclId=acl_arn, MaxItems="100"
                )
                for dist in dr.get("DistributionList",{}).get("Items",[]):
                    dist_domain = dist.get("DomainName","").lower()
                    dist_arn    = dist.get("ARN","")
                    aliases     = dist.get("Aliases",{}).get("Items",[])

                    entry = {
                        "waf_name":   acl_name, "waf_arn": acl_arn,
                        "managed_by": managed_by, "dist_arn": dist_arn,
                        "dist_domain": dist_domain, "acc_id": acc_id,
                        "acc_name": acc_name
                    }
                    cf_map[dist_domain] = entry
                    for alias in aliases:
                        cf_map[alias.lower()] = entry
                        print("      CF alias: " + alias + " WAF: " + acl_name)
            except:
                pass
    except:
        pass

    # Method 2 — scan ALL distributions and check webAclId
    try:
        cf   = session.client("cloudfront", verify=False)
        resp = cf.list_distributions()
        dists = resp.get("DistributionList",{}).get("Items",[])

        if dists:
            print("    CF distributions in " + acc_id + ": " + str(len(dists)))

        for dist in dists:
            dist_domain = dist.get("DomainName","").lower()
            dist_arn    = dist.get("ARN","")
            dist_id     = dist.get("Id","")
            aliases     = dist.get("Aliases",{}).get("Items",[])
            web_acl_id  = dist.get("WebACLId","")

            # If not yet in map, add it
            all_names = [dist_domain] + [a.lower() for a in aliases]
            if not any(n in cf_map for n in all_names):

                # Get full config to find WebACLId
                if not web_acl_id:
                    try:
                        config     = cf.get_distribution_config(Id=dist_id)
                        web_acl_id = config.get("DistributionConfig",{}).get("WebACLId","")
                    except:
                        pass

                waf_name   = ""
                managed_by = ""
                if web_acl_id:
                    waf_name   = web_acl_id.split("/")[-1]
                    managed_by = "Direct"

                entry = {
                    "waf_name":    waf_name,
                    "waf_arn":     web_acl_id,
                    "managed_by":  managed_by,
                    "dist_arn":    dist_arn,
                    "dist_domain": dist_domain,
                    "acc_id":      acc_id,
                    "acc_name":    acc_name
                }
                for n in all_names:
                    cf_map[n] = entry
                    if waf_name:
                        print("      CF (by scan): " + n + " WAF: " + waf_name)

    except:
        pass

    return cf_map

def find_in_r53(hostname, r53_map, apigw_map, cf_map):
    """
    For hostnames that didn't match directly:
    Follow Route53 chain to find the underlying resource.
    """
    h = hostname.lower()

    if h not in r53_map:
        return None

    rec    = r53_map[h]
    target = rec["target"]

    # R53 -> CloudFront
    if "cloudfront.net" in target:
        # Find in CF map
        for cf_domain, cf_info in cf_map.items():
            if cf_info.get("dist_domain","") in target or target in cf_info.get("dist_domain",""):
                return {
                    "res_type":   "CloudFront (via Route53)",
                    "api_name":   cf_info.get("dist_domain",""),
                    "api_id":     cf_info.get("dist_arn",""),
                    "api_type":   "",
                    "stage_name": "",
                    "waf_name":   cf_info.get("waf_name",""),
                    "waf_arn":    cf_info.get("waf_arn",""),
                    "managed_by": cf_info.get("managed_by",""),
                    "region":     "us-east-1",
                    "acc_id":     cf_info.get("acc_id",""),
                    "acc_name":   cf_info.get("acc_name",""),
                    "notes":      "R53 " + rec["zone_type"] + " -> CF: " + target
                }
        # CF in different account
        return {
            "res_type":   "CloudFront (via Route53 - diff account)",
            "api_name":   "", "api_id": "", "api_type": "",
            "stage_name": "", "waf_name": "", "waf_arn": "",
            "managed_by": "", "region": "us-east-1",
            "acc_id":     rec["acc_id"], "acc_name": rec["acc_name"],
            "notes":      "R53 -> CF: " + target + " (check CF account)"
        }

    # R53 -> API Gateway
    if "execute-api" in target or "amazonaws.com" in target:
        for d in apigw_map:
            if d["api_id"] and d["api_id"] in target:
                return {
                    "res_type":   "API Gateway (via Route53)",
                    "api_name":   d["api_name"],
                    "api_id":     d["api_id"],
                    "api_type":   d["api_type"],
                    "stage_name": d["stage_name"],
                    "waf_name":   d["waf_name"],
                    "waf_arn":    d["waf_arn"],
                    "managed_by": d["managed_by"],
                    "region":     d["region"],
                    "acc_id":     d["acc_id"],
                    "acc_name":   d["acc_name"],
                    "notes":      "R53 -> API GW: " + target
                }
        return {
            "res_type":   "API Gateway (via Route53)",
            "api_name":   target, "api_id": "", "api_type": "",
            "stage_name": "", "waf_name": "", "waf_arn": "",
            "managed_by": "", "region":     "us-east-1",
            "acc_id":     rec["acc_id"], "acc_name": rec["acc_name"],
            "notes":      "R53 -> API GW: " + target
        }

    # R53 -> ALB/ELB
    if "elb.amazonaws.com" in target:
        return {
            "res_type":   "ALB (via Route53)",
            "api_name":   target, "api_id": "", "api_type": "",
            "stage_name": "", "waf_name": "", "waf_arn": "",
            "managed_by": "", "region":     rec.get("acc_id",""),
            "acc_id":     rec["acc_id"], "acc_name": rec["acc_name"],
            "notes":      "R53 " + rec["zone_type"] + " -> ALB: " + target
        }

    # Generic R53 record
    return {
        "res_type":   "Route53 (" + rec["zone_type"] + ")",
        "api_name":   target, "api_id": "", "api_type": "",
        "stage_name": "", "waf_name": "", "waf_arn": "",
        "managed_by": "", "region": "",
        "acc_id":     rec["acc_id"], "acc_name": rec["acc_name"],
        "notes":      "R53 " + rec["rec_type"] + " -> " + target
    }

def build_row(hostname, resource):
    acc_id = resource.get("acc_id","")
    return {
        "Custom_Domain_Name": hostname,
        "Account_ID":         "'" + acc_id if acc_id else "",
        "Account_Name":       resource.get("acc_name",""),
        "Resource_Type":      resource.get("res_type",""),
        "API_Name":           resource.get("api_name",""),
        "API_ID":             resource.get("api_id",""),
        "API_Type":           resource.get("api_type",""),
        "Stage_Name":         resource.get("stage_name",""),
        "WebACL_Name":        resource.get("waf_name",""),
        "WebACL_ARN":         resource.get("waf_arn",""),
        "WAF_Region":         resource.get("region",""),
        "WAF_Managed_By":     resource.get("managed_by",""),
        "Region":             resource.get("region",""),
        "WAF_Protected":      "YES" if resource.get("waf_name") else "NO",
        "Notes":              resource.get("notes","")
    }

# ══════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════
print("=" * 60)
print("WAF Coverage — API Gateway + CloudFront + Route53")
print("=" * 60)

if not os.path.exists(HOSTNAMES_FILE):
    print("ERROR: hostnames.txt not found!")
    exit(1)

with open(HOSTNAMES_FILE, encoding="utf-8-sig") as f:
    hostnames = [l.strip().lower() for l in f if l.strip()]

if not hostnames:
    print("ERROR: hostnames.txt is empty!")
    exit(1)

print("Loaded " + str(len(hostnames)) + " hostnames")

token = get_sso_token()
if not token:
    print("ERROR: No SSO token!")
    print("Run: aws sso login --profile waf-search1 --no-verify-ssl")
    exit(1)
print("SSO token OK\n")

accounts = get_all_accounts(token)
if not accounts:
    print("ERROR: No accounts found!")
    exit(1)

print("\nScanning " + str(len(accounts)) + " accounts...\n")

all_apigw = []
all_cf    = {}
all_r53   = {}

for i, account in enumerate(accounts):
    acc_id   = account["accountId"]
    acc_name = account.get("accountName","unknown")

    if i % 20 == 0:
        print("[" + str(i) + "/" + str(len(accounts)) + "] "
              "APIGW=" + str(len(all_apigw)) +
              " CF=" + str(len(all_cf)) +
              " R53=" + str(len(all_r53)))

    creds = get_creds(token, acc_id)
    if not creds:
        continue

    session = make_session(creds)

    # API Gateway
    apigw_results = get_apigw_domain_map(session, acc_id, acc_name)
    if apigw_results:
        all_apigw.extend(apigw_results)

    # CloudFront
    cf_results = get_cloudfront_map(session, acc_id, acc_name)
    for alias, info in cf_results.items():
        if alias not in all_cf:
            all_cf[alias] = info
        elif not all_cf[alias].get("waf_name") and info.get("waf_name"):
            all_cf[alias] = info

    # Route53 — catches internal/private DNS
    r53_results = scan_route53_all_zones(session, acc_id, acc_name)
    for rec_name, info in r53_results.items():
        if rec_name not in all_r53:
            all_r53[rec_name] = info

print("\nScan complete:")
print("  API GW domains : " + str(len(all_apigw)))
print("  CF aliases     : " + str(len(all_cf)))
print("  R53 records    : " + str(len(all_r53)))

# Match hostnames
print("\nMatching " + str(len(hostnames)) + " hostnames...")
print("=" * 60)

matched   = []
unmatched = []

for hostname in hostnames:
    row = None

    # 1 — Exact API GW match
    for d in all_apigw:
        if hostname == d["dn"].lower():
            row = build_row(hostname, {
                "res_type":   "API Gateway",
                "api_name":   d["api_name"],
                "api_id":     d["api_id"],
                "api_type":   d["api_type"],
                "stage_name": d["stage_name"],
                "waf_name":   d["waf_name"],
                "waf_arn":    d["waf_arn"],
                "managed_by": d["managed_by"],
                "region":     d["region"],
                "acc_id":     d["acc_id"],
                "acc_name":   d["acc_name"]
            })
            break

    # 2 — Exact CF match
    if not row and hostname in all_cf:
        cf = all_cf[hostname]
        row = build_row(hostname, {
            "res_type":   "CloudFront",
            "api_name":   cf.get("dist_domain",""),
            "api_id":     cf.get("dist_arn",""),
            "api_type":   "",
            "stage_name": "",
            "waf_name":   cf.get("waf_name",""),
            "waf_arn":    cf.get("waf_arn",""),
            "managed_by": cf.get("managed_by",""),
            "region":     "us-east-1",
            "acc_id":     cf.get("acc_id",""),
            "acc_name":   cf.get("acc_name","")
        })

    # 3 — Route53 chain
    if not row:
        r53_result = find_in_r53(hostname, all_r53, all_apigw, all_cf)
        if r53_result:
            row = build_row(hostname, r53_result)

    # 4 — Partial API GW match
    if not row:
        for d in all_apigw:
            dn = d["dn"].lower()
            if hostname in dn or dn in hostname:
                row = build_row(hostname, {
                    "res_type":   "API Gateway (partial)",
                    "api_name":   d["api_name"],
                    "api_id":     d["api_id"],
                    "api_type":   d["api_type"],
                    "stage_name": d["stage_name"],
                    "waf_name":   d["waf_name"],
                    "waf_arn":    d["waf_arn"],
                    "managed_by": d["managed_by"],
                    "region":     d["region"],
                    "acc_id":     d["acc_id"],
                    "acc_name":   d["acc_name"],
                    "notes":      "Partial match: " + d["dn"]
                })
                break

    # 5 — Partial CF match
    if not row:
        for alias, cf in all_cf.items():
            if hostname in alias or alias in hostname:
                row = build_row(hostname, {
                    "res_type":   "CloudFront (partial)",
                    "api_name":   cf.get("dist_domain",""),
                    "api_id":     cf.get("dist_arn",""),
                    "api_type":   "",
                    "stage_name": "",
                    "waf_name":   cf.get("waf_name",""),
                    "waf_arn":    cf.get("waf_arn",""),
                    "managed_by": cf.get("managed_by",""),
                    "region":     "us-east-1",
                    "acc_id":     cf.get("acc_id",""),
                    "acc_name":   cf.get("acc_name",""),
                    "notes":      "Partial CF match: " + alias
                })
                break

    if row:
        matched.append(row)
        status = "YES" if row["WAF_Protected"] == "YES" else "NO"
        print("MATCHED: " + hostname + " | " + row["Resource_Type"] + " | WAF:" + status)
    else:
        r = empty_result(hostname)
        unmatched.append(r)
        print("NOT FOUND: " + hostname)

# Write CSV
print("\nWriting: " + OUT_FILE)
rows = matched + unmatched

with open(OUT_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=FIELDS)
    writer.writeheader()
    for row in rows:
        writer.writerow({field: row.get(field,"") for field in FIELDS})

protected  = sum(1 for r in matched if r["WAF_Protected"] == "YES")
no_waf     = sum(1 for r in matched if r["WAF_Protected"] == "NO")
apigw_rows = sum(1 for r in matched if "API Gateway" in r.get("Resource_Type",""))
cf_rows    = sum(1 for r in matched if "CloudFront" in r.get("Resource_Type",""))
r53_rows   = sum(1 for r in matched if "Route53" in r.get("Resource_Type",""))

print("\n" + "=" * 60)
print("FINAL SUMMARY")
print("  Total hostnames  : " + str(len(hostnames)))
print("  Matched          : " + str(len(matched)))
print("    API Gateway    : " + str(apigw_rows))
print("    CloudFront     : " + str(cf_rows))
print("    Route53 chain  : " + str(r53_rows))
print("  WAF protected    : " + str(protected))
print("  Found - NO WAF   : " + str(no_waf))
print("  Not found        : " + str(len(unmatched)))
print("  Report           : " + OUT_FILE)
print("=" * 60)
