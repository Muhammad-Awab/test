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

# ─────────────────────────────────────────
# WAF HELPERS
# ─────────────────────────────────────────

def get_regional_waf_map(session, region):
    """
    Returns dict: resource_arn -> {waf_name, waf_arn, managed_by}
    For REGIONAL WAFs (API GW, ALB).
    """
    waf_map = {}
    try:
        waf  = session.client("wafv2", region_name=region, verify=False)
        resp = waf.list_web_acls(Scope="REGIONAL", Limit=100)
        for acl in resp.get("WebACLs", []):
            acl_name = acl["Name"]
            acl_arn  = acl["ARN"]
            managed_by = "Direct"

            # Check if FMS managed via tags
            try:
                tags_resp = waf.list_tags_for_resource(ResourceARN=acl_arn)
                tags = tags_resp.get("TagInfoForResource", {}).get("TagList", [])
                for tag in tags:
                    k = tag.get("Key", "").lower()
                    v = tag.get("Value", "").lower()
                    if "fms" in k or "firewall" in k or "fms" in v:
                        managed_by = "Firewall Manager"
                        break
            except:
                pass

            # Get all resources this ACL protects
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

def get_cloudfront_waf_map(session):
    """
    Returns dict: cf_distribution_arn -> {waf_name, waf_arn, managed_by}
    Uses list_distributions_by_web_acl_id (correct CF method per AWS docs).
    Also maps domain aliases -> distribution ARN.
    """
    cf_domain_map = {}  # alias/domain -> {waf info + dist info}

    try:
        # Step 1 - Get all CloudFront WAF ACLs
        waf  = session.client("wafv2", region_name="us-east-1", verify=False)
        resp = waf.list_web_acls(Scope="CLOUDFRONT", Limit=100)
        cf_acls = resp.get("WebACLs", [])

        for acl in cf_acls:
            acl_name = acl["Name"]
            acl_arn  = acl["ARN"]
            acl_id   = acl["Id"]
            managed_by = "Direct"

            try:
                tags_resp = waf.list_tags_for_resource(ResourceARN=acl_arn)
                tags = tags_resp.get("TagInfoForResource", {}).get("TagList", [])
                for tag in tags:
                    k = tag.get("Key", "").lower()
                    if "fms" in k or "firewall" in k:
                        managed_by = "Firewall Manager"
                        break
            except:
                pass

            # Step 2 - Use list_distributions_by_web_acl_id (correct method for CF)
            try:
                cf_client = session.client("cloudfront", verify=False)
                dist_resp = cf_client.list_distributions_by_web_acl_id(
                    WebAclId=acl_arn,
                    MaxItems="100"
                )
                dist_list = dist_resp.get("DistributionList", {}).get("Items", [])

                for dist in dist_list:
                    dist_arn    = dist.get("ARN", "")
                    dist_domain = dist.get("DomainName", "").lower()

                    # Map the CF domain itself
                    cf_domain_map[dist_domain] = {
                        "waf_name":   acl_name,
                        "waf_arn":    acl_arn,
                        "managed_by": managed_by,
                        "dist_arn":   dist_arn,
                        "dist_domain": dist_domain,
                        "resource_type": "CloudFront"
                    }

                    # Map ALL custom aliases
                    aliases = dist.get("Aliases", {}).get("Items", [])
                    for alias in aliases:
                        cf_domain_map[alias.lower()] = {
                            "waf_name":    acl_name,
                            "waf_arn":     acl_arn,
                            "managed_by":  managed_by,
                            "dist_arn":    dist_arn,
                            "dist_domain": dist_domain,
                            "resource_type": "CloudFront"
                        }

            except Exception as e:
                # Fallback: get all CF distributions and check webAclId
                try:
                    cf_client = session.client("cloudfront", verify=False)
                    all_resp  = cf_client.list_distributions()
                    all_dists = all_resp.get("DistributionList", {}).get("Items", [])

                    for dist in all_dists:
                        dist_acl_id = dist.get("WebACLId", "")
                        if not dist_acl_id:
                            # Check via get_distribution_config
                            try:
                                config = cf_client.get_distribution_config(
                                    Id=dist["Id"]
                                )
                                dist_acl_id = config.get(
                                    "DistributionConfig", {}
                                ).get("WebACLId", "")
                            except:
                                pass

                        if dist_acl_id and (acl_arn in dist_acl_id or acl_id in dist_acl_id):
                            dist_arn    = dist.get("ARN", "")
                            dist_domain = dist.get("DomainName", "").lower()

                            cf_domain_map[dist_domain] = {
                                "waf_name":    acl_name,
                                "waf_arn":     acl_arn,
                                "managed_by":  managed_by,
                                "dist_arn":    dist_arn,
                                "dist_domain": dist_domain,
                                "resource_type": "CloudFront"
                            }

                            aliases = dist.get("Aliases", {}).get("Items", [])
                            for alias in aliases:
                                cf_domain_map[alias.lower()] = {
                                    "waf_name":    acl_name,
                                    "waf_arn":     acl_arn,
                                    "managed_by":  managed_by,
                                    "dist_arn":    dist_arn,
                                    "dist_domain": dist_domain,
                                    "resource_type": "CloudFront"
                                }
                except:
                    pass

    except:
        pass

    # Also scan ALL CF distributions for webAclId even without WAF ACL list
    try:
        cf_client = session.client("cloudfront", verify=False)
        all_resp  = cf_client.list_distributions()
        all_dists = all_resp.get("DistributionList", {}).get("Items", [])

        for dist in all_dists:
            dist_arn    = dist.get("ARN", "")
            dist_domain = dist.get("DomainName", "").lower()
            aliases     = dist.get("Aliases", {}).get("Items", [])
            web_acl_id  = dist.get("WebACLId", "")

            # If not already mapped, add without WAF info
            all_aliases = [dist_domain] + [a.lower() for a in aliases]
            for alias in all_aliases:
                if alias not in cf_domain_map:
                    entry = {
                        "waf_name":    "",
                        "waf_arn":     web_acl_id,
                        "managed_by":  "",
                        "dist_arn":    dist_arn,
                        "dist_domain": dist_domain,
                        "resource_type": "CloudFront"
                    }
                    if web_acl_id:
                        entry["waf_name"] = web_acl_id.split("/")[-1]
                        entry["managed_by"] = "Direct"
                    cf_domain_map[alias] = entry

    except:
        pass

    return cf_domain_map

# ─────────────────────────────────────────
# API GATEWAY SCANNER
# ─────────────────────────────────────────

def get_apigw_domain_map(session, acc_id, acc_name):
    """
    Returns list of dicts for all API GW custom domains.
    """
    found = []

    for region in REGIONS:

        # Build regional WAF map once per region
        regional_waf = get_regional_waf_map(session, region)

        # REST API v1
        try:
            client  = session.client("apigateway", region_name=region, verify=False)
            resp    = client.get_domain_names(limit=500)
            domains = resp.get("items", [])

            if domains:
                print("    [" + region + "] REST: " + str(len(domains)))

            for domain in domains:
                dn         = domain.get("domainName", "")
                api_id     = ""
                api_name   = ""
                stage_name = ""

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

                # Find WAF — Method 1: via resource ARN map
                waf_name   = ""
                waf_arn    = ""
                managed_by = ""

                if api_id:
                    for r_arn, w_info in regional_waf.items():
                        if api_id in r_arn:
                            waf_name   = w_info["waf_name"]
                            waf_arn    = w_info["waf_arn"]
                            managed_by = w_info["managed_by"]
                            break

                # Method 2: direct webAclArn on stage
                if not waf_name and api_id:
                    try:
                        stages = client.get_stages(restApiId=api_id)
                        for stage in stages.get("item", []):
                            web_acl = stage.get("webAclArn", "")
                            sn      = stage.get("stageName", "")
                            if web_acl:
                                waf_name   = web_acl.split("/")[-1]
                                waf_arn    = web_acl
                                managed_by = "Direct (Stage)"
                                if not stage_name:
                                    stage_name = sn
                                break
                    except:
                        pass

                # Method 3: FMS compliance
                if not waf_name:
                    try:
                        fms = session.client(
                            "fms", region_name="us-east-1", verify=False
                        )
                        policies = fms.list_policies()
                        for pol in policies.get("PolicyList", []):
                            if pol.get("SecurityServiceType") in ["WAFV2", "WAF"]:
                                try:
                                    comp = fms.list_compliance_status(
                                        PolicyId=pol["PolicyId"]
                                    )
                                    for s in comp.get("PolicyComplianceStatusList", []):
                                        if s.get("MemberAccount") == acc_id:
                                            for ev in s.get("EvaluationResults", []):
                                                if ev.get("ComplianceStatus") == "COMPLIANT":
                                                    waf_name   = pol.get("PolicyName", "FMS")
                                                    waf_arn    = pol.get("PolicyArn", "")
                                                    managed_by = "Firewall Manager"
                                                    break
                                except:
                                    pass
                                if waf_name:
                                    break
                    except:
                        pass

                found.append({
                    "dn":          dn,
                    "api_id":      api_id,
                    "api_name":    api_name,
                    "api_type":    "REST",
                    "stage_name":  stage_name,
                    "waf_name":    waf_name,
                    "waf_arn":     waf_arn,
                    "managed_by":  managed_by,
                    "region":      region,
                    "acc_id":      acc_id,
                    "acc_name":    acc_name,
                    "res_type":    "API Gateway"
                })

        except:
            pass

        # HTTP API v2
        try:
            client  = session.client("apigatewayv2", region_name=region, verify=False)
            resp    = client.get_domain_names()
            domains = resp.get("Items", [])

            if domains:
                print("    [" + region + "] HTTP: " + str(len(domains)))

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

                waf_name   = ""
                waf_arn    = ""
                managed_by = ""

                if api_id:
                    for r_arn, w_info in regional_waf.items():
                        if api_id in r_arn:
                            waf_name   = w_info["waf_name"]
                            waf_arn    = w_info["waf_arn"]
                            managed_by = w_info["managed_by"]
                            break

                found.append({
                    "dn":         dn,
                    "api_id":     api_id,
                    "api_name":   api_name,
                    "api_type":   "HTTP",
                    "stage_name": stage_name,
                    "waf_name":   waf_name,
                    "waf_arn":    waf_arn,
                    "managed_by": managed_by,
                    "region":     region,
                    "acc_id":     acc_id,
                    "acc_name":   acc_name,
                    "res_type":   "API Gateway"
                })

        except:
            pass

    return found

# ─────────────────────────────────────────
# MATCH HOSTNAME TO RESOURCE
# ─────────────────────────────────────────

def build_csv_row(hostname, resource, res_type):
    acc_id = resource.get("acc_id", "")
    return {
        "Custom_Domain_Name": hostname,
        "Account_ID":         "'" + acc_id,
        "Account_Name":       resource.get("acc_name", ""),
        "Resource_Type":      res_type,
        "API_Name":           resource.get("api_name", ""),
        "API_ID":             resource.get("api_id", ""),
        "API_Type":           resource.get("api_type", ""),
        "Stage_Name":         resource.get("stage_name", ""),
        "WebACL_Name":        resource.get("waf_name", ""),
        "WebACL_ARN":         resource.get("waf_arn", ""),
        "WAF_Region":         resource.get("region", ""),
        "WAF_Managed_By":     resource.get("managed_by", ""),
        "Region":             resource.get("region", ""),
        "WAF_Protected":      "YES" if resource.get("waf_name") else "NO",
        "Notes":              resource.get("notes", "")
    }

# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
print("=" * 60)
print("WAF Coverage Report — API Gateway + CloudFront")
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

print("\nScanning all " + str(len(accounts)) + " accounts...\n")

all_apigw_domains = []   # list of dicts from API GW scan
all_cf_domains    = {}   # alias -> waf info from CF scan

for i, account in enumerate(accounts):
    acc_id   = account["accountId"]
    acc_name = account.get("accountName", "unknown")

    if i % 20 == 0:
        apigw_count = len(all_apigw_domains)
        cf_count    = len(all_cf_domains)
        print("[" + str(i) + "/" + str(len(accounts)) + "] APIGW domains: " +
              str(apigw_count) + " | CF domains/aliases: " + str(cf_count))

    creds = get_creds(token, acc_id)
    if not creds:
        continue

    session = make_session(creds)

    # Scan API Gateway
    apigw_results = get_apigw_domain_map(session, acc_id, acc_name)
    if apigw_results:
        all_apigw_domains.extend(apigw_results)

    # Scan CloudFront — uses correct list_distributions_by_web_acl_id
    cf_results = get_cloudfront_waf_map(session)
    if cf_results:
        for alias, info in cf_results.items():
            if alias not in all_cf_domains:
                info["acc_id"]   = acc_id
                info["acc_name"] = acc_name
                all_cf_domains[alias] = info
            elif not all_cf_domains[alias].get("waf_name") and info.get("waf_name"):
                info["acc_id"]   = acc_id
                info["acc_name"] = acc_name
                all_cf_domains[alias] = info

print("\n\nScan complete!")
print("  API GW domains found     : " + str(len(all_apigw_domains)))
print("  CF aliases/domains found : " + str(len(all_cf_domains)))

# Match hostnames
print("\nMatching " + str(len(hostnames)) + " hostnames...")
print("=" * 60)

matched   = []
unmatched = []

for hostname in hostnames:
    row        = None
    match_note = ""

    # 1. Exact API GW match
    for d in all_apigw_domains:
        if hostname == d["dn"].lower():
            row = build_csv_row(hostname, d, "API Gateway")
            break

    # 2. Exact CloudFront alias match
    if not row and hostname in all_cf_domains:
        cf = all_cf_domains[hostname]
        row = build_csv_row(hostname, {
            "acc_id":     cf.get("acc_id", ""),
            "acc_name":   cf.get("acc_name", ""),
            "api_name":   cf.get("dist_domain", ""),
            "api_id":     cf.get("dist_arn", ""),
            "api_type":   "",
            "stage_name": "",
            "waf_name":   cf.get("waf_name", ""),
            "waf_arn":    cf.get("waf_arn", ""),
            "managed_by": cf.get("managed_by", ""),
            "region":     "us-east-1"
        }, "CloudFront")

    # 3. Partial API GW match
    if not row:
        for d in all_apigw_domains:
            dn = d["dn"].lower()
            if hostname in dn or dn in hostname:
                row = build_csv_row(hostname, d, "API Gateway")
                row["Notes"] = "Partial match: " + d["dn"]
                break

    # 4. Partial CloudFront match
    if not row:
        for alias, cf in all_cf_domains.items():
            if hostname in alias or alias in hostname:
                row = build_csv_row(hostname, {
                    "acc_id":     cf.get("acc_id", ""),
                    "acc_name":   cf.get("acc_name", ""),
                    "api_name":   cf.get("dist_domain", ""),
                    "api_id":     cf.get("dist_arn", ""),
                    "api_type":   "",
                    "stage_name": "",
                    "waf_name":   cf.get("waf_name", ""),
                    "waf_arn":    cf.get("waf_arn", ""),
                    "managed_by": cf.get("managed_by", ""),
                    "region":     "us-east-1"
                }, "CloudFront")
                row["Notes"] = "Partial CF match: " + alias
                break

    if row:
        matched.append(row)
        status = "YES" if row["WAF_Protected"] == "YES" else "NO"
        print("MATCHED: " + hostname)
        print("         Type   : " + row["Resource_Type"])
        print("         Account: " + row["Account_Name"])
        print("         WAF    : " + status +
              (" -> " + row["WebACL_Name"] if row["WebACL_Name"] else ""))
        print("")
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
        writer.writerow({field: row.get(field, "") for field in FIELDS})

protected  = sum(1 for r in matched if r["WAF_Protected"] == "YES")
no_waf     = sum(1 for r in matched if r["WAF_Protected"] == "NO")
apigw_rows = sum(1 for r in matched if r["Resource_Type"] == "API Gateway")
cf_rows    = sum(1 for r in matched if r["Resource_Type"] == "CloudFront")

print("\n" + "=" * 60)
print("FINAL SUMMARY")
print("  Total hostnames  : " + str(len(hostnames)))
print("  Matched          : " + str(len(matched)))
print("    via API Gateway: " + str(apigw_rows))
print("    via CloudFront : " + str(cf_rows))
print("  WAF protected    : " + str(protected))
print("  Found - NO WAF   : " + str(no_waf))
print("  Not found        : " + str(len(unmatched)))
print("  Report saved     : " + OUT_FILE)
print("=" * 60)
