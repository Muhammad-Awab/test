# AWS Bot Control — Akamai CDN X-Forwarded-For

## Answers to the Two Questions

**Q1: Can AWS Bot Control reliably use X-Forwarded-For when requests are proxied through Akamai?**

Yes — but it requires a custom rule. AWS Bot Control does NOT automatically
read X-Forwarded-For for Akamai. It only does this automatically for
CloudFront, Cloudflare, and Fastly. For Akamai you must add a custom rule
that runs BEFORE Bot Control to handle the real client IP.

**Q2: What specific AWS WAF configuration is required?**

Two rules must be added to the Web ACL on the CloudFront distribution:

Rule 1 (Priority 0) — Custom rule that reads the real client IP
from the X-Forwarded-For header for Akamai traffic.

Rule 2 (Priority 1) — Bot Control managed rule group runs after Rule 1.

See waf-bot-control-akamai.json for the full configuration.

---

## Traffic Flow

End User → Akamai CDN → AWS CloudFront → Authentication Endpoint

When Akamai proxies the request, the real end-user IP is NOT visible
to AWS WAF directly. Akamai places the real IP in the X-Forwarded-For
header. AWS WAF must be configured to read this header.

---

## How to Apply — Console Steps

Step 1: Go to AWS WAF → Web ACLs
Step 2: Select the Web ACL attached to your CloudFront distribution
Step 3: Click Rules → Add rules → Add my own rules
Step 4: Add Rule 1 first (AkamaiXFFHandling) — see JSON file
Step 5: Add Rule 2 second (BotControlRuleGroup) — see JSON file
Step 6: Confirm Rule 1 is priority 0 and Rule 2 is priority 1
Step 7: Save the Web ACL

---

## Important Notes

- Rule 1 MUST have a lower priority number than Bot Control
  (priority 0 runs before priority 1)

- Akamai sends the real client IP in two headers:
  True-Client-IP  (preferred — set in Akamai property config)
  X-Forwarded-For (standard — always present)
  Use True-Client-IP if available, otherwise use X-Forwarded-For

- Bot Control itself cannot be configured to use forwarded IP directly.
  The custom rule before it handles the Akamai-specific logic.

- Both rules should be set to COUNT mode first to monitor before blocking.

---

## Prerequisites

1. AWS WAF must be attached to the CloudFront distribution
2. CloudFront must be configured to forward X-Forwarded-For to origin
   CloudFront Console → Distribution → Behaviors → Origin request policy
   Select: All Viewer (or create custom policy including X-Forwarded-For)
3. Akamai must have True-Client-IP header enabled in the property config
   Akamai Portal → Property → Origin → Send True Client IP Header = ON

---

## References

AWS WAF Forwarded IP:
https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-forwarded-ip-address.html

AWS Bot Control Rule Group:
https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-bot.html

Akamai True-Client-IP Header:
https://techdocs.akamai.com/property-mgr/docs/origin-server
