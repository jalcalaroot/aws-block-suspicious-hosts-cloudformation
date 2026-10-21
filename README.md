# Block Suspicious Hosts from GuardDuty Findings (CloudFormation)

CloudFormation template that reacts to Amazon GuardDuty EC2 findings by adding the attacker IP to a VPC network ACL deny rule and to an AWS WAFv2 IP set, notifying an admin by email and expiring the entries after a retention period. The Lambda code (in `artifacts/`) is based on the AWS sample "GuardDuty to ACL" (MIT-0 headers kept in the source).

> **Status:** legacy reference template (2026), not actively maintained. Review and update before deploying.

## Architecture

Template: `guarddutytoacl.template`

```
GuardDuty finding --> EventBridge rule --> GuardDutytoACL Lambda --+--> NACL deny rule (71-80) on the instance subnet
 (UnauthorizedAccess, Recon,                                       +--> WAFv2 regional IP set (IPv4)
  Trojan, Backdoor, Impact,                                        +--> DynamoDB state table
  CryptoCurrency, Behavior :EC2)                                   +--> SNS email to AdminEmail
EventBridge rate(5 minutes) --> PruneOldEntries Lambda --> removes entries older than Retention
```

- EventBridge rule matching GuardDuty `*:EC2` finding types listed above
- `GuardDutytoACL` Lambda (Python 3.9, arm64): finds the subnet's NACL, adds an inbound deny-all rule for the remote IP `/32` (rule numbers 71-80, oldest replaced when full), updates the WAF IP set, publishes to SNS
- `PruneOldEntries` Lambda on a 5-minute schedule, removing expired NACL/WAF/DynamoDB entries
- DynamoDB table (`NetACLId` + `CreatedAt`, provisioned 5/5) holding block state
- WAFv2 regional IP sets (IPv4 and IPv6) and, optionally, a regional Web ACL that blocks both sets (not associated with any resource)
- SNS topic with an email subscription; IAM roles/policies for both functions
- `gd2acl_test_event.json`: sample `UnauthorizedAccess:EC2/SSHBruteForce` finding for testing the Lambda (replace the `subnetId`)

## Parameters

| Name | Purpose | Default |
|------|---------|---------|
| `Retention` | Minutes to keep an IP blocked (5-10080) | `720` |
| `AdminEmail` | Email for SNS notifications | `<ADMIN_EMAIL>` (required) |
| `RegionalWebACL` | Create the regional Web ACL (`True`/`False`) | `True` |
| `ArtifactsBucket` | S3 bucket holding the Lambda zips | (required) |
| `ArtifactsPrefix` | Key prefix for the zips (concatenated directly with the file name) | `/` |

## Deploy

```bash
aws s3 cp artifacts/ s3://<ARTIFACTS_BUCKET>/gd2acl/ --recursive
aws cloudformation deploy \
  --stack-name <STACK_NAME> \
  --template-file guarddutytoacl.template \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides AdminEmail=<ADMIN_EMAIL> ArtifactsBucket=<ARTIFACTS_BUCKET> ArtifactsPrefix=gd2acl/
```

GuardDuty must be enabled in the region. Confirm the SNS subscription email. Associate the Web ACL with your ALB/API Gateway yourself if you want WAF blocking to take effect.

## Known issues / Security notes

- `prune_old_entries.py` reads a `CLOUDFRONT_IP_SET` environment variable that the template does not set, so the pruning Lambda fails as shipped and entries are never expired. Add the variable or remove the reference before use.
- Both Lambda roles allow `ec2:Describe*` and `ec2:*NetworkAcl*` on `Resource: "*"`, so they can modify any NACL in the account/region.
- The functions write to whichever NACL is associated with the finding's subnet and fail if rules 71-80 are already in use there.
- Only the IPv4 IP set is updated; the IPv6 set stays at its placeholder `::1/128`.
- Python 3.9 is a deprecated Lambda runtime; the SNS topic is not KMS-encrypted.
- Metadata references a `RegionalIPSetId` parameter that does not exist.

## Cleanup

```bash
aws cloudformation delete-stack --stack-name <STACK_NAME>
```

NACL deny rules (71-80) created by the Lambda are not stack resources; remove any that remain with `aws ec2 delete-network-acl-entry`. Delete the uploaded zips from the artifacts bucket.

## License

MIT — see [LICENSE](LICENSE).
