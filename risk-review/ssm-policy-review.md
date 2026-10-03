# SSM Automation Policy Risk Review

## Overview

The reviewed IAM policy is intended to support automated deployments from Azure DevOps through AWS Systems Manager (SSM).

The architecture allows a deployment pipeline to execute commands and deployment activities through AWS Systems Manager Run Command against managed EC2 instances.

The policy demonstrates several positive security controls including:

- Explicit denial of high-risk SSM administrative actions
- Instance targeting through resource tags
- Read-only operational visibility
- CloudWatch logging integration
- Region-specific EC2 permissions

Despite these controls, several security risks remain that should be addressed before production deployment.

---

# Finding 1 – Excessive S3 Object Permissions

## Observation

The policy grants:

```json
{
  "Action": [
    "s3:GetObject",
    "s3:PutObject"
  ],
  "Resource": "arn:aws:s3:::*/*"
}
```

This allows read and write activity against objects in all S3 buckets.

## Risk

The automation role is not limited to the deployment bucket required by the solution.

## Potential Impact

- Sensitive information could be accessed from unrelated buckets.
- Deployment artifacts could be uploaded to incorrect locations.
- A compromised automation role could be used for broader data access.

## Recommendation

Restrict access to approved deployment buckets only.

Example:

```json
{
  "Action": [
    "s3:GetObject",
    "s3:PutObject"
  ],
  "Resource": [
    "arn:aws:s3:::automated-deployment/releases/*",
    "arn:aws:s3:::automated-deployment/output/*"
  ]
}
```

## Risk Rating

High

---

# Finding 2 – Potential Privilege Escalation Through Tag Management

## Observation

The role can perform:

```json
ec2:CreateTags
```

while Systems Manager command execution is controlled using:

```json
AutomationAllowed=true
Application=Automated-Deployment-Dev
```

instance tags.

## Risk

A principal able to create or modify tags may be able to make additional systems eligible for deployment actions.

## Potential Impact

- Commands could execute on unauthorized systems.
- Security boundaries based on tags could be bypassed.
- Additional infrastructure could become deployment targets.

## Recommendation

- Limit tag creation permissions.
- Protect security-sensitive tags with IAM conditions.
- Separate deployment execution roles from infrastructure administration roles.

## Risk Rating

High

---

# Finding 3 – Broad Command Execution Capability

## Observation

The policy allows execution of:

```json
AWS-RunShellScript
AWS-RunPowerShellScript
```

against approved instances.

## Risk

These SSM documents allow arbitrary command execution.

## Potential Impact

- Unauthorized software deployment.
- Service disruption due to incorrect commands.
- Abuse following compromise of the deployment role.

## Recommendation

- Use custom deployment-specific SSM documents.
- Pin document versions.
- Implement approval workflows for production deployments.
- Monitor all command execution through CloudTrail and CloudWatch Logs.

## Risk Rating

High

---

# Finding 4 – Cross-Account Governance Risk

## Observation

The policy references resources across multiple AWS accounts.

## Risk

Cross-account automation increases complexity and expands the blast radius of a potential compromise.

## Potential Impact

- Security events may affect multiple AWS environments.
- Increased difficulty auditing access relationships.
- Broader operational impact during incidents.

## Recommendation

- Use dedicated cross-account roles.
- Apply least-privilege trust policies.
- Restrict role session duration.
- Audit all role assumptions.

## Risk Rating

Medium

---

# Finding 5 – CloudWatch Logging Controls Are Positive

## Observation

The policy grants:

```json
logs:CreateLogGroup
logs:CreateLogStream
logs:PutLogEvents
```

to support deployment logging.

## Positive Security Control

This improves traceability and supports incident investigation.

## Residual Risk

The policy does not explicitly enforce:

- Log retention
- Encryption
- Monitoring and alerting

## Recommendation

- Enable KMS encryption.
- Configure retention policies.
- Alert on unusual deployment activity and failures.

## Risk Rating

Low

---

# Finding 6 – Explicit Deny Statements Are Strong Security Controls

## Observation

The policy explicitly denies many high-risk Systems Manager actions, including:

- Session Manager administration
- Maintenance Window modification
- Patch baseline administration
- Parameter Store modification
- SSM document modification

## Positive Security Control

This significantly reduces opportunities for privilege escalation and misuse.

## Residual Risk

The deny list may require review as AWS introduces new SSM functionality.

## Recommendation

Continue periodic IAM reviews and combine deny statements with strict least-privilege allow policies.

## Risk Rating

Low

---

# Positive Security Controls Identified

| Control | Assessment |
|----------|------------|
| Tag-based deployment targeting | Good |
| Explicit deny statements | Strong |
| Read-only operational visibility | Good |
| CloudWatch deployment logging | Good |
| Region-specific EC2 permissions | Good |

---

# Overall Assessment

The proposed SSM automation model demonstrates good security intent through:

- Tag-based deployment controls
- Explicit deny statements
- Operational visibility
- Restricted EC2 permissions

The most significant risks identified are:

1. Excessive S3 object permissions
2. Potential privilege escalation through tag management
3. Broad command execution capabilities using generic SSM documents

Addressing these issues would significantly improve the security posture of the deployment solution.

## Overall Risk Rating

**Medium**