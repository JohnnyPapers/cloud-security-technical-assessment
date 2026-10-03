# AWS Region Restriction SCP

## Objective

The objective of this Service Control Policy (SCP) is to restrict AWS service usage to the European (Ireland) region:

```text
eu-west-1
```

This helps enforce:

- Data residency requirements
- Regulatory compliance
- Centralized operational governance
- Reduced attack surface

---

## Design Approach

The SCP uses an explicit Deny statement.

All AWS API requests made outside:

```text
eu-west-1
```

are denied.

A set of AWS global services are excluded from the restriction because they do not operate within a single AWS region.

Examples include:

- IAM
- Organizations
- Route53
- CloudFront
- AWS Support

---

## Deployment Process

1. Validate SCP syntax.
2. Create a dedicated test Organizational Unit (OU).
3. Attach the SCP to the test OU.
4. Move a non-production AWS account into the test OU.
5. Verify workloads function correctly in eu-west-1.
6. Verify requests fail outside eu-west-1.
7. Review CloudTrail denied events.
8. Roll out incrementally to production OUs.

---

## Testing

### Allowed

```bash
aws ec2 describe-instances --region eu-west-1
```

### Denied

```bash
aws ec2 describe-instances --region eu-central-1
```

Expected Result:

```text
Access Denied by Service Control Policy
```

---

## Risks and Considerations

The following should be considered before deployment:

- Certain AWS services are global and require exemptions.
- Existing workloads operating outside eu-west-1 may stop functioning.
- SCPs limit permissions but do not grant permissions.
- Testing should be completed in a separate OU before production rollout.

---

## Security Benefits

This SCP provides:

- Regional governance
- Data sovereignty enforcement
- Reduced risk of resource deployment in unauthorized regions
- Stronger compliance controls

## Overall Assessment

The SCP provides a straightforward and effective method of enforcing regional governance while still allowing required global AWS services to operate normally.