# RDS Role Policy Risk Review

## Overview

The proposed solution intends to provide three levels of database access:

- ReadOnly
- CRUB (CRUD)
- Admin

The objective is to provide role-based access to Amazon RDS databases while integrating with centralized identity management and user-specific role assignment.

While the overall objective is sound, the supplied IAM policies do not fully implement the intended database authorization model.

The primary finding is that the IAM policies grant permissions to manage Amazon RDS resources rather than enforce database-level permissions such as SELECT, INSERT, UPDATE, DELETE or DDL operations.

---

# Finding 1 – Database Authorization and AWS Administration Are Mixed

## Observation

The Admin and CRUB policies contain:

```json
{
  "Action": [
    "rds:*"
  ],
  "Resource": "*"
}
```

## Risk

These permissions grant extensive access to the RDS service itself, including infrastructure administration activities.

Examples include:

- Creating databases
- Deleting databases
- Restoring snapshots
- Modifying database settings
- Changing configuration

These permissions do not directly control access to database tables or records.

## Potential Impact

A user assigned the CRUB role could receive infrastructure administration permissions that exceed the intended access requirements.

## Recommendation

Separate:

1. Infrastructure administration
2. Database authentication
3. Database authorization

Only database administrators should receive RDS administration permissions.

## Risk Rating

**High**

---

# Finding 2 – ReadOnly Role Does Not Provide Read-Only Database Access

## Observation

The ReadOnly policy grants:

```text
rds:Describe*
rds:ListTagsForResource
```

and supporting EC2 visibility permissions.

## Risk

These permissions provide visibility into RDS infrastructure but do not provide database-level SELECT permissions.

## Potential Impact

Users may be able to view instance information while being unable to query database data.

The implementation does not satisfy the requirement for read-only database access.

## Recommendation

Implement a database role that grants:

```sql
GRANT SELECT
```

permissions to required schemas and tables.

## Risk Rating

**High**

---

# Finding 3 – CRUB Role Does Not Implement CRUD Operations

## Observation

The role is intended to support:

```text
SELECT
INSERT
UPDATE
DELETE
```

operations.

However, the IAM policy grants:

```json
rds:*
```

which controls AWS resources rather than database records.

## Risk

The policy does not enforce the intended application-level permissions.

## Potential Impact

Users could gain excessive administrative privileges while still lacking proper database authorization.

## Recommendation

Implement database-native roles and permissions.

Example:

```sql
GRANT SELECT;
GRANT INSERT;
GRANT UPDATE;
GRANT DELETE;
```

to a dedicated CRUD role.

## Risk Rating

**High**

---

# Finding 4 – IAM Database Authentication Should Be Considered

## Observation

The architecture uses centralized identity management and user-specific role assignment.

## Risk

Traditional database usernames and passwords introduce:

- Credential management overhead
- Password rotation complexity
- Increased risk of credential exposure
- Potential use of shared database accounts

## Potential Impact

Long-lived credentials increase both operational effort and security risk.

## Recommendation

Consider implementing IAM Database Authentication for supported database engines.

Benefits include:

- Centralized authentication
- Elimination of long-lived database passwords
- Improved auditability
- Better integration with enterprise identity systems

Database permissions should continue to be enforced at the database layer.

## Risk Rating

**Medium**

---

# Finding 5 – Admin Role Provides Broad Administrative Access

## Observation

The Admin role grants:

```json
rds:*
```

along with additional permissions across:

- CloudWatch
- SNS
- Performance Insights
- Application Auto Scaling

## Risk

Compromise of the Admin role could allow significant modification of database infrastructure.

## Potential Impact

An attacker could:

- Delete databases
- Modify backups
- Change scaling settings
- Change configuration
- Impact service availability

## Recommendation

Implement:

- Just-in-time privileged access
- Access approval workflows
- Session logging
- Regular access reviews
- Separation of duties

## Risk Rating

**Medium**

---

# Finding 6 – Database Activity Auditing Is Not Explicitly Defined

## Observation

The proposed design does not explicitly mention database audit logging.

## Risk

Activities performed by privileged users may not be adequately monitored.

## Potential Impact

- Reduced forensic visibility
- Compliance challenges
- Limited insight into privileged database activity

## Recommendation

Enable:

- Database audit logging
- CloudWatch log exports
- Query logging
- Privileged activity monitoring

## Risk Rating

**Medium**

---

# Finding 7 – Federated Identity Model Is A Positive Security Control

## Observation

The architecture proposes user-specific identity assignment and centralized access management.

## Positive Security Control

This approach provides:

- Improved accountability
- Reduced credential sharing
- Stronger access governance
- Enhanced auditing capability

## Recommendation

Continue using federated identities and perform periodic access reviews.

## Risk Rating

**Low**

---

# Positive Security Controls Identified

| Control | Assessment |
|----------|------------|
| Role-based access model | Good |
| Federated identity integration | Good |
| User-specific role assignment | Good |
| Administrative role separation concept | Good |

---

# Key Security Observation

The most significant issue identified is that the policies govern access to the Amazon RDS service rather than access to database objects.

Examples:

- ReadOnly does not provide SELECT permissions.
- CRUB does not provide INSERT, UPDATE and DELETE permissions.
- Admin provides infrastructure control rather than database-only administration.

Database permissions should be enforced through database roles while IAM should be used for authentication and access governance.

---

# Overall Assessment

The proposed design demonstrates strong identity governance principles and a sensible role-based access model.

However, the current implementation does not correctly enforce the stated database authorization requirements.

The highest-priority recommendation is to separate:

1. AWS infrastructure administration
2. Database authentication
3. Database authorization

and enforce SQL permissions at the database layer.

## Overall Risk Rating

**Medium-High**