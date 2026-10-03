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

High

---

# Finding 2 – ReadOnly Role Does Not Provide Read-Only Database Access

## Observation

The ReadOnly policy grants:

```json
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
SELECT
```

permissions to required schemas and tables.

## Risk Rating

High

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

Users could gain excessive administrative privileges while still lacking proper database authorisation.

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

High

---

# Finding 4 – IAM Database Authentication