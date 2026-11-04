# Privacy, guest-document, consent, retention and audit policy

Status: approved MVP policy  
Owner: User service / Security owner  
Review cadence: every 12 months and before enabling a new PII purpose or vendor

This policy is an engineering and operational control baseline. Production
activation still requires validation against the applicable jurisdiction and
the signed customer/host terms; a legal hold overrides scheduled deletion.

## Ownership and data minimization

The User service is the system of record for customer, host and Backoffice
profiles. Authentication/Keycloak owns credentials and sessions. Media owns
encrypted document objects. Domain services receive stable account/profile IDs
and the minimum attributes needed for a declared purpose; they must not read the
User database directly.

| Class | Examples | Storage and exposure |
| --- | --- | --- |
| Identity/contact PII | name, email, normalized phone | PostgreSQL only; scoped `profile:*`/`customer:*` access; never logs, metrics or Redis |
| Sensitive profile PII | date of birth, nationality, address, tax code, employment dates | PostgreSQL only; field-level API allow-list and audit on privileged access/export |
| Credentials/session data | passwords, factors, tokens, sessions | Keycloak only; never User DB or events |
| Guest identity documents | passport/ID images and numbers | Collection disabled for MVP. When enabled, encrypted Media storage holds the object and User stores only an opaque media reference plus lifecycle metadata |
| Consent evidence | purpose, policy version, decision, time, source, actor | Dedicated append-only PostgreSQL records before any consent-dependent collection; never a mutable profile flag |
| Authorization/audit | roles, grants, scopes, reason, actor, correlation ID | PostgreSQL append-only audit; Redis may hold only expiring authorization snapshots |

Free-text fields must not contain identity-document numbers, card data,
credentials or special-category data. Kafka events expose IDs and minimum
workflow attributes; PII requires an explicitly versioned contract and review.

## Purpose and consent

Each collection point must declare purpose, required/optional status, policy
version and retention class. Contract/performance or legal-obligation processing
must not be presented as optional consent. Optional marketing or secondary use
requires a separate, unticked choice.

Consent-dependent processing is disabled until a migration and API persist:
subject ID, purpose code, policy version, `GRANTED`/`WITHDRAWN`, occurred time,
source and actor/correlation ID. Withdrawal stops future optional processing but
does not erase records under contract, dispute, accounting or legal hold.

## Guest documents

Guest-document upload and document-number fields are prohibited in the current
MVP schema. Enabling them requires all of the following in one reviewed change:

1. encrypted object storage with per-object authorization and malware scanning;
2. opaque references only in User, never document bytes in PostgreSQL/Kafka;
3. purpose/versioned consent or another documented lawful basis;
4. automatic deletion job, deletion audit and restore/deletion test;
5. redaction in logs, traces, support exports and error payloads;
6. `SELF`, `OWN`, `ASSIGNED` or exceptional `ALL` scope enforcement.

## Retention schedule

| Record | Active retention | Deletion/anonymization target |
| --- | --- | --- |
| Customer profile | while active booking/account purpose exists | anonymize 24 months after the last completed/cancelled booking and account closure |
| Host profile/tax identity | while relationship or settlement obligation exists | restrict at termination; anonymize after 10 years unless the approved jurisdiction requires a different period |
| Backoffice profile | while employed/contracted | disable immediately at end; remove contact PII after 24 months |
| Guest document object (future gate) | check-in through dispute window | delete 30 days after checkout; hard maximum 90 days without documented legal hold |
| Consent evidence | while purpose is active | retain 5 years after withdrawal or last processing evidence, then delete/anonymize |
| Authorization and security audit | operational lifetime | retain 7 years, then delete/anonymize subject attributes while preserving non-identifying integrity evidence |
| Idempotency/inbox data | replay/support window | 30 days unless a shorter contract window applies |
| Backups | disaster-recovery window | expire within 35 days; deletion is not selectively rewritten into immutable backups |

Retention jobs must be idempotent, scoped, observable and dry-run capable. Legal
hold records include approver, reason and expiry; expired holds are reviewed.
Restored backups must replay the deletion queue before serving production traffic.

## Subject requests and deletion

Identity verification is required before access, correction, export or deletion.
Exports use an approved, encrypted channel and are audited. Deletion is a
workflow: deactivate access, evaluate holds/obligations, delete document objects,
anonymize profile PII, invalidate caches, publish a non-PII lifecycle event and
record outcome/reason. Authorization and accounting integrity references may be
retained as pseudonymous IDs.

## Authorization and audit

PII access requires both action permission and data scope. Bulk/export access
requires `audit:export` or the domain export permission and a reason. Sensitive
changes record actor subject, target subject, action, before/after redacted
metadata, reason, correlation ID and timestamp. Audit records are append-only;
secrets, document values and full free-text PII are excluded.

## Incident and operational controls

- Logs/traces use IDs, never raw PII or tokens; alert payloads are redacted.
- Encryption is required in transit and at rest; production DB/storage access is private.
- Suspected disclosure triggers access revocation, evidence preservation,
  affected-data classification and the incident notification process.
- Quarterly sampling verifies scope enforcement, retention jobs, failed deletions,
  legal holds, privileged exports and backup expiry.

## Change gate

Any schema/API/event adding PII, consent or documents must update this policy,
threat model, migration/rollback plan, retention automation and executable tests.
CI validates that this policy remains versioned and that the current baseline
does not introduce guest-document or consent tables before their activation gate.
