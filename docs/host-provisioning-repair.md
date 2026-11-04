# HOST provisioning repair runbook

`HostProvisioningService` keeps Authentication as the source of identity
lifecycle facts and User as the source of the host profile and authorization
projection. The consumer does not read Property storage and does not infer an
ownership binding.

## Preflight

Run the following read-only checks with the `app` schema selected:

```sql
SELECT auth_account_id, count(*) AS subject_count,
       string_agg(account_type, ',' ORDER BY account_type) AS account_types
FROM authorization_subjects
GROUP BY auth_account_id
HAVING count(*) > 1;

SELECT event_id, business_key, event_type, processed_at
FROM processed_events
WHERE consumer_name = 'user-host-provisioning-v1'
ORDER BY processed_at DESC;

SELECT id, aggregate_id, aggregate_version, event_type,
       publish_attempts, last_error, available_at
FROM outbox_events
WHERE published_at IS NULL
ORDER BY available_at, occurred_at;
```

The first query must return no rows before applying `V14`; an existing
cross-type row is a visible data conflict and must be resolved by the owning
identity/data migration authority before the unique index is introduced.

## Safe retry

1. Keep the original event ID, canonical payload and correlation ID. Replaying
   an identical event is safe and is a no-op after the inbox hash matches.
2. For a failed transaction, first verify that no `hosts`, authorization
   subject, role assignment, audit, or outbox row was committed for the event.
3. Correct the source event or the explicit User-owned policy, then replay the
   original event. Never delete a profile, role assignment, property
   relationship, or processed-event row to force a retry.
4. A different payload with the same event ID or business key is a terminal
   collision. Preserve it for incident evidence and issue a new, versioned
   source event only after the source owner has resolved the conflict.

Lifecycle replays use the aggregate version in their business key. They do not
remove role history or property relationships; only the User-owned profile
state and authorization subject active/version projection change.
