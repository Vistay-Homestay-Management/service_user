package com.vistay.user.application;

import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

@Service
public class AuthorizationSnapshotService {
    private static final Logger log = LoggerFactory.getLogger(AuthorizationSnapshotService.class);

    private final JdbcClient jdbc;
    private final StringRedisTemplate redis;
    private final ObjectMapper json;
    private final Duration cacheTtl;

    public AuthorizationSnapshotService(
        JdbcClient jdbc,
        StringRedisTemplate redis,
        ObjectMapper json,
        @Value("${vistay.authorization.cache-ttl:60s}") Duration cacheTtl
    ) {
        this.jdbc = jdbc;
        this.redis = redis;
        this.json = json;
        this.cacheTtl = cacheTtl;
    }

    public Snapshot get(String accountType, UUID authAccountId) {
        var normalizedType = normalizeType(accountType);
        var header = loadHeader(normalizedType, authAccountId);
        if (header == null) {
            return Snapshot.inactive(normalizedType, authAccountId);
        }

        var key = cacheKey(normalizedType, authAccountId, header.authorizationVersion());
        var cached = readCache(key);
        if (cached != null
            && cached.profileId().equals(header.profileId())
            && cached.active() == header.active()) {
            return cached;
        }

        var snapshot = loadSnapshot(normalizedType, authAccountId, header);
        writeCache(key, snapshot);
        return snapshot;
    }

    public void evict(String accountType, UUID authAccountId) {
        try {
            var keys = redis.keys("vistay:user:authz:v1:" + normalizeType(accountType) + ":" + authAccountId + ":v*");
            if (keys != null && !keys.isEmpty()) {
                redis.delete(keys);
            }
        } catch (RuntimeException unavailable) {
            log.warn("Authorization Redis eviction failed; versioned keys keep correctness", unavailable);
        }
    }

    private Header loadHeader(String accountType, UUID authAccountId) {
        var table = switch (accountType) {
            case "ADMIN" -> "admin_users";
            case "CUSTOMER" -> "customers";
            case "HOST" -> "hosts";
            default -> throw new IllegalArgumentException("Unsupported account type");
        };
        return jdbc.sql("""
                SELECT s.id AS subject_id, p.id AS profile_id,
                       (s.active AND p.profile_status = 'ACTIVE') AS active,
                       s.authorization_version
                FROM authorization_subjects s
                JOIN %s p ON p.authorization_subject_id = s.id
                WHERE s.account_type = :accountType AND s.auth_account_id = :accountId
                """.formatted(table))
            .param("accountType", accountType)
            .param("accountId", authAccountId)
            .query(Header.class)
            .optional()
            .orElse(null);
    }

    private Snapshot loadSnapshot(String accountType, UUID authAccountId, Header header) {
        if (!header.active()) {
            return new Snapshot(accountType, authAccountId, header.subjectId(), header.profileId(), false,
                header.authorizationVersion(), List.of(), List.of());
        }

        var roles = jdbc.sql("""
                SELECT DISTINCT r.code
                FROM subject_role_assignments sra
                JOIN roles r ON r.id = sra.role_id
                WHERE sra.subject_id = :subjectId
                  AND sra.revoked_at IS NULL
                  AND sra.valid_from <= now()
                  AND (sra.valid_until IS NULL OR sra.valid_until > now())
                  AND r.active AND r.audience = :accountType
                ORDER BY r.code
                """)
            .param("subjectId", header.subjectId())
            .param("accountType", accountType)
            .query(String.class)
            .list();

        var rows = jdbc.sql("""
                SELECT p.code AS permission_code, srps.scope_type
                FROM subject_role_assignments sra
                JOIN roles r ON r.id = sra.role_id AND r.active
                JOIN subject_role_permission_scopes srps ON srps.assignment_id = sra.id
                JOIN permissions p ON p.id = srps.permission_id AND p.active
                WHERE sra.subject_id = :subjectId
                  AND sra.revoked_at IS NULL
                  AND sra.valid_from <= now()
                  AND (sra.valid_until IS NULL OR sra.valid_until > now())
                  AND r.audience = :accountType
                ORDER BY p.code, srps.scope_type
                """)
            .param("subjectId", header.subjectId())
            .param("accountType", accountType)
            .query(GrantRow.class)
            .list();

        Map<String, EnumSet<Scope>> grouped = new LinkedHashMap<>();
        for (var row : rows) {
            grouped.computeIfAbsent(row.permissionCode(), ignored -> EnumSet.noneOf(Scope.class))
                .add(Scope.valueOf(row.scopeType()));
        }
        var grants = new ArrayList<Grant>();
        grouped.forEach((permission, scopes) -> grants.add(new Grant(permission, List.copyOf(scopes))));
        return new Snapshot(accountType, authAccountId, header.subjectId(), header.profileId(), true,
            header.authorizationVersion(), roles, List.copyOf(grants));
    }

    private Snapshot readCache(String key) {
        try {
            var raw = redis.opsForValue().get(key);
            return raw == null ? null : json.readValue(raw, Snapshot.class);
        } catch (Exception unavailableOrInvalid) {
            log.warn("Authorization Redis read failed; falling back to PostgreSQL", unavailableOrInvalid);
            return null;
        }
    }

    private void writeCache(String key, Snapshot snapshot) {
        try {
            redis.opsForValue().set(key, json.writeValueAsString(snapshot), cacheTtl);
        } catch (Exception unavailable) {
            log.warn("Authorization Redis write failed; PostgreSQL remains authoritative", unavailable);
        }
    }

    private static String normalizeType(String value) {
        var type = value == null ? "" : value.trim().toUpperCase();
        if (!List.of("CUSTOMER", "ADMIN", "HOST").contains(type)) {
            throw new IllegalArgumentException("Unsupported account type: " + value);
        }
        return type;
    }

    private static String cacheKey(String accountType, UUID accountId, long version) {
        return "vistay:user:authz:v1:" + accountType + ":" + accountId + ":v" + version;
    }

    private record Header(UUID subjectId, UUID profileId, boolean active, long authorizationVersion) {}
    private record GrantRow(String permissionCode, String scopeType) {}

    public enum Scope { SELF, OWN, ASSIGNED, ALL }

    public record Grant(String permissionCode, List<Scope> scopes) {}

    public record Snapshot(
        String accountType,
        UUID authAccountId,
        UUID subjectId,
        UUID profileId,
        boolean active,
        long authorizationVersion,
        List<String> roles,
        List<Grant> grants
    ) {
        public static Snapshot inactive(String accountType, UUID accountId) {
            return new Snapshot(accountType, accountId, null, null, false, 0, List.of(), List.of());
        }

        public List<String> permissions() {
            return grants.stream().map(Grant::permissionCode).distinct().sorted().toList();
        }

        public boolean allows(String permission, Scope requiredScope) {
            return grants.stream().filter(grant -> grant.permissionCode().equals(permission))
                .anyMatch(grant -> grant.scopes().contains(Scope.ALL) || grant.scopes().contains(requiredScope));
        }
    }
}
