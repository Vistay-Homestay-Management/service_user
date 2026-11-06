package com.vistay.user.application;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

/**
 * Role-owned authorization policy reader.
 *
 * <p>User Service is the only writer for these Redis entries. A caller reads
 * every role from one MGET and a cold request is filled by one SQL batch. An
 * unavailable or malformed Redis entry is only a cache miss; PostgreSQL stays
 * authoritative. Unknown and inactive roles are omitted and grant nothing.</p>
 */
@Service
public class RolePolicyService {
    public static final int SCHEMA_VERSION = 2;
    private static final Logger log = LoggerFactory.getLogger(RolePolicyService.class);
    private static final Pattern ROLE_CODE = Pattern.compile("^[A-Z][A-Z0-9_]{1,63}$");
    private static final Set<String> ACCOUNT_TYPES = Set.of("CUSTOMER", "ADMIN", "HOST");

    private final JdbcClient jdbc;
    private final StringRedisTemplate redis;
    private final ObjectMapper json;
    private final Duration cacheTtl;
    private final Duration cacheJitter;

    public RolePolicyService(
        JdbcClient jdbc,
        StringRedisTemplate redis,
        ObjectMapper json,
        @Value("${vistay.authorization.role-policy-cache-ttl:5m}") Duration cacheTtl,
        @Value("${vistay.authorization.role-policy-cache-jitter:30s}") Duration cacheJitter
    ) {
        this.jdbc = jdbc;
        this.redis = redis;
        this.json = json;
        this.cacheTtl = cacheTtl;
        this.cacheJitter = cacheJitter;
    }

    public BatchResult get(String accountType, Collection<String> requestedRoleCodes) {
        var normalizedType = normalizeAccountType(accountType);
        var roleCodes = normalizeRoleCodes(requestedRoleCodes);
        var catalog = catalogVersion();
        if (roleCodes.isEmpty()) {
            return new BatchResult(catalog, SCHEMA_VERSION, List.of());
        }

        Map<String, RolePolicy> found = new LinkedHashMap<>();
        var misses = new ArrayList<String>();
        var keys = roleCodes.stream().map(code -> cacheKey(normalizedType, code)).toList();
        List<String> cached = null;
        try {
            cached = redis.opsForValue().multiGet(keys);
        } catch (RuntimeException unavailable) {
            log.warn("Role-policy Redis MGET failed; falling back to PostgreSQL", unavailable);
        }

        for (var index = 0; index < roleCodes.size(); index++) {
            var code = roleCodes.get(index);
            var raw = cached != null && index < cached.size() ? cached.get(index) : null;
            var entry = decode(raw, normalizedType, code, catalog);
            if (entry == null) {
                misses.add(code);
            } else if (entry.active() && entry.policy() != null) {
                found.put(code, entry.policy());
            }
        }

        if (!misses.isEmpty()) {
            var loaded = load(normalizedType, misses);
            for (var code : misses) {
                var policy = loaded.get(code);
                var entry = new CacheEntry(normalizedType, code, policy != null, catalog,
                    SCHEMA_VERSION, policy);
                write(cacheKey(normalizedType, code), entry);
                if (policy != null) {
                    found.put(code, policy);
                }
            }
        }

        return new BatchResult(catalog, SCHEMA_VERSION,
            roleCodes.stream().map(found::get).filter(java.util.Objects::nonNull).toList());
    }

    public void evict(String accountType, String roleCode) {
        try {
            redis.delete(cacheKey(normalizeAccountType(accountType), normalizeRoleCodes(List.of(roleCode)).getFirst()));
        } catch (RuntimeException unavailable) {
            log.warn("Role-policy Redis eviction failed; TTL bounds stale data", unavailable);
        }
    }

    private long catalogVersion() {
        return jdbc.sql("SELECT catalog_version FROM authorization_catalog_state WHERE singleton")
            .query(Long.class).single();
    }

    private Map<String, RolePolicy> load(String accountType, List<String> roleCodes) {
        var rows = jdbc.sql("""
                SELECT r.code AS role_code, r.policy_version, p.code AS permission_code,
                       rpp.scope_type, rppt.partition_type
                FROM roles r
                LEFT JOIN role_permissions rp ON rp.role_id = r.id
                LEFT JOIN permissions p ON p.id = rp.permission_id AND p.active
                LEFT JOIN role_permission_policies rpp
                  ON rpp.role_id = rp.role_id AND rpp.permission_id = rp.permission_id
                LEFT JOIN role_permission_partition_types rppt
                  ON rppt.role_id = rp.role_id AND rppt.permission_id = rp.permission_id
                WHERE r.audience = :accountType AND r.active AND r.code IN (:roleCodes)
                ORDER BY r.code, p.code, rpp.scope_type, rppt.partition_type
                """)
            .param("accountType", accountType)
            .param("roleCodes", roleCodes)
            .query(PolicyRow.class)
            .list();

        Map<String, MutableRole> grouped = new LinkedHashMap<>();
        for (var row : rows) {
            var role = grouped.computeIfAbsent(row.roleCode(),
                ignored -> new MutableRole(row.roleCode(), row.policyVersion()));
            if (row.permissionCode() != null) {
                var permission = role.permissions.computeIfAbsent(row.permissionCode(),
                    ignored -> new MutablePermission(row.permissionCode()));
                if (row.scopeType() != null) permission.allowedScopes.add(row.scopeType());
                if (row.partitionType() != null) permission.partitionTypes.add(row.partitionType());
            }
        }
        Map<String, RolePolicy> result = new LinkedHashMap<>();
        grouped.forEach((code, role) -> result.put(code, role.freeze()));
        return result;
    }

    private CacheEntry decode(String raw, String accountType, String roleCode, long catalogVersion) {
        if (raw == null) return null;
        try {
            var entry = json.readValue(raw, CacheEntry.class);
            if (!accountType.equals(entry.accountType()) || !roleCode.equals(entry.roleCode())
                || entry.schemaVersion() != SCHEMA_VERSION) {
                return null;
            }
            return entry;
        } catch (RuntimeException invalid) {
            log.warn("Ignoring malformed role-policy cache entry for {}/{}", accountType, roleCode);
            return null;
        }
    }

    private void write(String key, CacheEntry entry) {
        try {
            var jitterBound = Math.max(0, cacheJitter.toSeconds());
            var jitter = jitterBound == 0 ? 0 : ThreadLocalRandom.current().nextLong(-jitterBound, jitterBound + 1);
            var ttl = cacheTtl.plusSeconds(jitter);
            if (ttl.isNegative() || ttl.isZero()) ttl = Duration.ofSeconds(1);
            redis.opsForValue().set(key, json.writeValueAsString(entry), ttl);
        } catch (RuntimeException unavailable) {
            log.warn("Role-policy Redis write failed; PostgreSQL remains authoritative", unavailable);
        }
    }

    static String cacheKey(String accountType, String roleCode) {
        return "vistay:authz:role-policy:v2:" + accountType + ":" + roleCode;
    }

    private static String normalizeAccountType(String value) {
        var normalized = value == null ? "" : value.trim().toUpperCase();
        if (!ACCOUNT_TYPES.contains(normalized)) {
            throw new IllegalArgumentException("Unsupported account type");
        }
        return normalized;
    }

    private static List<String> normalizeRoleCodes(Collection<String> values) {
        if (values == null) return List.of();
        var unique = new LinkedHashSet<String>();
        for (var value : values) {
            var code = value == null ? "" : value.trim().toUpperCase();
            if (!ROLE_CODE.matcher(code).matches()) {
                throw new IllegalArgumentException("Invalid role code");
            }
            unique.add(code);
        }
        if (unique.size() > 64) throw new IllegalArgumentException("At most 64 role codes are allowed");
        return List.copyOf(unique);
    }

    private record PolicyRow(String roleCode, long policyVersion, String permissionCode,
        String scopeType, String partitionType) {}
    private record CacheEntry(String accountType, String roleCode, boolean active,
        long catalogVersion, int schemaVersion, RolePolicy policy) {}

    private static final class MutableRole {
        private final String code;
        private final long version;
        private final Map<String, MutablePermission> permissions = new LinkedHashMap<>();
        private MutableRole(String code, long version) { this.code = code; this.version = version; }
        private RolePolicy freeze() {
            return new RolePolicy(code, version, permissions.values().stream()
                .map(MutablePermission::freeze).toList());
        }
    }

    private static final class MutablePermission {
        private final String code;
        private final Set<String> allowedScopes = new LinkedHashSet<>();
        private final Set<String> partitionTypes = new LinkedHashSet<>();
        private MutablePermission(String code) { this.code = code; }
        private PermissionPolicy freeze() {
            return new PermissionPolicy(code, List.copyOf(allowedScopes), List.copyOf(partitionTypes));
        }
    }

    public record PermissionPolicy(String permissionCode, List<String> allowedScopes,
        List<String> partitionTypes) {}
    public record RolePolicy(String roleCode, long roleVersion, List<PermissionPolicy> permissions) {}
    public record BatchResult(long catalogVersion, int schemaVersion, List<RolePolicy> policies) {}
}
