package com.vistay.user.application;

import com.vistay.user.application.AuthorizationSnapshotService.Scope;
import graphql.GraphqlErrorException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.graphql.execution.ErrorType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;

@Service
public class UserDirectoryService {
    private static final int DEFAULT_PAGE_SIZE = 25;
    private static final int MAX_PAGE_SIZE = 100;

    private final JdbcClient jdbc;
    private final AuthorizationSnapshotService snapshots;

    public UserDirectoryService(JdbcClient jdbc, AuthorizationSnapshotService snapshots) {
        this.jdbc = jdbc;
        this.snapshots = snapshots;
    }

    public UserDirectoryPage find(
        UUID requesterAccountId,
        String accountType,
        String search,
        Integer first,
        String after
    ) {
        requireRead(requesterAccountId);
        var type = normalizeAccountType(accountType);
        var query = search == null ? "" : search.trim();
        var limit = first == null ? DEFAULT_PAGE_SIZE : Math.max(1, Math.min(first, MAX_PAGE_SIZE));
        var offset = decodeCursor(after);
        var table = table(type);
        var codeColumn = codeColumn(type);
        var subtypeColumn = subtypeColumn(type);
        var verificationColumn = verificationColumn(type);

        var total = jdbc.sql("""
                SELECT count(*)::int
                FROM %s
                WHERE :query = ''
                   OR full_name ILIKE '%%' || :query || '%%'
                   OR COALESCE(email::text, '') ILIKE '%%' || :query || '%%'
                   OR COALESCE(normalized_phone, '') ILIKE '%%' || :query || '%%'
                   OR COALESCE(%s, '') ILIKE '%%' || :query || '%%'
                """.formatted(table, codeColumn))
            .param("query", query)
            .query(Integer.class)
            .single();

        var nodes = jdbc.sql("""
                SELECT id AS profile_id,
                       auth_account_id AS account_id,
                       CAST(:accountType AS varchar) AS account_type,
                       full_name AS display_name,
                       email::text AS email,
                       normalized_phone AS contact_phone,
                       profile_status AS status,
                       %s AS reference_code,
                       %s AS subtype,
                       %s AS verification_status,
                       %s AS joined_on,
                       created_at,
                       updated_at
                FROM %s
                WHERE :query = ''
                   OR full_name ILIKE '%%' || :query || '%%'
                   OR COALESCE(email::text, '') ILIKE '%%' || :query || '%%'
                   OR COALESCE(normalized_phone, '') ILIKE '%%' || :query || '%%'
                   OR COALESCE(%s, '') ILIKE '%%' || :query || '%%'
                ORDER BY updated_at DESC, id
                LIMIT :limit OFFSET :offset
                """.formatted(
                    codeColumn,
                    subtypeColumn,
                    verificationColumn,
                    joinedOnColumn(type),
                    table,
                    codeColumn
                ))
            .param("accountType", type)
            .param("query", query)
            .param("limit", limit)
            .param("offset", offset)
            .query(UserDirectoryEntry.class)
            .list();

        var nextOffset = offset + nodes.size();
        return new UserDirectoryPage(
            nodes,
            total,
            nextOffset < total ? encodeCursor(nextOffset) : null
        );
    }

    private void requireRead(UUID accountId) {
        var snapshot = snapshots.get("ADMIN", accountId);
        if (!snapshot.active() || !snapshot.allows("user:read", Scope.ALL)) {
            throw error("FORBIDDEN", "Missing permission user:read@ALL");
        }
    }

    private static String normalizeAccountType(String value) {
        var type = value == null ? "" : value.trim().toUpperCase();
        if (!List.of("CUSTOMER", "ADMIN", "HOST").contains(type)) {
            throw error("INVALID_ACCOUNT_TYPE", "Unsupported account type");
        }
        return type;
    }

    private static String table(String type) {
        return switch (type) {
            case "CUSTOMER" -> "customers";
            case "ADMIN" -> "admin_users";
            case "HOST" -> "hosts";
            default -> throw new IllegalArgumentException("Unsupported account type");
        };
    }

    private static String codeColumn(String type) {
        return switch (type) {
            case "CUSTOMER" -> "NULL::varchar";
            case "ADMIN" -> "employee_code";
            case "HOST" -> "host_code";
            default -> throw new IllegalArgumentException("Unsupported account type");
        };
    }

    private static String subtypeColumn(String type) {
        return "ADMIN".equals(type) ? "user_type" : "NULL::varchar";
    }

    private static String verificationColumn(String type) {
        return "HOST".equals(type) ? "verification_status" : "NULL::varchar";
    }

    private static String joinedOnColumn(String type) {
        return "ADMIN".equals(type) ? "hired_on" : "NULL::date";
    }

    private static int decodeCursor(String cursor) {
        if (cursor == null || cursor.isBlank()) return 0;
        try {
            var decoded = new String(Base64.getUrlDecoder().decode(cursor), StandardCharsets.US_ASCII);
            if (!decoded.startsWith("offset:")) throw new IllegalArgumentException();
            return Math.max(0, Integer.parseInt(decoded.substring("offset:".length())));
        } catch (RuntimeException invalid) {
            throw error("INVALID_CURSOR", "User directory cursor is invalid");
        }
    }

    private static String encodeCursor(long offset) {
        return Base64.getUrlEncoder().withoutPadding()
            .encodeToString(("offset:" + offset).getBytes(StandardCharsets.US_ASCII));
    }

    private static GraphqlErrorException error(String code, String message) {
        return GraphqlErrorException.newErrorException()
            .message(message)
            .errorClassification("FORBIDDEN".equals(code) ? ErrorType.FORBIDDEN : ErrorType.BAD_REQUEST)
            .extensions(Map.of("code", code))
            .build();
    }

    public record UserDirectoryPage(
        List<UserDirectoryEntry> nodes,
        int totalCount,
        String nextCursor
    ) {}

    public record UserDirectoryEntry(
        UUID profileId,
        UUID accountId,
        String accountType,
        String displayName,
        String email,
        String contactPhone,
        String status,
        String referenceCode,
        String subtype,
        String verificationStatus,
        LocalDate joinedOn,
        OffsetDateTime createdAt,
        OffsetDateTime updatedAt
    ) {}
}
