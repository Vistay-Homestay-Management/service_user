package com.vistay.user.adapter.in.grpc;

import java.util.List;
import java.util.UUID;
import com.vistay.contracts.common.v1.AccountType;
import com.vistay.contracts.user.v1.GetAuthorizationSnapshotRequest;
import com.vistay.contracts.user.v1.GetAuthorizationSnapshotResponse;
import com.vistay.contracts.user.v1.UserAuthorizationServiceGrpc;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import org.springframework.grpc.server.service.GrpcService;
import com.vistay.user.config.GrpcTrustBoundaryInterceptor;
import org.springframework.jdbc.core.simple.JdbcClient;

@GrpcService(interceptors = GrpcTrustBoundaryInterceptor.class)
public class UserAuthorizationGrpcService extends UserAuthorizationServiceGrpc.UserAuthorizationServiceImplBase {
    private final JdbcClient jdbc;

    public UserAuthorizationGrpcService(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public void getAuthorizationSnapshot(
        GetAuthorizationSnapshotRequest request,
        StreamObserver<GetAuthorizationSnapshotResponse> response
    ) {
        try {
            var accountId = UUID.fromString(request.getAccount().getAccountId());
            var snapshot = switch (request.getAccount().getAccountType()) {
                case ACCOUNT_TYPE_ADMIN -> adminSnapshot(accountId);
                case ACCOUNT_TYPE_CUSTOMER -> profileSnapshot("customers", accountId);
                case ACCOUNT_TYPE_HOST -> profileSnapshot("hosts", accountId);
                default -> throw Status.INVALID_ARGUMENT
                    .withDescription("account_type is required")
                    .asRuntimeException();
            };
            response.onNext(snapshot);
            response.onCompleted();
        } catch (IllegalArgumentException invalid) {
            response.onError(Status.INVALID_ARGUMENT.withDescription("Invalid account id").asRuntimeException());
        } catch (RuntimeException failure) {
            response.onError(failure);
        }
    }

    private GetAuthorizationSnapshotResponse adminSnapshot(UUID authAccountId) {
        var profile = jdbc.sql("""
            SELECT id, profile_status = 'ACTIVE' AS active, version
            FROM admin_users WHERE auth_account_id = :accountId
            """)
            .param("accountId", authAccountId)
            .query(ProfileRow.class)
            .optional();
        if (profile.isEmpty()) {
            return GetAuthorizationSnapshotResponse.newBuilder().setActive(false).build();
        }
        var row = profile.get();
        List<String> roles = jdbc.sql("""
            SELECT r.code FROM admin_user_roles aur
            JOIN roles r ON r.id = aur.role_id
            WHERE aur.admin_user_id = :profileId
              AND aur.revoked_at IS NULL
              AND aur.valid_from <= now()
              AND (aur.valid_until IS NULL OR aur.valid_until > now())
              AND r.active
            ORDER BY r.code
            """)
            .param("profileId", row.id())
            .query(String.class)
            .list();
        List<String> permissions = jdbc.sql("""
            SELECT DISTINCT p.code FROM admin_user_roles aur
            JOIN roles r ON r.id = aur.role_id AND r.active
            JOIN role_permissions rp ON rp.role_id = r.id
            JOIN permissions p ON p.id = rp.permission_id
            WHERE aur.admin_user_id = :profileId
              AND aur.revoked_at IS NULL
              AND aur.valid_from <= now()
              AND (aur.valid_until IS NULL OR aur.valid_until > now())
            ORDER BY p.code
            """)
            .param("profileId", row.id())
            .query(String.class)
            .list();
        return GetAuthorizationSnapshotResponse.newBuilder()
            .setActive(row.active())
            .setProfileId(row.id().toString())
            .addAllRoles(roles)
            .addAllPermissions(permissions)
            .setAuthorizationVersion(row.version())
            .build();
    }

    private GetAuthorizationSnapshotResponse profileSnapshot(String table, UUID authAccountId) {
        var row = jdbc.sql("SELECT id, profile_status = 'ACTIVE' AS active, version FROM " + table
                + " WHERE auth_account_id = :accountId")
            .param("accountId", authAccountId)
            .query(ProfileRow.class)
            .optional();
        if (row.isEmpty()) {
            return GetAuthorizationSnapshotResponse.newBuilder().setActive(false).build();
        }
        return GetAuthorizationSnapshotResponse.newBuilder()
            .setActive(row.get().active())
            .setProfileId(row.get().id().toString())
            .setAuthorizationVersion(row.get().version())
            .build();
    }

    private record ProfileRow(UUID id, boolean active, long version) {}
}
