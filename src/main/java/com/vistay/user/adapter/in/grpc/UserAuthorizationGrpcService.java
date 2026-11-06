package com.vistay.user.adapter.in.grpc;

import com.vistay.contracts.common.v1.AccountType;
import com.vistay.contracts.common.v1.DataScopeType;
import com.vistay.contracts.common.v1.PermissionGrant;
import com.vistay.contracts.common.v1.PartitionGrant;
import com.vistay.contracts.user.v1.GetAuthorizationSnapshotRequest;
import com.vistay.contracts.user.v1.GetAuthorizationSnapshotResponse;
import com.vistay.contracts.user.v1.GetRolePoliciesRequest;
import com.vistay.contracts.user.v1.GetRolePoliciesResponse;
import com.vistay.contracts.user.v1.RolePermissionPolicy;
import com.vistay.contracts.user.v1.RolePolicy;
import com.vistay.contracts.user.v1.UserAuthorizationServiceGrpc;
import com.vistay.user.application.AuthorizationSnapshotService;
import com.vistay.user.application.RolePolicyService;
import com.vistay.user.config.GrpcTrustBoundaryInterceptor;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import java.util.UUID;
import org.springframework.grpc.server.service.GrpcService;

@GrpcService(interceptors = GrpcTrustBoundaryInterceptor.class)
public class UserAuthorizationGrpcService extends UserAuthorizationServiceGrpc.UserAuthorizationServiceImplBase {
    private final AuthorizationSnapshotService snapshots;
    private final RolePolicyService rolePolicies;

    public UserAuthorizationGrpcService(
        AuthorizationSnapshotService snapshots,
        RolePolicyService rolePolicies
    ) {
        this.snapshots = snapshots;
        this.rolePolicies = rolePolicies;
    }

    @Override
    public void getRolePolicies(
        GetRolePoliciesRequest request,
        StreamObserver<GetRolePoliciesResponse> response
    ) {
        try {
            var accountType = accountType(request.getAccountType());
            var result = rolePolicies.get(accountType, request.getRoleCodesList());
            var builder = GetRolePoliciesResponse.newBuilder()
                .setCatalogVersion(result.catalogVersion())
                .setSchemaVersion(result.schemaVersion());
            result.policies().forEach(policy -> builder.addPolicies(RolePolicy.newBuilder()
                .setRoleCode(policy.roleCode())
                .setRoleVersion(policy.roleVersion())
                .addAllPermissions(policy.permissions().stream().map(permission ->
                    RolePermissionPolicy.newBuilder()
                        .setPermissionCode(permission.permissionCode())
                        .addAllAllowedScopes(permission.allowedScopes().stream()
                            .map(scope -> DataScopeType.valueOf("DATA_SCOPE_TYPE_" + scope)).toList())
                        .addAllPartitionTypes(permission.partitionTypes())
                        .build()).toList())
                .build()));
            response.onNext(builder.build());
            response.onCompleted();
        } catch (IllegalArgumentException invalid) {
            response.onError(Status.INVALID_ARGUMENT.withDescription(invalid.getMessage()).asRuntimeException());
        } catch (RuntimeException failure) {
            response.onError(Status.UNAVAILABLE.withDescription("Role policies are unavailable")
                .withCause(failure).asRuntimeException());
        }
    }

    @Override
    public void getAuthorizationSnapshot(
        GetAuthorizationSnapshotRequest request,
        StreamObserver<GetAuthorizationSnapshotResponse> response
    ) {
        try {
            if (!request.hasAccount()) {
                throw Status.INVALID_ARGUMENT.withDescription("account is required").asRuntimeException();
            }
            var accountId = UUID.fromString(request.getAccount().getAccountId());
            var accountType = accountType(request.getAccount().getAccountType());
            var snapshot = snapshots.get(accountType, accountId);
            if (request.getMinimumAuthorizationVersion() > snapshot.authorizationVersion()) {
                throw Status.FAILED_PRECONDITION
                    .withDescription("Authorization snapshot has not reached the requested version")
                    .asRuntimeException();
            }

            var builder = GetAuthorizationSnapshotResponse.newBuilder()
                .setActive(snapshot.active())
                .addAllRoles(snapshot.roles())
                .addAllPermissions(snapshot.permissions())
                .setAuthorizationVersion(snapshot.authorizationVersion());
            if (snapshot.profileId() != null) {
                builder.setProfileId(snapshot.profileId().toString());
            }
            snapshot.grants().forEach(grant -> builder.addGrants(PermissionGrant.newBuilder()
                .setPermissionCode(grant.permissionCode())
                .addAllScopes(grant.scopes().stream().map(scope -> DataScopeType.valueOf(
                    "DATA_SCOPE_TYPE_" + scope.name())).toList())
                .addAllPartitions(grant.partitions().stream().map(partition -> PartitionGrant.newBuilder()
                    .setPartitionType(partition.partitionType())
                    .setPartitionId(partition.partitionId().toString())
                    .build()).toList())
                .build()));
            response.onNext(builder.build());
            response.onCompleted();
        } catch (IllegalArgumentException invalid) {
            response.onError(Status.INVALID_ARGUMENT.withDescription(invalid.getMessage()).asRuntimeException());
        } catch (RuntimeException failure) {
            response.onError(failure);
        }
    }

    private static String accountType(AccountType accountType) {
        return switch (accountType) {
            case ACCOUNT_TYPE_ADMIN -> "ADMIN";
            case ACCOUNT_TYPE_CUSTOMER -> "CUSTOMER";
            case ACCOUNT_TYPE_HOST -> "HOST";
            default -> throw new IllegalArgumentException("account_type is required");
        };
    }
}
