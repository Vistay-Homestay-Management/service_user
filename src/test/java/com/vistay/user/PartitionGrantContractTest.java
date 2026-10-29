package com.vistay.user;

import static org.assertj.core.api.Assertions.assertThat;

import com.vistay.contracts.common.v1.DataScopeType;
import com.vistay.contracts.common.v1.PartitionGrant;
import com.vistay.contracts.common.v1.PermissionGrant;
import org.junit.jupiter.api.Test;

class PartitionGrantContractTest {

    @Test
    void carriesAnOpaqueTypedPartitionAlongsideTheScope() {
        var binding = PartitionGrant.newBuilder()
            .setPartitionType("PROPERTY")
            .setPartitionId("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
            .build();
        var grant = PermissionGrant.newBuilder()
            .setPermissionCode("booking:read")
            .addScopes(DataScopeType.DATA_SCOPE_TYPE_PARTITION)
            .addPartitions(binding)
            .build();

        assertThat(grant.getScopesList()).containsExactly(DataScopeType.DATA_SCOPE_TYPE_PARTITION);
        assertThat(grant.getPartitionsList()).containsExactly(binding);
    }
}
