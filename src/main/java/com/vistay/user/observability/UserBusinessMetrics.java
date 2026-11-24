package com.vistay.user.observability;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/** Read-model gauges for profile/account health without personal-data labels. */
@Component
public class UserBusinessMetrics {
    private final JdbcClient jdbc;
    private final Map<String, AtomicLong> profiles = new LinkedHashMap<>();
    private final Map<String, AtomicLong> linkedProfiles = new LinkedHashMap<>();
    private final Map<String, Counter> creations = new LinkedHashMap<>();

    public UserBusinessMetrics(JdbcClient jdbc, MeterRegistry registry) {
        this.jdbc = jdbc;
        for (var type : new String[] {"CUSTOMER", "ADMIN", "HOST"}) {
            var total = new AtomicLong();
            var linked = new AtomicLong();
            profiles.put(type, total);
            linkedProfiles.put(type, linked);
            Gauge.builder("vistay_user_profiles", total, AtomicLong::get)
                .description("Current profiles by account type").tag("account_type", type).register(registry);
            Gauge.builder("vistay_user_linked_profiles", linked, AtomicLong::get)
                .description("Profiles that are linked to an identity account").tag("account_type", type).register(registry);
            creations.put(type, Counter.builder("vistay_user_profile_creations")
                .description("Successful profile creations").tag("account_type", type).register(registry));
        }
    }

    @PostConstruct
    @Scheduled(fixedDelayString = "${vistay.observability.business-metrics-refresh:60s}")
    public void refresh() {
        try {
            refreshType("CUSTOMER", "customers");
            refreshType("ADMIN", "admin_users");
            refreshType("HOST", "hosts");
        } catch (RuntimeException ignored) {
            // Observability is intentionally fail-open.
        }
    }

    public void profileCreated(String accountType) {
        var counter = creations.get(accountType);
        if (counter != null) counter.increment();
    }

    private void refreshType(String accountType, String table) {
        profiles.get(accountType).set(queryCount("SELECT count(*) FROM " + table + " WHERE profile_status = 'ACTIVE'"));
        linkedProfiles.get(accountType).set(queryCount("SELECT count(*) FROM " + table + " WHERE auth_account_id IS NOT NULL AND profile_status = 'ACTIVE'"));
    }

    private long queryCount(String sql) {
        return jdbc.sql(sql).query((rs, rowNum) -> rs.getLong(1)).single();
    }
}
