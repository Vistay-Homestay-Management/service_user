package com.vistay.user.config;

import io.grpc.Context;
import io.grpc.Deadline;
import io.grpc.Grpc;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class GrpcTrustBoundaryInterceptor implements ServerInterceptor {
    private static final int URI_SAN_TYPE = 6;

    private final Set<String> allowedCallerUris;
    private final long maximumDeadlineMillis;

    public GrpcTrustBoundaryInterceptor(
        @Value("${vistay.grpc.allowed-caller-uris:spiffe://vistay/service/authentication}")
        List<String> allowedCallerUris,
        @Value("${vistay.grpc.maximum-deadline:2s}") java.time.Duration maximumDeadline
    ) {
        this.allowedCallerUris = Set.copyOf(allowedCallerUris);
        this.maximumDeadlineMillis = maximumDeadline.toMillis();
    }

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
        ServerCall<ReqT, RespT> call,
        Metadata headers,
        ServerCallHandler<ReqT, RespT> next
    ) {
        var rejection = validate(call, Context.current().getDeadline());
        if (rejection != null) {
            call.close(rejection, new Metadata());
            return new ServerCall.Listener<>() {};
        }
        return next.startCall(call, headers);
    }

    Status validate(ServerCall<?, ?> call, Deadline deadline) {
        var session = call.getAttributes().get(Grpc.TRANSPORT_ATTR_SSL_SESSION);
        if (session == null) {
            return Status.UNAUTHENTICATED.withDescription("mTLS client certificate is required");
        }
        var callerUri = allowedCallerUri(session);
        if (callerUri == null) {
            return Status.PERMISSION_DENIED.withDescription("Caller certificate identity is not allowed");
        }
        if (deadline == null) {
            return Status.INVALID_ARGUMENT.withDescription("An explicit gRPC deadline is required");
        }
        if (deadline.isExpired()) {
            return Status.DEADLINE_EXCEEDED.withDescription("The gRPC deadline has expired");
        }
        if (deadline.timeRemaining(TimeUnit.MILLISECONDS) > maximumDeadlineMillis) {
            return Status.INVALID_ARGUMENT.withDescription(
                "The gRPC deadline exceeds " + maximumDeadlineMillis + "ms"
            );
        }
        return null;
    }

    private String allowedCallerUri(SSLSession session) {
        try {
            for (Certificate certificate : session.getPeerCertificates()) {
                if (!(certificate instanceof X509Certificate x509)) {
                    continue;
                }
                Collection<List<?>> names = x509.getSubjectAlternativeNames();
                if (names == null) {
                    continue;
                }
                for (var name : names) {
                    if (name.size() >= 2
                        && name.get(0) instanceof Integer type
                        && type == URI_SAN_TYPE
                        && name.get(1) instanceof String uri
                        && allowedCallerUris.contains(uri)) {
                        return uri;
                    }
                }
            }
            return null;
        } catch (SSLPeerUnverifiedException | java.security.cert.CertificateParsingException failure) {
            return null;
        }
    }
}
