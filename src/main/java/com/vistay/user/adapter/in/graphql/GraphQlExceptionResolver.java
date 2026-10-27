package com.vistay.user.adapter.in.graphql;

import graphql.GraphQLError;
import graphql.GraphqlErrorBuilder;
import graphql.GraphqlErrorException;
import graphql.schema.DataFetchingEnvironment;
import org.springframework.graphql.execution.DataFetcherExceptionResolverAdapter;
import org.springframework.stereotype.Component;

@Component
public class GraphQlExceptionResolver extends DataFetcherExceptionResolverAdapter {
    @Override
    protected GraphQLError resolveToSingleError(Throwable exception, DataFetchingEnvironment environment) {
        if (!(exception instanceof GraphqlErrorException error)) {
            return null;
        }
        return GraphqlErrorBuilder.newError(environment)
            .message(error.getMessage())
            .errorType(error.getErrorType())
            .extensions(error.getExtensions())
            .build();
    }
}
