package com.nur.filter;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Predicate;

@Component
public class RouterValidator {

    public static final List<String> openAPiEndPoints =
            List.of("/auth/register", "/auth/authenticate", "/eureka");

    public Predicate<ServerHttpRequest> isSecured =
            serverHttpRequest -> openAPiEndPoints.stream()
                    .noneMatch(uri -> serverHttpRequest.getURI().getPath().contains(uri));
}
