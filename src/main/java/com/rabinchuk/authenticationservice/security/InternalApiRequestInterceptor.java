package com.rabinchuk.authenticationservice.security;

import feign.RequestInterceptor;
import feign.RequestTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class InternalApiRequestInterceptor implements RequestInterceptor {

    @Value("${INTERNAL_KEY}")
    private String internalApiKey;

    @Override
    public void apply(RequestTemplate requestTemplate) {
        requestTemplate.header("X-Internal-API-Key", internalApiKey);
    }
}
