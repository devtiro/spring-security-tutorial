package com.devtiro.books.config;

import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import jakarta.servlet.http.HttpServletRequest;

public class ApiKeyAuthFilter extends AbstractPreAuthenticatedProcessingFilter {

    private String principalRequestHeader;

    public ApiKeyAuthFilter(String principalRequestHeader) {
        this.principalRequestHeader = principalRequestHeader;
    }

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        return request.getHeader(principalRequestHeader);
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return null;
    }

}
