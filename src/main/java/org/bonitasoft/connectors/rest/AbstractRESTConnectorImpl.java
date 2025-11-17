/**
 * Copyright (C) 2014-2025 BonitaSoft S.A. BonitaSoft, 32 rue Gustave Eiffel - 38000 Grenoble This
 * library is free software; you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation version 2.1 of the
 * License. This library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU Lesser General Public License for more details. You should have received a
 * copy of the GNU Lesser General Public License along with this program; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package org.bonitasoft.connectors.rest;

import java.net.URI;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.bonitasoft.connectors.rest.model.AuthorizationType;
import org.bonitasoft.connectors.rest.model.ProxyProtocol;
import org.bonitasoft.connectors.rest.model.SSLVerifier;
import org.bonitasoft.connectors.rest.model.TrustCertificateStrategy;
import org.bonitasoft.connectors.rest.utils.ProxyUtils;
import org.bonitasoft.engine.connector.AbstractConnector;
import org.bonitasoft.engine.connector.ConnectorValidationException;

public abstract class AbstractRESTConnectorImpl extends AbstractConnector {

    protected static final String URL_INPUT_PARAMETER = "url";
    protected static final String METHOD_INPUT_PARAMETER = "method";
    protected static final String CONTENTTYPE_INPUT_PARAMETER = "contentType";
    protected static final String CHARSET_INPUT_PARAMETER = "charset";
    protected static final String URLCOOKIES_INPUT_PARAMETER = "urlCookies";
    protected static final String URLHEADERS_INPUT_PARAMETER = "urlHeaders";
    protected static final String ADD_BONITA_CONTEXT_HEADERS_INPUT_PARAMETER = "add_bonita_context_headers";
    protected static final String BONITA_ACTIVITY_INSTANCE_ID_HEADER_INPUT_PARAMETER = "bonita_activity_instance_id_header";
    protected static final String BONITA_PROCESS_INSTANCE_ID_HEADER_INPUT_PARAMETER = "bonita_process_instance_id_header";
    protected static final String BONITA_ROOT_PROCESS_INSTANCE_ID_HEADER_INPUT_PARAMETER = "bonita_root_process_instance_id_header";
    protected static final String BONITA_PROCESS_DEFINITION_ID_HEADER_INPUT_PARAMETER = "bonita_process_definition_id_header";
    protected static final String BONITA_TASK_ASSIGNEE_ID_HEADER_INPUT_PARAMETER = "bonita_task_assignee_id_header";
    protected static final String DOCUMENT_BODY_INPUT_PARAMETER = "documentBody";
    protected static final String BODY_INPUT_PARAMETER = "body";
    protected static final String DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER = "do_not_follow_redirect";
    protected static final String IGNORE_BODY_INPUT_PARAMETER = "ignore_body";
    protected static final String FAIL_ON_HTTP_4XX_INPUT_PARAMETER = "fail_on_http_4xx";
    protected static final String FAIL_ON_HTTP_5XX_INPUT_PARAMETER = "fail_on_http_5xx";
    protected static final String FAILURE_EXCEPTIONS_HTTP_CODES_INPUT_PARAMETER = "failure_exception_codes";
    protected static final String RETRY_ON_HTTP_5XX_INPUT_PARAMETER = "retry_on_http_5xx";
    protected static final String RETRY_ADDITIONAL_HTTP_CODES_INPUT_PARAMETER = "retry_additional_codes";
    protected static final String MAXIMUM_BODY_CONTENT_PRINTED_LOGS_PARAMETER = "max_body_content_printed";
    protected static final String SENSITIVE_HEADERS_PRINTED_LOGS_PARAMETER = "sensitive_headers_printed";
    protected static final String TRUST_CERTIFICATE_STRATEGY_INPUT_PARAMETER = "trust_strategy";
    protected static final String TLS_INPUT_PARAMETER = "TLS";
    protected static final String HOSTNAME_VERIFIER_INPUT_PARAMETER = "hostname_verifier";
    protected static final String TRUST_STORE_FILE_INPUT_PARAMETER = "trust_store_file";
    protected static final String TRUST_STORE_PASSWORD_INPUT_PARAMETER = "trust_store_password";
    protected static final String KEY_STORE_FILE_INPUT_PARAMETER = "key_store_file";
    protected static final String KEY_STORE_PASSWORD_INPUT_PARAMETER = "key_store_password";
    protected static final String AUTH_TYPE_PARAMETER = "auth_type";
    protected static final String AUTH_USERNAME_INPUT_PARAMETER = "auth_username";
    protected static final String AUTH_PASSWORD_INPUT_PARAMETER = "auth_password";
    protected static final String AUTH_HOST_INPUT_PARAMETER = "auth_host";
    protected static final String AUTH_PORT_INPUT_PARAMETER = "auth_port";
    protected static final String AUTH_REALM_INPUT_PARAMETER = "auth_realm";
    protected static final String AUTH_PREEMPTIVE_INPUT_PARAMETER = "auth_preemptive";
    protected static final String OAUTH2_TOKEN_ENDPOINT_INPUT_PARAMETER = "oauth2_token_endpoint";
    protected static final String OAUTH2_CLIENT_ID_INPUT_PARAMETER = "oauth2_client_id";
    protected static final String OAUTH2_CLIENT_SECRET_INPUT_PARAMETER = "oauth2_client_secret";
    protected static final String OAUTH2_SCOPE_INPUT_PARAMETER = "oauth2_scope";
    protected static final String OAUTH2_TOKEN_INPUT_PARAMETER = "oauth2_token";
    protected static final String OAUTH2_CODE_INPUT_PARAMETER = "oauth2_code";
    protected static final String OAUTH2_CODE_VERIFIER_INPUT_PARAMETER = "oauth2_code_verifier";
    protected static final String OAUTH2_REDIRECT_URI_INPUT_PARAMETER = "oauth2_redirect_uri";
    protected static final String PROXY_PROTOCOL_INPUT_PARAMETER = "proxy_protocol";
    protected static final String PROXY_HOST_INPUT_PARAMETER = "proxy_host";
    protected static final String PROXY_PORT_INPUT_PARAMETER = "proxy_port";
    protected static final String PROXY_USERNAME_INPUT_PARAMETER = "proxy_username";
    protected static final String PROXY_PASSWORD_INPUT_PARAMETER = "proxy_password";
    protected static final String BODY_AS_STRING_OUTPUT_PARAMETER = "bodyAsString";
    protected static final String BODY_AS_OBJECT_OUTPUT_PARAMETER = "bodyAsObject";
    protected static final String HEADERS_OUTPUT_PARAMETER = "headers";
    protected static final String STATUS_CODE_OUTPUT_PARAMETER = "status_code";
    protected static final String STATUS_MESSAGE_OUTPUT_PARAMETER = "status_message";
    protected static final String SOCKET_TIMEOUT_MS_PARAMETER = "socket_timeout_ms";
    protected static final String CONNECTION_TIMEOUT_MS_PARAMETER = "connection_timeout_ms";
    protected static final String AUTOMATIC_PROXY_RESOLUTION_PARAMETER = "automatic_proxy_resolution";

    protected static final int SOCKET_TIMEOUT_MS_DEFAULT_VALUE = 60_000;
    protected static final int CONNECTION_TIMEOUT_MS_DEFAULT_VALUE = 60_000;

    protected final String getUrl() {
        return (java.lang.String) getInputParameter(URL_INPUT_PARAMETER);
    }

    protected String getMethod() {
        return (java.lang.String) getInputParameter(METHOD_INPUT_PARAMETER);
    }

    protected final String getContentType() {
        return (java.lang.String) getInputParameter(CONTENTTYPE_INPUT_PARAMETER);
    }

    protected final String getCharset() {
        return (java.lang.String) getInputParameter(CHARSET_INPUT_PARAMETER);
    }

    @SuppressWarnings("unchecked")
    protected final List<List<?>> getUrlCookies() {
        List<List<?>> cookies = (List<List<?>>) getInputParameter(URLCOOKIES_INPUT_PARAMETER);
        if (cookies == null) {
            cookies = Collections.emptyList();
        }
        cookies.removeIf(emptyLines());
        return cookies;
    }

    private Predicate<Object> emptyLines() {
        return new Predicate<>() {

            @Override
            public boolean test(Object input) {
                if (input instanceof List) {
                    final List<?> line = (List<?>) input;
                    return line.size() != 2 || (emptyCell(line, 0) && emptyCell(line, 1));
                }
                return true;
            }

            private boolean emptyCell(final List<?> line, int cellIndex) {
                final Object cellValue = line.get(cellIndex);
                return cellValue == null || cellValue.toString().trim().isEmpty();
            }
        };
    }

    @SuppressWarnings("unchecked")
    protected final List<List<?>> getUrlHeaders() {
        List<List<?>> headers = (List<List<?>>) getInputParameter(URLHEADERS_INPUT_PARAMETER);
        if (headers == null) {
            headers = Collections.emptyList();
        }
        headers.removeIf(emptyLines());
        return headers;
    }

    protected final Boolean getAddBonitaContextHeaders() {
        return (Boolean) getInputParameter(ADD_BONITA_CONTEXT_HEADERS_INPUT_PARAMETER, Boolean.FALSE);
    }

    protected final String getBonitaActivityInstanceIdHeader() {
        return (String) getInputParameter(BONITA_ACTIVITY_INSTANCE_ID_HEADER_INPUT_PARAMETER);
    }

    protected final String getBonitaProcessInstanceIdHeader() {
        return (String) getInputParameter(BONITA_PROCESS_INSTANCE_ID_HEADER_INPUT_PARAMETER);
    }

    protected final String getBonitaRootProcessInstanceIdHeader() {
        return (String) getInputParameter(BONITA_ROOT_PROCESS_INSTANCE_ID_HEADER_INPUT_PARAMETER);
    }

    protected final String getBonitaProcessDefinitionIdHeader() {
        return (String) getInputParameter(BONITA_PROCESS_DEFINITION_ID_HEADER_INPUT_PARAMETER);
    }

    protected final String getBonitaTaskAssigneeIdHeader() {
        return (String) getInputParameter(BONITA_TASK_ASSIGNEE_ID_HEADER_INPUT_PARAMETER);
    }

    protected final String getDocumentBody() {
        return (String) getInputParameter(DOCUMENT_BODY_INPUT_PARAMETER);
    }

    protected final String getBody() {
        return (String) getInputParameter(BODY_INPUT_PARAMETER);
    }

    protected final Boolean getTLS() {
        return (Boolean) getInputParameter(TLS_INPUT_PARAMETER, Boolean.TRUE);
    }

    protected final TrustCertificateStrategy getTrustCertificateStrategy() {
        final String trustParam = (String) getInputParameter(TRUST_CERTIFICATE_STRATEGY_INPUT_PARAMETER);
        if (trustParam != null && !trustParam.trim().isEmpty()) {
            return TrustCertificateStrategy.valueOf(trustParam);
        }
        return TrustCertificateStrategy.DEFAULT;
    }

    protected final SSLVerifier getHostnameVerifier() {
        return SSLVerifier.getSSLVerifierFromValue((String) getInputParameter(HOSTNAME_VERIFIER_INPUT_PARAMETER));
    }

    protected final String getTrustStoreFile() {
        return (String) getInputParameter(TRUST_STORE_FILE_INPUT_PARAMETER);
    }

    protected final String getTrustStorePassword() {
        return (String) getInputParameter(TRUST_STORE_PASSWORD_INPUT_PARAMETER);
    }

    protected final String getKeyStoreFile() {
        return (String) getInputParameter(KEY_STORE_FILE_INPUT_PARAMETER);
    }

    protected final String getKeyStorePassword() {
        return (String) getInputParameter(KEY_STORE_PASSWORD_INPUT_PARAMETER);
    }

    protected final Boolean getDoNotFollowRedirect() {
        return (Boolean) getInputParameter(DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, Boolean.FALSE);
    }

    protected final Boolean getIgnoreBody() {
        return (Boolean) getInputParameter(IGNORE_BODY_INPUT_PARAMETER, Boolean.FALSE);
    }

    protected final Boolean getFailOnHttp5xx() {
        return (Boolean) getInputParameter(FAIL_ON_HTTP_5XX_INPUT_PARAMETER,Boolean.FALSE);
    }

    protected final Boolean getFailOnHttp4xx() {
        return (Boolean) getInputParameter(FAIL_ON_HTTP_4XX_INPUT_PARAMETER,Boolean.FALSE);
    }

    protected final List<String> getFailExceptionHttpCodes() {
        List<List<?>> exceptionCodes = (List<List<?>>) getInputParameter(FAILURE_EXCEPTIONS_HTTP_CODES_INPUT_PARAMETER);
        if (exceptionCodes == null) {
            return Collections.emptyList();
        }
        return exceptionCodes.stream()
                .map(code -> (String) code.get(0))
                .collect(Collectors.toList());
    }

    protected final Boolean getRetryOnHttp5xx() {
        return (Boolean) getInputParameter(RETRY_ON_HTTP_5XX_INPUT_PARAMETER, Boolean.FALSE);
    }

    protected final List<String> getRetryAdditionalHttpCodes() {
        List<List<?>> additionalCodes = (List<List<?>>) getInputParameter(RETRY_ADDITIONAL_HTTP_CODES_INPUT_PARAMETER);
        if (additionalCodes == null) {
            return Collections.emptyList();
        }
        return additionalCodes.stream()
                .map(code -> (String) code.get(0))
                .collect(Collectors.toList());
    }

    protected final Integer getMaximumBodyContentPrintedLogs() {
        return  (Integer) getInputParameter(MAXIMUM_BODY_CONTENT_PRINTED_LOGS_PARAMETER, 1000);
    }

    protected final Boolean getShowSensitiveHeadersInLogs() {
        return (Boolean) getInputParameter(SENSITIVE_HEADERS_PRINTED_LOGS_PARAMETER, Boolean.FALSE);
    }

    protected final String getAuthUsername() {
        return (String) getInputParameter(AUTH_USERNAME_INPUT_PARAMETER);
    }

    protected final String getAuthPassword() {
        return (String) getInputParameter(AUTH_PASSWORD_INPUT_PARAMETER);
    }

    protected final String getAuthHost() {
        return (String) getInputParameter(AUTH_HOST_INPUT_PARAMETER);
    }

    protected final Integer getAuthPort() {
        Integer port = (Integer) getInputParameter(AUTH_PORT_INPUT_PARAMETER);
        return port == null ? -1 : port;
    }

    protected final String getAuthRealm() {
        return (String) getInputParameter(AUTH_REALM_INPUT_PARAMETER);
    }

    protected final Boolean getAuthPreemptive() {
        return (Boolean) getInputParameter(AUTH_PREEMPTIVE_INPUT_PARAMETER, Boolean.TRUE);
    }

    protected final AuthorizationType getAuthType() {
        final String authType = (String) getInputParameter(AUTH_TYPE_PARAMETER);
        return authType != null ? AuthorizationType.fromString(authType) : AuthorizationType.NONE;
    }

    protected final String getOAuth2TokenEndpoint() {
        return (String) getInputParameter(OAUTH2_TOKEN_ENDPOINT_INPUT_PARAMETER);
    }

    protected final String getOAuth2ClientId() {
        return (String) getInputParameter(OAUTH2_CLIENT_ID_INPUT_PARAMETER);
    }

    protected final String getOAuth2ClientSecret() {
        return (String) getInputParameter(OAUTH2_CLIENT_SECRET_INPUT_PARAMETER);
    }

    protected final String getOAuth2Scope() {
        return (String) getInputParameter(OAUTH2_SCOPE_INPUT_PARAMETER);
    }

    protected final String getOAuth2Token() {
        return (String) getInputParameter(OAUTH2_TOKEN_INPUT_PARAMETER);
    }

    protected final String getOAuth2Code() {
        return (String) getInputParameter(OAUTH2_CODE_INPUT_PARAMETER);
    }

    protected final String getOAuth2CodeVerifier() {
        return (String) getInputParameter(OAUTH2_CODE_VERIFIER_INPUT_PARAMETER);
    }

    protected final String getOAuth2RedirectUri() {
        return (String) getInputParameter(OAUTH2_REDIRECT_URI_INPUT_PARAMETER);
    }

    protected final java.lang.String getProxyProtocol() {
        if (Boolean.TRUE.equals(getAutomaticProxyResolution())) {
            URI url = URI.create(getUrl());
            return url.isAbsolute() ? url.getScheme() : ProxyProtocol.HTTP.toString().toLowerCase();
        }
        return (String) getInputParameter(PROXY_PROTOCOL_INPUT_PARAMETER);
    }

    protected final String getProxyHost() {
        if (Boolean.TRUE.equals(getAutomaticProxyResolution())) {
            return ProxyUtils.hostName(URI.create(getUrl())).orElse(null);
        }
        return (String) getInputParameter(PROXY_HOST_INPUT_PARAMETER);
    }

    protected final Integer getProxyPort() {
        if (Boolean.TRUE.equals(getAutomaticProxyResolution())) {
            return ProxyUtils.port(URI.create(getUrl())).orElse(null);
        }
        return (Integer) getInputParameter(PROXY_PORT_INPUT_PARAMETER);
    }

    protected final String getProxyUsername() {
        return (String) getInputParameter(PROXY_USERNAME_INPUT_PARAMETER);
    }

    protected final String getProxyPassword() {
        return (String) getInputParameter(PROXY_PASSWORD_INPUT_PARAMETER);
    }

    protected final Integer getSocketTimeoutMs() {
        return (Integer) getInputParameter(SOCKET_TIMEOUT_MS_PARAMETER, SOCKET_TIMEOUT_MS_DEFAULT_VALUE);
    }

    protected final Integer getConnectionTimeoutMs() {
        return (Integer) getInputParameter(CONNECTION_TIMEOUT_MS_PARAMETER, CONNECTION_TIMEOUT_MS_DEFAULT_VALUE);
    }

    protected final Boolean getAutomaticProxyResolution() {
        return (Boolean) getInputParameter(AUTOMATIC_PROXY_RESOLUTION_PARAMETER, Boolean.FALSE);
    }

    protected void setBody(java.lang.String body) {
        setOutputParameter(BODY_AS_STRING_OUTPUT_PARAMETER, body);
    }

    protected void setBody(Object body) {
        setOutputParameter(BODY_AS_OBJECT_OUTPUT_PARAMETER, body);
    }

    protected void setHeaders(Map<String, String> headers) {
        setOutputParameter(HEADERS_OUTPUT_PARAMETER, headers);
    }

    protected void setStatusCode(Integer statusCode) {
        setOutputParameter(STATUS_CODE_OUTPUT_PARAMETER, statusCode);
    }

    protected void setStatusMessage(String statusMessage) {
        setOutputParameter(STATUS_MESSAGE_OUTPUT_PARAMETER, statusMessage);
    }

    @Override
    public void validateInputParameters() throws ConnectorValidationException {
        validateUrl();
        validateMethod();
        validateContentType();
        validateCharset();
        validateUrlCookies();
        validateUrlHeaders();
        validateAddBonitaContextHeaders();
        validateBonitaContextHeaders();
        validateBody();
        validateIgnoreBody();
        validateDoNotFollowRedirect();
        validateFailOnHttp5xx();
        validateFailOnHttp4xx();
        validateFailExceptionHttpCodes();
        validateRetryOnHttp5xx();
        validateRetryAdditionalHttpCodes();
        validateMaximumBodyContentPrintedLogs();
        validateShowSensitiveHeadersInLogs();
        validateTLS();
        validateTrustCertificateStrategyInput();
        validateHostnameVerifierInput();
        validateTrustStoreFile();
        validateTrustStorePassword();
        validateKeyStoreFile();
        validateKeyStorePassword();
        validateAuthUsername();
        validateAuthPassword();
        validateAuthHost();
        validateAuthPort();
        validateAuthRealm();
        validateAuthPreemptive();
        if (getAuthType() == AuthorizationType.OAUTH2_CLIENT_CREDENTIALS) {
            validateOAuth2TokenEndpoint();
            validateOAuth2ClientId();
            validateOAuth2ClientSecret();
            validateOAuth2Scope();
        } else if (getAuthType() == AuthorizationType.OAUTH2_BEARER) {
            validateOAuth2Token();
        } else if (getAuthType() == AuthorizationType.OAUTH2_AUTHORIZATION_CODE) {
            validateOAuth2TokenEndpoint();
            validateOAuth2ClientId();
            validateOAuth2ClientSecret();
            validateOAuth2Code();
            validateOAuth2CodeVerifier();
            validateOAuth2RedirectUri();
        }
        validateProxyProtocol();
        validateProxyHost();
        validateProxyPort();
        validateProxyUsername();
        validateProxyPassword();
        validateSocketTimeoutMs();
        validateConnectionTimeoutMs();
        validateAutomaticProxyResolution();
    }

    void validateConnectionTimeoutMs() throws ConnectorValidationException {
        try {
            getConnectionTimeoutMs();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException(CONNECTION_TIMEOUT_MS_PARAMETER + " type is invalid");
        }
    }

    void validateSocketTimeoutMs() throws ConnectorValidationException {
        try {
            getSocketTimeoutMs();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException(SOCKET_TIMEOUT_MS_PARAMETER + " type is invalid");
        }
    }

    void validateProxyPassword() throws ConnectorValidationException {
        try {
            getProxyPassword();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("proxy_password type is invalid");
        }
    }

    void validateProxyUsername() throws ConnectorValidationException {
        try {
            getProxyUsername();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("proxy_username type is invalid");
        }
    }

    void validateProxyPort() throws ConnectorValidationException {
        try {
            getProxyPort();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("proxy_port type is invalid");
        }
    }

    void validateProxyHost() throws ConnectorValidationException {
        try {
            getProxyHost();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("proxy_host type is invalid");
        }
    }

    void validateProxyProtocol() throws ConnectorValidationException {
        try {
            getProxyProtocol();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("proxy_protocol type is invalid");
        }
    }

    void validateAuthPreemptive() throws ConnectorValidationException {
        try {
            getAuthPreemptive();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("auth_basic_preemptive type is invalid");
        }
    }

    void validateAuthRealm() throws ConnectorValidationException {
        try {
            getAuthRealm();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("auth_basic_realm type is invalid");
        }
    }

    void validateAuthPort() throws ConnectorValidationException {
        try {
            getAuthPort();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("auth_basic_port type is invalid");
        }
    }

    void validateAuthHost() throws ConnectorValidationException {
        try {
            getAuthHost();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("auth_basic_host type is invalid");
        }
    }

    void validateAuthPassword() throws ConnectorValidationException {
        try {
            getAuthPassword();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("auth_basic_password type is invalid");
        }
    }

    void validateAuthUsername() throws ConnectorValidationException {
        try {
            getAuthUsername();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("auth_basic_username type is invalid");
        }
    }

    void validateKeyStorePassword() throws ConnectorValidationException {
        try {
            getKeyStorePassword();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("key_store_password type is invalid");
        }
    }

    void validateKeyStoreFile() throws ConnectorValidationException {
        try {
            getKeyStoreFile();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("key_store_file type is invalid");
        }
    }

    void validateTrustStorePassword() throws ConnectorValidationException {
        try {
            getTrustStorePassword();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("trust_store_password type is invalid");
        }
    }

    void validateTrustStoreFile() throws ConnectorValidationException {
        try {
            getTrustStoreFile();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("trust_store_file type is invalid");
        }
    }

    void validateTLS() throws ConnectorValidationException {
        try {
            getTLS();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("TLS type is invalid");
        }
    }

    void validateIgnoreBody() throws ConnectorValidationException {
        try {
            getIgnoreBody();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("ignore_body type is invalid");
        }
    }

    void validateDoNotFollowRedirect() throws ConnectorValidationException {
        try {
            getDoNotFollowRedirect();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("do_not_follow_redirect type is invalid");
        }
    }

    void validateBody() throws ConnectorValidationException {
        if (hasBody()) {
            try {
                getBody();
            } catch (final ClassCastException cce) {
                throw new ConnectorValidationException("body type is invalid");
            }
        }
    }

    void validateUrlHeaders() throws ConnectorValidationException {
        try {
            getUrlHeaders();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("urlHeaders type is invalid");
        }
    }

    void validateAddBonitaContextHeaders() throws ConnectorValidationException {
        try {
            getAddBonitaContextHeaders();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException(ADD_BONITA_CONTEXT_HEADERS_INPUT_PARAMETER + " type is invalid");
        }
    }

    void validateBonitaContextHeaders() throws ConnectorValidationException {
        try {
            getBonitaActivityInstanceIdHeader();
            getBonitaProcessInstanceIdHeader();
            getBonitaRootProcessInstanceIdHeader();
            getBonitaProcessDefinitionIdHeader();
            getBonitaTaskAssigneeIdHeader();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("one of bonita context headers type is invalid");
        }
    }

    void validateUrlCookies() throws ConnectorValidationException {
        try {
            getUrlCookies();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("urlCookies type is invalid");
        }
    }

    void validateCharset() throws ConnectorValidationException {
        try {
            getCharset();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("charset type is invalid");
        }
    }

    void validateContentType() throws ConnectorValidationException {
        try {
            getContentType();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("contentType type is invalid");
        }
    }

    void validateMethod() throws ConnectorValidationException {
        try {
            getMethod();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("method type is invalid");
        }
    }

    void validateUrl() throws ConnectorValidationException {
        try {
            getUrl();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("url type is invalid");
        }
    }

    void validateFailOnHttp5xx() throws ConnectorValidationException {
        try {
            getFailOnHttp5xx();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException(FAIL_ON_HTTP_5XX_INPUT_PARAMETER + " type is invalid");
        }
    }

    void validateFailOnHttp4xx() throws ConnectorValidationException {
        try {
            getFailOnHttp4xx();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException(FAIL_ON_HTTP_4XX_INPUT_PARAMETER + " type is invalid");
        }
    }

    void validateFailExceptionHttpCodes() throws ConnectorValidationException {
        try {
            for (String code : getFailExceptionHttpCodes()) {
                int statusCode = Integer.parseInt(code);
                if (statusCode < 400 || statusCode > 599) {
                    throw new ConnectorValidationException(FAILURE_EXCEPTIONS_HTTP_CODES_INPUT_PARAMETER + " type is invalid");
                }
            }
        } catch (final NumberFormatException|ClassCastException e) {
            throw new ConnectorValidationException(FAILURE_EXCEPTIONS_HTTP_CODES_INPUT_PARAMETER + " type is invalid");
        }
    }

    void validateRetryOnHttp5xx() throws ConnectorValidationException {
        try {
            getRetryOnHttp5xx();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException(RETRY_ON_HTTP_5XX_INPUT_PARAMETER + "type is invalid");
        }
    }

    void validateRetryAdditionalHttpCodes() throws ConnectorValidationException {
        try {
            for (String code : getRetryAdditionalHttpCodes()) {
                int statusCode = Integer.parseInt(code);
                if (statusCode < 400 || statusCode > 599) {
                    throw new ConnectorValidationException(RETRY_ADDITIONAL_HTTP_CODES_INPUT_PARAMETER + " type is invalid");
                }
            }
        } catch (final ConnectorValidationException e) {
            throw e;
        } catch (final NumberFormatException|ClassCastException e) {
            throw new ConnectorValidationException(RETRY_ADDITIONAL_HTTP_CODES_INPUT_PARAMETER + " type is invalid");
        }
    }

    void validateMaximumBodyContentPrintedLogs() throws ConnectorValidationException {
        try {
            Integer maxBodyContentPrintedLogs = getMaximumBodyContentPrintedLogs();
            if (Optional.ofNullable(maxBodyContentPrintedLogs).orElse(0) < 0) {
                throw new ConnectorValidationException(MAXIMUM_BODY_CONTENT_PRINTED_LOGS_PARAMETER + " must be a positive integer");
            }
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException(MAXIMUM_BODY_CONTENT_PRINTED_LOGS_PARAMETER + " type is invalid");
        }
    }

    void validateShowSensitiveHeadersInLogs() throws ConnectorValidationException {
        try {
            getShowSensitiveHeadersInLogs();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException(SENSITIVE_HEADERS_PRINTED_LOGS_PARAMETER + " type is invalid");
        }
    }

    void validateTrustCertificateStrategyInput() throws ConnectorValidationException {
        String trustParam = null;
        try {
            trustParam = (String) getInputParameter(TRUST_CERTIFICATE_STRATEGY_INPUT_PARAMETER);
            if (trustParam != null && !trustParam.trim().isEmpty()) {
                TrustCertificateStrategy.valueOf(trustParam);
            }
        } catch (ClassCastException cce) {
            throw new ConnectorValidationException(
                    String.format("%s type is invalid", TRUST_CERTIFICATE_STRATEGY_INPUT_PARAMETER));
        } catch (IllegalArgumentException e) {
            throw new ConnectorValidationException(
                    String.format(
                            "'%s' option is invalid for %s. Only one of %s is supported.",
                            trustParam,
                            TRUST_CERTIFICATE_STRATEGY_INPUT_PARAMETER,
                            Arrays.toString(TrustCertificateStrategy.values())));
        }
    }

    void validateHostnameVerifierInput() throws ConnectorValidationException {
        try {
            var hostNameVerifierParam = (String) getInputParameter(HOSTNAME_VERIFIER_INPUT_PARAMETER);
            SSLVerifier.getSSLVerifierFromValue(hostNameVerifierParam);
        } catch (ClassCastException cce) {
            throw new ConnectorValidationException(
                    String.format("%s type is invalid", HOSTNAME_VERIFIER_INPUT_PARAMETER));
        }
    }

    void validateAutomaticProxyResolution() throws ConnectorValidationException {
        try {
            getAutomaticProxyResolution();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException(AUTOMATIC_PROXY_RESOLUTION_PARAMETER + " type is invalid");
        }
    }

    void validateOAuth2TokenEndpoint() throws ConnectorValidationException {
        try {
            String tokenEndpoint = getOAuth2TokenEndpoint();
            if (tokenEndpoint == null || tokenEndpoint.trim().isEmpty()) {
                throw new ConnectorValidationException(OAUTH2_TOKEN_ENDPOINT_INPUT_PARAMETER + " is required for OAuth2 Client Credentials");
            }
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException(OAUTH2_TOKEN_ENDPOINT_INPUT_PARAMETER + " type is invalid");
        }
    }

    void validateOAuth2ClientId() throws ConnectorValidationException {
        try {
            String clientId = getOAuth2ClientId();
            if (clientId == null || clientId.trim().isEmpty()) {
                throw new ConnectorValidationException(OAUTH2_CLIENT_ID_INPUT_PARAMETER + " is required for OAuth2 Client Credentials");
            }
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException(OAUTH2_CLIENT_ID_INPUT_PARAMETER + " type is invalid");
        }
    }

    void validateOAuth2ClientSecret() throws ConnectorValidationException {
        try {
            String clientSecret = getOAuth2ClientSecret();

            // Client secret is required only for Client Credentials flow
            // For Authorization Code flow, it's optional (supports PKCE public clients)
            if (getAuthType() == AuthorizationType.OAUTH2_CLIENT_CREDENTIALS) {
                if (clientSecret == null || clientSecret.trim().isEmpty()) {
                    throw new ConnectorValidationException(OAUTH2_CLIENT_SECRET_INPUT_PARAMETER + " is required for OAuth2 Client Credentials");
                }
            }
            // For other OAuth2 flows, client secret is optional - no validation needed
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException(OAUTH2_CLIENT_SECRET_INPUT_PARAMETER + " type is invalid");
        }
    }

    void validateOAuth2Scope() throws ConnectorValidationException {
        try {
            getOAuth2Scope();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException(OAUTH2_SCOPE_INPUT_PARAMETER + " type is invalid");
        }
    }

    void validateOAuth2Token() throws ConnectorValidationException {
        try {
            String token = getOAuth2Token();
            if (token == null || token.trim().isEmpty()) {
                throw new ConnectorValidationException(OAUTH2_TOKEN_INPUT_PARAMETER + " is required for OAuth2 Bearer");
            }
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException(OAUTH2_TOKEN_INPUT_PARAMETER + " type is invalid");
        }
    }

    void validateOAuth2Code() throws ConnectorValidationException {
        try {
            String code = getOAuth2Code();
            if (code == null || code.trim().isEmpty()) {
                throw new ConnectorValidationException(
                    OAUTH2_CODE_INPUT_PARAMETER + " is required for OAuth2 Authorization Code");
            }
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException(
                OAUTH2_CODE_INPUT_PARAMETER + " type is invalid");
        }
    }

    void validateOAuth2CodeVerifier() throws ConnectorValidationException {
        try {
            // Code verifier is optional (PKCE is not mandatory) - just validate type
            getOAuth2CodeVerifier();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException(
                OAUTH2_CODE_VERIFIER_INPUT_PARAMETER + " type is invalid");
        }
    }

    void validateOAuth2RedirectUri() throws ConnectorValidationException {
        try {
            // Redirect URI is optional - just validate type
            getOAuth2RedirectUri();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException(
                OAUTH2_REDIRECT_URI_INPUT_PARAMETER + " type is invalid");
        }
    }

    public abstract boolean hasBody();
}
