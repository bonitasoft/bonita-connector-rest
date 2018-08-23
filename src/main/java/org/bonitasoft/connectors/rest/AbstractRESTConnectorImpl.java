/**
 * Copyright (C) 2014 BonitaSoft S.A.
 * BonitaSoft, 32 rue Gustave Eiffel - 38000 Grenoble
 * This library is free software; you can redistribute it and/or modify it under the terms
 * of the GNU Lesser General Public License as published by the Free Software Foundation
 * version 2.1 of the License.
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 * You should have received a copy of the GNU Lesser General Public License along with this
 * program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA.
 **/

package org.bonitasoft.connectors.rest;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.bonitasoft.connectors.rest.model.AuthorizationType;
import org.bonitasoft.engine.connector.AbstractConnector;
import org.bonitasoft.engine.connector.ConnectorValidationException;

import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;

public abstract class AbstractRESTConnectorImpl extends AbstractConnector {

    protected final static String URL_INPUT_PARAMETER = "url";
    protected final static String METHOD_INPUT_PARAMETER = "method";
    protected final static String CONTENTTYPE_INPUT_PARAMETER = "contentType";
    protected final static String CHARSET_INPUT_PARAMETER = "charset";
    protected final static String URLCOOKIES_INPUT_PARAMETER = "urlCookies";
    protected final static String URLHEADERS_INPUT_PARAMETER = "urlHeaders";
    protected final static String BODY_INPUT_PARAMETER = "body";
    protected final static String DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER = "do_not_follow_redirect";
    protected final static String IGNORE_BODY_INPUT_PARAMETER = "ignore_body";
    protected final static String TRUST_SELF_SIGNED_CERTIFICATE_INPUT_PARAMETER = "trust_self_signed_certificate";
    protected final static String TLS_INPUT_PARAMETER = "TLS";
    protected final static String HOSTNAME_VERIFIER_INPUT_PARAMETER = "hostname_verifier";
    protected final static String TRUST_STORE_FILE_INPUT_PARAMETER = "trust_store_file";
    protected final static String TRUST_STORE_PASSWORD_INPUT_PARAMETER = "trust_store_password";
    protected final static String KEY_STORE_FILE_INPUT_PARAMETER = "key_store_file";
    protected final static String KEY_STORE_PASSWORD_INPUT_PARAMETER = "key_store_password";
    protected final static String AUTH_TYPE_PARAMETER = "auth_type";
    protected final static String AUTH_USERNAME_INPUT_PARAMETER = "auth_username";
    protected final static String AUTH_PASSWORD_INPUT_PARAMETER = "auth_password";
    protected final static String AUTH_HOST_INPUT_PARAMETER = "auth_host";
    protected final static String AUTH_PORT_INPUT_PARAMETER = "auth_port";
    protected final static String AUTH_REALM_INPUT_PARAMETER = "auth_realm";
    protected final static String AUTH_PREEMPTIVE_INPUT_PARAMETER = "auth_preemptive";
    protected final static String PROXY_PROTOCOL_INPUT_PARAMETER = "proxy_protocol";
    protected final static String PROXY_HOST_INPUT_PARAMETER = "proxy_host";
    protected final static String PROXY_PORT_INPUT_PARAMETER = "proxy_port";
    protected final static String PROXY_USERNAME_INPUT_PARAMETER = "proxy_username";
    protected final static String PROXY_PASSWORD_INPUT_PARAMETER = "proxy_password";
    protected final static String BODY_AS_STRING_OUTPUT_PARAMETER = "bodyAsString";
    protected final static String BODY_AS_OBJECT_OUTPUT_PARAMETER = "bodyAsObject";
    protected final static String HEADERS_OUTPUT_PARAMETER = "headers";
    protected final static String STATUS_CODE_OUTPUT_PARAMETER = "status_code";
    protected final static String STATUS_MESSAGE_OUTPUT_PARAMETER = "status_message";
    protected final static String SOCKET_TIMEOUT_MS_PARAMETER = "socket_timeout_ms";
    protected final static String CONNECTION_TIMEOUT_MS_PARAMETER = "connection_timeout_ms";

    protected final java.lang.String getUrl() {
        return (java.lang.String) getInputParameter(URL_INPUT_PARAMETER);
    }

    protected java.lang.String getMethod() {
        return (java.lang.String) getInputParameter(METHOD_INPUT_PARAMETER);
    }

    protected final java.lang.String getContentType() {
        return (java.lang.String) getInputParameter(CONTENTTYPE_INPUT_PARAMETER);
    }

    protected final java.lang.String getCharset() {
        return (java.lang.String) getInputParameter(CHARSET_INPUT_PARAMETER);
    }

    protected final java.util.List getUrlCookies() {
        java.util.List cookies = (java.util.List) getInputParameter(URLCOOKIES_INPUT_PARAMETER);
        if (cookies == null) {
            cookies = Collections.emptyList();
        }
        Iterables.removeIf(cookies, emptyLines());
        return cookies;
    }

    private Predicate<Object> emptyLines() {
        return new Predicate<Object>() {

            @Override
            public boolean apply(Object input) {
                if (input instanceof List) {
                    final List line = (List) input;
                    return line.size() != 2 || (emptyCell(line, 0) && emptyCell(line, 1));
                }
                return true;
            }

            private boolean emptyCell(final List line, int cellIndex) {
                final Object cellValue = line.get(cellIndex);
                return cellValue == null || cellValue.toString().trim().isEmpty();
            }
        };
    }

    protected final java.util.List getUrlHeaders() {
        java.util.List headers = (java.util.List) getInputParameter(URLHEADERS_INPUT_PARAMETER);
        if (headers == null) {
            headers = Collections.emptyList();
        }
        Iterables.removeIf(headers, emptyLines());
        return headers;
    }

    protected final java.lang.String getBody() {
        return (java.lang.String) getInputParameter(BODY_INPUT_PARAMETER);
    }

    protected final java.lang.Boolean getTLS() {
        final java.lang.Boolean tlsParam = (java.lang.Boolean) getInputParameter(TLS_INPUT_PARAMETER);
        return tlsParam != null ? tlsParam : Boolean.TRUE;
    }

    protected final java.lang.Boolean getTrust_self_signed_certificate() {
        final java.lang.Boolean trustParam = (java.lang.Boolean) getInputParameter(TRUST_SELF_SIGNED_CERTIFICATE_INPUT_PARAMETER);
        return trustParam != null ? trustParam : Boolean.FALSE;
    }

    protected final java.lang.String getHostname_verifier() {
        return (java.lang.String) getInputParameter(HOSTNAME_VERIFIER_INPUT_PARAMETER);
    }

    protected final java.lang.String getTrust_store_file() {
        return (java.lang.String) getInputParameter(TRUST_STORE_FILE_INPUT_PARAMETER);
    }

    protected final java.lang.String getTrust_store_password() {
        return (java.lang.String) getInputParameter(TRUST_STORE_PASSWORD_INPUT_PARAMETER);
    }

    protected final java.lang.String getKey_store_file() {
        return (java.lang.String) getInputParameter(KEY_STORE_FILE_INPUT_PARAMETER);
    }

    protected final java.lang.String getKey_store_password() {
        return (java.lang.String) getInputParameter(KEY_STORE_PASSWORD_INPUT_PARAMETER);
    }

    protected final java.lang.Boolean getDoNotFollowRedirect() {
        final java.lang.Boolean follozRedirect = (java.lang.Boolean) getInputParameter(DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER);
        return follozRedirect != null ? follozRedirect : Boolean.FALSE;
    }

    protected final java.lang.Boolean getIgnoreBody() {
        final java.lang.Boolean ignoreBody = (java.lang.Boolean) getInputParameter(IGNORE_BODY_INPUT_PARAMETER);
        return ignoreBody != null ? ignoreBody : Boolean.FALSE ;
    }

    protected final java.lang.String getAuth_username() {
        return (java.lang.String) getInputParameter(AUTH_USERNAME_INPUT_PARAMETER);
    }

    protected final java.lang.String getAuth_password() {
        return (java.lang.String) getInputParameter(AUTH_PASSWORD_INPUT_PARAMETER);
    }

    protected final java.lang.String getAuth_host() {
        return (java.lang.String) getInputParameter(AUTH_HOST_INPUT_PARAMETER);
    }

    protected final java.lang.Integer getAuth_port() {
        return (java.lang.Integer) getInputParameter(AUTH_PORT_INPUT_PARAMETER);
    }

    protected final java.lang.String getAuth_realm() {
        return (java.lang.String) getInputParameter(AUTH_REALM_INPUT_PARAMETER);
    }

    protected final java.lang.Boolean getAuth_preemptive() {
        final java.lang.Boolean preemptive = (java.lang.Boolean) getInputParameter(AUTH_PREEMPTIVE_INPUT_PARAMETER);
        return preemptive != null ? preemptive : Boolean.TRUE;
    }

    protected final AuthorizationType getAuth_type() {
        final String authType = (String) getInputParameter(AUTH_TYPE_PARAMETER);
        return authType != null ? AuthorizationType.valueOf(authType) : AuthorizationType.NONE;
    }

    protected final java.lang.String getProxy_protocol() {
        return (java.lang.String) getInputParameter(PROXY_PROTOCOL_INPUT_PARAMETER);
    }

    protected final java.lang.String getProxy_host() {
        return (java.lang.String) getInputParameter(PROXY_HOST_INPUT_PARAMETER);
    }

    protected final java.lang.Integer getProxy_port() {
        return (java.lang.Integer) getInputParameter(PROXY_PORT_INPUT_PARAMETER);
    }

    protected final java.lang.String getProxy_username() {
        return (java.lang.String) getInputParameter(PROXY_USERNAME_INPUT_PARAMETER);
    }

    protected final java.lang.String getProxy_password() {
        return (java.lang.String) getInputParameter(PROXY_PASSWORD_INPUT_PARAMETER);
    }

    protected final Integer getSocketTimeoutMs() {
        return (Integer) getInputParameter(SOCKET_TIMEOUT_MS_PARAMETER);
    }

    protected final Integer getConnectionTimeoutMs() {
        return (Integer) getInputParameter(CONNECTION_TIMEOUT_MS_PARAMETER);
    }

    protected final void setBody(java.lang.String body) {
        setOutputParameter(BODY_AS_STRING_OUTPUT_PARAMETER, body);
    }

    protected final void setBody(Object body) {
        setOutputParameter(BODY_AS_OBJECT_OUTPUT_PARAMETER, body);
    }

    protected final void setHeaders(Map<String, String> headers) {
        setOutputParameter(HEADERS_OUTPUT_PARAMETER, headers);
    }

    protected final void setStatusCode(java.lang.Integer statusCode) {
        setOutputParameter(STATUS_CODE_OUTPUT_PARAMETER, statusCode);
    }

    protected final void setStatusMessage(java.lang.String statusMessage) {
        setOutputParameter(STATUS_MESSAGE_OUTPUT_PARAMETER, statusMessage);
    }

    @Override
    public void validateInputParameters() throws ConnectorValidationException {
        try {
            getUrl();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("url type is invalid");
        }
        try {
            getMethod();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("method type is invalid");
        }
        try {
            getContentType();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException(
                    "contentType type is invalid");
        }
        try {
            getCharset();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("charset type is invalid");
        }
        try {
            getUrlCookies();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("urlCookies type is invalid");
        }
        try {
            getUrlHeaders();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("urlHeaders type is invalid");
        }
        try {
            getBody();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("body type is invalid");
        }
        try {
            getDoNotFollowRedirect();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("do_not_follow_redirect type is invalid");
        }
        try {
            getIgnoreBody();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("ignore_body type is invalid");
        }
        try {
            getTLS();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("TLS type is invalid");
        }
        try {
            getTrust_self_signed_certificate();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("trust_self_signed_certificate type is invalid");
        }
        try {
            getHostname_verifier();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("hostname_verifier type is invalid");
        }
        try {
            getTrust_store_file();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("trust_store_file type is invalid");
        }
        try {
            getTrust_store_password();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("trust_store_password type is invalid");
        }
        try {
            getKey_store_file();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("key_store_file type is invalid");
        }
        try {
            getKey_store_password();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("key_store_password type is invalid");
        }
        try {
            getAuth_username();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("auth_basic_username type is invalid");
        }
        try {
            getAuth_password();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("auth_basic_password type is invalid");
        }
        try {
            getAuth_host();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("auth_basic_host type is invalid");
        }
        try {
            getAuth_port();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("auth_basic_port type is invalid");
        }
        try {
            getAuth_realm();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("auth_basic_realm type is invalid");
        }
        try {
            getAuth_preemptive();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("auth_basic_preemptive type is invalid");
        }
        try {
            getProxy_protocol();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("proxy_protocol type is invalid");
        }
        try {
            getProxy_host();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("proxy_host type is invalid");
        }
        try {
            getProxy_port();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("proxy_port type is invalid");
        }
        try {
            getProxy_username();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("proxy_username type is invalid");
        }
        try {
            getProxy_password();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException("proxy_password type is invalid");
        }
        try {
            getSocketTimeoutMs();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException(SOCKET_TIMEOUT_MS_PARAMETER + " type is invalid");
        }
        try {
            getConnectionTimeoutMs();
        } catch (final ClassCastException cce) {
            throw new ConnectorValidationException(CONNECTION_TIMEOUT_MS_PARAMETER + " type is invalid");
        }
    }
}
