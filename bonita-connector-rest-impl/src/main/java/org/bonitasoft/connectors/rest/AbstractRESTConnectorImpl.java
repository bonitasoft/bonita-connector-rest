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

import org.bonitasoft.engine.connector.AbstractConnector;
import org.bonitasoft.engine.connector.ConnectorValidationException;

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
	protected final static String AUTH_BASIC_USERNAME_INPUT_PARAMETER = "auth_basic_username";
	protected final static String AUTH_BASIC_PASSWORD_INPUT_PARAMETER = "auth_basic_password";
	protected final static String AUTH_BASIC_HOST_INPUT_PARAMETER = "auth_basic_host";
	protected final static String AUTH_BASIC_PORT_INPUT_PARAMETER = "auth_basic_port";
	protected final static String AUTH_BASIC_REALM_INPUT_PARAMETER = "auth_basic_realm";
	protected final static String AUTH_BASIC_PREEMPTIVE_INPUT_PARAMETER = "auth_basic_preemptive";
	protected final static String AUTH_DIGEST_USERNAME_INPUT_PARAMETER = "auth_digest_username";
	protected final static String AUTH_DIGEST_PASSWORD_INPUT_PARAMETER = "auth_digest_password";
	protected final static String AUTH_DIGEST_HOST_INPUT_PARAMETER = "auth_digest_host";
	protected final static String AUTH_DIGEST_PORT_INPUT_PARAMETER = "auth_digest_port";
	protected final static String AUTH_DIGEST_REALM_INPUT_PARAMETER = "auth_digest_realm";
	protected final static String AUTH_DIGEST_PREEMPTIVE_INPUT_PARAMETER = "auth_digest_preemptive";
	protected final static String AUTH_NTLM_USERNAME_INPUT_PARAMETER = "auth_NTLM_username";
	protected final static String AUTH_NTLM_PASSWORD_INPUT_PARAMETER = "auth_NTLM_password";
	protected final static String AUTH_NTLM_WORKSTATION_INPUT_PARAMETER = "auth_NTLM_workstation";
	protected final static String AUTH_NTLM_DOMAIN_INPUT_PARAMETER = "auth_NTLM_domain";
	protected final static String AUTH_OAUTH2_BEARER_TOKEN_INPUT_PARAMETER = "auth_OAuth2_bearer_token";
	protected final static String PROXY_PROTOCOL_INPUT_PARAMETER = "proxy_protocol";
	protected final static String PROXY_HOST_INPUT_PARAMETER = "proxy_host";
	protected final static String PROXY_PORT_INPUT_PARAMETER = "proxy_port";
	protected final static String PROXY_USERNAME_INPUT_PARAMETER = "proxy_username";
	protected final static String PROXY_PASSWORD_INPUT_PARAMETER = "proxy_password";
	protected final static String BODY_OUTPUT_PARAMETER = "body";
	protected final static String HEADERS_OUTPUT_PARAMETER = "headers";
	protected final static String STATUS_CODE_OUTPUT_PARAMETER = "status_code";
	protected final static String STATUS_MESSAGE_OUTPUT_PARAMETER = "status_message";

	protected final java.lang.String getUrl() {
		return (java.lang.String) getInputParameter(URL_INPUT_PARAMETER);
	}

	protected final java.lang.String getMethod() {
		return (java.lang.String) getInputParameter(METHOD_INPUT_PARAMETER);
	}

	protected final java.lang.String getContentType() {
		return (java.lang.String) getInputParameter(CONTENTTYPE_INPUT_PARAMETER);
	}

	protected final java.lang.String getCharset() {
		return (java.lang.String) getInputParameter(CHARSET_INPUT_PARAMETER);
	}

	protected final java.util.List getUrlCookies() {
		return (java.util.List) getInputParameter(URLCOOKIES_INPUT_PARAMETER);
	}

	protected final java.util.List getUrlHeaders() {
		return (java.util.List) getInputParameter(URLHEADERS_INPUT_PARAMETER);
	}

	protected final java.lang.String getBody() {
		return (java.lang.String) getInputParameter(BODY_INPUT_PARAMETER);
	}

	protected final java.lang.Boolean getTLS() {
		return (java.lang.Boolean) getInputParameter(TLS_INPUT_PARAMETER);
	}

	protected final java.lang.Boolean getTrust_self_signed_certificate() {
		return (java.lang.Boolean) getInputParameter(TRUST_SELF_SIGNED_CERTIFICATE_INPUT_PARAMETER);
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
		return (java.lang.Boolean) getInputParameter(DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER);
	}

	protected final java.lang.Boolean getIgnoreBody() {
		return (java.lang.Boolean) getInputParameter(IGNORE_BODY_INPUT_PARAMETER);
	}

	protected final java.lang.String getAuth_basic_username() {
		return (java.lang.String) getInputParameter(AUTH_BASIC_USERNAME_INPUT_PARAMETER);
	}

	protected final java.lang.String getAuth_basic_password() {
		return (java.lang.String) getInputParameter(AUTH_BASIC_PASSWORD_INPUT_PARAMETER);
	}

	protected final java.lang.String getAuth_basic_host() {
		return (java.lang.String) getInputParameter(AUTH_BASIC_HOST_INPUT_PARAMETER);
	}

	protected final java.lang.String getAuth_basic_port() {
		return (java.lang.String) getInputParameter(AUTH_BASIC_PORT_INPUT_PARAMETER);
	}

	protected final java.lang.String getAuth_basic_realm() {
		return (java.lang.String) getInputParameter(AUTH_BASIC_REALM_INPUT_PARAMETER);
	}

	protected final java.lang.Boolean getAuth_basic_preemptive() {
		return (java.lang.Boolean) getInputParameter(AUTH_BASIC_PREEMPTIVE_INPUT_PARAMETER);
	}

	protected final java.lang.String getAuth_digest_username() {
		return (java.lang.String) getInputParameter(AUTH_DIGEST_USERNAME_INPUT_PARAMETER);
	}

	protected final java.lang.String getAuth_digest_password() {
		return (java.lang.String) getInputParameter(AUTH_DIGEST_PASSWORD_INPUT_PARAMETER);
	}

	protected final java.lang.String getAuth_digest_host() {
		return (java.lang.String) getInputParameter(AUTH_DIGEST_HOST_INPUT_PARAMETER);
	}

	protected final java.lang.String getAuth_digest_port() {
		return (java.lang.String) getInputParameter(AUTH_DIGEST_PORT_INPUT_PARAMETER);
	}

	protected final java.lang.String getAuth_digest_realm() {
		return (java.lang.String) getInputParameter(AUTH_DIGEST_REALM_INPUT_PARAMETER);
	}

	protected final java.lang.Boolean getAuth_digest_preemptive() {
		return (java.lang.Boolean) getInputParameter(AUTH_DIGEST_PREEMPTIVE_INPUT_PARAMETER);
	}

	protected final java.lang.String getAuth_NTLM_username() {
		return (java.lang.String) getInputParameter(AUTH_NTLM_USERNAME_INPUT_PARAMETER);
	}

	protected final java.lang.String getAuth_NTLM_password() {
		return (java.lang.String) getInputParameter(AUTH_NTLM_PASSWORD_INPUT_PARAMETER);
	}

	protected final java.lang.String getAuth_NTLM_workstation() {
		return (java.lang.String) getInputParameter(AUTH_NTLM_WORKSTATION_INPUT_PARAMETER);
	}

	protected final java.lang.String getAuth_NTLM_domain() {
		return (java.lang.String) getInputParameter(AUTH_NTLM_DOMAIN_INPUT_PARAMETER);
	}

	protected final java.lang.String getAuth_OAuth2_bearer_token() {
		return (java.lang.String) getInputParameter(AUTH_OAUTH2_BEARER_TOKEN_INPUT_PARAMETER);
	}

	protected final java.lang.String getProxy_protocol() {
		return (java.lang.String) getInputParameter(PROXY_PROTOCOL_INPUT_PARAMETER);
	}

	protected final java.lang.String getProxy_host() {
		return (java.lang.String) getInputParameter(PROXY_HOST_INPUT_PARAMETER);
	}

	protected final java.lang.String getProxy_port() {
		return (java.lang.String) getInputParameter(PROXY_PORT_INPUT_PARAMETER);
	}

	protected final java.lang.String getProxy_username() {
		return (java.lang.String) getInputParameter(PROXY_USERNAME_INPUT_PARAMETER);
	}

	protected final java.lang.String getProxy_password() {
		return (java.lang.String) getInputParameter(PROXY_PASSWORD_INPUT_PARAMETER);
	}

	protected final void setBody(java.lang.String body) {
		setOutputParameter(BODY_OUTPUT_PARAMETER, body);
	}
	
	protected final void setHeaders(java.util.List headers) {
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
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("url type is invalid");
		}
		try {
			getMethod();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("method type is invalid");
		}
		try {
			getContentType();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException(
					"contentType type is invalid");
		}
		try {
			getCharset();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("charset type is invalid");
		}
		try {
			getUrlCookies();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("urlCookies type is invalid");
		}
		try {
			getUrlHeaders();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("urlHeaders type is invalid");
		}
		try {
			getBody();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("body type is invalid");
		}
		try {
			getDoNotFollowRedirect();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("do_not_follow_redirect type is invalid");
		}
		try {
			getIgnoreBody();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("ignore_body type is invalid");
		}
		try {
			getTLS();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("TLS type is invalid");
		}
		try {
			getTrust_self_signed_certificate();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("trust_self_signed_certificate type is invalid");
		}
		try {
			getHostname_verifier();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("hostname_verifier type is invalid");
		}
		try {
			getTrust_store_file();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("trust_store_file type is invalid");
		}
		try {
			getTrust_store_password();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("trust_store_password type is invalid");
		}
		try {
			getKey_store_file();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("key_store_file type is invalid");
		}
		try {
			getKey_store_password();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("key_store_password type is invalid");
		}
		try {
			getAuth_basic_username();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("auth_basic_username type is invalid");
		}
		try {
			getAuth_basic_password();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("auth_basic_password type is invalid");
		}
		try {
			getAuth_basic_host();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("auth_basic_host type is invalid");
		}
		try {
			String authBasicPortValue = getAuth_basic_port();
			if(authBasicPortValue != null && !authBasicPortValue.isEmpty()) {
				Integer.parseInt(authBasicPortValue);
			}
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("auth_basic_port type is invalid");
		} catch (NumberFormatException nfe) {
			throw new ConnectorValidationException("auth_basic_port is not a valid number");
		}
		try {
			getAuth_basic_realm();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("auth_basic_realm type is invalid");
		}
		try {
			getAuth_basic_preemptive();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("auth_basic_preemptive type is invalid");
		}
		try {
			getAuth_digest_username();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("auth_digest_username type is invalid");
		}
		try {
			getAuth_digest_password();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("auth_digest_password type is invalid");
		}
		try {
			getAuth_digest_host();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("auth_digest_host type is invalid");
		}
		try {
			String authDigestPortValue = getAuth_digest_port();
			if(authDigestPortValue != null && !authDigestPortValue.isEmpty()) {
				Integer.parseInt(authDigestPortValue);
			}
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("auth_digest_port type is invalid");
		} catch (NumberFormatException nfe) {
			throw new ConnectorValidationException("auth_digest_port is not a valid number");
		}
		try {
			getAuth_digest_realm();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("auth_digest_realm type is invalid");
		}
		try {
			getAuth_digest_preemptive();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("auth_digest_preemptive type is invalid");
		}
		try {
			getAuth_NTLM_username();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("auth_NTLM_username type is invalid");
		}
		try {
			getAuth_NTLM_password();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("auth_NTLM_password type is invalid");
		}
		try {
			getAuth_NTLM_workstation();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("auth_NTLM_workstation type is invalid");
		}
		try {
			getAuth_NTLM_domain();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("auth_NTLM_domain type is invalid");
		}
		try {
			getAuth_OAuth2_bearer_token();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("auth_OAuth2_bearer_token type is invalid");
		}
		try {
			getProxy_protocol();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("proxy_protocol type is invalid");
		}
		try {
			getProxy_host();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("proxy_host type is invalid");
		}
		try {
			String portValue = getProxy_port();
			if(portValue != null && !portValue.isEmpty()) {
				Integer.parseInt(portValue);
			}
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("proxy_port type is invalid");
		} catch (NumberFormatException nfe) {
			throw new ConnectorValidationException("proxy_port is not a valid number");
		}
		try {
			getProxy_username();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("proxy_username type is invalid");
		}
		try {
			getProxy_password();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException("proxy_password type is invalid");
		}
	}
}
