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
	protected final static String AUTH_BASIC_USERNAME_INPUT_PARAMETER = "auth_basic_username";
	protected final static String AUTH_BASIC_PASSWORD_INPUT_PARAMETER = "auth_basic_password";
	protected final static String AUTH_BASIC_HOST_INPUT_PARAMETER = "auth_basic_host";
	protected final static String AUTH_BASIC_REALM_INPUT_PARAMETER = "auth_basic_realm";
	protected final static String AUTH_BASIC_PREEMPTIVE_INPUT_PARAMETER = "auth_basic_preemptive";
	protected final static String AUTH_DIGEST_USERNAME_INPUT_PARAMETER = "auth_digest_username";
	protected final static String AUTH_DIGEST_PASSWORD_INPUT_PARAMETER = "auth_digest_password";
	protected final static String AUTH_DIGEST_HOST_INPUT_PARAMETER = "auth_digest_host";
	protected final static String AUTH_DIGEST_REALM_INPUT_PARAMETER = "auth_digest_realm";
	protected final static String AUTH_DIGEST_PREEMPTIVE_INPUT_PARAMETER = "auth_digest_preemptive";
	protected final static String AUTH_NTLM_USERNAME_INPUT_PARAMETER = "auth_NTLM_username";
	protected final static String AUTH_NTLM_PASSWORD_INPUT_PARAMETER = "auth_NTLM_password";
	protected final static String AUTH_NTLM_WORKSTATION_INPUT_PARAMETER = "auth_NTLM_workstation";
	protected final static String AUTH_NTLM_DOMAIN_INPUT_PARAMETER = "auth_NTLM_domain";
	protected final static String AUTH_OAUTH2_BEARER_TOKEN_INPUT_PARAMETER = "auth_OAuth2_bearer_token";
	protected final String RESULT_OUTPUT_PARAMETER = "result";

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

	protected final void setResult(org.bonitasoft.connectors.rest.RESTResult result) {
		setOutputParameter(RESULT_OUTPUT_PARAMETER, result);
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
			getAuth_basic_username();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException(
					"auth_basic_username type is invalid");
		}
		try {
			getAuth_basic_password();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException(
					"auth_basic_password type is invalid");
		}
		try {
			getAuth_basic_host();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException(
					"auth_basic_host type is invalid");
		}
		try {
			getAuth_basic_realm();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException(
					"auth_basic_realm type is invalid");
		}
		try {
			getAuth_basic_preemptive();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException(
					"auth_basic_preemptive type is invalid");
		}
		try {
			getAuth_digest_username();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException(
					"auth_digest_username type is invalid");
		}
		try {
			getAuth_digest_password();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException(
					"auth_digest_password type is invalid");
		}
		try {
			getAuth_digest_host();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException(
					"auth_digest_host type is invalid");
		}
		try {
			getAuth_digest_realm();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException(
					"auth_digest_realm type is invalid");
		}
		try {
			getAuth_digest_preemptive();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException(
					"auth_digest_preemptive type is invalid");
		}
		try {
			getAuth_NTLM_username();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException(
					"auth_NTLM_username type is invalid");
		}
		try {
			getAuth_NTLM_password();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException(
					"auth_NTLM_password type is invalid");
		}
		try {
			getAuth_NTLM_workstation();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException(
					"auth_NTLM_workstation type is invalid");
		}
		try {
			getAuth_NTLM_domain();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException(
					"auth_NTLM_domain type is invalid");
		}
		try {
			getAuth_OAuth2_bearer_token();
		} catch (ClassCastException cce) {
			throw new ConnectorValidationException(
					"auth_OAuth2_bearer_token type is invalid");
		}

	}

}
