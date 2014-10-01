package org.bonitasoft.connectors.rest;

import org.bonitasoft.engine.connector.AbstractConnector;
import org.bonitasoft.engine.connector.ConnectorValidationException;

public abstract class AbstractRESTConnector extends AbstractConnector {

	protected final static String URL_INPUT_PARAMETER = "url";
	protected final static String METHOD_INPUT_PARAMETER = "method";
	protected final static String CONTENTTYPE_INPUT_PARAMETER = "contentType";
	protected final static String CHARSET_INPUT_PARAMETER = "charset";
	protected final static String URLCOOKIES_INPUT_PARAMETER = "urlCookies";
	protected final static String URLHEADERS_INPUT_PARAMETER = "urlHeaders";
	protected final static String BODY_INPUT_PARAMETER = "body";
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

	}

}
