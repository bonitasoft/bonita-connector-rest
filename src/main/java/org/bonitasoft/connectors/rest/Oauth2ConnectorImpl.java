package org.bonitasoft.connectors.rest;

import org.apache.http.HttpResponse;
import org.bonitasoft.connectors.rest.model.*;
import org.bonitasoft.engine.commons.exceptions.SRetryableException;
import org.bonitasoft.engine.connector.ConnectorException;
import org.bonitasoft.engine.connector.ConnectorValidationException;

import java.io.IOException;
import java.util.logging.Logger;

public class Oauth2ConnectorImpl extends RESTConnector {

    protected static final String OAUTH2_TOKEN_OUTPUT_PARAMETER = "token";

    /** The class logger */
    private static final Logger LOGGER = Logger.getLogger(Oauth2ConnectorImpl.class.getName());

   private static final boolean NO_BODY = true;

    public Oauth2ConnectorImpl() {
        super(NO_BODY);
    }

    @Override
    protected String getMethod() {
        return HTTPMethod.POST.name();
    }

    @Override
    protected void executeBusinessLogic() throws ConnectorException {
        try {
            String oauth2TokenRetrieved = null;
            OAuth2TokenRequestAuthorization authorization = null;

            if (getAuthType() == AuthorizationType.OAUTH2_CLIENT_CREDENTIALS) {
                LOGGER.fine("Add OAuth2 Client Credentials auth");
                authorization = buildOAuth2ClientCredentialsAuthorization();
            } else if (getAuthType() == AuthorizationType.OAUTH2_AUTHORIZATION_CODE) {
                LOGGER.fine("Add OAuth2 Authorization Code auth");
                authorization = buildOAuth2AuthorizationCodeAuthorization();
            } else {
                throw new ConnectorException("Unsupported authorization type for OAuth2: " + getAuthType());
            }

            if (authorization != null) {
                Proxy proxy = null;
                if (isProxySet()) {
                    proxy = buildProxy();
                    LOGGER.fine("Add the Proxy options");
                }
                SSL ssl = buildSSL();
                LOGGER.fine("Add the SSL options");
                oauth2TokenRetrieved = getOAuth2AccessToken(authorization, proxy, ssl);
            }

            if (oauth2TokenRetrieved != null) {
                setOAuth2TokenOutput(oauth2TokenRetrieved);
                LOGGER.fine("OAuth2 token output set");
            }
        } catch (final Exception e) {
            logException(e);
            throw new ConnectorException(e);
        }
    }

    @Override
    public void validateInputParameters() throws ConnectorValidationException {
        // Validate OAuth2 authentication parameters based on type
        if (getAuthType() == AuthorizationType.OAUTH2_CLIENT_CREDENTIALS) {
            validateOAuth2TokenEndpoint();
            validateOAuth2ClientId();
            validateOAuth2ClientSecret();
            validateOAuth2Scope();
        } else if (getAuthType() == AuthorizationType.OAUTH2_AUTHORIZATION_CODE) {
            validateOAuth2TokenEndpoint();
            validateOAuth2ClientId();
            validateOAuth2ClientSecret();
            validateOAuth2Code();
            validateOAuth2CodeVerifier();
            validateOAuth2RedirectUri();
        } else {
            throw new ConnectorValidationException("OAuth2 connector requires auth_type to be OAUTH2_CLIENT_CREDENTIALS or OAUTH2_AUTHORIZATION_CODE");
        }

        // Validate SSL/TLS configuration
        validateTLS();
        validateTrustCertificateStrategyInput();
        validateHostnameVerifierInput();
        validateTrustStoreFile();
        validateTrustStorePassword();
        validateKeyStoreFile();
        validateKeyStorePassword();

        // Validate proxy configuration if set
        validateProxyProtocol();
        validateProxyHost();
        validateProxyPort();
        validateProxyUsername();
        validateProxyPassword();
        validateAutomaticProxyResolution();

        // Validate timeout parameters
        validateSocketTimeoutMs();
        validateConnectionTimeoutMs();
    }

    protected void setOAuth2TokenOutput(String token) {
        setOutputParameter(OAUTH2_TOKEN_OUTPUT_PARAMETER, token);
    }
}
