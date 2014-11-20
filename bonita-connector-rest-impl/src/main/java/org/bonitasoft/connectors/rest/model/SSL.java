package org.bonitasoft.connectors.rest.model;

public class SSL {
    private RESTKeyStore trustStore;

    private RESTKeyStore keyStore;

    private SSLVerifier sslVerifier = SSLVerifier.STRICT;

    private boolean trustSelfSignedCert = false;


    public RESTKeyStore getTrustStore() {
        return trustStore;
    }

    public void setTrustStore(RESTKeyStore trustStore) {
        this.trustStore = trustStore;
    }

    public RESTKeyStore getKeyStore() {
        return keyStore;
    }

    public void setKeyStore(RESTKeyStore keyStore) {
        this.keyStore = keyStore;
    }


    public SSLVerifier getSslVerifier() {
        return sslVerifier;
    }


    public void setSslVerifier(SSLVerifier sslVerifier) {
        this.sslVerifier = sslVerifier;
    }


    public boolean isTrustSelfSignedCert() {
        return trustSelfSignedCert;
    }


    public void setTrustSelfSignedCert(boolean trustSelfSignedCert) {
        this.trustSelfSignedCert = trustSelfSignedCert;
    }
}
