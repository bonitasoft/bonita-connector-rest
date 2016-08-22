package org.bonitasoft.connectors.rest.model;

/**
 * This class reflects the information for SSL.
 */
public class SSL {
    
    /**
     * The truststore.
     */
    private Store trustStore = null;

    /**
     * The key store.
     */
    private Store keyStore = null;

    /**
     * The SSL verifier.
     */
    private SSLVerifier sslVerifier = SSLVerifier.STRICT;

    /**
     * Is the self signed certificate has to be used.
     */
    private boolean useSelfSignedCertificate = false;

    /**
     * Is TLS has to be used.
     */
    private boolean useTLS = false;
    
    /**
     * Trust store value getter.
     * @return The truststore value.
     */
    public Store getTrustStore() {
        return trustStore;
    }

    /**
     * Truststore value setter.
     * @param trustStore The truststore new value.
     */
    public void setTrustStore(final Store trustStore) {
        this.trustStore = trustStore;
    }
    
    /**
     * Key store value getter.
     * @return The key store value.
     */
    public Store getKeyStore() {
        return keyStore;
    }

    /**
     * Keystore value setter.
     * @param keyStore The keystore new value.
     */
    public void setKeyStore(final Store keyStore) {
        this.keyStore = keyStore;
    }

    /**
     * SSL verifier value getter.
     * @return The SSL verifier value.
     */
    public SSLVerifier getSslVerifier() {
        return sslVerifier;
    }

    /**
     * SSL verifier value setter.
     * @param sslVerifier The SSL verifier new value.
     */
    public void setSslVerifier(final SSLVerifier sslVerifier) {
        this.sslVerifier = sslVerifier;
    }

    /**
     * Use self signed certificate value getter.
     * @return The Use self signed certificate value.
     */
    public boolean isUseSelfSignedCertificate() {
        return useSelfSignedCertificate;
    }

    /**
     * Use self signed certificate value setter.
     * @param useSelfSignedCertificate The Use self signed certificate new value.
     */
    public void setUseSelfSignedCertificate(final boolean useSelfSignedCertificate) {
        this.useSelfSignedCertificate = useSelfSignedCertificate;
    }
    
    /**
     * Use TLS value getter.
     * @return The Use TLS value.
     */
    public boolean isUseTLS() {
        return useTLS;
    }

    /**
     * Use TLS setter.
     * @param useTLS The Use TLS new value.
     */
    public void setUseTLS(final boolean useTLS) {
        this.useTLS = useTLS;
    }
}
