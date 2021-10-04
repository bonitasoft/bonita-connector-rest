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

    private TrustCertificateStrategy trustCertificateStrategy = TrustCertificateStrategy.DEFAULT;

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

    public TrustCertificateStrategy getTrustCertificateStrategy() {
        return trustCertificateStrategy;
    }

    public void setTrustCertificateStrategy(final TrustCertificateStrategy trustCertificateStrategy) {
        this.trustCertificateStrategy = trustCertificateStrategy;
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
