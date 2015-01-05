package org.bonitasoft.connectors.rest.model;

/**
 * This class reflects the information for a Basic or Digest authorization of a HTTP request.
 */
public class BasicDigestAuthorization implements Authorization {

    /**
     * Is the authorization information for a Basic authorization.
     */
    private boolean basic = true;
    
    /**
     * The username value.
     */
    private String username = null;
    
    /**
     * The password value.
     */
    private String password = null;
    
    /**
     * The host value.
     */
    private String host = null;
    
    /**
     * The realm value.
     */
    private String realm = null;
    
    /**
     * Is this authorization preemptive.
     */
    private boolean isPreemptive = true;

    /**
     * Constructor setting if the authorization is a Basic typed one.
     * Default Constructor.
     * @param basic States if it is a Basic authorization.
     */
    public BasicDigestAuthorization(final boolean basic) {
        this.basic = basic;
    }
    
    /**
     * Username value getter.
     * @return The username value.
     */
    public String getUsername() {
        return username;
    }

    /**
     * Username value setter.
     * @param username The new username value.
     */
    public void setUsername(final String username) {
        this.username = username;
    }

    /**
     * Password value getter.
     * @return The password value.
     */
    public String getPassword() {
        return password;
    }

    /**
     * Password value setter.
     * @param password The new password value.
     */
    public void setPassword(final String password) {
        this.password = password;
    }

    /**
     * Host value getter.
     * @return The host value.
     */
    public String getHost() {
        return host;
    }

    /**
     * Host value setter.
     * @param host The new Host value.
     */
    public void setHost(final String host) {
        this.host = host;
    }

    /**
     * Realm value getter.
     * @return The realm value.
     */
    public String getRealm() {
        return realm;
    }

    /**
     * Realm value setter.
     * @param realm The new realm value.
     */
    public void setRealm(final String realm) {
        this.realm = realm;
    }

    /**
     * Preemptive value getter.
     * @return The preemptive value.
     */
    public boolean isPreemptive() {
        return isPreemptive;
    }

    /**
     * Preemptive value setter.
     * @param isPreemptive The new preemptive value.
     */
    public void setPreemptive(final boolean isPreemptive) {
        this.isPreemptive = isPreemptive;
    }

    /**
     * Basic value getter.
     * @return The basic value.
     */
    public boolean isBasic() {
        return basic;
    }

    /**
     * Basic value setter.
     * @param basic The new basic value.
     */
    public void setBasic(final boolean basic) {
        this.basic = basic;
    }
    
}
