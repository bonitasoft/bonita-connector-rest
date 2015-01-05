package org.bonitasoft.connectors.rest.model;

/**
 * This class reflects the information for a NTLM authorization of a HTTP request.
 */
public class NtlmAuthorization implements Authorization {
    /**
     * The username value.
     */
    private String username = null;

    /**
     * The password value.
     */
    private String password = null;
    
    /**
     * The workstation value.
     */
    private String workstation = null;
    
    /**
     * The domain value.
     */
    private String domain = null;

    
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
     * Workstation value getter.
     * @return The workstation value.
     */
    public String getWorkstation() {
        return workstation;
    }

    /**
     * Workstation value setter.
     * @param workstation The new workstation value.
     */
    public void setWorkstation(final String workstation) {
        this.workstation = workstation;
    }

    /**
     * Domain value getter.
     * @return The domain value.
     */
    public String getDomain() {
        return domain;
    }

    /**
     * Domain value setter.
     * @param domain The new domain value.
     */
    public void setDomain(final String domain) {
        this.domain = domain;
    }
    
}
