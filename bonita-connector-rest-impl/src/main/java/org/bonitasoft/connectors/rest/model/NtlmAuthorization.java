package org.bonitasoft.connectors.rest.model;


public class NtlmAuthorization extends Authorization {
    private String username = null;

    private String password = null;
    
    private String workstation = null;
    
    private String domain = null;

    
    public String getUsername() {
        return username;
    }

    
    public void setUsername(String username) {
        this.username = username;
    }

    
    public String getPassword() {
        return password;
    }

    
    public void setPassword(String password) {
        this.password = password;
    }

    
    public String getWorkstation() {
        return workstation;
    }

    
    public void setWorkstation(String workstation) {
        this.workstation = workstation;
    }

    
    public String getDomain() {
        return domain;
    }

    
    public void setDomain(String domain) {
        this.domain = domain;
    }
    
}
