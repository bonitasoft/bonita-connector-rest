package org.bonitasoft.connectors.rest.model;


public class BasicDigestAuthorization extends Authorization {
    private boolean basic = true;
    
    private String username = null;
    
    private String password = null;
    
    private String host = null;
    
    private String realm = null;
    
    private boolean isPreemptive = true;

    public BasicDigestAuthorization(boolean digest) {
        if(digest) {
            basic = false;
        }
    }
    
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

    
    public String getHost() {
        return host;
    }

    
    public void setHost(String host) {
        this.host = host;
    }

    
    public String getRealm() {
        return realm;
    }

    
    public void setRealm(String realm) {
        this.realm = realm;
    }

    
    public boolean isPreemptive() {
        return isPreemptive;
    }

    
    public void setPreemptive(boolean isPreemptive) {
        this.isPreemptive = isPreemptive;
    }

    
    public boolean isBasic() {
        return basic;
    }

    
    public void setBasic(boolean basic) {
        this.basic = basic;
    }
    
}
