package org.bonitasoft.connectors.rest.model;

/**
 * This class reflects the information for a header authorization of a HTTP request.
 */
public class HeaderAuthorization implements Authorization {
    
    /**
     * The token value.
     */
    private String value = null;
    
    /**
     * Value getter.
     * @return The value.
     */
    public String getValue() {
        return value;
    }
    
    /**
     * The value setter.
     * @param value The new value.
     */
    public void setValue(final String value) {
        this.value = value;
    }
    
    
}
