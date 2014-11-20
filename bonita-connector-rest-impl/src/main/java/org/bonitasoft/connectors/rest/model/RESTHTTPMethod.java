package org.bonitasoft.connectors.rest.model;

public enum RESTHTTPMethod {
    GET, POST, PUT, DELETE;
    
    /**
     * Get the HTTPMethod value based on a String value
     * @param value The String value
     * @return The associated HTTPMethod value
     */
    public static RESTHTTPMethod getRESTHTTPMethodFromValue(String value) {
        if (value != null) {
            return valueOf(value);
        }
        return GET;
    }
}
