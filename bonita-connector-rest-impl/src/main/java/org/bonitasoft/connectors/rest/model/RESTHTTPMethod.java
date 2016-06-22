package org.bonitasoft.connectors.rest.model;

/**
 * The HTTP methods applicable for REST.
 */
public enum RESTHTTPMethod {
    /**
     * The items.
     */
    GET, POST, PUT, DELETE;
    
    /**
     * Get the RESTHTTPMethod based on a value
     * @param value The value
     * @return The associated RESTHTTPMethod value
     */
    public static RESTHTTPMethod getRESTHTTPMethodFromValue(final String value) {
        if (value != null) {
            return valueOf(value);
        }
        return GET;
    }
}
