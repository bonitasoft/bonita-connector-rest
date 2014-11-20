package org.bonitasoft.connectors.rest.model;

/**
 * The charsets applicable for REST.
 */
public enum RESTCharsets {
    /**
     * The items.
     */
    UTF_8("UTF-8"), UTF_16("UTF-16"), UTF_16BE("UTF-16BE"), UTF_16LE("UTF-16LE"), ISO_8859_1("ISO-8859-1"), US_ASCII("US-ASCII");
    
    /**
     * The value of a item.
     */
    private String value = null;
    
    /**
     * Constructor to set the value of the created item.
     * Default Constructor.
     * @param value The value of the item.
     */
    RESTCharsets(final String value) {
        this.value = value;
    }
    
    /**
     * Value getter.
     * @return The value.
     */
    public String getValue() {
        return value;
    }
    
    /**
     * Get the RESTCharsets value based on a given value, by default UTF-8 is returned.
     * @param value The value.
     * @return The associated RESTCharsets value.
     */
    public static RESTCharsets getRESTCharsetsFromValue(final String value) {
        if (value != null) {
            if (UTF_8.value.equals(value)) {
                return RESTCharsets.UTF_8;
            }
            if (UTF_16.value.equals(value)) {
                return RESTCharsets.UTF_16;
            }
            if (UTF_16BE.value.equals(value)) {
                return RESTCharsets.UTF_16BE;
            }
            if (UTF_16LE.value.equals(value)) {
                return RESTCharsets.UTF_16LE;
            }
            if (ISO_8859_1.value.equals(value)) {
                return RESTCharsets.ISO_8859_1;
            }
            if (US_ASCII.value.equals(value)) {
                return RESTCharsets.US_ASCII;
            }
        }
        return RESTCharsets.UTF_8;
    }
}
