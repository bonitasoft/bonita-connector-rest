package org.bonitasoft.connectors.rest.model;

/**
 * This class reflects the information for a Content of a HTTP request.
 */
public class Content {
    
    /**
     * The content type of the content.
     */
    private String contentType = null;
    
    /**
     * The charset parameter of the content.
     */
    private RESTCharsets charset = null;

    /**
     * Content type value getter.
     * @return The content type value.
     */
    public String getContentType() {
        return contentType;
    }

    /**
     * The content type value setter.
     * @param contentType The new content type value.
     */
    public void setContentType(final String contentType) {
        this.contentType = contentType;
    }

    /**
     * Charset value getter.
     * @return The charset value.
     */
    public RESTCharsets getCharset() {
        return charset;
    }

    /**
    * The charset value setter.
    * @param charset The new charset value.
    */
    public void setCharset(final RESTCharsets charset) {
        this.charset = charset;
    }

    /**
     * Gives the content string based on the charset and the content type parameter.
     * @return The content string to use in a HTTP request.
     */
    public String getContent() {
        String charsetStr = "";
        if (charset != null && !charset.toString().isEmpty()) {
            charsetStr = "; charset=";
        }
        return contentType + charsetStr;
    }
}
