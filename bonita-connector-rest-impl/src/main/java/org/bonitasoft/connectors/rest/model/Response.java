package org.bonitasoft.connectors.rest.model;

import java.util.ArrayList;
import java.util.List;

import org.apache.http.Header;

/**
 * This class reflects the information for a REST response.
 */
public class Response {
    
    /**
     * The body.
     */
    private String body = "";

    /**
     * The HTTP status code.
     */
    private Integer statusCode = -1;
    
    /**
     * The information message.
     */
    private String message = null;
    
    /**
     * The headers.
     */
    private Header[] headers = null;
    
    /**
     * Body value getter.
     * @return The body value.
     */
    public String getBody() {
        return body;
    }

    /**
     * Body value setter.
     * @param body The new body value.
     */
    public void setBody(final String body) {
        this.body = body;
    }

    /**
     * Status code value getter.
     * @return The status code value.
     */
    public Integer getStatusCode() {
        return statusCode;
    }

    /**
     * Status code value setter.
     * @param statusCode The new status code value.
     */
    public void setStatusCode(Integer statusCode) {
        this.statusCode = statusCode;
    }


    
    /**
     * Message value getter.
     * @return The message value.
     */
    public String getMessage() {
        return message;
    }


    /**
     * Message value setter.
     * @param message The new message value.
     */
    public void setMessage(final String message) {
        this.message = message;
    }


    
    /**
     * Headers value getter.
     * @return The headers value.
     */
    public Header[] getHeaders() {
        return headers;
    }


    /**
     * Headers value setter.
     * @param headers The new headers value.
     */
    public void setHeaders(final Header[] headers) {
        this.headers = headers;
    }
}
