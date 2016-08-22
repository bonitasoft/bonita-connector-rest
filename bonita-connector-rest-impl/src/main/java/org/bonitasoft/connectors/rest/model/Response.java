package org.bonitasoft.connectors.rest.model;

import java.util.ArrayList;
import java.util.List;

import org.bonitasoft.connectors.rest.RESTResultKeyValueMap;

/**
 * This class reflects the information for a REST response.
 */
public class Response {
    
    /**
     * The body.
     */
    private String body = "";

    /**
     * The execution time.
     */
    private long executionTime = 0L;
    
    /**
     * The HTTP status code.
     */
    private int statusCode = -1;
    
    /**
     * The information message.
     */
    private String message = "";
    
    /**
     * The headers.
     */
    private List<RESTResultKeyValueMap> headers = new ArrayList<RESTResultKeyValueMap>();
    
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
     * Execution time value getter.
     * @return The execution time value.
     */
    public long getExecutionTime() {
        return executionTime;
    }

    /**
     * Execution time value setter.
     * @param executionTime The new execution time value.
     */
   public void setExecutionTime(final long executionTime) {
        this.executionTime = executionTime;
    }


    
    /**
     * Status code value getter.
     * @return The status code value.
     */
    public int getStatusCode() {
        return statusCode;
    }

    /**
     * Status code value setter.
     * @param statusCode The new status code value.
     */
    public void setStatusCode(int statusCode) {
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
    public List<RESTResultKeyValueMap> getHeaders() {
        return headers;
    }


    /**
     * Headers value setter.
     * @param headers The new headers value.
     */
    public void setHeaders(final List<RESTResultKeyValueMap> headers) {
        this.headers = headers;
    }
    
    /**
     * Add a header couple in the headers.
     * @param key The key of the new header.
     * @param value The lonely value of the new header.
     * @return True if the header has been added or false otherwise.
     */
    public boolean addHeader(final String key, final String value) {
        if (headers != null) {
            RESTResultKeyValueMap restResultKeyValueMap = new RESTResultKeyValueMap();
            restResultKeyValueMap.setKey(key);
            List<String> values = new ArrayList<String>();
            values.add(value);
            restResultKeyValueMap.setValue(values);
            headers.add(restResultKeyValueMap);
            return true;
        }
        return false;
    }
}
