package org.bonitasoft.connectors.rest.model;

import java.util.ArrayList;
import java.util.List;

import org.bonitasoft.connectors.rest.RESTResultKeyValueMap;

public class RESTResponse {
    private String body = "";

    private long executionTime = 0l;
    
    private int statusCode = -1;
    
    private String message = "";
    
    private List<RESTResultKeyValueMap> headers = new ArrayList<RESTResultKeyValueMap>();
    
    public String getBody() {
        return body;
    }

    
    public void setBody(String body) {
        this.body = body;
    }


    
    public long getExecutionTime() {
        return executionTime;
    }


    
    public void setExecutionTime(long executionTime) {
        this.executionTime = executionTime;
    }


    
    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }


    
    public String getMessage() {
        return message;
    }


    
    public void setMessage(String message) {
        this.message = message;
    }


    
    public List<RESTResultKeyValueMap> getHeaders() {
        return headers;
    }


    
    public void setHeaders(List<RESTResultKeyValueMap> headers) {
        this.headers = headers;
    }
    
    public boolean addHeader(String key, String value) {
        if(headers != null) {
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
    
    public boolean addHeader(String key, List<String> value) {
        if(headers != null) {
            RESTResultKeyValueMap restResultKeyValueMap = new RESTResultKeyValueMap();
            restResultKeyValueMap.setKey(key);
            restResultKeyValueMap.setValue(value);
            headers.add(restResultKeyValueMap);
            return true;
        }
        return false;
    }
}
