package org.bonitasoft.connectors.rest.model;

import java.net.HttpCookie;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bonitasoft.connectors.rest.RESTResultKeyValueMap;

public class RESTRequest {
    private URL url;
    private RESTHTTPMethod restMethod;
    private Authorization authorization;
    private final List<RESTResultKeyValueMap> headers = new ArrayList<RESTResultKeyValueMap>();
    private final List<HttpCookie> cookies = new ArrayList<>();
    private SSL ssl;
    private boolean redirect;
    private boolean ignore = false;
    private Content content = null;
    private String body = "";

    public URL getUrl() {
        return url;
    }
    
    public void setUrl(URL url) {
        this.url = url;
    }
    
    public RESTHTTPMethod getRestMethod() {
        return restMethod;
    }
    
    public void setRestMethod(RESTHTTPMethod restMethod) {
        this.restMethod = restMethod;
    }
    
    public Authorization getAuthorization() {
        return authorization;
    }
    
    public void setAuthorization(Authorization authorization) {
        this.authorization = authorization;
    }
    
    public SSL getSsl() {
        return ssl;
    }
    
    public void setSsl(SSL ssl) {
        this.ssl = ssl;
    }
    
    public boolean isRedirect() {
        return redirect;
    }
    
    public void setRedirect(boolean redirect) {
        this.redirect = redirect;
    }
    
    public boolean isIgnore() {
        return ignore;
    }
    
    public void setIgnore(boolean ignore) {
        this.ignore = ignore;
    }
    
    public List<RESTResultKeyValueMap> getHeaders() {
        return headers;
    }
    
    public List<HttpCookie> getCookies() {
        return cookies;
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
    
    public boolean addCookie(String key, String value) {
        if(cookies != null) {
            HttpCookie cookie = new HttpCookie(key,  value);
            cookies.add(cookie);
            return true;
        }
        return false;
    }

    
    public Content getContent() {
        return content;
    }

    
    public void setContent(Content content) {
        this.content = content;
    }

    
    public String getBody() {
        return body;
    }

    
    public void setBody(String body) {
        this.body = body;
    }
    
}
