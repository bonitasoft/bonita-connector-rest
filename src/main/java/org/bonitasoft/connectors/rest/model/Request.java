package org.bonitasoft.connectors.rest.model;

import java.net.HttpCookie;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.apache.http.Header;
import org.apache.http.entity.ContentType;
import org.apache.http.message.BasicHeader;


/**
 * This class reflects the information for a REST request.
 */
public class Request {
    
    /**
     * The URL.
     */
    private URL url;
    
    /**
     * The REST HTTP Method.
     */
    private HTTPMethod restMethod;
    
    /**
     * The authorization.
     */
    private Authorization authorization;
    
    /**
     * The headers.
     */
    private final List<Header> headers = new ArrayList<>();
    
    /**
     * The cookies.
     */
    private final List<HttpCookie> cookies = new ArrayList<>();
    
    /**
     * The ssl information.
     */
    private SSL ssl;
    
    /**
     * The Proxy information.
     */
    private Proxy proxy;
    
    /**
     * Is the request has to follow the redirections.
     */
    private boolean redirect;
    
    /**
     * Is the response body has to be digested.
     */
    private boolean ignore = false;
    
    /**
     * The body string.
     */
    private String body = "";

    private ContentType contentType;

    /**
     * URL value getter.
     * @return The URL value.
     */
    public URL getUrl() {
        return url;
    }
    
    /**
     * The URL value setter.
     * @param url URL value.
     */
    public void setUrl(final URL url) {
        this.url = url;
    }
    
    /**
     * RESTHTTPMethod value getter.
     * @return The RESTHTTPMethod value.
     */
    public HTTPMethod getRestMethod() {
        return restMethod;
    }
    
    /**
     * RESTHTTPMethod value setter.
     * @param restMethod The RESTHTTPMethod new value.
     */
    public void setRestMethod(final HTTPMethod restMethod) {
        this.restMethod = restMethod;
    }
    
    /**
     * Authorization value getter.
     * @return The authorization value.
     */
    public Authorization getAuthorization() {
        return authorization;
    }
    
    /**
     * Authorization value setter.
     * @param authorization The authorization new value.
     */
    public void setAuthorization(final Authorization authorization) {
        this.authorization = authorization;
    }
    
    /**
     * SSL value getter.
     * @return The SSL value.
     */
    public SSL getSsl() {
        return ssl;
    }
    
    /**
     * SSL value setter.
     * @param ssl The SSL new value.
     */
    public void setSsl(final SSL ssl) {
        this.ssl = ssl;
    }
    
    /**
     * Proxy value getter.
     * @return The Proxy value.
     */
    public Proxy getProxy() {
        return proxy;
    }
    
    /**
     * Proxy value setter.
     * @param proxy The Proxy new value.
     */
    public void setProxy(final Proxy proxy) {
        this.proxy = proxy;
    }
    
    /**
     * Redirect value getter.
     * @return The redirect value.
     */
    public boolean isRedirect() {
        return redirect;
    }
    
    /**
     * Redirect value setter.
     * @param redirect The redirect new value.
     */
    public void setRedirect(final boolean redirect) {
        this.redirect = redirect;
    }
    
    /**
     * Ignore value getter.
     * @return The ignore value.
     */
    public boolean isIgnore() {
        return ignore;
    }
    
    /**
     * Ignore value setter.
     * @param ignore The ignore new value.
     */
    public void setIgnore(final boolean ignore) {
        this.ignore = ignore;
    }
    
    /**
     * Headers value getter.
     * @return The headers value.
     */
    public List<Header> getHeaders() {
        return headers;
    }
    
    /**
     * Cookies value getter.
     * @return The cookies value.
     */
    public List<HttpCookie> getCookies() {
        return cookies;
    }
    
    /**
     * Add a header couple in the headers.
     * @param key The key of the new header.
     * @param value The lonely value of the new header.
     * @return True if the header has been added or false otherwise.
     */
    public boolean addHeader(final String key, final String value) {
        return headers.add(new BasicHeader(key,value));
    }
    
    /**
     * Add a cookie couple in the cookies.
     * @param key The key of the new cookie.
     * @param value The lonely value of the new cookie.
     * @return True if the cookie has been added or false otherwise.
     */
    public boolean addCookie(final String key, final String value) {
        return cookies.add(new HttpCookie(key,  value));
    }

    
    /**
     * Body value getter.
     * @return The body value.
     */
    public String getBody() {
        return body;
    }

    /**
     * Body value setter.
     * @param body The body new value.
     */
    public void setBody(final String body) {
        this.body = body;
    }
    

    public void setContentType(final ContentType contentType) {
        this.contentType = contentType;
    }


    public ContentType getContentType() {
        return contentType;
    }
    
    /*
     * (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return String.format("[%s] %s", restMethod, url);
    }
}
