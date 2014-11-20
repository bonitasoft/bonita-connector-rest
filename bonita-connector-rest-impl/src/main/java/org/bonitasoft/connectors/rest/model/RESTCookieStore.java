package org.bonitasoft.connectors.rest.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import org.apache.http.client.CookieStore;
import org.apache.http.cookie.Cookie;

public class RESTCookieStore implements CookieStore {
    
    private List<Cookie> cookies = new ArrayList<Cookie>();

    @Override
    public void addCookie(Cookie cookie) {
        cookies.add(cookie);
    }

    @Override
    public List<Cookie> getCookies() {
        return cookies;
    }

    @Override
    public boolean clearExpired(Date date) {
        return true;
    }

    @Override
    public void clear() {
        cookies.clear();
    }
    
}
