package org.bonitasoft.connectors.rest.utils;

import org.junit.Before;
import org.junit.Test;

import java.net.URI;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ProxyUtilsTest {

    @Before
    public void beforeEach() {
        System.setProperty(ProxyUtils.HTTPS_PROXY_HOST, "my-https-proxy");
        System.setProperty(ProxyUtils.HTTPS_PROXY_PORT, "8443");
        System.setProperty(ProxyUtils.HTTP_PROXY_HOST, "my-http-proxy");
        System.setProperty(ProxyUtils.HTTP_PROXY_PORT, "8080");
        System.setProperty(ProxyUtils.HTTP_NON_PROXY_HOSTS, "*.host1.com");
    }

    @Test
    public void https_non_proxy_host_should_not_be_proxied() {
        var proxyAddress = ProxyUtils.proxyAddress(URI.create("https://www.host1.com"));
        assertTrue(proxyAddress.isEmpty());
    }

    @Test
    public void http_non_proxy_host_should_not_be_proxied() {
        var proxyAddress = ProxyUtils.proxyAddress(URI.create("http://www.host1.com"));
        assertTrue(proxyAddress.isEmpty());
    }

    @Test
    public void https_host_should_be_proxied_through_https_proxy() {
        var proxyAddress = ProxyUtils.proxyAddress(URI.create("https://www.host2.com"));
        assertTrue(proxyAddress.isPresent());
        assertEquals("my-https-proxy", proxyAddress.get().getHostName());
        assertEquals(8443, proxyAddress.get().getPort());
    }

    @Test
    public void http_host_should_be_proxied_through_http_proxy() {
        var proxyAddress = ProxyUtils.proxyAddress(URI.create("http://www.host2.com"));
        assertTrue(proxyAddress.isPresent());
        assertEquals("my-http-proxy", proxyAddress.get().getHostName());
        assertEquals(8080, proxyAddress.get().getPort());
    }
}
