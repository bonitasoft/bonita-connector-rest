package org.bonitasoft.connectors.rest.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URI;
import java.util.Optional;

public class ProxyUtils {

	private static final Logger log = LoggerFactory.getLogger(ProxyUtils.class);

	private ProxyUtils() {}

	public static final String HTTPS_PROXY_HOST = "https.proxyHost";
	public static final String HTTPS_PROXY_PORT = "https.proxyPort";
	public static final String HTTP_PROXY_HOST = "http.proxyHost";
	public static final String HTTP_PROXY_PORT = "http.proxyPort";
	public static final String HTTP_NON_PROXY_HOSTS = "http.nonProxyHosts";

	public static Optional<InetSocketAddress> proxyAddress(URI uri) {
		return proxy(uri)
				.map(Proxy::address)
				.map(InetSocketAddress.class::cast);
	}

	public static Optional<Proxy> proxy(URI uri) {
		var proxy = ProxySelector.getDefault().select(uri).get(0);
		log.debug("Using proxy {} for URI {}", proxy, uri);
		if (Proxy.NO_PROXY.equals(proxy)) {
			return Optional.empty();
		}
		return Optional.of(proxy);
	}

	public static Optional<String> hostName(URI uri) {
		return proxyAddress(uri)
			.map(InetSocketAddress::getHostName);
	}

	public static Optional<Integer> port(URI uri) {
		return proxyAddress(uri)
			.map(InetSocketAddress::getPort);
	}
}
