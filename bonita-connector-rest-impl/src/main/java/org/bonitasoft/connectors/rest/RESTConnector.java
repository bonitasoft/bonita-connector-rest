/**
 * Copyright (C) 2014 BonitaSoft S.A.
 * BonitaSoft, 32 rue Gustave Eiffel - 38000 Grenoble
 * This library is free software; you can redistribute it and/or modify it under the terms
 * of the GNU Lesser General Public License as published by the Free Software Foundation
 * version 2.1 of the License.
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 * You should have received a copy of the GNU Lesser General Public License along with this
 * program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA.
 **/

package org.bonitasoft.connectors.rest;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpCookie;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.IllegalCharsetNameException;
import java.nio.charset.UnsupportedCharsetException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Logger;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.ProtocolVersion;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.NTCredentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.auth.params.AuthPNames;
import org.apache.http.client.AuthCache;
import org.apache.http.client.CookieStore;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpOptions;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpTrace;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.params.AuthPolicy;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.client.protocol.ClientContext;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.entity.AbstractHttpEntity;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.FileEntity;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.entity.mime.MultipartEntity;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.impl.auth.AuthSchemeBase;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.auth.DigestScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.message.AbstractHttpMessage;
import org.apache.http.message.BasicHeader;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.CoreProtocolPNames;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import org.bonitasoft.engine.connector.ConnectorException;
import org.bonitasoft.engine.connector.ConnectorValidationException;
import org.wiztools.commons.Charsets;
import org.wiztools.commons.MultiValueMap;
import org.wiztools.commons.StreamUtil;
import org.wiztools.commons.StringUtil;
import org.wiztools.restclient.IGlobalOptions;
import org.wiztools.restclient.ProxyConfig;
import org.wiztools.restclient.ServiceLocator;
import org.wiztools.restclient.bean.Auth;
import org.wiztools.restclient.bean.AuthorizationHeaderAuth;
import org.wiztools.restclient.bean.AuthorizationHeaderAuthBean;
import org.wiztools.restclient.bean.BasicAuth;
import org.wiztools.restclient.bean.BasicAuthBean;
import org.wiztools.restclient.bean.BasicDigestAuth;
import org.wiztools.restclient.bean.ContentType;
import org.wiztools.restclient.bean.ContentTypeBean;
import org.wiztools.restclient.bean.DigestAuth;
import org.wiztools.restclient.bean.DigestAuthBean;
import org.wiztools.restclient.bean.HTTPMethod;
import org.wiztools.restclient.bean.HTTPVersion;
import org.wiztools.restclient.bean.NtlmAuth;
import org.wiztools.restclient.bean.NtlmAuthBean;
import org.wiztools.restclient.bean.ReqEntity;
import org.wiztools.restclient.bean.ReqEntityByteArray;
import org.wiztools.restclient.bean.ReqEntityFile;
import org.wiztools.restclient.bean.ReqEntityFilePart;
import org.wiztools.restclient.bean.ReqEntityMultipart;
import org.wiztools.restclient.bean.ReqEntityPart;
import org.wiztools.restclient.bean.ReqEntitySimple;
import org.wiztools.restclient.bean.ReqEntityStream;
import org.wiztools.restclient.bean.ReqEntityString;
import org.wiztools.restclient.bean.ReqEntityStringBean;
import org.wiztools.restclient.bean.ReqEntityStringPart;
import org.wiztools.restclient.bean.Request;
import org.wiztools.restclient.bean.RequestBean;
import org.wiztools.restclient.bean.ResponseBean;
import org.wiztools.restclient.bean.SSLHostnameVerifier;
import org.wiztools.restclient.bean.SSLReq;
import org.wiztools.restclient.http.EntityEnclosingDelete;
import org.wiztools.restclient.http.NoValidationCookieSpecFactory;
import org.wiztools.restclient.http.RESTClientCookieStore;
import org.wiztools.restclient.util.HttpUtil;
import org.wiztools.restclient.util.IDNUtil;

public class RESTConnector extends AbstractRESTConnectorImpl {
	final static private String UTF_8_STR = "UTF-8";

	private static Logger LOGGER = Logger.getLogger(RESTConnector.class.getName());

	@Override
	public void validateInputParameters() throws ConnectorValidationException {
		super.validateInputParameters();

		LOGGER.info("super validateInputParameters done.");

		final List<String> messages = new ArrayList<String>(0);
		if (getUrl() == null || getUrl().isEmpty()) {
			messages.add(URL_INPUT_PARAMETER);
		} else {
			try {
				URL url = new URL(getUrl());
			} catch(MalformedURLException e) {
				messages.add(URL_INPUT_PARAMETER);
			}
		}

		if (getMethod() == null || getMethod().isEmpty()) {
			messages.add(METHOD_INPUT_PARAMETER);
		}

		if (getContentType() == null || getContentType().isEmpty()) {
			messages.add(CONTENTTYPE_INPUT_PARAMETER);
		}
		if (getCharset() == null || getCharset().isEmpty()) {
			messages.add(CHARSET_INPUT_PARAMETER);
		}

		List urlCookies = getUrlCookies();
		if(urlCookies != null) {
			for(Object urlCookie : urlCookies) {
				if(urlCookie instanceof List) {
					List urlCookieRow = (List)urlCookie;
					if(urlCookieRow.size() != 2) {
						messages.add(URLCOOKIES_INPUT_PARAMETER + " - columns - " + urlCookieRow.size());
					} else if(urlCookieRow.get(0) == null || urlCookieRow.get(0).toString().isEmpty() || urlCookieRow.get(1) == null) {
						messages.add(URLCOOKIES_INPUT_PARAMETER + " - value");
					}
				} else {
					messages.add(URLCOOKIES_INPUT_PARAMETER + " - type");
				}
			}
		}

		List urlheaders = getUrlHeaders();
		if(urlheaders != null) {
			for(Object urlheader : urlheaders) {
				if(urlheader instanceof List) {
					List urlheaderRow = (List)urlheader;
					if(urlheaderRow.size() != 2) {
						messages.add(URLHEADERS_INPUT_PARAMETER + " - columns - " + urlheaderRow.size());
					} else if(urlheaderRow.get(0) == null || urlheaderRow.get(0).toString().isEmpty() || urlheaderRow.get(1) == null) {
						messages.add(URLHEADERS_INPUT_PARAMETER + " - value");
					}
				} else {
					messages.add(URLHEADERS_INPUT_PARAMETER + " - type");
				}
			}
		}
		
		if (getCharset() == null || getCharset().isEmpty()) {
			messages.add(CHARSET_INPUT_PARAMETER);
		}
		if (getCharset() == null || getCharset().isEmpty()) {
			messages.add(CHARSET_INPUT_PARAMETER);
		}
		if (getCharset() == null || getCharset().isEmpty()) {
			messages.add(CHARSET_INPUT_PARAMETER);
		}

		if (!messages.isEmpty()) {
			LOGGER.severe("validateInputParameters error: " + messages.toString());
			throw new ConnectorValidationException(this, messages);
		}
	}

	@Override
	protected void executeBusinessLogic() throws ConnectorException {
		RESTResult result = new RESTResult();
		try {
			//construct the request
			RequestBean request = new RequestBean();
			request.setUrl(new URL(getUrl()));
			LOGGER.info("URL set to: " + request.getUrl().toString());
			String bodyStr = "";
			if(getBody() != null) {
				bodyStr = getBody();
			}
			request.setBody(new ReqEntityStringBean(bodyStr, new ContentTypeBean(getContentType(), getCharset(getCharset()))));
			LOGGER.info("Body set to: " + request.getBody().toString());
			request.setMethod(getHTTPMethod(getMethod()));
			LOGGER.info("Method set to: " + request.getMethod().toString());
			request.setFollowRedirect(true);
			LOGGER.info("Follow redirect set to: " + request.isFollowRedirect());
			for(Object urlheader : getUrlHeaders()) {
				List urlheaderRow = (List)urlheader;
				request.addHeader(urlheaderRow.get(0).toString(), urlheaderRow.get(1).toString());	
				LOGGER.info("Add header: " + urlheaderRow.get(0).toString() + " set as " +  urlheaderRow.get(1).toString());
			}
			for(Object urlCookie : getUrlCookies()) {
				List urlCookieRow = (List)urlCookie;
				request.addCookie(new HttpCookie(urlCookieRow.get(0).toString(), urlCookieRow.get(1).toString()));
				LOGGER.info("Add cookie: " + urlCookieRow.get(0).toString() + " set as " + urlCookieRow.get(1).toString());
			}
			
			if ((getAuth_basic_username() != null && getAuth_basic_username().isEmpty()) &&
					(getAuth_basic_password() != null && getAuth_basic_password().isEmpty()) && 
					getAuth_basic_preemptive() != null) {
				LOGGER.info("Add basic auth");
				
				BasicAuthBean auth = new BasicAuthBean();
				auth.setUsername(getAuth_basic_username());
				auth.setPassword(getAuth_basic_password().toCharArray());
				
				if(getAuth_basic_host() != null && getAuth_basic_host().isEmpty()) {
					auth.setHost(getAuth_basic_host());
				}
				if(getAuth_basic_realm() != null && getAuth_basic_realm().isEmpty()) {
					auth.setRealm(getAuth_basic_realm());
				}
				auth.setPreemptive(getAuth_basic_preemptive());
					
				request.setAuth(auth);
			} else if ((getAuth_digest_username() != null && getAuth_digest_username().isEmpty()) &&
					(getAuth_digest_password() != null && getAuth_digest_password().isEmpty()) && 
					getAuth_digest_preemptive() != null) {
				LOGGER.info("Add digest auth");
				
				DigestAuthBean auth = new DigestAuthBean();
				auth.setUsername(getAuth_digest_username());
				auth.setPassword(getAuth_digest_password().toCharArray());
				
				if(getAuth_digest_host() != null && getAuth_digest_host().isEmpty()) {
					auth.setHost(getAuth_digest_host());
				}
				if(getAuth_digest_realm() != null && getAuth_digest_realm().isEmpty()) {
					auth.setRealm(getAuth_digest_realm());
				}
				auth.setPreemptive(getAuth_digest_preemptive());
					
				request.setAuth(auth);
			} else if((getAuth_NTLM_username() != null && getAuth_NTLM_username().isEmpty()) &&
					(getAuth_NTLM_password() != null && getAuth_NTLM_password().isEmpty()) && 
					(getAuth_NTLM_workstation() != null && getAuth_NTLM_workstation().isEmpty()) &&
					(getAuth_NTLM_domain() != null && getAuth_NTLM_domain().isEmpty())) {
				NtlmAuthBean auth = new NtlmAuthBean();
				auth.setUsername(getAuth_NTLM_username());
				auth.setPassword(getAuth_NTLM_password().toCharArray());
				auth.setWorkstation(getAuth_NTLM_workstation());
				auth.setDomain(getAuth_NTLM_domain());

				request.setAuth(auth);
			} else if((getAuth_OAuth2_bearer_token() != null && getAuth_OAuth2_bearer_token().isEmpty())) {
				AuthorizationHeaderAuthBean auth = new AuthorizationHeaderAuthBean();
				auth.setAuthorizationHeaderValue(getAuth_OAuth2_bearer_token());
				request.setAuth(auth);
			}

			//execute the request
			ResponseBean response = execute(request);
			LOGGER.info("Request sent.");

			if(response != null) {
				//construct the result
				String entity = "empty";
				if(response.getResponseBody() != null && response.getResponseBody().length > 0) {
					entity = new String(response.getResponseBody()).trim();
					LOGGER.info("Response entity extracted and not empty.");
				}
				result.setEntity(entity);
				List<RESTResultKeyValueMap> header = new ArrayList<RESTResultKeyValueMap>();
				MultiValueMap<String, String> returnedHeader = response.getHeaders();
				Iterator<String> returnedHeaderIterator = returnedHeader.keySet().iterator();
				while(returnedHeaderIterator.hasNext()) {
					RESTResultKeyValueMap mapping = new RESTResultKeyValueMap();
					String key = returnedHeaderIterator.next();
					List<String> values = new ArrayList<String>();
					Collection<String> returnedValues = returnedHeader.get(key);
					Iterator<String> returnedValuesIterator = returnedValues.iterator();
					while(returnedValuesIterator.hasNext()) {
						values.add(returnedValuesIterator.next());
					}
					mapping.setKey(key);
					mapping.setValue(values);
					header.add(mapping);
					LOGGER.info("Header value extracted.");
				}
				result.setHeader(header);
				result.setTime(response.getExecutionTime());
				LOGGER.info("Time extracted.");
				result.setStatusCode(response.getStatusCode());
				LOGGER.info("Status code extracted.");
				result.setStatusLine(response.getStatusLine());
				LOGGER.info("Status line extracted.");
			} else {
				LOGGER.severe("Response is null.");
			}
		} catch (Exception e) {
			logException(e);
			throw new ConnectorException(e);
		}
		setResult(result);
		LOGGER.info("Result set.");
	}

	static public HTTPMethod getHTTPMethod(String input) {
		if(input != null) {
			return HTTPMethod.valueOf(input);
		}
		return HTTPMethod.GET;
	}

	static public Charset getCharset(String input) {
		if(input != null) {
			if(UTF_8_STR.equals(input)) {
				return Charsets.UTF_8;
			}
		}
		return Charsets.UTF_8;
	}

	public static ResponseBean execute(Request request) {
		// Verify if this is the first call to this object:

		DefaultHttpClient httpclient = new DefaultHttpClient();

		final URL url = IDNUtil.getIDNizedURL(request.getUrl());
		final String urlHost = url.getHost();
		final int urlPort = url.getPort()==-1?url.getDefaultPort():url.getPort();
		final String urlProtocol = url.getProtocol();
		final String urlStr = url.toString();

		// Needed for specifying HTTP pre-emptive authentication
		HttpContext httpContext = null;

		// Set HTTP version
		HTTPVersion httpVersion = request.getHttpVersion();
		ProtocolVersion protocolVersion =
				httpVersion==HTTPVersion.HTTP_1_1? new ProtocolVersion("HTTP", 1, 1):
					new ProtocolVersion("HTTP", 1, 0);
				httpclient.getParams().setParameter(CoreProtocolPNames.PROTOCOL_VERSION, protocolVersion);

				// Set request timeout (default 1 minute--60000 milliseconds)
				IGlobalOptions options = ServiceLocator.getInstance(IGlobalOptions.class);
				options.acquire();
				HttpConnectionParams.setConnectionTimeout(httpclient.getParams(), Integer.parseInt(options.getProperty("request-timeout-in-millis")));
				options.release();

				// Set proxy
				ProxyConfig proxy = ProxyConfig.getInstance();
				proxy.acquire();
				if (proxy.isEnabled()) {
					final HttpHost proxyHost = new HttpHost(proxy.getHost(), proxy.getPort(), "http");
					if (proxy.isAuthEnabled()) {
						httpclient.getCredentialsProvider().setCredentials(
								new AuthScope(proxy.getHost(), proxy.getPort()),
								new UsernamePasswordCredentials(proxy.getUsername(), new String(proxy.getPassword())));
					}
					httpclient.getParams().setParameter(ConnRoutePNames.DEFAULT_PROXY, proxyHost);
				}
				proxy.release();

				// HTTP Authentication
				if(request.getAuth() != null) {
					// Add auth preference:
					Auth auth = request.getAuth();
					List<String> authPrefs = new ArrayList<String>();
					if(auth instanceof BasicAuth) {
						authPrefs.add(AuthPolicy.BASIC);
					}
					else if(auth instanceof DigestAuth) {
						authPrefs.add(AuthPolicy.DIGEST);
					}
					else if(auth instanceof NtlmAuth) {
						authPrefs.add(AuthPolicy.NTLM);
					}
					httpclient.getParams().setParameter(AuthPNames.TARGET_AUTH_PREF, authPrefs);

					// BASIC & DIGEST:
						if(auth instanceof BasicAuth || auth instanceof DigestAuth) {
							BasicDigestAuth a = (BasicDigestAuth) auth;
							String uid = a.getUsername();
							String pwd = new String(a.getPassword());
							String host = StringUtil.isEmpty(a.getHost()) ? urlHost : a.getHost();
							String realm = StringUtil.isEmpty(a.getRealm()) ? AuthScope.ANY_REALM : a.getRealm();

							httpclient.getCredentialsProvider().setCredentials(
									new AuthScope(host, urlPort, realm),
									new UsernamePasswordCredentials(uid, pwd));

							// preemptive mode
							if (a.isPreemptive()) {
								AuthCache authCache = new BasicAuthCache();
								AuthSchemeBase authScheme = a instanceof BasicAuth?
										new BasicScheme(): new DigestScheme();
										authCache.put(new HttpHost(urlHost, urlPort, urlProtocol), authScheme);
										BasicHttpContext localcontext = new BasicHttpContext();
										localcontext.setAttribute(ClientContext.AUTH_CACHE, authCache);
										httpContext = localcontext;
							}
						}

						// NTLM:
						if(auth instanceof NtlmAuth) {
							NtlmAuth a = (NtlmAuth) auth;
							String uid = a.getUsername();
							String pwd = new String(a.getPassword());

							httpclient.getCredentialsProvider().setCredentials(
									AuthScope.ANY,
									new NTCredentials(uid, pwd,
											a.getWorkstation(), a.getDomain()));
						}

						// Authorization header
						// Logic written in same place where Header is processed--a little down!
				}

				AbstractHttpMessage method = null;

				final HTTPMethod httpMethod = request.getMethod();
				try {
					switch(httpMethod){
					case GET:
						method = new HttpGet(urlStr);
						break;
					case POST:
						method = new HttpPost(urlStr);
						break;
					case PUT:
						method = new HttpPut(urlStr);
						break;
					case PATCH:
						method = new HttpPatch(urlStr);
						break;
					case DELETE:
						method = new EntityEnclosingDelete(urlStr);
						break;
					case HEAD:
						method = new HttpHead(urlStr);
						break;
					case OPTIONS:
						method = new HttpOptions(urlStr);
						break;
					case TRACE:
						method = new HttpTrace(urlStr);
						break;
					}
					method.setParams(new BasicHttpParams().setParameter(urlStr, url));

					{ // Authorization Header Authentication:
						Auth auth = request.getAuth();
					if(auth != null && auth instanceof AuthorizationHeaderAuth) {
						AuthorizationHeaderAuth a = (AuthorizationHeaderAuth) auth;
						final String authHeader = a.getAuthorizationHeaderValue();
						if(StringUtil.isNotEmpty(authHeader)) {
							Header header = new BasicHeader("Authorization", authHeader);
							method.addHeader(header);
						}
					}
					}

					// Get request headers
					MultiValueMap<String, String> header_data = request.getHeaders();
					for (String key : header_data.keySet()) {
						for(String value: header_data.get(key)) {
							Header header = new BasicHeader(key, value);
							method.addHeader(header);
						}
					}

					// Cookies
					{
						// Set cookie policy:
						httpclient.getCookieSpecs().register(NoValidationCookieSpecFactory.NAME, new NoValidationCookieSpecFactory());
						httpclient.getParams().setParameter(ClientPNames.COOKIE_POLICY, NoValidationCookieSpecFactory.NAME);

						// Add to CookieStore:
						CookieStore store = new RESTClientCookieStore();
						List<HttpCookie> cookies = request.getCookies();
						for(HttpCookie cookie: cookies) {
							BasicClientCookie c = new BasicClientCookie(
									cookie.getName(), cookie.getValue());
							c.setVersion(cookie.getVersion());
							c.setDomain(urlHost);
							c.setPath("/");

							store.addCookie(c);
						}

						// Attach store to client:
						httpclient.setCookieStore(store);
					}    

					// POST/PUT/PATCH/DELETE method specific logic
					if (method instanceof HttpEntityEnclosingRequest) {
						HttpEntityEnclosingRequest eeMethod = (HttpEntityEnclosingRequest) method;

						// Create and set RequestEntity
						ReqEntity bean = request.getBody();
						if (bean != null) {
							try {
								if(bean instanceof ReqEntitySimple) {
									AbstractHttpEntity e = getEntity((ReqEntitySimple)bean);
									eeMethod.setEntity(e);
								}
								else if(bean instanceof ReqEntityMultipart) {
									ReqEntityMultipart multipart = (ReqEntityMultipart)bean;
									MultipartEntity me = new MultipartEntity();
									for(ReqEntityPart part: multipart.getBody()) {
										if(part instanceof ReqEntityStringPart) {
											ReqEntityStringPart p = (ReqEntityStringPart)part;
											String body = p.getPart();
											ContentType ct = p.getContentType();
											StringBody sb = null;
											if(ct != null) {
												sb = new StringBody(body, ct.getContentType(), HttpUtil.getCharsetDefault(ct));
											}
											else {
												sb = new StringBody(body);
											}
											me.addPart(part.getName(), sb);
										}
										else if(part instanceof ReqEntityFilePart) {
											ReqEntityFilePart p = (ReqEntityFilePart)part;
											File body = p.getPart();
											ContentType ct = p.getContentType();
											FileBody fb = null;
											if(ct != null) {
												fb = new FileBody(body, ct.getContentType(), HttpUtil.getCharsetDefault(ct).name());
											}
											else {
												fb = new FileBody(body);
											}
											me.addPart(part.getName(), fb);
										}
									}
									eeMethod.setEntity(me);
								}


							}
							catch (UnsupportedEncodingException ex) {
								return null;
							}
						}
					}

					// SSL

					// Set the hostname verifier:
					final SSLReq sslReq = request.getSslReq();
					if(sslReq != null) {
						SSLHostnameVerifier verifier = sslReq.getHostNameVerifier();
						final X509HostnameVerifier hcVerifier;
						switch(verifier){
						case STRICT:
							hcVerifier = SSLSocketFactory.STRICT_HOSTNAME_VERIFIER;
							break;
						case BROWSER_COMPATIBLE:
							hcVerifier = SSLSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER;
							break;
						case ALLOW_ALL:
							hcVerifier = SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
							break;
						default:
							hcVerifier = SSLSocketFactory.STRICT_HOSTNAME_VERIFIER;
							break;
						}

						// Register the SSL Scheme:
							final String trustStorePath = sslReq.getTrustStore();
						final String keyStorePath = sslReq.getKeyStore();

						final KeyStore trustStore  = StringUtil.isEmpty(trustStorePath)?
								null:
									getKeyStore(trustStorePath, sslReq.getTrustStorePassword());
						final KeyStore keyStore = StringUtil.isEmpty(keyStorePath)?
								null:
									getKeyStore(keyStorePath, sslReq.getKeyStorePassword());

						final TrustStrategy trustStrategy = sslReq.isTrustSelfSignedCert()
								? new TrustSelfSignedStrategy(): null;

								SSLSocketFactory socketFactory = new SSLSocketFactory(
										"TLS", // Algorithm
										keyStore,  // Keystore
										sslReq.getKeyStorePassword()!=null? new String(sslReq.getKeyStorePassword()): null,  // Keystore password
												trustStore,
												null,  // Secure Random
												trustStrategy, // Trust strategy
												hcVerifier);
								Scheme sch = new Scheme(urlProtocol, urlPort, socketFactory);
								httpclient.getConnectionManager().getSchemeRegistry().register(sch);
					}

					// How to handle retries and redirects:
					httpclient.setHttpRequestRetryHandler(new DefaultHttpRequestRetryHandler());
					httpclient.getParams().setParameter(ClientPNames.HANDLE_REDIRECTS,request.isFollowRedirect());

					// Now Execute:
					long startTime = System.currentTimeMillis();
					HttpResponse http_res = httpclient.execute((HttpUriRequest) method,
							httpContext);
					long endTime = System.currentTimeMillis();

					ResponseBean response = new ResponseBean();

					response.setExecutionTime(endTime - startTime);

					response.setStatusCode(http_res.getStatusLine().getStatusCode());
					response.setStatusLine(http_res.getStatusLine().toString());

					final Header[] responseHeaders = http_res.getAllHeaders();
					String contentType = null;
					for (Header header : responseHeaders) {
						response.addHeader(header.getName(), header.getValue());
						if(header.getName().equalsIgnoreCase("content-type")) {
							contentType = header.getValue();
						}
					}

					// find out the charset:
					final Charset charset;
					{
						Charset c;
						if(contentType != null) {
							final String charsetStr = HttpUtil.getCharsetFromContentType(contentType);
							try{
								c = Charset.forName(charsetStr);
							}
							catch(IllegalCharsetNameException ex) {
								c = Charset.defaultCharset();
							}
							catch(UnsupportedCharsetException ex) {
								c = Charset.defaultCharset();
							}
							catch(IllegalArgumentException ex) {
								c = Charset.defaultCharset();
							}
						}
						else {
							c = Charset.defaultCharset();
						}
						charset = c;
					}

					// Response body:
						final HttpEntity entity = http_res.getEntity();
					if(entity != null) {
						if(request.isIgnoreResponseBody()) {
							EntityUtils.consumeQuietly(entity);
						}
						else {
							InputStream is = entity.getContent();
							try{
								byte[] responseBody = StreamUtil.inputStream2Bytes(is);
								if (responseBody != null) {
									response.setResponseBody(responseBody);
								}
							}
							catch(IOException ex) {
							}
						}
					}

					return response;
				} catch (IOException ex) {
					logException(ex);
				} catch (Exception ex) {
					logException(ex);
				} finally {
					if (method != null) {
						httpclient.getConnectionManager().shutdown();
					}
				}

				return null;
	}

	private static void logException(Exception e) {
		StringBuffer stringBuffer = new StringBuffer();
		stringBuffer.append(e.toString());
		for(StackTraceElement stackTraceElement : e.getStackTrace()) {
			stringBuffer.append("\n" + stackTraceElement);
		}
		LOGGER.severe("executeBusinessLogic error: " + stringBuffer.toString());
	}

	static AbstractHttpEntity getEntity(ReqEntitySimple bean)
			throws UnsupportedEncodingException, IOException {
		AbstractHttpEntity entity = null;
		org.apache.http.entity.ContentType contentType = null;
		if (bean.getContentType() != null) {
			org.wiztools.restclient.bean.ContentType ct = bean.getContentType();
			contentType = org.apache.http.entity.ContentType.create(ct.getContentType(), ct.getCharset());
		}
		if (bean instanceof ReqEntityString) {
			entity = new StringEntity(((ReqEntityString) bean).getBody(), contentType);
		}
		else if (bean instanceof ReqEntityByteArray) {
			entity = new ByteArrayEntity(((ReqEntityByteArray) bean).getBody(), contentType);
		}
		else if (bean instanceof ReqEntityStream) {
			entity = new InputStreamEntity(((ReqEntityStream) bean).getBody(),
					((ReqEntityStream) bean).getLength(), contentType);
		}
		else if (bean instanceof ReqEntityFile) {
			entity = new FileEntity(((ReqEntityFile) bean).getBody(), contentType);
		}
		return entity;
	}

	private static KeyStore getKeyStore(String storePath, char[] storePassword)
			throws KeyStoreException, IOException,
			NoSuchAlgorithmException, CertificateException {
		KeyStore store  = KeyStore.getInstance(KeyStore.getDefaultType());
		if(StringUtil.isNotEmpty(storePath)) {
			FileInputStream instream = new FileInputStream(new File(storePath));
			try{
				store.load(instream, storePassword);
			}
			finally{
				instream.close();
			}
		}
		return store;
	}
}
