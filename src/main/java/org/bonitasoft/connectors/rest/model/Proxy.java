package org.bonitasoft.connectors.rest.model;

/** This class reflects the Proxy settings of a HTTP request. */
public class Proxy {

  /** The protocol value. */
  private ProxyProtocol protocol = ProxyProtocol.HTTP;

  /** The host value. */
  private String host = null;

  /** The host value. */
  private Integer port = null;

  /** The username value. */
  private String username = null;

  /** The password value. */
  private String password = null;

  /**
   * Protocol value getter.
   *
   * @return The protocol value.
   */
  public ProxyProtocol getProtocol() {
    return protocol;
  }

  /**
   * Protocol value setter.
   *
   * @param protocol The new protocol value.
   */
  public void setProtocol(ProxyProtocol protocol) {
    this.protocol = protocol;
  }

  /**
   * Host value getter.
   *
   * @return The host value.
   */
  public String getHost() {
    return host;
  }

  /**
   * Host value setter.
   *
   * @param host The new host value.
   */
  public void setHost(String host) {
    this.host = host;
  }

  /**
   * Port value getter.
   *
   * @return The port value.
   */
  public Integer getPort() {
    return port;
  }

  /**
   * Port value setter.
   *
   * @param port The new port value.
   */
  public void setPort(Integer port) {
    this.port = port;
  }

  /**
   * Username value getter.
   *
   * @return The username value.
   */
  public String getUsername() {
    return username;
  }

  /**
   * Username value setter.
   *
   * @param username The new username value.
   */
  public void setUsername(final String username) {
    this.username = username;
  }

  /**
   * Password value getter.
   *
   * @return The password value.
   */
  public String getPassword() {
    return password;
  }

  /**
   * Password value setter.
   *
   * @param password The new password value.
   */
  public void setPassword(final String password) {
    this.password = password;
  }

  /**
   * Check if it has credentials.
   *
   * @return if it has credentials.
   */
  public boolean hasCredentials() {
    return this.username != null && !this.username.isEmpty();
  }
}
