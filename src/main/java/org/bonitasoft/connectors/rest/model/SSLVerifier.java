package org.bonitasoft.connectors.rest.model;

/** The SSL verifiers applicable for REST. */
public enum SSLVerifier {
  /** The items; */
  STRICT("Strict"),
  BROWSER("BROWSER COMPATIBLE"),
  ALLOW("ALLOW ALL");

  /** The value of a item. */
  private String value = null;

  /**
   * Constructor to set the value of the created item. Default Constructor.
   *
   * @param value The value of the item.
   */
  SSLVerifier(final String value) {
    this.value = value;
  }

  /**
   * Value getter.
   *
   * @return The value.
   */
  public String getValue() {
    return value;
  }

  /**
   * Get the SSLVerifier value based on a given value, by default STRICT is returned.
   *
   * @param value The value.
   * @return The associated SSLVerifier value.
   */
  public static SSLVerifier getSSLVerifierFromValue(final String value) {
    if (value != null) {
      if (STRICT.value.equals(value)) {
        return SSLVerifier.STRICT;
      }
      if (BROWSER.value.equals(value)) {
        return SSLVerifier.BROWSER;
      }
      if (ALLOW.value.equals(value)) {
        return SSLVerifier.ALLOW;
      }
    }
    return SSLVerifier.STRICT;
  }
}
