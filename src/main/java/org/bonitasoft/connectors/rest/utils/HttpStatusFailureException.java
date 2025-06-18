package org.bonitasoft.connectors.rest.utils;

public class HttpStatusFailureException extends RuntimeException {

    public HttpStatusFailureException(int statusCode) {
        super(String.format("End-point returned status code %s", statusCode));
    }
}
