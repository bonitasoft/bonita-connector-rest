package org.bonitasoft.connectors.rest.model;


public class Content {
    
    private String contentType = null;
    
    private RESTCharsets charset = null;

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public RESTCharsets getCharset() {
        return charset;
    }

    public void setCharset(RESTCharsets charset) {
        this.charset = charset;
    }

    public String getContent() {
        String charsetStr = "";
        if(charset != null && !charset.toString().isEmpty()) {
            charsetStr = "; charset=";
        }
        return contentType + charsetStr;
    }
}
