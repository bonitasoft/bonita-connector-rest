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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * The REST Connector result object
 */
public class RESTResult implements Serializable {

    /**
     * The serial version
     */
    private static final long serialVersionUID = 1L;
    
    /**
     * The entity of the result
     */
    private String entity = null;
    
    /**
     * The headers of the result
     */
    private List<RESTResultKeyValueMap> header = new ArrayList<RESTResultKeyValueMap>();
    
    /**
     * The execution time
     */
    private long time = 0L;
    
    /**
     * The HTTP status code
     */
    private int statusCode = 0;
    
    /**
     * The status message
     */
    private String statusLine = null;

    /**
     * Get the entity
     * @return the entity
     */
    public String getEntity() {
        return this.entity;
    }

    /**
     * Set the entity
     * @param newEntity the entity
     */
    public void setEntity(final String newEntity) {
        this.entity = newEntity;
    }

    /**
     * Get the headers
     * @return the headers
     */
    public List<RESTResultKeyValueMap> getHeader() {
        return this.header;
    }

    /**
     * Set the headers
     * @param newHeader the headers
     */
    public void setHeader(final List<RESTResultKeyValueMap> newHeader) {
        this.header = newHeader;
    }

    /**
     * Get the execution time
     * @return the execution time
     */
    public long getTime() {
        return this.time;
    }

    /**
     * Set the execution time
     * @param newTime the execution time
     */
    public void setTime(final long newTime) {
        this.time = newTime;
    }

    /**
     * Get the HTTP status code
     * @return the HTTP status code
     */
    public int getStatusCode() {
        return this.statusCode;
    }

    /**
     * Set the HTTP status code
     * @param newStatusCode the HTTP status code
     */
    public void setStatusCode(final int newStatusCode) {
        this.statusCode = newStatusCode;
    }

    /**
     * Get status message
     * @return the status message
     */
    public String getStatusLine() {
        return this.statusLine;
    }

    /**
     * Get the status message 
     * @param newStatusLine the status message
     */
    public void setStatusLine(final String newStatusLine) {
        this.statusLine = newStatusLine;
    }

    @Override
    public String toString() {
        return "RESTResult  [entity: " + getEntity() + "]" + " [time: " + getTime() + "]" + " [statusCode: " + getStatusCode() + "]" + " [statusLine: "
                + getStatusLine() + "]";
    }
}
