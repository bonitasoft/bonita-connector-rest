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

public class RESTResult implements Serializable {

    private static final long serialVersionUID = 1L;
    private String entity = null;
    private List<RESTResultKeyValueMap> header = new ArrayList();
    private long time = 0L;
    private int statusCode = 0;
    private String statusLine = null;

    public String getEntity() {
        return this.entity;
    }

    public void setEntity(String newEntity) {
        this.entity = newEntity;
    }

    public List<RESTResultKeyValueMap> getHeader() {
        return this.header;
    }

    public void setHeader(List<RESTResultKeyValueMap> newHeader) {
        this.header = newHeader;
    }

    public long getTime() {
        return this.time;
    }

    public void setTime(long newTime) {
        this.time = newTime;
    }

    public int getStatusCode() {
        return this.statusCode;
    }

    public void setStatusCode(int newStatusCode) {
        this.statusCode = newStatusCode;
    }

    public String getStatusLine() {
        return this.statusLine;
    }

    public void setStatusLine(String newStatusLine) {
        this.statusLine = newStatusLine;
    }

    public String toString() {
        return "RESTResult  [entity: " + getEntity() + "]" + " [time: " + getTime() + "]" + " [statusCode: " + getStatusCode() + "]" + " [statusLine: "
                + getStatusLine() + "]";
    }
}
