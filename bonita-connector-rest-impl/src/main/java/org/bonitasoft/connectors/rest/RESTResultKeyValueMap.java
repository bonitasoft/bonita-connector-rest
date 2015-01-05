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
 * The key value object of the result of a REST Connector
 */
public class RESTResultKeyValueMap implements Serializable {

    /**
     * The serial version
     */
    private static final long serialVersionUID = 1L;
    
    /**
     * The key of the element
     */
    private String key = null;
    
    /**
     * The value of the element which is a list of values
     */
    private List<String> value = new ArrayList<String>();

    /**
     * Get the key
     * @return the key
     */
    public String getKey() {
        return this.key;
    }

    /**
     * Set the key
     * @param newKey the key
     */
    public void setKey(final String newKey) {
        this.key = newKey;
    }

    /**
     * Get the value
     * @return the value
     */
    public List<String> getValue() {
        return this.value;
    }

    /**
     * Set the value
     * @param newValue the value
     */
    public void setValue(final List<String> newValue) {
        this.value = newValue;
    }

    @Override
    public String toString() {
        return "RESTResultKeyValueMap  [key: " + getKey() + "]";
    }
}
