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

public class RESTResultKeyValueMap implements Serializable {
	private static final long serialVersionUID = 1L;
	private String key = null;
	private List<String> value = new ArrayList();

	public String getKey() {
		return this.key;
	}

	public void setKey(String newKey) {
		this.key = newKey;
	}

	public List<String> getValue() {
		return this.value;
	}

	public void setValue(List<String> newValue) {
		this.value = newValue;
	}

	public String toString() {
		return "RESTResultKeyValueMap  [key: " + getKey() + "]";
	}
}
