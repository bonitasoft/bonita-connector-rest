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
