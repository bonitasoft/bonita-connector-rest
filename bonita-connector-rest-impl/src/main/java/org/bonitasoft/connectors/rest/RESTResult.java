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
		return "RESTResult  [entity: " + getEntity() + "]" + " [time: " + getTime() + "]" + " [statusCode: " + getStatusCode() + "]" + " [statusLine: " + getStatusLine() + "]";
	}
}
