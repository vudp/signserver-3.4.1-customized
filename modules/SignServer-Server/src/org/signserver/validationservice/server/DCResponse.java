package org.signserver.validationservice.server;

public class DCResponse {
	
	private int responseCode;
	private String responseMessage;
	private byte[] data;
	private String asynStreamDataPath;
	private String asynStreamSignPath;
	
	public int getResponseCode() {
		return responseCode;
	}
	public void setResponseCode(int responseCode) {
		this.responseCode = responseCode;
	}
	public String getResponseMessage() {
		return responseMessage;
	}
	public void setResponseMessage(String responseMessage) {
		this.responseMessage = responseMessage;
	}
	public byte[] getData() {
		return data;
	}
	public void setData(byte[] data) {
		this.data = data;
	}
	public String getAsynStreamDataPath() {
		return asynStreamDataPath;
	}
	public void setAsynStreamDataPath(String asynStreamDataPath) {
		this.asynStreamDataPath = asynStreamDataPath;
	}
	public String getAsynStreamSignPath() {
		return asynStreamSignPath;
	}
	public void setAsynStreamSignPath(String asynStreamSignPath) {
		this.asynStreamSignPath = asynStreamSignPath;
	}
}