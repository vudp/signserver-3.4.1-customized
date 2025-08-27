package org.signserver.common;


public class EndpointServiceResp {
	private int endpointId;
	private int responseCode;
	private byte[] responseData;
	private String responseJsonData;
	
	public EndpointServiceResp() {
		
	}
	
	public EndpointServiceResp(int responseCode, int endpointId) {
		this.responseCode = responseCode;
		this.endpointId = endpointId;
	}
	
	public int getEndpointId() {
		return endpointId;
	}
	public void setEndpointId(int endpointId) {
		this.endpointId = endpointId;
	}
	public int getResponseCode() {
		return responseCode;
	}
	public void setResponseCode(int responseCode) {
		this.responseCode = responseCode;
	}
	public byte[] getResponseData() {
		return responseData;
	}
	public void setResponseData(byte[] responseData) {
		this.responseData = responseData;
	}
	public String getResponseJsonData() {
		return responseJsonData;
	}

	public void setResponseJsonData(String responseJsonData) {
		this.responseJsonData = responseJsonData;
	}
}