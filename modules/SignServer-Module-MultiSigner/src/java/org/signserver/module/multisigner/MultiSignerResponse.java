/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.module.multisigner;

/**
 *
 * @author PHUONGVU
 */
public class MultiSignerResponse {
    private byte[] signedData;
    private int responseCode;
    private String responseMessage;
    private String[] arraydata;
    private Integer endpointId;
    
    public MultiSignerResponse() {
    	
    }

    public MultiSignerResponse(byte[] signedData, int responseCode, String responseMessage) {
        this.signedData = signedData;
        this.responseCode = responseCode;
        this.responseMessage = responseMessage;
    }

    public MultiSignerResponse(int responseCode, String responseMessage) {
        this.responseCode = responseCode;
        this.responseMessage = responseMessage;
    }

    public byte[] getSignedData() {
        return signedData;
    }

    public void setSignedData(byte[] signedData) {
        this.signedData = signedData;
    }

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
    
    public String[] getArrayData() {
    	return this.arraydata;
    }
    
    public void setArrayData(String[] array) {
    	this.arraydata = array;
    }
    
    public Integer getEndpointId() {
		return endpointId;
	}

	public void setEndpointId(Integer endpointId) {
		this.endpointId = endpointId;
	}
}
