package org.signserver.clientws;

public class ProcessValidatorResp {
	private int responseCode;
	private String xmlData;
	private String signedData;
	private Integer preTrustedHubTransId;
	private byte[] fileData;
	
	public int getResponseCode() {
        return responseCode;
    }

    public void setResponseCode(int responseCode) {
        this.responseCode = responseCode;
    }

    public String getXmlData() {
        return xmlData;
    }

    public void setXmlData(String xmlData) {
        this.xmlData = xmlData;
    }

    public String getSignedData() {
        return signedData;
    }

    public void setSignedData(String signedData) {
        this.signedData = signedData;
    }
    
    public Integer getPreTrustedHubTransId() {
        return preTrustedHubTransId;
    }

    public void setPreTrustedHubTransId(Integer preTrustedHubTransId) {
        this.preTrustedHubTransId = preTrustedHubTransId;
    }
    
    public byte[] getFileData() {
        return fileData;
    }

    public void setFileData(byte[] fileData) {
        this.fileData = fileData;
    }
}