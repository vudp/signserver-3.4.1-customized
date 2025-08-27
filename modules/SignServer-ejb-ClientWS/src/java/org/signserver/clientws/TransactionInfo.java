package org.signserver.clientws;

public class TransactionInfo {
    private CAGCredential credentialData;
    private String xmlData;
    private byte[] fileData;
    private String base64FileData;

    public TransactionInfo() {
    }

    public TransactionInfo(CAGCredential credentialData, String xmlData, byte[] fileData) {
        this.credentialData = credentialData;
        this.xmlData = xmlData;
        this.fileData = fileData;
    }
    
    public TransactionInfo(String xmlData) {
        this.credentialData = null;
        this.xmlData = xmlData;
        this.fileData = null;
    }
    
    public TransactionInfo(String xmlData, byte[] fileData) {
        this.credentialData = null;
        this.xmlData = xmlData;
        this.fileData = fileData;
    }
    
    

    public CAGCredential getCredentialData() {
        return credentialData;
    }

    public void setCredentialData(CAGCredential credentialData) {
        this.credentialData = credentialData;
    }

    public String getXmlData() {
        return xmlData;
    }

    public void setXmlData(String xmlData) {
        this.xmlData = xmlData;
    }

    public byte[] getFileData() {
        return fileData;
    }

    public void setFileData(byte[] fileData) {
        this.fileData = fileData;
    }
    
    public String getBase64FileData() {
        return base64FileData;
    }

    public void setBase64FileData(String base64FileData) {
        this.base64FileData = base64FileData;
    }
}