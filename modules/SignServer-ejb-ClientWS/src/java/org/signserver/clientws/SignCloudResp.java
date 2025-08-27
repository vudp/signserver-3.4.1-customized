package org.signserver.clientws;

import java.util.Date;


public class SignCloudResp {
    private int responseCode;
    private String responseMessage;
    private String billCode;
    private String notificationMessage;
    private int remainingCounter;
    private byte[] signedFileData;
    private String authorizeCredential;
    private String signedFileUUID;
    private String mimeType;
    private String certificateDN;
    private String certificateSerialNumber;
    private String certificateThumbprint;
    private Date validFrom;
    private Date validTo;
    private String issuerDN;
    private String uploadedFileUUID;
    private String downloadedFileUUID;
    private byte[] downloadedFileData;
    private String signatureValue;
    private int authorizeMethod;
    private String notificationSubject;
    
    
    

    public String getBillCode() {
        return billCode;
    }

    public void setBillCode(String billCode) {
        this.billCode = billCode;
    }

    public String getNotificationMessage() {
        return notificationMessage;
    }

    public void setNotificationMessage(String notificationMessage) {
        this.notificationMessage = notificationMessage;
    }

    public int getRemainingCounter() {
        return remainingCounter;
    }

    public void setRemainingCounter(int remainingCounter) {
        this.remainingCounter = remainingCounter;
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

    public byte[] getSignedFileData() {
        return signedFileData;
    }

    public void setSignedFileData(byte[] signedFileData) {
        this.signedFileData = signedFileData;
    }

    public String getAuthorizeCredential() {
        return authorizeCredential;
    }

    public void setAuthorizeCredential(String authorizeCredential) {
        this.authorizeCredential = authorizeCredential;
    }

    public String getCertificateDN() {
        return certificateDN;
    }

    public void setCertificateDN(String certificateDN) {
        this.certificateDN = certificateDN;
    }

    public String getCertificateSerialNumber() {
        return certificateSerialNumber;
    }

    public void setCertificateSerialNumber(String certificateSerialNumber) {
        this.certificateSerialNumber = certificateSerialNumber;
    }

    public String getCertificateThumbprint() {
        return certificateThumbprint;
    }

    public void setCertificateThumbprint(String certificateThumbprint) {
        this.certificateThumbprint = certificateThumbprint;
    }

    public String getIssuerDN() {
        return issuerDN;
    }

    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    public String getMimeType() {
        return mimeType;
    }

    public void setMimeType(String mimeType) {
        this.mimeType = mimeType;
    }

    public String getSignedFileUUID() {
        return signedFileUUID;
    }

    public void setSignedFileUUID(String signedFileUUID) {
        this.signedFileUUID = signedFileUUID;
    }

    public Date getValidFrom() {
        return validFrom;
    }

    public void setValidFrom(Date validFrom) {
        this.validFrom = validFrom;
    }

    public Date getValidTo() {
        return validTo;
    }

    public void setValidTo(Date validTo) {
        this.validTo = validTo;
    }

    public byte[] getDownloadedFileData() {
        return downloadedFileData;
    }

    public void setDownloadedFileData(byte[] downloadedFileData) {
        this.downloadedFileData = downloadedFileData;
    }

    public String getDownloadedFileUUID() {
        return downloadedFileUUID;
    }

    public void setDownloadedFileUUID(String downloadedFileUUID) {
        this.downloadedFileUUID = downloadedFileUUID;
    }

    public String getSignatureValue() {
        return signatureValue;
    }

    public void setSignatureValue(String signatureValue) {
        this.signatureValue = signatureValue;
    }

    public String getUploadedFileUUID() {
        return uploadedFileUUID;
    }

    public void setUploadedFileUUID(String uploadedFileUUID) {
        this.uploadedFileUUID = uploadedFileUUID;
    }

    public int getAuthorizeMethod() {
        return authorizeMethod;
    }

    public void setAuthorizeMethod(int authorizeMethod) {
        this.authorizeMethod = authorizeMethod;
    }

    public String getNotificationSubject() {
        return notificationSubject;
    }

    public void setNotificationSubject(String notificationSubject) {
        this.notificationSubject = notificationSubject;
    }
    
    
}