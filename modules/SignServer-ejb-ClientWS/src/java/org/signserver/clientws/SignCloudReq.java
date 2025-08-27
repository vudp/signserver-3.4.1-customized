package org.signserver.clientws;

import java.util.List;


public class SignCloudReq {
    private String relyingParty;
    private String agreementID;
    private String mobileNo;
    private String email;
    private String certificateProfile;
    private AgreementDetails agreementDetails;
    private CredentialData credentialData;
    private String signingFileUUID;
    private byte[] signingFileData;
    private String mimeType;
    private String notificationTemplate;
    private String notificationSubject;
    private boolean timestampEnable;
    private String language;
    private String authorizeCode;
    private boolean postbackEnable;
    private int authorizeMethod;
    private byte[] uploadingFileData;
    private String downloadingFileUUID;
    private String currentPasscode;
    private String newPasscode;
    private String hash;
    private String hashAlgorithm;
    private String encryption;
    private String billCode;
    private SignCloudMetaData signCloudMetaData;
    private int messagingMode;
    private int sharedMode;
    private String xslTemplateUUID;
    private String xslTemplate;
    private String xmlDocument;

    
    

    public AgreementDetails getAgreementDetails() {
        return agreementDetails;
    }

    public void setAgreementDetails(AgreementDetails agreementDetails) {
        this.agreementDetails = agreementDetails;
    }

    public String getAgreementID() {
        return agreementID;
    }

    public void setAgreementID(String agreementID) {
        this.agreementID = agreementID;
    }

    public String getCertificateProfile() {
        return certificateProfile;
    }
    
    

    public void setCertificateProfile(String certificateProfile) {
        this.certificateProfile = certificateProfile;
    }

    public CredentialData getCredentialData() {
        return credentialData;
    }

    public void setCredentialData(CredentialData credentialData) {
        this.credentialData = credentialData;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getMobileNo() {
        return mobileNo;
    }

    public void setMobileNo(String mobileNo) {
        this.mobileNo = mobileNo;
    }

    public String getRelyingParty() {
        return relyingParty;
    }

    public void setRelyingParty(String relyingParty) {
        this.relyingParty = relyingParty;
    }

    public String getAuthorizeCode() {
        return authorizeCode;
    }

    public void setAuthorizeCode(String authorizeCode) {
        this.authorizeCode = authorizeCode;
    }

    public int getAuthorizeMethod() {
        return authorizeMethod;
    }

    public void setAuthorizeMethod(int authorizeMethod) {
        this.authorizeMethod = authorizeMethod;
    }

    public byte[] getSigningFileData() {
        return signingFileData;
    }

    public void setSigningFileData(byte[] signingFileData) {
        this.signingFileData = signingFileData;
    }

    public String getLanguage() {
        return language;
    }

    public void setLanguage(String language) {
        this.language = language;
    }

    public String getMimeType() {
        return mimeType;
    }

    public void setMimeType(String mimeType) {
        this.mimeType = mimeType;
    }

    public String getNotificationTemplate() {
        return notificationTemplate;
    }

    public void setNotificationTemplate(String notificationTemplate) {
        this.notificationTemplate = notificationTemplate;
    }

    public boolean isPostbackEnable() {
        return postbackEnable;
    }

    public void setPostbackEnable(boolean postbackEnable) {
        this.postbackEnable = postbackEnable;
    }

    public String getSigningFileUUID() {
        return signingFileUUID;
    }

    public void setSigningFileUUID(String signingFileUUID) {
        this.signingFileUUID = signingFileUUID;
    }

    public int getSharedMode() {
        return sharedMode;
    }

    public void setSharedMode(int sharedMode) {
        this.sharedMode = sharedMode;
    }

    public boolean isTimestampEnable() {
        return timestampEnable;
    }

    public void setTimestampEnable(boolean timestampEnable) {
        this.timestampEnable = timestampEnable;
    }

    public String getCurrentPasscode() {
        return currentPasscode;
    }

    public void setCurrentPasscode(String currentPasscode) {
        this.currentPasscode = currentPasscode;
    }

    public String getDownloadingFileUUID() {
        return downloadingFileUUID;
    }

    public void setDownloadingFileUUID(String downloadingFileUUID) {
        this.downloadingFileUUID = downloadingFileUUID;
    }

    public String getEncryption() {
        return encryption;
    }

    public void setEncryption(String encryption) {
        this.encryption = encryption;
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    public void setHashAlgorithm(String hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    public String getNewPasscode() {
        return newPasscode;
    }

    public void setNewPasscode(String newPasscode) {
        this.newPasscode = newPasscode;
    }

    public byte[] getUploadingFileData() {
        return uploadingFileData;
    }

    public void setUploadingFileData(byte[] uploadingFileData) {
        this.uploadingFileData = uploadingFileData;
    }

    public String getNotificationSubject() {
        return notificationSubject;
    }

    public void setNotificationSubject(String notificationSubject) {
        this.notificationSubject = notificationSubject;
    }

    public String getBillCode() {
        return billCode;
    }

    public void setBillCode(String billCode) {
        this.billCode = billCode;
    }

    public SignCloudMetaData getSignCloudMetaData() {
        return signCloudMetaData;
    }

    public void setSignCloudMetaData(SignCloudMetaData signCloudMetaData) {
        this.signCloudMetaData = signCloudMetaData;
    }

    public int getMessagingMode() {
        return messagingMode;
    }

    public void setMessagingMode(int messagingMode) {
        this.messagingMode = messagingMode;
    }

    public String getXmlDocument() {
        return xmlDocument;
    }

    public void setXmlDocument(String xmlDocument) {
        this.xmlDocument = xmlDocument;
    }

    public String getXslTemplate() {
        return xslTemplate;
    }

    public void setXslTemplate(String xslTemplate) {
        this.xslTemplate = xslTemplate;
    }

    public String getXslTemplateUUID() {
        return xslTemplateUUID;
    }

    public void setXslTemplateUUID(String xslTemplateUUID) {
        this.xslTemplateUUID = xslTemplateUUID;
    }
    
}