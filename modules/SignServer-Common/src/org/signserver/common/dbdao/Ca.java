package org.signserver.common.dbdao;

public class Ca {
    
    private int caID;
    private String caCode;
    private String caDesc;
    private String ocspUrl;
    private String crlUrl;
    private String crlPath;
    private String cert;
    private boolean isDownloadableCRL;
    
    private String ocspUrl2;
    private String crlUrl2;
    private String crlPath2;
    private String cert2;
    private boolean isDownloadableCRL2;
    
    private boolean isCheckOCSP;
    private boolean isCheckCRL;
    
    private int ocspRetry;
    private int endPointConfigID;
    private int endPointParamsID;
    private String endPointParamsValue;
    
    private int methodValidateCert;
    
    private String subjectKeyIdentifier1;
    private String subjectKeyIdentifier2;
    

    public int getCaID() {
        return caID;
    }

    public void setCaID(int caID) {
        this.caID = caID;
    }

    public String getCaCode() {
        return caCode;
    }

    public void setCaCode(String caCode) {
        this.caCode = caCode;
    }

    public String getCaDesc() {
        return caDesc;
    }

    public void setCaDesc(String caDesc) {
        this.caDesc = caDesc;
    }

    public String getOcspUrl() {
        return ocspUrl;
    }

    public void setOcspUrl(String ocspUrl) {
        this.ocspUrl = ocspUrl;
    }

    public String getCrlUrl() {
        return crlUrl;
    }

    public void setCrlUrl(String crlUrl) {
        this.crlUrl = crlUrl;
    }

    public String getCrlPath() {
        return crlPath;
    }

    public void setCrlPath(String crlPath) {
        this.crlPath = crlPath;
    }

    public String getCert() {
        return cert;
    }

    public void setCert(String cert) {
        this.cert = cert;
    }

    public boolean isIsDownloadableCRL() {
        return isDownloadableCRL;
    }

    public void setIsDownloadableCRL(boolean isDownloadableCRL) {
        this.isDownloadableCRL = isDownloadableCRL;
    }

    public String getOcspUrl2() {
        return ocspUrl2;
    }

    public void setOcspUrl2(String ocspUrl2) {
        this.ocspUrl2 = ocspUrl2;
    }

    public String getCrlUrl2() {
        return crlUrl2;
    }

    public void setCrlUrl2(String crlUrl2) {
        this.crlUrl2 = crlUrl2;
    }

    public String getCrlPath2() {
        return crlPath2;
    }

    public void setCrlPath2(String crlPath2) {
        this.crlPath2 = crlPath2;
    }

    public String getCert2() {
        return cert2;
    }

    public void setCert2(String cert2) {
        this.cert2 = cert2;
    }

    public boolean isIsDownloadableCRL2() {
        return isDownloadableCRL2;
    }

    public void setIsDownloadableCRL2(boolean isDownloadableCRL2) {
        this.isDownloadableCRL2 = isDownloadableCRL2;
    }

    public boolean isIsCheckOCSP() {
        return isCheckOCSP;
    }

    public void setIsCheckOCSP(boolean isCheckOCSP) {
        this.isCheckOCSP = isCheckOCSP;
    }

    public boolean isIsCheckCRL() {
        return isCheckCRL;
    }

    public void setIsCheckCRL(boolean isCheckCRL) {
        this.isCheckCRL = isCheckCRL;
    }

    public int getOcspRetry() {
        return ocspRetry;
    }

    public void setOcspRetry(int ocspRetry) {
        this.ocspRetry = ocspRetry;
    }

    public int getEndPointConfigID() {
        return endPointConfigID;
    }

    public void setEndPointConfigID(int endPointConfigID) {
        this.endPointConfigID = endPointConfigID;
    }

    public int getEndPointParamsID() {
        return endPointParamsID;
    }

    public void setEndPointParamsID(int endPointParamsID) {
        this.endPointParamsID = endPointParamsID;
    }

    public String getEndPointParamsValue() {
        return endPointParamsValue;
    }

    public void setEndPointParamsValue(String endPointParamsValue) {
        this.endPointParamsValue = endPointParamsValue;
    }

    public int getMethodValidateCert() {
        return methodValidateCert;
    }

    public void setMethodValidateCert(int methodValidateCert) {
        this.methodValidateCert = methodValidateCert;
    }

    public String getSubjectKeyIdentifier1() {
        return subjectKeyIdentifier1;
    }

    public void setSubjectKeyIdentifier1(String subjectKeyIdentifier1) {
        this.subjectKeyIdentifier1 = subjectKeyIdentifier1;
    }

    public String getSubjectKeyIdentifier2() {
        return subjectKeyIdentifier2;
    }

    public void setSubjectKeyIdentifier2(String subjectKeyIdentifier2) {
        this.subjectKeyIdentifier2 = subjectKeyIdentifier2;
    }
    
    
    
    
}