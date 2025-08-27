package org.signserver.common;

import java.util.Date;
import java.util.List;

public class SignerInfoResponse {
	private String certificate;
	private boolean isSigning;
	private String serilaNumber;
	private String issuerName;
	private String subjectName;
	private Date notBefore;
	private Date notAfter;
	private Date signingTime;
	
	private int isRevoked;
	private Date revokeTime;
	
	boolean isCRLCheck;
	
	List<OwnerInfo> ownerInfos;
	
	public SignerInfoResponse() {
		
	}
	
    public SignerInfoResponse(String certificate, String serilaNumber, String issuerName, String subjectName, Date notBefore, Date notAfter) {
        this.certificate = certificate;
    	this.serilaNumber = serilaNumber;
        this.issuerName = issuerName;
        this.subjectName = subjectName;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
    }
	
    public String getSerilaNumber() {
        return serilaNumber;
    }

    public void setSerilaNumber(String serilaNumber) {
        this.serilaNumber = serilaNumber;
    }

    public String getIssuerName() {
        return issuerName;
    }

    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

    public String getSubjectName() {
        return subjectName;
    }

    public void setSubjectName(String subjectName) {
        this.subjectName = subjectName;
    }

    public Date getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(Date notBefore) {
        this.notBefore = notBefore;
    }

    public Date getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(Date notAfter) {
        this.notAfter = notAfter;
    }
    
    public Date getSigningTime() {
        return signingTime;
    }

    public void setSigningTime(Date signingTime) {
        this.signingTime = signingTime;
    }

    public int isIsRevoked() {
        return isRevoked;
    }

    public void setIsRevoked(int isRevoked) {
        this.isRevoked = isRevoked;
    }

    public Date getRevokeTime() {
        return revokeTime;
    }

    public void setRevokeTime(Date revokeTime) {
        this.revokeTime = revokeTime;
    }
    
    public boolean isIsCRLCheck() {
        return isCRLCheck;
    }

    public void setIsCRLCheck(boolean isCRLCheck) {
        this.isCRLCheck = isCRLCheck;
    }
    
    public boolean isIsSigning() {
        return isSigning;
    }

    public void setIsSigning(boolean isSigning) {
        this.isSigning = isSigning;
    }
	
	public String getCertificate() {
		return certificate;
	}
	
	public void setCertificate(String certificate) {
		this.certificate = certificate;
	}
	
    public List<OwnerInfo> getOwnerInfos() {
        return ownerInfos;
    }

    public void setOwnerInfos(List<OwnerInfo> ownerInfos) {
        this.ownerInfos = ownerInfos;
    }    
}