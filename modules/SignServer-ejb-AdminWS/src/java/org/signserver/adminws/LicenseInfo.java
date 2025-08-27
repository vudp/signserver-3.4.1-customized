package org.signserver.adminws;

import java.util.Date;


public class LicenseInfo {
	
	private int statusCode;
	private String statusDescription;
	private Date validFrom;
	private Date validTo;
	private long dayRemain;
	private String licenseType;
	
	private boolean isPdfSigner;
	private boolean isOfficeSigner;
	private boolean isXmlSigner;
	private boolean isMrtdSigner;

	private boolean isPdfValidator;
	private boolean isOfficeValidator;
	private boolean isXmlValidator;
	private boolean isFidoValidator;
	private boolean isOathValidator;
	private boolean isMultiValidator;
	private boolean isSignatureValidator;
	private boolean isGeneralValidator;
	private boolean isMobileOtp;
	private boolean isCmsSigner;
	private boolean isPkcs1Signer;
	private boolean isCmsValidator;
	private boolean isPkcs1Validator;
	private boolean isDcSigner;
	private boolean isMultiSigner;
	private boolean isSignerAp;

	private String certificateLicenseType;
	private int certificateLicenseNo;

	private String perFormanceLicenseType;
	private int perFormanceLicenseNo;
	
	
	public int getStatusCode() {
		return statusCode;
	}
	public void setStatusCode(int statusCode) {
		this.statusCode = statusCode;
	}
	public String getStatusDescription() {
		return statusDescription;
	}
	public void setStatusDescription(String statusDescription) {
		this.statusDescription = statusDescription;
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
	public long getDayRemain() {
		return dayRemain;
	}
	public void setDayRemain(long dayRemain) {
		this.dayRemain = dayRemain;
	}
	public String getLicenseType() {
		return licenseType;
	}
	public void setLicenseType(String licenseType) {
		this.licenseType = licenseType;
	}
	public boolean isPdfSigner() {
		return isPdfSigner;
	}
	public void setPdfSigner(boolean isPdfSigner) {
		this.isPdfSigner = isPdfSigner;
	}
	public boolean isOfficeSigner() {
		return isOfficeSigner;
	}
	public void setOfficeSigner(boolean isOfficeSigner) {
		this.isOfficeSigner = isOfficeSigner;
	}
	public boolean isXmlSigner() {
		return isXmlSigner;
	}
	public void setXmlSigner(boolean isXmlSigner) {
		this.isXmlSigner = isXmlSigner;
	}
	public boolean isMrtdSigner() {
		return isMrtdSigner;
	}
	public void setMrtdSigner(boolean isMrtdSigner) {
		this.isMrtdSigner = isMrtdSigner;
	}
	public boolean isPdfValidator() {
		return isPdfValidator;
	}
	public void setPdfValidator(boolean isPdfValidator) {
		this.isPdfValidator = isPdfValidator;
	}
	public boolean isOfficeValidator() {
		return isOfficeValidator;
	}
	public void setOfficeValidator(boolean isOfficeValidator) {
		this.isOfficeValidator = isOfficeValidator;
	}
	public boolean isXmlValidator() {
		return isXmlValidator;
	}
	public void setXmlValidator(boolean isXmlValidator) {
		this.isXmlValidator = isXmlValidator;
	}
	public boolean isFidoValidator() {
		return isFidoValidator;
	}
	public void setFidoValidator(boolean isFidoValidator) {
		this.isFidoValidator = isFidoValidator;
	}
	public boolean isOathValidator() {
		return isOathValidator;
	}
	public void setOathValidator(boolean isOathValidator) {
		this.isOathValidator = isOathValidator;
	}
	public boolean isMobileOtp() {
		return isMobileOtp;
	}
	public void setMobileOtp(boolean isMobileOtp) {
		this.isMobileOtp = isMobileOtp;
	}
	public boolean isCmsSigner() {
		return isCmsSigner;
	}
	public void setCmsSigner(boolean isCmsSigner) {
		this.isCmsSigner = isCmsSigner;
	}
	public boolean isPkcs1Signer() {
		return isPkcs1Signer;
	}
	public void setPkcs1Signer(boolean isPkcs1Signer) {
		this.isPkcs1Signer = isPkcs1Signer;
	}
	public boolean isCmsValidator() {
		return isCmsValidator;
	}
	public void setCmsValidator(boolean isCmsValidator) {
		this.isCmsValidator = isCmsValidator;
	}
	public boolean isPkcs1Validator() {
		return isPkcs1Validator;
	}
	public void setPkcs1Validator(boolean isPkcs1Validator) {
		this.isPkcs1Validator = isPkcs1Validator;
	}
	public boolean isDcSigner() {
		return isDcSigner;
	}
	public void setDcSigner(boolean isDcSigner) {
		this.isDcSigner = isDcSigner;
	}
	public boolean isMultiSigner() {
		return isMultiSigner;
	}
	public void setMultiSigner(boolean isMultiSigner) {
		this.isMultiSigner = isMultiSigner;
	}
	public boolean isSignerAp() {
		return isSignerAp;
	}
	public void setSignerAp(boolean isSignerAp) {
		this.isSignerAp = isSignerAp;
	}
	public String getCertificateLicenseType() {
		return certificateLicenseType;
	}
	public void setCertificateLicenseType(String certificateLicenseType) {
		this.certificateLicenseType = certificateLicenseType;
	}
	public int getCertificateLicenseNo() {
		return certificateLicenseNo;
	}
	public void setCertificateLicenseNo(int certificateLicenseNo) {
		this.certificateLicenseNo = certificateLicenseNo;
	}
	public String getPerFormanceLicenseType() {
		return perFormanceLicenseType;
	}
	public void setPerFormanceLicenseType(String perFormanceLicenseType) {
		this.perFormanceLicenseType = perFormanceLicenseType;
	}
	public int getPerFormanceLicenseNo() {
		return perFormanceLicenseNo;
	}
	public void setPerFormanceLicenseNo(int perFormanceLicenseNo) {
		this.perFormanceLicenseNo = perFormanceLicenseNo;
	}
	public boolean isMultiValidator() {
		return isMultiValidator;
	}
	public void setMultiValidator(boolean isMultiValidator) {
		this.isMultiValidator = isMultiValidator;
	}
	public boolean isSignatureValidator() {
		return isSignatureValidator;
	}
	public void setSignatureValidator(boolean isSignatureValidator) {
		this.isSignatureValidator = isSignatureValidator;
	}
	public boolean isGeneralValidator() {
		return isGeneralValidator;
	}
	public void setGeneralValidator(boolean isGeneralValidator) {
		this.isGeneralValidator = isGeneralValidator;
	}
}