package org.signserver.common;

import java.util.Date;

public class OcspStatus {
	private String certificateState;
	private boolean isValid;
	public static String REVOKED = "REVOKED";
	public static String UNKNOWN = "UNKNOWN";
	public static String GOOD	 = "GOOD";
	public static String ERROR	 = "ERROR GETTING CERTIFICATE STATUS";
	public static String DATENOTVALID	= "The certificate has expied or is not yet valid";
	public static Date revokeDate;
	private Integer endpointId;
	
	public OcspStatus(String certStatus, boolean isValid, Integer endpointId) {
		this.certificateState = certStatus;
		this.isValid = isValid;
		this.endpointId = endpointId;
		this.revokeDate = null;
	}
	
	public OcspStatus(String certStatus, boolean isValid, Integer endpointId, Date revokeDate) {
		this.certificateState = certStatus;
		this.isValid = isValid;
		this.endpointId = endpointId;
		this.revokeDate = revokeDate;
	}
	
	public OcspStatus(String certStatus, boolean isValid) {
		this.certificateState = certStatus;
		this.isValid = isValid;
	}
	
	public OcspStatus(String certStatus, Date revokeDate) {
		this.certificateState = REVOKED;
		this.revokeDate = revokeDate;
		this.isValid = false;
	}
	
	public String getCertificateState() {
		return this.certificateState;
	}
	
	public boolean getIsValid() {
		return this.isValid;
	}
	
	public Integer getEndpointId() {
		return endpointId;
	}

	public void setEndpointId(Integer endpointId) {
		this.endpointId = endpointId;
	}
	
	public void setRevokeDate(Date revokeDate) {
		this.revokeDate = revokeDate;
	}
	
	public Date getRevokeDate() {
		return this.revokeDate;
	}
}
