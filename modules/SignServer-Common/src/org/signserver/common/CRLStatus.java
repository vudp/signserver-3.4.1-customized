package org.signserver.common;

import java.util.Date;

public class CRLStatus {
	private String certificateState;
	private boolean isRevoked;
	public static String REVOKED		= "REVOKED";
	public static String GOOD 			= "GOOD";
	public static String DATENOTVALID	= "The certificate has expied or is not yet valid";
	public static String ERROR	 		= "ERROR GETTING CERTIFICATE STATUS";
	public static Date revokeDate;
	
	public CRLStatus(String certStatus, boolean isRevoked) {
		this.certificateState = certStatus;
		this.isRevoked = isRevoked;
	}
	
	public CRLStatus(String certStatus, Date revokeDate) {
		this.certificateState = certStatus;
		this.isRevoked = true;
		this.revokeDate = revokeDate;
	}
	
	public void setRevokeDate(Date revokeDate) {
		this.revokeDate = revokeDate;
	}
	
	public Date getRevokeDate() {
		return this.revokeDate;
	}
	
	public String getCertificateState() {
		return this.certificateState;
	}
	
	public boolean getIsRevoked() {
		return this.isRevoked;
	}
}
