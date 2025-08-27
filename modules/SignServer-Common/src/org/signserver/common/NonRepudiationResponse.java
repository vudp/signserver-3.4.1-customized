package org.signserver.common;

import java.util.*;

public class NonRepudiationResponse {
	
	public static int NONREPUDIATION_CODE_VALIDSIGNATURE = 0;
	public static int NONREPUDIATION_CODE_REVOKED = 1;
	public static int NONREPUDIATION_CODE_ERROR = 2;
	public static int NONREPUDIATION_CODE_INVALIDSIGNATURE = 3;
	
	public static String NONREPUDIATION_MESS_VALIDSIGNATURE = "VALID SIGNATURE";
	public static String NONREPUDIATION_MESS_REVOKED = "REVOKED";
	public static String NONREPUDIATION_MESS_ERROR = "Error while checking signature status. Detail: ";
	public static String NONREPUDIATION_MESS_INVALIDSIGNATURE = "INVALID SIGNATURE";
	
	
	private int responseCode;
	private String responseMessage;
	private String certificate;
	private Date signingTime;
	
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
	
	public String getCertificate() {
		return certificate;
	}
	
	public void setCertificate(String certificate) {
		this.certificate = certificate;
	}
	
	public Date getSigningTime() {
		return signingTime;
	}
	
	public void setSigningTime(Date signingTime) {
		this.signingTime = signingTime;
	}
}