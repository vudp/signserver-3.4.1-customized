package org.signserver.validationservice.server;

import java.util.*;
import org.signserver.common.*;
import org.signserver.common.util.*;
import org.signserver.common.dbdao.*;

public class MultiValidatorResponse {
	private int responseCode;
	private String responseMessage;
	private List<SignerInfoResponse> listSignerInfoResponse;
	
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
	public List<SignerInfoResponse> getListSignerInfoResponse() {
		return listSignerInfoResponse;
	}
	public void setListSignerInfoResponse(
			List<SignerInfoResponse> listSignerInfoResponse) {
		this.listSignerInfoResponse = listSignerInfoResponse;
	}
	
}