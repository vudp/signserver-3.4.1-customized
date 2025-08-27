package org.signserver.u2f.tomica.model;

import com.fasterxml.jackson.databind.util.JSONPObject;
import org.signserver.u2f.json.JSONObject;




public class TokenInfo {
	private String tokenResponse;
	private String username;
	private boolean isSuccess;
	private String error;
	
	public TokenInfo() {
		// TODO Auto-generated constructor stub
	}


	public String getTokenResponse() {
		return tokenResponse;
	}

	public void setTokenResponse(String tokenResponse) {
		this.tokenResponse = tokenResponse;
	}


	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}


	public boolean isSuccess() {
		return isSuccess;
	}


	public void setSuccess(boolean isSuccess) {
		this.isSuccess = isSuccess;
	}


	public String getError() {
		return error;
	}


	public void setError(String error) {
		this.error = error;
	}
	
	public String toJson() {
                JSONObject object = new JSONObject();
                object.put("TokenResponse", tokenResponse);
                object.put("Username", username);
                object.put("IsSuccess", isSuccess);
                object.put("Error", error);
                
                return object.toString();               
	}
}
