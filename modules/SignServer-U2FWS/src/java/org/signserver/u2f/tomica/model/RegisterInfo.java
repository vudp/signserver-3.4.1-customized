package org.signserver.u2f.tomica.model;


public class RegisterInfo {

	private String username;
	private String requestId;
	private String registerData;
	
	public RegisterInfo() {
	}

	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	

	public String getRequestId() {
		return requestId;
	}
	public void setRequestId(String requestId) {
		this.requestId = requestId;
	}
	

	public String getRegisterData() {
		return registerData;
	}
	public void setRegisterData(String registerData) {
		this.registerData = registerData;
	}
	
	
}
