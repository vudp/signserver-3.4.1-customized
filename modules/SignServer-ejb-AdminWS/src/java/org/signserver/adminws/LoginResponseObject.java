package org.signserver.adminws;

public class LoginResponseObject {
	int code;
	String sessionKey;
	
	public LoginResponseObject() {
	}
    public LoginResponseObject(int code, String sessionKey) {
        this.code = code;
        this.sessionKey = sessionKey;
    }
	
    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public String getSessionKey() {
        return sessionKey;
    }

    public void setSessionKey(String sessionKey) {
        this.sessionKey = sessionKey;
    }
}