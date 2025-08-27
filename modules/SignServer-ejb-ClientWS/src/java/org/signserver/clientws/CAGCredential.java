package org.signserver.clientws;
public class CAGCredential {
    private String username;

    private String password;

    private String signature;

    private String timestamp;
    
    private String pkcs1Signature;

    public CAGCredential() {
    }

    public CAGCredential(String username, String password
    		, String signature, String timestamp, String pkcs1Signature) {
        this.username = username;
        this.password = password;
        this.signature = signature;
        this.timestamp = timestamp;
        this.pkcs1Signature = pkcs1Signature;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }
    
    public String getPkcs1Signature() {
        return pkcs1Signature;
    }

    public void setPkcs1Signature(String pkcs1Signature) {
        this.pkcs1Signature = pkcs1Signature;
    }
}