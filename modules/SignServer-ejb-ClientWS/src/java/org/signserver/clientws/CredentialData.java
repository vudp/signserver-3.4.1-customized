package org.signserver.clientws;

public class CredentialData {
    private String username;
    private String password;
    private String signature;
    private String pkcs1Signature;
    private String timestamp;

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getPkcs1Signature() {
        return pkcs1Signature;
    }

    public void setPkcs1Signature(String pkcs1Signature) {
        this.pkcs1Signature = pkcs1Signature;
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

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
}