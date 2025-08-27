package org.signserver.common;

public class SocketRequestObject {
    private byte[] requestData;
    private String timeSystem;
    private String ip;

    public SocketRequestObject(byte[] requestData, String timeSystem, String ip) {
    	this.requestData = requestData;
    	this.timeSystem = timeSystem;
    	this.ip = ip;
    }
    
    public byte[] getRequestData() {
        return requestData;
    }

    public void setRequestData(byte[] requestData) {
        this.requestData = requestData;
    }

    public String getTimeSystem() {
        return timeSystem;
    }

    public void setTimeSystem(String timeSystem) {
        this.timeSystem = timeSystem;
    }
    
    public String getIp() {
    	return ip;
    }
    
    public void setIp(String ip) {
    	this.ip = ip;
    }
}