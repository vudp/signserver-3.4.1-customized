package org.signserver.common.dbdao;

public class EndPointConfig {
	private int endPointConfigID;
    private String endPointConfigCode;
    private String endPointConfigDesc;
    private String url;
    private String appID;
    private int keyID;
    private String keyValue;
    private String hostname;

    public int getEndPointConfigID() {
        return endPointConfigID;
    }

    public void setEndPointConfigID(int endPointConfigID) {
        this.endPointConfigID = endPointConfigID;
    }

    public String getEndPointConfigCode() {
        return endPointConfigCode;
    }

    public void setEndPointConfigCode(String endPointConfigCode) {
        this.endPointConfigCode = endPointConfigCode;
    }

    public String getEndPointConfigDesc() {
        return endPointConfigDesc;
    }

    public void setEndPointConfigDesc(String endPointConfigDesc) {
        this.endPointConfigDesc = endPointConfigDesc;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getAppID() {
        return appID;
    }

    public void setAppID(String appID) {
        this.appID = appID;
    }

    public int getKeyID() {
        return keyID;
    }

    public void setKeyID(int keyID) {
        this.keyID = keyID;
    }

    public String getKeyValue() {
        return keyValue;
    }

    public void setKeyValue(String keyValue) {
        this.keyValue = keyValue;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }
}