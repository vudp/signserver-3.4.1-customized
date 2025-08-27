package org.signserver.common.dbdao;



public class Tsa {
	private String tsaUrl;
	private String user;
	private String password;
	private int endpointConfigId;
	private String ocspUrl;
	private String crlUrl;
	private String crlPath;
	private String thumbprint;
	private String tsaCACert;
	private boolean checkOcsp;
	private boolean checkCrl;
	private int checkOcspRetry;
	
	public String getTsaUrl() {
        return tsaUrl;
    }

    public void setTsaUrl(String tsaUrl) {
        this.tsaUrl = tsaUrl;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public int getEndpointConfigId() {
        return endpointConfigId;
    }

    public void setEndpointConfigId(int endpointConfigId) {
        this.endpointConfigId = endpointConfigId;
    }
    
    public String getOcspUrl() {
        return ocspUrl;
    }

    public void setOcspUrl(String ocspUrl) {
        this.ocspUrl = ocspUrl;
    }

    public String getCrlUrl() {
        return crlUrl;
    }

    public void setCrlUrl(String crlUrl) {
        this.crlUrl = crlUrl;
    }

    public String getCrlPath() {
        return crlPath;
    }

    public void setCrlPath(String crlPath) {
        this.crlPath = crlPath;
    }

    public String getThumbprint() {
        return thumbprint;
    }

    public void setThumbprint(String thumbprint) {
        this.thumbprint = thumbprint;
    }

    public String getTsaCACert() {
        return tsaCACert;
    }

    public void setTsaCACert(String tsaCACert) {
        this.tsaCACert = tsaCACert;
    }

    public boolean isCheckOcsp() {
        return checkOcsp;
    }

    public void setCheckOcsp(boolean checkOcsp) {
        this.checkOcsp = checkOcsp;
    }

    public boolean isCheckCrl() {
        return checkCrl;
    }

    public void setCheckCrl(boolean checkCrl) {
        this.checkCrl = checkCrl;
    }

    public int getCheckOcspRetry() {
        return checkOcspRetry;
    }

    public void setCheckOcspRetry(int checkOcspRetry) {
        this.checkOcspRetry = checkOcspRetry;
    }
	
}