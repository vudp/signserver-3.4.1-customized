package org.signserver.common.dbdao;

import java.util.Date;

public class EndPointParams {
	private int endPointParamsID;
    private String endPointParamsCode;
    private String endPointParamsDesc;
    private String endPointParamsValue;
    private int endPointConfigID;
    private int endPointGroupParamsID;

    public int getEndPointParamsID() {
        return endPointParamsID;
    }

    public void setEndPointParamsID(int endPointParamsID) {
        this.endPointParamsID = endPointParamsID;
    }

    public String getEndPointParamsCode() {
        return endPointParamsCode;
    }

    public void setEndPointParamsCode(String endPointParamsCode) {
        this.endPointParamsCode = endPointParamsCode;
    }

    public String getEndPointParamsDesc() {
        return endPointParamsDesc;
    }

    public void setEndPointParamsDesc(String endPointParamsDesc) {
        this.endPointParamsDesc = endPointParamsDesc;
    }

    public String getEndPointParamsValue() {
        return endPointParamsValue;
    }

    public void setEndPointParamsValue(String endPointParamsValue) {
        this.endPointParamsValue = endPointParamsValue;
    }

    public int getEndPointConfigID() {
        return endPointConfigID;
    }

    public void setEndPointConfigID(int endPointConfigID) {
        this.endPointConfigID = endPointConfigID;
    }

    public int getEndPointGroupParamsID() {
        return endPointGroupParamsID;
    }

    public void setEndPointGroupParamsID(int endPointGroupParamsID) {
        this.endPointGroupParamsID = endPointGroupParamsID;
    }
}