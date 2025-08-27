package org.signserver.common.dbdao;

import java.util.Date;

public class ReceiverHAStatus {
	
	private int receiverHAStatusID;
    private String fullName;
    private String email;
    private String phoneNo;

    public int getReceiverHAStatusID() {
        return receiverHAStatusID;
    }

    public void setReceiverHAStatusID(int receiverHAStatusID) {
        this.receiverHAStatusID = receiverHAStatusID;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPhoneNo() {
        return phoneNo;
    }

    public void setPhoneNo(String phoneNo) {
        this.phoneNo = phoneNo;
    }
	
}