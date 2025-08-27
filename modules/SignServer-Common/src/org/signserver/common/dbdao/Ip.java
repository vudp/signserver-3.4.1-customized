package org.signserver.common.dbdao;

import java.util.Date;


public class Ip {
	
	private int ipListID;
	private int channelID;
	private String channelCode;
	private String ip;
	private boolean activeFlag;
	private String descriptions;
	private Date lastConnect;
	
	public int getIpListID() {
		return ipListID;
	}
	public void setIpListID(int ipListID) {
		this.ipListID = ipListID;
	}
	public int getChannelID() {
		return channelID;
	}
	public void setChannelID(int channelID) {
		this.channelID = channelID;
	}
	public String getIp() {
		return ip;
	}
	public void setIp(String ip) {
		this.ip = ip;
	}
	public boolean isActiveFlag() {
		return activeFlag;
	}
	public void setActiveFlag(boolean activeFlag) {
		this.activeFlag = activeFlag;
	}
	public String getDescriptions() {
		return descriptions;
	}
	public void setDescriptions(String descriptions) {
		this.descriptions = descriptions;
	}
	public Date getLastConnect() {
		return lastConnect;
	}
	public void setLastConnect(Date lastConnect) {
		this.lastConnect = lastConnect;
	}
	public String getChannelCode() {
		return channelCode;
	}
	public void setChannelCode(String channelCode) {
		this.channelCode = channelCode;
	}
}