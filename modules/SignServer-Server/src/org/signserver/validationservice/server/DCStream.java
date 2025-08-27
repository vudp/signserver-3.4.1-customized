package org.signserver.validationservice.server;

public class DCStream {
	
	private byte[] fileData;
	private byte[] streamSign;
	private byte[] signData;
	
	public byte[] getFileData() {
		return fileData;
	}
	public void setFileData(byte[] fileData) {
		this.fileData = fileData;
	}
	public byte[] getStreamSign() {
		return streamSign;
	}
	public void setStreamSign(byte[] streamSign) {
		this.streamSign = streamSign;
	}
	public byte[] getSignData() {
		return signData;
	}
	public void setSignData(byte[] signData) {
		this.signData = signData;
	}
}