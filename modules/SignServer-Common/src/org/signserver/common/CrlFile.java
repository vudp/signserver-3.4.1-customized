package org.signserver.common;

import java.util.Date;

public class CrlFile {
	private long sizeOfFile;
	private String fileName;
	private Date lastModify;
	private Date nextModify;
	
	public long getSizeOfFile() {
		return sizeOfFile;
	}
	public void setSizeOfFile(long sizeOfFile) {
		this.sizeOfFile = sizeOfFile;
	}
	public String getFileName() {
		return fileName;
	}
	public void setFileName(String fileName) {
		this.fileName = fileName;
	}
	public Date getLastModify() {
		return lastModify;
	}
	public void setLastModify(Date lastModify) {
		this.lastModify = lastModify;
	}
	public Date getNextModify() {
		return nextModify;
	}
	public void setNextModify(Date nextModify) {
		this.nextModify = nextModify;
	}
}