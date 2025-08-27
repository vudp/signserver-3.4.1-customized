package org.signserver.common;

import java.util.*;

public class FileDetail {
	
	private String oldFileId;
	private String newFileId;
	private String fileId;
	private String mimeType;
	private String digest;
	private int status;
	private String message;
	private List<SignerInfoResponse> signerInfoResponse;
	
	public String getOldFileId() {
		return oldFileId;
	}
	public void setOldFileId(String oldFileId) {
		this.oldFileId = oldFileId;
	}
	public String getNewFileId() {
		return newFileId;
	}
	public void setNewFileId(String newFileId) {
		this.newFileId = newFileId;
	}
	public int getStatus() {
		return status;
	}
	public void setStatus(int status) {
		this.status = status;
	}
	public String getMessage() {
		return message;
	}
	public void setMessage(String message) {
		this.message = message;
	}
	public String getFileId() {
		return fileId;
	}
	public void setFileId(String fileId) {
		this.fileId = fileId;
	}
	public List<SignerInfoResponse> getSignerInfoResponse() {
		return signerInfoResponse;
	}
	public void setSignerInfoResponse(List<SignerInfoResponse> signerInfoResponse) {
		this.signerInfoResponse = signerInfoResponse;
	}
	public String getMimeType() {
		return mimeType;
	}
	public void setMimeType(String mimeType) {
		this.mimeType = mimeType;
	}
	public String getDigest() {
		return digest;
	}
	public void setDigest(String digest) {
		this.digest = digest;
	}
}