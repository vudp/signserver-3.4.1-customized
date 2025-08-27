package org.signserver.socket;

import java.util.Arrays;

public class TransactionInfo {
    private CAGCredential credentialData;
    private String xmlData;
    private byte[] fileData = {0x00};
    private byte[] NULL = {0x00};

    public TransactionInfo() {
    }

    public TransactionInfo(CAGCredential credentialData, String xmlData, byte[] fileData) {
        this.credentialData = credentialData;
        this.xmlData = xmlData;
        this.fileData = fileData;
    }
    
    public TransactionInfo(String xmlData) {
        this.credentialData = null;
        this.xmlData = xmlData;
    }
    
    public TransactionInfo(String xmlData, byte[] fileData) {
        this.credentialData = null;
        this.xmlData = xmlData;
        this.fileData = fileData;
    }
    
    

    public CAGCredential getCredentialData() {
        return credentialData;
    }

    public void setCredentialData(CAGCredential credentialData) {
        this.credentialData = credentialData;
    }

    public String getXmlData() {
        return xmlData;
    }

    public void setXmlData(String xmlData) {
        this.xmlData = xmlData;
    }

    public byte[] getFileData() {
        return fileData;
    }

    public void setFileData(byte[] fileData) {
        this.fileData = fileData;
    }
    
    public TransactionInfo fromBytes(byte[] byteData) {
    	byte[] raw_xmlData 		= Utils.getBytesValue(byteData, Utils.S_XMLDATA, Utils.E_XMLDATA);
		byte[] raw_byteData 	= Utils.getBytesValue(byteData, Utils.S_FILEDATA, Utils.E_FILEDATA);
		byte[] raw_userName		= Utils.getBytesValue(byteData, Utils.S_USERNAME, Utils.E_USERNAME);
		byte[] raw_passWord		= Utils.getBytesValue(byteData, Utils.S_PASSWORD, Utils.E_PASSWORD);
		byte[] raw_signature	= Utils.getBytesValue(byteData, Utils.S_SIGNATURE, Utils.E_SIGNATURE);
		byte[] raw_timestamp	= Utils.getBytesValue(byteData, Utils.S_TIMESTAMP, Utils.E_TIMESTAMP);
		byte[] raw_pkcs1Sig		= Utils.getBytesValue(byteData, Utils.S_PKCS1SIGNATURE, Utils.E_PKCS1SIGNATURE);
		
		String xmlData,username,password,signature,timestamp,pkcs1signature;
		byte[] fileData;
		if(!Arrays.equals(raw_xmlData, NULL)) {
			xmlData = new String(raw_xmlData);
		} else {
			xmlData = null;
		}
		
		if(!Arrays.equals(raw_userName, NULL)) {
			username = new String(raw_userName);
		} else {
			username = null;
		}
		
		if(!Arrays.equals(raw_passWord, NULL)) {
			password = new String(raw_passWord);
		} else {
			password = null;
		}
		
		if(!Arrays.equals(raw_signature, NULL)) {
			signature = new String(raw_signature);
		} else {
			signature = null;
		}
		
		if(!Arrays.equals(raw_timestamp, NULL)) {
			timestamp = new String(raw_timestamp);
		} else {
			timestamp = null;
		}
		
		if(!Arrays.equals(raw_pkcs1Sig, NULL)) {
			pkcs1signature = new String(raw_pkcs1Sig);
		} else {
			pkcs1signature = null;
		}
		
		if(!Arrays.equals(raw_byteData, NULL)) {
			fileData = raw_byteData;
		} else {
			fileData = null;
		}
		
		CAGCredential cag = new CAGCredential(username, password, signature, timestamp, pkcs1signature);
		
		TransactionInfo trans = new TransactionInfo(cag, xmlData, fileData);
		
		return trans;
    }

    public byte[] toBytes() {
    	
    	byte[] xml = (this.xmlData != null) ? this.xmlData.getBytes():NULL;
    	int xml_length = xml.length;
    	
    	byte[] filedata = this.fileData != null ? this.fileData : NULL;
    	int filedata_length = filedata.length;
    	
    	byte[] username = (this.credentialData != null) ? ((this.credentialData.getUsername() != null)?this.credentialData.getUsername().getBytes():NULL):NULL;
    	int username_length = username.length;
    	
    	byte[] password = (this.credentialData != null) ? ((this.credentialData.getPassword() != null)?this.credentialData.getPassword().getBytes():NULL):NULL;
    	int password_length = password.length;
    	
    	byte[] signature = (this.credentialData != null) ? ((this.credentialData.getSignature() != null)?this.credentialData.getSignature().getBytes():NULL):NULL;
    	int siganture_length = signature.length;
    	
    	byte[] timestamp = (this.credentialData != null) ? ((this.credentialData.getTimestamp() != null)?this.credentialData.getTimestamp().getBytes():NULL):NULL;
    	int timestamp_length = timestamp.length;
    	
    	byte[] pkcs1signature = (this.credentialData != null) ? ((this.credentialData.getPkcs1Signature() != null)?this.credentialData.getPkcs1Signature().getBytes():NULL):NULL;
    	int pkcs1signature_length = pkcs1signature.length;
    	
    	int total = xml_length + filedata_length + username_length + password_length 
    			+ siganture_length + timestamp_length + pkcs1signature_length 
    			+ Utils.S_XMLDATA.length + Utils.E_XMLDATA.length 
    			+ Utils.S_FILEDATA.length + Utils.E_FILEDATA.length
    			+ Utils.S_USERNAME.length + Utils.E_USERNAME.length
    			+ Utils.S_PASSWORD.length + Utils.E_PASSWORD.length
    			+ Utils.S_SIGNATURE.length + Utils.E_SIGNATURE.length
    			+ Utils.S_TIMESTAMP.length + Utils.E_TIMESTAMP.length
    			+ Utils.S_PKCS1SIGNATURE.length + Utils.E_PKCS1SIGNATURE.length;
    	byte[] res = new byte[total];
    	System.arraycopy(Utils.S_XMLDATA, 0, res, 0, Utils.S_XMLDATA.length);
    	System.arraycopy(xml, 0, res, Utils.S_XMLDATA.length, xml_length);
    	System.arraycopy(Utils.E_XMLDATA, 0, res, Utils.S_XMLDATA.length + xml_length, Utils.E_XMLDATA.length);
    	
    	System.arraycopy(Utils.S_FILEDATA, 0, res, Utils.S_XMLDATA.length + xml_length + Utils.E_XMLDATA.length, Utils.S_FILEDATA.length);
    	System.arraycopy(filedata, 0, res, Utils.S_XMLDATA.length + xml_length + Utils.E_XMLDATA.length + Utils.S_FILEDATA.length, filedata_length);
    	System.arraycopy(Utils.E_FILEDATA, 0, res, Utils.S_XMLDATA.length + xml_length + Utils.E_XMLDATA.length + Utils.S_FILEDATA.length + filedata_length, Utils.E_FILEDATA.length);
    	
    	System.arraycopy(Utils.S_USERNAME, 0, res, Utils.S_XMLDATA.length + xml_length + Utils.E_XMLDATA.length + Utils.S_FILEDATA.length + filedata_length + Utils.E_FILEDATA.length, Utils.S_USERNAME.length);
    	System.arraycopy(username, 0, res, Utils.S_XMLDATA.length + xml_length + Utils.E_XMLDATA.length + Utils.S_FILEDATA.length + filedata_length + Utils.E_FILEDATA.length + Utils.S_USERNAME.length, username_length);
    	System.arraycopy(Utils.E_USERNAME, 0, res, Utils.S_XMLDATA.length + xml_length + Utils.E_XMLDATA.length + Utils.S_FILEDATA.length + filedata_length + Utils.E_FILEDATA.length + Utils.S_USERNAME.length + username_length, Utils.E_USERNAME.length);
    	
    	System.arraycopy(Utils.S_PASSWORD, 0, res, Utils.S_XMLDATA.length + xml_length + Utils.E_XMLDATA.length + Utils.S_FILEDATA.length + filedata_length + Utils.E_FILEDATA.length + Utils.S_USERNAME.length + username_length + Utils.E_USERNAME.length, Utils.S_PASSWORD.length);
    	System.arraycopy(password, 0, res, Utils.S_XMLDATA.length + xml_length + Utils.E_XMLDATA.length + Utils.S_FILEDATA.length + filedata_length + Utils.E_FILEDATA.length + Utils.S_USERNAME.length + username_length + Utils.E_USERNAME.length + Utils.S_PASSWORD.length, password_length);
    	System.arraycopy(Utils.E_PASSWORD, 0, res, Utils.S_XMLDATA.length + xml_length + Utils.E_XMLDATA.length + Utils.S_FILEDATA.length + filedata_length + Utils.E_FILEDATA.length + Utils.S_USERNAME.length + username_length + Utils.E_USERNAME.length + Utils.S_PASSWORD.length + password_length, Utils.E_PASSWORD.length);
    	
    	System.arraycopy(Utils.S_SIGNATURE, 0, res, Utils.S_XMLDATA.length + xml_length + Utils.E_XMLDATA.length + Utils.S_FILEDATA.length + filedata_length + Utils.E_FILEDATA.length + Utils.S_USERNAME.length + username_length + Utils.E_USERNAME.length + Utils.S_PASSWORD.length + password_length + Utils.E_PASSWORD.length, Utils.S_SIGNATURE.length);
    	System.arraycopy(signature, 0, res, Utils.S_XMLDATA.length + xml_length + Utils.E_XMLDATA.length + Utils.S_FILEDATA.length + filedata_length + Utils.E_FILEDATA.length + Utils.S_USERNAME.length + username_length + Utils.E_USERNAME.length + Utils.S_PASSWORD.length + password_length + Utils.E_PASSWORD.length + Utils.S_SIGNATURE.length, siganture_length);
    	System.arraycopy(Utils.E_SIGNATURE, 0, res, Utils.S_XMLDATA.length + xml_length + Utils.E_XMLDATA.length + Utils.S_FILEDATA.length + filedata_length + Utils.E_FILEDATA.length + Utils.S_USERNAME.length + username_length + Utils.E_USERNAME.length + Utils.S_PASSWORD.length + password_length + Utils.E_PASSWORD.length + Utils.S_SIGNATURE.length + siganture_length, Utils.E_SIGNATURE.length);
    	
    	System.arraycopy(Utils.S_TIMESTAMP, 0, res, Utils.S_XMLDATA.length + xml_length + Utils.E_XMLDATA.length + Utils.S_FILEDATA.length + filedata_length + Utils.E_FILEDATA.length + Utils.S_USERNAME.length + username_length + Utils.E_USERNAME.length + Utils.S_PASSWORD.length + password_length + Utils.E_PASSWORD.length + Utils.S_SIGNATURE.length + siganture_length + Utils.E_SIGNATURE.length, Utils.S_TIMESTAMP.length);
    	System.arraycopy(timestamp, 0, res, Utils.S_XMLDATA.length + xml_length + Utils.E_XMLDATA.length + Utils.S_FILEDATA.length + filedata_length + Utils.E_FILEDATA.length + Utils.S_USERNAME.length + username_length + Utils.E_USERNAME.length + Utils.S_PASSWORD.length + password_length + Utils.E_PASSWORD.length + Utils.S_SIGNATURE.length + siganture_length + Utils.E_SIGNATURE.length + Utils.S_TIMESTAMP.length, timestamp_length);
    	System.arraycopy(Utils.E_TIMESTAMP, 0, res, Utils.S_XMLDATA.length + xml_length + Utils.E_XMLDATA.length + Utils.S_FILEDATA.length + filedata_length + Utils.E_FILEDATA.length + Utils.S_USERNAME.length + username_length + Utils.E_USERNAME.length + Utils.S_PASSWORD.length + password_length + Utils.E_PASSWORD.length + Utils.S_SIGNATURE.length + siganture_length + Utils.E_SIGNATURE.length + Utils.S_TIMESTAMP.length + timestamp_length, Utils.E_TIMESTAMP.length);
    	
    	System.arraycopy(Utils.S_PKCS1SIGNATURE, 0, res, Utils.S_XMLDATA.length + xml_length + Utils.E_XMLDATA.length + Utils.S_FILEDATA.length + filedata_length + Utils.E_FILEDATA.length + Utils.S_USERNAME.length + username_length + Utils.E_USERNAME.length + Utils.S_PASSWORD.length + password_length + Utils.E_PASSWORD.length + Utils.S_SIGNATURE.length + siganture_length + Utils.E_SIGNATURE.length + Utils.S_TIMESTAMP.length + timestamp_length + Utils.E_TIMESTAMP.length, Utils.S_PKCS1SIGNATURE.length);
    	System.arraycopy(pkcs1signature, 0, res, Utils.S_XMLDATA.length + xml_length + Utils.E_XMLDATA.length + Utils.S_FILEDATA.length + filedata_length + Utils.E_FILEDATA.length + Utils.S_USERNAME.length + username_length + Utils.E_USERNAME.length + Utils.S_PASSWORD.length + password_length + Utils.E_PASSWORD.length + Utils.S_SIGNATURE.length + siganture_length + Utils.E_SIGNATURE.length + Utils.S_TIMESTAMP.length + timestamp_length + Utils.E_TIMESTAMP.length + Utils.S_PKCS1SIGNATURE.length, pkcs1signature_length);
    	System.arraycopy(Utils.E_PKCS1SIGNATURE, 0, res, Utils.S_XMLDATA.length + xml_length + Utils.E_XMLDATA.length + Utils.S_FILEDATA.length + filedata_length + Utils.E_FILEDATA.length + Utils.S_USERNAME.length + username_length + Utils.E_USERNAME.length + Utils.S_PASSWORD.length + password_length + Utils.E_PASSWORD.length + Utils.S_SIGNATURE.length + siganture_length + Utils.E_SIGNATURE.length + Utils.S_TIMESTAMP.length + timestamp_length + Utils.E_TIMESTAMP.length + Utils.S_PKCS1SIGNATURE.length + pkcs1signature_length, Utils.E_PKCS1SIGNATURE.length);
    	
    	return res;
    }
}