package org.signserver.clientws;

public class InforResponseHashToClient {
	   
    private String name;
    private byte[] hashData;

    public InforResponseHashToClient() {    	
    }

    public InforResponseHashToClient(String name, byte[] hashData) {
    	this.name = name;
    	this.hashData = hashData;
    }  
    
    public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public byte[] getHashData() {
		return hashData;
	}

	public void setHashData(byte[] hashData) {
		this.hashData = hashData;
	}
    
    
}