/*************************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.socket;

import java.util.List;
import org.signserver.common.*;

/**
 * Represents the response (result) of requesting some data to be processed.
 *
 * @author Markus Kilås
 * @version $Id: DataResponse.java 3055 2012-11-29 12:38:43Z netmackan $
 */
public class DataResponse {
   
    private int requestId;
    private byte[] data;
    private String archiveId;
    private byte[] signerCertificate;
    private List<Metadata> metadata;
    private List<SignerInfoResponse> signerInfoResponse;
    private int responseCode;
    private String responseMessage;

    public DataResponse() {
    }

    /**
     * Constructs a new instance of DataResponse.
     * @param requestId Id of the worker that processed the request.
     * @param data The result (for instance signed document).
     * @param archiveId The ID assigned to the archivable item(s).
     * @param signerCertificate Certificate of the signer signing the data (if any).
     * @param metadata Response metadata.
     */
    public DataResponse(int requestId, byte[] data, String archiveId, byte[] signerCertificate, List<Metadata> metadata) {
        this.requestId = requestId;
        this.data = data;
        this.archiveId = archiveId;
        this.signerCertificate = signerCertificate;
        this.metadata = metadata;
    }
    
    public DataResponse(int requestId, byte[] data, String archiveId, byte[] signerCertificate
    		, List<Metadata> metadata, int responseCode, String responseMessage, List<SignerInfoResponse> signerInfoResponse) {
        this.requestId = requestId;
        this.data = data;
        this.archiveId = archiveId;
        this.signerCertificate = signerCertificate;
        this.metadata = metadata;
        this.responseCode = responseCode;
        this.responseMessage = responseMessage;
        this.signerInfoResponse = signerInfoResponse;
    }
    
    public DataResponse(int requestId, byte[] data, String archiveId, byte[] signerCertificate
    		, List<Metadata> metadata, int responseCode, String responseMessage) {
        this.requestId = requestId;
        this.data = data;
        this.archiveId = archiveId;
        this.signerCertificate = signerCertificate;
        this.metadata = metadata;
        this.responseCode = responseCode;
        this.responseMessage = responseMessage;
    }
    
    public DataResponse(int responseCode, String responseMessage) {
        this.responseCode = responseCode;
        this.responseMessage = responseMessage;
    }
    
    public DataResponse(int responseCode, String responseMessage, byte[] responseData) {
        this.responseCode = responseCode;
        this.responseMessage = responseMessage;
        this.data = responseData;
    }
    
    public DataResponse(int requestId, int responseCode, String responseMessage) {
    	this.requestId = requestId;
        this.responseCode = responseCode;
        this.responseMessage = responseMessage;
    }

    /**
     * @return The archive id
     */
    public String getArchiveId() {
        return archiveId;
    }

    /**
     * @param archiveId The archive id
     */
    public void setArchiveId(String archiveId) {
        this.archiveId = archiveId;
    }

    /**
     * @return The signed data
     */
    public byte[] getData() {
        return data;
    }

    /**
     * @param data The signed data
     */
    public void setData(byte[] data) {
        this.data = data;
    }

    /**
     * @return The id of the request
     */
    public int getRequestId() {
        return requestId;
    }

    /**
     * @param requestId The id of the request
     */
    public void setRequestId(int requestId) {
        this.requestId = requestId;
    }

    /**
     * @return The signer certificate (if any)
     */
    public byte[] getSignerCertificate() {
        return signerCertificate;
    }

    /**
     * @param signerCertificate The signer certificate
     */
    public void setSignerCertificate(byte[] signerCertificate) {
        this.signerCertificate = signerCertificate;
    }

    /**
     * @return The response metadata (if any)
     */
    public List<Metadata> getMetadata() {
        return metadata;
    }
    
    public List<SignerInfoResponse> getSignerInfoResponse() {
    	return signerInfoResponse;
    }

    /**
     * @param metadata The response metadata
     */
    public void setMetadata(List<Metadata> metadata) {
        this.metadata = metadata;
    }
    
    public void setSignerInfoResponse(List<SignerInfoResponse> signerInfoResponse) {
    	this.signerInfoResponse = signerInfoResponse;
    } 
    
    public void setResponseCode(int responseCode) {
    	this.responseCode = responseCode;
    }
    
    public int getResponseCode() {
    	return responseCode;
    }
    
    public void setResponseMessage(String responseMessage) {
    	this.responseMessage = responseMessage;
    }
    
    public String getResponseMessage() {
    	return responseMessage;
    }
    
}

