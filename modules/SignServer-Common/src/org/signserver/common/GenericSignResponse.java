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
package org.signserver.common;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.List;
import java.util.Properties;

import org.ejbca.util.CertTools;
import org.signserver.server.archive.Archivable;

/**
 * A generic work response class implementing the minimal required functionality.
 * 
 * Could be used for TimeStamp Responses.
 * 
 * @author philip
 * @version $Id: GenericSignResponse.java 2841 2012-10-16 08:31:40Z netmackan $
 */
public class GenericSignResponse extends ProcessResponse implements ISignResponse {

    private static final long serialVersionUID = 3L;
    protected int tag = RequestAndResponseManager.RESPONSETYPE_GENERICSIGNRESPONSE;
    private int requestID;
    private byte[] processedData;
    private transient Certificate signerCertificate;
    private byte[] signerCertificateBytes;
    private byte[] signerCertificateChainBytes;
    private int responseCode;
    private String responseMessage;
    private String responseStrData;
    private String archiveId;
    private List<SignerInfoResponse> singerInfo;
    private Integer endpointId;
    private String fileId;
    
    private Properties propertiesData;
    
    private Collection<? extends Archivable> archivables;
    private boolean responseOTP;

    /**
     * Default constructor used during serialization.
     */
    public GenericSignResponse() {
    }

    /**
     * Creates a GenericWorkResponse, works as a simple VO.
     * 
     * @see org.signserver.common.ProcessRequest
     */
    public GenericSignResponse(int requestID, byte[] processedData,
            Certificate signerCertificate,
	    byte[] signerCertificateChainBytes,
            String archiveId, Collection<? extends Archivable> archivables) {
        try {
            this.requestID = requestID;
            this.processedData = processedData;
            this.signerCertificate = signerCertificate;
            this.signerCertificateBytes = signerCertificate == null ? null
                    : signerCertificate.getEncoded();
	    this.signerCertificateChainBytes = signerCertificateChainBytes == null ? null
		    : signerCertificateChainBytes;
            this.archiveId = archiveId;
            this.archivables = archivables;
        } catch (CertificateEncodingException ex) {
            throw new RuntimeException(ex);
        }
    }
    
    public GenericSignResponse(int requestID, byte[] processedData,
            Certificate signerCertificate,
	    byte[] signerCertificateChainBytes,
            String archiveId, Collection<? extends Archivable> archivables,
            int responseCode, String responseMessage, List<SignerInfoResponse> signerInfo) {
        try {
            this.requestID = requestID;
            this.processedData = processedData;
            this.signerCertificate = signerCertificate;
            this.signerCertificateBytes = signerCertificate == null ? null
                    : signerCertificate.getEncoded();
	    this.signerCertificateChainBytes = signerCertificateChainBytes == null ? null
		    : signerCertificateChainBytes;
            this.archiveId = archiveId;
            this.archivables = archivables;
            this.responseCode = responseCode;
            this.responseMessage = responseMessage;
            this.singerInfo = signerInfo;
        } catch (CertificateEncodingException ex) {
            throw new RuntimeException(ex);
        }
    }
    
    public GenericSignResponse(
    		int requestID,
    		byte[] processedData,
            Certificate signerCertificate,
            byte[] signerCertificateChainBytes,
            String archiveId, 
            Collection<? extends Archivable> archivables,
            int responseCode, 
            String responseMessage, 
            List<SignerInfoResponse> signerInfo, 
            Properties propertiesData) {
    	
        try {
            this.requestID = requestID;
            this.processedData = processedData;
            this.signerCertificate = signerCertificate;
            this.signerCertificateBytes = signerCertificate == null ? null
                    : signerCertificate.getEncoded();
	    this.signerCertificateChainBytes = signerCertificateChainBytes == null ? null
		    : signerCertificateChainBytes;
            this.archiveId = archiveId;
            this.archivables = archivables;
            this.responseCode = responseCode;
            this.responseMessage = responseMessage;
            this.singerInfo = signerInfo;
            this.propertiesData = propertiesData;
        } catch (CertificateEncodingException ex) {
            throw new RuntimeException(ex);
        }
    }
    
    public GenericSignResponse(int requestID, byte[] processedData,
            Certificate signerCertificate,
	    byte[] signerCertificateChainBytes,
            String archiveId, Collection<? extends Archivable> archivables,
            int responseCode, String responseMessage) {
        try {
            this.requestID = requestID;
            this.processedData = processedData;
            this.signerCertificate = signerCertificate;
            this.signerCertificateBytes = signerCertificate == null ? null
                    : signerCertificate.getEncoded();
	    this.signerCertificateChainBytes = signerCertificateChainBytes == null ? null
		    : signerCertificateChainBytes;
            this.archiveId = archiveId;
            this.archivables = archivables;
            this.responseCode = responseCode;
            this.responseMessage = responseMessage;
        } catch (CertificateEncodingException ex) {
            throw new RuntimeException(ex);
        }
    }
    
    public GenericSignResponse(int requestID, String archiveId, int responseCode, String responseMessage) {
            this.requestID = requestID;
            this.processedData = null;
            this.signerCertificate = null;
            this.signerCertificateBytes = null;
            this.archiveId = archiveId;
            this.archivables = null;
            this.responseCode = responseCode;
            this.responseMessage = responseMessage;
    }
    
    public GenericSignResponse(int requestID, String archiveId, int responseCode, String responseMessage, String responseStrData) {
        this.requestID = requestID;
        this.processedData = null;
        this.signerCertificate = null;
        this.signerCertificateBytes = null;
        this.archiveId = archiveId;
        this.archivables = null;
        this.responseCode = responseCode;
        this.responseMessage = responseMessage;
        this.responseStrData = responseStrData;
}
    /**
     * @return the request ID
     */
    public int getRequestID() {
        return requestID;
    }

    @Override
    public Certificate getSignerCertificate() {
        if (signerCertificate == null && signerCertificateBytes != null) {
            try {
                signerCertificate = CertTools.getCertfromByteArray(
                        signerCertificateBytes);
            } catch (CertificateException ex) {
                throw new RuntimeException(ex);
            }
        }
        return signerCertificate;
    }

    public byte[] getSignerCertificateChainBytes() {
    	return signerCertificateChainBytes;
    }

    @Override
    public String getArchiveId() {
        return archiveId;
    }

    /**
     * @return the processedData
     */
    public byte[] getProcessedData() {
        return processedData;
    }

    public void parse(DataInput in) throws IOException {
        in.readInt();
        this.requestID = in.readInt();

        int certSize = in.readInt();
        if (certSize != 0) {
            byte[] certData = new byte[certSize];
            in.readFully(certData);
            try {
                this.signerCertificate = CertTools.getCertfromByteArray(certData);
            } catch (CertificateException e) {
                try {
                    throw new IOException(e.getMessage()).initCause(e);
                } catch (Throwable e1) {
                    throw new IOException(e.getMessage());
                }
            }
        }
        int dataSize = in.readInt();
        processedData = new byte[dataSize];
        in.readFully(processedData);
    }

    public void serialize(DataOutput out) throws IOException {
        out.writeInt(tag);
        out.writeInt(this.requestID);
        if (signerCertificate != null) {
            try {
                byte[] certData = this.signerCertificate.getEncoded();
                out.writeInt(certData.length);
                out.write(certData);
            } catch (CertificateEncodingException e) {
                try {
                    throw new IOException(e.getMessage()).initCause(e);
                } catch (Throwable e1) {
                    throw new IOException(e.getMessage());
                }
            }
        } else {
            out.writeInt(0);
        }
        out.writeInt(processedData.length);
        out.write(processedData);
    }

    public Collection<? extends Archivable> getArchivables() {
        return archivables;
    }
    
    public int getResponseCode() {
    	return this.responseCode;
    }
    
    public String getResponseMessage() {
    	return this.responseMessage;
    }
    
    public List<SignerInfoResponse> getSignerInfoResponse() {
    	return this.singerInfo;
    }
    
	public Properties getPropertiesData() {
		return propertiesData;
	}
	
	public void setPropertiesData(Properties propertiesData) {
		this.propertiesData = propertiesData;
	}
    
	public Integer getEndpointId() {
		return endpointId;
	}
	public void setEndpointId(Integer endpointId) {
		this.endpointId = endpointId;
	}
	
	public void setResponseStrData(String responseStrData) {
		this.responseStrData = responseStrData;
	}
	
	public String getResponseStrData() {
		return this.responseStrData;
	}
	
	public void setFileId(String fileId) {
		this.fileId = fileId;
	}
	
	public String getFileId() {
		return this.fileId;
	}

    public boolean isResponseOTP() {
        return responseOTP;
    }

    public void setResponseOTP(boolean responseOTP) {
        this.responseOTP = responseOTP;
    }
        
        
	
}
