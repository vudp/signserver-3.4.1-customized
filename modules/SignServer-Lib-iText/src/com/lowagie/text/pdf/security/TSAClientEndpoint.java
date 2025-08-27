package com.lowagie.text.pdf.security;

import java.io.*;
import java.math.*;
import java.net.*;

import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.tsp.*;

import com.lowagie.text.pdf.codec.Base64;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import org.signserver.common.*;
import org.signserver.common.util.*;
import org.signserver.common.dbdao.*;


/**
 * Time Stamp Authority Client interface implementation using Bouncy Castle
 * org.bouncycastle.tsp package.
 * <p>
 * Created by Aiken Sam, 2006-11-15, refactored by Martin Brunecky, 07/15/2007
 * for ease of subclassing.
 * </p>
 * @since	2.1.6
 */
public class TSAClientEndpoint implements TSAClient {
    
    /** The default value for the hash algorithm */
    public static final String DEFAULTHASHALGORITHM = "SHA-256";
    /** Hash algorithm */
    protected String digestAlgorithm;
    
    protected int tokSzEstimate;
    protected String tsaProvider;
    protected int trustedhubTransId;
    protected String channelName;
    protected String user;
    
    
   
    public TSAClientEndpoint() {
        this(7168);
    }
    
    public TSAClientEndpoint(String channelName, String user, String tsaProvider, int trustedhubTransId, String digestAlgorithm) {
        this(7168);
        this.tsaProvider = tsaProvider;
        this.trustedhubTransId = trustedhubTransId;
        this.channelName = channelName;
        this.user = user;
        this.digestAlgorithm = digestAlgorithm;
    }
    
    public TSAClientEndpoint(String channelName, String user, String tsaProvider, int trustedhubTransId) {
        this(7168);
        this.tsaProvider = tsaProvider;
        this.trustedhubTransId = trustedhubTransId;
        this.channelName = channelName;
        this.user = user;
        this.digestAlgorithm = DEFAULTHASHALGORITHM;
    }
    

    public TSAClientEndpoint(int tokSzEstimate) {
        this.tokSzEstimate = tokSzEstimate;
    }
    
    /**
     * Get the token size estimate.
     * Returned value reflects the result of the last succesfull call, padded
     * @return an estimate of the token size
     */
    public int getTokenSizeEstimate() {
        return tokSzEstimate;
    }
    
    /**
     * Get RFC 3161 timeStampToken.
     * Method may return null indicating that timestamp should be skipped.
     * @param caller PdfPKCS7 - calling PdfPKCS7 instance (in case caller needs it)
     * @param imprint byte[] - data imprint to be time-stamped
     * @return byte[] - encoded, TSA signed data of the timeStampToken
     * @throws Exception - TSA request failed
     * @see com.lowagie.text.pdf.TSAClient#getTimeStampToken(com.lowagie.text.pdf.PdfPKCS7, byte[])
     */
    public byte[] getTimeStampToken(PdfPKCS7 caller, byte[] imprint) throws Exception {
        return getTimeStampToken(imprint);
    }
    
    /**
     * Get timestamp token - Bouncy Castle request encoding / decoding layer
     */
    @Override
    public byte[] getTimeStampToken(byte[] imprint) throws Exception {
        byte[] respBytes = null;
        try {
            // Setup the time stamp request
            TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
            tsqGenerator.setCertReq(true);
            // tsqGenerator.setReqPolicy("1.3.6.1.4.1.601.10.3.1");
            BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
            TimeStampRequest request = tsqGenerator.generate(new ASN1ObjectIdentifier(DigestAlgorithms.getAllowedDigests(digestAlgorithm)), imprint, nonce);
            byte[] requestBytes = request.getEncoded();
            
            // Call the communications layer
            respBytes = getTSAResponse(requestBytes);
            
            // Handle the TSA response
            TimeStampResponse response = new TimeStampResponse(respBytes);
            
            // validate communication level attributes (RFC 3161 PKIStatus)
            response.validate(request);
            PKIFailureInfo failure = response.getFailInfo();
            int value = (failure == null) ? 0 : failure.intValue();
            if (value != 0) {
                // @todo: Translate value of 15 error codes defined by PKIFailureInfo to string
                throw new Exception("Invalid TSA response, code " + value);
            }
            // @todo: validate the time stap certificate chain (if we want
            //        assure we do not sign using an invalid timestamp).
            
            // extract just the time stamp token (removes communication status info)
            TimeStampToken  tsToken = response.getTimeStampToken();
            if (tsToken == null) {
                throw new Exception("TSA failed to return time stamp token: " + response.getStatusString());
            }
            TimeStampTokenInfo info = tsToken.getTimeStampInfo(); // to view details
            byte[] encoded = tsToken.getEncoded();
            long stop = System.currentTimeMillis();
            
            // Update our token size estimate for the next call (padded to be safe)
            this.tokSzEstimate = encoded.length + 32;
            return encoded;
        } catch (Exception e) {
            throw e;
        } catch (Throwable t) {
            throw new Exception("Failed to get TSA response", t);
        }
    }
    
    /**
     * Get timestamp token - communications layer
     * @return - byte[] - TSA response, raw bytes (RFC 3161 encoded)
     */
    protected byte[] getTSAResponse(byte[] requestBytes) throws Exception {
    	
    	
    	Tsa tsa =  DBConnector.getInstances().getTSA(this.tsaProvider);
    	
    	String tsaUrl = tsa.getTsaUrl();
    	String tsaUser = tsa.getUser();
    	String password = tsa.getPassword();
    	
    	String tsaConfig = null;
    	if(tsaUser != null && password != null) {
	    	tsaConfig = "TSA_URL="+tsaUrl+"\n"+
	    						"TSA_USERNAME="+tsaUser+"\n"+
	    						"TSA_PASSWORD="+password;
    	} else {
    		tsaConfig = "TSA_URL="+tsaUrl;
    	}
    	
    	if(tsa == null) {
    		throw new Exception("Error while requesting TSA server. Details: No TSA provider found in system");
    	}
    	
    	EndpointServiceResp endpointServiceResp = EndpointService.getInstance().getTSAResponse(channelName, user
    			, requestBytes, tsaConfig, tsa.getEndpointConfigId(), this.trustedhubTransId);
    	
    	if(endpointServiceResp.getResponseCode() == 0) {
    		return endpointServiceResp.getResponseData();
    	} else {
    		throw new Exception("Error while requesting TSA server. Details: "+endpointServiceResp.getResponseCode());
    	}
    }

    @Override
    public MessageDigest getMessageDigest() throws GeneralSecurityException {
        return new BouncyCastleDigest().getMessageDigest(digestAlgorithm);
    }
}