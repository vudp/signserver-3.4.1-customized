package org.signserver.module.pkcs1signer;

import java.io.IOException;

import javax.xml.bind.DatatypeConverter;
import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.signserver.common.*;
import org.signserver.common.util.*;
import org.signserver.server.WorkerContext;
import org.signserver.server.signers.BaseSigner;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import org.signserver.server.cryptotokens.ICryptoToken;

import javax.crypto.Cipher;

import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.*;

import javax.crypto.*;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class PKCS1Signer extends BaseSigner{
	private static final String CONTENT_TYPE = "text/xml";
	private static byte[] mCertificateChain;
	private String WORKERNAME = "PKCS1Signer";
	private String ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
	private int ResponseCode = Defines.CODE_INTERNALSYSTEM;
    public static final Logger LOG = Logger.getLogger(PKCS1Signer.class);
	@Override
	public void init(int workerId, WorkerConfig config,
			WorkerContext workerContext, EntityManager workerEM) {
		// TODO Auto-generated method stub
		BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        
		super.init(workerId, config, workerContext, workerEM);
	}

	@Override
	public ProcessResponse processData(ProcessRequest signRequest,
			RequestContext requestContext) throws IllegalRequestException,
			CryptoTokenOfflineException, SignServerException {
		// TODO Auto-generated method stub
		ProcessResponse signResponse;
		// Check that the request contains a valid GenericSignRequest object
		// with a byte[].
		if (!(signRequest instanceof GenericSignRequest)) {
		    throw new IllegalRequestException(
		            "Recieved request wasn't a expected GenericSignRequest.");
		}
		
		final ISignRequest sReq = (ISignRequest) signRequest;
		    
		
		String isHashed = RequestMetadata.getInstance(requestContext).get(Defines._ISHASHED);
		String method = RequestMetadata.getInstance(requestContext).get(Defines._METHOD);
		if(method.compareTo(Defines.PKCS1SIGREQUEST) != 0) {
			method = Defines.PKCS1CERREQUEST;
		}

		boolean _isHashed = false;
		if(isHashed != null) {
			if(isHashed.compareTo("True") == 0)
				_isHashed = true;
		}

		byte[] data = "OK".getBytes();
		if(method.compareTo(Defines.PKCS1SIGREQUEST) == 0)
		{
			data = (byte[]) sReq.getRequestData();
		}
		
		final String archiveId = createArchiveId(data, (String) requestContext.get(RequestContext.TRANSACTION_ID));

		 // check license for PKCS1Signer
        LOG.info("Checking license for PKCS1Signer.");
        License licInfo = License.getInstance();
        if(licInfo.getStatusCode() != 0) {
        	return new GenericSignResponse(sReq.getRequestID(), archiveId, Defines.CODE_INFO_LICENSE, licInfo.getStatusDescription());
        } else {
        	if(!licInfo.checkWorker(WORKERNAME)) {
        		return new GenericSignResponse(sReq.getRequestID(), archiveId
        				, Defines.CODE_INFO_LICENSE_NOTSUPPORT, Defines.ERROR_INFO_LICENSE_NOTSUPPORT);
        	}
        }
       
        byte[] cipherText = null;
        
		if(method.compareTo(Defines.PKCS1SIGREQUEST) == 0) {
			 
			PrivateKey privKey = getCryptoToken().getPrivateKey(ICryptoToken.PURPOSE_SIGN);
			String mProvider = getCryptoToken().getProvider(ICryptoToken.PROVIDERUSAGE_SIGN);
			 
			if(_isHashed) {
				try
				{
					LOG.info("Data already hashed! Just sign");
					DERObjectIdentifier sha1oid_ = new DERObjectIdentifier("1.3.14.3.2.26");
	
			        AlgorithmIdentifier sha1aid_ = new AlgorithmIdentifier(sha1oid_, null);
			        DigestInfo di = new DigestInfo(sha1aid_, data);
			        byte[] plainSig = di.getEncoded(ASN1Encoding.DER);
					
			        Signature sig = Signature.getInstance("NONEwithRSA");
			        sig.initSign(privKey);
			        sig.update(plainSig);
			        cipherText = sig.sign();
					
					ResponseCode = Defines.CODE_SUCCESS;
					ResponseMessage = Defines.SUCCESS;
					
				} catch(Exception e) {
					e.printStackTrace();
					return new GenericSignResponse(sReq.getRequestID(), archiveId, Defines.CODE_PKCS1EXP, Defines.ERROR_PKCS1EXP);
				}
			} else {
				try {
					LOG.info("Hash and sign data");
					Signature sig = Signature.getInstance("SHA1withRSA", mProvider);
					sig.initSign(privKey);
					sig.update(data);
					cipherText = sig.sign();
					ResponseCode = Defines.CODE_SUCCESS;
					ResponseMessage = Defines.SUCCESS;
				} catch(Exception e) {
					e.printStackTrace();
					return new GenericSignResponse(sReq.getRequestID(), archiveId, Defines.CODE_PKCS1EXP, Defines.ERROR_PKCS1EXP);
				}
			}
		} else {
			// request certificate
			cipherText = "OK".getBytes();
		}

		//Get Certificate Chain
		//List<Certificate> listCerts = getSigningCertificateChain();
		//Certificate[] certChain = (Certificate[]) listCerts.toArray(new Certificate[listCerts.size()]);

		//byte[] mCertChain = ConvertCertChainToByteArray(certChain);
		//if(mCertChain == null)
		//{
		//	return new GenericSignResponse(sReq.getRequestID(), archiveId, Defines.CODE_PKCS1MAKECHAIN, Defines.ERROR_PKCS1MAKECHAIN);
		//}
		
		
		final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE, CONTENT_TYPE, cipherText, archiveId));

    	if (signRequest instanceof GenericServletRequest) {
       		signResponse = new GenericServletResponse(sReq.getRequestID(), cipherText, getSigningCertificate(), archiveId, archivables, CONTENT_TYPE);
        } else {
        	signResponse = new GenericSignResponse(sReq.getRequestID(), cipherText, getSigningCertificate(), null, archiveId, archivables, ResponseCode, ResponseMessage);
    	}

        return signResponse;
	}
	public byte[] ConvertCertChainToByteArray(Certificate[] certList)
	{
		byte[] bridge = "TOMICABRIDGE".getBytes();
		int tmp_size = 0;
		
		try {
			for(int i=0; i<certList.length; i++)
			{
				tmp_size += certList[i].getEncoded().length + bridge.length;
			}
		}
		catch (CertificateEncodingException e)
		{
			e.printStackTrace();
			return null;
		}
		
		byte[] Result = new byte[tmp_size];
		Arrays.fill(Result, (byte)0);
		int index = 0;
		
		try {
			for(int i=0; i<certList.length; i++)
			{
				System.arraycopy(certList[i].getEncoded(), 0, Result, index, certList[i].getEncoded().length);
				index = index + certList[i].getEncoded().length;
				System.arraycopy(bridge, 0, Result, index, bridge.length);
				index = index + bridge.length;
			}
		}
		catch (CertificateEncodingException e)
		{
			e.printStackTrace();
			return null;
		}
		return Result;
	}
}


