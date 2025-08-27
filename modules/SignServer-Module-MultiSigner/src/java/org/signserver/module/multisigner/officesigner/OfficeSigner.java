package org.signserver.module.multisigner.officesigner;

import java.io.FileInputStream;
import java.io.IOException;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.xml.bind.DatatypeConverter;
import javax.persistence.EntityManager;

import org.signserver.module.multisigner.*;
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
import org.signserver.validationservice.server.IValidator;

import javax.crypto.Cipher;

import java.security.*;
import java.security.cert.*;
import java.util.*;

import javax.crypto.*;

import java.io.*;

import org.apache.commons.io.IOUtils;

import com.tomicalab.cryptos.CryptoS;

import SecureBlackbox.Base.SBUtils;
import SecureBlackbox.Base.TElDCAsyncState;
import SecureBlackbox.Base.TElMemoryStream;
import SecureBlackbox.DC.SBDCXMLEnc;
import SecureBlackbox.Office.SBOfficeSecurity;
import SecureBlackbox.Office.TElOfficeBinaryXMLSignatureHandler;
import SecureBlackbox.Office.TElOfficeCustomSignatureHandler;
import SecureBlackbox.Office.TElOfficeDocument;
import SecureBlackbox.Office.TElOfficeOpenXMLSignatureHandler;
import SecureBlackbox.Office.TElOpenOfficeSignatureHandler;

import org.signserver.validationservice.server.dcsigner.*;
import org.signserver.validationservice.server.dcsigner.signprocess.*;
import org.signserver.validationservice.server.dcsigner.signprocess.handlers.*;

public class OfficeSigner {
	private static OfficeSigner instance;
	
	public static OfficeSigner getInstance() {
		if(instance == null)
			instance = new OfficeSigner();
		return instance;
	}
	
	private static final String CONTENT_TYPE = "text/xml";
	private String WORKERNAME = "OfficeSigner";
	private String ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
	private int ResponseCode = Defines.CODE_INTERNALSYSTEM;

	
	private OfficeSigner() {
		CryptoS.getInstance(IValidator.class, 1);
		SBOfficeSecurity.initialize();
		BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
	}

	public MultiSignerResponse processData(byte[] data
			, String _reason
			, X509Certificate signingCertificate, PrivateKey privateKey, String provider) {
		// TODO Auto-generated method stub
		MultiSignerResponse signResponse = null;
		byte[] signedbytes = null;
		try {
			UUID uuid = UUID.randomUUID();
	        String tmpFile = Defines.TMP_DIR + "/" + UUID.randomUUID().toString();
	        FileOutputStream outputFile = new FileOutputStream(new File(tmpFile));
	    	IOUtils.write(data, outputFile);
	    	outputFile.close();
	    	
	    	
	    	TElOfficeDocument _OfficeDocument = new TElOfficeDocument();
			_OfficeDocument.open(tmpFile);
			
			if (_OfficeDocument.getIsEncrypted()) {
				return new MultiSignerResponse(Defines.CODE_OFFICESIGNERISENCRYPT, Defines.ERROR_OFFICESIGNERISENCRYPT);
			}
			
			if(!_OfficeDocument.getSignable()) {
				return new MultiSignerResponse(Defines.CODE_OFFICESIGNERCANSIGN, Defines.ERROR_OFFICESIGNERCANSIGN);
			}

			TElMemoryStream output = new TElMemoryStream();
			TElDCAsyncState state;

			if (_OfficeDocument.getBinaryDocument() != null) {

				TElOfficeBinaryXMLSignatureHandler BinXMLSigHandler = new TElOfficeBinaryXMLSignatureHandler();
				_OfficeDocument.addSignature(BinXMLSigHandler, true);

				state = BinXMLSigHandler.initiateAsyncSign();

			} else if (_OfficeDocument.getOpenXMLDocument() != null) {

				TElOfficeOpenXMLSignatureHandler OpenXMLSigHandler = new TElOfficeOpenXMLSignatureHandler();
				_OfficeDocument.addSignature(OpenXMLSigHandler, true);
				OpenXMLSigHandler.addDocument();
				state = OpenXMLSigHandler.initiateAsyncSign();
			} else if(_OfficeDocument.getOpenDocument() != null) {
				TElOpenOfficeSignatureHandler ODFSigHandler = new TElOpenOfficeSignatureHandler();
				_OfficeDocument.addSignature(ODFSigHandler, true);
				ODFSigHandler.addDocument();
				state = ODFSigHandler.initiateAsyncSign();
			} else {
				return new MultiSignerResponse(Defines.CODE_INTERNALSYSTEM, Defines.ERROR_INTERNALSYSTEM);
			}

			state.saveToStream(output, SBDCXMLEnc.dcxmlEncoding());
			byte[] stream = output.getBuffer();
			_OfficeDocument.close();
			output.Destroy();
			
			final ByteArrayInputStream byteArrayInputStreamInit = new ByteArrayInputStream(stream);
			final ByteArrayOutputStream byteArrayOutputStreamInit = new ByteArrayOutputStream();
			final ElDCStandardServer elDCStandardServerInit = new ElDCStandardServer();

			final CustomOperationHandler elDCX509SignOperationHandlerInit = new CustomOperationHandler();
			
			elDCStandardServerInit.addOperationHandler((ElDCOperationHandler) elDCX509SignOperationHandlerInit);
			elDCStandardServerInit.process((InputStream) byteArrayInputStreamInit, (OutputStream) byteArrayOutputStreamInit);
			byte[] sig = byteArrayOutputStreamInit.toByteArray();
			byte[] d = elDCX509SignOperationHandlerInit.getDataToSign();
			
			byteArrayInputStreamInit.close();
			byteArrayOutputStreamInit.close();
			
			// step 2
			
			final ByteArrayInputStream byteArrayInputStreamFinal = new ByteArrayInputStream(stream);
			final ByteArrayOutputStream byteArrayOutputStreamFinal = new ByteArrayOutputStream();
			final ElDCStandardServer elDCStandardServerFinal = new ElDCStandardServer();

			final CustomOperationHandler elDCX509SignOperationHandlerFinal = new CustomOperationHandler();
	        
			
	        elDCX509SignOperationHandlerFinal.setSigningCertificate(signingCertificate);
	        elDCX509SignOperationHandlerFinal.setSignature(sign(d, privateKey, provider));
			elDCStandardServerFinal.addOperationHandler((ElDCOperationHandler) elDCX509SignOperationHandlerFinal);
			elDCStandardServerFinal.process((InputStream) byteArrayInputStreamFinal, (OutputStream) byteArrayOutputStreamFinal);

			byte[] signatureFinal = byteArrayOutputStreamFinal.toByteArray();
			
			byteArrayInputStreamFinal.close();
			byteArrayOutputStreamFinal.close();
			
			TElDCAsyncState state2 = new TElDCAsyncState();
			TElMemoryStream input = new TElMemoryStream(signatureFinal, 0, signatureFinal.length);
			state2.loadFromStream(input, SBDCXMLEnc.dcxmlEncoding());
			
			TElOfficeDocument of = new TElOfficeDocument();
			of.open(tmpFile);
			
			TElOfficeCustomSignatureHandler handler = of.getSignatureHandler(of
					.getSignatureHandlerCount() - 1);

			of.completeAsyncSign(handler, state2);
			of.close();
			input.Destroy();
			
			InputStream in = new FileInputStream(tmpFile);
	    	signedbytes = IOUtils.toByteArray(in);
	    	new File(tmpFile).delete();
	    	in.close();
			
			ResponseCode = Defines.CODE_SUCCESS;
	        ResponseMessage = Defines.SUCCESS;
	        
	        signResponse = new MultiSignerResponse(signedbytes, ResponseCode, ResponseMessage);
	    	

	    	/*
			TElX509Certificate userCert = new TElX509Certificate();
			
			userCert.fromX509Certificate(signingCertificate);
			//combine two cert
			userCert.setKeyMaterial(cert.getKeyMaterial());
			
			TElOfficeDocument _OfficeDocument = null;

			_OfficeDocument = new TElOfficeDocument();
			_OfficeDocument.open(tmpFile, false);

			if (_OfficeDocument.getIsEncrypted()) {
				//do something
				return new MultiSignerResponse(Defines.CODE_OFFICESIGNERISENCRYPT, Defines.ERROR_OFFICESIGNERISENCRYPT);
			}
			
			if(!_OfficeDocument.getSignable()) {
				//do something
				return new MultiSignerResponse(Defines.CODE_OFFICESIGNERCANSIGN, Defines.ERROR_OFFICESIGNERCANSIGN);
			}
			
	        try
	        {
	            if (_OfficeDocument.getOpenXMLDocument() != null)
	            {
	                TElOfficeOpenXMLSignatureHandler OpenXMLSigHandler = new TElOfficeOpenXMLSignatureHandler();
	                _OfficeDocument.addSignature(OpenXMLSigHandler, true);

	                OpenXMLSigHandler.addDocument();
	                
	                if(_reason == null) {
	                	OpenXMLSigHandler.getSignatureInfoV1().setIncluded(false);
	                } else if(_reason.compareTo("") == 0) {
	                	OpenXMLSigHandler.getSignatureInfoV1().setIncluded(false);
	                } else {
	                	OpenXMLSigHandler.getSignatureInfoV1().setSignatureComments(_reason);
	                	OpenXMLSigHandler.getSignatureInfoV1().setIncluded(true);
	                }
	                OpenXMLSigHandler.sign(userCert);
	                System.out.println("SignedOOXML OK");
	            }
	            else if (_OfficeDocument.getOpenXPSDocument() != null)
	            {

	                TElOfficeOpenXPSSignatureHandler OpenXPSSigHandler = new TElOfficeOpenXPSSignatureHandler();
	                _OfficeDocument.addSignature(OpenXPSSigHandler, true);

	                OpenXPSSigHandler.addDocument();
	                OpenXPSSigHandler.sign(userCert);
	                System.out.println("SignedXPS OK");
	            }
	            else if ((_OfficeDocument.getBinaryDocument() != null))
	            {
	            	
	                TElOfficeBinaryXMLSignatureHandler BinXMLSigHandler = new TElOfficeBinaryXMLSignatureHandler();
	                _OfficeDocument.addSignature(BinXMLSigHandler, true);
	                
	                if(_reason == null) {
	                	BinXMLSigHandler.getSignatureInfoV1().setIncluded(false);
	                } else if(_reason.compareTo("") == 0) {
	                	BinXMLSigHandler.getSignatureInfoV1().setIncluded(false);
	                } else {
	                	BinXMLSigHandler.getSignatureInfoV1().setSignatureComments(_reason);
	                	BinXMLSigHandler.getSignatureInfoV1().setIncluded(true);
	                }
	                BinXMLSigHandler.sign(userCert);
	
	                System.out.println("SignedBinary OK");
	            }
	            else if ((_OfficeDocument.getOpenDocument() != null))
	            {
	                TElOpenOfficeSignatureHandler ODFSigHandler = new TElOpenOfficeSignatureHandler();
	                _OfficeDocument.addSignature(ODFSigHandler, true);

	                ODFSigHandler.addDocument();
	                ODFSigHandler.sign(userCert);
	                System.out.println("SignedODF OK");
	            }
	            else
	            {
	            	return new MultiSignerResponse(Defines.CODE_INTERNALSYSTEM, Defines.ERROR_INTERNALSYSTEM);
	                //do something
	            }
	        }
	        catch (Exception ex)
	        {
	            ex.printStackTrace();
	            return new MultiSignerResponse(Defines.CODE_INTERNALSYSTEM, Defines.ERROR_INTERNALSYSTEM);
	            //do something
	        }
	        _OfficeDocument.close();
	        
	        InputStream in = new FileInputStream(tmpFile);
	    	signedbytes = IOUtils.toByteArray(in);
	    	new File(tmpFile).delete();
	    	in.close();
			
			ResponseCode = Defines.CODE_SUCCESS;
	        ResponseMessage = Defines.SUCCESS;
	        
	        signResponse = new MultiSignerResponse(signedbytes, ResponseCode, ResponseMessage);
	        */
		} catch (Exception e) {
			e.printStackTrace();
			return new MultiSignerResponse(Defines.CODE_INTERNALSYSTEM, Defines.ERROR_INTERNALSYSTEM);
		}
		return signResponse;
	}
	
	private byte[] sign(byte[] dtbs, PrivateKey privateKey, String provider) throws Exception {
		
		byte[] d = ExtFunc.padSHA1Oid(dtbs);
		
		Signature sig = Signature.getInstance("NONEwithRSA", provider);
		sig.initSign(privateKey);
		sig.update(d);
		return sig.sign();
	}
	
}


