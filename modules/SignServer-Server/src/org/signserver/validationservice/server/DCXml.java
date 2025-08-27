package org.signserver.validationservice.server;

import SecureBlackbox.Base.SBDCPKIConstants;
import SecureBlackbox.Base.SBEncoding;
import SecureBlackbox.Base.SBUtils;
import SecureBlackbox.Base.TElDCAsyncState;
import SecureBlackbox.Base.TElDCBaseMessage;
import SecureBlackbox.Base.TElDCOperationResponseMessage;
import SecureBlackbox.Base.TElMemoryStream;
import SecureBlackbox.Base.TElX509Certificate;
import SecureBlackbox.Base.TSBObject;
import SecureBlackbox.DC.SBDCXMLEnc;
import SecureBlackbox.HTTPClient.SBHTTPCRL;
import SecureBlackbox.HTTPClient.SBHTTPCertRetriever;
import SecureBlackbox.HTTPClient.SBHTTPOCSPClient;
import SecureBlackbox.LDAP.SBLDAPCRL;
import SecureBlackbox.LDAP.SBLDAPCertRetriever;
import SecureBlackbox.XML.SBXMLDefs;
import SecureBlackbox.XML.SBXMLUtils;
import SecureBlackbox.XML.TElXMLDOMDocument;
import SecureBlackbox.XMLSecurity.SBXMLSec;
import SecureBlackbox.XMLSecurity.TElXMLEnvelopedSignatureTransform;
import SecureBlackbox.XMLSecurity.TElXMLKeyInfoX509Data;
import SecureBlackbox.XMLSecurity.TElXMLReference;
import SecureBlackbox.XMLSecurity.TElXMLSigner;

import org.signserver.validationservice.server.dcsigner.*;
import org.signserver.validationservice.server.dcsigner.signprocess.*;
import org.signserver.validationservice.server.dcsigner.signprocess.handlers.*;
import org.apache.commons.io.IOUtils;

import java.io.*;
import java.awt.image.BufferedImage;

import javax.imageio.ImageIO;

import org.signserver.common.util.*;

import com.tomicalab.cryptos.CryptoS;

import org.signserver.validationservice.server.IValidator;
import org.signserver.common.*;
import org.apache.log4j.Logger;

import javax.xml.bind.DatatypeConverter;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

public class DCXml implements DC {
	
	private static String DEFAULT_URI = "data";
	private static String DEFAULT_URINODE = "#data";
	private static String DEFAULT_SIGNATURE_PREFIX = "#default";
	
	public DCXml() {
		CryptoS.getInstance(IValidator.class, 1);
		SBHTTPCRL.registerHTTPCRLRetrieverFactory();
        SBLDAPCRL.registerLDAPCRLRetrieverFactory();
        SBHTTPOCSPClient.registerHTTPOCSPClientFactory();
        SBHTTPCertRetriever.registerHTTPCertificateRetrieverFactory();
        SBLDAPCertRetriever.registerLDAPCertificateRetrieverFactory();
	}
	
	public DCXmlResponse signInit(byte[] fileData, Properties signaturePro) {
		
		DCXmlResponse response = new DCXmlResponse();
		try {
			// signature propeties
			String uri = null;
			try {
				uri = signaturePro.getProperty(Defines._URI);
			} catch(NullPointerException e) {
				
			}
			if(uri == null) {
				uri = DEFAULT_URI;
			}
			
			String uriNode = null;
			try {
				uriNode = signaturePro.getProperty(Defines._URINODE);
			} catch(NullPointerException e) {
				
			}
			if(uriNode == null) {
				uriNode = DEFAULT_URINODE;
			}
			
			String signaturePrefix = null;
			try {
				signaturePrefix = signaturePro.getProperty(Defines._SIGNATUREPREFIX);
			} catch(NullPointerException e) {
				
			}
			if(signaturePrefix == null) {
				signaturePrefix = DEFAULT_SIGNATURE_PREFIX;
			}
			
			byte[] docBin = fileData;
			
			TElMemoryStream doc = new TElMemoryStream(docBin, 0, docBin.length);
			
			TElMemoryStream output = new TElMemoryStream();
			
			TElDCAsyncState state;

	        TElXMLDOMDocument xml = new TElXMLDOMDocument();
	        xml.loadFromStream(doc);
			
	        TElXMLSigner signer = new TElXMLSigner();
	        signer.setSignatureType(SBXMLSec.xstEnveloped);
	        signer.setSignatureMethodType(SBXMLSec.xmtSig);
	        signer.setSignatureMethod(SBXMLSec.xsmRSA_SHA1);
	        signer.setIncludeKey(true);
	       
	        TElXMLReference ref = new TElXMLReference();
	        ref.setDigestMethod(SBXMLSec.xdmSHA1);
	        
	        ref.getTransformChain().add(new TElXMLEnvelopedSignatureTransform());
	        ref.setURINode(SBXMLUtils.findElementById(xml.getDocumentElement(), uri));
	        ref.setURI(uriNode);
	        
	        ref.getTransformChain().add(new TElXMLEnvelopedSignatureTransform());
	        signer.getReferences().add(ref);

	        signer.updateReferencesDigest();
	        signer.generateSignatureAsync();
	        signer.getSignature().setSignaturePrefix(signaturePrefix);

	        TSBObject var = new TSBObject();
	        var.value = xml.getDocumentElement();

	        state = signer.initiateAsyncSign(var);
	        state.saveToStream(output, SBDCXMLEnc.dcxmlEncoding());

	        doc.setLength(0);
	        xml.saveToStream(doc, SBXMLDefs.xcmNone, "");
	        
	        String datatosend = SBEncoding.base64EncodeArray(output.getBuffer(), false);
	        
	        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(ElBase64.decodeString(datatosend));
	        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
	        final ElDCStandardServer elDCStandardServer = new ElDCStandardServer();
	        
	        final CustomOperationHandler elDCX509SignOperationHandler = new CustomOperationHandler();

	        elDCStandardServer.addOperationHandler((ElDCOperationHandler)elDCX509SignOperationHandler);
	        elDCStandardServer.process((InputStream)byteArrayInputStream, (OutputStream)byteArrayOutputStream);
			
	        byte[] sig = byteArrayOutputStream.toByteArray();
	        byte[] d = elDCX509SignOperationHandler.getDataToSign();
	        
	        String streamDataPath = Defines.TMP_DIR + "/" + UUID.randomUUID().toString();
			FileOutputStream oStreamDataPath = new FileOutputStream(new File(streamDataPath));
	    	IOUtils.write(doc.getBuffer(), oStreamDataPath);
	    	oStreamDataPath.close();
			
	    	String streamSignPath = Defines.TMP_DIR + "/" + UUID.randomUUID().toString();
	    	FileOutputStream oStreamSignPath = new FileOutputStream(new File(streamSignPath));
	    	IOUtils.write(output.getBuffer(), oStreamSignPath);
	    	oStreamSignPath.close();
	    	
			response.setResponseCode(Defines.CODE_SUCCESS);
			response.setResponseMessage(Defines.SUCCESS);
			response.setData(d);
			response.setAsynStreamDataPath(streamDataPath);
			response.setAsynStreamSignPath(streamSignPath);
		} catch(Exception e) {
			e.printStackTrace();
			response.setResponseCode(Defines.CODE_INTERNALSYSTEM);
			response.setResponseMessage(Defines.ERROR_INTERNALSYSTEM);
			response.setData(null);
		}
		return response;
	}
	
	public DCXmlResponse signFinal(String dcStreamDataPath, String dcStreamSignPath, byte[] signature, String base64Cert) {
		DCXmlResponse response = new DCXmlResponse();
		try {
			byte[] stream = IOUtils.toByteArray(new FileInputStream(dcStreamSignPath));
			
	        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(stream);
	        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
	        final ElDCStandardServer elDCStandardServer = new ElDCStandardServer();
	        
	        final CustomOperationHandler elDCX509SignOperationHandler = new CustomOperationHandler();
	        
	        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
	        InputStream in = new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(base64Cert));
	        X509Certificate x509 = (X509Certificate) certFactory.generateCertificate(in);
	        
	        
	        elDCX509SignOperationHandler.setSigningCertificate(x509);
	        elDCX509SignOperationHandler.setSignature(signature);
	        elDCStandardServer.addOperationHandler((ElDCOperationHandler)elDCX509SignOperationHandler);
	        elDCStandardServer.process((InputStream)byteArrayInputStream, (OutputStream)byteArrayOutputStream);
			
	        byte[] sig = byteArrayOutputStream.toByteArray();
			
			TElDCAsyncState state2 = new TElDCAsyncState();
	        TElMemoryStream input = new TElMemoryStream(sig, 0, sig.length);
	        state2.loadFromStream(input, SBDCXMLEnc.dcxmlEncoding());
	        
	        
	        byte[] savedDoc = IOUtils.toByteArray(new FileInputStream(dcStreamDataPath));
	        
	        TElMemoryStream result = new TElMemoryStream(savedDoc, 0, savedDoc.length);
	        TElXMLDOMDocument doc2 = new TElXMLDOMDocument();
	        doc2.loadFromStream(result);
	        TElXMLSigner signer2 = new TElXMLSigner();
	        TElXMLKeyInfoX509Data x509Data = new TElXMLKeyInfoX509Data(true);
	        
	        TElDCBaseMessage msg = state2.findMessageByType(TElDCOperationResponseMessage.class);
	        if (msg != null) {
	            byte[] buf = ((TElDCOperationResponseMessage)msg).getKeysRDN().getFirstValueByOID(SBDCPKIConstants.SB_OID_DC_SIGNING_CERTIFICATE.Data);
	            TElX509Certificate cert = new TElX509Certificate();
	            if (cert.loadFromBufferAuto(buf, 0, buf.length, "") == 0) {
	                x509Data.setCertificate(cert);
	                signer2.setKeyData(x509Data);
	                signer2.setIncludeKey(true);
	            }

	            signer2.completeAsyncSign(doc2, state2);
	        }

	        result.setLength(0);
	        doc2.saveToStream(result);
	        result.setPosition(0);
	        
	        byte[] signedFile = result.getBuffer();
	        response.setResponseCode(Defines.CODE_SUCCESS);
			response.setResponseMessage(Defines.SUCCESS);
			response.setData(signedFile);
		} catch(Exception e) {
			e.printStackTrace();
			response.setResponseCode(Defines.CODE_INTERNALSYSTEM);
			response.setResponseMessage(Defines.ERROR_INTERNALSYSTEM);
			response.setData(null);
		}
		return response;
	}
	
}