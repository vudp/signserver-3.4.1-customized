package org.signserver.validationservice.server;



import java.io.*;
import java.util.*;
import java.security.cert.X509Certificate;
import SecureBlackbox.Base.TElDCAsyncState;
import SecureBlackbox.Base.TElMemoryStream;
import SecureBlackbox.DC.SBDCXMLEnc;
import SecureBlackbox.Office.SBOfficeSecurity;
import SecureBlackbox.Office.TElOfficeBinaryXMLSignatureHandler;
import SecureBlackbox.Office.TElOfficeCustomSignatureHandler;
import SecureBlackbox.Office.TElOfficeDocument;
import SecureBlackbox.Office.TElOfficeOpenXMLSignatureHandler;

import org.signserver.validationservice.server.dcsigner.*;
import org.signserver.validationservice.server.dcsigner.signprocess.*;
import org.signserver.validationservice.server.dcsigner.signprocess.handlers.*;

import org.signserver.common.util.*;
import com.tomicalab.cryptos.CryptoS;
import org.apache.log4j.Logger;
import org.apache.commons.io.IOUtils;

public class DCOffice implements DC {
	
	private static final Logger LOG = Logger.getLogger(DCOffice.class);
	
	public DCOffice() {
		CryptoS.getInstance(IValidator.class, 1);
		SBOfficeSecurity.initialize();
	}
	/*
	public DCOfficeResponse signInit(byte[] fileData, Properties signaturePro) {
		DCOfficeResponse response = new DCOfficeResponse();
		try {
			byte[] docBin = fileData;
			
			TElMemoryStream doc = new TElMemoryStream(docBin, 0, docBin.length);
	
			TElOfficeDocument _OfficeDocument = new TElOfficeDocument();
			_OfficeDocument.open(doc);
	
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
				
			} else {
				LOG.error("Invalid office format");
				response.setResponseCode(Defines.CODE_UNKNOWN);
				response.setResponseMessage(Defines.ERROR_UNKNOWN);
				response.setData(null);
				return response;
			}
	
			state.saveToStream(output, SBDCXMLEnc.dcxmlEncoding());
			_OfficeDocument.close();
			
			final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(output.getBuffer());
			final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			final ElDCStandardServer elDCStandardServer = new ElDCStandardServer();
	
			final CustomOperationHandler elDCX509SignOperationHandler = new CustomOperationHandler();
			elDCStandardServer.addOperationHandler((ElDCOperationHandler) elDCX509SignOperationHandler);
			elDCStandardServer.process((InputStream) byteArrayInputStream, (OutputStream) byteArrayOutputStream);
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
			response.setResponseCode(Defines.CODE_UNKNOWN);
			response.setResponseMessage(Defines.ERROR_UNKNOWN);
			response.setData(null);
		}
		return response;
	}
	
	public DCOfficeResponse signFinal(String dcStreamDataPath, String dcStreamSignPath, byte[] signature, String base64Cert) {
		DCOfficeResponse response = new DCOfficeResponse();
		try {
			
			byte[] stream = IOUtils.toByteArray(new FileInputStream(dcStreamSignPath));

			final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(stream);
			final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			final ElDCStandardServer elDCStandardServer = new ElDCStandardServer();

			final CustomOperationHandler elDCX509SignOperationHandler = new CustomOperationHandler();
			
	        X509Certificate x509 = ExtFunc.convertToX509Cert(base64Cert);
			
	        elDCX509SignOperationHandler.setSigningCertificate(x509);
	        elDCX509SignOperationHandler.setSignature(signature);
			elDCStandardServer.addOperationHandler((ElDCOperationHandler) elDCX509SignOperationHandler);
			elDCStandardServer.process((InputStream) byteArrayInputStream,
					(OutputStream) byteArrayOutputStream);

			byte[] sig = byteArrayOutputStream.toByteArray();
			
			TElDCAsyncState state2 = new TElDCAsyncState();
			TElMemoryStream input = new TElMemoryStream(sig, 0, sig.length);
			state2.loadFromStream(input, SBDCXMLEnc.dcxmlEncoding());

			byte[] savedDoc = IOUtils.toByteArray(new FileInputStream(dcStreamDataPath));
			TElMemoryStream doc = new TElMemoryStream(savedDoc, 0, savedDoc.length);
			
			TElOfficeDocument of = new TElOfficeDocument();
			of.open(doc);
			
			TElOfficeCustomSignatureHandler handler = of.getSignatureHandler(of
					.getSignatureHandlerCount() - 1);

			of.completeAsyncSign(handler, state2);

			of.close();
			
			byte[] signedFile = doc.getBuffer();
			
			response.setResponseCode(Defines.CODE_SUCCESS);
			response.setResponseMessage(Defines.SUCCESS);
			response.setData(signedFile);
		} catch(Exception e) {
			e.printStackTrace();
			response.setResponseCode(Defines.CODE_UNKNOWN);
			response.setResponseMessage(Defines.ERROR_UNKNOWN);
			response.setData(null);
		}
		return response;
	}
	*/
	public DCOfficeResponse signInit(byte[] fileData, Properties signaturePro) {
		DCOfficeResponse response = new DCOfficeResponse();
		try {
			
			String streamDataPath = Defines.TMP_DIR + "/" + UUID.randomUUID().toString();
			FileOutputStream oStreamDataPath = new FileOutputStream(new File(streamDataPath));
	    	IOUtils.write(fileData, oStreamDataPath);
	    	oStreamDataPath.close();
	
			TElOfficeDocument _OfficeDocument = new TElOfficeDocument();
			_OfficeDocument.open(streamDataPath);
	
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
				
			} else {
				LOG.error("Invalid office format");
				response.setResponseCode(Defines.CODE_INTERNALSYSTEM);
				response.setResponseMessage(Defines.ERROR_INTERNALSYSTEM);
				response.setData(null);
				return response;
			}
	
			state.saveToStream(output, SBDCXMLEnc.dcxmlEncoding());
			_OfficeDocument.close();
			
			final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(output.getBuffer());
			final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			final ElDCStandardServer elDCStandardServer = new ElDCStandardServer();
	
			final CustomOperationHandler elDCX509SignOperationHandler = new CustomOperationHandler();
			elDCStandardServer.addOperationHandler((ElDCOperationHandler) elDCX509SignOperationHandler);
			elDCStandardServer.process((InputStream) byteArrayInputStream, (OutputStream) byteArrayOutputStream);
			byte[] sig = byteArrayOutputStream.toByteArray();
			byte[] d = elDCX509SignOperationHandler.getDataToSign();
			
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
	
	public DCOfficeResponse signFinal(String dcStreamDataPath, String dcStreamSignPath, byte[] signature, String base64Cert) {
		DCOfficeResponse response = new DCOfficeResponse();
		try {
			
			byte[] stream = IOUtils.toByteArray(new FileInputStream(dcStreamSignPath));

			final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(stream);
			final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			final ElDCStandardServer elDCStandardServer = new ElDCStandardServer();

			final CustomOperationHandler elDCX509SignOperationHandler = new CustomOperationHandler();
			
	        X509Certificate x509 = ExtFunc.convertToX509Cert(base64Cert);
			
	        elDCX509SignOperationHandler.setSigningCertificate(x509);
	        elDCX509SignOperationHandler.setSignature(signature);
			elDCStandardServer.addOperationHandler((ElDCOperationHandler) elDCX509SignOperationHandler);
			elDCStandardServer.process((InputStream) byteArrayInputStream,
					(OutputStream) byteArrayOutputStream);

			byte[] sig = byteArrayOutputStream.toByteArray();
			
			TElDCAsyncState state2 = new TElDCAsyncState();
			TElMemoryStream input = new TElMemoryStream(sig, 0, sig.length);
			state2.loadFromStream(input, SBDCXMLEnc.dcxmlEncoding());
			
			TElOfficeDocument of = new TElOfficeDocument();
			of.open(dcStreamDataPath);
			
			TElOfficeCustomSignatureHandler handler = of.getSignatureHandler(of
					.getSignatureHandlerCount() - 1);

			of.completeAsyncSign(handler, state2);

			of.close();
			
			byte[] signedFile = IOUtils.toByteArray(new FileInputStream(dcStreamDataPath));
			
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