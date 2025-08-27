package org.signserver.module.officesigner;

import java.io.IOException;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;

import javax.xml.bind.DatatypeConverter;
import javax.persistence.EntityManager;

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
import org.apache.log4j.Logger;
import javax.crypto.*;

import java.io.*;

import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;

import com.tomicalab.cryptos.CryptoS;

import SecureBlackbox.Base.JNI;
import SecureBlackbox.Base.SBUtils;
import SecureBlackbox.Base.TElX509Certificate;
import SecureBlackbox.Office.SBOfficeSecurity;
import SecureBlackbox.Office.TElOfficeBinaryCryptoAPISignatureHandler;
import SecureBlackbox.Office.TElOfficeBinaryXMLSignatureHandler;
import SecureBlackbox.Office.TElOfficeDocument;
import SecureBlackbox.Office.TElOfficeOpenXMLSignatureHandler;
import SecureBlackbox.Office.TElOfficeOpenXPSSignatureHandler;
import SecureBlackbox.Office.TElOfficeXMLSignatureInfoV1;
import SecureBlackbox.Office.TElOpenOfficeSignatureHandler;
import SecureBlackbox.PKI.SBPKCS11Base;
import SecureBlackbox.PKI.TElPKCS11CertStorage;
import SecureBlackbox.PKI.TElPKCS11SessionInfo;

public class OfficeSigner extends BaseSigner {
	private static final String CONTENT_TYPE = "text/xml";
	private static byte[] mCertificateChain;
	private String WORKERNAME = "OfficeSigner";
	private String ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
	private int ResponseCode = Defines.CODE_INTERNALSYSTEM;
	private String SHAREDLIBRARY = "sharedLibrary";
	private String JNI_32 = "JNI32";
	private String JNI_64 = "JNI64";
	private String PIN = "pin";
	private String DEFAULTKEY = "defaultKey";
	private String SLOT = "slot";

	private String jniPath;
	private String pinCode;
	private String sharedLib;
	private String defaultKey;
	private int slotInfo;
	private int jSlotInfo;

	UUID uuid = UUID.randomUUID();
	private static KeyStore ks = null;
	private static X509Certificate x509 = null;

	public static final Logger LOG = Logger.getLogger(OfficeSigner.class);

	private List<TElX509Certificate> certs = null;

	@Override
	public void init(int workerId, WorkerConfig config,
			WorkerContext workerContext, EntityManager workerEM) {
		// TODO Auto-generated method stub
		super.init(workerId, config, workerContext, workerEM);
	}

	@Override
	public ProcessResponse processData(ProcessRequest signRequest,
			RequestContext requestContext) throws IllegalRequestException,
			CryptoTokenOfflineException, SignServerException {
		// TODO Auto-generated method stub
		ProcessResponse signResponse = null;
		// Check that the request contains a valid GenericSignRequest object
		// with a byte[].
		// final String userContract =
		// RequestMetadata.getInstance(requestContext).get("UsernameContract");
		if (!(signRequest instanceof GenericSignRequest)) {
			throw new IllegalRequestException(
					"Recieved request wasn't a expected GenericSignRequest.");
		}

		final ISignRequest sReq = (ISignRequest) signRequest;
		if (!(sReq.getRequestData() instanceof byte[])) {
			throw new IllegalRequestException(
					"Recieved request data wasn't a expected byte[].");
		}

		byte[] data = (byte[]) sReq.getRequestData();

		byte[] signedbytes = null;

		final String archiveId = createArchiveId(data,
				(String) requestContext.get(RequestContext.TRANSACTION_ID));

		// check license for OfficeSigner
		LOG.info("Checking license for OfficeSigner.");
		License licInfo = License.getInstance();
		if (licInfo.getStatusCode() != 0) {
			return new GenericSignResponse(sReq.getRequestID(), archiveId,
					Defines.CODE_INFO_LICENSE, licInfo.getStatusDescription());
		} else {
			if (!licInfo.checkWorker(WORKERNAME)) {
				return new GenericSignResponse(sReq.getRequestID(), archiveId,
						Defines.CODE_INFO_LICENSE_NOTSUPPORT,
						Defines.ERROR_INFO_LICENSE_NOTSUPPORT);
			}
		}

		final Collection<? extends Archivable> archivables = Arrays
				.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
						CONTENT_TYPE, signedbytes, archiveId));
		try {
			X509Certificate signingCertificate = (X509Certificate) getSigningCertificate();

			String tmpFile = Defines.TMP_DIR + "/"
					+ UUID.randomUUID().toString();
			FileOutputStream output = new FileOutputStream(new File(tmpFile));
			IOUtils.write(data, output);
			output.close();

			if (System.getProperty("sun.arch.data.model").compareTo("32") == 0)
				jniPath = config.getProperties().getProperty(JNI_32);
			else
				jniPath = config.getProperties().getProperty(JNI_64);

			pinCode = config.getProperties().getProperty(PIN);
			sharedLib = config.getProperties().getProperty(SHAREDLIBRARY);
			defaultKey = config.getProperties().getProperty(DEFAULTKEY);
			slotInfo = Integer
					.valueOf(config.getProperties().getProperty(SLOT));
			jSlotInfo = Integer.valueOf(config.getProperties()
					.getProperty(SLOT));

			CryptoS.getInstance(IValidator.class, 1);
			SBOfficeSecurity.initialize();
			if (!JNI.isInitialized()) {
				JNI.initialize(jniPath);
			}

			TElPKCS11SessionInfo session = null;
			TElPKCS11CertStorage Storage = new TElPKCS11CertStorage();
			Storage.setDLLName(sharedLib);

			Storage.open();

			for (int i = 0; i < Storage.getModule().getSlotCount(); i++) {
				if ((long) jSlotInfo == Storage.getModule().getSlot(i)
						.getSlotID()) {
					slotInfo = i;
					break;
				}
			}

			boolean RO = Storage.getModule().getSlot(slotInfo).getReadOnly();

			try {
				session = Storage.openSession(slotInfo, RO);

			} catch (Exception ex) {

				if (!RO) {
					session = Storage.openSession(slotInfo, true);

				} else {
					// do something;
					return new GenericSignResponse(sReq.getRequestID(),
							archiveId, Defines.CODE_OFFICESIGNEREXP,
							Defines.ERROR_OFFICESIGNEREXP);
				}
			}

			// login
			try {

				session.login((int) SBPKCS11Base.utUser, pinCode);

			} catch (Exception ex) {
				ex.printStackTrace();
				Storage.closeSession(0);
				session = null;
				// do something
				return new GenericSignResponse(sReq.getRequestID(), archiveId,
						Defines.CODE_OFFICESIGNEREXP,
						Defines.ERROR_OFFICESIGNEREXP);
			}
			if (ks == null) {
				// pure java stuff
				String configValue = "name = PROVIDER" + uuid.toString()
						+ "\r\nlibrary = " + sharedLib + "\r\nslot = "
						+ jSlotInfo
						+ "\r\ndisabledMechanisms={ CKM_SHA1_RSA_PKCS }\r\n";
				Provider p = new sun.security.pkcs11.SunPKCS11(
						new ByteArrayInputStream(configValue.getBytes()));
				Security.addProvider(p);

				ks = KeyStore.getInstance("PKCS11", p);
				ks.load(null, pinCode.toCharArray());
				x509 = (X509Certificate) ks.getCertificate(defaultKey);
			} else {
				// System.out.println("ks != null");
			}

			TElX509Certificate telx509 = new TElX509Certificate();
			telx509.fromX509Certificate(x509);
			// System.out.println(telx509.getSubjectName().CommonName);
			int signingcertIndex = Storage.indexOf(telx509);
			// System.out.println("Cert index="+signingcertIndex);
			TElX509Certificate cert = null;
			if (signingcertIndex != -1)
				cert = Storage.getCertificate(signingcertIndex);

			/*
			 * X509Principal principal =
			 * PrincipalUtil.getSubjectX509Principal(x509); Vector<?> values =
			 * principal.getValues(X509Name.CN); String cn = (String)
			 * values.get(0);
			 * 
			 * TElX509Certificate cert = null; //get all certs int numOfCert =
			 * Storage.getCount(); for (int i = 0; i < numOfCert; i++) { cert =
			 * Storage.getCertificate(i); String tAlias =
			 * "VNPT Viettel SmartSign CA2 FPT-CA SAFE-CA "+defaultKey;
			 * if(cert.getSubjectName().CommonName.compareTo(defaultKey) == 0 ||
			 * cert.getSubjectName().CommonName.compareTo(tAlias) == 0 ||
			 * cert.getSubjectName().CommonName.compareTo(cn) == 0) { break; }
			 * else { cert = null; } }
			 */
			if (cert == null) {
				// do something
				return new GenericSignResponse(sReq.getRequestID(), archiveId,
						Defines.CODE_OFFICESIGNERNOKEY,
						Defines.ERROR_OFFICESIGNERNOKEY);
			}

			TElX509Certificate userCert = new TElX509Certificate();

			userCert.fromX509Certificate(signingCertificate);
			// combine two cert
			userCert.setKeyMaterial(cert.getKeyMaterial());

			TElOfficeDocument _OfficeDocument = null;

			_OfficeDocument = new TElOfficeDocument();
			_OfficeDocument.open(tmpFile, false);
			
			if (_OfficeDocument.getIsEncrypted()) {
				// do something
				return new GenericSignResponse(sReq.getRequestID(), archiveId,
						Defines.CODE_OFFICESIGNERISENCRYPT,
						Defines.ERROR_OFFICESIGNERISENCRYPT);
			}

			if (!_OfficeDocument.getSignable()) {
				// do something
				return new GenericSignResponse(sReq.getRequestID(), archiveId,
						Defines.CODE_OFFICESIGNERCANSIGN,
						Defines.ERROR_OFFICESIGNERCANSIGN);
			}

			try {
				if (_OfficeDocument.getOpenXMLDocument() != null) {
					TElOfficeOpenXMLSignatureHandler OpenXMLSigHandler = new TElOfficeOpenXMLSignatureHandler();
					_OfficeDocument.addSignature(OpenXMLSigHandler, true);

					OpenXMLSigHandler.addDocument();
					OpenXMLSigHandler.getSignatureInfoV1().setIncluded(false);
					OpenXMLSigHandler.sign(userCert);
					System.out.println("SignedOOXML OK");
				} else if (_OfficeDocument.getOpenXPSDocument() != null) {

					TElOfficeOpenXPSSignatureHandler OpenXPSSigHandler = new TElOfficeOpenXPSSignatureHandler();
					_OfficeDocument.addSignature(OpenXPSSigHandler, true);

					OpenXPSSigHandler.addDocument();
					OpenXPSSigHandler.sign(userCert);
					System.out.println("SignedXPS OK");
				} else if ((_OfficeDocument.getBinaryDocument() != null)) {

					TElOfficeBinaryXMLSignatureHandler BinXMLSigHandler = new TElOfficeBinaryXMLSignatureHandler();
					_OfficeDocument.addSignature(BinXMLSigHandler, true);

					BinXMLSigHandler.getSignatureInfoV1().setIncluded(false);

					BinXMLSigHandler.sign(userCert);

					System.out.println("SignedBinary OK");
				} else if ((_OfficeDocument.getOpenDocument() != null)) {
					TElOpenOfficeSignatureHandler ODFSigHandler = new TElOpenOfficeSignatureHandler();
					_OfficeDocument.addSignature(ODFSigHandler, true);

					ODFSigHandler.addDocument();
					ODFSigHandler.sign(userCert);
					System.out.println("SignedODF OK");
				} else {
					return new GenericSignResponse(sReq.getRequestID(),
							archiveId, Defines.CODE_OFFICESIGNERCANSIGN,
							Defines.ERROR_OFFICESIGNERCANSIGN);
					// do something
				}
			} catch (Exception ex) {
				ex.printStackTrace();
				return new GenericSignResponse(sReq.getRequestID(), archiveId,
						Defines.CODE_OFFICESIGNERCANSIGN,
						Defines.ERROR_OFFICESIGNERCANSIGN);
				// do something
			}
			_OfficeDocument.close();
			// session.logout();
			// Storage.closeAllSessions(Storage.getModule().getSlot(slotInfo));

			InputStream in = new FileInputStream(tmpFile);
			signedbytes = IOUtils.toByteArray(in);
			new File(tmpFile).delete();
			in.close();
			
			ResponseCode = Defines.CODE_SUCCESS;
			ResponseMessage = Defines.SUCCESS;
			signResponse = new GenericSignResponse(sReq.getRequestID(),
					signedbytes, getSigningCertificate(), null, archiveId,
					archivables, ResponseCode, ResponseMessage);

		} catch (Exception e) {
			e.printStackTrace();
			return new GenericSignResponse(sReq.getRequestID(), archiveId,
					Defines.CODE_OFFICESIGNEREXP, Defines.ERROR_OFFICESIGNEREXP);
		}
		return signResponse;
	}

}
