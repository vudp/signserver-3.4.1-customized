package org.signserver.common;

import com.tomicalab.cag360.license.*;
import org.signserver.common.util.*;
import org.apache.log4j.Logger;

public class License {
	
	private static final Logger LOG = Logger.getLogger(License.class);
	
	private static License instance;
	private byte[] rawLic;
	private LicInfoV3 licInfo;
	private int statusCode;
	private String statusDescription;

	public static License getInstance() {
		
		if (instance == null) {
			instance = new License();
		}
		return instance;
	}

	private License() {
		try {
			rawLic = DBConnector.getInstances().authGetLicenseInfo();
			licInfo = (new LicInfoV3(rawLic)).getLicInfo();
			String hardwareInfo = licInfo.getHardwareInfoValue();
			statusCode = licInfo.getStatusCode();
			statusDescription = licInfo.getStatusDescription();
			LOG.info("License Status Code: "+statusCode);
			LOG.info("License Status Description: "+statusDescription);
		} catch (Exception e) {
			e.printStackTrace();
			statusCode = 1;
			statusDescription = "Your license is invalid";
		}
	}
	
	public LicInfoV3 getLicenseInfoV3() {
		return licInfo;
	}

	public int getStatusCode() {
		return statusCode;
	}

	public String getStatusDescription() {
		return statusDescription;
	}
	
	public String getLicenseType() {
		return licInfo.getLicenseType();
	}
	
	public String getHardwareId() {
		HardwareInfo hw = new HardwareInfo();
		return hw.getHardwareId();
	}

	public boolean checkKeystore(int numkey) {
		if (licInfo.getLicenseType().equals("Unlimited"))
			return true;
		int certNo = licInfo.getCertificateLicenseNo();
		if (certNo <= numkey)
			return false;
		return true;
	}

	public boolean checkTransaction() {
		if (licInfo.getLicenseType().equals("Unlimited"))
			return true;
		int licNo = licInfo.getPerFormanceLicenseNo();
		int dbNo = DBConnector.getInstances().authGetSuccessTransaction();
		if (licNo < dbNo)
			return false;
		return true;
	}

	public boolean checkWorker(String workerName) {
		if (licInfo.getLicenseType().equals("Unlimited"))
			return true;
		/*
		System.out.println("isIsPdfSigner: "+ licInfo.isIsPdfSigner());
		System.out.println("isIsXmlSigner: "+ licInfo.isIsXmlSigner());
		System.out.println("isIsOfficeSigner: "+ licInfo.isIsOfficeSigner());
		System.out.println("isIsCmsSigner: "+ licInfo.isIsCmsSigner());
		System.out.println("isIsPkcs1Signer: "+ licInfo.isIsPkcs1Signer());
		System.out.println("isIsPdfValidator: "+ licInfo.isIsPdfValidator());
		System.out.println("isIsOfficeValidator: "+ licInfo.isIsOfficeValidator());
		System.out.println("isIsXmlValidator: "+ licInfo.isIsXmlValidator());
		System.out.println("isIsFidoValidator: "+ licInfo.isIsFidoValidator());
		System.out.println("isIsOathValidator: "+ licInfo.isIsOathValidator());
		System.out.println("isIsMobileOtp: "+ licInfo.isIsMobileOtp());
		System.out.println("isIsCmsValidator: "+ licInfo.isIsCmsValidator());
		System.out.println("isIsPkcs1Validator: "+ licInfo.isIsPkcs1Validator());
		System.out.println("isIsDcSigner: "+ licInfo.isIsDcSigner());
		System.out.println("isIsSignerAp: "+ licInfo.isIsSignerAp());
		System.out.println("isIsMultiSigner: "+ licInfo.isIsMultiSigner());
		*/
		boolean accept = false;
		if (workerName.compareTo(Defines.WORKER_PDFSIGNER) == 0) {
			accept = licInfo.isIsPdfSigner();
			return accept;
		} else if (workerName.compareTo(Defines.WORKER_XMLSIGNER) == 0) {
			accept = licInfo.isIsXmlSigner(); 
			return accept;
		} else if (workerName.compareTo(Defines.WORKER_OFFICESIGNER) == 0) {
			accept = licInfo.isIsOfficeSigner(); 
			return accept;
		} else if (workerName.compareTo(Defines.WORKER_MRTDSIGNER) == 0) {
			accept = licInfo.isIsMrtdSigner();
			return accept;
		} else if (workerName.compareTo(Defines.WORKER_CMSSIGNER) == 0) {
			accept = licInfo.isIsCmsSigner();
			return accept;
		} else if (workerName.compareTo(Defines.WORKER_PKCS1SIGNER) == 0) {
			accept = licInfo.isIsPkcs1Signer();
			return accept;
		} else if (workerName.compareTo(Defines.WORKER_PDFVALIDATOR) == 0) {
			accept = licInfo.isIsPdfValidator();
			return accept;
		} else if (workerName.compareTo(Defines.WORKER_OFFICEVALIDATOR) == 0) {
			accept = licInfo.isIsOfficeValidator();
			return accept;
		} else if (workerName.compareTo(Defines.WORKER_XMLVALIDATOR) == 0) {
			accept = licInfo.isIsXmlValidator();
			return accept;
		} else if (workerName.compareTo(Defines.WORKER_FIDOVALIDATOR) == 0) {
			accept = licInfo.isIsFidoValidator();
			return accept;
		} else if (workerName.compareTo(Defines.WORKER_OATHVALIDATOR) == 0) {
			accept = licInfo.isIsOathValidator();
			return accept;
		} else if (workerName.compareTo(Defines.WORKER_MOBILEOTPVALIDATOR) == 0) {
			accept = licInfo.isIsMobileOtp();
			return accept;
		} else if (workerName.compareTo(Defines.WORKER_CAPICOMVALIDATOR) == 0) {
			accept = licInfo.isIsCmsValidator();
			return accept;
		} else if (workerName.compareTo(Defines.WORKER_PKCS1VALIDATOR) == 0) {
			accept = licInfo.isIsPkcs1Validator();
			return accept;
		} else if (workerName.compareTo(Defines.WORKER_DCSIGNER) == 0) {
			accept = licInfo.isIsDcSigner();
			return accept;
		} else if (workerName.compareTo(Defines.WORKER_SIGNERAP) == 0) {
			accept = licInfo.isIsSignerAp();
			return accept;
		} else if (workerName.compareTo(Defines.WORKER_MULTISIGNER) == 0) {
			accept = licInfo.isIsMultiSigner();
			return accept;
		} else if(workerName.compareTo(Defines.WORKER_MULTIVALIDATOR) == 0) {
			accept = licInfo.isIsMultiValidator();
			return accept;
		} else if(workerName.compareTo(Defines.WORKER_SIGNATUREVALIDATOR) == 0) {
			accept = licInfo.isIsSignatureValidator();
			return accept;
		} else if(workerName.compareTo(Defines.WORKER_GENERALVALIDATOR) == 0) {
			accept = licInfo.isIsGeneralValidator();
			return accept;
		} else {
			return false;
		}
	}
	
	public void reloadLicense() {
		try {
			rawLic = DBConnector.getInstances().authGetLicenseInfo();
			licInfo = (new LicInfoV3(rawLic)).getLicInfo();
			String hardwareInfo = licInfo.getHardwareInfoValue();
			statusCode = licInfo.getStatusCode();
			statusDescription = licInfo.getStatusDescription();
			LOG.info("Reload license Status Code: "+statusCode);
			LOG.info("Reload license Status Description: "+statusDescription);
		} catch (Exception e) {
			e.printStackTrace();
			statusCode = 1;
			statusDescription = "Your license is invalid";
		}
	}
}