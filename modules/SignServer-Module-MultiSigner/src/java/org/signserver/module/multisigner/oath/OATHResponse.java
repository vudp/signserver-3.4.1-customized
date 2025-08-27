package org.signserver.module.multisigner.oath;

import org.signserver.common.*;
import org.signserver.module.multisigner.*;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.WorkerContext;
import org.signserver.server.signers.BaseSigner;
import javax.persistence.EntityManager;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import java.io.*;
import java.util.*;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import javax.xml.bind.DatatypeConverter;
import java.util.LinkedList;
import java.util.List;
import org.apache.log4j.Logger;
import org.signserver.server.BaseProcessable;
import org.signserver.validationservice.common.ValidateRequest;
import org.signserver.validationservice.common.ValidationServiceConstants;
import java.text.SimpleDateFormat;
import org.signserver.common.util.*;

public class OATHResponse {

	private static OATHResponse instance;

	public static OATHResponse getInstance() {
		if (instance == null) {
			instance = new OATHResponse();
		}
		return instance;
	}

	private static final Logger LOG = Logger.getLogger(OATHResponse.class);

	private static final String CONTENT_TYPE = "text/xml";
	private static String WORKERNAME = "OATHResponse";
	private int ResponseCode = Defines.CODE_INTERNALSYSTEM;
	private String ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
	private Properties propertiesData;

	public MultiSignerResponse processData(String channelName, String user,
			RequestContext requestContext) {
		// TODO Auto-generated method stub
		MultiSignerResponse signResponse;

		final String billCode = RequestMetadata.getInstance(requestContext).get(Defines._BILLCODE);
		final String otp = RequestMetadata.getInstance(requestContext).get(Defines._OTP);

		String s = "OK";
		
		if (!ExtFunc.isNumeric(otp)) {
			LOG.info("Non Numeric OTP");
			return new MultiSignerResponse(Defines.CODE_OTP_STATUS_FAIL,
					Defines.OTP_STATUS_FAIL);
		}
		int transId = ExtFunc.getTransId(billCode);
        String [] otpTransaction = DBConnector.getInstances().authGetAsyncTransaction(transId);
        
        if(otpTransaction == null) {
        	LOG.info("No billcode found for otp authentication "+billCode);
        	return new MultiSignerResponse(Defines.CODE_INVALIDTRANSACSTATUS, Defines.ERROR_INVALIDTRANSACSTATUS);
        }
        
        if(billCode.compareTo(otpTransaction[5]) != 0) {
        	DBConnector.getInstances().authResetOTPTransaction(transId);
        	return new MultiSignerResponse(Defines.CODE_INVALIDTRANSACSTATUS, Defines.ERROR_INVALIDTRANSACSTATUS);
        }
        
        if(user.compareTo(otpTransaction[15]) != 0) {
        	DBConnector.getInstances().authResetOTPTransaction(transId);
        	return new MultiSignerResponse(Defines.CODE_INVALIDTRANSACSTATUS, Defines.ERROR_INVALIDTRANSACSTATUS);
        }

		try {
			if(otpTransaction[4].compareTo(Defines.OTP_STATUS_SUCC) == 0) {
				DBConnector.getInstances().authResetOTPTransaction(transId);
				return new MultiSignerResponse(Defines.CODE_OTP_STATUS_EXPI, Defines.OTP_STATUS_EXPI);
			} else if(otpTransaction[4].compareTo(Defines.OTP_STATUS_WAIT) == 0) {
				try {
					Date dateVerify = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.S").parse(otpTransaction[1]);
					Date dateNow = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.S").parse(otpTransaction[3]);
					if(dateVerify.compareTo(dateNow) < 0) {
						DBConnector.getInstances().authSetOTPTransactionStatus(transId, Defines.OTP_STATUS_TIME);
						DBConnector.getInstances().authResetOTPTransaction(transId);
						return new MultiSignerResponse(Defines.CODE_OTP_STATUS_TIME, Defines.OTP_STATUS_TIME);
						
					}
					
					if(otp.compareTo(otpTransaction[2]) == 0) {
						if(otp.equals(otpTransaction[2])) {
							DBConnector.getInstances().authSetOTPTransactionStatus(transId, Defines.OTP_STATUS_SUCC);
							DBConnector.getInstances().authResetOTPTransaction(transId);
							MultiSignerResponse multiSignerResponse = new MultiSignerResponse(Defines.CODE_SUCCESS, Defines.SUCCESS);
							multiSignerResponse.setArrayData(otpTransaction);
							return multiSignerResponse;
						} else {
							DBConnector.getInstances().authResetOTPTransaction(transId);
							return new MultiSignerResponse(Defines.CODE_OTP_STATUS_FAIL, Defines.OTP_STATUS_FAIL);
						}
					} else {
						DBConnector.getInstances().authResetOTPTransaction(transId);
						return new MultiSignerResponse(Defines.CODE_OTP_STATUS_FAIL, Defines.OTP_STATUS_FAIL);
					}
				} catch(Exception e) {
					e.printStackTrace();
					LOG.error("ServerException. Details: "+e.getMessage());
					DBConnector.getInstances().authResetOTPTransaction(transId);
					return new MultiSignerResponse(Defines.CODE_OTP_STATUS_FAIL, Defines.OTP_STATUS_FAIL);
				}
			} else {
				DBConnector.getInstances().authResetOTPTransaction(transId);
				return new MultiSignerResponse(Defines.CODE_OTP_STATUS_TIME, Defines.OTP_STATUS_TIME);
			}
			//LOG.info("TOMICA: SERVER DATA ---"+otpTransaction[4]+" OTP: "+otpTransaction[2]+" USER: "+user+" OTP: "+otp
				//	+" RESPCODE: "+ResponseCode+" RESPMESS: "+ResponseMessage);
		} catch(Exception e) {
			e.printStackTrace();
			LOG.error("ServerException. Details: "+e.getMessage());
			DBConnector.getInstances().authResetOTPTransaction(transId);
			return new MultiSignerResponse(Defines.CODE_INTERNALSYSTEM, Defines.ERROR_INTERNALSYSTEM);
		}
		/*
		signResponse = new MultiSignerResponse(s.getBytes(), ResponseCode,
				ResponseMessage);
		
		DBConnector.getInstances().authResetOTPTransaction(transId);
		return signResponse;
		*/
	}
}
