package org.signserver.module.multisigner.oath;

import org.signserver.common.*;
import org.signserver.common.util.*;
import org.signserver.module.multisigner.*;

import java.io.*;
import java.util.*;

import javax.xml.bind.DatatypeConverter;

import java.util.LinkedList;
import java.util.List;

import org.apache.log4j.Logger;
import ft.otp.agent.OTPAgent;
import ft.otp.agent.OTPResult;

public class OATHValidator {

    private static final Logger LOG = Logger.getLogger(OATHValidator.class);
    
	private static final String CONTENT_TYPE = "text/xml";
	private static String WORKERNAME = "OATHValidator";
	private String SIGNSERVER_BUILD_CONFIG = "/opt/CAG360/signserver-3.4.1/conf/signserver_build.properties";
	private static final String OTPR_OK = "0000";
	private int ResponseCode = Defines.CODE_OTP_STATUS_FAIL;
	private String ResponseMessage = Defines.OTP_STATUS_FAIL;
	
	private static OATHValidator instance;
	public static OATHValidator getInstance() {
		if(instance == null)
			instance = new OATHValidator();
		return instance;
	}
	
	public MultiSignerResponse processData(String strChannelName, String userContract
			, RequestContext requestContext) {
		
		final String strOtp = RequestMetadata.getInstance(requestContext).get("OTP");
		MultiSignerResponse signResponse;
		String OtpHardware = DBConnector.getInstances().authGetOTPHardware(strChannelName, userContract);
		OTPResult _retry;
		String reTry = "0";
		
		if(OtpHardware != null || OtpHardware.compareTo("") != 0) {
			
			InputStream inPropFile;
			Properties tempProp = new Properties();
	
			try {
				File f = new File(SIGNSERVER_BUILD_CONFIG);
				if(!f.exists()) {
					SIGNSERVER_BUILD_CONFIG = "C:/CAG360/signserver-3.4.1/conf/signserver_build.properties";
				}
				
				inPropFile = new FileInputStream(SIGNSERVER_BUILD_CONFIG);
				tempProp.load(inPropFile);
				inPropFile.close();
			} catch (IOException ioe) {
				ioe.printStackTrace();
			}
			
			String strRet; //V3.2
			Integer strCounter=-1;
			String strAcf = System.getProperty("jboss.server.home.dir")+"/"+"../../../../../file/foas.acf";
			/*
			 * V3.2
			OTPAgent otpAgent = new OTPAgent();
			otpAgent.setConfig(strAcf);
			strRet = otpAgent.auth(userContract, strOtp);
			*/
			
			// V4.0
			int rv;
			OTPAgent otpAgent = OTPAuth.getInstance(strAcf).getOTPAgent();
			rv = otpAgent.authToken(OtpHardware, strOtp);
			//LOG.info("OTP Token Authentication for user "+ userContract+" token "+OtpHardware+" with code="+strOtp+" and response "+rv);
			/*
			 * V3.2
			if(!strRet.equalsIgnoreCase(String.valueOf(OTPAgentReturnCode.OTPR_UID_NOTEXIST))) {
				Map map = otpAgent.getRetryCount(userContract);
				if(OTPR_OK.equalsIgnoreCase((String)map.get("ReturnCode")))
				{
					strCounter = (Integer)map.get("Retry");
				}
			}
			if(Integer.parseInt(strRet) == Defines.CODE_SUCCESS) {
				ResponseCode = Defines.CODE_SUCCESS;
				ResponseMessage = Defines.SUCCESS;
			}
			else if(Integer.parseInt(strRet) == OTPAgentReturnCode.OTPR_NEED_SYNC) {
				ResponseCode = Defines.CODE_OTPNEEDSYNC;
				ResponseMessage = Defines.ERROR_OTPNEEDSYNC;
			} else {
				ResponseCode = Defines.CODE_OTP_STATUS_FAIL;
				ResponseMessage = Defines.OTP_STATUS_FAIL;
			}
			*/
			//String reTry = String.valueOf(strCounter);
			if(rv == OTPAgentReturnCode.OTPR_OK) {
				ResponseCode = Defines.CODE_SUCCESS;
				ResponseMessage = Defines.SUCCESS;
			} else if(rv == OTPAgentReturnCode.OTPR_INVALID_PACKET) {
				ResponseCode = Defines.CODE_OTPNEEDSYNC;
				ResponseMessage = Defines.ERROR_OTPNEEDSYNC;
			} else if(rv == OTPAgentReturnCode.OTPR_OTP_INVALID) {
				_retry = OTPAuth.getInstance(strAcf).getOTPAgent().getRetryToken(OtpHardware);
				reTry = String.valueOf(_retry.getNumData());
				ResponseCode = Defines.CODE_OTP_STATUS_FAIL;
				ResponseMessage = Defines.OTP_STATUS_FAIL;
			} else if(rv == OTPAgentReturnCode.OTPR_TOKEN_TEMP_LOCKED 
					|| rv == OTPAgentReturnCode.OTPR_TOKEN_LONG_LOCKED) {
				ResponseCode = Defines.CODE_OTPLOCKED;
				ResponseMessage = Defines.ERROR_OTPLOCKED;
			} else if(rv == OTPAgentReturnCode.OTPR_TOKEN_LOCKED) {
				ResponseCode = Defines.CODE_OTP_STATUS_LOST;
				ResponseMessage = Defines.OTP_STATUS_LOST;
			} else if(rv == OTPAgentReturnCode.OTPR_TOKEN_DISABLE) {
				ResponseCode = Defines.CODE_OTP_STATUS_DISABLE;
				ResponseMessage = Defines.OTP_STATUS_DISA;
			} else {
				LOG.info(Defines.ERROR_OTPEXCEPTION+"\t"+"responseCode="+rv);
				_retry = OTPAuth.getInstance(strAcf).getOTPAgent().getRetryToken(OtpHardware);
				reTry = String.valueOf(_retry.getNumData());
				ResponseCode = Defines.CODE_OTP_STATUS_FAIL;
				ResponseMessage = Defines.OTP_STATUS_FAIL;
			}
		} else {
			ResponseCode = Defines.CODE_ERRORGETOLDOTP;
			ResponseMessage = Defines.ERROR_ERRORGETOLDOTP;
		}
		signResponse = new MultiSignerResponse(reTry.getBytes(), ResponseCode, ResponseMessage);
        return signResponse;
	}
    
    private static class OTPAuth {
    	private static OTPAuth instance;
    	private OTPAgent otpAgent = null;
    	private static String afcFile;
    	public static OTPAuth getInstance(String acf) {
    		if(instance == null) {
    			afcFile = acf;
    			instance = new OTPAuth();
    		}
    		return instance;
    	}
    	
    	private OTPAuth() {
    		otpAgent = new OTPAgent();
    		otpAgent.setConfig(afcFile);
    	}
    	
    	public OTPAgent getOTPAgent() {
    		return otpAgent;
    	}
    }
}
