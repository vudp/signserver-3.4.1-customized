package org.signserver.validationservice.server;

import org.signserver.common.*;
import org.signserver.common.util.*;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.WorkerContext;
import org.signserver.server.signers.BaseSigner;

import javax.persistence.EntityManager;

import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;

import java.io.*;
import java.util.*;

import javax.xml.bind.DatatypeConverter;

import java.util.LinkedList;
import java.util.List;

import org.apache.log4j.Logger;
import org.signserver.server.BaseProcessable;
import org.signserver.validationservice.common.ValidateRequest;
import org.signserver.validationservice.common.ValidationServiceConstants;

import ft.otp.agent.OTPAgent;
import ft.otp.agent.OTPResult;

public class OATHValidator extends BaseProcessable {

    private IValidationService validationService;
    private List<String> fatalErrors;
    private static final Logger LOG = Logger.getLogger(OATHValidator.class);
    
	private static final String CONTENT_TYPE = "text/xml";
	private static String WORKERNAME = "OATHValidator";
	private String SIGNSERVER_BUILD_CONFIG = System.getProperty("jboss.server.home.dir")+"/../../../../../signserver-3.4.1/conf/signserver_build.properties";
	private static final String OTPR_OK = "0000";
	private int ResponseCode = Defines.CODE_OTP_STATUS_FAIL;
	private String ResponseMessage = Defines.OTP_STATUS_FAIL;
	private List<SignerInfoResponse> listSignerInfoResponse;
	@Override
	public void init(int workerId, WorkerConfig config,
			WorkerContext workerContext, EntityManager workerEM) {
		// TODO Auto-generated method stub
		super.init(workerId, config, workerContext, workerEM);
        fatalErrors = new LinkedList<String>();
        try {
            validationService = createValidationService(config);
        } catch (SignServerException e) {
            final String error = "Could not get crypto token: " + e.getMessage();
            LOG.error(error);
            fatalErrors.add(error);
        }
	}
	
    /**
     * Creating a Validation Service depending on the TYPE setting
     * @param config configuration containing the validation service to create
     * @return a non initialized group key service.
     */
    private IValidationService createValidationService(WorkerConfig config) throws SignServerException {
        String classPath = config.getProperties().getProperty(ValidationServiceConstants.VALIDATIONSERVICE_TYPE, ValidationServiceConstants.DEFAULT_TYPE);
        IValidationService retval = null;
        String error = null;
        try {
            if (classPath != null) {
                Class<?> implClass = Class.forName(classPath);
                retval = (IValidationService) implClass.newInstance();
                retval.init(workerId, config, em, getCryptoToken());
            }
        } catch (ClassNotFoundException e) {
            error = "Error instatiating Validation Service, check that the TYPE setting of workerid : " + workerId + " have the correct class path.";
            LOG.error(error, e);
            
        } catch (IllegalAccessException e) {
            error = "Error instatiating Validation Service, check that the TYPE setting of workerid : " + workerId + " have the correct class path.";
            LOG.error(error, e);
        } catch (InstantiationException e) {
            error = "Error instatiating Validation Service, check that the TYPE setting of workerid : " + workerId + " have the correct class path.";
            LOG.error(error, e);
            
        }

        if (error != null) {
            fatalErrors.add(error);
        }
        
        return retval;
    }
    
	@Override
	public ProcessResponse processData(ProcessRequest signRequest,
			RequestContext requestContext) throws IllegalRequestException,
			CryptoTokenOfflineException, SignServerException {
		// TODO Auto-generated method stub
		ProcessResponse signResponse;
		// Check that the request contains a valid GenericSignRequest object
		// with a byte[].
		final String userContract = RequestMetadata.getInstance(requestContext).get(Defines._USER);
		final String strOtp = RequestMetadata.getInstance(requestContext).get(Defines._OTP);
		final String strChannelName = RequestMetadata.getInstance(requestContext).get(Defines._CHANNEL);
		
		
		final ISignRequest sReq = (ISignRequest) signRequest;
		byte[] data = new byte[] {0,0,0,0};
		
		final String archiveId = createArchiveId(data, (String) requestContext.get(RequestContext.TRANSACTION_ID));
		
		// check license for OATHValidator
        LOG.info("Checking license for OATHValidator.");
        License licInfo = License.getInstance();
        if(licInfo.getStatusCode() != 0) {
        	return new GenericSignResponse(sReq.getRequestID(), archiveId, Defines.CODE_INFO_LICENSE, licInfo.getStatusDescription());
        } else {
        	if(!licInfo.checkWorker(WORKERNAME)) {
        		return new GenericSignResponse(sReq.getRequestID(), archiveId
        				, Defines.CODE_INFO_LICENSE_NOTSUPPORT, Defines.ERROR_INFO_LICENSE_NOTSUPPORT);
        	}
        }
		
		String OtpHardware = DBConnector.getInstances().authGetOTPHardware(strChannelName, userContract);
		OTPResult _retry;
		String reTry = "null";
		
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
		
		final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE
				, CONTENT_TYPE, reTry.getBytes(), archiveId));
		
		signResponse = new GenericSignResponse(sReq.getRequestID(), reTry.getBytes()
    			, null, null, archiveId
    			, archivables, ResponseCode, ResponseMessage, null);
		
        return signResponse;
	}
    /**
     * @see org.signserver.server.BaseProcessable#getStatus()
     */
    @Override
    public WorkerStatus getStatus(final List<String> additionalFatalErrors) {
        return validationService.getStatus();
    }

    @Override
    protected List<String> getFatalErrors() {
        final List<String> errors = new LinkedList<String>();
        
        errors.addAll(super.getFatalErrors());
        errors.addAll(fatalErrors);

        return errors;
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
