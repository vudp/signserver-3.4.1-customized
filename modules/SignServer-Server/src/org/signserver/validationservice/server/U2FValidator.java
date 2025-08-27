package org.signserver.validationservice.server;

import org.signserver.common.*;
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

public class U2FValidator extends BaseProcessable {
	private IValidationService validationService;
    private List<String> fatalErrors;
    private static final Logger LOG = Logger.getLogger(U2FValidator.class);
    
	private static final String CONTENT_TYPE = "text/xml";
	private static String WORKERNAME = "U2FValidator";
	private int ResponseCode = Defines.CODE_INTERNALSYSTEM;
	private String ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
	
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
		
		final String channelName = RequestMetadata.getInstance(requestContext).get(Defines._CHANNEL);
		final String user = RequestMetadata.getInstance(requestContext).get(Defines._USER);
		final String appId = RequestMetadata.getInstance(requestContext).get(Defines._APPID);
		final String method = RequestMetadata.getInstance(requestContext).get(Defines._METHOD);
		final String registrationData = RequestMetadata.getInstance(requestContext).get(Defines._REGISTRATIONDATA);
		final String clientData = RequestMetadata.getInstance(requestContext).get(Defines._CLIENTDATA);
		final String sessionId = RequestMetadata.getInstance(requestContext).get(Defines._SESSIONID);
		final String challenge = RequestMetadata.getInstance(requestContext).get(Defines._CHALLENGE);
		final String signatureData = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATUREDATA);
		
		int trustedhubTransId = Integer.parseInt(RequestMetadata.getInstance(requestContext).get(Defines._TRUSTEDHUBTRANSID));

		final ISignRequest sReq = (ISignRequest) signRequest;
		byte[] secretBytes = String.valueOf(System.currentTimeMillis()).getBytes();
		final String archiveId = createArchiveId(secretBytes, (String) requestContext.get(RequestContext.TRANSACTION_ID));
		// check license for U2FValidator based on FidoValidator
        LOG.info("Checking license for U2FValidator.");
        License licInfo = License.getInstance();
        if(licInfo.getStatusCode() != 0) {
        	return new GenericSignResponse(sReq.getRequestID(), archiveId, Defines.CODE_INFO_LICENSE, licInfo.getStatusDescription());
        } else {
        	if(!licInfo.checkWorker(Defines.WORKER_FIDOVALIDATOR)) {
        		return new GenericSignResponse(sReq.getRequestID(), archiveId
        				, Defines.CODE_INFO_LICENSE_NOTSUPPORT, Defines.ERROR_INFO_LICENSE_NOTSUPPORT);
        	}
        }
        
        String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(Defines.CONNECTION_PARAMS_U2F);
        
        if(endpointParams == null) {
        	return new GenericSignResponse(sReq.getRequestID(), archiveId
    				, Defines.CODE_INVALID_EXT_CONN_VENDOR, Defines.ERROR_INVALID_EXT_CONN_VENDOR);
        }
        
        if(method.equals(Defines.U2F_REG_REQUEST)) {
        	EndpointServiceResp endpointServiceResp = EndpointService.getInstance()
        			.getU2FRegistrationRequest(channelName, user, appId, endpointParams[1], Integer.parseInt(endpointParams[2]), trustedhubTransId);
        	
        	if(endpointServiceResp.getResponseCode() == Defines.CODE_SUCCESS) {
        		return new GenericSignResponse(sReq.getRequestID(), archiveId
        				, Defines.CODE_SUCCESS, Defines.SUCCESS, endpointServiceResp.getResponseJsonData());
        	} else {
        		LOG.error("Error while process U2F request");
        		return new GenericSignResponse(sReq.getRequestID(), archiveId
        				, Defines.CODE_FAILED_TO_PROCESS_U2F, Defines.ERROR_FAILED_TO_PROCESS_U2F);
        	}
        } else if(method.equals(Defines.U2F_REG_RESPONSE)) {
        	
        	EndpointServiceResp endpointServiceResp = EndpointService.getInstance()
        			.getU2FRegistrationResponse(channelName, user, registrationData, clientData, sessionId, endpointParams[1], Integer.parseInt(endpointParams[2]), trustedhubTransId);
        	
        	if(endpointServiceResp.getResponseCode() == Defines.CODE_SUCCESS) {
        		return new GenericSignResponse(sReq.getRequestID(), archiveId
        				, Defines.CODE_SUCCESS, Defines.SUCCESS, endpointServiceResp.getResponseJsonData());
        	} else {
        		LOG.error("Error while process U2F request");
        		return new GenericSignResponse(sReq.getRequestID(), archiveId
        				, Defines.CODE_FAILED_TO_PROCESS_U2F, Defines.ERROR_FAILED_TO_PROCESS_U2F);
        	}
        } else if(method.equals(Defines.U2F_AUTH_REQUEST)) {
        	EndpointServiceResp endpointServiceResp = EndpointService.getInstance()
        			.getU2FSignRequest(channelName, user, appId, endpointParams[1], Integer.parseInt(endpointParams[2]), trustedhubTransId);
        	
        	if(endpointServiceResp.getResponseCode() == Defines.CODE_SUCCESS) {
        		return new GenericSignResponse(sReq.getRequestID(), archiveId
        				, Defines.CODE_SUCCESS, Defines.SUCCESS, endpointServiceResp.getResponseJsonData());
        	} else {
        		LOG.error("Error while process U2F request");
        		return new GenericSignResponse(sReq.getRequestID(), archiveId
        				, Defines.CODE_FAILED_TO_PROCESS_U2F, Defines.ERROR_FAILED_TO_PROCESS_U2F);
        	}
        } else if(method.equals(Defines.U2F_AUTH_RESPONSE)) {
        	EndpointServiceResp endpointServiceResp = EndpointService.getInstance()
        			.getU2FSignResponse(channelName, user, appId, signatureData, clientData, challenge, sessionId, endpointParams[1], Integer.parseInt(endpointParams[2]), trustedhubTransId);
        	
        	if(endpointServiceResp.getResponseCode() == Defines.CODE_SUCCESS) {
        		return new GenericSignResponse(sReq.getRequestID(), archiveId
        				, Defines.CODE_SUCCESS, Defines.SUCCESS, endpointServiceResp.getResponseJsonData());
        	} else {
        		LOG.error("Error while process U2F request");
        		return new GenericSignResponse(sReq.getRequestID(), archiveId
        				, Defines.CODE_FAILED_TO_PROCESS_U2F, Defines.ERROR_FAILED_TO_PROCESS_U2F);
        	}
        } else {
        	LOG.error("Invalid U2F method");
    		return new GenericSignResponse(sReq.getRequestID(), archiveId
    				, Defines.CODE_INVALIDPARAMETER, Defines.ERROR_INVALIDPARAMETER);
        }
	}
    
	
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
}