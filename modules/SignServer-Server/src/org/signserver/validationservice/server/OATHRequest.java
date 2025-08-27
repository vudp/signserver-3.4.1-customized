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

public class OATHRequest extends BaseProcessable {

    private IValidationService validationService;
    private List<String> fatalErrors;
    private static final Logger LOG = Logger.getLogger(OATHRequest.class);
    
	private static final String CONTENT_TYPE = "text/xml";
	private static String WORKERNAME = "OATHRequest";
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
		
		final String channelName = RequestMetadata.getInstance(requestContext).get(Defines._CHANNEL);
		final String user = RequestMetadata.getInstance(requestContext).get(Defines._USER);
		final String transData = RequestMetadata.getInstance(requestContext).get(Defines._TRANSACTIONDATA);

		final ISignRequest sReq = (ISignRequest) signRequest;

		String str_secert = channelName+"#"+user;
		byte[] secretBytes = str_secert.getBytes();
		
		final String archiveId = createArchiveId(secretBytes, (String) requestContext.get(RequestContext.TRANSACTION_ID));
		// check license for OATHRequest
        LOG.info("Checking license for OATHRequest.");
        License licInfo = License.getInstance();
        if(licInfo.getStatusCode() != 0) {
        	return new GenericSignResponse(sReq.getRequestID(), archiveId, Defines.CODE_INFO_LICENSE, licInfo.getStatusDescription());
        } else {
        	if(!licInfo.checkWorker("OATHValidator")) {
        		return new GenericSignResponse(sReq.getRequestID(), archiveId
        				, Defines.CODE_INFO_LICENSE_NOTSUPPORT, Defines.ERROR_INFO_LICENSE_NOTSUPPORT);
        	}
        }
	
		String timeStamp = new SimpleDateFormat("yyyyMMddHHmmssS").format(Calendar.getInstance().getTime());
		Long l = Long.valueOf(timeStamp);
		
		int digits = DBConnector.getInstances().authGetOTPDigits(channelName, user);
		String s = "";
		try {
			s = RFC4226.generateOTP(secretBytes, l, digits, false, -1);
		} catch(NoSuchAlgorithmException e) {
			e.printStackTrace();
			LOG.error("NoSuchAlgorithmException. Details: "+e.getMessage());
			return new GenericSignResponse(sReq.getRequestID(), archiveId
        				, Defines.CODE_INTERNALSYSTEM, Defines.ERROR_INTERNALSYSTEM);
		} catch(InvalidKeyException e) {
			e.printStackTrace();
			LOG.error("NoSuchAlgorithmException. Details: "+e.getMessage());
			return new GenericSignResponse(sReq.getRequestID(), archiveId
        				, Defines.CODE_INTERNALSYSTEM, Defines.ERROR_INTERNALSYSTEM);
		}
		ResponseCode = Defines.CODE_SUCCESS;
		ResponseMessage = Defines.SUCCESS;
		
		final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE
				, CONTENT_TYPE, s.getBytes(), archiveId));
		
		signResponse = new GenericSignResponse(sReq.getRequestID(), s.getBytes()
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
}
