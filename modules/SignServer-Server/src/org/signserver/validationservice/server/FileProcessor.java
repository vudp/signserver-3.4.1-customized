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
import vn.mobile_id.endpoint.service.datatype.*;
import vn.mobile_id.endpoint.service.datatype.params.*;
import vn.mobile_id.endpoint.client.*;

import com.fasterxml.jackson.databind.ObjectMapper;

public class FileProcessor extends BaseProcessable {

    private IValidationService validationService;
    private List<String> fatalErrors;
    private static final Logger LOG = Logger.getLogger(FileProcessor.class);
    
	private static final String CONTENT_TYPE = "text/xml";
	private static String WORKERNAME = "FileProcessor";
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
		final String fileId = RequestMetadata.getInstance(requestContext).get(Defines._FILEID);
		final String externalStorage = RequestMetadata.getInstance(requestContext).get(Defines._EXTERNALSTORAGE);
		int trustedHubTransId = Integer.parseInt(RequestMetadata.getInstance(requestContext).get(Defines._TRUSTEDHUBTRANSID));
		final String method = RequestMetadata.getInstance(requestContext).get(Defines._METHOD);
		final String displayValue = RequestMetadata.getInstance(requestContext).get(Defines._DISPLAYVALUE);
		final String mimeType = RequestMetadata.getInstance(requestContext).get(Defines._MIMETYPE);
		final String fileName = RequestMetadata.getInstance(requestContext).get(Defines._FILENAME);
		final String citizenId = RequestMetadata.getInstance(requestContext).get(Defines._CITIZENID);
		final String applicationId = RequestMetadata.getInstance(requestContext).get(Defines._APPLICATIONID);
		final String userHandle = RequestMetadata.getInstance(requestContext).get(Defines._USERHANDLE);
		
		final ISignRequest sReq = (ISignRequest) signRequest;
		
		byte[] data = (byte[]) sReq.getRequestData();
		
		if(data == null) {
			data = String.valueOf(System.currentTimeMillis()).getBytes();
		}
		
		final String archiveId = createArchiveId(data, (String) requestContext.get(RequestContext.TRANSACTION_ID));
		// check license for OATHRequest
        LOG.info("Checking license for FileProcessor.");
        LOG.info("No license constraint for this worker.");
        /*
        License licInfo = License.getInstance();
        if(licInfo.getStatusCode() != 0) {
        	return new GenericSignResponse(sReq.getRequestID(), archiveId, Defines.CODE_INFO_LICENSE, licInfo.getStatusDescription());
        } else {
        	if(!licInfo.checkWorker("OATHValidator")) {
        		return new GenericSignResponse(sReq.getRequestID(), archiveId
        				, Defines.CODE_INFO_LICENSE_NOTSUPPORT, Defines.ERROR_INFO_LICENSE_NOTSUPPORT);
        	}
        }
		*/
		
        String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(externalStorage);
		if(endpointParams == null) {
			return new GenericSignResponse(sReq.getRequestID(), archiveId
    				, Defines.CODE_INVALID_EXT_CONN_VENDOR, Defines.ERROR_INVALID_EXT_CONN_VENDOR);
		}
		
		if(method.compareTo(Defines.FILE_MANAGEMENT_GET) == 0) {
			if(ExtFunc.isNullOrEmpty(fileId)) {
				LOG.error("FileId is NULL or Empty");
				return new GenericSignResponse(sReq.getRequestID(), archiveId
	    				, Defines.CODE_INVALIDPARAMETER, Defines.ERROR_INVALIDPARAMETER);
			}
			
			EndpointServiceResponse endpointServiceResponse = EndpointService.getInstance().getRemoteFile(channelName, user, 
					externalStorage, endpointParams[1], fileId, Integer.parseInt(endpointParams[2]), trustedHubTransId);
			
			Response response = endpointServiceResponse.getResponse();
			if(response == null) {
				return new GenericSignResponse(sReq.getRequestID(), archiveId
	    				, Defines.CODE_ENDPOINTEXP, Defines.ERROR_ENDPOINTEXP);
			}
			
			if(response.getStatus().getResponseCode() != 0) {
				return new GenericSignResponse(sReq.getRequestID(), archiveId
	    				, Defines.CODE_EXTERNAL_FILE_GET, Defines.ERROR_EXTERNAL_FILE_GET);
			} else {
				byte[] byteData = response.getRemoteFileResp().getFileParams().getFileData();
				
				Properties properties = new Properties();
				properties.setProperty(Defines._FILENAME, response.getRemoteFileResp().getFileParams().getFileName());
				properties.setProperty(Defines._MIMETYPE, response.getRemoteFileResp().getFileParams().getMimeType());
						
				final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE
						, CONTENT_TYPE, byteData, archiveId));
				
				signResponse = new GenericSignResponse(
						sReq.getRequestID(), 
						byteData, 
						null, 
						null,
						archiveId, 
						archivables, 
						Defines.CODE_SUCCESS, 
						Defines.SUCCESS,
						null,
						properties);
		        return signResponse;
			}
		} else if(method.compareTo(Defines.FILE_MANAGEMENT_SUBMIT) == 0) {
			EndpointServiceResponse endpointServiceResponse = EndpointService.getInstance().setRemoteFile(channelName,
					user, externalStorage, endpointParams[1], fileId, data, displayValue, mimeType,
					fileName, citizenId, applicationId, userHandle, Integer.parseInt(endpointParams[2]), trustedHubTransId);
			
			Response response = endpointServiceResponse.getResponse();
			if(response == null) {
				return new GenericSignResponse(sReq.getRequestID(), archiveId
	    				, Defines.CODE_ENDPOINTEXP, Defines.ERROR_ENDPOINTEXP);
			}
			
			if(response.getStatus().getResponseCode() != 0) {
				return new GenericSignResponse(sReq.getRequestID(), archiveId
	    				, Defines.CODE_EXTERNAL_FILE_SET, Defines.ERROR_EXTERNAL_FILE_SET);
			} else {
				String newFileId = response.getRemoteFileResp().getFileParams().getFileId();
				GenericSignResponse genericSignResponse  = new GenericSignResponse(sReq.getRequestID(), archiveId
	    				, Defines.CODE_SUCCESS, Defines.SUCCESS);
				genericSignResponse.setFileId(newFileId);
				return genericSignResponse;
			}
		} else {
			return new GenericSignResponse(sReq.getRequestID(), archiveId
    				, Defines.CODE_INVALIDPARAMETER, Defines.ERROR_INVALIDPARAMETER);
		}
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
