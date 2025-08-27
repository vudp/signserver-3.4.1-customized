package org.signserver.validationservice.server;

import org.signserver.common.*;
import org.signserver.common.util.*;
import org.signserver.common.dbdao.*;
import org.signserver.server.WorkerContext;
import javax.persistence.EntityManager;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import java.util.*;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import org.apache.log4j.Logger;
import org.signserver.server.BaseProcessable;
import org.signserver.validationservice.common.ValidationServiceConstants;

public class GeneralValidator extends BaseProcessable {
	
	private IValidationService validationService;
	private List<String> fatalErrors;
	private static final Logger LOG = Logger.getLogger(GeneralValidator.class);

	private static final String CONTENT_TYPE = "text/xml";
	private int ResponseCode = Defines.CODE_INVALIDSIGNATURE;;
	private String ResponseMessage = Defines.ERROR_INVALIDSIGNATURE;
	private static String WORKERNAME = "GeneralValidator";
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
			final String error = "Could not get crypto token: "
					+ e.getMessage();
			LOG.error(error);
			fatalErrors.add(error);
		}
	}
	
	private IValidationService createValidationService(WorkerConfig config)
			throws SignServerException {
		String classPath = config.getProperties().getProperty(
				ValidationServiceConstants.VALIDATIONSERVICE_TYPE,
				ValidationServiceConstants.DEFAULT_TYPE);
		IValidationService retval = null;
		String error = null;
		try {
			if (classPath != null) {
				Class<?> implClass = Class.forName(classPath);
				retval = (IValidationService) implClass.newInstance();
				retval.init(workerId, config, em, getCryptoToken());
			}
		} catch (ClassNotFoundException e) {
			error = "Error instatiating Validation Service, check that the TYPE setting of workerid : "
					+ workerId + " have the correct class path.";
			LOG.error(error, e);

		} catch (IllegalAccessException e) {
			error = "Error instatiating Validation Service, check that the TYPE setting of workerid : "
					+ workerId + " have the correct class path.";
			LOG.error(error, e);
		} catch (InstantiationException e) {
			error = "Error instatiating Validation Service, check that the TYPE setting of workerid : "
					+ workerId + " have the correct class path.";
			LOG.error(error, e);

		}

		if (error != null) {
			fatalErrors.add(error);
		}

		return retval;
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
	
	@Override
	public ProcessResponse processData(ProcessRequest signRequest,
			RequestContext requestContext) throws IllegalRequestException,
			CryptoTokenOfflineException, SignServerException {
		
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
		final String archiveId = createArchiveId(data,
				(String) requestContext.get(RequestContext.TRANSACTION_ID));
		
		// check license for OfficeSigner
		LOG.info("Checking license for GeneralValidator.");
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

		String serialNumber = null;
		String fileType = RequestMetadata.getInstance(requestContext).get(Defines._FILETYPE);
		String password = RequestMetadata.getInstance(requestContext).get(Defines._PDFPASSWORD);
		String xpathNamespace = RequestMetadata.getInstance(requestContext).get(Defines._XPATHNAMESPACE);
		String signingTimeTag = RequestMetadata.getInstance(requestContext).get(Defines._SIGNINGTIMEIDENTIFIER);
		String signingTimePattern = RequestMetadata.getInstance(requestContext).get(Defines._SIGNINGTIMEPATTERN);
		String channelName = RequestMetadata.getInstance(requestContext).get(Defines._CHANNEL);
		String user = RequestMetadata.getInstance(requestContext).get(Defines._USER);
		int trustedhubTransId = Integer.parseInt(RequestMetadata.getInstance(requestContext).get(Defines._TRUSTEDHUBTRANSID));
		
		
		ArrayList<Ca> caProviders = new ArrayList<Ca>();
		caProviders = DBConnector.getInstances().getCAProviders();
		
		MultiValidatorResponse multiValidatorResponse = null;
		if(ExtFunc.checkFileType(data, fileType).compareTo(ExtFunc.C_FILETYPE_PDF) == 0) {
			// pdf
			org.signserver.validationservice.server.multivalidator.PDFValidator
									pdfValidator = new org.signserver
									.validationservice.server
									.multivalidator.PDFValidator(channelName, user);
			
			multiValidatorResponse = pdfValidator.verify(data, password, serialNumber, caProviders, trustedhubTransId);
			
		} else if(ExtFunc.checkFileType(data, fileType).compareTo(ExtFunc.C_FILETYPE_OFFICE) == 0) { 
			// office
			org.signserver.validationservice.server.multivalidator.OfficeValidator
									officeValidator = new org.signserver.validationservice.server.multivalidator.OfficeValidator(channelName, user);
			multiValidatorResponse = officeValidator.verify(data, serialNumber, caProviders, trustedhubTransId);
		} else {
			// xml
			org.signserver.validationservice.server.multivalidator.XMLValidator
									xmlValidator = new org.signserver.validationservice
									.server.multivalidator.XMLValidator(xpathNamespace, signingTimeTag, signingTimePattern, channelName, user);
			multiValidatorResponse = xmlValidator.verify(data, serialNumber, caProviders, trustedhubTransId);
		}
		
		final Collection<? extends Archivable> archivables = Arrays
				.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
						CONTENT_TYPE, data, archiveId));
		
		ProcessResponse signResponse = new GenericSignResponse(sReq.getRequestID(),
				data, getSigningCertificate(), null, archiveId,
				archivables, multiValidatorResponse.getResponseCode(), 
				multiValidatorResponse.getResponseMessage(),
				multiValidatorResponse.getListSignerInfoResponse());
		
		return signResponse;
	}
	
}