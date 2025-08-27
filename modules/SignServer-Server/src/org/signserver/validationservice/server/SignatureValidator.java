package org.signserver.validationservice.server;

import org.signserver.common.*;
import org.signserver.common.util.*;
import org.signserver.common.dbdao.*;
import org.signserver.server.WorkerContext;

import javax.persistence.EntityManager;

import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;

import java.security.Security;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.*;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.util.LinkedList;
import java.util.List;

import org.apache.log4j.Logger;
import org.signserver.server.BaseProcessable;
import org.signserver.validationservice.common.ValidationServiceConstants;
import org.apache.commons.lang.StringEscapeUtils;

public class SignatureValidator extends BaseProcessable {

    private IValidationService validationService;
    private List<String> fatalErrors;
    private static final Logger LOG = Logger.getLogger(SignatureValidator.class);
    private static final String CONTENT_TYPE = "text/xml";
    private static String WORKERNAME = "SignatureValidator";
    private int ResponseCode = Defines.CODE_INVALIDSIGNATURE;
    ;
	private String ResponseMessage = Defines.ERROR_INVALIDSIGNATURE;
    private List<SignerInfoResponse> listSignerInfoResponse;

    @Override
    public void init(
            int workerId,
            WorkerConfig config,
            WorkerContext workerContext,
            EntityManager workerEM) {
        // TODO Auto-generated method stub
        super.init(workerId, config, workerContext, workerEM);
        Security.addProvider(new BouncyCastleProvider());
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
     *
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

        if (!(signRequest instanceof GenericSignRequest)) {
            throw new IllegalRequestException("Recieved request wasn't a expected GenericSignRequest.");
        }

        final ISignRequest sReq = (ISignRequest) signRequest;
        if (!(sReq.getRequestData() instanceof byte[])) {
            throw new IllegalRequestException("Recieved request data wasn't a expected byte[].");
        }

        byte[] data = (byte[]) sReq.getRequestData();
        final String archiveId = createArchiveId(data, (String) requestContext.get(RequestContext.TRANSACTION_ID));


        // check license for CapicomValidator
        LOG.info("Checking license for SignatureValidator.");
        License licInfo = License.getInstance();
        if (licInfo.getStatusCode() != 0) {
            return new GenericSignResponse(sReq.getRequestID(), archiveId, Defines.CODE_INFO_LICENSE, licInfo.getStatusDescription());
        } else {
            if (!licInfo.checkWorker(WORKERNAME)) {
                return new GenericSignResponse(sReq.getRequestID(), archiveId, Defines.CODE_INFO_LICENSE_NOTSUPPORT, Defines.ERROR_INFO_LICENSE_NOTSUPPORT);
            }
        }

        String signatureMethod = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATUREMETHOD);
        String serialNumber = RequestMetadata.getInstance(requestContext).get(Defines._SERIALNUMBER);
        String signedData = RequestMetadata.getInstance(requestContext).get(Defines._SIGNEDDATA);
        String encoding = RequestMetadata.getInstance(requestContext).get(Defines._ENCODING);
        String certificate = RequestMetadata.getInstance(requestContext).get(Defines._CERTIFICATE);
        String channelName = RequestMetadata.getInstance(requestContext).get(Defines._CHANNEL);
        String user = RequestMetadata.getInstance(requestContext).get(Defines._USER);
        int trustedhubTransId = Integer.parseInt(RequestMetadata.getInstance(requestContext).get(Defines._TRUSTEDHUBTRANSID));

        byte[] dtbs = null;

        if (encoding != null) {
            try {
                dtbs = StringEscapeUtils.unescapeHtml(signedData).getBytes(encoding);
            } catch (Exception e) {
                LOG.error("Invalid encoding. Get default encoding");
                dtbs = StringEscapeUtils.unescapeHtml(signedData).getBytes();
            }
        } else {
            dtbs = StringEscapeUtils.unescapeHtml(signedData).getBytes();
        }
        //LOG.info("Encoding: "+encoding);
        //LOG.info("dtbs: "+DatatypeConverter.printHexBinary(dtbs));
        //LOG.info("serialNumber: "+serialNumber);
        ArrayList<Ca> caProviders = new ArrayList<Ca>();
        caProviders = DBConnector.getInstances().getCAProviders();

        SignatureValidatorResponse signatureValidatorResponse = null;

        if (ExtFunc.isNullOrEmpty(signatureMethod)) {
            signatureMethod = Defines.SIGNATURE_METHOD_TPKI; // default
        }

        if (signatureMethod.compareTo(Defines.SIGNATURE_METHOD_TPKI) == 0
                || signatureMethod.compareTo(Defines.SIGNATURE_METHOD_WPKI) == 0) {
            org.signserver.validationservice.server.signaturevalidator.CapicomValidator capicomValidator = new org.signserver.validationservice.server.signaturevalidator.CapicomValidator();
            signatureValidatorResponse = capicomValidator.verify(channelName, user, dtbs, data, serialNumber, caProviders, trustedhubTransId);
        } else {
            // LPKI
            org.signserver.validationservice.server.signaturevalidator.PKCS1Validator pkcs1Validator = new org.signserver.validationservice.server.signaturevalidator.PKCS1Validator();
            signatureValidatorResponse = pkcs1Validator.verify(channelName, user, dtbs, data, certificate, serialNumber, caProviders, trustedhubTransId);
        }

        final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE, CONTENT_TYPE, data, archiveId));

        if (signRequest instanceof GenericServletRequest) {
            signResponse = new GenericServletResponse(sReq.getRequestID(), data, getSigningCertificate(), archiveId, archivables, CONTENT_TYPE);
        } else {
            signResponse = new GenericSignResponse(sReq.getRequestID(), data, getSigningCertificate(), null, archiveId, archivables, signatureValidatorResponse.getResponseCode(), signatureValidatorResponse.getResponseMessage(), signatureValidatorResponse.getListSignerInfoResponse());
        }

        return signResponse;
    }

    private String getCN(X509Certificate c) {
        String cn = "Error DN";
        try {
            X509Principal principal = PrincipalUtil.getSubjectX509Principal(c);
            Vector<?> values = principal.getValues(X509Name.CN);
            cn = (String) values.get(0);
        } catch (Exception e) {
            LOG.error("Error when parsing DN: " + e.getMessage());
        }
        return cn;
    }

    private boolean checkDataValidity(X509Certificate x509) {
        try {
            x509.checkValidity();
            return true;
        } catch (CertificateExpiredException e) {
            LOG.error("Certificate has been expired");
        } catch (CertificateNotYetValidException e) {
            LOG.error("Certificate is not valid yet");
        }
        return false;
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
