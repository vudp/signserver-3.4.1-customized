package org.signserver.validationservice.server;

import org.signserver.common.*;
import org.signserver.server.WorkerContext;

import javax.persistence.EntityManager;

import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;

import java.util.*;
import java.security.cert.X509Certificate;

import javax.xml.bind.DatatypeConverter;

import java.util.LinkedList;
import java.util.List;

import org.apache.log4j.Logger;
import org.signserver.server.BaseProcessable;
import org.signserver.validationservice.common.ValidationServiceConstants;


import org.signserver.common.util.*;

public class DCSigner extends BaseProcessable {

    private IValidationService validationService;
    private List<String> fatalErrors;
    private static final Logger LOG = Logger.getLogger(DCSigner.class);
    private static final String CONTENT_TYPE = "text/xml";
    private String ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
    private int ResponseCode = Defines.CODE_INTERNALSYSTEM;
    private static String WORKERNAME = "DCSigner";
    private static String PDFMINETYPE = "pdf";
    private static String XMLMINETYPE = "text/html";

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
        ProcessResponse signResponse = null;

        final ISignRequest sReq = (ISignRequest) signRequest;

        String channelName = RequestMetadata.getInstance(requestContext).get(Defines._CHANNEL);
        String user = RequestMetadata.getInstance(requestContext).get(Defines._USER);
        String method = RequestMetadata.getInstance(requestContext).get(Defines._METHOD);
        String signature = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATURE);

        String visibleSignature = RequestMetadata.getInstance(requestContext).get(Defines._VISIBLESIGNATURE);
        String coordinate = RequestMetadata.getInstance(requestContext).get(Defines._COORDINATE);
        String pageNo = RequestMetadata.getInstance(requestContext).get(Defines._PAGENO);
        String signReason = RequestMetadata.getInstance(requestContext).get(Defines._SIGNREASON);
        String visualStatus = RequestMetadata.getInstance(requestContext).get(Defines._VISUALSTATUS);
        String signatureImage = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATUREIMAGE);
        String certificate = RequestMetadata.getInstance(requestContext).get(Defines._CERTIFICATE);
        String signerInfoPrefix = RequestMetadata.getInstance(requestContext).get(Defines._SIGNERINFOPREFIX);
        String dateTimePrefix = RequestMetadata.getInstance(requestContext).get(Defines._DATETIMEPREFIX);
        String signReasonPrefix = RequestMetadata.getInstance(requestContext).get(Defines._SIGNREASONPREFIX);
        String location = RequestMetadata.getInstance(requestContext).get(Defines._LOCATION);

        String showTitle = RequestMetadata.getInstance(requestContext).get(Defines._SHOWTITLE);
        String titlePrefix = RequestMetadata.getInstance(requestContext).get(Defines._TITLEPREFIX);
        String title = RequestMetadata.getInstance(requestContext).get(Defines._TITLE);
        String showOrganization = RequestMetadata.getInstance(requestContext).get(Defines._SHOWORGANIZATION);
        String organizationPrefix = RequestMetadata.getInstance(requestContext).get(Defines._ORGANIZATIONPREFIX);
        String organization = RequestMetadata.getInstance(requestContext).get(Defines._ORGANIZATION);
        String showOrganizationUnit = RequestMetadata.getInstance(requestContext).get(Defines._SHOWORGANIZATIONUNIT);
        String organizationUnitPrefix = RequestMetadata.getInstance(requestContext).get(Defines._ORGANIZATIONUNITPREFIX);
        String organizationUnit = RequestMetadata.getInstance(requestContext).get(Defines._ORGANIZATIONUNIT);
        String showSigningID = RequestMetadata.getInstance(requestContext).get(Defines._SHOWSIGNINGID);
        String signingIDPrefix = RequestMetadata.getInstance(requestContext).get(Defines._SIGNINGIDPREFIX);
        String signingID = RequestMetadata.getInstance(requestContext).get(Defines._SIGNINGID);
        String datetimeFormat = RequestMetadata.getInstance(requestContext).get(Defines._DATETIMEFORMAT);
        String fontName = RequestMetadata.getInstance(requestContext).get(Defines._FONTNAME);

        String fileType = RequestMetadata.getInstance(requestContext).get(Defines._FILETYPE);
        String billCode = RequestMetadata.getInstance(requestContext).get(Defines._BILLCODE);


        // xml
        String uri = RequestMetadata.getInstance(requestContext).get(Defines._URI);
        String uriNode = RequestMetadata.getInstance(requestContext).get(Defines._URINODE);
        String signaturePrefix = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATUREPREFIX);

        byte[] errors = {(byte) 0xFF, (byte) 0xFA};
        String archiveId = createArchiveId(errors, (String) requestContext.get(RequestContext.TRANSACTION_ID));

        // check license for DCSigner
        LOG.info("Checking license for DCSigner.");
        License licInfo = License.getInstance();
        if (licInfo.getStatusCode() != 0) {
            return new GenericSignResponse(sReq.getRequestID(), archiveId, Defines.CODE_INFO_LICENSE, licInfo.getStatusDescription());
        } else {
            if (!licInfo.checkWorker(WORKERNAME)) {
                return new GenericSignResponse(sReq.getRequestID(), archiveId, Defines.CODE_INFO_LICENSE_NOTSUPPORT, Defines.ERROR_INFO_LICENSE_NOTSUPPORT);
            }
        }

        byte[] data = (byte[]) sReq.getRequestData();

        if (method.compareTo(Defines.METHOD_SIGNREQUEST) == 0) {

            DC dc = null;
            DCResponse dcResp = null;

            if (ExtFunc.checkFileType(data, fileType).compareTo(ExtFunc.C_FILETYPE_PDF) == 0) {

                Properties signaturePro = new Properties();

                if (!ExtFunc.isNullOrEmpty(visibleSignature)) {
                    signaturePro.setProperty(Defines._VISIBLESIGNATURE, visibleSignature);
                } else {
                    visibleSignature = Defines.FALSE;
                    signaturePro.setProperty(Defines._VISIBLESIGNATURE, visibleSignature);
                }

                if (!ExtFunc.isNullOrEmpty(coordinate)) {
                    signaturePro.setProperty(Defines._COORDINATE, coordinate);
                }
                if (!ExtFunc.isNullOrEmpty(pageNo)) {
                    signaturePro.setProperty(Defines._PAGENO, pageNo);
                }
                if (!ExtFunc.isNullOrEmpty(signReason)) {
                    signaturePro.setProperty(Defines._SIGNREASON, signReason);
                }
                if (!ExtFunc.isNullOrEmpty(visualStatus)) {
                    signaturePro.setProperty(Defines._VISUALSTATUS, visualStatus);
                }
                if (!ExtFunc.isNullOrEmpty(signatureImage)) {
                    signaturePro.setProperty(Defines._SIGNATUREIMAGE, signatureImage);
                }
                if (!ExtFunc.isNullOrEmpty(certificate)) {
                    signaturePro.setProperty(Defines._CERTIFICATE, certificate);
                }
                if (!ExtFunc.isNullOrEmpty(signerInfoPrefix)) {
                    signaturePro.setProperty(Defines._SIGNERINFOPREFIX, signerInfoPrefix);
                }
                if (!ExtFunc.isNullOrEmpty(dateTimePrefix)) {
                    signaturePro.setProperty(Defines._DATETIMEPREFIX, dateTimePrefix);
                }
                if (!ExtFunc.isNullOrEmpty(signReasonPrefix)) {
                    signaturePro.setProperty(Defines._SIGNREASONPREFIX, signReasonPrefix);
                }
                if (!ExtFunc.isNullOrEmpty(location)) {
                    signaturePro.setProperty(Defines._LOCATION, location);
                }
                if (!ExtFunc.isNullOrEmpty(showTitle)) {
                    signaturePro.setProperty(Defines._SHOWTITLE, showTitle);
                }
                if (!ExtFunc.isNullOrEmpty(titlePrefix)) {
                    signaturePro.setProperty(Defines._TITLEPREFIX, titlePrefix);
                }
                if (!ExtFunc.isNullOrEmpty(title)) {
                    signaturePro.setProperty(Defines._TITLE, title);
                }
                if (!ExtFunc.isNullOrEmpty(showOrganization)) {
                    signaturePro.setProperty(Defines._SHOWORGANIZATION, showOrganization);
                }
                if (!ExtFunc.isNullOrEmpty(organizationPrefix)) {
                    signaturePro.setProperty(Defines._ORGANIZATIONPREFIX, organizationPrefix);
                }
                if (!ExtFunc.isNullOrEmpty(organization)) {
                    signaturePro.setProperty(Defines._ORGANIZATION, organization);
                }
                if (!ExtFunc.isNullOrEmpty(showOrganizationUnit)) {
                    signaturePro.setProperty(Defines._SHOWORGANIZATIONUNIT, showOrganizationUnit);
                }
                if (!ExtFunc.isNullOrEmpty(organizationUnitPrefix)) {
                    signaturePro.setProperty(Defines._ORGANIZATIONUNITPREFIX, organizationUnitPrefix);
                }
                if (!ExtFunc.isNullOrEmpty(organizationUnit)) {
                    signaturePro.setProperty(Defines._ORGANIZATIONUNIT, organizationUnit);
                }
                if (!ExtFunc.isNullOrEmpty(showSigningID)) {
                    signaturePro.setProperty(Defines._SHOWSIGNINGID, showSigningID);
                }
                if (!ExtFunc.isNullOrEmpty(signingIDPrefix)) {
                    signaturePro.setProperty(Defines._SIGNINGIDPREFIX, signingIDPrefix);
                }
                if (!ExtFunc.isNullOrEmpty(signingID)) {
                    signaturePro.setProperty(Defines._SIGNINGID, signingID);
                }
                if (!ExtFunc.isNullOrEmpty(datetimeFormat)) {
                    signaturePro.setProperty(Defines._DATETIMEFORMAT, datetimeFormat);
                }
                if (!ExtFunc.isNullOrEmpty(fontName)) {
                    signaturePro.setProperty(Defines._FONTNAME, fontName);
                }
                dc = new DCPDF();
                dcResp = dc.signInit(data, signaturePro);

            } else if (ExtFunc.checkFileType(data, fileType).compareTo(ExtFunc.C_FILETYPE_OFFICE) == 0) {
                dc = new DCOffice();
                dcResp = dc.signInit(data, null);
            } else {
                // xml
                Properties signaturePro = new Properties();
                if (!ExtFunc.isNullOrEmpty(uri)) {
                    signaturePro.setProperty(Defines._URI, uri);
                }
                if (!ExtFunc.isNullOrEmpty(uriNode)) {
                    signaturePro.setProperty(Defines._URINODE, uriNode);
                }
                if (!ExtFunc.isNullOrEmpty(signaturePrefix)) {
                    signaturePro.setProperty(Defines._SIGNATUREPREFIX, signaturePrefix);
                }

                dc = new DCXml();
                dcResp = dc.signInit(data, signaturePro);
            }

            if (dcResp.getResponseCode() != Defines.CODE_SUCCESS) {
                LOG.error("Error while initializing file to be signed.");
                ResponseMessage = dcResp.getResponseMessage();
                ResponseCode = dcResp.getResponseCode();
                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                        Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                        errors, archiveId));
                signResponse = new GenericSignResponse(
                        sReq.getRequestID(), errors, null, null,
                        archiveId, archivables, ResponseCode,
                        ResponseMessage, null);
                return signResponse;
            }

            byte[] plainSig = dcResp.getData();
            String streamDataPath = dcResp.getAsynStreamDataPath();
            String streamSignPath = dcResp.getAsynStreamSignPath();

            ResponseCode = Defines.CODE_MSSP_REQUEST_ACCEPTED;
            ResponseMessage = Defines.MSSP_REQUEST_ACCEPTED;

            Properties propertiesData = new Properties();
            propertiesData.setProperty(Defines._STREAMDATAPATH, streamDataPath);
            propertiesData.setProperty(Defines._STREAMSIGNPATH, streamSignPath);
            propertiesData.setProperty(Defines._FILETYPE, ExtFunc.checkFileType(data, fileType));

            archiveId = createArchiveId(errors, (String) requestContext.get(RequestContext.TRANSACTION_ID));
            final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                    CONTENT_TYPE, errors, archiveId));
            signResponse = new GenericSignResponse(sReq.getRequestID(), plainSig, null, null, archiveId, archivables, ResponseCode,
                    ResponseMessage, null, propertiesData);
            return signResponse;

        } else if (method.compareTo(Defines.METHOD_SIGNRESPONSE) == 0) {
            int transId = ExtFunc.getTransId(billCode);
            String[] otpTransaction = DBConnector.getInstances().authGetAsyncTransaction(transId);
            DBConnector.getInstances().authResetOTPTransaction(transId);

            if (otpTransaction == null) {
                ResponseMessage = Defines.ERROR_INVALIDTRANSACSTATUS;
                ResponseCode = Defines.CODE_INVALIDTRANSACSTATUS;
                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                return signResponse;
            }

            if (otpTransaction[15].compareTo(user) != 0) {
                ResponseMessage = Defines.ERROR_INVALIDTRANSACSTATUS;
                ResponseCode = Defines.CODE_INVALIDTRANSACSTATUS;
                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                return signResponse;
            }

            boolean isValidSignature = ExtFunc.verifyDcSignature(certificate, signature, otpTransaction[19]);

            if (!isValidSignature) {
                ResponseMessage = Defines.ERROR_INVALIDSIGNATURE;
                ResponseCode = Defines.CODE_INVALIDSIGNATURE;
                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                return signResponse;
            }

            DC dc = null;
            DCResponse dcResp = null;

            if (otpTransaction[7].compareTo(ExtFunc.C_FILETYPE_PDF) == 0) {

                dc = new DCPDF();
                dcResp = dc.signFinal(otpTransaction[8], otpTransaction[9], signature.getBytes(), certificate);

            } else if (otpTransaction[7].compareTo(ExtFunc.C_FILETYPE_OFFICE) == 0) {

                dc = new DCOffice();
                dcResp = dc.signFinal(otpTransaction[8], otpTransaction[9], DatatypeConverter.parseBase64Binary(signature), certificate);

            } else {
                // xml
                dc = new DCXml();
                dcResp = dc.signFinal(otpTransaction[8], otpTransaction[9], DatatypeConverter.parseBase64Binary(signature), certificate);
            }

            if (dcResp.getResponseCode() != Defines.CODE_SUCCESS) {
                LOG.error("Error while finalizing signed file");
                ResponseMessage = dcResp.getResponseMessage();
                ResponseCode = dcResp.getResponseCode();
                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                        Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                        errors, archiveId));
                signResponse = new GenericSignResponse(
                        sReq.getRequestID(), errors, null, null,
                        archiveId, archivables, ResponseCode,
                        ResponseMessage, null);
                return signResponse;
            }

            byte[] signedFile = dcResp.getData();

            archiveId = createArchiveId(errors,
                    (String) requestContext.get(RequestContext.TRANSACTION_ID));

            final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                    Archivable.TYPE_RESPONSE,
                    CONTENT_TYPE,
                    DatatypeConverter.parseBase64Binary(signature),
                    archiveId));

            X509Certificate x509 = null;
            try {
                x509 = ExtFunc.getCertificate(certificate);
            } catch (Exception e) {
                e.printStackTrace();
            }

            ResponseCode = Defines.CODE_SUCCESS;
            ResponseMessage = Defines.SUCCESS;

            Properties propertiesData = null;

            if (otpTransaction[16] != null && otpTransaction[17] != null
                    && otpTransaction[18] != null && otpTransaction[20] != null) {
                propertiesData = new Properties();
                propertiesData.setProperty(Defines._FILEID, otpTransaction[16]);
                propertiesData.setProperty(Defines._FILENAME, otpTransaction[18]);
                propertiesData.setProperty(Defines._MIMETYPE, otpTransaction[17]);
                propertiesData.setProperty(Defines._DISPLAYVALUE, otpTransaction[20]);
            }

            signResponse = new GenericSignResponse(
                    sReq.getRequestID(),
                    signedFile,
                    x509, null, archiveId, archivables,
                    ResponseCode, ResponseMessage, null, propertiesData);
            return signResponse;

        } else {
            ResponseMessage = Defines.ERROR_INVALIDPKIMETHOD;
            ResponseCode = Defines.CODE_INVALIDPKIMETHOD;
            archiveId = createArchiveId(errors, (String) requestContext.get(RequestContext.TRANSACTION_ID));
            final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE, CONTENT_TYPE, errors, archiveId));
            signResponse = new GenericSignResponse(sReq.getRequestID(), errors, null, null, archiveId, archivables, ResponseCode, ResponseMessage, null);
            return signResponse;
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
