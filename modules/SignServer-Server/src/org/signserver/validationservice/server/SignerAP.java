package org.signserver.validationservice.server;

import org.signserver.common.*;
import org.signserver.common.dbdao.*;
import org.signserver.common.util.*;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.WorkerContext;
import org.signserver.server.signers.BaseSigner;

import javax.persistence.EntityManager;

import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;

import java.io.*;
import java.util.*;
import java.security.cert.*;

import javax.xml.bind.DatatypeConverter;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import org.apache.log4j.Logger;
import org.signserver.server.BaseProcessable;
import org.signserver.validationservice.common.ValidateRequest;
import org.signserver.validationservice.common.ValidationServiceConstants;

import java.text.SimpleDateFormat;

import org.signserver.common.util.*;
import org.signserver.validationservice.server.dcsigner.*;

import java.security.MessageDigest;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import vn.mobile_id.endpoint.service.datatype.*;
import vn.mobile_id.endpoint.service.datatype.params.*;
import vn.mobile_id.endpoint.client.*;

import com.fasterxml.jackson.databind.ObjectMapper;

import SecureBlackbox.Base.TElMemoryStream;
import SecureBlackbox.Office.SBOfficeSecurity;
import SecureBlackbox.Office.TElOfficeDocument;
import SecureBlackbox.PDF.SBPDF;
import SecureBlackbox.PDF.TElPDFDocument;
import SecureBlackbox.XML.TElXMLDOMDocument;

import com.tomicalab.cryptos.CryptoS;

public class SignerAP extends BaseProcessable {

    private IValidationService validationService;
    private List<String> fatalErrors;
    private static final Logger LOG = Logger.getLogger(SignerAP.class);
    private static final String CONTENT_TYPE = "text/xml";
    private String ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
    private int ResponseCode = Defines.CODE_INTERNALSYSTEM;
    private static String WORKERNAME = "SignerAP";
    private static String PDFMINETYPE = "pdf";
    private static String XMLMINETYPE = "text/html";
    private static String HASH_SHA1 = "SHA-1";
    private static String HASH_SHA256 = "SHA-256";
    private static String HASH_SHA384 = "SHA-384";
    private static String HASH_SHA512 = "SHA-512";
    public static int CODE_DETAILS_MSSP_EXPR = 15;
    public static int CODE_DETAILS_MSSP_NO_KEY_FOUND = 16;
    public static int CODE_DETAILS_MSSP_UNAUTHORIZED_ACCESS = 17;
    public static int CODE_DETAILS_MSSP_NOCERT = 18;
    public static int CODE_DETAILS_MSSP_OUTS = 19;
    public static int CODE_DETAILS_MSSP_NOTRANS = 20;
    public static int CODE_DETAILS_MSSP_AUTH_FAILED = 25;
    public static int CODE_DETAILS_MSSP_TRANS_CANCELED = 26;
    public static String C_FILETYPE_XML = "xml";
    public static String C_FILETYPE_OFFICE = "doc";
    public static String C_FILETYPE_OFFICEX = "docx";
    public static String C_FILETYPE_EXCEL = "xls";
    public static String C_FILETYPE_EXCELX = "xlsx";
    public static String C_FILETYPE_POWERPOINT = "ppt";
    public static String C_FILETYPE_POWERPOINTX = "pptx";
    public static String C_FILETYPE_PDF = "pdf";
    final public static String SIGNATURE_PROFILE_DIGITALSIGN = "http://mobile-id.vn/digitalSignature";
    final public static String SIGNATURE_PROFILE_AUTH = "http://mobile-id.vn/authentication";

    static {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
    }

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

    /**
     * Creating a Validation Service depending on the TYPE setting
     *
     * @param config configuration containing the validation service to create
     * @return a non initialized group key service.
     */
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
    public ProcessResponse processData(ProcessRequest signRequest,
            RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {
        // TODO Auto-generated method stub
        ProcessResponse signResponse = null;

        final ISignRequest sReq = (ISignRequest) signRequest;

        byte[] data = (byte[]) sReq.getRequestData();
        String channelName = RequestMetadata.getInstance(requestContext).get(Defines._CHANNEL);

        String user = RequestMetadata.getInstance(requestContext).get(Defines._USER);
        String pkiSim = RequestMetadata.getInstance(requestContext).get(Defines._PKISIM);
        String vendor = RequestMetadata.getInstance(requestContext).get(Defines._PKISIMVENDOR);
        String cerificate = RequestMetadata.getInstance(requestContext).get(Defines._CERTIFICATE);
        String thumbprint = RequestMetadata.getInstance(requestContext).get(Defines._THUMBPRINT);
        String isHashed = RequestMetadata.getInstance(requestContext).get(Defines._ISHASHED);
        String signatureFormat = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATUREFORMAT);
        String algorithm = RequestMetadata.getInstance(requestContext).get(Defines._ALGORITHM);
        String displayData = RequestMetadata.getInstance(requestContext).get(Defines._DISPLAYMESSAGE);
        String messageMode = RequestMetadata.getInstance(requestContext).get(Defines._MESSAGEMODE);
        String method = RequestMetadata.getInstance(requestContext).get(Defines._METHOD);
        String transactionCode = RequestMetadata.getInstance(requestContext).get(Defines._TRANSACTIONCODE);
        String fileType = RequestMetadata.getInstance(requestContext).get(Defines._FILETYPE);
        String billCode = RequestMetadata.getInstance(requestContext).get(Defines._BILLCODE);
        int endpointConfigId = Integer.parseInt(RequestMetadata.getInstance(requestContext).get(Defines._ENDPOINTCONFIGID));
        String endpointValue = RequestMetadata.getInstance(requestContext).get(Defines._ENDPOINTVALUE);

        String fileId = RequestMetadata.getInstance(requestContext).get(Defines._FILEID);
        String fileName = RequestMetadata.getInstance(requestContext).get(Defines._FILENAME);
        String fileMimeType = RequestMetadata.getInstance(requestContext).get(Defines._MIMETYPE);
        String fileDisplayValue = RequestMetadata.getInstance(requestContext).get(Defines._DISPLAYVALUE);

        // xml
        String uri = RequestMetadata.getInstance(requestContext).get(Defines._URI);
        String uriNode = RequestMetadata.getInstance(requestContext).get(Defines._URINODE);
        String signaturePrefix = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATUREPREFIX);

        int trustedhubTransId = Integer.parseInt(RequestMetadata.getInstance(requestContext).get(Defines._TRUSTEDHUBTRANSID));
        String authCode = RequestMetadata.getInstance(requestContext).get(Defines._AUTHENCODE);


        byte[] errors = ExtFunc.randomHex(10);
        String archiveId = createArchiveId(errors,
                (String) requestContext.get(RequestContext.TRANSACTION_ID));
        // check license for SignerAP
        LOG.info("Checking license for SignerAP.");
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
        if (method.compareTo(Defines.SIGNERAP_SIGREG) == 0) {
            // SignatureRequest
            // signature format
            if (signatureFormat != null) {
                if (!signatureFormat.equals(Defines.SIGNERAP_SIGNFORMAT_P7)) {
                    signatureFormat = Defines.SIGNERAP_SIGNFORMAT_P1;
                }
            } else {
                signatureFormat = Defines.SIGNERAP_SIGNFORMAT_P1;
            }

            // message mode
            if (messageMode != null) {
                if (!messageMode.equals(Defines.SIGNERAP_ASYNC)
                        && !messageMode.equals(Defines.SIGNERAP_SYNC)
                        && !messageMode.equals(Defines.SIGNERAP_ASYNC_REQ_RESP)) {
                    messageMode = Defines.SIGNERAP_ASYNC;
                }
            } else {
                messageMode = Defines.SIGNERAP_ASYNC;
            }

            // hash
            if (isHashed != null) {
                if (!isHashed.equals(Defines.TRUE)) {
                    isHashed = Defines.FALSE;
                }
            } else {
                isHashed = Defines.FALSE;
            }

            if (signatureFormat.equals(Defines.SIGNERAP_SIGNFORMAT_P1)) {
                // PKCS#1
                byte[] plainSig = null;
                if (isHashed.equals(Defines.TRUE)) {
                    if (data.length != 20) {
                        LOG.error("Data should be hashed. Expected length is 20 bytes");
                        ResponseMessage = Defines.ERROR_NOBASE64FILE;
                        ResponseCode = Defines.CODE_NOBASE64FILE;
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
                    } else {
                        try {
                            plainSig = ExtFunc.padSHA1Oid(data);
                        } catch (Exception e) {
                            e.printStackTrace();
                            LOG.error("Error while padding SHA1 OID");
                            ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                            ResponseCode = Defines.CODE_INTERNALSYSTEM;
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
                    }
                } else {
                    // non-hash
                    try {
                        MessageDigest md = MessageDigest.getInstance(HASH_SHA1);
                        md.update(data);
                        data = md.digest();

                        plainSig = ExtFunc.padSHA1Oid(data);
                    } catch (Exception e) {
                        LOG.error("Error while hashing and padding SHA1 OID");
                        e.printStackTrace();
                        ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                        ResponseCode = Defines.CODE_INTERNALSYSTEM;

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
                }

                if (transactionCode != null) {
                    if (billCode == null) {
                        ResponseMessage = Defines.ERROR_INVALIDPARAMETER;
                        ResponseCode = Defines.CODE_INVALIDPARAMETER;
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

                    if (transactionCode.compareTo(otpTransaction[11]) != 0) {
                        ResponseMessage = Defines.ERROR_NOTMATCHID;
                        ResponseCode = Defines.CODE_NOTMATCHID;
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
                } else if (messageMode.compareToIgnoreCase(Defines.SIGNERAP_SYNC) == 0) {
                    ResponseMessage = Defines.ERROR_INVALIDPARAMETER;
                    ResponseCode = Defines.CODE_INVALIDPARAMETER;
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
                } else {
                    // RequestID=null and method Async then do nothing
                    //transactionCode = ExtFunc.generateApTransIdAndRequestId()[1];
                    transactionCode = ExtFunc.calculateVerificationCode(plainSig);
                }


                if (displayData == null || displayData.compareTo("") == 0) {
                    displayData = "Transaction code: " + Defines.MSSP_SYMBOL_VC; // by
                    // default
                }

                displayData = DBConnector.getInstances().getWPKITransactionGeneration(displayData, Defines.MSSP_SYMBOL_VC);

                EndpointServiceResponse endpointServiceResponse = EndpointService.getInstance().requestMobileSignature(
                        channelName,
                        user,
                        pkiSim,
                        vendor,
                        messageMode,
                        ExtFunc.generateApTransId(),
                        signatureFormat,
                        displayData,
                        plainSig,
                        endpointValue,
                        endpointConfigId,
                        trustedhubTransId);

                Response response = endpointServiceResponse.getResponse();

                if (response == null) {
                    ResponseMessage = Defines.ERROR_ENDPOINTEXP;
                    ResponseCode = Defines.CODE_ENDPOINTEXP;

                    archiveId = createArchiveId(errors,
                            (String) requestContext.get(RequestContext.TRANSACTION_ID));
                    final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                            Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                            errors, archiveId));
                    signResponse = new GenericSignResponse(sReq.getRequestID(),
                            errors, null, null, archiveId, archivables,
                            ResponseCode, ResponseMessage, null);
                    ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                    return signResponse;
                }

                String responseMess = response.getStatus().getResponseMesssage();
                int responseCode = response.getStatus().getResponseCode();

                if (responseCode == 0) {

                    if (messageMode.compareTo(Defines.SIGNERAP_SYNC) == 0) {

                        String signature = response.getMssSignatureResp().getSignature();
                        String signatureformat = response.getMssSignatureResp().getSignatureFormat();
                        String certificate = response.getMssSignatureResp().getCertificate();

                        X509Certificate x509 = null;
                        // PKCS#1
                        String[] pkiSimInfo = DBConnector.getInstances().authGetPhoneNoSimPKI(
                                channelName, user);
                        try {
                            x509 = ExtFunc.getCertificate(pkiSimInfo[1]);
                        } catch (Exception e) {
                            e.printStackTrace();
                            ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                            ResponseCode = Defines.CODE_INTERNALSYSTEM;
                            archiveId = createArchiveId(errors,
                                    (String) requestContext.get(RequestContext.TRANSACTION_ID));
                            final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                                    Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                                    errors, archiveId));
                            signResponse = new GenericSignResponse(
                                    sReq.getRequestID(), errors, null, null,
                                    archiveId, archivables, ResponseCode,
                                    ResponseMessage, null);
                            ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                            return signResponse;
                        }
                        String[] msspCertCompos = ExtFunc.getCertificateComponents(certificate);

                        if (msspCertCompos[5].compareToIgnoreCase(pkiSimInfo[2]) != 0) {
                            LOG.error("Invalid certificate. Certificate in system isn't match signer certificate");
                            ResponseMessage = Defines.ERROR_INVALIDCERTIFICATE;
                            ResponseCode = Defines.CODE_INVALIDCERTIFICATE;
                            archiveId = createArchiveId(errors,
                                    (String) requestContext.get(RequestContext.TRANSACTION_ID));
                            final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                                    Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                                    errors, archiveId));
                            signResponse = new GenericSignResponse(
                                    sReq.getRequestID(), errors, null, null,
                                    archiveId, archivables, ResponseCode,
                                    ResponseMessage, null);
                            ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                            return signResponse;
                        }

                        ResponseCode = Defines.CODE_SUCCESS;
                        ResponseMessage = Defines.SUCCESS;

                        archiveId = createArchiveId(errors,
                                (String) requestContext.get(RequestContext.TRANSACTION_ID));
                        final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                                Archivable.TYPE_RESPONSE,
                                CONTENT_TYPE,
                                DatatypeConverter.parseBase64Binary(signature),
                                archiveId));
                        signResponse = new GenericSignResponse(
                                sReq.getRequestID(),
                                DatatypeConverter.parseBase64Binary(signature),
                                x509, null, archiveId, archivables,
                                ResponseCode, ResponseMessage);
                        ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                        return signResponse;

                    } else {
                        // messagemode = Asynch

                        String msspTransId = response.getMssSignatureResp().getMsspTransactionId();

                        ResponseCode = Defines.CODE_MSSP_REQUEST_ACCEPTED;
                        ResponseMessage = Defines.MSSP_REQUEST_ACCEPTED;

                        java.util.Properties propertiesData = new java.util.Properties();
                        propertiesData.setProperty(Defines._TRANSACTIONCODE, transactionCode);
                        //propertiesData.setProperty(Defines._STREAMDATAPATH, streamDataPath);
                        //propertiesData.setProperty(Defines._STREAMSIGNPATH, streamSignPath);
                        propertiesData.setProperty(Defines._TRANSACTIONID, msspTransId);
                        //propertiesData.setProperty(Defines._FILETYPE, ExtFunc.checkFileType(data, fileType));

                        archiveId = createArchiveId(errors,
                                (String) requestContext.get(RequestContext.TRANSACTION_ID));
                        final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                                Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                                errors, archiveId));
                        signResponse = new GenericSignResponse(
                                sReq.getRequestID(), errors, null, null,
                                archiveId, archivables, ResponseCode,
                                ResponseMessage, null, propertiesData);
                        ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                        return signResponse;
                    }
                } else {
                    // Connector response no success
                    ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                    ResponseCode = Defines.CODE_INTERNALSYSTEM;

                    archiveId = createArchiveId(errors,
                            (String) requestContext.get(RequestContext.TRANSACTION_ID));
                    final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                            Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                            errors, archiveId));
                    signResponse = new GenericSignResponse(sReq.getRequestID(),
                            errors, null, null, archiveId, archivables,
                            ResponseCode, ResponseMessage, null);
                    ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                    return signResponse;
                }
            } else {
                // PKCS#7
                byte[] plainSig = data;

                if (transactionCode != null) {

                    if (billCode == null) {
                        ResponseMessage = Defines.ERROR_INVALIDPARAMETER;
                        ResponseCode = Defines.CODE_INVALIDPARAMETER;
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

                    if (transactionCode.compareTo(otpTransaction[11]) != 0) {
                        ResponseMessage = Defines.ERROR_NOTMATCHID;
                        ResponseCode = Defines.CODE_NOTMATCHID;
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
                } else if (messageMode.compareToIgnoreCase(Defines.SIGNERAP_SYNC) == 0) {
                    ResponseMessage = Defines.ERROR_INVALIDPARAMETER;
                    ResponseCode = Defines.CODE_INVALIDPARAMETER;
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
                } else {
                    // RequestID=null and method Async then do nothing
                    //transactionCode = ExtFunc.generateApTransIdAndRequestId()[1];
                    transactionCode = ExtFunc.calculateVerificationCode(plainSig);
                }

                if (displayData == null || displayData.compareTo("") == 0) {
                    displayData = "Transaction code: " + Defines.MSSP_SYMBOL_VC; // by
                    // default
                }

                displayData = DBConnector.getInstances().getWPKITransactionGeneration(displayData, Defines.MSSP_SYMBOL_VC);

                EndpointServiceResponse endpointServiceResponse = EndpointService.getInstance().requestMobileSignature(channelName, user, pkiSim, vendor,
                        messageMode, ExtFunc.generateApTransId(), signatureFormat, displayData, plainSig, endpointValue, endpointConfigId, trustedhubTransId);

                Response response = endpointServiceResponse.getResponse();

                if (response == null) {
                    ResponseMessage = Defines.ERROR_ENDPOINTEXP;
                    ResponseCode = Defines.CODE_ENDPOINTEXP;

                    archiveId = createArchiveId(errors,
                            (String) requestContext.get(RequestContext.TRANSACTION_ID));
                    final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                            Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                            errors, archiveId));
                    signResponse = new GenericSignResponse(sReq.getRequestID(),
                            errors, null, null, archiveId, archivables,
                            ResponseCode, ResponseMessage, null);
                    ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                    return signResponse;
                }

                String responseMess = response.getStatus().getResponseMesssage();
                int responseCode = response.getStatus().getResponseCode();

                if (responseCode == 0) {
                    if (messageMode.compareTo(Defines.SIGNERAP_SYNC) == 0) {

                        String signature = response.getMssSignatureResp().getSignature();
                        String signatureformat = response.getMssSignatureResp().getSignatureFormat();
                        String certificate = response.getMssSignatureResp().getCertificate();

                        X509Certificate x509 = null;
                        // PKCS#1
                        String[] pkiSimInfo = DBConnector.getInstances().authGetPhoneNoSimPKI(
                                channelName, user);
                        try {
                            x509 = ExtFunc.getCertificate(pkiSimInfo[1]);
                        } catch (Exception e) {
                            e.printStackTrace();
                            ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                            ResponseCode = Defines.CODE_INTERNALSYSTEM;
                            archiveId = createArchiveId(errors,
                                    (String) requestContext.get(RequestContext.TRANSACTION_ID));
                            final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                                    Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                                    errors, archiveId));
                            signResponse = new GenericSignResponse(
                                    sReq.getRequestID(), errors, null, null,
                                    archiveId, archivables, ResponseCode,
                                    ResponseMessage, null);
                            ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                            return signResponse;
                        }
                        String[] msspCertCompos = ExtFunc.getCertificateComponents(certificate);

                        if (msspCertCompos[5].compareToIgnoreCase(pkiSimInfo[2]) != 0) {
                            LOG.error("Invalid certificate. Certificate in system isn't match signer certificate");
                            ResponseMessage = Defines.ERROR_INVALIDCERTIFICATE;
                            ResponseCode = Defines.CODE_INVALIDCERTIFICATE;
                            archiveId = createArchiveId(errors,
                                    (String) requestContext.get(RequestContext.TRANSACTION_ID));
                            final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                                    Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                                    errors, archiveId));
                            signResponse = new GenericSignResponse(
                                    sReq.getRequestID(), errors, null, null,
                                    archiveId, archivables, ResponseCode,
                                    ResponseMessage, null);
                            ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                            return signResponse;
                        }

                        ResponseCode = Defines.CODE_SUCCESS;
                        ResponseMessage = Defines.SUCCESS;

                        archiveId = createArchiveId(errors,
                                (String) requestContext.get(RequestContext.TRANSACTION_ID));
                        final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                                Archivable.TYPE_RESPONSE,
                                CONTENT_TYPE,
                                DatatypeConverter.parseBase64Binary(signature),
                                archiveId));
                        signResponse = new GenericSignResponse(
                                sReq.getRequestID(),
                                DatatypeConverter.parseBase64Binary(signature),
                                x509, null, archiveId, archivables,
                                ResponseCode, ResponseMessage);
                        ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                        return signResponse;

                    } else {
                        // messagemode = Asynch

                        String msspTransId = response.getMssSignatureResp().getMsspTransactionId();

                        ResponseCode = Defines.CODE_MSSP_REQUEST_ACCEPTED;
                        ResponseMessage = Defines.MSSP_REQUEST_ACCEPTED;

                        java.util.Properties propertiesData = new java.util.Properties();
                        propertiesData.setProperty(Defines._TRANSACTIONCODE, transactionCode);
                        //propertiesData.setProperty(Defines._STREAMDATAPATH, streamDataPath);
                        //propertiesData.setProperty(Defines._STREAMSIGNPATH, streamSignPath);
                        propertiesData.setProperty(Defines._TRANSACTIONID, msspTransId);
                        //propertiesData.setProperty(Defines._FILETYPE, ExtFunc.checkFileType(data, fileType));

                        archiveId = createArchiveId(errors,
                                (String) requestContext.get(RequestContext.TRANSACTION_ID));
                        final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                                Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                                errors, archiveId));
                        signResponse = new GenericSignResponse(
                                sReq.getRequestID(), errors, null, null,
                                archiveId, archivables, ResponseCode,
                                ResponseMessage, null, propertiesData);
                        ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                        return signResponse;
                    }
                } else {
                    // Connector response no success
                    ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                    ResponseCode = Defines.CODE_INTERNALSYSTEM;

                    archiveId = createArchiveId(errors,
                            (String) requestContext.get(RequestContext.TRANSACTION_ID));
                    final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                            Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                            errors, archiveId));
                    signResponse = new GenericSignResponse(sReq.getRequestID(),
                            errors, null, null, archiveId, archivables,
                            ResponseCode, ResponseMessage, null);
                    ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                    return signResponse;
                }
            }

        } else if (method.compareTo(Defines.SIGNERAP_STAREG) == 0) {
            // StatusRequest

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

            String msspId = otpTransaction[10];

            if (msspId == null) {
                ResponseMessage = Defines.ERROR_NOTMATCHID;
                ResponseCode = Defines.CODE_NOTMATCHID;
                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                return signResponse;
            }


            EndpointServiceResponse endpointServiceResponse = EndpointService.getInstance().requestMobileSignatureStatus(
                    channelName,
                    user,
                    vendor,
                    msspId,
                    authCode,
                    endpointValue,
                    endpointConfigId,
                    trustedhubTransId);
            Response response = endpointServiceResponse.getResponse();

            if (response == null) {
                ResponseMessage = Defines.ERROR_ENDPOINTEXP;
                ResponseCode = Defines.CODE_ENDPOINTEXP;
                // update mssp transaction
                //DBConnector.getInstances().mssp_InsertTransaction(user, channelName, pkiSim, null, null, ResponseMessage, null);
                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                        Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                        errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            }

            int responseCode = response.getStatus().getResponseCode();
            String responseMess = response.getStatus().getResponseMesssage();

            if (responseCode == Defines.CODE_SUCCESS) {
                String signature = response.getMssStatusResp().getSignature();
                String signatureformat = response.getMssStatusResp().getSignatureFormat();
                String certificate = response.getMssStatusResp().getCertificate();

                X509Certificate x509 = null;
                // PKCS#1
                String[] pkiSimInfo = DBConnector.getInstances().authGetPhoneNoSimPKI(
                        channelName, user);
                try {
                    x509 = ExtFunc.getCertificate(pkiSimInfo[1]);
                } catch (Exception e) {
                    e.printStackTrace();
                    ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                    ResponseCode = Defines.CODE_INTERNALSYSTEM;
                    archiveId = createArchiveId(errors,
                            (String) requestContext.get(RequestContext.TRANSACTION_ID));
                    final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                            Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                            errors, archiveId));
                    signResponse = new GenericSignResponse(
                            sReq.getRequestID(), errors, null, null,
                            archiveId, archivables, ResponseCode,
                            ResponseMessage, null);
                    ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                    return signResponse;
                }
                String[] msspCertCompos = ExtFunc.getCertificateComponents(certificate);

                if (msspCertCompos[5].compareToIgnoreCase(pkiSimInfo[2]) != 0) {
                    LOG.error("Invalid certificate. Certificate in system isn't match signer certificate");
                    ResponseMessage = Defines.ERROR_INVALIDCERTIFICATE;
                    ResponseCode = Defines.CODE_INVALIDCERTIFICATE;
                    archiveId = createArchiveId(errors,
                            (String) requestContext.get(RequestContext.TRANSACTION_ID));
                    final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                            Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                            errors, archiveId));
                    signResponse = new GenericSignResponse(
                            sReq.getRequestID(), errors, null, null,
                            archiveId, archivables, ResponseCode,
                            ResponseMessage, null);
                    ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                    return signResponse;
                }

                ResponseCode = Defines.CODE_SUCCESS;
                ResponseMessage = Defines.SUCCESS;

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                        Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                        DatatypeConverter.parseBase64Binary(signature),
                        archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        DatatypeConverter.parseBase64Binary(signature),
                        x509, null, archiveId, archivables, ResponseCode,
                        ResponseMessage);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;

            } else if (responseCode == CODE_DETAILS_MSSP_EXPR) {
                LOG.info("Transaction expired");
                ResponseMessage = Defines.MSSP_TRANSACTION_EXPIRED;
                ResponseCode = Defines.CODE_MSSP_TRANSACTION_EXPIRED;
                // update mssp transaction
                //DBConnector.getInstances().mssp_InsertTransaction(user, channelName, pkiSim, null, null, responseMess, null);
                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            } else if (responseCode == CODE_DETAILS_MSSP_NOTRANS) {
                LOG.info("No transaction found");
                ResponseMessage = Defines.MSSP_NO_TRANSACTION_FOUND;
                ResponseCode = Defines.CODE_MSSP_NO_TRANSACTION_FOUND;
                // update mssp transaction
                //DBConnector.getInstances().mssp_InsertTransaction(user, channelName, pkiSim, null, null, responseMess, null);
                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            } else if (responseCode == CODE_DETAILS_MSSP_OUTS) {
                LOG.info("Outstanding transaction");
                ResponseMessage = Defines.MSSP_OUT_TRANSACTION;
                ResponseCode = Defines.CODE_MSSP_OUT_TRANSACTION;
                // update mssp transaction
                //DBConnector.getInstances().mssp_InsertTransaction(user, channelName, pkiSim, null, null, responseMess, null);
                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            } else if (responseCode == CODE_DETAILS_MSSP_AUTH_FAILED) {
                LOG.info("WPKI auth failed");
                ResponseMessage = Defines.MSSP_AUTH_FAILED;
                ResponseCode = Defines.CODE_MSSP_AUTH_FAILED;
                // update mssp transaction
                //DBConnector.getInstances().mssp_InsertTransaction(user, channelName, pkiSim, null, null, responseMess, null);
                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            } else if (responseCode == CODE_DETAILS_MSSP_NOCERT) {
                LOG.info("Certificate hasn't been registered.");
                ResponseMessage = Defines.MSSP_NOCERTIFICATE;
                ResponseCode = Defines.CODE_MSSP_NOCERTIFICATE;
                // update mssp transaction
                //DBConnector.getInstances().mssp_InsertTransaction(user, channelName, pkiSim, null, null, responseMess, null);
                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            } else if (responseCode == CODE_DETAILS_MSSP_TRANS_CANCELED) {
                LOG.info("Transaction is canceled by user");
                ResponseMessage = Defines.MSSP_TRANSACTION_CANCELED;
                ResponseCode = Defines.CODE_MSSP_CANCELED;

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            } else {
                ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                ResponseCode = Defines.CODE_INTERNALSYSTEM;
                // update mssp transaction
                //DBConnector.getInstances().mssp_InsertTransaction(user, channelName, pkiSim, null, null, responseMess, null);
                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            }

        } else if (method.compareTo(Defines.SIGNERAP_STRREG) == 0) {
            // TransRequest
            String transCode = getTransactionId(user);

            ResponseCode = Defines.CODE_MSSP_REQUEST_ACCEPTED;
            ResponseMessage = Defines.MSSP_REQUEST_ACCEPTED;

            java.util.Properties propertiesData = new java.util.Properties();
            propertiesData.setProperty(Defines._TRANSACTIONCODE, transCode);

            archiveId = createArchiveId(errors,
                    (String) requestContext.get(RequestContext.TRANSACTION_ID));
            final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                    CONTENT_TYPE, errors, archiveId));
            signResponse = new GenericSignResponse(sReq.getRequestID(), errors,
                    null, null, archiveId, archivables, ResponseCode,
                    ResponseMessage, null, propertiesData);
            return signResponse;
        } else if (method.compareTo(Defines.SIGNERAP_CERTREG) == 0) {
            // Certificate Request
			/*
             * if (algorithm.compareTo(HASH_SHA1) == 0) { if (data.length != 20)
             * { LOG.error("Data should be hashed. Expected length is 20
             * bytes"); ResponseMessage = Defines.ERROR_NOBASE64FILE;
             * ResponseCode = Defines.CODE_NOBASE64FILE; archiveId =
             * createArchiveId(errors, (String) requestContext
             * .get(RequestContext.TRANSACTION_ID)); final Collection<? extends
             * Archivable> archivables = Arrays .asList(new DefaultArchivable(
             * Archivable.TYPE_RESPONSE, CONTENT_TYPE, errors, archiveId));
             * signResponse = new GenericSignResponse(sReq.getRequestID(),
             * errors, null, null, archiveId, archivables, ResponseCode,
             * ResponseMessage, null); return signResponse; } else { try {
             * BouncyCastleProvider provider = new BouncyCastleProvider();
             * Security.addProvider(provider);
             *
             * DERObjectIdentifier sha1oid_ = new DERObjectIdentifier(
             * "1.3.14.3.2.26");
             *
             * AlgorithmIdentifier sha1aid_ = new AlgorithmIdentifier( sha1oid_,
             * null); DigestInfo di = new DigestInfo(sha1aid_, data);
             *
             * byte[] plainSig = di.getEncoded(ASN1Encoding.DER);
             *
             *
             *
             * EndpointServiceResponse endpointServiceResponse =
             * EndpointService.getInstance().requestMobileSignature(channelName,
             * user, pkiSim, vendor, messageMode, ExtFunc.generateApTransId(),
             * Defines.SIGNERAP_SIGNFORMAT_P7, displayData, plainSig,
             * endpointValue, endpointConfigId);
             *
             * Response response = endpointServiceResponse.getResponse();
             *
             * if(response == null) { ResponseMessage =
             * Defines.ERROR_ENDPOINTEXP; ResponseCode =
             * Defines.CODE_ENDPOINTEXP;
             *
             * archiveId = createArchiveId(errors, (String) requestContext
             * .get(RequestContext.TRANSACTION_ID)); final Collection<? extends
             * Archivable> archivables = Arrays .asList(new DefaultArchivable(
             * Archivable.TYPE_RESPONSE, CONTENT_TYPE, errors, archiveId));
             * signResponse = new GenericSignResponse(sReq.getRequestID(),
             * errors, null, null, archiveId, archivables, ResponseCode,
             * ResponseMessage, null); ((GenericSignResponse)
             * signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
             * return signResponse; }
             *
             * int responseCode = response.getStatus().getResponseCode(); String
             * responseMess = response.getStatus().getResponseMesssage();
             *
             *
             * if (responseCode == Defines.CODE_SUCCESS) {
             *
             * String signature = response.getMssSignatureResp().getSignature();
             * String certificate =
             * response.getMssSignatureResp().getCertificate();
             *
             * Certificate x509 = ExtFunc.convertToX509Cert(certificate);
             *
             * ResponseCode = Defines.CODE_SUCCESS; ResponseMessage =
             * Defines.SUCCESS;
             *
             * archiveId = createArchiveId(data, (String) requestContext
             * .get(RequestContext.TRANSACTION_ID)); final Collection<? extends
             * Archivable> archivables = Arrays .asList(new DefaultArchivable(
             * Archivable.TYPE_RESPONSE, CONTENT_TYPE, DatatypeConverter
             * .parseBase64Binary(signature), archiveId)); signResponse = new
             * GenericSignResponse( sReq.getRequestID(), DatatypeConverter
             * .parseBase64Binary(signature), x509, null, archiveId,
             * archivables, ResponseCode, ResponseMessage);
             * ((GenericSignResponse)
             * signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
             * return signResponse; } else { ResponseMessage =
             * Defines.MSSP_ERROR; ResponseCode = Defines.CODE_MSSP_ERROR;
             * archiveId = createArchiveId(errors, (String) requestContext
             * .get(RequestContext.TRANSACTION_ID)); final Collection<? extends
             * Archivable> archivables = Arrays .asList(new DefaultArchivable(
             * Archivable.TYPE_RESPONSE, CONTENT_TYPE, errors, archiveId));
             * signResponse = new GenericSignResponse( sReq.getRequestID(),
             * errors, null, null, archiveId, archivables, ResponseCode,
             * ResponseMessage, null); ((GenericSignResponse)
             * signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
             * return signResponse; } } catch (Exception e) {
             * LOG.error("Something wrong: " + e.getMessage());
             * e.printStackTrace(); ResponseMessage =
             * Defines.ERROR_INTERNALSYSTEM; ResponseCode =
             * Defines.CODE_INTERNALSYSTEM; archiveId = createArchiveId(errors,
             * (String) requestContext .get(RequestContext.TRANSACTION_ID));
             * final Collection<? extends Archivable> archivables = Arrays
             * .asList(new DefaultArchivable( Archivable.TYPE_RESPONSE,
             * CONTENT_TYPE, errors, archiveId)); signResponse = new
             * GenericSignResponse( sReq.getRequestID(), errors, null, null,
             * archiveId, archivables, ResponseCode, ResponseMessage, null);
             * return signResponse; } } } else { ResponseMessage =
             * Defines.ERROR_INVALID_ALGORITHM; ResponseCode =
             * Defines.CODE_INVALID_ALGORITHM; final Collection<? extends
             * Archivable> archivables = Arrays .asList(new
             * DefaultArchivable(Archivable.TYPE_RESPONSE, CONTENT_TYPE, errors,
             * archiveId)); signResponse = new
             * GenericSignResponse(sReq.getRequestID(), errors, null, null,
             * archiveId, archivables, ResponseCode, ResponseMessage, null);
             * return signResponse; }
             */
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

            String msspId = otpTransaction[10];

            if (msspId == null) {
                ResponseMessage = Defines.ERROR_NOTMATCHID;
                ResponseCode = Defines.CODE_NOTMATCHID;
                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                return signResponse;
            }


            EndpointServiceResponse endpointServiceResponse = EndpointService.getInstance().requestMobileSignatureStatus(
                    channelName,
                    user,
                    vendor,
                    msspId,
                    authCode,
                    endpointValue,
                    endpointConfigId,
                    trustedhubTransId);
            Response response = endpointServiceResponse.getResponse();

            if (response == null) {
                ResponseMessage = Defines.ERROR_ENDPOINTEXP;
                ResponseCode = Defines.CODE_ENDPOINTEXP;
                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                        Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                        errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            }

            int responseCode = response.getStatus().getResponseCode();
            String responseMess = response.getStatus().getResponseMesssage();

            if (responseCode == Defines.CODE_SUCCESS) {
                String signature = response.getMssStatusResp().getSignature();
                String signatureformat = response.getMssStatusResp().getSignatureFormat();
                String certificate = response.getMssStatusResp().getCertificate();

                X509Certificate x509 = null;
                try {
                    x509 = ExtFunc.getCertificate(certificate);
                } catch (Exception e) {
                    e.printStackTrace();
                    ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                    ResponseCode = Defines.CODE_INTERNALSYSTEM;
                    archiveId = createArchiveId(errors,
                            (String) requestContext.get(RequestContext.TRANSACTION_ID));
                    final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                            Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                            errors, archiveId));
                    signResponse = new GenericSignResponse(
                            sReq.getRequestID(), errors, null, null,
                            archiveId, archivables, ResponseCode,
                            ResponseMessage, null);
                    ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                    return signResponse;
                }

                ResponseCode = Defines.CODE_SUCCESS;
                ResponseMessage = Defines.SUCCESS;

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                        Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                        DatatypeConverter.parseBase64Binary(signature),
                        archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        DatatypeConverter.parseBase64Binary(signature),
                        x509, null, archiveId, archivables, ResponseCode,
                        ResponseMessage);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;

            } else if (responseCode == CODE_DETAILS_MSSP_EXPR) {
                LOG.info("Transaction expired");
                ResponseMessage = Defines.MSSP_TRANSACTION_EXPIRED;
                ResponseCode = Defines.CODE_MSSP_TRANSACTION_EXPIRED;
                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            } else if (responseCode == CODE_DETAILS_MSSP_NOTRANS) {
                LOG.info("No transaction found");
                ResponseMessage = Defines.MSSP_NO_TRANSACTION_FOUND;
                ResponseCode = Defines.CODE_MSSP_NO_TRANSACTION_FOUND;

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            } else if (responseCode == CODE_DETAILS_MSSP_OUTS) {
                LOG.info("Outstanding transaction");
                ResponseMessage = Defines.MSSP_OUT_TRANSACTION;
                ResponseCode = Defines.CODE_MSSP_OUT_TRANSACTION;

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            } else if (responseCode == CODE_DETAILS_MSSP_AUTH_FAILED) {
                LOG.info("WPKI auth failed");
                ResponseMessage = Defines.MSSP_AUTH_FAILED;
                ResponseCode = Defines.CODE_MSSP_AUTH_FAILED;
                // update mssp transaction
                //DBConnector.getInstances().mssp_InsertTransaction(user, channelName, pkiSim, null, null, responseMess, null);
                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            } else if (responseCode == CODE_DETAILS_MSSP_NOCERT) {
                LOG.info("Certificate hasn't been registered.");
                ResponseMessage = Defines.MSSP_NOCERTIFICATE;
                ResponseCode = Defines.CODE_MSSP_NOCERTIFICATE;

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            } else if (responseCode == CODE_DETAILS_MSSP_TRANS_CANCELED) {
                LOG.info("Transaction is canceled by user");
                ResponseMessage = Defines.MSSP_TRANSACTION_CANCELED;
                ResponseCode = Defines.CODE_MSSP_CANCELED;

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            } else {
                ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                ResponseCode = Defines.CODE_INTERNALSYSTEM;

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            }
        } else if (method.compareTo(Defines.SIGNERAP_FILESIGREG) == 0) {
            // SignFileRequest
            // message mode
            if (messageMode != null) {
                if (!messageMode.equals(Defines.SIGNERAP_ASYNC)
                        && !messageMode.equals(Defines.SIGNERAP_SYNC)
                        && !messageMode.equals(Defines.SIGNERAP_ASYNC_REQ_RESP)) {
                    messageMode = Defines.SIGNERAP_ASYNC;
                }
            } else {
                messageMode = Defines.SIGNERAP_ASYNC;
            }
            // force async

            signatureFormat = Defines.SIGNERAP_SIGNFORMAT_P1;

            DC dc = null;
            DCResponse dcResp = null;

            if (ExtFunc.checkFileType(data, fileType).compareTo(ExtFunc.C_FILETYPE_PDF) == 0) {
                String visibleSignature = RequestMetadata.getInstance(requestContext).get(Defines._VISIBLESIGNATURE);
                String coordinate = RequestMetadata.getInstance(requestContext).get(Defines._COORDINATE);
                String pageNo = RequestMetadata.getInstance(requestContext).get(Defines._PAGENO);
                String signReason = RequestMetadata.getInstance(requestContext).get(Defines._SIGNREASON);
                String visualStatus = RequestMetadata.getInstance(requestContext).get(Defines._VISUALSTATUS);
                String signatureImage = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATUREIMAGE);
                String signerInfoPrefix = RequestMetadata.getInstance(requestContext).get(Defines._SIGNERINFOPREFIX);
                String dateTimePrefix = RequestMetadata.getInstance(requestContext).get(Defines._DATETIMEPREFIX);
                String signReasonPrefix = RequestMetadata.getInstance(requestContext).get(Defines._SIGNREASONPREFIX);
                String location = RequestMetadata.getInstance(requestContext).get(Defines._LOCATION);

                java.util.Properties signaturePro = new java.util.Properties();

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
                if (!ExtFunc.isNullOrEmpty(cerificate)) {
                    signaturePro.setProperty(Defines._CERTIFICATE, cerificate);
                }

                if (!ExtFunc.isNull(signerInfoPrefix)) {
                    signaturePro.setProperty(Defines._SIGNERINFOPREFIX, signerInfoPrefix);
                }
                if (!ExtFunc.isNull(dateTimePrefix)) {
                    signaturePro.setProperty(Defines._DATETIMEPREFIX, dateTimePrefix);
                }
                if (!ExtFunc.isNull(signReasonPrefix)) {
                    signaturePro.setProperty(Defines._SIGNREASONPREFIX, signReasonPrefix);
                }
                if (!ExtFunc.isNull(location)) {
                    signaturePro.setProperty(Defines._LOCATION, location);
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

            try {
                plainSig = ExtFunc.padSHA1Oid(plainSig);
            } catch (Exception e) {
                e.printStackTrace();
                LOG.error("Error while padding SHA1 OID");
                ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                ResponseCode = Defines.CODE_INTERNALSYSTEM;
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

            if (transactionCode != null) {

                if (billCode == null) {
                    ResponseMessage = Defines.ERROR_INVALIDPARAMETER;
                    ResponseCode = Defines.CODE_INVALIDPARAMETER;
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

                if (transactionCode.compareTo(otpTransaction[11]) != 0) {
                    ResponseMessage = Defines.ERROR_NOTMATCHID;
                    ResponseCode = Defines.CODE_NOTMATCHID;
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
            } else if (messageMode.compareToIgnoreCase(Defines.SIGNERAP_SYNC) == 0) {
                ResponseMessage = Defines.ERROR_INVALIDPARAMETER;
                ResponseCode = Defines.CODE_INVALIDPARAMETER;
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
            } else {
                // RequestID=null and method Async then do nothing
                //transactionCode = ExtFunc.generateApTransIdAndRequestId()[1];
                transactionCode = ExtFunc.calculateVerificationCode(plainSig);
            }

            if (displayData == null || displayData.compareTo("") == 0) {
                displayData = "Transaction code: " + Defines.MSSP_SYMBOL_VC; // by
                // default
            }

            displayData = DBConnector.getInstances().getWPKITransactionGeneration(displayData, Defines.MSSP_SYMBOL_VC);

            EndpointServiceResponse endpointServiceResponse = EndpointService.getInstance().requestMobileSignature(channelName, user, pkiSim,
                    vendor, messageMode, ExtFunc.generateApTransId(),
                    signatureFormat, displayData, plainSig, endpointValue, endpointConfigId, trustedhubTransId);

            Response response = endpointServiceResponse.getResponse();

            if (response == null) {
                ResponseMessage = Defines.ERROR_ENDPOINTEXP;
                ResponseCode = Defines.CODE_ENDPOINTEXP;

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                        Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                        errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            }


            String responseMess = response.getStatus().getResponseMesssage();
            int responseCode = response.getStatus().getResponseCode();

            if (responseCode == 0) {
                if (messageMode.compareTo(Defines.SIGNERAP_SYNC) == 0) {

                    String signature = response.getMssSignatureResp().getSignature();
                    String signatureformat = response.getMssSignatureResp().getSignatureFormat();
                    String certificate = response.getMssSignatureResp().getCertificate();

                    X509Certificate x509 = null;
                    // PKCS#1
                    String[] pkiSimInfo = DBConnector.getInstances().authGetPhoneNoSimPKI(
                            channelName, user);
                    try {
                        x509 = ExtFunc.getCertificate(pkiSimInfo[1]);
                    } catch (Exception e) {
                        e.printStackTrace();
                        ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                        ResponseCode = Defines.CODE_INTERNALSYSTEM;
                        archiveId = createArchiveId(errors,
                                (String) requestContext.get(RequestContext.TRANSACTION_ID));
                        final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                                Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                                errors, archiveId));
                        signResponse = new GenericSignResponse(
                                sReq.getRequestID(), errors, null, null,
                                archiveId, archivables, ResponseCode,
                                ResponseMessage, null);
                        ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                        return signResponse;
                    }
                    String[] msspCertCompos = ExtFunc.getCertificateComponents(certificate);

                    if (msspCertCompos[5].compareToIgnoreCase(pkiSimInfo[2]) != 0) {
                        LOG.error("Invalid certificate. Certificate in system isn't match signer certificate");
                        ResponseMessage = Defines.ERROR_INVALIDCERTIFICATE;
                        ResponseCode = Defines.CODE_INVALIDCERTIFICATE;
                        archiveId = createArchiveId(errors,
                                (String) requestContext.get(RequestContext.TRANSACTION_ID));
                        final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                                Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                                errors, archiveId));
                        signResponse = new GenericSignResponse(
                                sReq.getRequestID(), errors, null, null,
                                archiveId, archivables, ResponseCode,
                                ResponseMessage, null);
                        ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                        return signResponse;
                    }

                    ResponseCode = Defines.CODE_SUCCESS;
                    ResponseMessage = Defines.SUCCESS;

                    //DC dc = null;
                    //DCResponse dcResp = null;

                    if (fileType.compareTo(ExtFunc.C_FILETYPE_PDF) == 0) {

                        dc = new DCPDF();
                        dcResp = dc.signFinal(streamDataPath, streamSignPath, DatatypeConverter.parseBase64Binary(signature), certificate);

                    } else if (fileType.compareTo(ExtFunc.C_FILETYPE_OFFICE) == 0) {

                        dc = new DCOffice();
                        dcResp = dc.signFinal(streamDataPath, streamSignPath, DatatypeConverter.parseBase64Binary(signature), certificate);
                    } else {
                        // xml
                        dc = new DCXml();
                        dcResp = dc.signFinal(streamDataPath, streamSignPath, DatatypeConverter.parseBase64Binary(signature), certificate);
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
                        ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
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
                    signResponse = new GenericSignResponse(
                            sReq.getRequestID(),
                            signedFile,
                            x509, null, archiveId, archivables,
                            ResponseCode, ResponseMessage);
                    ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                    return signResponse;


                } else {
                    // messagemode = Asynch
                    String msspTransId = response.getMssSignatureResp().getMsspTransactionId();

                    ResponseCode = Defines.CODE_MSSP_REQUEST_ACCEPTED;
                    ResponseMessage = Defines.MSSP_REQUEST_ACCEPTED;

                    java.util.Properties propertiesData = new java.util.Properties();
                    propertiesData.setProperty(Defines._TRANSACTIONCODE, transactionCode);
                    propertiesData.setProperty(Defines._STREAMDATAPATH, streamDataPath);
                    propertiesData.setProperty(Defines._STREAMSIGNPATH, streamSignPath);
                    propertiesData.setProperty(Defines._TRANSACTIONID, msspTransId);
                    propertiesData.setProperty(Defines._FILETYPE, ExtFunc.checkFileType(data, fileType));

                    if (fileName != null && fileId != null && fileMimeType != null && fileDisplayValue != null) {
                        propertiesData.setProperty(Defines._FILENAME, fileName);
                        propertiesData.setProperty(Defines._FILEID, fileId);
                        propertiesData.setProperty(Defines._MIMETYPE, fileMimeType);
                        propertiesData.setProperty(Defines._DISPLAYVALUE, fileDisplayValue);
                    }

                    archiveId = createArchiveId(errors,
                            (String) requestContext.get(RequestContext.TRANSACTION_ID));
                    final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                            Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                            errors, archiveId));
                    signResponse = new GenericSignResponse(
                            sReq.getRequestID(), errors, null, null,
                            archiveId, archivables, ResponseCode,
                            ResponseMessage, null, propertiesData);
                    ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                    return signResponse;
                }
            } else {
                // Connector response no success
                ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                ResponseCode = Defines.CODE_INTERNALSYSTEM;
                // update mssp transaction
                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                        Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                        errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            }
        } else if (method.compareTo(Defines.SIGNERAP_FILESTAREG) == 0) {
            // SignFileResponse
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

            String msspId = otpTransaction[10];

            if (msspId == null) {
                ResponseMessage = Defines.ERROR_NOTMATCHID;
                ResponseCode = Defines.CODE_NOTMATCHID;
                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                return signResponse;
            }


            EndpointServiceResponse endpointServiceResponse = EndpointService.getInstance().requestMobileSignatureStatus(
                    channelName,
                    user,
                    vendor,
                    msspId,
                    authCode,
                    endpointValue,
                    endpointConfigId,
                    trustedhubTransId);

            Response response = endpointServiceResponse.getResponse();

            if (response == null) {
                ResponseMessage = Defines.ERROR_ENDPOINTEXP;
                ResponseCode = Defines.CODE_ENDPOINTEXP;
                // update mssp transaction
                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                        Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                        errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            }

            int responseCode = response.getStatus().getResponseCode();
            String responseMess = response.getStatus().getResponseMesssage();

            if (responseCode == Defines.CODE_SUCCESS) {
                String signature = response.getMssStatusResp().getSignature();
                String signatureformat = response.getMssStatusResp().getSignatureFormat();
                String certificate = response.getMssStatusResp().getCertificate();

                X509Certificate x509 = null;
                // PKCS#1
                String[] pkiSimInfo = DBConnector.getInstances().authGetPhoneNoSimPKI(
                        channelName, user);
                try {
                    x509 = ExtFunc.getCertificate(pkiSimInfo[1]);
                } catch (Exception e) {
                    e.printStackTrace();
                    ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                    ResponseCode = Defines.CODE_INTERNALSYSTEM;
                    archiveId = createArchiveId(errors,
                            (String) requestContext.get(RequestContext.TRANSACTION_ID));
                    final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                            Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                            errors, archiveId));
                    signResponse = new GenericSignResponse(
                            sReq.getRequestID(), errors, null, null,
                            archiveId, archivables, ResponseCode,
                            ResponseMessage, null);
                    ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                    return signResponse;
                }
                String[] msspCertCompos = ExtFunc.getCertificateComponents(certificate);

                if (msspCertCompos[5].compareToIgnoreCase(pkiSimInfo[2]) != 0) {
                    LOG.error("Invalid certificate. Certificate in system isn't match signer certificate");
                    ResponseMessage = Defines.ERROR_INVALIDCERTIFICATE;
                    ResponseCode = Defines.CODE_INVALIDCERTIFICATE;
                    archiveId = createArchiveId(errors,
                            (String) requestContext.get(RequestContext.TRANSACTION_ID));
                    final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                            Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                            errors, archiveId));
                    signResponse = new GenericSignResponse(
                            sReq.getRequestID(), errors, null, null,
                            archiveId, archivables, ResponseCode,
                            ResponseMessage, null);
                    ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                    return signResponse;
                }

                ResponseCode = Defines.CODE_SUCCESS;
                ResponseMessage = Defines.SUCCESS;

                DC dc = null;
                DCResponse dcResp = null;

                if (otpTransaction[7].compareTo(ExtFunc.C_FILETYPE_PDF) == 0) {

                    dc = new DCPDF();
                    dcResp = dc.signFinal(otpTransaction[8], otpTransaction[9], DatatypeConverter.parseBase64Binary(signature), certificate);

                } else if (otpTransaction[7].compareTo(ExtFunc.C_FILETYPE_OFFICE) == 0) {

                    dc = new DCOffice();
                    dcResp = dc.signFinal(otpTransaction[8], otpTransaction[9], DatatypeConverter.parseBase64Binary(signature), certificate);

                } else {
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
                    ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
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
                signResponse = new GenericSignResponse(
                        sReq.getRequestID(),
                        signedFile,
                        x509, null, archiveId, archivables,
                        ResponseCode, ResponseMessage);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());

                if (otpTransaction[16] != null && otpTransaction[18] != null
                        && otpTransaction[17] != null && otpTransaction[20] != null) {

                    Properties propertiesData = new Properties();
                    propertiesData.setProperty(Defines._FILEID, otpTransaction[16]);
                    propertiesData.setProperty(Defines._FILENAME, otpTransaction[18]);
                    propertiesData.setProperty(Defines._MIMETYPE, otpTransaction[17]);
                    propertiesData.setProperty(Defines._DISPLAYVALUE, otpTransaction[20]);
                    ((GenericSignResponse) signResponse).setPropertiesData(propertiesData);
                }
                return signResponse;

            } else if (responseCode == CODE_DETAILS_MSSP_EXPR) {
                LOG.info("Transaction expired");
                ResponseMessage = Defines.MSSP_TRANSACTION_EXPIRED;
                ResponseCode = Defines.CODE_MSSP_TRANSACTION_EXPIRED;

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            } else if (responseCode == CODE_DETAILS_MSSP_NOTRANS) {
                LOG.info("No transaction found");
                ResponseMessage = Defines.MSSP_NO_TRANSACTION_FOUND;
                ResponseCode = Defines.CODE_MSSP_NO_TRANSACTION_FOUND;

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            } else if (responseCode == CODE_DETAILS_MSSP_OUTS) {
                LOG.info("Outstanding transaction");
                ResponseMessage = Defines.MSSP_OUT_TRANSACTION;
                ResponseCode = Defines.CODE_MSSP_OUT_TRANSACTION;

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            } else if (responseCode == CODE_DETAILS_MSSP_AUTH_FAILED) {
                LOG.info("WPKI auth failed");
                ResponseMessage = Defines.MSSP_AUTH_FAILED;
                ResponseCode = Defines.CODE_MSSP_AUTH_FAILED;
                // update mssp transaction
                //DBConnector.getInstances().mssp_InsertTransaction(user, channelName, pkiSim, null, null, responseMess, null);
                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            } else if (responseCode == CODE_DETAILS_MSSP_NOCERT) {
                LOG.info("Certificate hasn't been registered.");
                ResponseMessage = Defines.MSSP_NOCERTIFICATE;
                ResponseCode = Defines.CODE_MSSP_NOCERTIFICATE;
                // update mssp transaction
                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            } else if (responseCode == CODE_DETAILS_MSSP_TRANS_CANCELED) {
                LOG.info("Transaction is canceled by user");
                ResponseMessage = Defines.MSSP_TRANSACTION_CANCELED;
                ResponseCode = Defines.CODE_MSSP_CANCELED;

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            } else {
                ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                ResponseCode = Defines.CODE_INTERNALSYSTEM;
                // update mssp transaction
                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            }

        } else if (method.compareTo(Defines.SIGNERAP_AUTH_REQ) == 0) {
            // SignatureRequest
            if (messageMode != null) {
                if (!messageMode.equals(Defines.SIGNERAP_ASYNC)
                        /*
                         * && !messageMode.equals(Defines.SIGNERAP_SYNC)
                         */ //--> only async
                        && !messageMode.equals(Defines.SIGNERAP_ASYNC_REQ_RESP)) {
                    messageMode = Defines.SIGNERAP_ASYNC;
                }
            } else {
                messageMode = Defines.SIGNERAP_ASYNC;
            }

            signatureFormat = Defines.SIGNERAP_SIGNFORMAT_P1;

            byte[] plainSig = null;
            data = String.valueOf(System.currentTimeMillis()).getBytes();
            // non-hash
            try {
                MessageDigest md = MessageDigest.getInstance(HASH_SHA1);
                md.update(data);
                data = md.digest();
                plainSig = ExtFunc.padSHA1Oid(data);
            } catch (Exception e) {
                LOG.error("Error while hashing and padding SHA1 OID");
                e.printStackTrace();
                ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                ResponseCode = Defines.CODE_INTERNALSYSTEM;

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

            // RequestID=null and method Async then do nothing
            //transactionCode = ExtFunc.generateApTransIdAndRequestId()[1];
            transactionCode = ExtFunc.calculateVerificationCode(plainSig);

            if (displayData == null || displayData.compareTo("") == 0) {
                displayData = "Transaction code: " + Defines.MSSP_SYMBOL_VC; // by
                // default
            }

            displayData = DBConnector.getInstances().getWPKITransactionGeneration(displayData, Defines.MSSP_SYMBOL_VC);

            EndpointServiceResponse endpointServiceResponse = EndpointService.getInstance().requestMobileSignature(channelName, user, pkiSim, vendor,
                    messageMode, ExtFunc.generateApTransId(), signatureFormat, displayData, plainSig, endpointValue, endpointConfigId, trustedhubTransId);

            Response response = endpointServiceResponse.getResponse();

            if (response == null) {
                ResponseMessage = Defines.ERROR_ENDPOINTEXP;
                ResponseCode = Defines.CODE_ENDPOINTEXP;

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                        Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                        errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            }

            String responseMess = response.getStatus().getResponseMesssage();
            int responseCode = response.getStatus().getResponseCode();

            if (responseCode == 0) {
                // messagemode = Asynch
                String msspTransId = response.getMssSignatureResp().getMsspTransactionId();

                ResponseCode = Defines.CODE_MSSP_REQUEST_ACCEPTED;
                ResponseMessage = Defines.MSSP_REQUEST_ACCEPTED;

                java.util.Properties propertiesData = new java.util.Properties();
                propertiesData.setProperty(Defines._TRANSACTIONCODE, transactionCode);
                propertiesData.setProperty(Defines._TRANSACTIONID, msspTransId);

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                        Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                        errors, archiveId));
                signResponse = new GenericSignResponse(
                        sReq.getRequestID(), errors, null, null,
                        archiveId, archivables, ResponseCode,
                        ResponseMessage, null, propertiesData);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            } else {
                // Connector response no success
                ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                ResponseCode = Defines.CODE_INTERNALSYSTEM;

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                        Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                        errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            }
        } else if (method.compareTo(Defines.SIGNERAP_AUTH_RESP) == 0) {
            // StatusRequest
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

            String msspId = otpTransaction[10];

            if (msspId == null) {
                ResponseMessage = Defines.ERROR_NOTMATCHID;
                ResponseCode = Defines.CODE_NOTMATCHID;
                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                return signResponse;
            }

            EndpointServiceResponse endpointServiceResponse = EndpointService.getInstance().requestMobileSignatureStatus(
                    channelName,
                    user,
                    vendor,
                    msspId,
                    authCode,
                    endpointValue,
                    endpointConfigId,
                    trustedhubTransId);
            Response response = endpointServiceResponse.getResponse();

            if (response == null) {
                ResponseMessage = Defines.ERROR_ENDPOINTEXP;
                ResponseCode = Defines.CODE_ENDPOINTEXP;

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                        Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                        errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            }

            int responseCode = response.getStatus().getResponseCode();
            String responseMess = response.getStatus().getResponseMesssage();

            if (responseCode == Defines.CODE_SUCCESS) {
                String signature = response.getMssStatusResp().getSignature();
                String signatureformat = response.getMssStatusResp().getSignatureFormat();
                String certificate = response.getMssStatusResp().getCertificate();

                X509Certificate x509 = null;
                // PKCS#1
                String[] pkiSimInfo = DBConnector.getInstances().authGetPhoneNoSimPKI(
                        channelName, user);
                try {
                    x509 = ExtFunc.getCertificate(pkiSimInfo[1]);
                } catch (Exception e) {
                    e.printStackTrace();
                    ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                    ResponseCode = Defines.CODE_INTERNALSYSTEM;
                    archiveId = createArchiveId(errors,
                            (String) requestContext.get(RequestContext.TRANSACTION_ID));
                    final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                            Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                            errors, archiveId));
                    signResponse = new GenericSignResponse(
                            sReq.getRequestID(), errors, null, null,
                            archiveId, archivables, ResponseCode,
                            ResponseMessage, null);
                    ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                    return signResponse;
                }
                String[] msspCertCompos = ExtFunc.getCertificateComponents(certificate);

                if (msspCertCompos[5].compareToIgnoreCase(pkiSimInfo[2]) != 0) {
                    LOG.error("Invalid certificate. Certificate in system isn't match signer certificate");
                    ResponseMessage = Defines.ERROR_INVALIDCERTIFICATE;
                    ResponseCode = Defines.CODE_INVALIDCERTIFICATE;
                    archiveId = createArchiveId(errors,
                            (String) requestContext.get(RequestContext.TRANSACTION_ID));
                    final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                            Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                            errors, archiveId));
                    signResponse = new GenericSignResponse(
                            sReq.getRequestID(), errors, null, null,
                            archiveId, archivables, ResponseCode,
                            ResponseMessage, null);
                    ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                    return signResponse;
                }

                ResponseCode = Defines.CODE_SUCCESS;
                ResponseMessage = Defines.SUCCESS;

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                        Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                        DatatypeConverter.parseBase64Binary(signature),
                        archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        DatatypeConverter.parseBase64Binary(signature),
                        x509, null, archiveId, archivables, ResponseCode,
                        ResponseMessage);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;

            } else if (responseCode == CODE_DETAILS_MSSP_EXPR) {
                LOG.info("Transaction expired");
                ResponseMessage = Defines.MSSP_TRANSACTION_EXPIRED;
                ResponseCode = Defines.CODE_MSSP_TRANSACTION_EXPIRED;

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            } else if (responseCode == CODE_DETAILS_MSSP_NOTRANS) {
                LOG.info("No transaction found");
                ResponseMessage = Defines.MSSP_NO_TRANSACTION_FOUND;
                ResponseCode = Defines.CODE_MSSP_NO_TRANSACTION_FOUND;

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            } else if (responseCode == CODE_DETAILS_MSSP_OUTS) {
                LOG.info("Outstanding transaction");
                ResponseMessage = Defines.MSSP_OUT_TRANSACTION;
                ResponseCode = Defines.CODE_MSSP_OUT_TRANSACTION;

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            } else if (responseCode == CODE_DETAILS_MSSP_AUTH_FAILED) {
                LOG.info("WPKI auth failed");
                ResponseMessage = Defines.MSSP_AUTH_FAILED;
                ResponseCode = Defines.CODE_MSSP_AUTH_FAILED;
                // update mssp transaction
                //DBConnector.getInstances().mssp_InsertTransaction(user, channelName, pkiSim, null, null, responseMess, null);
                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            } else if (responseCode == CODE_DETAILS_MSSP_NOCERT) {
                LOG.info("Certificate hasn't been registered.");
                ResponseMessage = Defines.MSSP_NOCERTIFICATE;
                ResponseCode = Defines.CODE_MSSP_NOCERTIFICATE;

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            } else if (responseCode == CODE_DETAILS_MSSP_TRANS_CANCELED) {
                LOG.info("Transaction is canceled by user");
                ResponseMessage = Defines.MSSP_TRANSACTION_CANCELED;
                ResponseCode = Defines.CODE_MSSP_CANCELED;

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            } else {
                ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                ResponseCode = Defines.CODE_INTERNALSYSTEM;

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            }
        } else if (method.compareTo(Defines.SIGNERAP_CERTQUERY) == 0) {

            EndpointServiceResponse endpointServiceResponse = EndpointService.getInstance().requestMobileCertificate(channelName, user, pkiSim, vendor,
                    ExtFunc.generateApTransId(), endpointValue, endpointConfigId, trustedhubTransId);

            Response response = endpointServiceResponse.getResponse();

            if (response == null) {
                ResponseMessage = Defines.ERROR_ENDPOINTEXP;
                ResponseCode = Defines.CODE_ENDPOINTEXP;

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(
                        Archivable.TYPE_RESPONSE, CONTENT_TYPE,
                        errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            }

            String responseMess = response.getStatus().getResponseMesssage();
            int responseCode = response.getStatus().getResponseCode();
            if (responseCode == 0) {
                List<MSSRegistrationResp> mssRegistrationResps = response.getMssSignatureResp().getMssRegistrationResp();
                if (mssRegistrationResps.size() == 0) {
                    LOG.info("No certificate found");
                    ResponseMessage = Defines.MSSP_NOCERTIFICATE;
                    ResponseCode = Defines.CODE_MSSP_NOCERTIFICATE;

                    archiveId = createArchiveId(errors,
                            (String) requestContext.get(RequestContext.TRANSACTION_ID));
                    final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                            CONTENT_TYPE, errors, archiveId));
                    signResponse = new GenericSignResponse(sReq.getRequestID(),
                            errors, null, null, archiveId, archivables,
                            ResponseCode, ResponseMessage, null);
                    ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                    return signResponse;
                } else {
                    List<SignerInfoResponse> signerInfo = new ArrayList<SignerInfoResponse>();
                    for (MSSRegistrationResp mssRegistrationResp : mssRegistrationResps) {
                        SignerInfoResponse signerInfoResponse = new SignerInfoResponse();
                        signerInfoResponse.setCertificate(mssRegistrationResp.getBase64Certificate());
                        if (mssRegistrationResp.getCertificateUri().compareTo(SIGNATURE_PROFILE_DIGITALSIGN) == 0) {
                            signerInfoResponse.setIsSigning(true);
                        } else {
                            signerInfoResponse.setIsSigning(false);
                        }
                        signerInfo.add(signerInfoResponse);
                    }
                    archiveId = createArchiveId(errors,
                            (String) requestContext.get(RequestContext.TRANSACTION_ID));
                    final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                            CONTENT_TYPE, errors, archiveId));

                    X509Certificate x509 = null;
                    signResponse = new GenericSignResponse(sReq.getRequestID(),
                            errors, x509, null, archiveId, archivables,
                            Defines.CODE_SUCCESS, Defines.SUCCESS, signerInfo);
                    return signResponse;
                }
            } else {
                LOG.info("No certificate found");
                ResponseMessage = Defines.MSSP_NOCERTIFICATE;
                ResponseCode = Defines.CODE_MSSP_NOCERTIFICATE;

                archiveId = createArchiveId(errors,
                        (String) requestContext.get(RequestContext.TRANSACTION_ID));
                final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        CONTENT_TYPE, errors, archiveId));
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        errors, null, null, archiveId, archivables,
                        ResponseCode, ResponseMessage, null);
                ((GenericSignResponse) signResponse).setEndpointId(endpointServiceResponse.getEndpointId());
                return signResponse;
            }

        } else {
            LOG.info("Invalid SignerAP Method");
            ResponseMessage = Defines.ERROR_INVALIDPARAMETER;
            ResponseCode = Defines.CODE_INVALIDPARAMETER;
            archiveId = createArchiveId(errors,
                    (String) requestContext.get(RequestContext.TRANSACTION_ID));
            final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE,
                    CONTENT_TYPE, errors, archiveId));
            signResponse = new GenericSignResponse(sReq.getRequestID(), errors,
                    null, null, archiveId, archivables, ResponseCode,
                    ResponseMessage, null);
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

    private String getTransactionId(String mobileNo) {
        String epochTime = String.valueOf(System.nanoTime());
        String transId = "";
        try {
            transId = epochTime.substring(epochTime.length() - 6);
        } catch (Exception e) {
            LOG.error("Something wrong: " + e.getMessage());
        }
        return transId;
    }

    private String hex2decimal(String s) {
        String digits = "0123456789ABCDEF";
        String rv = "";
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            int a = (int) c;
            rv += String.valueOf(a);
        }
        return rv;
    }
}