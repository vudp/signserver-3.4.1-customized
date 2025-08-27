package org.signserver.clientws;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.*;

import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebService;
import javax.naming.NamingException;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;
import javax.jws.HandlerChain;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.*;
import org.signserver.common.dbdao.*;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.CertificateClientCredential;
import org.signserver.server.IClientCredential;
import org.signserver.server.UsernamePasswordClientCredential;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;

import java.io.*;

import org.signserver.clientws.*;
import org.signserver.common.*;
import org.signserver.common.util.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.tomicalab.cag360.license.*;

import javax.xml.ws.handler.soap.SOAPMessageContext;

import java.util.Map;

import vn.mobile_id.endpoint.service.datatype.*;
import vn.mobile_id.endpoint.service.datatype.params.*;
import vn.mobile_id.endpoint.client.*;

import com.fasterxml.jackson.databind.ObjectMapper;

public class ProcessValidator {

    private static final Logger LOG = Logger.getLogger(ProcessValidator.class);
    private final Random random = new Random();
    private static final String HTTP_AUTH_BASIC_AUTHORIZATION = "Authorization";
    private WebServiceContext wsContext;
    private IWorkerSession.ILocal workersession;

    public ProcessValidator(WebServiceContext wsContext,
            IWorkerSession.ILocal workersession) {
        this.wsContext = wsContext;
        this.workersession = workersession;
    }

    public ProcessValidatorResp processData(TransactionInfo transInfo, int trustedHubTransId, int agreementStatus, String billCode) {
        String workerIdOrName = "";
        String functionName = "";
        String sslSubDn = "";
        String sslIseDn = "";
        String sslSnb = "";
        String unsignedData = "";
        String signedData = "";

        String xmlData = transInfo.getXmlData();
        CAGCredential cagCredential = transInfo.getCredentialData();
        byte[] byteData = transInfo.getFileData();

        if (transInfo.getBase64FileData() != null) {
            byteData = DatatypeConverter.parseBase64Binary(transInfo.getBase64FileData());
        }

        String username = cagCredential.getUsername();
        String channelName = ExtFunc.getContent(Defines._CHANNEL, xmlData);
        String user = ExtFunc.getContent(Defines._USER, xmlData);
        String idTag = ExtFunc.getContent(Defines._ID, xmlData);
        String method = ExtFunc.getContent(Defines._METHOD, xmlData);
        String signatureMethod = ExtFunc.getContent(Defines._SIGNATUREMETHOD, xmlData);

        functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
        workerIdOrName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
        boolean checkPKISate = false;
        // Ko check agreement neu la GENERALVALIDATOR
        if (workerIdOrName.compareTo(Defines.WORKER_GENERALVALIDATOR) != 0
                && !ExtFunc.isNullOrEmpty(signatureMethod)) {
            checkPKISate = true;
            if (agreementStatus == 1) {

                String pData = ExtFunc.genResponseMessage(Defines.CODE_AGREEMENTNOTEXITS,
                        Defines.ERROR_AGREEMENTNOTEXITS, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_AGREEMENTNOTEXITS);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            } else if (agreementStatus == 4 || agreementStatus == 2
                    || agreementStatus == 3 || agreementStatus == 6
                    || agreementStatus == 7) {

                String pData = ExtFunc.genResponseMessage(Defines.CODE_CONTRACTSTATUS,
                        Defines.ERROR_CONTRACTSTATUS, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_CONTRACTSTATUS);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            } else if (agreementStatus == 5) {

                String pData = ExtFunc.genResponseMessage(Defines.CODE_AGREEMENTEXPIRED,
                        Defines.ERROR_AGREEMENTEXPIRED, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_AGREEMENTEXPIRED);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            }
        }


        ProcessValidatorResp resp = null;

        if (functionName.compareTo(Defines.WORKER_PDFVALIDATOR) == 0) {
            resp = validatePdf(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (functionName.compareTo(Defines.WORKER_OFFICEVALIDATOR) == 0) {
            resp = validateOffice(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (functionName.compareTo(Defines.WORKER_XMLVALIDATOR) == 0) {
            resp = validateXml(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (functionName.compareTo(Defines.WORKER_CAPICOMVALIDATOR) == 0) {
            resp = validateCapicom(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (functionName.compareTo(Defines.WORKER_PKCS1VALIDATOR) == 0) {
            resp = validatePkcs1(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (functionName.compareTo(Defines.WORKER_OATHVALIDATOR) == 0) {
            resp = validateOtpToken(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (functionName.compareTo(Defines.WORKER_OATHSYNC) == 0) {
            resp = syncOtpToken(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (functionName.compareTo(Defines.WORKER_OATHUNLOCK) == 0) {
            resp = unlockOtpToken(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (functionName.compareTo(Defines.WORKER_OATHREQUEST) == 0) {
            resp = requestOtp(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (functionName.compareTo(Defines.WORKER_OATHRESPONSE) == 0) {
            resp = responseOtp(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (functionName.compareTo(Defines.WORKER_MULTIVALIDATOR) == 0) {
            resp = validateMultiType(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (functionName.compareTo(Defines.WORKER_SIGNATUREVALIDATOR) == 0) {
            resp = validateSignature(transInfo, trustedHubTransId, billCode, checkPKISate);
            return resp;
        } else if (functionName.compareTo(Defines.WORKER_GENERALVALIDATOR) == 0) {
            resp = generalValidation(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (functionName.compareTo(Defines.WORKER_U2FVALIDATOR) == 0) {
            resp = processU2FValidator(transInfo, trustedHubTransId, billCode);
            return resp;
        } else {
            // Invalid action

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                    Defines.ERROR_NOWORKER, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOWORKER);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }
    }

    private ProcessValidatorResp validateSignature(
            TransactionInfo transInfo,
            int trustedHubTransId,
            String billCode,
            boolean checkPKIState) {
        String workerIdOrName = "";
        String functionName = "";
        String sslSubDn = "";
        String sslIseDn = "";
        String sslSnb = "";
        String unsignedData = "";
        String signedData = "";

        String xmlData = transInfo.getXmlData();
        CAGCredential cagCredential = transInfo.getCredentialData();
        byte[] byteData = transInfo.getFileData();

        if (transInfo.getBase64FileData() != null) {
            byteData = DatatypeConverter.parseBase64Binary(transInfo.getBase64FileData());
        }

        String username = cagCredential.getUsername();
        String channelName = ExtFunc.getContent(Defines._CHANNEL, xmlData);
        String user = ExtFunc.getContent(Defines._USER, xmlData);
        String idTag = ExtFunc.getContent(Defines._ID, xmlData);
        String metaData = ExtFunc.getContent(Defines._METADATA, xmlData);

        functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
        workerIdOrName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);

        String signatureMethod = ExtFunc.getContent(Defines._SIGNATUREMETHOD, xmlData);
        if (signatureMethod == null) {
            signatureMethod = "";
        }
        if (checkPKIState) {
            int hwPkiCheck = DBConnector.getInstances().checkHWPKI(channelName, user);
            if (hwPkiCheck == 1 || hwPkiCheck == 2) {

                String pData = ExtFunc.genResponseMessage(Defines.CODE_PKILOCKED,
                        Defines.ERROR_PKILOCKED, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_PKILOCKED);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            } else if (hwPkiCheck == -1) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                        Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);
                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            }
        }
        String signature = ExtFunc.getContent(Defines._SIGNATURE, xmlData);
        unsignedData = ExtFunc.getContent(Defines._SIGNEDDATA, xmlData);
        signedData = signature;

        if (unsignedData.equals("")) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                    Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(signedData);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (signature.equals("")) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOCAPICOMSIGNATURE,
                    Defines.ERROR_NOCAPICOMSIGNATURE, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOCAPICOMSIGNATURE);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(signedData);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }
        byteData = Base64.decode(signature);

        if (byteData == null) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                    Defines.ERROR_NOBASE64FILE, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOBASE64FILE);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(signedData);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }



        String[] pkiInformation;
        String serialNumber = ExtFunc.getContent(Defines._SERIALNUMBER, xmlData);
        String certificate = null;

        if (signatureMethod.compareTo(Defines.SIGNATURE_METHOD_WPKI) == 0) {
            pkiInformation = DBConnector.getInstances().authGetPhoneNoSimPKI(channelName, user);
            if (ExtFunc.isNullOrEmpty(serialNumber)) {
                serialNumber = ExtFunc.getCertificateComponents(pkiInformation[1])[0];
            }
        } else if (signatureMethod.compareTo(Defines.SIGNATURE_METHOD_LPKI) == 0) {
            pkiInformation = DBConnector.getInstances().authGetCertificateLPKI(channelName, user);
            if (ExtFunc.isNullOrEmpty(serialNumber)) {
                serialNumber = ExtFunc.getCertificateComponents(pkiInformation[0])[0];
            }
            certificate = pkiInformation[0];
        } else if (signatureMethod.compareTo(Defines.SIGNATURE_METHOD_TPKI) == 0) {
            pkiInformation = DBConnector.getInstances().authGetCertificateTPKI(channelName, user);
            if (ExtFunc.isNullOrEmpty(serialNumber)) {
                serialNumber = ExtFunc.getCertificateComponents(pkiInformation[0])[0];
            }
        } else if (signatureMethod.compareTo(Defines.SIGNATURE_METHOD_SPKI) == 0) {
            pkiInformation = DBConnector.getInstances().authCertificateSPKI(channelName, user);
            if (pkiInformation == null) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_CONTRACTSTATUS,
                        Defines.ERROR_CONTRACTSTATUS, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_CONTRACTSTATUS);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(signedData);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            }

            if (pkiInformation[0] == null) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_CONTRACTSTATUS,
                        Defines.ERROR_CONTRACTSTATUS, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_CONTRACTSTATUS);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(signedData);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            }
            if (ExtFunc.isNullOrEmpty(serialNumber)) {
                serialNumber = ExtFunc.getCertificateComponents(pkiInformation[0])[0];
            }
        } else {
        }

        List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();
        if (!metaData.equals("")) {
            requestMetadata = getMetaData(metaData);
        }

        org.signserver.clientws.Metadata channelNameOTP = new org.signserver.clientws.Metadata(
                Defines._CHANNEL, channelName);

        org.signserver.clientws.Metadata userOTP = new org.signserver.clientws.Metadata(
                Defines._USER, user);

        org.signserver.clientws.Metadata meta_serialCertificate = new org.signserver.clientws.Metadata(
                Defines._SERIALNUMBER, serialNumber);

        org.signserver.clientws.Metadata meta_certificate = new org.signserver.clientws.Metadata(
                Defines._CERTIFICATE, certificate);

        org.signserver.clientws.Metadata trustedhub_trans_id = new org.signserver.clientws.Metadata(Defines._TRUSTEDHUBTRANSID, String.valueOf(trustedHubTransId));

        requestMetadata.add(channelNameOTP);
        requestMetadata.add(userOTP);
        requestMetadata.add(meta_serialCertificate);
        requestMetadata.add(meta_certificate);
        requestMetadata.add(trustedhub_trans_id);

        final int requestId = random.nextInt();
        final int workerId = getWorkerId(functionName);

        if (workerId < 1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                    Defines.ERROR_NOWORKER, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOWORKER);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(signedData);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        final RequestContext requestContext = handleRequestContext(
                requestMetadata, workerId);

        final ProcessRequest req = new GenericSignRequest(requestId, byteData);
        ProcessResponse resp = null;
        try {
            resp = getWorkerSession().process(workerId, req, requestContext);
        } catch (Exception e) {
            LOG.error("Something wrong: " + e.getMessage());
            e.printStackTrace();
            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(signedData);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (!(resp instanceof GenericSignResponse)) {
            LOG.error("resp is not a instance of GenericSignResponse");

            String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                    Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(signedData);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        } else {
            final GenericSignResponse signResponse = (GenericSignResponse) resp;
            if (signResponse.getRequestID() != requestId) {
                LOG.error("Response ID " + signResponse.getRequestID()
                        + " not matching request ID " + requestId);

                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                        Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_NOTMATCHID);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(signedData);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;

            }

            int responseCode = signResponse.getResponseCode();
            String responseMessage = signResponse.getResponseMessage();

            List<SignerInfoResponse> signInfo = signResponse.getSignerInfoResponse();

            if (responseCode == Defines.CODE_SUCCESS) {

                if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                    DBConnector.getInstances().increaseSuccessTransaction();
                }

                DBConnector.getInstances().resetErrorCounterHWPKI(channelName, user);
                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, signInfo, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(responseCode);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(signedData);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            } else if (responseCode == Defines.CODE_INVALIDSIGNATURE) {
                int pkiCheck = DBConnector.getInstances().leftRetryHWPKI(
                        channelName, user);
                if (pkiCheck == -100) {

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_PKILOCKED,
                            Defines.ERROR_PKILOCKED, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(Defines.CODE_PKILOCKED);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(signedData);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                }

                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, pkiCheck, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(responseCode);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(signedData);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;

            } else {
                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(responseCode);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(signedData);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            }
        }
    }

    private ProcessValidatorResp generalValidation(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
        String workerIdOrName = "";
        String functionName = "";
        String sslSubDn = "";
        String sslIseDn = "";
        String sslSnb = "";
        String unsignedData = null;
        String signedData = null;

        String xmlData = transInfo.getXmlData();
        CAGCredential cagCredential = transInfo.getCredentialData();
        byte[] byteData = transInfo.getFileData();

        if (transInfo.getBase64FileData() != null) {
            byteData = DatatypeConverter.parseBase64Binary(transInfo.getBase64FileData());
        }

        String username = cagCredential.getUsername();
        String channelName = ExtFunc.getContent(Defines._CHANNEL, xmlData);
        String user = (ExtFunc.getContent(Defines._USER, xmlData).compareTo("") == 0) ? cagCredential.getUsername()
                : ExtFunc.getContent(Defines._USER, xmlData);
        String idTag = ExtFunc.getContent(Defines._ID, xmlData);
        String metaData = ExtFunc.getContent(Defines._METADATA, xmlData);

        functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
        workerIdOrName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);

        String externalStorage = ExtFunc.getContent(Defines._EXTERNALSTORAGE, xmlData);
        String signatureMethod = ExtFunc.getContent(Defines._SIGNATUREMETHOD, xmlData);
        String fileId = ExtFunc.getContent(Defines._FILEID, xmlData);
        String fileType = ExtFunc.getContent(Defines._FILETYPE, xmlData);

        List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();
        if (!metaData.equals("")) {
            requestMetadata = getMetaData(metaData);
        }

        org.signserver.clientws.Metadata fileExtension = new org.signserver.clientws.Metadata(
                Defines._FILETYPE, fileType);

        org.signserver.clientws.Metadata channelNameOTP = new org.signserver.clientws.Metadata(
                Defines._CHANNEL, channelName);

        org.signserver.clientws.Metadata userMetadata = new org.signserver.clientws.Metadata(
                Defines._USER, user);

        org.signserver.clientws.Metadata trustedhub_trans_id = new org.signserver.clientws.Metadata(Defines._TRUSTEDHUBTRANSID, String.valueOf(trustedHubTransId));

        requestMetadata.add(channelNameOTP);
        requestMetadata.add(userMetadata);
        requestMetadata.add(fileExtension);
        requestMetadata.add(trustedhub_trans_id);

        if (externalStorage.compareTo("") != 0
                && externalStorage.compareTo(Defines.EXTERNAL_STORAGE_LOCAL) != 0) {

            String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(externalStorage);

            if (endpointParams == null) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                        Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            }

            if (fileId.compareTo("") == 0) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                        Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            } else {
                List<FileDetail> fileDetails = new ArrayList<FileDetail>();

                EndpointServiceResponse endpointServiceResponse = EndpointService.getInstance().getMultiRemoteFile(channelName, user,
                        externalStorage, endpointParams[1], fileId, Integer.parseInt(endpointParams[2]), trustedHubTransId);

                Response response = endpointServiceResponse.getResponse();
                if (response != null) {
                    if (response.getStatus().getResponseCode() == 0) {

                        List<FileParams> arrayOfFileParamsResp = response.getRemoteFileResp().getArrayOfFileParams();

                        for (int i = 0; i < arrayOfFileParamsResp.size(); i++) {
                            FileDetail fileDetail = new FileDetail();
                            fileDetail.setFileId(arrayOfFileParamsResp.get(i).getFileId());
                            fileDetail.setMimeType(arrayOfFileParamsResp.get(i).getMimeType());

                            byteData = arrayOfFileParamsResp.get(i).getFileData();
                            fileType = arrayOfFileParamsResp.get(i).getFileType();

                            if (byteData == null) {
                                fileDetail.setStatus(1);
                                fileDetail.setMessage(Defines.ERROR_NOBASE64FILE);
                                fileDetails.add(fileDetail);
                                continue;
                            }

                            if (fileType.equals("")) {
                                fileDetail.setStatus(1);
                                fileDetail.setMessage(Defines.ERROR_INVALIDFILETYPE);
                                fileDetails.add(fileDetail);
                                continue;
                            }

                            // add into metadata
                            fileExtension = new org.signserver.clientws.Metadata(Defines._FILETYPE, fileType);
                            requestMetadata.add(fileExtension);

                            final int requestId = random.nextInt();
                            final int workerId = getWorkerId(workerIdOrName);

                            if (workerId < 1) {
                                fileDetail.setStatus(1);
                                fileDetail.setMessage(Defines.ERROR_NOWORKER);
                                fileDetails.add(fileDetail);
                                continue;
                            }

                            final RequestContext requestContext = handleRequestContext(
                                    requestMetadata, workerId);

                            final ProcessRequest req = new GenericSignRequest(requestId, byteData);
                            ProcessResponse resp = null;
                            try {
                                resp = getWorkerSession().process(workerId, req, requestContext);
                            } catch (Exception e) {
                                LOG.error("Something wrong: " + e.getMessage());
                                e.printStackTrace();
                                fileDetail.setStatus(1);
                                fileDetail.setMessage(Defines.ERROR_INTERNALSYSTEM);
                                fileDetails.add(fileDetail);
                                continue;
                            }

                            if (!(resp instanceof GenericSignResponse)) {
                                LOG.error("resp is not a instance of GenericSignResponse");
                                fileDetail.setStatus(1);
                                fileDetail.setMessage(Defines.ERROR_UNEXPECTEDRETURNTYPE);
                                fileDetails.add(fileDetail);
                                continue;
                            } else {
                                final GenericSignResponse signResponse = (GenericSignResponse) resp;
                                if (signResponse.getRequestID() != requestId) {
                                    LOG.error("Response ID " + signResponse.getRequestID()
                                            + " not matching request ID " + requestId);
                                    fileDetail.setStatus(1);
                                    fileDetail.setMessage(Defines.ERROR_NOTMATCHID);
                                    fileDetails.add(fileDetail);
                                    continue;
                                }
                                int responseCode = signResponse.getResponseCode();
                                String responseMessage = signResponse.getResponseMessage();

                                if (responseCode == Defines.CODE_SUCCESS) {

                                    if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                                        DBConnector.getInstances().increaseSuccessTransaction();
                                    }

                                    //DBConnector.getInstances().resetErrorCounterHWPKI(channelName, user);
                                    List<SignerInfoResponse> signInfo = signResponse.getSignerInfoResponse();

                                    fileDetail.setStatus(0);
                                    fileDetail.setMessage(Defines.SUCCESS);
                                    fileDetail.setSignerInfoResponse(signInfo);
                                    fileDetails.add(fileDetail);
                                    continue;

                                } else if (responseCode == Defines.CODE_INVALIDSIGNATURE) {
                                    fileDetail.setStatus(1);
                                    fileDetail.setMessage(responseMessage);
                                    fileDetails.add(fileDetail);
                                    continue;

                                } else {
                                    fileDetail.setStatus(1);
                                    fileDetail.setMessage(responseMessage);
                                    fileDetails.add(fileDetail);
                                    continue;
                                }
                            }
                        } // end for loop
                        String pData = ExtFunc.genFileDetailsValidatorResponseMessage(Defines.CODE_SUCCESS,
                                Defines.SUCCESS, channelName, user, billCode, fileDetails);

                        ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                        processValidatorResp.setResponseCode(Defines.CODE_SUCCESS);
                        processValidatorResp.setXmlData(pData);
                        processValidatorResp.setSignedData(null);
                        processValidatorResp.setPreTrustedHubTransId(null);
                        return processValidatorResp;

                    } else {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_EXTERNAL_FILE_GET,
                                Defines.ERROR_EXTERNAL_FILE_GET, channelName, user, billCode);

                        ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                        processValidatorResp.setResponseCode(Defines.CODE_EXTERNAL_FILE_GET);
                        processValidatorResp.setXmlData(pData);
                        processValidatorResp.setSignedData(null);
                        processValidatorResp.setPreTrustedHubTransId(null);
                        return processValidatorResp;
                    }
                } else {

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_EXTERNAL_FILE_GET,
                            Defines.ERROR_EXTERNAL_FILE_GET, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(Defines.CODE_EXTERNAL_FILE_GET);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                }
            }
        } else {
            // P2P
            if (externalStorage.compareTo(Defines.EXTERNAL_STORAGE_LOCAL) != 0) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                        Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            }

            final int requestId = random.nextInt();
            final int workerId = getWorkerId(functionName);

            if (workerId < 1) {

                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                        Defines.ERROR_NOWORKER, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_NOWORKER);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            }

            if (byteData == null) {

                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                        Defines.ERROR_NOBASE64FILE, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_NOBASE64FILE);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            }

            if (ExtFunc.checkFileType(byteData, fileType).compareTo(ExtFunc.C_FILETYPE_PDF) != 0
                    && ExtFunc.checkFileType(byteData, fileType).compareTo(ExtFunc.C_FILETYPE_OFFICE) != 0) {
                signedData = new String(byteData);
            }

            final RequestContext requestContext = handleRequestContext(
                    requestMetadata, workerId);

            final ProcessRequest req = new GenericSignRequest(requestId, byteData);
            ProcessResponse resp = null;
            try {
                resp = getWorkerSession().process(workerId, req, requestContext);
            } catch (Exception e) {
                LOG.error("Something wrong: " + e.getMessage());
                e.printStackTrace();

                String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                        Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(signedData);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            }

            if (!(resp instanceof GenericSignResponse)) {
                LOG.error("resp is not a instance of GenericSignResponse");

                String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                        Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(signedData);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            } else {
                final GenericSignResponse signResponse = (GenericSignResponse) resp;
                if (signResponse.getRequestID() != requestId) {
                    LOG.error("Response ID " + signResponse.getRequestID()
                            + " not matching request ID " + requestId);

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                            Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(Defines.CODE_NOTMATCHID);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(signedData);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;

                }

                int responseCode = signResponse.getResponseCode();
                String responseMessage = signResponse.getResponseMessage();

                if (responseCode == Defines.CODE_SUCCESS) {

                    if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                        DBConnector.getInstances().increaseSuccessTransaction();
                    }

                    //DBConnector.getInstances().resetErrorCounterHWPKI(channelName, user);
                    List<SignerInfoResponse> signInfo = signResponse.getSignerInfoResponse();

                    String pData = ExtFunc.genResponseMessage(responseCode,
                            responseMessage, channelName, user, signInfo, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(responseCode);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(signedData);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;

                } else if (responseCode == Defines.CODE_INVALIDSIGNATURE) {

                    String pData = ExtFunc.genResponseMessage(responseCode,
                            responseMessage, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(responseCode);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(signedData);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                } else {

                    String pData = ExtFunc.genResponseMessage(responseCode,
                            responseMessage, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(responseCode);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(signedData);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                }
            }
        }
    }

    private ProcessValidatorResp validateMultiType(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
        String workerIdOrName = "";
        String functionName = "";
        String sslSubDn = "";
        String sslIseDn = "";
        String sslSnb = "";
        String unsignedData = null;
        String signedData = null;

        String xmlData = transInfo.getXmlData();
        CAGCredential cagCredential = transInfo.getCredentialData();
        byte[] byteData = transInfo.getFileData();

        if (transInfo.getBase64FileData() != null) {
            byteData = DatatypeConverter.parseBase64Binary(transInfo.getBase64FileData());
        }

        String username = cagCredential.getUsername();
        String channelName = ExtFunc.getContent(Defines._CHANNEL, xmlData);
        String user = ExtFunc.getContent(Defines._USER, xmlData);
        String idTag = ExtFunc.getContent(Defines._ID, xmlData);
        String metaData = ExtFunc.getContent(Defines._METADATA, xmlData);

        functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
        workerIdOrName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);

        String externalStorage = ExtFunc.getContent(Defines._EXTERNALSTORAGE, xmlData);
        String signatureMethod = ExtFunc.getContent(Defines._SIGNATUREMETHOD, xmlData);
        String fileId = ExtFunc.getContent(Defines._FILEID, xmlData);
        String fileType = ExtFunc.getContent(Defines._FILETYPE, xmlData);

        int hwPkiCheck = DBConnector.getInstances().checkHWPKI(channelName,
                user);

        if (hwPkiCheck == 1 || hwPkiCheck == 2) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_PKILOCKED,
                    Defines.ERROR_PKILOCKED, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_PKILOCKED);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        } else if (hwPkiCheck == -1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        String[] pkiInformation;
        String serialNumber = ExtFunc.getContent(Defines._SERIALNUMBER, xmlData);;

        if (signatureMethod.compareTo(Defines.SIGNATURE_METHOD_WPKI) == 0) {
            pkiInformation = DBConnector.getInstances().authGetPhoneNoSimPKI(channelName, user);
            if (ExtFunc.isNullOrEmpty(serialNumber)) {
                serialNumber = ExtFunc.getCertificateComponents(pkiInformation[1])[0];
            }
        } else if (signatureMethod.compareTo(Defines.SIGNATURE_METHOD_LPKI) == 0) {
            pkiInformation = DBConnector.getInstances().authGetCertificateLPKI(channelName, user);
            if (ExtFunc.isNullOrEmpty(serialNumber)) {
                serialNumber = ExtFunc.getCertificateComponents(pkiInformation[0])[0];
            }
        } else if (signatureMethod.compareTo(Defines.SIGNATURE_METHOD_TPKI) == 0) {
            pkiInformation = DBConnector.getInstances().authGetCertificateTPKI(channelName, user);
            if (ExtFunc.isNullOrEmpty(serialNumber)) {
                serialNumber = ExtFunc.getCertificateComponents(pkiInformation[0])[0];
            }
        } else {
            pkiInformation = DBConnector.getInstances().authCertificateSPKI(channelName, user);
            if (pkiInformation == null) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_CONTRACTSTATUS,
                        Defines.ERROR_CONTRACTSTATUS, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_CONTRACTSTATUS);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            }

            if (pkiInformation[0] == null) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_CONTRACTSTATUS,
                        Defines.ERROR_CONTRACTSTATUS, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_CONTRACTSTATUS);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            }
            if (ExtFunc.isNullOrEmpty(serialNumber)) {
                serialNumber = ExtFunc.getCertificateComponents(pkiInformation[0])[0];
            }
        }

        List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();
        if (!metaData.equals("")) {
            requestMetadata = getMetaData(metaData);
        }

        org.signserver.clientws.Metadata fileExtension = new org.signserver.clientws.Metadata(
                Defines._FILETYPE, fileType);

        org.signserver.clientws.Metadata channelNameOTP = new org.signserver.clientws.Metadata(
                Defines._CHANNEL, channelName);

        org.signserver.clientws.Metadata userOTP = new org.signserver.clientws.Metadata(
                Defines._USER, user);

        org.signserver.clientws.Metadata meta_serialCertificate = new org.signserver.clientws.Metadata(
                Defines._SERIALNUMBER, serialNumber);

        org.signserver.clientws.Metadata trustedhub_trans_id = new org.signserver.clientws.Metadata(Defines._TRUSTEDHUBTRANSID, String.valueOf(trustedHubTransId));

        requestMetadata.add(channelNameOTP);
        requestMetadata.add(userOTP);
        requestMetadata.add(fileExtension);
        requestMetadata.add(meta_serialCertificate);
        requestMetadata.add(trustedhub_trans_id);

        if (externalStorage.compareTo("") != 0
                && externalStorage.compareTo(Defines.EXTERNAL_STORAGE_LOCAL) != 0) {

            String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(externalStorage);

            if (endpointParams == null) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                        Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            }

            if (fileId.compareTo("") == 0) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                        Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            } else {
                List<FileDetail> fileDetails = new ArrayList<FileDetail>();

                EndpointServiceResponse endpointServiceResponse = EndpointService.getInstance().getMultiRemoteFile(channelName, user,
                        externalStorage, endpointParams[1], fileId, Integer.parseInt(endpointParams[2]), trustedHubTransId);

                Response response = endpointServiceResponse.getResponse();
                if (response != null) {
                    if (response.getStatus().getResponseCode() == 0) {

                        List<FileParams> arrayOfFileParamsResp = response.getRemoteFileResp().getArrayOfFileParams();

                        for (int i = 0; i < arrayOfFileParamsResp.size(); i++) {
                            FileDetail fileDetail = new FileDetail();
                            fileDetail.setFileId(arrayOfFileParamsResp.get(i).getFileId());
                            fileDetail.setMimeType(arrayOfFileParamsResp.get(i).getMimeType());

                            byteData = arrayOfFileParamsResp.get(i).getFileData();
                            fileType = arrayOfFileParamsResp.get(i).getFileType();

                            if (byteData == null) {
                                fileDetail.setStatus(1);
                                fileDetail.setMessage(Defines.ERROR_NOBASE64FILE);
                                fileDetails.add(fileDetail);
                                continue;
                            }

                            if (fileType.equals("")) {
                                fileDetail.setStatus(1);
                                fileDetail.setMessage(Defines.ERROR_INVALIDFILETYPE);
                                fileDetails.add(fileDetail);
                                continue;
                            }

                            // add into metadata
                            fileExtension = new org.signserver.clientws.Metadata(Defines._FILETYPE, fileType);
                            requestMetadata.add(fileExtension);

                            final int requestId = random.nextInt();
                            final int workerId = getWorkerId(workerIdOrName);

                            if (workerId < 1) {
                                fileDetail.setStatus(1);
                                fileDetail.setMessage(Defines.ERROR_NOWORKER);
                                fileDetails.add(fileDetail);
                                continue;
                            }

                            final RequestContext requestContext = handleRequestContext(
                                    requestMetadata, workerId);

                            final ProcessRequest req = new GenericSignRequest(requestId, byteData);
                            ProcessResponse resp = null;
                            try {
                                resp = getWorkerSession().process(workerId, req, requestContext);
                            } catch (Exception e) {
                                LOG.error("Something wrong: " + e.getMessage());
                                e.printStackTrace();
                                fileDetail.setStatus(1);
                                fileDetail.setMessage(Defines.ERROR_INTERNALSYSTEM);
                                fileDetails.add(fileDetail);
                                continue;
                            }

                            if (!(resp instanceof GenericSignResponse)) {
                                LOG.error("resp is not a instance of GenericSignResponse");
                                fileDetail.setStatus(1);
                                fileDetail.setMessage(Defines.ERROR_UNEXPECTEDRETURNTYPE);
                                fileDetails.add(fileDetail);
                                continue;
                            } else {
                                final GenericSignResponse signResponse = (GenericSignResponse) resp;
                                if (signResponse.getRequestID() != requestId) {
                                    LOG.error("Response ID " + signResponse.getRequestID()
                                            + " not matching request ID " + requestId);
                                    fileDetail.setStatus(1);
                                    fileDetail.setMessage(Defines.ERROR_NOTMATCHID);
                                    fileDetails.add(fileDetail);
                                    continue;
                                }
                                int responseCode = signResponse.getResponseCode();
                                String responseMessage = signResponse.getResponseMessage();

                                if (responseCode == Defines.CODE_SUCCESS) {

                                    if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                                        DBConnector.getInstances().increaseSuccessTransaction();
                                    }

                                    DBConnector.getInstances().resetErrorCounterHWPKI(channelName, user);
                                    List<SignerInfoResponse> signInfo = signResponse.getSignerInfoResponse();

                                    fileDetail.setStatus(0);
                                    fileDetail.setMessage(Defines.SUCCESS);
                                    fileDetail.setSignerInfoResponse(signInfo);
                                    fileDetails.add(fileDetail);
                                    continue;

                                } else if (responseCode == Defines.CODE_INVALIDSIGNATURE) {

                                    int pkiCheck = DBConnector.getInstances().leftRetryHWPKI(
                                            channelName, user);

                                    if (pkiCheck == -100) {
                                        fileDetail.setStatus(1);
                                        fileDetail.setMessage(Defines.ERROR_PKILOCKED);
                                        fileDetails.add(fileDetail);
                                        continue;
                                    }

                                    fileDetail.setStatus(1);
                                    fileDetail.setMessage(responseMessage);
                                    fileDetails.add(fileDetail);
                                    continue;

                                } else {
                                    fileDetail.setStatus(1);
                                    fileDetail.setMessage(responseMessage);
                                    fileDetails.add(fileDetail);
                                    continue;
                                }
                            }
                        } // end for loop
                        String pData = ExtFunc.genFileDetailsValidatorResponseMessage(Defines.CODE_SUCCESS,
                                Defines.SUCCESS, channelName, user, billCode, fileDetails);

                        ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                        processValidatorResp.setResponseCode(Defines.CODE_SUCCESS);
                        processValidatorResp.setXmlData(pData);
                        processValidatorResp.setSignedData(null);
                        processValidatorResp.setPreTrustedHubTransId(null);
                        return processValidatorResp;

                    } else {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_EXTERNAL_FILE_GET,
                                Defines.ERROR_EXTERNAL_FILE_GET, channelName, user, billCode);

                        ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                        processValidatorResp.setResponseCode(Defines.CODE_EXTERNAL_FILE_GET);
                        processValidatorResp.setXmlData(pData);
                        processValidatorResp.setSignedData(null);
                        processValidatorResp.setPreTrustedHubTransId(null);
                        return processValidatorResp;
                    }
                } else {

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_EXTERNAL_FILE_GET,
                            Defines.ERROR_EXTERNAL_FILE_GET, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(Defines.CODE_EXTERNAL_FILE_GET);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                }
            }
        } else {
            // P2P
            if (externalStorage.compareTo(Defines.EXTERNAL_STORAGE_LOCAL) != 0) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                        Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            }

            final int requestId = random.nextInt();
            final int workerId = getWorkerId(functionName);

            if (workerId < 1) {

                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                        Defines.ERROR_NOWORKER, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_NOWORKER);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            }

            if (byteData == null) {

                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                        Defines.ERROR_NOBASE64FILE, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_NOBASE64FILE);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            }

            if (ExtFunc.checkFileType(byteData, fileType).compareTo(ExtFunc.C_FILETYPE_PDF) != 0
                    && ExtFunc.checkFileType(byteData, fileType).compareTo(ExtFunc.C_FILETYPE_OFFICE) != 0) {
                signedData = new String(byteData);
            }

            final RequestContext requestContext = handleRequestContext(
                    requestMetadata, workerId);

            final ProcessRequest req = new GenericSignRequest(requestId, byteData);
            ProcessResponse resp = null;
            try {
                resp = getWorkerSession().process(workerId, req, requestContext);
            } catch (Exception e) {
                LOG.error("Something wrong: " + e.getMessage());
                e.printStackTrace();

                String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                        Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(signedData);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            }

            if (!(resp instanceof GenericSignResponse)) {
                LOG.error("resp is not a instance of GenericSignResponse");

                String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                        Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(signedData);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            } else {
                final GenericSignResponse signResponse = (GenericSignResponse) resp;
                if (signResponse.getRequestID() != requestId) {
                    LOG.error("Response ID " + signResponse.getRequestID()
                            + " not matching request ID " + requestId);

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                            Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(Defines.CODE_NOTMATCHID);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(signedData);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;

                }

                int responseCode = signResponse.getResponseCode();
                String responseMessage = signResponse.getResponseMessage();

                if (responseCode == Defines.CODE_SUCCESS) {

                    if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                        DBConnector.getInstances().increaseSuccessTransaction();
                    }

                    DBConnector.getInstances().resetErrorCounterHWPKI(channelName,
                            user);
                    List<SignerInfoResponse> signInfo = signResponse.getSignerInfoResponse();

                    String pData = ExtFunc.genResponseMessage(responseCode,
                            responseMessage, channelName, user, signInfo, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(responseCode);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(signedData);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                } else if (responseCode == Defines.CODE_INVALIDSIGNATURE) {

                    int pkiCheck = DBConnector.getInstances().leftRetryHWPKI(
                            channelName, user);
                    if (pkiCheck == -100) {

                        String pData = ExtFunc.genResponseMessage(Defines.CODE_PKILOCKED,
                                Defines.ERROR_PKILOCKED, channelName, user, billCode);

                        ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                        processValidatorResp.setResponseCode(Defines.CODE_PKILOCKED);
                        processValidatorResp.setXmlData(pData);
                        processValidatorResp.setSignedData(signedData);
                        processValidatorResp.setPreTrustedHubTransId(null);
                        return processValidatorResp;
                    }

                    String pData = ExtFunc.genResponseMessage(responseCode,
                            responseMessage, channelName, user, pkiCheck, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(responseCode);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(signedData);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                } else {

                    String pData = ExtFunc.genResponseMessage(responseCode,
                            responseMessage, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(responseCode);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(signedData);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                }
            }
        }
    }

    private ProcessValidatorResp validatePdf(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
        String workerIdOrName = "";
        String functionName = "";
        String sslSubDn = "";
        String sslIseDn = "";
        String sslSnb = "";
        String unsignedData = "";
        String signedData = "";

        String xmlData = transInfo.getXmlData();
        CAGCredential cagCredential = transInfo.getCredentialData();
        byte[] byteData = transInfo.getFileData();

        if (transInfo.getBase64FileData() != null) {
            byteData = DatatypeConverter.parseBase64Binary(transInfo.getBase64FileData());
        }

        String username = cagCredential.getUsername();
        String channelName = ExtFunc.getContent(Defines._CHANNEL, xmlData);
        String user = ExtFunc.getContent(Defines._USER, xmlData);
        String idTag = ExtFunc.getContent(Defines._ID, xmlData);
        String metaData = ExtFunc.getContent(Defines._METADATA, xmlData);

        functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
        workerIdOrName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);

        int hwPkiCheck = DBConnector.getInstances().checkHWPKI(channelName,
                user);

        if (hwPkiCheck == 1 || hwPkiCheck == 2) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_PKILOCKED,
                    Defines.ERROR_PKILOCKED, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_PKILOCKED);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        } else if (hwPkiCheck == -1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        String serialNumber = DBConnector.getInstances().getSerialNumberFromCa(channelName, user);
        if (serialNumber.equals("") || serialNumber.equals(Defines.NULL)) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOCERTSERIAL,
                    Defines.ERROR_NOCERTSERIAL, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOCERTSERIAL);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        metaData = ExtFunc.getContent(Defines._METADATA, xmlData);
        List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();

        if (!metaData.equals("")) {
            requestMetadata = getMetaData(metaData);
            org.signserver.clientws.Metadata certserial = new org.signserver.clientws.Metadata(
                    "certSerialNumber", serialNumber);
            requestMetadata.add(certserial);
        } else {
            org.signserver.clientws.Metadata certserial = new org.signserver.clientws.Metadata(
                    "certSerialNumber", serialNumber);
            requestMetadata.add(certserial);
        }

        org.signserver.clientws.Metadata channelNameOTP = new org.signserver.clientws.Metadata(
                Defines._CHANNEL, channelName);

        org.signserver.clientws.Metadata userOTP = new org.signserver.clientws.Metadata(
                Defines._USER, user);
        requestMetadata.add(channelNameOTP);
        requestMetadata.add(userOTP);

        final int requestId = random.nextInt();
        final int workerId = getWorkerId(functionName);

        if (workerId < 1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                    Defines.ERROR_NOWORKER, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOWORKER);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (byteData == null) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                    Defines.ERROR_NOBASE64FILE, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOBASE64FILE);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (ExtFunc.checkFileType(byteData, "pdf").compareTo(ExtFunc.C_FILETYPE_PDF) != 0) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                    Defines.ERROR_NOBASE64FILE, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOBASE64FILE);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        final RequestContext requestContext = handleRequestContext(
                requestMetadata, workerId);

        final ProcessRequest req = new GenericSignRequest(requestId, byteData);
        ProcessResponse resp = null;
        try {
            resp = getWorkerSession().process(workerId, req, requestContext);
        } catch (Exception e) {
            LOG.error("Something wrong: " + e.getMessage());
            e.printStackTrace();
            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (!(resp instanceof GenericSignResponse)) {
            LOG.error("resp is not a instance of GenericSignResponse");

            String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                    Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        } else {
            final GenericSignResponse signResponse = (GenericSignResponse) resp;
            if (signResponse.getRequestID() != requestId) {
                LOG.error("Response ID " + signResponse.getRequestID()
                        + " not matching request ID " + requestId);

                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                        Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_NOTMATCHID);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;

            }

            int responseCode = signResponse.getResponseCode();
            String responseMessage = signResponse.getResponseMessage();


            if (responseCode == Defines.CODE_SUCCESS) {
                if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                    DBConnector.getInstances().increaseSuccessTransaction();
                }
                DBConnector.getInstances().resetErrorCounterHWPKI(channelName,
                        user);
                List<SignerInfoResponse> signInfo = signResponse.getSignerInfoResponse();

                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, signInfo, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(responseCode);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            } else {
                int pkiCheck = DBConnector.getInstances().leftRetryHWPKI(
                        channelName, user);
                if (pkiCheck == -100) {

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_PKILOCKED,
                            Defines.ERROR_PKILOCKED, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(Defines.CODE_PKILOCKED);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                }

                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, pkiCheck, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(responseCode);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            }
        }

    }

    private ProcessValidatorResp validateOffice(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
        String workerIdOrName = "";
        String functionName = "";
        String sslSubDn = "";
        String sslIseDn = "";
        String sslSnb = "";
        String unsignedData = "";
        String signedData = "";

        String xmlData = transInfo.getXmlData();
        CAGCredential cagCredential = transInfo.getCredentialData();
        byte[] byteData = transInfo.getFileData();

        if (transInfo.getBase64FileData() != null) {
            byteData = DatatypeConverter.parseBase64Binary(transInfo.getBase64FileData());
        }

        String username = cagCredential.getUsername();
        String channelName = ExtFunc.getContent(Defines._CHANNEL, xmlData);
        String user = ExtFunc.getContent(Defines._USER, xmlData);
        String idTag = ExtFunc.getContent(Defines._ID, xmlData);
        String metaData = ExtFunc.getContent(Defines._METADATA, xmlData);

        functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
        workerIdOrName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);

        int hwPkiCheck = DBConnector.getInstances().checkHWPKI(channelName,
                user);

        if (hwPkiCheck == 1 || hwPkiCheck == 2) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_PKILOCKED,
                    Defines.ERROR_PKILOCKED, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_PKILOCKED);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        } else if (hwPkiCheck == -1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        String serialNumber = DBConnector.getInstances().getSerialNumberFromCa(
                channelName, user);
        if (serialNumber.equals("") || serialNumber.equals(Defines.NULL)) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOCERTSERIAL,
                    Defines.ERROR_NOCERTSERIAL, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOCERTSERIAL);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        metaData = ExtFunc.getContent(Defines._METADATA, xmlData);
        List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();

        if (!metaData.equals("")) {
            requestMetadata = getMetaData(metaData);
            org.signserver.clientws.Metadata certserial = new org.signserver.clientws.Metadata(
                    "certSerialNumber", serialNumber);
            requestMetadata.add(certserial);
        } else {
            org.signserver.clientws.Metadata certserial = new org.signserver.clientws.Metadata(
                    "certSerialNumber", serialNumber);
            requestMetadata.add(certserial);
        }

        org.signserver.clientws.Metadata channelNameOTP = new org.signserver.clientws.Metadata(
                Defines._CHANNEL, channelName);

        org.signserver.clientws.Metadata userOTP = new org.signserver.clientws.Metadata(
                Defines._USER, user);
        requestMetadata.add(channelNameOTP);
        requestMetadata.add(userOTP);

        final int requestId = random.nextInt();
        final int workerId = getWorkerId(functionName);

        if (workerId < 1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                    Defines.ERROR_NOWORKER, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOWORKER);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (byteData == null) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                    Defines.ERROR_NOBASE64FILE, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOBASE64FILE);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (ExtFunc.checkFileType(byteData, "doc").compareTo(ExtFunc.C_FILETYPE_OFFICE) != 0) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                    Defines.ERROR_NOBASE64FILE, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOBASE64FILE);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        final RequestContext requestContext = handleRequestContext(
                requestMetadata, workerId);

        final ProcessRequest req = new GenericSignRequest(requestId, byteData);
        ProcessResponse resp = null;
        try {
            resp = getWorkerSession().process(workerId, req, requestContext);
        } catch (Exception e) {
            LOG.error("Something wrong: " + e.getMessage());
            e.printStackTrace();
            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (!(resp instanceof GenericSignResponse)) {
            LOG.error("resp is not a instance of GenericSignResponse");

            String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                    Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        } else {
            final GenericSignResponse signResponse = (GenericSignResponse) resp;
            if (signResponse.getRequestID() != requestId) {
                LOG.error("Response ID " + signResponse.getRequestID()
                        + " not matching request ID " + requestId);

                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                        Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_NOTMATCHID);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;

            }

            int responseCode = signResponse.getResponseCode();
            String responseMessage = signResponse.getResponseMessage();


            if (responseCode == Defines.CODE_SUCCESS) {

                if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                    DBConnector.getInstances().increaseSuccessTransaction();
                }

                DBConnector.getInstances().resetErrorCounterHWPKI(channelName,
                        user);
                List<SignerInfoResponse> signInfo = signResponse.getSignerInfoResponse();

                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, signInfo, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(responseCode);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            } else {
                int pkiCheck = DBConnector.getInstances().leftRetryHWPKI(
                        channelName, user);
                if (pkiCheck == -100) {

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_PKILOCKED,
                            Defines.ERROR_PKILOCKED, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(Defines.CODE_PKILOCKED);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                }

                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, pkiCheck, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(responseCode);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            }
        }

    }

    private ProcessValidatorResp validateXml(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
        String workerIdOrName = "";
        String functionName = "";
        String sslSubDn = "";
        String sslIseDn = "";
        String sslSnb = "";
        String unsignedData = "";
        String signedData = "";

        String xmlData = transInfo.getXmlData();
        CAGCredential cagCredential = transInfo.getCredentialData();
        byte[] byteData = transInfo.getFileData();

        if (transInfo.getBase64FileData() != null) {
            byteData = DatatypeConverter.parseBase64Binary(transInfo.getBase64FileData());
        }

        String username = cagCredential.getUsername();
        String channelName = ExtFunc.getContent(Defines._CHANNEL, xmlData);
        String user = ExtFunc.getContent(Defines._USER, xmlData);
        String idTag = ExtFunc.getContent(Defines._ID, xmlData);
        String metaData = ExtFunc.getContent(Defines._METADATA, xmlData);

        functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
        workerIdOrName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);

        int hwPkiCheck = DBConnector.getInstances().checkHWPKI(channelName,
                user);

        if (hwPkiCheck == 1 || hwPkiCheck == 2) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_PKILOCKED,
                    Defines.ERROR_PKILOCKED, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_PKILOCKED);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        } else if (hwPkiCheck == -1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        String serialNumber = DBConnector.getInstances().getSerialNumberFromCa(
                channelName, user);
        if (serialNumber.equals("") || serialNumber.equals(Defines.NULL)) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOCERTSERIAL,
                    Defines.ERROR_NOCERTSERIAL, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOCERTSERIAL);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        metaData = ExtFunc.getContent(Defines._METADATA, xmlData);
        List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();

        if (!metaData.equals("")) {
            requestMetadata = getMetaData(metaData);
            org.signserver.clientws.Metadata certserial = new org.signserver.clientws.Metadata(
                    "certSerialNumber", serialNumber);
            requestMetadata.add(certserial);
        } else {
            org.signserver.clientws.Metadata certserial = new org.signserver.clientws.Metadata(
                    "certSerialNumber", serialNumber);
            requestMetadata.add(certserial);
        }

        org.signserver.clientws.Metadata channelNameOTP = new org.signserver.clientws.Metadata(
                Defines._CHANNEL, channelName);

        org.signserver.clientws.Metadata userOTP = new org.signserver.clientws.Metadata(
                Defines._USER, user);
        requestMetadata.add(channelNameOTP);
        requestMetadata.add(userOTP);

        final int requestId = random.nextInt();
        final int workerId = getWorkerId(functionName);

        if (workerId < 1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                    Defines.ERROR_NOWORKER, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOWORKER);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (byteData == null) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                    Defines.ERROR_NOBASE64FILE, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOBASE64FILE);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (ExtFunc.checkFileType(byteData, "xml").compareTo(ExtFunc.C_FILETYPE_XML) != 0) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                    Defines.ERROR_NOBASE64FILE, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOBASE64FILE);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        signedData = new String(byteData);

        final RequestContext requestContext = handleRequestContext(
                requestMetadata, workerId);

        final ProcessRequest req = new GenericSignRequest(requestId, byteData);
        ProcessResponse resp = null;
        try {
            resp = getWorkerSession().process(workerId, req, requestContext);
        } catch (Exception e) {
            LOG.error("Something wrong: " + e.getMessage());
            e.printStackTrace();
            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (!(resp instanceof GenericSignResponse)) {
            LOG.error("resp is not a instance of GenericSignResponse");

            String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                    Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        } else {
            final GenericSignResponse signResponse = (GenericSignResponse) resp;
            if (signResponse.getRequestID() != requestId) {
                LOG.error("Response ID " + signResponse.getRequestID()
                        + " not matching request ID " + requestId);

                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                        Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_NOTMATCHID);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;

            }

            int responseCode = signResponse.getResponseCode();
            String responseMessage = signResponse.getResponseMessage();

            if (responseCode == Defines.CODE_SUCCESS) {

                if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                    DBConnector.getInstances().increaseSuccessTransaction();
                }

                DBConnector.getInstances().resetErrorCounterHWPKI(channelName,
                        user);
                List<SignerInfoResponse> signInfo = signResponse.getSignerInfoResponse();

                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, signInfo, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(responseCode);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            } else {
                int pkiCheck = DBConnector.getInstances().leftRetryHWPKI(
                        channelName, user);
                if (pkiCheck == -100) {

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_PKILOCKED,
                            Defines.ERROR_PKILOCKED, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(Defines.CODE_PKILOCKED);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                }

                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, pkiCheck, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(responseCode);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            }
        }

    }

    private ProcessValidatorResp validateCapicom(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
        String workerIdOrName = "";
        String functionName = "";
        String sslSubDn = "";
        String sslIseDn = "";
        String sslSnb = "";
        String unsignedData = "";
        String signedData = "";

        String xmlData = transInfo.getXmlData();
        CAGCredential cagCredential = transInfo.getCredentialData();
        byte[] byteData = transInfo.getFileData();

        if (transInfo.getBase64FileData() != null) {
            byteData = DatatypeConverter.parseBase64Binary(transInfo.getBase64FileData());
        }

        String username = cagCredential.getUsername();
        String channelName = ExtFunc.getContent(Defines._CHANNEL, xmlData);
        String user = ExtFunc.getContent(Defines._USER, xmlData);
        String idTag = ExtFunc.getContent(Defines._ID, xmlData);
        String metaData = ExtFunc.getContent(Defines._METADATA, xmlData);

        String serialNumber = ExtFunc.getContent(Defines._SERIALNUMBER, xmlData);

        String signature = ExtFunc.getContent(Defines._SIGNATURE, xmlData);
        unsignedData = ExtFunc.getContent(Defines._SIGNEDDATA, xmlData);
        signedData = signature;

        functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
        workerIdOrName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);

        int hwPkiCheck = DBConnector.getInstances().checkHWPKI(channelName, user);

        if (hwPkiCheck == 1 || hwPkiCheck == 2) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_PKILOCKED,
                    Defines.ERROR_PKILOCKED, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_PKILOCKED);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        } else if (hwPkiCheck == -1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (unsignedData.equals("")) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                    Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (signature.equals("")) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOCAPICOMSIGNATURE,
                    Defines.ERROR_NOCAPICOMSIGNATURE, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOCAPICOMSIGNATURE);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }
        byteData = Base64.decode(signature);

        if (byteData == null) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                    Defines.ERROR_NOBASE64FILE, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOBASE64FILE);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (ExtFunc.isNullOrEmpty(serialNumber)) {
            serialNumber = DBConnector.getInstances().getSerialNumberFromCa(channelName, user);
        }

        if (serialNumber.equals("") || serialNumber.equals(Defines.NULL)) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOCERTSERIAL,
                    Defines.ERROR_NOCERTSERIAL, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOCERTSERIAL);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        metaData = ExtFunc.getContent(Defines._METADATA, xmlData);
        List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();

        if (!metaData.equals("")) {
            requestMetadata = getMetaData(metaData);
            org.signserver.clientws.Metadata certserial = new org.signserver.clientws.Metadata(
                    "certSerialNumber", serialNumber);
            requestMetadata.add(certserial);
        } else {
            org.signserver.clientws.Metadata certserial = new org.signserver.clientws.Metadata(
                    "certSerialNumber", serialNumber);
            requestMetadata.add(certserial);
        }

        org.signserver.clientws.Metadata channelNameOTP = new org.signserver.clientws.Metadata(
                Defines._CHANNEL, channelName);

        org.signserver.clientws.Metadata userOTP = new org.signserver.clientws.Metadata(
                Defines._USER, user);
        requestMetadata.add(channelNameOTP);
        requestMetadata.add(userOTP);

        final int requestId = random.nextInt();
        final int workerId = getWorkerId(functionName);

        if (workerId < 1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                    Defines.ERROR_NOWORKER, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOWORKER);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        final RequestContext requestContext = handleRequestContext(
                requestMetadata, workerId);

        final ProcessRequest req = new GenericSignRequest(requestId, byteData);
        ProcessResponse resp = null;
        try {
            resp = getWorkerSession().process(workerId, req, requestContext);
        } catch (Exception e) {
            LOG.error("Something wrong: " + e.getMessage());
            e.printStackTrace();
            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (!(resp instanceof GenericSignResponse)) {
            LOG.error("resp is not a instance of GenericSignResponse");

            String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                    Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        } else {
            final GenericSignResponse signResponse = (GenericSignResponse) resp;
            if (signResponse.getRequestID() != requestId) {
                LOG.error("Response ID " + signResponse.getRequestID()
                        + " not matching request ID " + requestId);

                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                        Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_NOTMATCHID);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;

            }

            int responseCode = signResponse.getResponseCode();
            String responseMessage = signResponse.getResponseMessage();
            if (responseCode == Defines.CODE_SUCCESS) {

                if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                    DBConnector.getInstances().increaseSuccessTransaction();
                }

                DBConnector.getInstances().resetErrorCounterHWPKI(channelName,
                        user);

                List<SignerInfoResponse> signInfo = signResponse.getSignerInfoResponse();

                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, signInfo, billCode);


                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(responseCode);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            } else {
                int pkiCheck = DBConnector.getInstances().leftRetryHWPKI(channelName, user);
                if (pkiCheck == -100) {

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_PKILOCKED,
                            Defines.ERROR_PKILOCKED, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(Defines.CODE_PKILOCKED);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                }

                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, pkiCheck, billCode);


                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(responseCode);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            }
        }

    }

    private ProcessValidatorResp validatePkcs1(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
        String workerIdOrName = "";
        String functionName = "";
        String sslSubDn = "";
        String sslIseDn = "";
        String sslSnb = "";
        String unsignedData = "";
        String signedData = "";

        String xmlData = transInfo.getXmlData();
        CAGCredential cagCredential = transInfo.getCredentialData();
        byte[] byteData = transInfo.getFileData();

        if (transInfo.getBase64FileData() != null) {
            byteData = DatatypeConverter.parseBase64Binary(transInfo.getBase64FileData());
        }

        String username = cagCredential.getUsername();
        String channelName = ExtFunc.getContent(Defines._CHANNEL, xmlData);
        String user = ExtFunc.getContent(Defines._USER, xmlData);
        String idTag = ExtFunc.getContent(Defines._ID, xmlData);
        String metaData = ExtFunc.getContent(Defines._METADATA, xmlData);

        functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
        workerIdOrName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);

        int lcdpkiCheck = DBConnector.getInstances().checkHWLCDPKI(channelName, user);
        if (lcdpkiCheck == 1 || lcdpkiCheck == 2) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_PKILOCKED,
                    Defines.ERROR_PKILOCKED, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_PKILOCKED);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        } else if (lcdpkiCheck == -1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();
        if (!metaData.equals("")) {
            requestMetadata = getMetaData(metaData);
        }

        org.signserver.clientws.Metadata channelNameOTP = new org.signserver.clientws.Metadata(
                Defines._CHANNEL, channelName);

        org.signserver.clientws.Metadata userOTP = new org.signserver.clientws.Metadata(
                Defines._USER, user);
        requestMetadata.add(channelNameOTP);
        requestMetadata.add(userOTP);

        String p1Sig = ExtFunc.getContent(Defines._SIGNATURE, xmlData);

        unsignedData = StringEscapeUtils.unescapeHtml(ExtFunc.getContent(
                Defines._SIGNEDDATA, xmlData));
        signedData = p1Sig;

        if (p1Sig.equals("")) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOCAPICOMSIGNATURE,
                    Defines.ERROR_NOCAPICOMSIGNATURE, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOCAPICOMSIGNATURE);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        byteData = Base64.decode(p1Sig);

        final int requestId = random.nextInt();
        final int workerId = getWorkerId(functionName);

        if (workerId < 1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                    Defines.ERROR_NOWORKER, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOWORKER);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        final RequestContext requestContext = handleRequestContext(
                requestMetadata, workerId);

        final ProcessRequest req = new GenericSignRequest(requestId, byteData);
        ProcessResponse resp = null;
        try {
            resp = getWorkerSession().process(workerId, req, requestContext);
        } catch (Exception e) {
            LOG.error("Something wrong: " + e.getMessage());
            e.printStackTrace();
            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (!(resp instanceof GenericSignResponse)) {
            LOG.error("resp is not a instance of GenericSignResponse");

            String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                    Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        } else {
            final GenericSignResponse signResponse = (GenericSignResponse) resp;
            if (signResponse.getRequestID() != requestId) {
                LOG.error("Response ID " + signResponse.getRequestID()
                        + " not matching request ID " + requestId);

                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                        Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_NOTMATCHID);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;

            }

            int responseCode = signResponse.getResponseCode();
            String responseMessage = signResponse.getResponseMessage();

            if (responseCode == Defines.CODE_SUCCESS) {

                if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                    DBConnector.getInstances().increaseSuccessTransaction();
                }

                DBConnector.getInstances().resetErrorCounterHWLCDPKI(
                        channelName, user);

                List<SignerInfoResponse> signInfo = signResponse.getSignerInfoResponse();


                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, signInfo, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(responseCode);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            } else {
                int pkiCheck = DBConnector.getInstances().leftRetryHWLCDPKI(channelName, user);
                if (pkiCheck == -100) {

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_PKILOCKED,
                            Defines.ERROR_PKILOCKED, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(Defines.CODE_PKILOCKED);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                }

                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, pkiCheck, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(responseCode);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            }
        }

    }

    private ProcessValidatorResp validateOtpToken(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
        String workerIdOrName = "";
        String functionName = "";
        String sslSubDn = "";
        String sslIseDn = "";
        String sslSnb = "";
        String unsignedData = "";
        String signedData = "";

        String xmlData = transInfo.getXmlData();
        CAGCredential cagCredential = transInfo.getCredentialData();
        byte[] byteData = transInfo.getFileData();

        if (transInfo.getBase64FileData() != null) {
            byteData = DatatypeConverter.parseBase64Binary(transInfo.getBase64FileData());
        }

        String username = cagCredential.getUsername();
        String channelName = ExtFunc.getContent(Defines._CHANNEL, xmlData);
        String user = ExtFunc.getContent(Defines._USER, xmlData);
        String idTag = ExtFunc.getContent(Defines._ID, xmlData);
        String metaData = ExtFunc.getContent(Defines._METADATA, xmlData);

        functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
        workerIdOrName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);

        if (!DBConnector.getInstances().authCheckOTPMethod(channelName, user, Defines._OTPHARDWARE)) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_AGREEMENTNOTREADY,
                    Defines.ERROR_AGREEMENTNOTREADY, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_AGREEMENTNOTREADY);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        int otpCheck = DBConnector.getInstances().checkHWOTP(channelName, user);
        if (otpCheck == 1 || otpCheck == 2) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_PKILOCKED,
                    Defines.ERROR_PKILOCKED, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_PKILOCKED);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        } else if (otpCheck == -1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();
        if (!metaData.equals("")) {
            requestMetadata = getMetaData(metaData);
        }

        org.signserver.clientws.Metadata channelNameOTP = new org.signserver.clientws.Metadata(
                Defines._CHANNEL, channelName);

        org.signserver.clientws.Metadata userOTP = new org.signserver.clientws.Metadata(
                Defines._USER, user);
        requestMetadata.add(channelNameOTP);
        requestMetadata.add(userOTP);

        final int requestId = random.nextInt();
        final int workerId = getWorkerId(functionName);

        if (workerId < 1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                    Defines.ERROR_NOWORKER, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOWORKER);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        final RequestContext requestContext = handleRequestContext(
                requestMetadata, workerId);

        final ProcessRequest req = new GenericSignRequest(requestId, byteData);
        ProcessResponse resp = null;
        try {
            resp = getWorkerSession().process(workerId, req, requestContext);
        } catch (Exception e) {
            LOG.error("Something wrong: " + e.getMessage());
            e.printStackTrace();
            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (!(resp instanceof GenericSignResponse)) {
            LOG.error("resp is not a instance of GenericSignResponse");

            String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                    Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        } else {
            final GenericSignResponse signResponse = (GenericSignResponse) resp;
            if (signResponse.getRequestID() != requestId) {
                LOG.error("Response ID " + signResponse.getRequestID()
                        + " not matching request ID " + requestId);

                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                        Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_NOTMATCHID);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;

            }

            int responseCode = signResponse.getResponseCode();
            String responseMessage = signResponse.getResponseMessage();

            if (responseCode == Defines.CODE_SUCCESS) {

                if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                    DBConnector.getInstances().increaseSuccessTransaction();
                }

                DBConnector.getInstances().resetErrorCounterHWOTP(channelName,
                        user);

                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(responseCode);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            } else {
                if (responseCode == Defines.CODE_OTPLOCKED) {
                    // locked
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_OTPLOCKED,
                            Defines.ERROR_OTPLOCKED, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(Defines.CODE_OTPLOCKED);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                } else if (responseCode == Defines.CODE_OTP_STATUS_FAIL) {
                    // invalid
                    String retry = new String(signResponse.getProcessedData());

                    int otpRetry = Integer.parseInt(retry);

                    String pData = ExtFunc.genResponseMessage(responseCode,
                            responseMessage, channelName, user, otpRetry,
                            billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(responseCode);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                } else if (responseCode == Defines.CODE_OTPNEEDSYNC) {
                    // synch

                    String pData = ExtFunc.genResponseMessage(responseCode,
                            responseMessage, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(responseCode);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                } else if (responseCode == Defines.CODE_OTP_STATUS_DISABLE) {
                    // disable
                    String pData = ExtFunc.genResponseMessage(responseCode,
                            responseMessage, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(responseCode);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                } else if (responseCode == Defines.CODE_OTP_STATUS_LOST) {
                    // lost
                    String pData = ExtFunc.genResponseMessage(responseCode,
                            responseMessage, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(responseCode);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                } else {
                    // unknown exception
                    String pData = ExtFunc.genResponseMessage(responseCode,
                            responseMessage, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(responseCode);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                }
            }
        }
    }

    private ProcessValidatorResp syncOtpToken(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
        String workerIdOrName = "";
        String functionName = "";
        String sslSubDn = "";
        String sslIseDn = "";
        String sslSnb = "";
        String unsignedData = "";
        String signedData = "";

        String xmlData = transInfo.getXmlData();
        CAGCredential cagCredential = transInfo.getCredentialData();
        byte[] byteData = transInfo.getFileData();

        if (transInfo.getBase64FileData() != null) {
            byteData = DatatypeConverter.parseBase64Binary(transInfo.getBase64FileData());
        }

        String username = cagCredential.getUsername();
        String channelName = ExtFunc.getContent(Defines._CHANNEL, xmlData);
        String user = ExtFunc.getContent(Defines._USER, xmlData);
        String idTag = ExtFunc.getContent(Defines._ID, xmlData);
        String metaData = ExtFunc.getContent(Defines._METADATA, xmlData);

        functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
        workerIdOrName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);

        int otpCheck = DBConnector.getInstances().checkHWOTP(channelName, user);
        if (otpCheck == 1 || otpCheck == 2) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_OTPLOCKED,
                    Defines.ERROR_OTPLOCKED, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_OTPLOCKED);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        } else if (otpCheck == -1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (!DBConnector.getInstances().authCheckOTPMethod(channelName, user, Defines._OTPHARDWARE)) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_AGREEMENTNOTREADY,
                    Defines.ERROR_AGREEMENTNOTREADY, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_AGREEMENTNOTREADY);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();
        if (!metaData.equals("")) {
            requestMetadata = getMetaData(metaData);
        }

        org.signserver.clientws.Metadata channelNameOTP = new org.signserver.clientws.Metadata(
                Defines._CHANNEL, channelName);

        org.signserver.clientws.Metadata userOTP = new org.signserver.clientws.Metadata(
                Defines._USER, user);
        requestMetadata.add(channelNameOTP);
        requestMetadata.add(userOTP);

        final int requestId = random.nextInt();
        final int workerId = getWorkerId(functionName);

        if (workerId < 1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                    Defines.ERROR_NOWORKER, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOWORKER);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        final RequestContext requestContext = handleRequestContext(
                requestMetadata, workerId);

        final ProcessRequest req = new GenericSignRequest(requestId, byteData);
        ProcessResponse resp = null;
        try {
            resp = getWorkerSession().process(workerId, req, requestContext);
        } catch (Exception e) {
            LOG.error("Something wrong: " + e.getMessage());
            e.printStackTrace();
            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (!(resp instanceof GenericSignResponse)) {
            LOG.error("resp is not a instance of GenericSignResponse");

            String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                    Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        } else {
            final GenericSignResponse signResponse = (GenericSignResponse) resp;
            if (signResponse.getRequestID() != requestId) {
                LOG.error("Response ID " + signResponse.getRequestID()
                        + " not matching request ID " + requestId);

                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                        Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_NOTMATCHID);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;

            }

            int responseCode = signResponse.getResponseCode();
            String responseMessage = signResponse.getResponseMessage();

            if (responseCode == Defines.CODE_SUCCESS) {

                if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                    DBConnector.getInstances().increaseSuccessTransaction();
                }

                DBConnector.getInstances().resetErrorCounterHWOTP(channelName,
                        user);

                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(responseCode);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            } else {
                if (responseCode == Defines.CODE_OTPLOCKED) {
                    // locked
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_OTPLOCKED,
                            Defines.ERROR_OTPLOCKED, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(Defines.CODE_OTPLOCKED);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                } else if (responseCode == Defines.CODE_OTP_STATUS_FAIL) {
                    // invalid
                    String retry = new String(signResponse.getProcessedData());

                    int otpRetry = Integer.parseInt(retry);

                    String pData = ExtFunc.genResponseMessage(responseCode,
                            responseMessage, channelName, user, otpRetry,
                            billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(responseCode);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                } else if (responseCode == Defines.CODE_OTPNEEDSYNC) {
                    // synch

                    String pData = ExtFunc.genResponseMessage(responseCode,
                            responseMessage, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(responseCode);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                } else if (responseCode == Defines.CODE_OTP_STATUS_DISABLE) {
                    // disable
                    String pData = ExtFunc.genResponseMessage(responseCode,
                            responseMessage, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(responseCode);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                } else if (responseCode == Defines.CODE_OTP_STATUS_LOST) {
                    // lost
                    String pData = ExtFunc.genResponseMessage(responseCode,
                            responseMessage, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(responseCode);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                } else {
                    // unknown exception
                    String pData = ExtFunc.genResponseMessage(responseCode,
                            responseMessage, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(responseCode);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                }
            }
        }

    }

    private ProcessValidatorResp unlockOtpToken(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
        String workerIdOrName = "";
        String functionName = "";
        String sslSubDn = "";
        String sslIseDn = "";
        String sslSnb = "";
        String unsignedData = "";
        String signedData = "";

        String xmlData = transInfo.getXmlData();
        CAGCredential cagCredential = transInfo.getCredentialData();
        byte[] byteData = transInfo.getFileData();

        if (transInfo.getBase64FileData() != null) {
            byteData = DatatypeConverter.parseBase64Binary(transInfo.getBase64FileData());
        }

        String username = cagCredential.getUsername();
        String channelName = ExtFunc.getContent(Defines._CHANNEL, xmlData);
        String user = ExtFunc.getContent(Defines._USER, xmlData);
        String idTag = ExtFunc.getContent(Defines._ID, xmlData);
        String metaData = ExtFunc.getContent(Defines._METADATA, xmlData);

        functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
        workerIdOrName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);

        int otpCheck = DBConnector.getInstances().checkHWOTP(channelName, user);
        if (otpCheck == 1 || otpCheck == 2) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_OTPLOCKED,
                    Defines.ERROR_OTPLOCKED, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_OTPLOCKED);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        } else if (otpCheck == -1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (!DBConnector.getInstances().authCheckOTPMethod(channelName, user, Defines._OTPHARDWARE)) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_AGREEMENTNOTREADY,
                    Defines.ERROR_AGREEMENTNOTREADY, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_AGREEMENTNOTREADY);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();
        if (!metaData.equals("")) {
            requestMetadata = getMetaData(metaData);
        }

        org.signserver.clientws.Metadata channelNameOTP = new org.signserver.clientws.Metadata(
                Defines._CHANNEL, channelName);

        org.signserver.clientws.Metadata userOTP = new org.signserver.clientws.Metadata(
                Defines._USER, user);
        requestMetadata.add(channelNameOTP);
        requestMetadata.add(userOTP);

        final int requestId = random.nextInt();
        final int workerId = getWorkerId(functionName);

        if (workerId < 1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                    Defines.ERROR_NOWORKER, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOWORKER);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        final RequestContext requestContext = handleRequestContext(
                requestMetadata, workerId);

        final ProcessRequest req = new GenericSignRequest(requestId, byteData);
        ProcessResponse resp = null;
        try {
            resp = getWorkerSession().process(workerId, req, requestContext);
        } catch (Exception e) {
            LOG.error("Something wrong: " + e.getMessage());
            e.printStackTrace();
            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (!(resp instanceof GenericSignResponse)) {
            LOG.error("resp is not a instance of GenericSignResponse");

            String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                    Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        } else {
            final GenericSignResponse signResponse = (GenericSignResponse) resp;
            if (signResponse.getRequestID() != requestId) {
                LOG.error("Response ID " + signResponse.getRequestID()
                        + " not matching request ID " + requestId);

                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                        Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_NOTMATCHID);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;

            }

            int responseCode = signResponse.getResponseCode();
            String responseMessage = signResponse.getResponseMessage();

            if (responseCode == Defines.CODE_SUCCESS) {

                if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                    DBConnector.getInstances().increaseSuccessTransaction();
                }

                DBConnector.getInstances().resetErrorCounterHWOTP(channelName,
                        user);

                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(responseCode);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            } else {
                if (responseCode == Defines.CODE_OTPLOCKED) {
                    // locked

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_OTPLOCKED,
                            Defines.ERROR_OTPLOCKED, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(Defines.CODE_OTPLOCKED);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                } else if (responseCode == Defines.CODE_OTP_STATUS_FAIL) {
                    // invalid
                    String retry = new String(signResponse.getProcessedData());

                    int otpRetry = Integer.parseInt(retry);

                    String pData = ExtFunc.genResponseMessage(responseCode,
                            responseMessage, channelName, user, otpRetry,
                            billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(responseCode);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                } else if (responseCode == Defines.CODE_OTPNEEDSYNC) {
                    // synch
                    String pData = ExtFunc.genResponseMessage(responseCode,
                            responseMessage, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(responseCode);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                } else if (responseCode == Defines.CODE_OTP_STATUS_DISABLE) {
                    // disable
                    String pData = ExtFunc.genResponseMessage(responseCode,
                            responseMessage, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(responseCode);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                } else if (responseCode == Defines.CODE_OTP_STATUS_LOST) {
                    // lost
                    String pData = ExtFunc.genResponseMessage(responseCode,
                            responseMessage, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(responseCode);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                } else {
                    // unknown exception
                    String pData = ExtFunc.genResponseMessage(responseCode,
                            responseMessage, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(responseCode);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                }
            }
        }

    }

    private ProcessValidatorResp requestOtp(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
        String workerIdOrName = "";
        String functionName = "";
        String sslSubDn = "";
        String sslIseDn = "";
        String sslSnb = "";
        String unsignedData = "";
        String signedData = "";

        String xmlData = transInfo.getXmlData();
        CAGCredential cagCredential = transInfo.getCredentialData();
        byte[] byteData = transInfo.getFileData();

        if (transInfo.getBase64FileData() != null) {
            byteData = DatatypeConverter.parseBase64Binary(transInfo.getBase64FileData());
        }

        String username = cagCredential.getUsername();
        final String channelName = ExtFunc.getContent(Defines._CHANNEL, xmlData);
        final String user = ExtFunc.getContent(Defines._USER, xmlData);
        String idTag = ExtFunc.getContent(Defines._ID, xmlData);
        String metaData = ExtFunc.getContent(Defines._METADATA, xmlData);

        String method = ExtFunc.getContent(Defines._METHOD, xmlData);
        String transactionData = ExtFunc.getContent(Defines._TRANSACTIONDATA,
                xmlData);
        String subject = ExtFunc.getContent(Defines._SUBJECT, xmlData);

        functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
        workerIdOrName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);

        List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();
        if (!metaData.equals("")) {
            requestMetadata = getMetaData(metaData);
        }

        org.signserver.clientws.Metadata channelNameOTP = new org.signserver.clientws.Metadata(
                Defines._CHANNEL, channelName);

        org.signserver.clientws.Metadata userOTP = new org.signserver.clientws.Metadata(
                Defines._USER, user);
        requestMetadata.add(channelNameOTP);
        requestMetadata.add(userOTP);

        if (method.equals("") || transactionData.equals("")) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                    Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (!method.equals(Defines._OTPSMS)
                && !method.equals(Defines._OTPEMAIL)) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDOTPMETHOD,
                    Defines.ERROR_INVALIDOTPMETHOD, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INVALIDOTPMETHOD);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (!DBConnector.getInstances().authCheckOTPMethod(channelName, user,
                method)) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_AGREEMENTNOTREADY,
                    Defines.ERROR_AGREEMENTNOTREADY, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_AGREEMENTNOTREADY);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        int otpCheck = DBConnector.getInstances().checkHWOTP(channelName, user);
        if (otpCheck == 1 || otpCheck == 2) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_OTPLOCKED,
                    Defines.ERROR_OTPLOCKED, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_OTPLOCKED);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        } else if (otpCheck == -1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        org.signserver.clientws.Metadata transDataOTP = new org.signserver.clientws.Metadata(
                Defines._TRANSACTIONDATA, transactionData);
        requestMetadata.add(transDataOTP);

        final int requestId = random.nextInt();
        final int workerId = getWorkerId(functionName);

        if (workerId < 1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                    Defines.ERROR_NOWORKER, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOWORKER);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        final RequestContext requestContext = handleRequestContext(
                requestMetadata, workerId);

        final ProcessRequest req = new GenericSignRequest(requestId, byteData);
        ProcessResponse resp = null;
        try {
            resp = getWorkerSession().process(workerId, req, requestContext);
        } catch (Exception e) {
            LOG.error("Something wrong: " + e.getMessage());
            e.printStackTrace();
            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (!(resp instanceof GenericSignResponse)) {
            LOG.error("resp is not a instance of GenericSignResponse");

            String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                    Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        } else {
            final GenericSignResponse signResponse = (GenericSignResponse) resp;
            if (signResponse.getRequestID() != requestId) {
                LOG.error("Response ID " + signResponse.getRequestID()
                        + " not matching request ID " + requestId);

                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                        Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_NOTMATCHID);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;

            }

            int responseCode = signResponse.getResponseCode();
            String responseMessage = signResponse.getResponseMessage();

            if (responseCode == Defines.CODE_SUCCESS) {

                if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                    DBConnector.getInstances().increaseSuccessTransaction();
                }

                String otpInformation = "";
                String otp = new String(signResponse.getProcessedData());
                int otpInformationID = DBConnector.getInstances().authGetOTPInformationID(channelName, user);

                String pData = ExtFunc.genResponseMessage(Defines.CODE_OTP_STATUS_WAIT,
                        Defines.OTP_STATUS_WAIT, channelName, user, billCode);


                boolean res = DBConnector.getInstances().authInsertOTPTransaction(ExtFunc.getTransId(billCode), otp, transactionData, otpInformationID, method, Defines.OTP_STATUS_WAIT);

                if (method.equals(Defines._OTPEMAIL)) {
                    String email = DBConnector.getInstances().authGetEmailOTP(
                            channelName, user);
                    otpInformation = DBConnector.getInstances().OTPInformationGeneration(transactionData, otp);

                    String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(Defines.CONNECTION_PARAMS_SMTP);

                    if (endpointParams == null) {
                        pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                                Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                        ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                        processValidatorResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                        processValidatorResp.setXmlData(pData);
                        processValidatorResp.setSignedData(null);
                        processValidatorResp.setPreTrustedHubTransId(null);
                        return processValidatorResp;
                    }

                    EndpointServiceResp endpointServiceResp = EndpointService.getInstance().sendEmail(channelName, user, email, subject, otpInformation, endpointParams[1], Integer.parseInt(endpointParams[2]), trustedHubTransId);


                } else {
                    final String phoneNo = DBConnector.getInstances().authGetPhoneNoOTP(channelName, user);
                    otpInformation = DBConnector.getInstances().OTPInformationGeneration(
                            ExtFunc.removeAccent(transactionData), otp);

                    String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(Defines.CONNECTION_PARAMS_SMPP);

                    if (endpointParams == null) {
                        pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                                Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                        ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                        processValidatorResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                        processValidatorResp.setXmlData(pData);
                        processValidatorResp.setSignedData(null);
                        processValidatorResp.setPreTrustedHubTransId(null);
                        return processValidatorResp;
                    }

                    EndpointServiceResp endpointServiceResp = EndpointService.getInstance().sendSms(channelName, user, phoneNo, otpInformation, endpointParams[1], Integer.parseInt(endpointParams[2]), trustedHubTransId);

                }

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_OTP_STATUS_WAIT);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            } else {
                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(responseCode);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            }
        }

    }

    private ProcessValidatorResp responseOtp(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
        String workerIdOrName = "";
        String functionName = "";
        String sslSubDn = "";
        String sslIseDn = "";
        String sslSnb = "";
        String unsignedData = "";
        String signedData = "";

        String xmlData = transInfo.getXmlData();
        CAGCredential cagCredential = transInfo.getCredentialData();
        byte[] byteData = transInfo.getFileData();

        if (transInfo.getBase64FileData() != null) {
            byteData = DatatypeConverter.parseBase64Binary(transInfo.getBase64FileData());
        }

        String username = cagCredential.getUsername();
        String channelName = ExtFunc.getContent(Defines._CHANNEL, xmlData);
        String user = ExtFunc.getContent(Defines._USER, xmlData);
        String idTag = ExtFunc.getContent(Defines._ID, xmlData);
        String metaData = ExtFunc.getContent(Defines._METADATA, xmlData);

        String _billCode = ExtFunc.getContent(Defines._BILLCODE, xmlData);
        int preTrustedHubTransId = ExtFunc.getTransId(_billCode);

        String _otp = ExtFunc.getContent(Defines._OTP, xmlData);
        String method = ExtFunc.getContent(Defines._METHOD, xmlData);

        functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
        workerIdOrName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);

        if (!method.equals(Defines._OTPSMS)
                && !method.equals(Defines._OTPEMAIL)) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDOTPMETHOD,
                    Defines.ERROR_INVALIDOTPMETHOD, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INVALIDOTPMETHOD);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(preTrustedHubTransId);
            return processValidatorResp;
        }

        if (!DBConnector.getInstances().authCheckOTPMethod(channelName, user,
                method)) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_AGREEMENTNOTREADY,
                    Defines.ERROR_AGREEMENTNOTREADY, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_AGREEMENTNOTREADY);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(preTrustedHubTransId);
            return processValidatorResp;
        }

        int hwOtpCheck = DBConnector.getInstances().checkHWOTP(channelName,
                user);
        if (hwOtpCheck == 1 || hwOtpCheck == 2) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_OTPLOCKED,
                    Defines.ERROR_OTPLOCKED, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_OTPLOCKED);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(preTrustedHubTransId);
            return processValidatorResp;
        } else if (hwOtpCheck == -1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(preTrustedHubTransId);
            return processValidatorResp;
        }

        List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();
        if (!metaData.equals("")) {
            requestMetadata = getMetaData(metaData);
        }

        org.signserver.clientws.Metadata channelNameOTP = new org.signserver.clientws.Metadata(
                Defines._CHANNEL, channelName);

        org.signserver.clientws.Metadata userOTP = new org.signserver.clientws.Metadata(
                Defines._USER, user);
        requestMetadata.add(channelNameOTP);
        requestMetadata.add(userOTP);

        if (_otp.compareTo("") == 0
                || _billCode.compareTo("") == 0) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                    Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(preTrustedHubTransId);
            return processValidatorResp;
        }

        if (ExtFunc.getTransId(_billCode) == 1) {
            LOG.error("Invalid billCode " + _billCode);
            String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                    Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(preTrustedHubTransId);
            return processValidatorResp;
        }

        org.signserver.clientws.Metadata otpOTP = new org.signserver.clientws.Metadata(
                Defines._OTP, _otp);
        org.signserver.clientws.Metadata otpBillCode = new org.signserver.clientws.Metadata(
                Defines._BILLCODE, _billCode);
        requestMetadata.add(otpOTP);
        requestMetadata.add(otpBillCode);

        final int requestId = random.nextInt();
        final int workerId = getWorkerId(functionName);

        if (workerId < 1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                    Defines.ERROR_NOWORKER, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOWORKER);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(preTrustedHubTransId);
            return processValidatorResp;
        }

        final RequestContext requestContext = handleRequestContext(
                requestMetadata, workerId);

        final ProcessRequest req = new GenericSignRequest(requestId, byteData);
        ProcessResponse resp = null;
        try {
            resp = getWorkerSession().process(workerId, req, requestContext);
        } catch (Exception e) {
            LOG.error("Something wrong: " + e.getMessage());
            e.printStackTrace();
            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(preTrustedHubTransId);
            return processValidatorResp;
        }

        if (!(resp instanceof GenericSignResponse)) {
            LOG.error("resp is not a instance of GenericSignResponse");

            String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                    Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(preTrustedHubTransId);
            return processValidatorResp;
        } else {
            final GenericSignResponse signResponse = (GenericSignResponse) resp;
            if (signResponse.getRequestID() != requestId) {
                LOG.error("Response ID " + signResponse.getRequestID()
                        + " not matching request ID " + requestId);

                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                        Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_NOTMATCHID);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(preTrustedHubTransId);
                return processValidatorResp;

            }

            int responseCode = signResponse.getResponseCode();
            String responseMessage = signResponse.getResponseMessage();

            if (responseCode == Defines.CODE_SUCCESS) {
                // SUCCESS

                if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                    DBConnector.getInstances().increaseSuccessTransaction();
                }

                DBConnector.getInstances().resetErrorCounterHWOTP(channelName,
                        user);

                String pData = ExtFunc.genResponseOATHMessage(responseCode,
                        responseMessage, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(responseCode);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(preTrustedHubTransId);
                return processValidatorResp;
            } else if (responseCode == Defines.CODE_OTP_STATUS_FAIL) {

                int otpCheck = DBConnector.getInstances().leftRetryHWOTP(channelName, user);
                if (otpCheck == -100) {

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_OTPLOCKED,
                            Defines.ERROR_OTPLOCKED, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(Defines.CODE_OTPLOCKED);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processValidatorResp;
                }

                String pData = ExtFunc.genResponseOATHMessage(responseCode,
                        responseMessage, channelName, user, billCode, otpCheck);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(responseCode);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(preTrustedHubTransId);
                return processValidatorResp;
            } else {
                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(responseCode);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(preTrustedHubTransId);
                return processValidatorResp;
            }
        }

    }

    private ProcessValidatorResp processU2FValidator(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
        String workerIdOrName = "";
        String functionName = "";
        String sslSubDn = "";
        String sslIseDn = "";
        String sslSnb = "";
        String unsignedData = "";
        String signedData = "";

        String xmlData = transInfo.getXmlData();
        CAGCredential cagCredential = transInfo.getCredentialData();
        byte[] byteData = transInfo.getFileData();

        String username = cagCredential.getUsername();
        String channelName = ExtFunc.getContent(Defines._CHANNEL, xmlData);
        String user = ExtFunc.getContent(Defines._USER, xmlData);
        String idTag = ExtFunc.getContent(Defines._ID, xmlData);
        String metaData = ExtFunc.getContent(Defines._METADATA, xmlData);
        String method = ExtFunc.getContent(Defines._METHOD, xmlData);

        functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
        workerIdOrName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);

        if (!method.equals(Defines.U2F_AUTH_REQUEST) && !method.equals(Defines.U2F_AUTH_RESPONSE)) {
            LOG.error("Invalid U2F method");
            String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                    Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        String appId = DBConnector.getInstances().getU2F(channelName, user);

        if (ExtFunc.isNullOrEmpty(appId)) {
            LOG.error("AppId cannot be null or empty");
            String pData = ExtFunc.genResponseMessage(Defines.CODE_AGREEMENTNOTREADY,
                    Defines.ERROR_AGREEMENTNOTREADY, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_AGREEMENTNOTREADY);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (!DBConnector.getInstances().checkU2FLock(channelName, user)) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_U2F_BLOCKED,
                    Defines.ERROR_U2F_BLOCKED, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_U2F_BLOCKED);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();
        if (!metaData.equals("")) {
            requestMetadata = getMetaData(metaData);
        }

        org.signserver.clientws.Metadata channelName_metadata = new org.signserver.clientws.Metadata(
                Defines._CHANNEL, channelName);

        org.signserver.clientws.Metadata user_metadata = new org.signserver.clientws.Metadata(
                Defines._USER, user);

        org.signserver.clientws.Metadata appId_metadata = new org.signserver.clientws.Metadata(
                Defines._APPID, appId);

        org.signserver.clientws.Metadata trustedhub_trans_id = new org.signserver.clientws.Metadata(Defines._TRUSTEDHUBTRANSID, String.valueOf(trustedHubTransId));


        requestMetadata.add(channelName_metadata);
        requestMetadata.add(user_metadata);
        requestMetadata.add(trustedhub_trans_id);
        requestMetadata.add(appId_metadata);

        final int requestId = random.nextInt();
        final int workerId = getWorkerId(functionName);

        if (workerId < 1) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                    Defines.ERROR_NOWORKER, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_NOWORKER);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        final RequestContext requestContext = handleRequestContext(requestMetadata, workerId);

        final ProcessRequest req = new GenericSignRequest(requestId, byteData);
        ProcessResponse resp = null;
        try {
            resp = getWorkerSession().process(workerId, req, requestContext);
        } catch (Exception e) {
            LOG.error("Something wrong: " + e.getMessage());
            e.printStackTrace();
            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        }

        if (!(resp instanceof GenericSignResponse)) {
            LOG.error("resp is not a instance of GenericSignResponse");

            String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                    Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

            ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
            processValidatorResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
            processValidatorResp.setXmlData(pData);
            processValidatorResp.setSignedData(null);
            processValidatorResp.setPreTrustedHubTransId(null);
            return processValidatorResp;
        } else {
            final GenericSignResponse signResponse = (GenericSignResponse) resp;
            if (signResponse.getRequestID() != requestId) {
                LOG.error("Response ID " + signResponse.getRequestID()
                        + " not matching request ID " + requestId);

                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                        Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(Defines.CODE_NOTMATCHID);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;

            }

            int responseCode = signResponse.getResponseCode();
            String responseMessage = signResponse.getResponseMessage();

            if (responseCode == Defines.CODE_SUCCESS) {

                if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                    DBConnector.getInstances().increaseSuccessTransaction();
                }
                // reset U2F ErrorCounter if <> 0
                DBConnector.getInstances().resetErrorCounterU2F(channelName, user);

                String u2fJsonResp = signResponse.getResponseStrData();

                String pData = ExtFunc.genResponseMessageForU2F(responseCode,
                        responseMessage, channelName, user, billCode, u2fJsonResp);

                ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                processValidatorResp.setResponseCode(responseCode);
                processValidatorResp.setXmlData(pData);
                processValidatorResp.setSignedData(null);
                processValidatorResp.setPreTrustedHubTransId(null);
                return processValidatorResp;
            } else {

                int leftRetry = DBConnector.getInstances().getLeftU2FRetry(channelName, user);
                if (leftRetry == -100) {

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_U2F_BLOCKED,
                            Defines.ERROR_U2F_BLOCKED, channelName, user, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(Defines.CODE_U2F_BLOCKED);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;

                } else {
                    String pData = ExtFunc.genResponseMessage(responseCode,
                            responseMessage, channelName, user, leftRetry, billCode);

                    ProcessValidatorResp processValidatorResp = new ProcessValidatorResp();
                    processValidatorResp.setResponseCode(responseCode);
                    processValidatorResp.setXmlData(pData);
                    processValidatorResp.setSignedData(null);
                    processValidatorResp.setPreTrustedHubTransId(null);
                    return processValidatorResp;
                }
            }
        }
    }

    private int getWorkerId(String workerIdOrName) {
        final int retval;

        if (workerIdOrName.substring(0, 1).matches("\\d")) {
            retval = Integer.parseInt(workerIdOrName);
        } else {
            retval = getWorkerSession().getWorkerId(workerIdOrName);
        }
        return retval;
    }

    private IWorkerSession.ILocal getWorkerSession() {
        if (workersession == null) {
            try {
                workersession = ServiceLocator.getInstance().lookupLocal(
                        IWorkerSession.ILocal.class);
            } catch (NamingException e) {
                LOG.error(e);
            }
        }
        return workersession;
    }

    private RequestContext handleRequestContext(
            final List<Metadata> requestMetadata, final int workerId) {
        final HttpServletRequest servletRequest = (HttpServletRequest) wsContext.getMessageContext().get(MessageContext.SERVLET_REQUEST);
        String requestIP = ExtFunc.getRequestIP(wsContext);
        X509Certificate clientCertificate = getClientCertificate();
        final RequestContext requestContext = new RequestContext(
                clientCertificate, requestIP);

        IClientCredential credential;

        if (clientCertificate instanceof X509Certificate) {
            final X509Certificate cert = (X509Certificate) clientCertificate;
            LOG.debug("Authentication: certificate");
            credential = new CertificateClientCredential(cert.getSerialNumber().toString(16), cert.getIssuerDN().getName());
        } else {
            // Check is client supplied basic-credentials
            final String authorization = servletRequest.getHeader(HTTP_AUTH_BASIC_AUTHORIZATION);
            if (authorization != null) {
                LOG.debug("Authentication: password");

                final String decoded[] = new String(Base64.decode(authorization.split("\\s")[1])).split(":", 2);

                credential = new UsernamePasswordClientCredential(decoded[0],
                        decoded[1]);
            } else {
                LOG.debug("Authentication: none");
                credential = null;
            }
        }
        requestContext.put(RequestContext.CLIENT_CREDENTIAL, credential);

        final LogMap logMap = LogMap.getInstance(requestContext);

        // Add HTTP specific log entries
        logMap.put(
                IWorkerLogger.LOG_REQUEST_FULLURL,
                servletRequest.getRequestURL().append("?").append(servletRequest.getQueryString()).toString());
        logMap.put(IWorkerLogger.LOG_REQUEST_LENGTH,
                servletRequest.getHeader("Content-Length"));
        logMap.put(IWorkerLogger.LOG_XFORWARDEDFOR,
                servletRequest.getHeader("X-Forwarded-For"));

        logMap.put(IWorkerLogger.LOG_WORKER_NAME,
                getWorkerSession().getCurrentWorkerConfig(workerId).getProperty(ProcessableConfig.NAME));

        if (requestMetadata == null) {
            requestContext.remove(RequestContext.REQUEST_METADATA);
        } else {
            final RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
            for (Metadata rmd : requestMetadata) {
                metadata.put(rmd.getName(), rmd.getValue());
            }

            // Special handling of FILENAME
            String fileName = metadata.get(RequestContext.FILENAME);
            if (fileName != null) {
                requestContext.put(RequestContext.FILENAME, fileName);
                logMap.put(IWorkerLogger.LOG_FILENAME, fileName);
            }
        }

        return requestContext;
    }

    private X509Certificate getClientCertificate() {
        MessageContext msgContext = wsContext.getMessageContext();
        HttpServletRequest request = (HttpServletRequest) msgContext.get(MessageContext.SERVLET_REQUEST);
        X509Certificate[] certificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");

        if (certificates != null) {
            return certificates[0];
        }
        return null;
    }

    private List<Metadata> getMetaData(String metaData) {
        List<org.signserver.clientws.Metadata> listMD = new ArrayList<org.signserver.clientws.Metadata>();
        try {
            String xmlData = "<MetaData>" + metaData + "</MetaData>";

            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(new InputSource(new StringReader(
                    xmlData)));
            Element rootElement = document.getDocumentElement();

            NodeList list = document.getElementsByTagName("*");
            for (int i = 0; i < list.getLength(); i++) {
                Element element = (Element) list.item(i);
                if (!element.getNodeName().equals("MetaData")) {
                    org.signserver.clientws.Metadata tmp = new org.signserver.clientws.Metadata(
                            element.getNodeName(), element.getTextContent());
                    listMD.add(tmp);

                }
            }

        } catch (Exception e) {
            listMD = null;
        }
        return listMD;
    }
}
