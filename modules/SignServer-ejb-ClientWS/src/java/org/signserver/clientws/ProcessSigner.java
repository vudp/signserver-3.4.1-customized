package org.signserver.clientws;

import java.security.Signature;
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
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.CertificateClientCredential;
import org.signserver.server.IClientCredential;
import org.signserver.server.UsernamePasswordClientCredential;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;

import java.io.*;

import org.signserver.clientws.*;
import org.signserver.common.*;
import org.signserver.common.dbdao.*;
import org.signserver.common.util.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.tomicalab.cag360.license.*;

import javax.xml.ws.handler.soap.SOAPMessageContext;

import java.util.Map;

import com.tomicalab.cag360.connector.ws.*;

import vn.mobile_id.endpoint.service.datatype.*;
import vn.mobile_id.endpoint.service.datatype.params.*;
import vn.mobile_id.endpoint.client.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import vn.mobileid.pkcs11basic.*;

public class ProcessSigner {

    private static final Logger LOG = Logger.getLogger(ProcessSigner.class);
    private final Random random = new Random();
    private static final String HTTP_AUTH_BASIC_AUTHORIZATION = "Authorization";
    private WebServiceContext wsContext;
    private IWorkerSession.ILocal workersession;

    public ProcessSigner(WebServiceContext wsContext,
            IWorkerSession.ILocal workersession) {
        this.wsContext = wsContext;
        this.workersession = workersession;
    }

    public ProcessSignerResp processData(TransactionInfo transInfo, int trustedHubTransId, int agreementStatus, String billCode) {
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
        workerIdOrName = functionName;
        int workerType = ExtFunc.getWorkerType(workerIdOrName, method, signatureMethod);

        if (workerType == 5) {
            // Signer, combind channel-user-workername
            workerIdOrName = channelName.concat("-").concat(user).concat("-").concat(functionName);
        }

        if (agreementStatus == 1) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_AGREEMENTNOTEXITS,
                    Defines.ERROR_AGREEMENTNOTEXITS, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_AGREEMENTNOTEXITS);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(null);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;

        } else if (agreementStatus == 4 || agreementStatus == 2
                || agreementStatus == 3 || agreementStatus == 6
                || agreementStatus == 7) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_CONTRACTSTATUS,
                    Defines.ERROR_CONTRACTSTATUS, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_CONTRACTSTATUS);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(null);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;

        } else if (agreementStatus == 5) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_AGREEMENTEXPIRED,
                    Defines.ERROR_AGREEMENTEXPIRED, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_AGREEMENTEXPIRED);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(null);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        }

        ProcessSignerResp resp = null;
        if (functionName.compareTo(Defines.WORKER_PDFSIGNER) == 0) {
            resp = signPdf(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (functionName.compareTo(Defines.WORKER_XMLSIGNER) == 0) {
            resp = signXml(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (functionName.compareTo(Defines.WORKER_OFFICESIGNER) == 0) {
            resp = signOffice(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (functionName.compareTo(Defines.WORKER_CMSSIGNER) == 0) {
            resp = signCms(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (functionName.compareTo(Defines.WORKER_PKCS1SIGNER) == 0) {
            resp = signPkcs1(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (functionName.compareTo(Defines.WORKER_MULTISIGNER) == 0) {
            resp = signMultiType(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (functionName.compareTo(Defines.WORKER_DCSIGNER) == 0) {
            resp = signDc(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (functionName.compareTo(Defines.WORKER_SIGNERAP) == 0) {
            resp = signAp(transInfo, trustedHubTransId, billCode);
            return resp;
        } else {
            // Invalid action
            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                    Defines.ERROR_NOWORKER, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_NOWORKER);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(null);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        }
    }

    private ProcessSignerResp signPdf(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
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
        String method = ExtFunc.getContent(Defines._METHOD, xmlData);
        String signatureMethod = ExtFunc.getContent(Defines._SIGNATUREMETHOD, xmlData);

        functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
        workerIdOrName = functionName;
        int workerType = ExtFunc.getWorkerType(workerIdOrName, method, signatureMethod);

        if (workerType == 5) {
            // Signer, combind channel-user-workername
            workerIdOrName = channelName.concat("-").concat(user).concat("-").concat(functionName);
        }

        String fileType = ExtFunc.getContent(Defines._FILETYPE, xmlData);

        if (fileType.equals("")) {
            LOG.error("File Type cannot be null or empty");

            String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDFILETYPE,
                    Defines.ERROR_INVALIDFILETYPE, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_INVALIDFILETYPE);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        }

        if (byteData == null) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                    Defines.ERROR_NOBASE64FILE, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_NOBASE64FILE);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        }

        if (ExtFunc.checkFileType(byteData, fileType).compareTo(ExtFunc.C_FILETYPE_PDF) != 0) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                    Defines.ERROR_NOBASE64FILE, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_NOBASE64FILE);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        }

        List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();
        if (!metaData.equals("")) {
            requestMetadata = getMetaData(metaData);
        }

        org.signserver.clientws.Metadata fileExtension = new org.signserver.clientws.Metadata(
                "fileType", fileType);

        requestMetadata.add(fileExtension);

        final int requestId = random.nextInt();
        final int workerId = getWorkerId(workerIdOrName);

        if (workerId < 1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                    Defines.ERROR_NOWORKER, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_NOWORKER);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
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

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        }

        if (!(resp instanceof GenericSignResponse)) {
            LOG.error("resp is not a instance of GenericSignResponse");

            String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                    Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        } else {
            final GenericSignResponse signResponse = (GenericSignResponse) resp;
            if (signResponse.getRequestID() != requestId) {
                LOG.error("Response ID " + signResponse.getRequestID()
                        + " not matching request ID " + requestId);

                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                        Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                processSignerResp.setResponseCode(Defines.CODE_NOTMATCHID);
                processSignerResp.setXmlData(pData);
                processSignerResp.setSignedData(signedData);
                processSignerResp.setPreTrustedHubTransId(null);
                return processSignerResp;

            }

            int responseCode = signResponse.getResponseCode();
            String responseMessage = signResponse.getResponseMessage();

            if (responseCode == Defines.CODE_SUCCESS) {
                LOG.info("Sign operation completed");
                if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                    DBConnector.getInstances().increaseSuccessTransaction();
                }
                byte[] signedFile = signResponse.getProcessedData();
                String signingcert = null;
                try {
                    signingcert = signResponse.getSignerCertificate() == null ? new String(
                            Base64.encode(signResponse.getSignerCertificateChainBytes()))
                            : new String(Base64.encode(signResponse.getSignerCertificate().getEncoded()));
                } catch (CertificateEncodingException e) {
                    LOG.error("Something wrong: " + e.getMessage());
                    e.printStackTrace();
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                            Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                }

                String pData = ExtFunc.genResponseMessage(responseCode, responseMessage, channelName, user, fileType,
                        signingcert, billCode);

                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                processSignerResp.setResponseCode(responseCode);
                processSignerResp.setXmlData(pData);
                processSignerResp.setSignedData(signedData);
                processSignerResp.setFileData(signedFile); // SUCCESS
                processSignerResp.setPreTrustedHubTransId(null);
                return processSignerResp;
            } else {
                LOG.error("Sign operation get error");

                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, billCode);

                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                processSignerResp.setResponseCode(responseCode);
                processSignerResp.setXmlData(pData);
                processSignerResp.setSignedData(signedData);
                processSignerResp.setPreTrustedHubTransId(null);
                return processSignerResp;
            }
        }
    }

    private ProcessSignerResp signXml(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
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
        String method = ExtFunc.getContent(Defines._METHOD, xmlData);
        String signatureMethod = ExtFunc.getContent(Defines._SIGNATUREMETHOD, xmlData);

        functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
        workerIdOrName = functionName;
        int workerType = ExtFunc.getWorkerType(workerIdOrName, method, signatureMethod);

        if (workerType == 5) {
            // Signer, combind channel-user-workername
            workerIdOrName = channelName.concat("-").concat(user).concat("-").concat(functionName);
        }

        String fileType = ExtFunc.getContent(Defines._FILETYPE, xmlData);

        if (fileType.equals("")) {
            LOG.error("File Type cannot be null or empty");

            String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDFILETYPE,
                    Defines.ERROR_INVALIDFILETYPE, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_INVALIDFILETYPE);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        }

        if (byteData == null) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                    Defines.ERROR_NOBASE64FILE, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_NOBASE64FILE);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        }

        if (ExtFunc.checkFileType(byteData, fileType).compareTo(ExtFunc.C_FILETYPE_XML) != 0) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                    Defines.ERROR_NOBASE64FILE, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_NOBASE64FILE);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        }

        unsignedData = new String(byteData);

        List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();

        if (!metaData.equals("")) {
            requestMetadata = getMetaData(metaData);
        }

        org.signserver.clientws.Metadata fileExtension = new org.signserver.clientws.Metadata(
                "fileType", fileType);

        requestMetadata.add(fileExtension);

        final int requestId = random.nextInt();
        final int workerId = getWorkerId(workerIdOrName);

        if (workerId < 1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                    Defines.ERROR_NOWORKER, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_NOWORKER);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
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

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        }

        if (!(resp instanceof GenericSignResponse)) {
            LOG.error("resp is not a instance of GenericSignResponse");

            String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                    Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        } else {
            final GenericSignResponse signResponse = (GenericSignResponse) resp;
            if (signResponse.getRequestID() != requestId) {
                LOG.error("Response ID " + signResponse.getRequestID()
                        + " not matching request ID " + requestId);

                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                        Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                processSignerResp.setResponseCode(Defines.CODE_NOTMATCHID);
                processSignerResp.setXmlData(pData);
                processSignerResp.setSignedData(signedData);
                processSignerResp.setPreTrustedHubTransId(null);
                return processSignerResp;

            }

            int responseCode = signResponse.getResponseCode();
            String responseMessage = signResponse.getResponseMessage();

            if (responseCode == Defines.CODE_SUCCESS) {
                LOG.info("Sign operation completed");
                if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                    DBConnector.getInstances().increaseSuccessTransaction();
                }
                byte[] signedFile = signResponse.getProcessedData();

                signedData = new String(signedFile);

                String signingcert = null;
                try {
                    signingcert = signResponse.getSignerCertificate() == null ? new String(
                            Base64.encode(signResponse.getSignerCertificateChainBytes()))
                            : new String(Base64.encode(signResponse.getSignerCertificate().getEncoded()));
                } catch (CertificateEncodingException e) {
                    LOG.error("Something wrong: " + e.getMessage());
                    e.printStackTrace();
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                            Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                }

                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, fileType,
                        signingcert, billCode);

                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                processSignerResp.setResponseCode(responseCode);
                processSignerResp.setXmlData(pData);
                processSignerResp.setSignedData(signedData);
                processSignerResp.setFileData(signedFile); // SUCCESS
                processSignerResp.setPreTrustedHubTransId(null);
                return processSignerResp;
            } else {
                LOG.error("Sign operation get error");

                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, billCode);

                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                processSignerResp.setResponseCode(responseCode);
                processSignerResp.setXmlData(pData);
                processSignerResp.setSignedData(signedData);
                processSignerResp.setPreTrustedHubTransId(null);
                return processSignerResp;
            }
        }
    }

    private ProcessSignerResp signOffice(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
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
        String method = ExtFunc.getContent(Defines._METHOD, xmlData);
        String signatureMethod = ExtFunc.getContent(Defines._SIGNATUREMETHOD, xmlData);

        functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
        workerIdOrName = functionName;
        int workerType = ExtFunc.getWorkerType(workerIdOrName, method, signatureMethod);

        if (workerType == 5) {
            // Signer, combind channel-user-workername
            workerIdOrName = channelName.concat("-").concat(user).concat("-").concat(functionName);
        }

        String fileType = ExtFunc.getContent(Defines._FILETYPE, xmlData);

        if (fileType.equals("")) {
            LOG.error("File Type cannot be null or empty");

            String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDFILETYPE,
                    Defines.ERROR_INVALIDFILETYPE, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_INVALIDFILETYPE);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        }

        if (byteData == null) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                    Defines.ERROR_NOBASE64FILE, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_NOBASE64FILE);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        }

        if (ExtFunc.checkFileType(byteData, fileType).compareTo(ExtFunc.C_FILETYPE_OFFICE) != 0) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                    Defines.ERROR_NOBASE64FILE, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_NOBASE64FILE);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        }

        List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();
        if (!metaData.equals("")) {
            requestMetadata = getMetaData(metaData);
        }
        org.signserver.clientws.Metadata fileExtension = new org.signserver.clientws.Metadata(
                "fileType", fileType);

        requestMetadata.add(fileExtension);

        final int requestId = random.nextInt();
        final int workerId = getWorkerId(workerIdOrName);

        if (workerId < 1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                    Defines.ERROR_NOWORKER, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_NOWORKER);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
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

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        }

        if (!(resp instanceof GenericSignResponse)) {
            LOG.error("resp is not a instance of GenericSignResponse");

            String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                    Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        } else {
            final GenericSignResponse signResponse = (GenericSignResponse) resp;
            if (signResponse.getRequestID() != requestId) {
                LOG.error("Response ID " + signResponse.getRequestID()
                        + " not matching request ID " + requestId);

                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                        Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                processSignerResp.setResponseCode(Defines.CODE_NOTMATCHID);
                processSignerResp.setXmlData(pData);
                processSignerResp.setSignedData(signedData);
                processSignerResp.setPreTrustedHubTransId(null);
                return processSignerResp;

            }

            int responseCode = signResponse.getResponseCode();
            String responseMessage = signResponse.getResponseMessage();

            if (responseCode == Defines.CODE_SUCCESS) {
                LOG.info("Sign operation completed");
                if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                    DBConnector.getInstances().increaseSuccessTransaction();
                }
                byte[] signedFile = signResponse.getProcessedData();
                String signingcert = null;
                try {
                    signingcert = signResponse.getSignerCertificate() == null ? new String(
                            Base64.encode(signResponse.getSignerCertificateChainBytes()))
                            : new String(Base64.encode(signResponse.getSignerCertificate().getEncoded()));
                } catch (CertificateEncodingException e) {
                    LOG.error("Something wrong: " + e.getMessage());
                    e.printStackTrace();
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                            Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                }

                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, fileType,
                        signingcert, billCode);

                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                processSignerResp.setResponseCode(responseCode);
                processSignerResp.setXmlData(pData);
                processSignerResp.setSignedData(signedData);
                processSignerResp.setFileData(signedFile); // SUCCESS
                processSignerResp.setPreTrustedHubTransId(null);
                return processSignerResp;
            } else {
                LOG.error("Sign operation get error");

                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, billCode);

                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                processSignerResp.setResponseCode(responseCode);
                processSignerResp.setXmlData(pData);
                processSignerResp.setSignedData(signedData);
                processSignerResp.setPreTrustedHubTransId(null);
                return processSignerResp;
            }
        }
    }

    private ProcessSignerResp signCms(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
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
        String method = ExtFunc.getContent(Defines._METHOD, xmlData);
        String signatureMethod = ExtFunc.getContent(Defines._SIGNATUREMETHOD, xmlData);

        functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
        workerIdOrName = functionName;
        int workerType = ExtFunc.getWorkerType(workerIdOrName, method, signatureMethod);

        if (workerType == 5) {
            // Signer, combind channel-user-workername
            workerIdOrName = channelName.concat("-").concat(user).concat("-").concat(functionName);
        }

        String fileType = ExtFunc.getContent(Defines._FILETYPE, xmlData);

        if (fileType.equals("")) {
            LOG.error("File Type cannot be null or empty");

            String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDFILETYPE,
                    Defines.ERROR_INVALIDFILETYPE, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_INVALIDFILETYPE);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        }

        String dataToSign = ExtFunc.getContent(Defines._DATATOSIGN, xmlData);

        if (dataToSign.equals("")) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDDATATOSIGN,
                    Defines.ERROR_INVALIDDATATOSIGN, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_INVALIDDATATOSIGN);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        }

        try {
            byteData = dataToSign.getBytes("UTF-16LE");
        } catch (UnsupportedEncodingException e) {
            LOG.error("Something wrong: " + e.getMessage());
            e.printStackTrace();
            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        }

        unsignedData = dataToSign;

        List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();
        if (!metaData.equals("")) {
            requestMetadata = getMetaData(metaData);
        }
        org.signserver.clientws.Metadata fileExtension = new org.signserver.clientws.Metadata(
                "fileType", fileType);

        requestMetadata.add(fileExtension);

        final int requestId = random.nextInt();
        final int workerId = getWorkerId(workerIdOrName);

        if (workerId < 1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                    Defines.ERROR_NOWORKER, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_NOWORKER);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
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

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        }

        if (!(resp instanceof GenericSignResponse)) {
            LOG.error("resp is not a instance of GenericSignResponse");

            String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                    Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        } else {
            final GenericSignResponse signResponse = (GenericSignResponse) resp;
            if (signResponse.getRequestID() != requestId) {
                LOG.error("Response ID " + signResponse.getRequestID()
                        + " not matching request ID " + requestId);

                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                        Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                processSignerResp.setResponseCode(Defines.CODE_NOTMATCHID);
                processSignerResp.setXmlData(pData);
                processSignerResp.setSignedData(signedData);
                processSignerResp.setPreTrustedHubTransId(null);
                return processSignerResp;
            }

            int responseCode = signResponse.getResponseCode();
            String responseMessage = signResponse.getResponseMessage();

            if (responseCode == Defines.CODE_SUCCESS) {
                LOG.info("Sign operation completed");
                if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                    DBConnector.getInstances().increaseSuccessTransaction();
                }
                byte[] signedFile = signResponse.getProcessedData();
                signedData = new String(signedFile);
                String signingcert = null;
                try {
                    signingcert = signResponse.getSignerCertificate() == null ? new String(
                            Base64.encode(signResponse.getSignerCertificateChainBytes()))
                            : new String(Base64.encode(signResponse.getSignerCertificate().getEncoded()));
                } catch (CertificateEncodingException e) {
                    LOG.error("Something wrong: " + e.getMessage());
                    e.printStackTrace();
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                            Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                }

                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, fileType,
                        signingcert, billCode);

                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                processSignerResp.setResponseCode(responseCode);
                processSignerResp.setXmlData(pData);
                processSignerResp.setSignedData(signedData);
                processSignerResp.setFileData(signedFile); // SUCCESS
                processSignerResp.setPreTrustedHubTransId(null);
                return processSignerResp;
            } else {
                LOG.error("Sign operation get error");

                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, billCode);

                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                processSignerResp.setResponseCode(responseCode);
                processSignerResp.setXmlData(pData);
                processSignerResp.setSignedData(signedData);
                processSignerResp.setPreTrustedHubTransId(null);
                return processSignerResp;
            }
        }
    }

    private ProcessSignerResp signPkcs1(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
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
        String method = ExtFunc.getContent(Defines._METHOD, xmlData);
        String signatureMethod = ExtFunc.getContent(Defines._SIGNATUREMETHOD, xmlData);

        functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
        workerIdOrName = functionName;
        int workerType = ExtFunc.getWorkerType(workerIdOrName, method, signatureMethod);

        if (workerType == 5) {
            // Signer, combind channel-user-workername
            workerIdOrName = channelName.concat("-").concat(user).concat("-").concat(functionName);
        }

        String fileType = ExtFunc.getContent(Defines._FILETYPE, xmlData);

        if (fileType.equals("")) {
            LOG.error("File Type cannot be null or empty");

            String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDFILETYPE,
                    Defines.ERROR_INVALIDFILETYPE, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_INVALIDFILETYPE);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        }

        List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();
        if (!metaData.equals("")) {
            requestMetadata = getMetaData(metaData);
        }
        org.signserver.clientws.Metadata fileExtension = new org.signserver.clientws.Metadata(
                "fileType", fileType);

        requestMetadata.add(fileExtension);

        final int requestId = random.nextInt();
        final int workerId = getWorkerId(workerIdOrName);

        if (workerId < 1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                    Defines.ERROR_NOWORKER, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_NOWORKER);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        }

        final RequestContext requestContext = handleRequestContext(
                requestMetadata, workerId);

        final ProcessRequest req = new GenericSignRequest(requestId, byteData);
        ProcessResponse resp = null;
        try {
            resp = getWorkerSession().process(workerId, req, requestContext);
        } catch (Exception e) {
            e.printStackTrace();
            LOG.error("Something wrong: " + e.getMessage());
            e.printStackTrace();
            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        }

        if (!(resp instanceof GenericSignResponse)) {
            LOG.error("resp is not a instance of GenericSignResponse");

            String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                    Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        } else {
            final GenericSignResponse signResponse = (GenericSignResponse) resp;
            if (signResponse.getRequestID() != requestId) {
                LOG.error("Response ID " + signResponse.getRequestID()
                        + " not matching request ID " + requestId);

                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                        Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                processSignerResp.setResponseCode(Defines.CODE_NOTMATCHID);
                processSignerResp.setXmlData(pData);
                processSignerResp.setSignedData(signedData);
                processSignerResp.setPreTrustedHubTransId(null);
                return processSignerResp;
            }

            int responseCode = signResponse.getResponseCode();
            String responseMessage = signResponse.getResponseMessage();

            if (responseCode == Defines.CODE_SUCCESS) {
                LOG.info("Sign operation completed");
                if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                    DBConnector.getInstances().increaseSuccessTransaction();
                }
                if (method.compareTo(Defines.PKCS1CERREQUEST) == 0) {
                    byte[] signedFile = signResponse.getProcessedData();
                    String signingcert = null;
                    try {
                        signingcert = signResponse.getSignerCertificate() == null ? new String(
                                Base64.encode(signResponse.getSignerCertificateChainBytes()))
                                : new String(Base64.encode(signResponse.getSignerCertificate().getEncoded()));
                    } catch (CertificateEncodingException e) {
                        LOG.error("Something wrong: " + e.getMessage());
                        e.printStackTrace();
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                                Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    }
                    String pData = ExtFunc.genResponseMessage(responseCode,
                            responseMessage, channelName, user, fileType,
                            signingcert, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(responseCode);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                } else {
                    byte[] signedFile = signResponse.getProcessedData();
                    String signingcert = null;
                    try {
                        signingcert = signResponse.getSignerCertificate() == null ? new String(
                                Base64.encode(signResponse.getSignerCertificateChainBytes()))
                                : new String(Base64.encode(signResponse.getSignerCertificate().getEncoded()));
                    } catch (CertificateEncodingException e) {
                        e.printStackTrace();
                        LOG.error("Something wrong: " + e.getMessage());
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                                Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    }
                    String pData = ExtFunc.genResponseMessage(responseCode,
                            responseMessage, channelName, user, fileType,
                            signingcert, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(responseCode);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setFileData(signedFile); // SUCCESS
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                }
            } else {
                LOG.error("Sign operation get error");

                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, billCode);

                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                processSignerResp.setResponseCode(responseCode);
                processSignerResp.setXmlData(pData);
                processSignerResp.setSignedData(signedData);
                processSignerResp.setPreTrustedHubTransId(null);
                return processSignerResp;
            }
        }
    }

    private ProcessSignerResp signMultiType(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
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
        String subject = ExtFunc.getContent(Defines._SUBJECT, xmlData);
        String signatureMethod = ExtFunc.getContent(Defines._SIGNATUREMETHOD, xmlData);
        String signerPassword = ExtFunc.getContent(Defines._PASSWORD, xmlData);

        functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
        workerIdOrName = functionName;
        int workerType = ExtFunc.getWorkerType(workerIdOrName, method, signatureMethod);

        if (workerType == 5) {
            // Signer, combind channel-user-workername
            workerIdOrName = channelName.concat("-").concat(user).concat("-").concat(functionName);
            LOG.info("Worker: " + workerIdOrName);
        }

        String fileType = ExtFunc.getContent(Defines._FILETYPE, xmlData);
        String otpMethod = ExtFunc.getContent(Defines._OTPMETHOD, xmlData);

        String transactionData = ExtFunc.getContent(Defines._TRANSACTIONDATA,
                xmlData);
        String _otp = ExtFunc.getContent(Defines._OTP, xmlData);
        String _billCode = ExtFunc.getContent(Defines._BILLCODE, xmlData);

        String externalStorage = ExtFunc.getContent(Defines._EXTERNALSTORAGE, xmlData);

        String fileId = ExtFunc.getContent(Defines._FILEID, xmlData);
        String fileDisplayValue = null;
        String fileMineType = null;
        String fileName = null;

        if (byteData != null) {
            fileType = ExtFunc.checkFileType(byteData, fileType);
        }

        List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();
        if (!metaData.equals("")) {
            requestMetadata = getMetaData(metaData);
        }

        org.signserver.clientws.Metadata fileExtension = new org.signserver.clientws.Metadata(
                Defines._FILETYPE, fileType);
        requestMetadata.add(fileExtension);

        org.signserver.clientws.Metadata channelNameOTP = new org.signserver.clientws.Metadata(
                Defines._CHANNEL, channelName);

        org.signserver.clientws.Metadata userOTP = new org.signserver.clientws.Metadata(
                Defines._USER, user);

        org.signserver.clientws.Metadata trustedhub_trans_id = new org.signserver.clientws.Metadata(Defines._TRUSTEDHUBTRANSID, String.valueOf(trustedHubTransId));

        requestMetadata.add(channelNameOTP);
        requestMetadata.add(userOTP);
        requestMetadata.add(trustedhub_trans_id);

        if (method.equals("")) {
            method = Defines.METHOD_SYNCHRONOUSSIGN;
        }

        if (externalStorage.equals("")) {
            externalStorage = Defines.EXTERNAL_STORAGE_LOCAL;
        }

        org.signserver.clientws.Metadata methodMetaData = new org.signserver.clientws.Metadata(Defines._METHOD, method);
        requestMetadata.add(methodMetaData);

        if (method.compareTo("") != 0) {
            if (method.compareTo(Defines.WORKER_OATHREQUEST) == 0) {
                // OATHRequest
                // store check OTP co bi lock hay ko
                int otpCheck = DBConnector.getInstances().checkHWOTP(
                        channelName, user);
                if (otpCheck == 1 || otpCheck == 2) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_OTPLOCKED,
                            Defines.ERROR_OTPLOCKED, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_OTPLOCKED);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                } else if (otpCheck == -1) {

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                            Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                }

                if (transactionData.compareTo("") == 0
                        || otpMethod.compareTo("") == 0) {

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                }

                if (!otpMethod.equals(Defines._OTPSMS)
                        && !otpMethod.equals(Defines._OTPEMAIL)) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDOTPMETHOD,
                            Defines.ERROR_INVALIDOTPMETHOD, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INVALIDOTPMETHOD);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                }
                // kiem tra xem hop dong co dang
                // ky otp sms hay khong
                if (!DBConnector.getInstances().authCheckOTPMethod(
                        channelName, user, otpMethod)) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_AGREEMENTNOTREADY,
                            Defines.ERROR_AGREEMENTNOTREADY, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_AGREEMENTNOTREADY);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                }
                // Kiem tra so lan toi da quy
                // dinh doi voi OTP
				/*
                 * if (!DBConnector.getInstances().authCheckOTPPerformance(
                 * channelName, user, method)) { String billCode =
                 * ExtFunc.getBillCode(); String pData =
                 * ExtFunc.genResponseMessage( Defines.CODE_OTPPERFORMANCEXCEED,
                 * Defines.ERROR_OTPPERFORMANCEXCEED, channelName, user,
                 * billCode);
                 * DBConnector.getInstances().writeLogToDataBaseOutside(
                 * workerIdOrName, username, ExtFunc.getRequestIP(wsContext),
                 * user, Defines.ERROR_OTPPERFORMANCEXCEED,
                 * Defines.CODE_OTPPERFORMANCEXCEED, sslSubDn, sslIseDn, sslSnb,
                 * idTag, channelName, xmlData, pData, billCode, unsignedData,
                 * signedData); return new TransactionInfo(pData); }
                 */
                /*
                 * // externalStorage = null or DIRECTLY if (byteData == null)
                 * { String pData =
                 * ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                 * Defines.ERROR_NOBASE64FILE, channelName, user, billCode);
                 *
                 * String billCode =
                 * DBConnector.getInstances().writeLogToDataBaseOutside(workerIdOrName,
                 * username, ExtFunc.getRequestIP(wsContext), user,
                 * Defines.CODE_NOBASE64FILE, idTag, channelName, xmlData,
                 * pData, unsignedData, signedData, functionName,
                 * trustedHubTransId);
                 *
                 * pData = ExtFunc.replaceBillCode(billCode, pData);
                 *
                 * return new TransactionInfo(pData); }
                 *
                 * if (fileType.equals("")) { LOG.error("File Type cannot be
                 * null or empty"); String pData =
                 * ExtFunc.genResponseMessage(Defines.CODE_INVALIDFILETYPE,
                 * Defines.ERROR_INVALIDFILETYPE, channelName, user, billCode);
                 *
                 * String billCode =
                 * DBConnector.getInstances().writeLogToDataBaseOutside(workerIdOrName,
                 * username, ExtFunc.getRequestIP(wsContext), user,
                 * Defines.CODE_INVALIDFILETYPE, idTag, channelName, xmlData,
                 * pData, unsignedData, signedData, functionName,
                 * trustedHubTransId);
                 *
                 * pData = ExtFunc.replaceBillCode(billCode, pData);
                 *
                 * return new TransactionInfo(pData); }
                 *
                 * if(ExtFunc.checkFileType(byteData, fileType)
                 * .compareTo(ExtFunc.C_FILETYPE_XML) == 0) { unsignedData = new
                 * String(byteData); }
                 */

                if (externalStorage.equals("")) {
                    externalStorage = Defines.EXTERNAL_STORAGE_LOCAL;
                }

                if (externalStorage.compareTo("") != 0
                        && externalStorage.compareTo(Defines.EXTERNAL_STORAGE_LOCAL) != 0) {
                    // Get file from external server
                    if (fileId.compareTo("") == 0
                            || fileId.split(";").length > 1) {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                                Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    } else {

                        String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(externalStorage);

                        if (endpointParams == null) {
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                                    Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(null);
                            return processSignerResp;
                        }

                        EndpointServiceResponse endpointServiceResponse = EndpointService.getInstance().getRemoteFile(channelName, user,
                                externalStorage, endpointParams[1], fileId, Integer.parseInt(endpointParams[2]), trustedHubTransId);

                        Response response = endpointServiceResponse.getResponse();
                        if (response == null) {
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_ENDPOINTEXP,
                                    Defines.ERROR_ENDPOINTEXP, channelName, user, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(Defines.CODE_ENDPOINTEXP);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(null);
                            return processSignerResp;
                        }

                        if (response.getStatus().getResponseCode() == 0) {

                            byteData = response.getRemoteFileResp().getFileParams().getFileData();
                            fileType = response.getRemoteFileResp().getFileParams().getFileType();
                            fileDisplayValue = response.getRemoteFileResp().getFileParams().getDisplayValue();
                            fileMineType = response.getRemoteFileResp().getFileParams().getMimeType();
                            fileName = response.getRemoteFileResp().getFileParams().getFileName();

                            // add into metadata
                            fileExtension = new org.signserver.clientws.Metadata(Defines._FILETYPE, fileType);
                            requestMetadata.add(fileExtension);

                            if (byteData == null) {
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                                        Defines.ERROR_NOBASE64FILE, channelName, user, billCode);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_NOBASE64FILE);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(null);
                                return processSignerResp;
                            }

                            if (fileType.equals("")) {
                                LOG.error("File Type cannot be null or empty");
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDFILETYPE,
                                        Defines.ERROR_INVALIDFILETYPE, channelName, user, billCode);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_INVALIDFILETYPE);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(null);
                                return processSignerResp;
                            }

                            if (ExtFunc.checkFileType(byteData, fileType).compareTo(ExtFunc.C_FILETYPE_XML) == 0) {
                                unsignedData = new String(byteData);
                            }

                        } else {
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_EXTERNAL_FILE_GET,
                                    Defines.ERROR_EXTERNAL_FILE_GET, channelName, user, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(Defines.CODE_EXTERNAL_FILE_GET);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(null);
                            return processSignerResp;
                        }
                    }
                } else {
                    // P2P
                    if (externalStorage.compareTo(Defines.EXTERNAL_STORAGE_LOCAL) != 0) {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                                Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    }

                    if (byteData == null) {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                                Defines.ERROR_NOBASE64FILE, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_NOBASE64FILE);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    }

                    if (fileType.equals("")) {
                        LOG.error("File Type cannot be null or empty");
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDFILETYPE,
                                Defines.ERROR_INVALIDFILETYPE, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_INVALIDFILETYPE);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    }

                    if (ExtFunc.checkFileType(byteData, fileType).compareTo(ExtFunc.C_FILETYPE_XML) == 0) {
                        unsignedData = new String(byteData);
                    }
                }

                // call MultiSigner
                requestMetadata.add(fileExtension);

                final int requestId = random.nextInt();
                final int workerId = getWorkerId(workerIdOrName);

                if (workerId < 1) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                            Defines.ERROR_NOWORKER, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_NOWORKER);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
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

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                }

                if (!(resp instanceof GenericSignResponse)) {
                    LOG.error("resp is not a instance of GenericSignResponse");

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                            Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                } else {
                    final GenericSignResponse signResponse = (GenericSignResponse) resp;
                    if (signResponse.getRequestID() != requestId) {
                        LOG.error("Response ID " + signResponse.getRequestID()
                                + " not matching request ID " + requestId);

                        String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                                Defines.ERROR_NOTMATCHID, channelName, user, billCode);


                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_NOTMATCHID);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;

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

                        boolean isResponseOtp = signResponse.isResponseOTP();
                        String pData = null;
                        if (isResponseOtp) {
                            pData = ExtFunc.genResponseMessage(Defines.CODE_OTP_STATUS_WAIT,
                                    Defines.OTP_STATUS_WAIT, channelName, user, billCode);
                            pData += "<OTP>" + otp + "</OTP>";
                        } else {
                            pData = ExtFunc.genResponseMessage(Defines.CODE_OTP_STATUS_WAIT,
                                    Defines.OTP_STATUS_WAIT, channelName, user, billCode);
                        }

                        String streamPath = Defines.TMP_DIR + "/" + UUID.randomUUID().toString();
                        try {
                            FileOutputStream output = new FileOutputStream(new File(streamPath));
                            IOUtils.write(byteData, output);
                            output.close();
                        } catch (Exception e) {
                            e.printStackTrace();
                        }

                        boolean res = DBConnector.getInstances().authInsertPKITransaction(ExtFunc.getTransId(billCode), otp, transactionData, otpInformationID, otpMethod, Defines.OTP_STATUS_WAIT, streamPath, fileType,
                                fileId, fileName, fileMineType, fileDisplayValue);

                        if (otpMethod.equals(Defines._OTPEMAIL)) {

                            String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(Defines.CONNECTION_PARAMS_SMTP);
                            if (endpointParams == null) {
                                pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                                        Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(null);
                                return processSignerResp;

                            }

                            String email = DBConnector.getInstances().authGetEmailOTP(
                                    channelName, user);
                            otpInformation = DBConnector.getInstances().OTPInformationGeneration(transactionData, otp);

                            EndpointServiceResp endpointServiceResp = EndpointService.getInstance().sendEmail(channelName, user, email, subject, otpInformation, endpointParams[1], Integer.parseInt(endpointParams[2]), trustedHubTransId);

                        } else {
                            final String phoneNo = DBConnector.getInstances().authGetPhoneNoOTP(channelName, user);
                            otpInformation = DBConnector.getInstances().OTPInformationGeneration(
                                    ExtFunc.removeAccent(transactionData), otp);

                            String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(Defines.CONNECTION_PARAMS_SMPP);

                            if (endpointParams == null) {
                                pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                                        Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(null);
                                return processSignerResp;
                            }

                            EndpointServiceResp endpointServiceResp = EndpointService.getInstance().sendSms(channelName, user, phoneNo, otpInformation, endpointParams[1], Integer.parseInt(endpointParams[2]), trustedHubTransId);
                        }

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_OTP_STATUS_WAIT);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    } else {

                        String pData = ExtFunc.genResponseMessage(responseCode,
                                responseMessage, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(responseCode);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    }
                }

            } else if (method.compareTo(Defines.WORKER_OATHRESPONSE) == 0) {
                // OATHResponse
                if (_otp.compareTo("") == 0
                        || _billCode.compareTo("") == 0) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                }

                int preTrustedHubTransId = ExtFunc.getTransId(_billCode);

                if (preTrustedHubTransId == 1) {
                    LOG.error("Invalid billCode " + _billCode);
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                }
                // store check OTP co bi lock hay ko
                int otpCheck = DBConnector.getInstances().checkHWOTP(
                        channelName, user);
                if (otpCheck == 1 || otpCheck == 2) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_OTPLOCKED,
                            Defines.ERROR_OTPLOCKED, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_OTPLOCKED);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processSignerResp;
                } else if (otpCheck == -1) {

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                            Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processSignerResp;
                }

                // call MultiSigner
                requestMetadata.add(fileExtension);

                final int requestId = random.nextInt();
                final int workerId = getWorkerId(workerIdOrName);

                if (workerId < 1) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                            Defines.ERROR_NOWORKER, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_NOWORKER);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processSignerResp;
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

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processSignerResp;
                }

                if (!(resp instanceof GenericSignResponse)) {
                    LOG.error("resp is not a instance of GenericSignResponse");

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                            Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processSignerResp;
                } else {
                    final GenericSignResponse signResponse = (GenericSignResponse) resp;
                    if (signResponse.getRequestID() != requestId) {
                        LOG.error("Response ID " + signResponse.getRequestID()
                                + " not matching request ID " + requestId);

                        String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                                Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_NOTMATCHID);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                        return processSignerResp;
                    }

                    int responseCode = signResponse.getResponseCode();
                    String responseMessage = signResponse.getResponseMessage();

                    if (responseCode == Defines.CODE_SUCCESS) {
                        // verify otp success and
                        // response sigend file
                        if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                            DBConnector.getInstances().increaseSuccessTransaction();
                        }

                        DBConnector.getInstances().resetErrorCounterHWOTP(
                                channelName, user);
                        byte[] signedFile = signResponse.getProcessedData();

                        if (fileType.compareToIgnoreCase("xml") == 0) {
                            signedData = new String(signedFile);
                        }

                        String signingcert = null;
                        try {
                            signingcert = signResponse.getSignerCertificate() == null ? new String(
                                    Base64.encode(signResponse.getSignerCertificateChainBytes()))
                                    : new String(Base64.encode(signResponse.getSignerCertificate().getEncoded()));
                        } catch (CertificateEncodingException e) {
                            LOG.error("Something wrong: " + e.getMessage());
                            e.printStackTrace();
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                            return processSignerResp;
                        }

                        if (externalStorage.compareTo("") == 0
                                || externalStorage.compareTo(Defines.EXTERNAL_STORAGE_LOCAL) == 0) {
                            String pData = ExtFunc.genResponseMessage(responseCode,
                                    responseMessage, channelName, user, fileType,
                                    signingcert, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(responseCode);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setFileData(signedFile); // SUCCESS
                            processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                            return processSignerResp;
                        } else {

                            String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(externalStorage);

                            if (endpointParams == null) {
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                                        Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                                return processSignerResp;
                            }

                            String citizenId = ExtFunc.getContent(Defines._CITIZENID, xmlData);
                            String applicationId = ExtFunc.getContent(Defines._APPLICATIONID, xmlData);
                            String userHandle = ExtFunc.getContent(Defines._USERHANDLE, xmlData);

                            Properties propertiesData = signResponse.getPropertiesData();
                            fileId = propertiesData.getProperty(Defines._FILEID);
                            fileName = propertiesData.getProperty(Defines._FILENAME);
                            fileMineType = propertiesData.getProperty(Defines._MIMETYPE);
                            fileDisplayValue = propertiesData.getProperty(Defines._DISPLAYVALUE);

                            EndpointServiceResponse endpointServiceResponse = EndpointService.getInstance().setRemoteFile(channelName,
                                    user, externalStorage, endpointParams[1], fileId, signedFile, fileDisplayValue, fileMineType,
                                    fileName, citizenId, applicationId, userHandle, Integer.parseInt(endpointParams[2]), trustedHubTransId);
                            Response response = endpointServiceResponse.getResponse();
                            if (response == null) {
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_ENDPOINTEXP,
                                        Defines.ERROR_ENDPOINTEXP, channelName, user, billCode);


                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_ENDPOINTEXP);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                                return processSignerResp;
                            }

                            if (response.getStatus().getResponseCode() == 0) {

                                List<FileDetail> fileDetails = new ArrayList<FileDetail>();

                                FileDetail fileDetail = new FileDetail();
                                fileDetail.setOldFileId(fileId);
                                fileDetail.setNewFileId(response.getRemoteFileResp() == null ? null
                                        : response.getRemoteFileResp().getFileParams().getFileId());

                                fileDetail.setMimeType(response.getRemoteFileResp() == null ? null
                                        : response.getRemoteFileResp().getFileParams().getMimeType());
                                fileDetail.setStatus(Defines.CODE_SUCCESS);
                                fileDetail.setMessage(Defines.SUCCESS);
                                fileDetail.setDigest(DatatypeConverter.printHexBinary(ExtFunc.hash(signedFile, Defines.HASH_SHA1)));

                                fileDetails.add(fileDetail);

                                String pData = ExtFunc.genFileDetailsResponseMessage(Defines.CODE_SUCCESS,
                                        Defines.SUCCESS,
                                        channelName, user, billCode,
                                        signingcert, fileDetails);


                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_SUCCESS);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                                return processSignerResp;
                            } else {
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_EXTERNAL_FILE_SET,
                                        Defines.ERROR_EXTERNAL_FILE_SET, channelName, user, billCode);


                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_EXTERNAL_FILE_SET);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                                return processSignerResp;
                            }
                        }
                    } else if (responseCode == Defines.CODE_OTP_STATUS_FAIL) {

                        otpCheck = DBConnector.getInstances().leftRetryHWOTP(
                                channelName, user);
                        if (otpCheck == -100) {

                            String pData = ExtFunc.genResponseMessage(Defines.CODE_OTPLOCKED,
                                    Defines.ERROR_OTPLOCKED, channelName, user, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(Defines.CODE_OTPLOCKED);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                            return processSignerResp;
                        }

                        String pData = ExtFunc.genResponseOATHMessage(responseCode,
                                responseMessage, channelName, user, billCode,
                                otpCheck);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(responseCode);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                        return processSignerResp;
                    } else {
                        String pData = ExtFunc.genResponseMessage(responseCode,
                                responseMessage, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(responseCode);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                        return processSignerResp;
                    }
                }

            } else if (method.compareTo(Defines.WORKER_OATHVALIDATOR) == 0) {
                // OATHValidator
                // kiem tra xem hop dong co dang ky
                // otp token hay khong
                if (!DBConnector.getInstances().authCheckOTPMethod(channelName,
                        user, Defines._OTPHARDWARE)) {

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_AGREEMENTNOTREADY,
                            Defines.ERROR_AGREEMENTNOTREADY, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_AGREEMENTNOTREADY);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                }

                if (_otp.equals("")) {

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                }

                if (externalStorage.compareTo("") != 0
                        && externalStorage.compareTo(Defines.EXTERNAL_STORAGE_LOCAL) != 0) {
                    // Get file from external server
                    if (fileId.compareTo("") == 0
                            || fileId.split(";").length > 1) {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                                Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    } else {

                        String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(externalStorage);

                        if (endpointParams == null) {
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                                    Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(null);
                            return processSignerResp;
                        }

                        EndpointServiceResponse endpointServiceResponse = EndpointService.getInstance().getRemoteFile(channelName, user,
                                externalStorage, endpointParams[1], fileId, Integer.parseInt(endpointParams[2]), trustedHubTransId);

                        Response response = endpointServiceResponse.getResponse();
                        if (response == null) {
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_ENDPOINTEXP,
                                    Defines.ERROR_ENDPOINTEXP, channelName, user, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(Defines.CODE_ENDPOINTEXP);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(null);
                            return processSignerResp;
                        }

                        if (response.getStatus().getResponseCode() == 0) {

                            byteData = response.getRemoteFileResp().getFileParams().getFileData();
                            fileType = response.getRemoteFileResp().getFileParams().getFileType();
                            fileDisplayValue = response.getRemoteFileResp().getFileParams().getDisplayValue();
                            fileMineType = response.getRemoteFileResp().getFileParams().getMimeType();
                            fileName = response.getRemoteFileResp().getFileParams().getFileName();

                            // add into metadata
                            fileExtension = new org.signserver.clientws.Metadata(Defines._FILETYPE, fileType);
                            requestMetadata.add(fileExtension);

                            if (byteData == null) {
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                                        Defines.ERROR_NOBASE64FILE, channelName, user, billCode);


                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_NOBASE64FILE);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(null);
                                return processSignerResp;
                            }

                            if (fileType.equals("")) {
                                LOG.error("File Type cannot be null or empty");
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDFILETYPE,
                                        Defines.ERROR_INVALIDFILETYPE, channelName, user, billCode);


                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_INVALIDFILETYPE);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(null);
                                return processSignerResp;
                            }

                            if (ExtFunc.checkFileType(byteData, fileType).compareTo(ExtFunc.C_FILETYPE_XML) == 0) {
                                unsignedData = new String(byteData);
                            }

                        } else {
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_EXTERNAL_FILE_GET,
                                    Defines.ERROR_EXTERNAL_FILE_GET, channelName, user, billCode);


                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(Defines.CODE_EXTERNAL_FILE_GET);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(null);
                            return processSignerResp;
                        }
                    }
                } else {
                    // P2P
                    if (externalStorage.compareTo(Defines.EXTERNAL_STORAGE_LOCAL) != 0) {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                                Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    }

                    if (byteData == null) {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                                Defines.ERROR_NOBASE64FILE, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_NOBASE64FILE);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    }

                    if (fileType.equals("")) {
                        LOG.error("File Type cannot be null or empty");
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDFILETYPE,
                                Defines.ERROR_INVALIDFILETYPE, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_INVALIDFILETYPE);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    }

                    if (ExtFunc.checkFileType(byteData, fileType).compareTo(ExtFunc.C_FILETYPE_XML) == 0) {
                        unsignedData = new String(byteData);
                    }
                }
                // call MultiSigner
                requestMetadata.add(fileExtension);

                final int requestId = random.nextInt();
                final int workerId = getWorkerId(workerIdOrName);

                if (workerId < 1) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                            Defines.ERROR_NOWORKER, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_NOWORKER);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
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

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                }

                if (!(resp instanceof GenericSignResponse)) {
                    LOG.error("resp is not a instance of GenericSignResponse");

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                            Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                } else {
                    final GenericSignResponse signResponse = (GenericSignResponse) resp;
                    if (signResponse.getRequestID() != requestId) {
                        LOG.error("Response ID " + signResponse.getRequestID()
                                + " not matching request ID " + requestId);

                        String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                                Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_NOTMATCHID);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    }

                    int responseCode = signResponse.getResponseCode();
                    String responseMessage = signResponse.getResponseMessage();

                    if (responseCode != Defines.CODE_SUCCESS) {
                        // Su dung lai store checkOTP de
                        // tra ve
                        // so lan con lai
                        if (responseCode == Defines.CODE_OTPLOCKED) {
                            // locked

                            String pData = ExtFunc.genResponseMessage(Defines.CODE_OTPLOCKED,
                                    Defines.ERROR_OTPLOCKED, channelName, user, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(Defines.CODE_OTPLOCKED);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(null);
                            return processSignerResp;
                        } else if (responseCode == Defines.CODE_OTP_STATUS_FAIL) {
                            // invalid
                            String retry = new String(
                                    signResponse.getProcessedData());

                            int otpRetry = Integer.parseInt(retry);

                            String pData = ExtFunc.genResponseMessage(responseCode,
                                    responseMessage, channelName, user, otpRetry,
                                    billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(responseCode);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(null);
                            return processSignerResp;
                        } else if (responseCode == Defines.CODE_OTPNEEDSYNC) {
                            // synch
                            String pData = ExtFunc.genResponseMessage(responseCode,
                                    responseMessage, channelName, user, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(responseCode);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(null);
                            return processSignerResp;
                        } else if (responseCode == Defines.CODE_OTP_STATUS_DISABLE) {
                            // disable
                            String pData = ExtFunc.genResponseMessage(responseCode,
                                    responseMessage, channelName, user, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(responseCode);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(null);
                            return processSignerResp;
                        } else {
                            // lost
                            String pData = ExtFunc.genResponseMessage(responseCode,
                                    responseMessage, channelName, user, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(responseCode);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(null);
                            return processSignerResp;
                        }
                    } else {

                        if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                            DBConnector.getInstances().increaseSuccessTransaction();
                        }

                        DBConnector.getInstances().resetErrorCounterHWOTP(
                                channelName, user);

                        byte[] signedFile = signResponse.getProcessedData();

                        if (fileType.compareToIgnoreCase("xml") == 0) {
                            signedData = new String(signedFile);
                        }

                        String signingcert = null;
                        try {
                            signingcert = signResponse.getSignerCertificate() == null ? new String(
                                    Base64.encode(signResponse.getSignerCertificateChainBytes()))
                                    : new String(Base64.encode(signResponse.getSignerCertificate().getEncoded()));
                        } catch (CertificateEncodingException e) {
                            LOG.error("Something wrong: " + e.getMessage());
                            e.printStackTrace();
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(null);
                            return processSignerResp;
                        }

                        if (externalStorage.compareTo("") == 0
                                || externalStorage.compareTo(Defines.EXTERNAL_STORAGE_LOCAL) == 0) {
                            String pData = ExtFunc.genResponseMessage(responseCode,
                                    responseMessage, channelName, user, fileType,
                                    signingcert, billCode);


                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(responseCode);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setFileData(signedFile); // SUCCESS
                            processSignerResp.setPreTrustedHubTransId(null);
                            return processSignerResp;
                        } else {

                            String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(externalStorage);

                            if (endpointParams == null) {
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                                        Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);


                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(null);
                                return processSignerResp;
                            }

                            String citizenId = ExtFunc.getContent(Defines._CITIZENID, xmlData);
                            String applicationId = ExtFunc.getContent(Defines._APPLICATIONID, xmlData);
                            String userHandle = ExtFunc.getContent(Defines._USERHANDLE, xmlData);

                            EndpointServiceResponse endpointServiceResponse = EndpointService.getInstance().setRemoteFile(channelName,
                                    user, externalStorage, endpointParams[1], fileId, signedFile, fileDisplayValue, fileMineType,
                                    fileName, citizenId, applicationId, userHandle, Integer.parseInt(endpointParams[2]), trustedHubTransId);
                            Response response = endpointServiceResponse.getResponse();
                            if (response == null) {
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_ENDPOINTEXP,
                                        Defines.ERROR_ENDPOINTEXP, channelName, user, billCode);


                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_ENDPOINTEXP);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(null);
                                return processSignerResp;
                            }

                            if (response.getStatus().getResponseCode() == 0) {

                                List<FileDetail> fileDetails = new ArrayList<FileDetail>();

                                FileDetail fileDetail = new FileDetail();
                                fileDetail.setOldFileId(fileId);
                                fileDetail.setNewFileId(response.getRemoteFileResp() == null ? null
                                        : response.getRemoteFileResp().getFileParams().getFileId());

                                fileDetail.setMimeType(response.getRemoteFileResp() == null ? null
                                        : response.getRemoteFileResp().getFileParams().getMimeType());
                                fileDetail.setStatus(Defines.CODE_SUCCESS);
                                fileDetail.setMessage(Defines.SUCCESS);
                                fileDetail.setDigest(DatatypeConverter.printHexBinary(ExtFunc.hash(signedFile, Defines.HASH_SHA1)));
                                fileDetails.add(fileDetail);

                                String pData = ExtFunc.genFileDetailsResponseMessage(Defines.CODE_SUCCESS,
                                        Defines.SUCCESS,
                                        channelName, user, billCode,
                                        signingcert, fileDetails);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_SUCCESS);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(null);
                                return processSignerResp;
                            } else {

                                String pData = ExtFunc.genResponseMessage(Defines.CODE_EXTERNAL_FILE_SET,
                                        Defines.ERROR_EXTERNAL_FILE_SET, channelName, user, billCode);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_EXTERNAL_FILE_SET);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(null);
                                return processSignerResp;
                            }
                        }
                    }
                }

            } else if (method.compareTo(Defines.METHOD_SYNCHRONOUSSIGN) == 0) {

                if (externalStorage.compareTo("") != 0
                        && externalStorage.compareTo(Defines.EXTERNAL_STORAGE_LOCAL) != 0) {
                    // Get file from external server
                    if (fileId.compareTo("") == 0
                            || fileId.split(";").length > 1) {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                                Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    } else {

                        String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(externalStorage);

                        if (endpointParams == null) {
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                                    Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(null);
                            return processSignerResp;
                        }

                        EndpointServiceResponse endpointServiceResponse = EndpointService.getInstance().getRemoteFile(channelName, user,
                                externalStorage, endpointParams[1], fileId, Integer.parseInt(endpointParams[2]), trustedHubTransId);

                        Response response = endpointServiceResponse.getResponse();
                        if (response == null) {
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_ENDPOINTEXP,
                                    Defines.ERROR_ENDPOINTEXP, channelName, user, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(Defines.CODE_ENDPOINTEXP);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(null);
                            return processSignerResp;
                        }

                        if (response.getStatus().getResponseCode() == 0) {

                            byteData = response.getRemoteFileResp().getFileParams().getFileData();
                            fileType = response.getRemoteFileResp().getFileParams().getFileType();
                            fileDisplayValue = response.getRemoteFileResp().getFileParams().getDisplayValue();
                            fileMineType = response.getRemoteFileResp().getFileParams().getMimeType();
                            fileName = response.getRemoteFileResp().getFileParams().getFileName();

                            // add into metadata
                            fileExtension = new org.signserver.clientws.Metadata(Defines._FILETYPE, fileType);
                            requestMetadata.add(fileExtension);

                            if (byteData == null) {
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                                        Defines.ERROR_NOBASE64FILE, channelName, user, billCode);


                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_NOBASE64FILE);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(null);
                                return processSignerResp;
                            }

                            if (fileType.equals("")) {
                                LOG.error("File Type cannot be null or empty");
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDFILETYPE,
                                        Defines.ERROR_INVALIDFILETYPE, channelName, user, billCode);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_INVALIDFILETYPE);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(null);
                                return processSignerResp;
                            }

                            if (ExtFunc.checkFileType(byteData, fileType).compareTo(ExtFunc.C_FILETYPE_XML) == 0) {
                                unsignedData = new String(byteData);
                            }

                        } else {
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_EXTERNAL_FILE_GET,
                                    Defines.ERROR_EXTERNAL_FILE_GET, channelName, user, billCode);


                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(Defines.CODE_EXTERNAL_FILE_GET);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(null);
                            return processSignerResp;
                        }
                    }
                } else {
                    // P2P
                    if (externalStorage.compareTo(Defines.EXTERNAL_STORAGE_LOCAL) != 0) {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                                Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    }

                    if (byteData == null) {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                                Defines.ERROR_NOBASE64FILE, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_NOBASE64FILE);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    }

                    if (fileType.equals("")) {
                        LOG.error("File Type cannot be null or empty");
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDFILETYPE,
                                Defines.ERROR_INVALIDFILETYPE, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_INVALIDFILETYPE);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    }

                    if (ExtFunc.checkFileType(byteData, fileType).compareTo(ExtFunc.C_FILETYPE_XML) == 0) {
                        unsignedData = new String(byteData);
                    }
                }

                String[] signserverInfo = DBConnector.getInstances().authCertificateSPKI(channelName, user);

                if (signserverInfo == null) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_AGREEMENTNOTREADY,
                            Defines.ERROR_AGREEMENTNOTREADY, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_AGREEMENTNOTREADY);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                }

                // check cert validaity
                X509Certificate signingCertificate = null;
                try {
                    signingCertificate = ExtFunc.getCertificate(signserverInfo[0]);
                } catch (Exception e) {
                    LOG.error("Error while parsing the signing certificate of user " + user);
                    e.printStackTrace();
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                            Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                }

                if (!ExtFunc.checkDataValidity(signingCertificate)) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_CERTIFICATEEXPIRED,
                            Defines.ERROR_CERTIFICATEEXPIRED, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_CERTIFICATEEXPIRED);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                }

                org.signserver.clientws.Metadata p11InfoLevel = new org.signserver.clientws.Metadata(Defines._P11INFOLEVEL, signserverInfo[1]);
                requestMetadata.add(p11InfoLevel);

                if (signserverInfo[1].compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                    // check Signserver Agreement is locked or not
                    int errorCountSignServerStatus = DBConnector.getInstances().checkErrorCountSignServer(channelName, user);

                    if (errorCountSignServerStatus == 1) {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_AGREEMENTNOTREADY,
                                Defines.ERROR_AGREEMENTNOTREADY, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_AGREEMENTNOTREADY);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    } else if (errorCountSignServerStatus == 2) {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_SIGNSERVER_PKI_LOCKED,
                                Defines.ERROR_SIGNSERVER_PKI_LOCKED, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_SIGNSERVER_PKI_LOCKED);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    } else {
                        // errorCountSignServerStatus = 0 OK
                    }

                    // check HSM Pin
                    TokenManager tokenManager = new TokenManager();
                    if (tokenManager.initialize(signserverInfo[3], Long.parseLong(signserverInfo[2]))) {
                        if (!tokenManager.authTokenPin(signerPassword)) {
                            int[] response = DBConnector.getInstances().authCheckPassSignServer(user, channelName, String.valueOf(System.currentTimeMillis()));
                            int status = response[0];
                            int retry = response[1];
                            if (status == 1) {
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_PASSWORD,
                                        Defines.ERROR_INVALID_PASSWORD, channelName, user, retry, billCode);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_INVALID_PASSWORD);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(null);
                                return processSignerResp;
                            } else {
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_SIGNSERVER_PKI_LOCKED,
                                        Defines.ERROR_SIGNSERVER_PKI_LOCKED, channelName, user, billCode);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_SIGNSERVER_PKI_LOCKED);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(null);
                                return processSignerResp;
                            }
                        } else {
                            DBConnector.getInstances().resetErrorCountSignServer(channelName, user);
                        }
                        tokenManager.release();
                    } else {
                        LOG.error("Error while initializing HSM connection");
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                                Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    }
                    AdminLayer.getInstance().activateSigner(Integer.parseInt(signserverInfo[6]), signerPassword);
                }

                // call MultiSigner
                requestMetadata.add(fileExtension);

                final int requestId = random.nextInt();
                final int workerId = getWorkerId(workerIdOrName);

                if (workerId < 1) {

                    if (signserverInfo[1].compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                        AdminLayer.getInstance().deactivateSigner(Integer.parseInt(signserverInfo[6]));
                    }

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                            Defines.ERROR_NOWORKER, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_NOWORKER);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
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

                    if (signserverInfo[1].compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                        AdminLayer.getInstance().deactivateSigner(Integer.parseInt(signserverInfo[6]));
                    }

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                            Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                }

                if (!(resp instanceof GenericSignResponse)) {
                    LOG.error("resp is not a instance of GenericSignResponse");

                    if (signserverInfo[1].compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                        AdminLayer.getInstance().deactivateSigner(Integer.parseInt(signserverInfo[6]));
                    }

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                            Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                } else {
                    final GenericSignResponse signResponse = (GenericSignResponse) resp;
                    if (signResponse.getRequestID() != requestId) {
                        LOG.error("Response ID " + signResponse.getRequestID()
                                + " not matching request ID " + requestId);

                        if (signserverInfo[1].compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                            AdminLayer.getInstance().deactivateSigner(Integer.parseInt(signserverInfo[6]));
                        }

                        String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                                Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_NOTMATCHID);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    }

                    int responseCode = signResponse.getResponseCode();
                    String responseMessage = signResponse.getResponseMessage();

                    if (responseCode == Defines.CODE_SUCCESS) {

                        if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                            DBConnector.getInstances().increaseSuccessTransaction();
                        }

                        byte[] signedFile = signResponse.getProcessedData();

                        if (ExtFunc.checkFileType(signedFile, fileType).compareTo(ExtFunc.C_FILETYPE_XML) == 0) {
                            signedData = new String(signedFile);
                        }

                        String signingcert = null;
                        try {
                            signingcert = signResponse.getSignerCertificate() == null ? new String(
                                    Base64.encode(signResponse.getSignerCertificateChainBytes()))
                                    : new String(Base64.encode(signResponse.getSignerCertificate().getEncoded()));
                        } catch (CertificateEncodingException e) {
                            LOG.error("Something wrong: " + e.getMessage());
                            e.printStackTrace();

                            if (signserverInfo[1].compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                                AdminLayer.getInstance().deactivateSigner(Integer.parseInt(signserverInfo[6]));
                            }

                            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(null);
                            return processSignerResp;
                        }

                        if (externalStorage.compareTo("") == 0
                                || externalStorage.compareTo(Defines.EXTERNAL_STORAGE_LOCAL) == 0) {

                            if (signserverInfo[1].compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                                AdminLayer.getInstance().deactivateSigner(Integer.parseInt(signserverInfo[6]));
                            }

                            String pData = ExtFunc.genResponseMessage(responseCode,
                                    responseMessage, channelName, user, fileType,
                                    signingcert, billCode);


                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(responseCode);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setFileData(signedFile); // SUCCESS
                            processSignerResp.setPreTrustedHubTransId(null);
                            return processSignerResp;
                        } else {

                            String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(externalStorage);

                            if (endpointParams == null) {

                                if (signserverInfo[1].compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                                    AdminLayer.getInstance().deactivateSigner(Integer.parseInt(signserverInfo[6]));
                                }

                                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                                        Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(null);
                                return processSignerResp;
                            }

                            String citizenId = ExtFunc.getContent(Defines._CITIZENID, xmlData);
                            String applicationId = ExtFunc.getContent(Defines._APPLICATIONID, xmlData);
                            String userHandle = ExtFunc.getContent(Defines._USERHANDLE, xmlData);

                            EndpointServiceResponse endpointServiceResponse = EndpointService.getInstance().setRemoteFile(channelName,
                                    user, externalStorage, endpointParams[1], fileId, signedFile, fileDisplayValue, fileMineType,
                                    fileName, citizenId, applicationId, userHandle, Integer.parseInt(endpointParams[2]), trustedHubTransId);
                            Response response = endpointServiceResponse.getResponse();
                            if (response == null) {

                                if (signserverInfo[1].compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                                    AdminLayer.getInstance().deactivateSigner(Integer.parseInt(signserverInfo[6]));
                                }

                                String pData = ExtFunc.genResponseMessage(Defines.CODE_ENDPOINTEXP,
                                        Defines.ERROR_ENDPOINTEXP, channelName, user, billCode);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_ENDPOINTEXP);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(null);
                                return processSignerResp;
                            }

                            if (response.getStatus().getResponseCode() == 0) {

                                List<FileDetail> fileDetails = new ArrayList<FileDetail>();

                                FileDetail fileDetail = new FileDetail();
                                fileDetail.setOldFileId(fileId);
                                fileDetail.setNewFileId(response.getRemoteFileResp() == null ? null
                                        : response.getRemoteFileResp().getFileParams().getFileId());

                                fileDetail.setMimeType(response.getRemoteFileResp() == null ? null
                                        : response.getRemoteFileResp().getFileParams().getMimeType());
                                fileDetail.setStatus(Defines.CODE_SUCCESS);
                                fileDetail.setMessage(Defines.SUCCESS);
                                fileDetail.setDigest(DatatypeConverter.printHexBinary(ExtFunc.hash(signedFile, Defines.HASH_SHA1)));
                                fileDetails.add(fileDetail);

                                if (signserverInfo[1].compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                                    AdminLayer.getInstance().deactivateSigner(Integer.parseInt(signserverInfo[6]));
                                }

                                String pData = ExtFunc.genFileDetailsResponseMessage(Defines.CODE_SUCCESS,
                                        Defines.SUCCESS,
                                        channelName, user, billCode,
                                        signingcert, fileDetails);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_SUCCESS);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(null);
                                return processSignerResp;
                            } else {

                                if (signserverInfo[1].compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                                    AdminLayer.getInstance().deactivateSigner(Integer.parseInt(signserverInfo[6]));
                                }

                                String pData = ExtFunc.genResponseMessage(Defines.CODE_EXTERNAL_FILE_SET,
                                        Defines.ERROR_EXTERNAL_FILE_SET, channelName, user, billCode);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_EXTERNAL_FILE_SET);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(null);
                                return processSignerResp;
                            }
                        }
                    } else {

                        if (responseCode == Defines.CODE_INVALID_PASSWORD) {

                            int retry = Integer.parseInt(new String(signResponse.getProcessedData()));

                            if (signserverInfo[1].compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                                AdminLayer.getInstance().deactivateSigner(Integer.parseInt(signserverInfo[6]));
                            }

                            String pData = ExtFunc.genResponseMessage(responseCode,
                                    responseMessage, channelName, user, retry, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(responseCode);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(null);
                            return processSignerResp;

                        } else {

                            if (signserverInfo[1].compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                                AdminLayer.getInstance().deactivateSigner(Integer.parseInt(signserverInfo[6]));
                            }

                            String pData = ExtFunc.genResponseMessage(responseCode,
                                    responseMessage, channelName, user, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(responseCode);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(null);
                            return processSignerResp;
                        }
                    }
                }
            } else if (method.compareTo(Defines.METHOD_SIGNREQUEST) == 0) {

                if (externalStorage.compareTo("") != 0
                        && externalStorage.compareTo(Defines.EXTERNAL_STORAGE_LOCAL) != 0) {

                    String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(externalStorage);

                    if (endpointParams == null) {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                                Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    }

                    // Get file from external server
                    if (fileId.compareTo("") == 0) {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                                Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    } else {
                        boolean p11AvancedLevel = false;
                        String workerUUID = null;
                        String[] signserverInfo = DBConnector.getInstances().authCertificateSPKI(channelName, user);

                        if (signserverInfo == null) {
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_AGREEMENTNOTREADY,
                                    Defines.ERROR_AGREEMENTNOTREADY, channelName, user, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(Defines.CODE_AGREEMENTNOTREADY);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(null);
                            return processSignerResp;
                        }

                        if (signserverInfo[1].compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                            p11AvancedLevel = true;
                            workerUUID = signserverInfo[6];
                            // check Signserver Agreement is locked or not
                            int errorCountSignServerStatus = DBConnector.getInstances().checkErrorCountSignServer(channelName, user);

                            if (errorCountSignServerStatus == 1) {
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_AGREEMENTNOTREADY,
                                        Defines.ERROR_AGREEMENTNOTREADY, channelName, user, billCode);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_AGREEMENTNOTREADY);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(null);
                                return processSignerResp;
                            } else if (errorCountSignServerStatus == 2) {
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_SIGNSERVER_PKI_LOCKED,
                                        Defines.ERROR_SIGNSERVER_PKI_LOCKED, channelName, user, billCode);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_SIGNSERVER_PKI_LOCKED);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(null);
                                return processSignerResp;
                            } else {
                                // errorCountSignServerStatus = 0 OK
                            }

                            // check HSM Pin
                            TokenManager tokenManager = new TokenManager();
                            if (tokenManager.initialize(signserverInfo[3], Long.parseLong(signserverInfo[2]))) {
                                if (!tokenManager.authTokenPin(signerPassword)) {
                                    int[] response = DBConnector.getInstances().authCheckPassSignServer(user, channelName, String.valueOf(System.currentTimeMillis()));
                                    int status = response[0];
                                    int retry = response[1];
                                    if (status == 1) {
                                        String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_PASSWORD,
                                                Defines.ERROR_INVALID_PASSWORD, channelName, user, retry, billCode);

                                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                        processSignerResp.setResponseCode(Defines.CODE_INVALID_PASSWORD);
                                        processSignerResp.setXmlData(pData);
                                        processSignerResp.setSignedData(signedData);
                                        processSignerResp.setPreTrustedHubTransId(null);
                                        return processSignerResp;
                                    } else {
                                        String pData = ExtFunc.genResponseMessage(Defines.CODE_SIGNSERVER_PKI_LOCKED,
                                                Defines.ERROR_SIGNSERVER_PKI_LOCKED, channelName, user, billCode);

                                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                        processSignerResp.setResponseCode(Defines.CODE_SIGNSERVER_PKI_LOCKED);
                                        processSignerResp.setXmlData(pData);
                                        processSignerResp.setSignedData(signedData);
                                        processSignerResp.setPreTrustedHubTransId(null);
                                        return processSignerResp;
                                    }
                                } else {
                                    DBConnector.getInstances().resetErrorCountSignServer(channelName, user);
                                }
                                tokenManager.release();
                            } else {
                                LOG.error("Error while initializing HSM connection");
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                                        Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(null);
                                return processSignerResp;
                            }
                            AdminLayer.getInstance().activateSigner(Integer.parseInt(signserverInfo[6]), signerPassword);
                        } else {
                            // BASIC
                            int[] response = DBConnector.getInstances().authCheckPassSignServer(user, channelName, signerPassword);
                            int status = response[0];
                            int retry = response[1];

                            if (status == 1) {
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_PASSWORD,
                                        Defines.ERROR_INVALID_PASSWORD, channelName, user, retry, billCode);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_INVALID_PASSWORD);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(null);
                                return processSignerResp;
                            } else if (status == 2) {
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_SIGNSERVER_PKI_LOCKED,
                                        Defines.ERROR_SIGNSERVER_PKI_LOCKED, channelName, user, billCode);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_SIGNSERVER_PKI_LOCKED);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(null);
                                return processSignerResp;
                            }
                        }

                        String pData = ExtFunc.genResponseMessage(Defines.CODE_MSSP_REQUEST_ACCEPTED,
                                Defines.MSSP_REQUEST_ACCEPTED, channelName, user, billCode);

                        String citizenId = ExtFunc.getContent(Defines._CITIZENID, xmlData);
                        String applicationId = ExtFunc.getContent(Defines._APPLICATIONID, xmlData);
                        String userHandle = ExtFunc.getContent(Defines._USERHANDLE, xmlData);

                        boolean res = DBConnector.getInstances().authInsertSignExternalStorageTransaction(ExtFunc.getTransId(billCode), Defines.SIGN_EXTERNAL_ASYNC_PROCESSING);

                        org.signserver.clientws.Metadata p11InfoLevel = new org.signserver.clientws.Metadata(Defines._P11INFOLEVEL, signserverInfo[1]);
                        requestMetadata.add(p11InfoLevel);

                        Thread t = new Thread(new SignThread(channelName, user, requestMetadata,
                                externalStorage, endpointParams[1], Integer.parseInt(endpointParams[2]), fileId,
                                workerIdOrName, trustedHubTransId, citizenId, applicationId, userHandle, p11AvancedLevel, workerUUID));
                        t.start();


                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_MSSP_REQUEST_ACCEPTED);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    }
                } else {
                    LOG.error("Asynchronous sign only supported with in external storage.");
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTSUPPORTYET,
                            Defines.ERROR_NOTSUPPORTYET, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_NOTSUPPORTYET);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                }
            } else if (method.compareTo(Defines.METHOD_SIGNRESPONSE) == 0) {

                if (_billCode.compareTo("") == 0) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                }

                int preTrustedHubTransId = ExtFunc.getTransId(_billCode);

                if (preTrustedHubTransId == 1) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processSignerResp;
                }

                String[] otpTransaction = DBConnector.getInstances().authGetAsyncTransaction(preTrustedHubTransId);
                DBConnector.getInstances().authResetOTPTransaction(preTrustedHubTransId);

                if (otpTransaction == null) {

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDTRANSACSTATUS,
                            Defines.ERROR_INVALIDTRANSACSTATUS, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INVALIDTRANSACSTATUS);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processSignerResp;
                }

                if (otpTransaction[15].compareTo(user) != 0) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDTRANSACSTATUS,
                            Defines.ERROR_INVALIDTRANSACSTATUS, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INVALIDTRANSACSTATUS);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processSignerResp;
                }

                int externalStorageResponseStatus = Integer.parseInt(otpTransaction[13]);
                String externalStorageResponseStatusDes = otpTransaction[12];

                if (externalStorageResponseStatus == Defines.SIGN_EXTERNAL_ASYNC_COMPLETED) {

                    String pData = ExtFunc.genFileDetailsResponseMessage(Defines.CODE_SUCCESS,
                            Defines.SUCCESS, channelName, user, billCode, externalStorageResponseStatusDes);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_SUCCESS);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processSignerResp;
                } else if (externalStorageResponseStatus == Defines.SIGN_EXTERNAL_ASYNC_PROCESSING) {

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_SIGN_ASYNC_PROCESSING,
                            Defines.ERROR_SIGN_ASYNC_PROCESSING, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_SIGN_ASYNC_PROCESSING);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processSignerResp;

                } else {
                    String pData = ExtFunc.genFileDetailsResponseMessage(Defines.CODE_SIGN_ASYNC_ERROR,
                            Defines.ERROR_SIGN_ASYNC_ERROR, channelName, user, billCode, null, externalStorageResponseStatusDes);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_SIGN_ASYNC_ERROR);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processSignerResp;
                }

            } else {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPKIMETHOD,
                        Defines.ERROR_INVALIDPKIMETHOD, channelName, user, billCode);

                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                processSignerResp.setResponseCode(Defines.CODE_INVALIDPKIMETHOD);
                processSignerResp.setXmlData(pData);
                processSignerResp.setSignedData(signedData);
                processSignerResp.setPreTrustedHubTransId(null);
                return processSignerResp;
            }
        } else {
            // method = null or empty
            String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPKIMETHOD,
                    Defines.ERROR_INVALIDPKIMETHOD, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_INVALIDPKIMETHOD);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        }
    }

    private ProcessSignerResp signDc(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
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
        String subject = ExtFunc.getContent(Defines._SUBJECT, xmlData);
        String signatureMethod = ExtFunc.getContent(Defines._SIGNATUREMETHOD, xmlData);

        functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
        workerIdOrName = functionName;
        int workerType = ExtFunc.getWorkerType(workerIdOrName, method, signatureMethod);

        if (workerType == 5) {
            // Signer, combind channel-user-workername
            workerIdOrName = channelName.concat("-").concat(user).concat("-").concat(functionName);
            LOG.info("Worker: " + workerIdOrName);
        }

        String fileType = ExtFunc.getContent(Defines._FILETYPE, xmlData);
        String otpMethod = ExtFunc.getContent(Defines._OTPMETHOD, xmlData);

        String transactionData = ExtFunc.getContent(Defines._TRANSACTIONDATA,
                xmlData);
        String _otp = ExtFunc.getContent(Defines._OTP, xmlData);
        String _billCode = ExtFunc.getContent(Defines._BILLCODE, xmlData);

        String externalStorage = ExtFunc.getContent(Defines._EXTERNALSTORAGE, xmlData);

        String fileId = ExtFunc.getContent(Defines._FILEID, xmlData);
        String fileDisplayValue = null;
        String fileMineType = null;
        String fileName = null;

        if (byteData != null) {
            fileType = ExtFunc.checkFileType(byteData, fileType);
        }

        List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();
        if (!metaData.equals("")) {
            requestMetadata = getMetaData(metaData);
        }

        org.signserver.clientws.Metadata fileExtension = new org.signserver.clientws.Metadata(
                Defines._FILETYPE, fileType);
        requestMetadata.add(fileExtension);

        org.signserver.clientws.Metadata channelNameOTP = new org.signserver.clientws.Metadata(
                Defines._CHANNEL, channelName);

        org.signserver.clientws.Metadata userOTP = new org.signserver.clientws.Metadata(
                Defines._USER, user);

        String[] pkiInformation = DBConnector.getInstances().authGetCertificateTPKI(channelName, user);

        if (pkiInformation == null) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_CONTRACTSTATUS,
                    Defines.ERROR_CONTRACTSTATUS, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_CONTRACTSTATUS);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        }

        org.signserver.clientws.Metadata meta_certificate = new org.signserver.clientws.Metadata(
                Defines._CERTIFICATE, pkiInformation[0]);

        requestMetadata.add(channelNameOTP);
        requestMetadata.add(userOTP);
        requestMetadata.add(meta_certificate);

        if (method.compareTo("") == 0) {
            // method = null or empty
            String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPKIMETHOD,
                    Defines.ERROR_INVALIDPKIMETHOD, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_INVALIDPKIMETHOD);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        } else {
            if (method.compareTo(Defines.METHOD_SIGNREQUEST) == 0) {

                if (externalStorage.compareTo("") != 0
                        && externalStorage.compareTo(Defines.EXTERNAL_STORAGE_LOCAL) != 0) {
                    // Get file from external server
                    if (fileId.compareTo("") == 0
                            || fileId.split(";").length > 1) {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                                Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    } else {

                        String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(externalStorage);

                        if (endpointParams == null) {
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                                    Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(null);
                            return processSignerResp;
                        }

                        EndpointServiceResponse endpointServiceResponse = EndpointService.getInstance().getRemoteFile(channelName, user,
                                externalStorage, endpointParams[1], fileId, Integer.parseInt(endpointParams[2]), trustedHubTransId);

                        Response response = endpointServiceResponse.getResponse();
                        if (response == null) {
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_ENDPOINTEXP,
                                    Defines.ERROR_ENDPOINTEXP, channelName, user, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(Defines.CODE_ENDPOINTEXP);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(null);
                            return processSignerResp;
                        }

                        if (response.getStatus().getResponseCode() == 0) {

                            byteData = response.getRemoteFileResp().getFileParams().getFileData();
                            fileType = response.getRemoteFileResp().getFileParams().getFileType();
                            fileDisplayValue = response.getRemoteFileResp().getFileParams().getDisplayValue();
                            fileMineType = response.getRemoteFileResp().getFileParams().getMimeType();
                            fileName = response.getRemoteFileResp().getFileParams().getFileName();

                            // add into metadata
                            fileExtension = new org.signserver.clientws.Metadata(Defines._FILETYPE, fileType);
                            requestMetadata.add(fileExtension);

                            if (byteData == null) {
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                                        Defines.ERROR_NOBASE64FILE, channelName, user, billCode);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_NOBASE64FILE);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(null);
                                return processSignerResp;
                            }

                            if (fileType.equals("")) {
                                LOG.error("File Type cannot be null or empty");
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDFILETYPE,
                                        Defines.ERROR_INVALIDFILETYPE, channelName, user, billCode);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_INVALIDFILETYPE);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(null);
                                return processSignerResp;
                            }

                            if (ExtFunc.checkFileType(byteData, fileType).compareTo(ExtFunc.C_FILETYPE_XML) == 0) {
                                unsignedData = new String(byteData);
                            }

                        } else {
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_EXTERNAL_FILE_GET,
                                    Defines.ERROR_EXTERNAL_FILE_GET, channelName, user, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(Defines.CODE_EXTERNAL_FILE_GET);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(null);
                            return processSignerResp;
                        }
                    }
                } else {
                    // P2P
                    if (externalStorage.compareTo(Defines.EXTERNAL_STORAGE_LOCAL) != 0) {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                                Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    }

                    if (byteData == null) {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                                Defines.ERROR_NOBASE64FILE, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_NOBASE64FILE);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    }

                    if (fileType.equals("")) {
                        LOG.error("File Type cannot be null or empty");
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDFILETYPE,
                                Defines.ERROR_INVALIDFILETYPE, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_INVALIDFILETYPE);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    }

                    if (ExtFunc.checkFileType(byteData, fileType).compareTo(ExtFunc.C_FILETYPE_XML) == 0) {
                        unsignedData = new String(byteData);
                    }

                    fileId = ExtFunc.getContent(Defines._FILEID, xmlData).equals("") ? "N/A"
                            : ExtFunc.getContent(Defines._FILEID, xmlData);
                    fileName = ExtFunc.getContent(Defines._FILENAME, xmlData);
                    fileDisplayValue = ExtFunc.getContent(Defines._FILENAME, xmlData);
                    fileMineType = ExtFunc.checkMimeType(byteData, fileType);
                }

                // call DCSigner
                requestMetadata.add(fileExtension);

                final int requestId = random.nextInt();
                final int workerId = getWorkerId(workerIdOrName);

                if (workerId < 1) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                            Defines.ERROR_NOWORKER, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_NOWORKER);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
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

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                }

                if (!(resp instanceof GenericSignResponse)) {
                    LOG.error("resp is not a instance of GenericSignResponse");

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                            Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                } else {
                    final GenericSignResponse signResponse = (GenericSignResponse) resp;
                    if (signResponse.getRequestID() != requestId) {
                        LOG.error("Response ID " + signResponse.getRequestID()
                                + " not matching request ID " + requestId);

                        String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                                Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_NOTMATCHID);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    }

                    int responseCode = signResponse.getResponseCode();
                    String responseMessage = signResponse.getResponseMessage();

                    if (responseCode == Defines.CODE_MSSP_REQUEST_ACCEPTED) {

                        byte[] needToSign = signResponse.getProcessedData();

                        java.util.Properties propertiesData = signResponse.getPropertiesData();
                        String streamDataPath = propertiesData.getProperty(Defines._STREAMDATAPATH);
                        String streamSignPath = propertiesData.getProperty(Defines._STREAMSIGNPATH);
                        String receivedFileType = propertiesData.getProperty(Defines._FILETYPE);

                        String pData = ExtFunc.genResponseMessageDc(Defines.CODE_MSSP_REQUEST_ACCEPTED,
                                Defines.MSSP_REQUEST_ACCEPTED, channelName, user, needToSign, billCode);

                        boolean res = DBConnector.getInstances().authInsertDcTPKITransaction(ExtFunc.getTransId(billCode), streamDataPath, streamSignPath, fileId, receivedFileType, fileMineType, fileName,
                                DatatypeConverter.printHexBinary(needToSign), fileDisplayValue);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_MSSP_REQUEST_ACCEPTED);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;

                    } else {

                        String pData = ExtFunc.genResponseMessage(responseCode,
                                responseMessage, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(responseCode);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(null);
                        return processSignerResp;
                    }
                }
            } else if (method.compareTo(Defines.METHOD_SIGNRESPONSE) == 0) {

                if (_billCode.compareTo("") == 0) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                }

                int preTrustedHubTransId = ExtFunc.getTransId(_billCode);

                if (preTrustedHubTransId == 1) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processSignerResp;
                }

                String signature = ExtFunc.getContent(Defines._SIGNATURE, xmlData);
                if (signature.compareTo("") == 0) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processSignerResp;
                }

                // call DCSigner
                final int requestId = random.nextInt();
                final int workerId = getWorkerId(workerIdOrName);

                if (workerId < 1) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                            Defines.ERROR_NOWORKER, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_NOWORKER);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processSignerResp;
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

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processSignerResp;
                }

                if (!(resp instanceof GenericSignResponse)) {
                    LOG.error("resp is not a instance of GenericSignResponse");

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                            Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processSignerResp;
                } else {
                    final GenericSignResponse signResponse = (GenericSignResponse) resp;
                    if (signResponse.getRequestID() != requestId) {
                        LOG.error("Response ID " + signResponse.getRequestID()
                                + " not matching request ID " + requestId);

                        String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                                Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_NOTMATCHID);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                        return processSignerResp;

                    }

                    int responseCode = signResponse.getResponseCode();
                    String responseMessage = signResponse.getResponseMessage();
                    if (responseCode == Defines.CODE_SUCCESS) {

                        LOG.info("Sign operation completed");
                        if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                            DBConnector.getInstances().increaseSuccessTransaction();
                        }

                        byte[] signedFile = signResponse.getProcessedData();
                        String signingcert = null;
                        try {
                            signingcert = signResponse.getSignerCertificate() == null ? new String(
                                    Base64.encode(signResponse.getSignerCertificateChainBytes()))
                                    : new String(Base64.encode(signResponse.getSignerCertificate().getEncoded()));

                        } catch (Exception e) {
                            LOG.error("Something wrong: " + e.getMessage());
                            e.printStackTrace();
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                            return processSignerResp;
                        }

                        if (externalStorage.compareTo("") == 0) {
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                                    Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                            return processSignerResp;
                        } else if (externalStorage.compareTo(Defines.EXTERNAL_STORAGE_LOCAL) == 0) {
                            String pData = ExtFunc.genResponseMessage(responseCode,
                                    responseMessage, channelName, user, fileType,
                                    signingcert, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(responseCode);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setFileData(signedFile); // SUCCESS
                            processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                            return processSignerResp;
                        } else {
                            String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(externalStorage);

                            if (endpointParams == null) {
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                                        Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                                return processSignerResp;
                            }

                            Properties propertiesData = signResponse.getPropertiesData();
                            try {

                                fileId = propertiesData.getProperty(Defines._FILEID);
                                fileMineType = propertiesData.getProperty(Defines._MIMETYPE);
                                fileName = propertiesData.getProperty(Defines._FILENAME);
                                fileDisplayValue = propertiesData.getProperty(Defines._DISPLAYVALUE);

                            } catch (NullPointerException e) {
                                LOG.error("SignRequest is P2P but SignResponse is ExternalStorage");
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                                        Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                                return processSignerResp;
                            }

                            String citizenId = ExtFunc.getContent(Defines._CITIZENID, xmlData);
                            String applicationId = ExtFunc.getContent(Defines._APPLICATIONID, xmlData);
                            String userHandle = ExtFunc.getContent(Defines._USERHANDLE, xmlData);

                            EndpointServiceResponse endpointServiceResponse = EndpointService.getInstance().setRemoteFile(channelName,
                                    user, externalStorage, endpointParams[1], fileId, signedFile, fileDisplayValue, fileMineType,
                                    fileName, citizenId, applicationId, userHandle, Integer.parseInt(endpointParams[2]), trustedHubTransId);

                            Response response = endpointServiceResponse.getResponse();
                            if (response == null) {
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_ENDPOINTEXP,
                                        Defines.ERROR_ENDPOINTEXP, channelName, user, billCode);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_ENDPOINTEXP);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                                return processSignerResp;
                            }

                            if (response.getStatus().getResponseCode() == 0) {

                                List<FileDetail> fileDetails = new ArrayList<FileDetail>();

                                FileDetail fileDetail = new FileDetail();
                                fileDetail.setOldFileId(fileId);

                                fileDetail.setNewFileId(response.getRemoteFileResp() == null ? null
                                        : response.getRemoteFileResp().getFileParams().getFileId());

                                fileDetail.setMimeType(response.getRemoteFileResp() == null ? null
                                        : response.getRemoteFileResp().getFileParams().getMimeType());

                                fileDetail.setStatus(Defines.CODE_SUCCESS);
                                fileDetail.setMessage(Defines.SUCCESS);
                                fileDetail.setDigest(DatatypeConverter.printHexBinary(ExtFunc.hash(signedFile, Defines.HASH_SHA1)));
                                fileDetails.add(fileDetail);

                                String pData = ExtFunc.genFileDetailsResponseMessage(Defines.CODE_SUCCESS,
                                        Defines.SUCCESS,
                                        channelName, user, billCode,
                                        signingcert, fileDetails);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_SUCCESS);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                                return processSignerResp;
                            } else {

                                String pData = ExtFunc.genResponseMessage(Defines.CODE_EXTERNAL_FILE_SET,
                                        Defines.ERROR_EXTERNAL_FILE_SET, channelName, user, billCode);

                                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                                processSignerResp.setResponseCode(Defines.CODE_EXTERNAL_FILE_SET);
                                processSignerResp.setXmlData(pData);
                                processSignerResp.setSignedData(signedData);
                                processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                                return processSignerResp;
                            }
                        }
                    } else {

                        String pData = ExtFunc.genResponseMessage(responseCode,
                                responseMessage, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(responseCode);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                        return processSignerResp;
                    }
                }

            } else {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPKIMETHOD,
                        Defines.ERROR_INVALIDPKIMETHOD, channelName, user, billCode);

                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                processSignerResp.setResponseCode(Defines.CODE_INVALIDPKIMETHOD);
                processSignerResp.setXmlData(pData);
                processSignerResp.setSignedData(signedData);
                processSignerResp.setPreTrustedHubTransId(null);
                return processSignerResp;
            }
        }
    }

    private ProcessSignerResp signAp(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
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
        String method = ExtFunc.getContent(Defines._METHOD, xmlData);
        String _billCode = ExtFunc.getContent(Defines._BILLCODE, xmlData);
        String signatureMethod = ExtFunc.getContent(Defines._SIGNATUREMETHOD, xmlData);

        functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
        workerIdOrName = functionName;
        int workerType = ExtFunc.getWorkerType(workerIdOrName, method, signatureMethod);



        int preTrustedHubTransId = ExtFunc.getTransId(_billCode);

        if (workerType == 5) {
            // Signer, combind channel-user-workername
            workerIdOrName = channelName.concat("-").concat(user).concat("-").concat(functionName);
        }
        // check PKI locked or not
        int hwPkiCheck = DBConnector.getInstances().checkHWPKI(channelName, user);

        if (hwPkiCheck == 1 || hwPkiCheck == 2) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_PKILOCKED,
                    Defines.ERROR_PKILOCKED, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_PKILOCKED);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(null);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        } else if (hwPkiCheck == -1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(null);
            processSignerResp.setPreTrustedHubTransId(null);
            return processSignerResp;
        }

        String fileType = ExtFunc.getContent(Defines._FILETYPE, xmlData);
        String externalStorage = ExtFunc.getContent(Defines._EXTERNALSTORAGE, xmlData);

        String fileId = ExtFunc.getContent(Defines._FILEID, xmlData);
        String fileDisplayValue = null;
        String fileMineType = null;
        String fileName = null;

        List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();
        if (!metaData.equals("")) {
            requestMetadata = getMetaData(metaData);
        }

        String[] pkiSim = DBConnector.getInstances().authGetPhoneNoSimPKI(channelName, user);

        if (pkiSim == null) {
            String pData = ExtFunc.genResponseMessage(Defines.CODE_CONTRACTSTATUS,
                    Defines.ERROR_CONTRACTSTATUS, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_CONTRACTSTATUS);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
            return processSignerResp;
        }

        org.signserver.clientws.Metadata channel_pkisim = new org.signserver.clientws.Metadata(Defines._CHANNEL, channelName);
        org.signserver.clientws.Metadata user_pkisim = new org.signserver.clientws.Metadata(Defines._USER, user);
        org.signserver.clientws.Metadata vendor_pkisim = new org.signserver.clientws.Metadata(Defines._PKISIMVENDOR, pkiSim[3]);
        org.signserver.clientws.Metadata phoneNo_pkisim = new org.signserver.clientws.Metadata(Defines._PKISIM, pkiSim[0]);
        org.signserver.clientws.Metadata thumbprint_pkisim = new org.signserver.clientws.Metadata(Defines._THUMBPRINT, pkiSim[2]);
        org.signserver.clientws.Metadata certificate_pkisim = new org.signserver.clientws.Metadata(Defines._CERTIFICATE, pkiSim[1]);
        org.signserver.clientws.Metadata fileExtension = new org.signserver.clientws.Metadata(Defines._FILETYPE, fileType);
        org.signserver.clientws.Metadata endpointparam_value = new org.signserver.clientws.Metadata(Defines._ENDPOINTVALUE, pkiSim[4]);
        org.signserver.clientws.Metadata endpointconfig_id = new org.signserver.clientws.Metadata(Defines._ENDPOINTCONFIGID, pkiSim[5]);
        org.signserver.clientws.Metadata trustedhub_trans_id = new org.signserver.clientws.Metadata(Defines._TRUSTEDHUBTRANSID, String.valueOf(trustedHubTransId));

        requestMetadata.add(channel_pkisim);
        requestMetadata.add(user_pkisim);
        requestMetadata.add(phoneNo_pkisim);
        requestMetadata.add(vendor_pkisim);
        requestMetadata.add(certificate_pkisim);
        requestMetadata.add(thumbprint_pkisim);
        requestMetadata.add(fileExtension);
        requestMetadata.add(endpointparam_value);
        requestMetadata.add(endpointconfig_id);
        requestMetadata.add(trustedhub_trans_id);

        if (method.compareTo(Defines.SIGNERAP_STAREG) != 0
                && method.compareTo(Defines.SIGNERAP_STRREG) != 0
                && method.compareTo(Defines.SIGNERAP_FILESTAREG) != 0
                && method.compareTo(Defines.SIGNERAP_SIGREG) != 0
                && method.compareTo(Defines.SIGNERAP_CERTREG) != 0
                && method.compareTo(Defines.SIGNERAP_AUTH_REQ) != 0
                && method.compareTo(Defines.SIGNERAP_AUTH_RESP) != 0
                && method.compareTo(Defines.SIGNERAP_CERTQUERY) != 0) {

            if (fileType.equals("")) {
                LOG.error("File Type cannot be null or empty");
                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDFILETYPE,
                        Defines.ERROR_INVALIDFILETYPE, channelName, user, billCode);

                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                processSignerResp.setResponseCode(Defines.CODE_INVALIDFILETYPE);
                processSignerResp.setXmlData(pData);
                processSignerResp.setSignedData(signedData);
                processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                return processSignerResp;
            }
        }

        if (method.equals(Defines.SIGNERAP_STAREG)
                || method.equals(Defines.SIGNERAP_STRREG)
                || method.equals(Defines.SIGNERAP_FILESTAREG)
                || method.equals(Defines.SIGNERAP_AUTH_REQ)
                || method.equals(Defines.SIGNERAP_AUTH_RESP)
                || method.equals(Defines.SIGNERAP_CERTQUERY)) {
            // do nothing
        } else {

            if (externalStorage.compareTo("") != 0
                    && externalStorage.compareTo(Defines.EXTERNAL_STORAGE_LOCAL) != 0) {
                // Get file from external server
                if (fileId.compareTo("") == 0
                        || fileId.split(";").length > 1) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processSignerResp;
                } else {
                    String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(externalStorage);

                    if (endpointParams == null) {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                                Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                        return processSignerResp;
                    }

                    EndpointServiceResponse endpointServiceResponse = EndpointService.getInstance().getRemoteFile(channelName, user,
                            externalStorage, endpointParams[1], fileId, Integer.parseInt(endpointParams[2]), trustedHubTransId);

                    Response response = endpointServiceResponse.getResponse();
                    if (response == null) {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_ENDPOINTEXP,
                                Defines.ERROR_ENDPOINTEXP, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_ENDPOINTEXP);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                        return processSignerResp;
                    }

                    if (response.getStatus().getResponseCode() == 0) {

                        byteData = response.getRemoteFileResp().getFileParams().getFileData();
                        fileType = response.getRemoteFileResp().getFileParams().getFileType();
                        fileDisplayValue = response.getRemoteFileResp().getFileParams().getDisplayValue();
                        fileMineType = response.getRemoteFileResp().getFileParams().getMimeType();
                        fileName = response.getRemoteFileResp().getFileParams().getFileName();

                        // add into metadata
                        fileExtension = new org.signserver.clientws.Metadata(Defines._FILETYPE, fileType);
                        org.signserver.clientws.Metadata mdFileId = new org.signserver.clientws.Metadata(Defines._FILEID, fileId);
                        org.signserver.clientws.Metadata mdFileName = new org.signserver.clientws.Metadata(Defines._FILENAME, fileName);
                        org.signserver.clientws.Metadata mdFileMimeType = new org.signserver.clientws.Metadata(Defines._MIMETYPE, fileMineType);
                        org.signserver.clientws.Metadata mdFileDisplayValue = new org.signserver.clientws.Metadata(Defines._DISPLAYVALUE, fileDisplayValue);

                        requestMetadata.add(fileExtension);
                        requestMetadata.add(mdFileId);
                        requestMetadata.add(mdFileName);
                        requestMetadata.add(mdFileMimeType);
                        requestMetadata.add(mdFileDisplayValue);

                        if (byteData == null) {
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                                    Defines.ERROR_NOBASE64FILE, channelName, user, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(Defines.CODE_NOBASE64FILE);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                            return processSignerResp;
                        }

                        if (fileType.equals("")) {
                            LOG.error("File Type cannot be null or empty");
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDFILETYPE,
                                    Defines.ERROR_INVALIDFILETYPE, channelName, user, billCode);

                            ProcessSignerResp processSignerResp = new ProcessSignerResp();
                            processSignerResp.setResponseCode(Defines.CODE_INVALIDFILETYPE);
                            processSignerResp.setXmlData(pData);
                            processSignerResp.setSignedData(signedData);
                            processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                            return processSignerResp;
                        }

                        if (ExtFunc.checkFileType(byteData, fileType).compareTo(ExtFunc.C_FILETYPE_XML) == 0) {
                            unsignedData = new String(byteData);
                        }

                    } else {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_EXTERNAL_FILE_GET,
                                Defines.ERROR_EXTERNAL_FILE_GET, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_EXTERNAL_FILE_GET);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                        return processSignerResp;
                    }
                }
            } else {
                // P2P
                if (externalStorage.compareTo(Defines.EXTERNAL_STORAGE_LOCAL) != 0) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                            Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processSignerResp;
                }

                if (byteData == null) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
                            Defines.ERROR_NOBASE64FILE, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_NOBASE64FILE);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processSignerResp;
                }

                if (ExtFunc.checkFileType(byteData, fileType).compareTo(ExtFunc.C_FILETYPE_XML) == 0) {
                    unsignedData = new String(byteData);
                }
            }
        }

        if (method.equals(Defines.SIGNERAP_FILESTAREG)
                || method.equals(Defines.SIGNERAP_STAREG)
                || method.equals(Defines.SIGNERAP_AUTH_RESP)) {
            if (_billCode.compareTo("") == 0) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                        Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                processSignerResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                processSignerResp.setXmlData(pData);
                processSignerResp.setSignedData(signedData);
                processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                return processSignerResp;
            }

            if (ExtFunc.getTransId(_billCode) == 1) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                        Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                processSignerResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                processSignerResp.setXmlData(pData);
                processSignerResp.setSignedData(signedData);
                processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                return processSignerResp;
            }
        }

        final int requestId = random.nextInt();
        final int workerId = getWorkerId(workerIdOrName);

        if (workerId < 1) {

            String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                    Defines.ERROR_NOWORKER, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_NOWORKER);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
            return processSignerResp;
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

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
            return processSignerResp;
        }

        if (!(resp instanceof GenericSignResponse)) {
            LOG.error("resp is not a instance of GenericSignResponse");

            String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                    Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

            ProcessSignerResp processSignerResp = new ProcessSignerResp();
            processSignerResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
            processSignerResp.setXmlData(pData);
            processSignerResp.setSignedData(signedData);
            processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
            return processSignerResp;
        } else {
            final GenericSignResponse signResponse = (GenericSignResponse) resp;
            if (signResponse.getRequestID() != requestId) {
                LOG.error("Response ID " + signResponse.getRequestID()
                        + " not matching request ID " + requestId);

                String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                        Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                processSignerResp.setResponseCode(Defines.CODE_NOTMATCHID);
                processSignerResp.setXmlData(pData);
                processSignerResp.setSignedData(signedData);
                processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                return processSignerResp;
            }

            int responseCode = signResponse.getResponseCode();
            String responseMessage = signResponse.getResponseMessage();

            if (responseCode == Defines.CODE_SUCCESS) {
                LOG.info("Sign operation completed");
                if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                    DBConnector.getInstances().increaseSuccessTransaction();
                }
                // reset error counter
                DBConnector.getInstances().resetErrorCounterHWPKI(channelName, user);

                byte[] signedFile = signResponse.getProcessedData();
                String signingcert = null;
                try {
                    if (signResponse.getSignerCertificate() != null || signResponse.getSignerCertificateChainBytes() != null) {
                        signingcert = signResponse.getSignerCertificate() == null ? new String(
                                Base64.encode(signResponse.getSignerCertificateChainBytes()))
                                : new String(Base64.encode(signResponse.getSignerCertificate().getEncoded()));
                    }

                } catch (Exception e) {
                    LOG.error("Something wrong: " + e.getMessage());
                    e.printStackTrace();
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                            Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(signedData);
                    processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processSignerResp;
                }

                if (externalStorage.compareTo("") == 0
                        || externalStorage.compareTo(Defines.EXTERNAL_STORAGE_LOCAL) == 0) {

                    if (method.compareTo(Defines.SIGNERAP_AUTH_RESP) == 0) {
                        String pData = ExtFunc.genResponseMessageForSignerAPAuth(responseCode,
                                responseMessage, channelName, user, null,
                                signingcert, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(responseCode);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setFileData(signedFile); // SUCCESS
                        processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                        return processSignerResp;

                    } else if (method.compareTo(Defines.SIGNERAP_CERTQUERY) == 0) {
                        List<SignerInfoResponse> signerInfo = signResponse.getSignerInfoResponse();
                        String signingCert = null;
                        String authCert = null;
                        for (int i = 0; i < signerInfo.size(); i++) {
                            if (signerInfo.get(i).isIsSigning()) {
                                signingCert = signerInfo.get(i).getCertificate();
                            } else {
                                authCert = signerInfo.get(i).getCertificate();
                            }
                        }
                        String pData = ExtFunc.genResponseMessageForSignerAPAuth(responseCode,
                                responseMessage, channelName, user, authCert,
                                signingCert, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(responseCode);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(null);
                        processSignerResp.setFileData(null); // SUCCESS
                        processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                        return processSignerResp;
                    } else {
                        String pData = ExtFunc.genResponseMessage(responseCode,
                                responseMessage, channelName, user, fileType,
                                signingcert, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(responseCode);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setFileData(signedFile); // SUCCESS
                        processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                        return processSignerResp;
                    }
                } else {

                    String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(externalStorage);

                    if (endpointParams == null) {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                                Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                        return processSignerResp;
                    }

                    String citizenId = ExtFunc.getContent(Defines._CITIZENID, xmlData);
                    String applicationId = ExtFunc.getContent(Defines._APPLICATIONID, xmlData);
                    String userHandle = ExtFunc.getContent(Defines._USERHANDLE, xmlData);

                    Properties propertiesData = signResponse.getPropertiesData();
                    fileId = propertiesData.getProperty(Defines._FILEID);
                    fileName = propertiesData.getProperty(Defines._FILENAME);
                    fileMineType = propertiesData.getProperty(Defines._MIMETYPE);
                    fileDisplayValue = propertiesData.getProperty(Defines._DISPLAYVALUE);

                    EndpointServiceResponse endpointServiceResponse = EndpointService.getInstance().setRemoteFile(channelName,
                            user, externalStorage, endpointParams[1], fileId, signedFile, fileDisplayValue, fileMineType,
                            fileName, citizenId, applicationId, userHandle, Integer.parseInt(endpointParams[2]), trustedHubTransId);
                    Response response = endpointServiceResponse.getResponse();
                    if (response == null) {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_ENDPOINTEXP,
                                Defines.ERROR_ENDPOINTEXP, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_ENDPOINTEXP);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                        return processSignerResp;
                    }

                    if (response.getStatus().getResponseCode() == 0) {

                        List<FileDetail> fileDetails = new ArrayList<FileDetail>();

                        FileDetail fileDetail = new FileDetail();
                        fileDetail.setOldFileId(fileId);
                        fileDetail.setNewFileId(response.getRemoteFileResp() == null ? null
                                : response.getRemoteFileResp().getFileParams().getFileId());

                        fileDetail.setMimeType(response.getRemoteFileResp() == null ? null
                                : response.getRemoteFileResp().getFileParams().getMimeType());
                        fileDetail.setStatus(Defines.CODE_SUCCESS);
                        fileDetail.setMessage(Defines.SUCCESS);
                        fileDetail.setDigest(DatatypeConverter.printHexBinary(ExtFunc.hash(signedFile, Defines.HASH_SHA1)));
                        fileDetails.add(fileDetail);

                        String pData = ExtFunc.genFileDetailsResponseMessage(Defines.CODE_SUCCESS,
                                Defines.SUCCESS,
                                channelName, user, billCode,
                                signingcert, fileDetails);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_SUCCESS);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                        return processSignerResp;
                    } else {

                        String pData = ExtFunc.genResponseMessage(Defines.CODE_EXTERNAL_FILE_SET,
                                Defines.ERROR_EXTERNAL_FILE_SET, channelName, user, billCode);

                        ProcessSignerResp processSignerResp = new ProcessSignerResp();
                        processSignerResp.setResponseCode(Defines.CODE_EXTERNAL_FILE_SET);
                        processSignerResp.setXmlData(pData);
                        processSignerResp.setSignedData(signedData);
                        processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                        return processSignerResp;
                    }
                }

            } else if (responseCode == Defines.CODE_MSSP_REQUEST_ACCEPTED) {
                java.util.Properties propertiesData = signResponse.getPropertiesData();
                String receivedRequestId = propertiesData.getProperty(Defines._TRANSACTIONCODE);
                String streamDataPath = propertiesData.getProperty(Defines._STREAMDATAPATH);
                String streamSignPath = propertiesData.getProperty(Defines._STREAMSIGNPATH);
                String transactionId = propertiesData.getProperty(Defines._TRANSACTIONID);
                String receivedFileType = propertiesData.getProperty(Defines._FILETYPE);

                String receivedFileName = propertiesData.getProperty(Defines._FILENAME);
                String receivedFileId = propertiesData.getProperty(Defines._FILEID);
                String receivedFileMimeType = propertiesData.getProperty(Defines._MIMETYPE);
                String receivedFileDisplayValue = propertiesData.getProperty(Defines._DISPLAYVALUE);

                String pData = ExtFunc.genResponseMessageDc(Defines.CODE_MSSP_REQUEST_ACCEPTED,
                        Defines.MSSP_REQUEST_ACCEPTED, channelName, user, receivedRequestId, billCode);


                boolean res = DBConnector.getInstances().authInsertDcWPKITransaction(ExtFunc.getTransId(billCode), streamDataPath, streamSignPath, transactionId, receivedFileType, receivedRequestId, receivedFileName, receivedFileId, receivedFileMimeType, receivedFileDisplayValue);


                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                processSignerResp.setResponseCode(Defines.CODE_MSSP_REQUEST_ACCEPTED);
                processSignerResp.setXmlData(pData);
                processSignerResp.setSignedData(signedData);
                processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                return processSignerResp;
            } else if (responseCode == Defines.CODE_MSSP_AUTH_FAILED) {
                int pkiCheck = DBConnector.getInstances().leftRetryHWPKI(channelName, user);
                if (pkiCheck == -100) {

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_PKILOCKED,
                            Defines.ERROR_PKILOCKED, channelName, user, billCode);

                    ProcessSignerResp processSignerResp = new ProcessSignerResp();
                    processSignerResp.setResponseCode(Defines.CODE_PKILOCKED);
                    processSignerResp.setXmlData(pData);
                    processSignerResp.setSignedData(null);
                    processSignerResp.setPreTrustedHubTransId(null);
                    return processSignerResp;
                }

                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, pkiCheck, billCode);


                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                processSignerResp.setResponseCode(responseCode);
                processSignerResp.setXmlData(pData);
                processSignerResp.setSignedData(null);
                processSignerResp.setPreTrustedHubTransId(null);
                return processSignerResp;
            } else {

                String pData = ExtFunc.genResponseMessage(responseCode,
                        responseMessage, channelName, user, billCode);

                ProcessSignerResp processSignerResp = new ProcessSignerResp();
                processSignerResp.setResponseCode(responseCode);
                processSignerResp.setXmlData(pData);
                processSignerResp.setSignedData(signedData);
                processSignerResp.setPreTrustedHubTransId(preTrustedHubTransId);
                return processSignerResp;
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
        /*
         * final HttpServletRequest servletRequest = (HttpServletRequest)
         * wsContext .getMessageContext().get(MessageContext.SERVLET_REQUEST);
         */
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
            final String authorization = null;/*
             * servletRequest .getHeader(HTTP_AUTH_BASIC_AUTHORIZATION);
             */
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
        /*
         * final LogMap logMap = LogMap.getInstance(requestContext);
         *
         * // Add HTTP specific log entries logMap.put(
         * IWorkerLogger.LOG_REQUEST_FULLURL,
         * servletRequest.getRequestURL().append("?")
         * .append(servletRequest.getQueryString()).toString());
         * logMap.put(IWorkerLogger.LOG_REQUEST_LENGTH,
         * servletRequest.getHeader("Content-Length"));
         * logMap.put(IWorkerLogger.LOG_XFORWARDEDFOR,
         * servletRequest.getHeader("X-Forwarded-For"));
         *
         * logMap.put(IWorkerLogger.LOG_WORKER_NAME,
         * getWorkerSession().getCurrentWorkerConfig(workerId)
         * .getProperty(ProcessableConfig.NAME));
         */
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
                //logMap.put(IWorkerLogger.LOG_FILENAME, fileName);
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

            String password = ExtFunc.getContent(Defines._PASSWORD, metaData);
            if (!ExtFunc.isNullOrEmpty(password)) {
                password = StringEscapeUtils.escapeXml(password);
                metaData = ExtFunc.replaceContentInXmlTag(metaData, Defines._PASSWORD, password);
            }

            String title = ExtFunc.getContent(Defines._TITLE, metaData);
            if (!ExtFunc.isNullOrEmpty(title)) {
                title = StringEscapeUtils.escapeXml(title);
                metaData = ExtFunc.replaceContentInXmlTag(metaData, Defines._TITLE, title);
            }

            String signReason = ExtFunc.getContent(Defines._SIGNREASON, metaData);
            if (!ExtFunc.isNullOrEmpty(signReason)) {
                signReason = StringEscapeUtils.escapeXml(signReason);
                metaData = ExtFunc.replaceContentInXmlTag(metaData, Defines._SIGNREASON, signReason);
            }

            String location = ExtFunc.getContent(Defines._LOCATION, metaData);
            if (!ExtFunc.isNullOrEmpty(location)) {
                location = StringEscapeUtils.escapeXml(location);
                metaData = ExtFunc.replaceContentInXmlTag(metaData, Defines._LOCATION, location);
            }

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
            e.printStackTrace();
            listMD = null;
        }
        return listMD;
    }

    public class SignThread implements Runnable {

        private String externalStorage;
        private String properties;
        private int endpointConfigId;
        private String fileId;
        private String channelName;
        private String user;
        private List<org.signserver.clientws.Metadata> requestMetadata;
        private String workerIdOrName;
        private int trustedHubTransId;
        private String signingCertificate;
        private String citizenId;
        private String applicationId;
        private String userHandle;
        private boolean p11AvancedLevel;
        private String workerUUID;

        public SignThread(String channelName, String user, List<org.signserver.clientws.Metadata> requestMetadata, String externalStorage, String properties, int endpointConfigId, String fileId, String workerIdOrName, int trustedHubTransId, String citizenId, String applicationId, String userHandle, boolean p11AvancedLevel, String workerUUID) {
            this.externalStorage = externalStorage;
            this.properties = properties;
            this.endpointConfigId = endpointConfigId;
            this.fileId = fileId;
            this.channelName = channelName;
            this.user = user;
            this.requestMetadata = requestMetadata;
            this.workerIdOrName = workerIdOrName;
            this.trustedHubTransId = trustedHubTransId;
            this.signingCertificate = null;
            this.citizenId = citizenId;
            this.applicationId = applicationId;
            this.userHandle = userHandle;
            this.p11AvancedLevel = p11AvancedLevel;
            this.workerUUID = workerUUID;
        }

        @Override
        public void run() {

            List<FileDetail> fileDetails = new ArrayList<FileDetail>();

            EndpointServiceResponse endpointServiceResponse = EndpointService.getInstance().getMultiRemoteFile(this.channelName, this.user,
                    this.externalStorage, this.properties, this.fileId, endpointConfigId, trustedHubTransId);

            Response response = endpointServiceResponse.getResponse();
            if (response != null) {
                if (response.getStatus().getResponseCode() == 0) {

                    List<FileParams> arrayOfFileParamsResp = response.getRemoteFileResp().getArrayOfFileParams();

                    for (int i = 0; i < arrayOfFileParamsResp.size(); i++) {
                        FileDetail fileDetail = new FileDetail();
                        fileDetail.setOldFileId(arrayOfFileParamsResp.get(i).getFileId());
                        fileDetail.setMimeType(arrayOfFileParamsResp.get(i).getMimeType());

                        byte[] byteData = arrayOfFileParamsResp.get(i).getFileData();
                        String fileType = arrayOfFileParamsResp.get(i).getFileType();

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
                        org.signserver.clientws.Metadata fileExtension = new org.signserver.clientws.Metadata(Defines._FILETYPE, fileType);
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
                                // Ky thanh cong

                                if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                                    DBConnector.getInstances().increaseSuccessTransaction();
                                }

                                byte[] signedFile = signResponse.getProcessedData();

                                if (signingCertificate == null) {
                                    try {
                                        signingCertificate = signResponse.getSignerCertificate() == null ? new String(
                                                Base64.encode(signResponse.getSignerCertificateChainBytes()))
                                                : new String(Base64.encode(signResponse.getSignerCertificate().getEncoded()));
                                    } catch (CertificateEncodingException e) {
                                        LOG.error("Something wrong: " + e.getMessage());
                                        e.printStackTrace();
                                    }
                                }

                                EndpointServiceResponse endpointServiceResponseInLoop = EndpointService.getInstance().setRemoteFile(this.channelName,
                                        this.user, this.externalStorage, this.properties, arrayOfFileParamsResp.get(i).getFileId(),
                                        signedFile, arrayOfFileParamsResp.get(i).getDisplayValue(),
                                        arrayOfFileParamsResp.get(i).getMimeType(),
                                        arrayOfFileParamsResp.get(i).getFileName(), this.citizenId, this.applicationId, this.userHandle, this.endpointConfigId, trustedHubTransId);

                                Response responseInLoop = endpointServiceResponseInLoop.getResponse();

                                if (responseInLoop == null) {
                                    fileDetail.setStatus(1);
                                    fileDetail.setMessage(Defines.ERROR_ENDPOINTEXP);
                                    fileDetails.add(fileDetail);
                                    continue;
                                }

                                if (responseInLoop.getStatus().getResponseCode() == 0) {
                                    fileDetail.setNewFileId(responseInLoop.getRemoteFileResp().getFileParams().getFileId());
                                    fileDetail.setDigest(DatatypeConverter.printHexBinary(ExtFunc.hash(signedFile, Defines.HASH_SHA1)));
                                    fileDetail.setStatus(0);
                                    fileDetail.setMessage(Defines.SUCCESS);
                                    fileDetails.add(fileDetail);
                                    continue;
                                } else {
                                    fileDetail.setStatus(1);
                                    fileDetail.setMessage(Defines.ERROR_EXTERNAL_FILE_SET);
                                    fileDetails.add(fileDetail);
                                    continue;
                                }
                            } else {
                                // Ky loi
                                LOG.error(responseMessage);
                                fileDetail.setStatus(1);
                                fileDetail.setMessage(responseMessage);
                                fileDetails.add(fileDetail);
                                continue;
                            }
                        }
                    } // end for loop
                    String signResult = ExtFunc.genFileDetailsResponseMessage(this.signingCertificate, fileDetails);
                    DBConnector.getInstances().authUpdateSignExternalStorageTransaction(trustedHubTransId, signResult, Defines.SIGN_EXTERNAL_ASYNC_COMPLETED);
                } else {
                    DBConnector.getInstances().authUpdateSignExternalStorageTransaction(trustedHubTransId, Defines.ERROR_EXTERNAL_FILE_GET, Defines.SIGN_EXTERNAL_ASYNC_ERROR);
                }
            } else {
                DBConnector.getInstances().authUpdateSignExternalStorageTransaction(trustedHubTransId, Defines.ERROR_EXTERNAL_FILE_GET,
                        Defines.SIGN_EXTERNAL_ASYNC_ERROR);
            }

            if (this.p11AvancedLevel) {
                AdminLayer.getInstance().deactivateSigner(Integer.parseInt(workerUUID));
            }
        }
    }
}