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
import com.tomicalab.cag360.connector.ws.*;

/**
 * Client web services implementation containing operations for requesting
 * signing etc.
 *
 * @author Markus Kilås
 * @version $Id: ClientWS.java 3444 2013-04-17 09:18:16Z malu9369 $
 */
@WebService(serviceName = "ClientWSService")
@Stateless()
public class ClientWS {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(ClientWS.class);
    // private OTPCore otpcore = null;
    private static boolean isUseContraints = true;
    private static final String HTTP_AUTH_BASIC_AUTHORIZATION = "Authorization";
    private static String SIGNSERVER_BUILD_CONFIG = System.getProperty("jboss.server.home.dir") + "/../../../../../signserver-3.4.1/conf/signserver_build.properties";
    private static String SIGNSERVER_HOME = System.getProperty("jboss.server.home.dir") + "/../../../../../signserver-3.4.1";
    private static Properties proConfig = null;
    private static Properties config = null;
    private static boolean isCheckLicense = false;

    static {
        if (config == null) {
            config = getPropertiesConfig();
        }
    }

    public static Properties getPropertiesConfig() {
        if (proConfig == null) {
            InputStream inPropFile;
            Properties tempProp = new Properties();

            try {
                File f = new File(SIGNSERVER_BUILD_CONFIG);
                if (!f.exists()) {
                    SIGNSERVER_BUILD_CONFIG = "C:/CAG360/signserver-3.4.1/conf/signserver_build.properties";
                    SIGNSERVER_HOME = "C:/CAG360/signserver-3.4.1";
                }
                inPropFile = new FileInputStream(SIGNSERVER_BUILD_CONFIG);
                tempProp.load(inPropFile);
                inPropFile.close();
            } catch (IOException ioe) {
                LOG.error("Something wrong: " + ioe.getMessage());
            }
            return tempProp;
        }
        return proConfig;
    }
    @Resource
    private WebServiceContext wsContext;
    @EJB
    private IWorkerSession.ILocal workersession;

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
    private final Random random = new Random();

    @WebMethod(operationName = "processData")
    public TransactionInfo processData(
            @WebParam(name = "transInfo") TransactionInfo transInfo)
            throws RequestFailedException, InternalServerException {

        if (transInfo == null) {
            throw new InternalServerException("TransactionInfo cannot be null");
        }

        if (transInfo.getCredentialData() == null) {
            throw new InternalServerException("CAGCredential cannot be null");
        }


        String functionName = null;
        String workerIdOrName = null;

        CAGCredential cagCredential = transInfo.getCredentialData();
        String jsonRequest = Utils.processTransactionInfo(transInfo);
        int dataInId = DBConnector.getInstances().insertDataIn(jsonRequest);
        String unsignedData = "";
        String signedData = "";
        String fileType = "";
        byte[] byteData = transInfo.getFileData();

        String xmlData = "";
        String channelName = "";
        String user = "";
        String clientBillCode = "";

        String username = "";
        String password = "";
        String timestamp = "";
        String signature = "";
        String pkcs1Signature = "";

        try {
            xmlData = transInfo.getXmlData();
            channelName = ExtFunc.getContent(Defines._CHANNEL, xmlData);
            user = ExtFunc.getContent(Defines._USER, xmlData);
            clientBillCode = ExtFunc.getContent(Defines._ID, xmlData);

            username = cagCredential.getUsername();
            password = cagCredential.getPassword();
            timestamp = cagCredential.getTimestamp();
            signature = cagCredential.getSignature();
            pkcs1Signature = cagCredential.getPkcs1Signature();
        } catch (NullPointerException e) {
            LOG.error("Some params is NULL.");
        }

        workerIdOrName = functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
        if (workerIdOrName.compareTo("") == 0) {
            workerIdOrName = functionName = "FunctionError";
        }

        unsignedData = StringEscapeUtils.unescapeHtml(ExtFunc.getContent(Defines._SIGNEDDATA, xmlData));

        String method = ExtFunc.getContent(Defines._METHOD, xmlData);
        String signatureMethod = ExtFunc.getContent(Defines._SIGNATUREMETHOD, xmlData);

        int workerType = ExtFunc.getWorkerType(workerIdOrName, method, signatureMethod);
        if (workerType == 5) {
            workerIdOrName = channelName.concat("-").concat(user).concat("-").concat(functionName);
        }

        if (byteData != null) {
            if (ExtFunc.checkFileType(byteData, ExtFunc.C_FILETYPE_XML).compareTo(ExtFunc.C_FILETYPE_PDF) != 0
                    && ExtFunc.checkFileType(byteData, fileType).compareTo(ExtFunc.C_FILETYPE_OFFICE) != 0) {
                if (workerType == 5) {
                    unsignedData = new String(byteData);
                } else {
                    unsignedData = StringEscapeUtils.unescapeHtml(ExtFunc.getContent(Defines._SIGNEDDATA, xmlData));
                }
            }
        }

        // Check agreement status
        int[] infoUser = DBConnector.getInstances().getAgreementStatusUser(user, channelName,
                ExtFunc.getWorkerType(functionName, method, signatureMethod));

        int agreementStatus = infoUser[0];
        int agreementId = infoUser[1];

        if (workerIdOrName.equals(Defines.WORKER_AGREEMENT)) {
            String action = ExtFunc.getContent(Defines._ACTION, xmlData);
            if (action.equals(Defines.AGREEMENT_ACTION_VALIDA)) {
                user = Defines.USER_SYSTEM;
            }
        } else if (workerIdOrName.equals(Defines.WORKER_GENERALVALIDATOR)) {
            user = Defines.USER_SYSTEM;
        }

        String billCode = DBConnector.getInstances().insertTrustedHubTransaction(
                user,
                getRequestIP(),
                workerIdOrName,
                clientBillCode,
                channelName,
                xmlData,
                unsignedData,
                functionName,
                dataInId,
                null,
                agreementId,
                false);

        int trustedHubTransId = ExtFunc.getTransId(billCode);

        if (cagCredential == null || xmlData == null) {
            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_INVALIDPARAMETER,
                    Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

            DBConnector.getInstances().updateTrustedHubTransaction(
                    trustedHubTransId,
                    Defines.CODE_INVALIDPARAMETER,
                    pData,
                    signedData,
                    null,
                    null);

            TransactionInfo transResp = new TransactionInfo(pData);
            String jsonResp = Utils.processTransactionInfo(transResp);
            DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
            return transResp;
        }

        String transactionData = ExtFunc.getContent(Defines._TRANSACTIONDATA,
                xmlData);

        String subject = ExtFunc.getContent(Defines._SUBJECT, xmlData);
        String _billCode = ExtFunc.getContent(Defines._BILLCODE, xmlData);
        String _otp = ExtFunc.getContent(Defines._OTP, xmlData);

        String _signedData = StringEscapeUtils.unescapeHtml(ExtFunc.getContent(
                Defines._SIGNEDDATA, xmlData));

        String fileDisplayValue = null;
        String fileMineType = null;
        String fileName = null;

        if (username == null || password == null /*
                 * || timestamp == null
                 */
                || signature == null || pkcs1Signature == null) {

            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_INVALIDCREDENTIAL,
                    Defines.ERROR_INVALIDCREDENTIAL, channelName, user, billCode);

            DBConnector.getInstances().updateTrustedHubTransaction(
                    trustedHubTransId,
                    Defines.CODE_INVALIDCREDENTIAL,
                    pData,
                    signedData,
                    null,
                    null);

            TransactionInfo transResp = new TransactionInfo(pData);
            String jsonResp = Utils.processTransactionInfo(transResp);
            DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
            return transResp;
        }

        if (channelName.equals("")) {
            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_INVALIDCHANNEL,
                    Defines.ERROR_INVALIDCHANNEL, channelName, user, billCode);

            DBConnector.getInstances().updateTrustedHubTransaction(
                    trustedHubTransId,
                    Defines.CODE_INVALIDCHANNEL,
                    pData,
                    signedData,
                    null,
                    null);

            TransactionInfo transResp = new TransactionInfo(pData);
            String jsonResp = Utils.processTransactionInfo(transResp);
            DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
            return transResp;
        }
        //--------------------------------------------------------------------------------
        License licInfo = License.getInstance();
        if (licInfo.getStatusCode() != 0) {
            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_INFO_LICENSE,
                    Defines.ERROR_INFO_LICENSE, channelName, user, billCode);

            DBConnector.getInstances().updateTrustedHubTransaction(
                    trustedHubTransId,
                    Defines.CODE_INFO_LICENSE,
                    pData,
                    signedData,
                    null,
                    null);

            TransactionInfo transResp = new TransactionInfo(pData);
            String jsonResp = Utils.processTransactionInfo(transResp);
            DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
            return transResp;
        } else {
            if (!licInfo.checkTransaction()) {

                String pData = ExtFunc.genResponseMessage(
                        Defines.CODE_INFO_LICENSE_PERFORMANCE,
                        Defines.ERROR_INFO_LICENSE_PERFORMANCE, channelName, user, billCode);

                DBConnector.getInstances().updateTrustedHubTransaction(
                        trustedHubTransId,
                        Defines.CODE_INFO_LICENSE_PERFORMANCE,
                        pData,
                        signedData,
                        null,
                        null);

                TransactionInfo transResp = new TransactionInfo(pData);
                String jsonResp = Utils.processTransactionInfo(transResp);
                DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
                return transResp;
            }
        }
        /*
         * // Chi co ham xac thuc hop dong bang CTS moi khong can User if
         * (ExtFunc.getContent(Defines._WORKERNAME, xmlData).equals(
         * Defines.WORKER_AGREEMENT) && ExtFunc.getContent(Defines._ACTION,
         * xmlData).equals( Defines.AGREEMENT_ACTION_VALIDA)) { // do nothing //
         * chi co ham huy hop dong hang loat moi khong can User } else if
         * (ExtFunc.getContent(Defines._WORKERNAME, xmlData).equals(
         * Defines.WORKER_AGREEMENT) && ExtFunc.getContent(Defines._ACTION,
         * xmlData).equals( Defines.AGREEMENT_ACTION_MULTI_UNREG)) { // do
         * nothing } else {
         *
         * }
         */
        /*
         * boolean isValidChannel =
         * DBConnector.getInstances().checkChannelCode(channelName);
         *
         * if (!isValidChannel) {
         *
         * String pData = ExtFunc.genResponseMessage(
         * Defines.CODE_INVALIDCHANNEL, Defines.ERROR_INVALIDCHANNEL,
         * channelName, user, billCode);
         *
         * DBConnector.getInstances().updateTrustedHubTransaction(
         * trustedHubTransId, Defines.CODE_INVALIDCHANNEL, pData, signedData,
         * null, null);
         *
         * TransactionInfo transResp = new TransactionInfo(pData); String
         * jsonResp = Utils.processTransactionInfo(transResp);
         * DBConnector.getInstances().insertDataOut(jsonResp, dataInId); return
         * transResp; } else {
         *
         * }
         */
        String result = DBConnector.getInstances().readDataBase(channelName,
                getRequestIP(), cagCredential.getUsername(),
                cagCredential.getPassword(), cagCredential.getSignature(),
                cagCredential.getTimestamp(),
                cagCredential.getPkcs1Signature());

        if (result.equals(Defines.ERROR_INVALIDLOGININFO)) {
            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_INVALIDLOGININFO,
                    Defines.ERROR_INVALIDLOGININFO, channelName, user, billCode);

            DBConnector.getInstances().updateTrustedHubTransaction(
                    trustedHubTransId,
                    Defines.CODE_INVALIDLOGININFO,
                    pData,
                    signedData,
                    null,
                    null);

            TransactionInfo transResp = new TransactionInfo(pData);
            String jsonResp = Utils.processTransactionInfo(transResp);
            DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
            return transResp;
        } else if (result.equals(Defines.ERROR_INVALIDSIGNATURE)) {
            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_INVALIDSIGNATURE,
                    Defines.ERROR_INVALIDSIGNATURE, channelName, user, billCode);

            DBConnector.getInstances().updateTrustedHubTransaction(
                    trustedHubTransId,
                    Defines.CODE_INVALIDSIGNATURE,
                    pData,
                    signedData,
                    null,
                    null);

            TransactionInfo transResp = new TransactionInfo(pData);
            String jsonResp = Utils.processTransactionInfo(transResp);
            DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
            return transResp;
        } else if (result.equals(Defines.ERROR_INVALIDIP)) {
            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_INVALIDIP,
                    Defines.ERROR_INVALIDIP, channelName, user, billCode);

            DBConnector.getInstances().updateTrustedHubTransaction(
                    trustedHubTransId,
                    Defines.CODE_INVALIDIP,
                    pData,
                    signedData,
                    null,
                    null);

            TransactionInfo transResp = new TransactionInfo(pData);
            String jsonResp = Utils.processTransactionInfo(transResp);
            DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
            return transResp;
        } else {
            try {
                // do operation
                functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);

                if (functionName.equals("")) {

                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INVALIDWORKERNAME,
                            Defines.ERROR_INVALIDWORKERNAME, channelName, user, billCode);

                    DBConnector.getInstances().updateTrustedHubTransaction(
                            trustedHubTransId,
                            Defines.CODE_INVALIDWORKERNAME,
                            pData,
                            signedData,
                            null,
                            null);

                    TransactionInfo transResp = new TransactionInfo(pData);
                    String jsonResp = Utils.processTransactionInfo(transResp);
                    DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
                    return transResp;
                }

                workerIdOrName = functionName;
                if (workerType == 5) {
                    // Signer, combind channel-user-workername
                    workerIdOrName = channelName.concat("-").concat(user).concat("-").concat(functionName);
                }
                final int workerId = getWorkerId(workerIdOrName);

                // Check WorkerName and ChannelName for permission
                boolean isAllow = false;
                if (DBConnector.getInstances().getIsFunctionAccess() == 1) {
                    isAllow = DBConnector.getInstances().authCheckRelation(
                            channelName, functionName);
                    if (!isAllow) {

                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_INVALIDFUNCTION,
                                Defines.ERROR_INVALIDFUNCTION, channelName, user, billCode);

                        DBConnector.getInstances().updateTrustedHubTransaction(
                                trustedHubTransId,
                                Defines.CODE_INVALIDFUNCTION,
                                pData,
                                signedData,
                                null,
                                null);

                        TransactionInfo transResp = new TransactionInfo(pData);
                        String jsonResp = Utils.processTransactionInfo(transResp);
                        DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
                        return transResp;
                    }
                }

                if (workerType == 5) {
                    // SIGNER
                    LOG.info("SIGNER PARTS");
                    ProcessSigner ps = new ProcessSigner(wsContext, workersession);
                    ProcessSignerResp signerResp = ps.processData(transInfo, trustedHubTransId, agreementStatus, billCode);

                    DBConnector.getInstances().updateTrustedHubTransaction(
                            trustedHubTransId,
                            signerResp.getResponseCode(),
                            signerResp.getXmlData(),
                            signerResp.getSignedData(),
                            signerResp.getPreTrustedHubTransId(),
                            null);

                    TransactionInfo tranResp = new TransactionInfo();
                    tranResp.setXmlData(signerResp.getXmlData());
                    tranResp.setFileData(signerResp.getFileData());
                    
                    String fileHash = transInfo.getFileData() != null ? 
                            DatatypeConverter.printHexBinary(ExtFunc.hash(transInfo.getFileData(), "SHA-1")) 
                            : "";
                    
                    LOG.info("FileDataHash: " + fileHash);
                    LOG.info("XMLReq["+fileHash+"]:\n" + transInfo.getXmlData());
                    String signedFileHash = signerResp.getFileData() != null ? 
                            DatatypeConverter.printHexBinary(ExtFunc.hash(signerResp.getFileData(), "SHA-1")) : "";
                    LOG.info("SignedFileDataHash["+fileHash+"]: " + signedFileHash);

                    String jsonResp = Utils.processTransactionInfo(tranResp);
                    DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
                    return tranResp;
                } else if (workerType == 8) {
                    // SIGNER AP
                    LOG.info("SIGNERAP PARTS");
                    ProcessSigner ps = new ProcessSigner(wsContext, workersession);
                    ProcessSignerResp signerResp = ps.processData(transInfo, trustedHubTransId, agreementStatus, billCode);

                    DBConnector.getInstances().updateTrustedHubTransaction(
                            trustedHubTransId,
                            signerResp.getResponseCode(),
                            signerResp.getXmlData(),
                            signerResp.getSignedData(),
                            signerResp.getPreTrustedHubTransId(),
                            null);

                    TransactionInfo tranResp = new TransactionInfo();
                    tranResp.setXmlData(signerResp.getXmlData());
                    tranResp.setFileData(signerResp.getFileData());

                    String jsonResp = Utils.processTransactionInfo(tranResp);
                    DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
                    return tranResp;
                } else if (workerType == 2) {
                    // PKI VALIDATOR
                    LOG.info("PKI VALIDATOR PARTS");
                    ProcessValidator pv = new ProcessValidator(wsContext, workersession);
                    ProcessValidatorResp pkiValidatorResp = pv.processData(transInfo, trustedHubTransId, agreementStatus, billCode);

                    DBConnector.getInstances().updateTrustedHubTransaction(
                            trustedHubTransId,
                            pkiValidatorResp.getResponseCode(),
                            pkiValidatorResp.getXmlData(),
                            pkiValidatorResp.getSignedData(),
                            pkiValidatorResp.getPreTrustedHubTransId(),
                            null);

                    TransactionInfo tranResp = new TransactionInfo();
                    tranResp.setXmlData(pkiValidatorResp.getXmlData());
                    tranResp.setFileData(pkiValidatorResp.getFileData());

                    String jsonResp = Utils.processTransactionInfo(tranResp);
                    DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
                    return tranResp;
                } else if (workerType == 7) {
                    // LPKI VALIDATOR
                    LOG.info("LPKI VALIDATOR PARTS");
                    ProcessValidator pv = new ProcessValidator(wsContext, workersession);
                    ProcessValidatorResp pkiValidatorResp = pv.processData(transInfo, trustedHubTransId, agreementStatus, billCode);

                    DBConnector.getInstances().updateTrustedHubTransaction(
                            trustedHubTransId,
                            pkiValidatorResp.getResponseCode(),
                            pkiValidatorResp.getXmlData(),
                            pkiValidatorResp.getSignedData(),
                            pkiValidatorResp.getPreTrustedHubTransId(),
                            null);

                    TransactionInfo tranResp = new TransactionInfo();
                    tranResp.setXmlData(pkiValidatorResp.getXmlData());
                    tranResp.setFileData(pkiValidatorResp.getFileData());

                    String jsonResp = Utils.processTransactionInfo(tranResp);
                    DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
                    return tranResp;
                } else if (workerType == 1) {
                    // HARDWARE OTP
                    LOG.info("OTP HARDWARE PARTS");
                    ProcessValidator pv = new ProcessValidator(wsContext, workersession);
                    ProcessValidatorResp pkiValidatorResp = pv.processData(transInfo, trustedHubTransId, agreementStatus, billCode);

                    DBConnector.getInstances().updateTrustedHubTransaction(
                            trustedHubTransId,
                            pkiValidatorResp.getResponseCode(),
                            pkiValidatorResp.getXmlData(),
                            pkiValidatorResp.getSignedData(),
                            pkiValidatorResp.getPreTrustedHubTransId(),
                            null);

                    TransactionInfo tranResp = new TransactionInfo();
                    tranResp.setXmlData(pkiValidatorResp.getXmlData());
                    tranResp.setFileData(pkiValidatorResp.getFileData());

                    String jsonResp = Utils.processTransactionInfo(tranResp);
                    DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
                    return tranResp;
                } else if (workerType == 3) {
                    // OTP EMAIL
                    LOG.info("OTP EMAIL PARTS");
                    ProcessValidator pv = new ProcessValidator(wsContext, workersession);
                    ProcessValidatorResp pkiValidatorResp = pv.processData(transInfo, trustedHubTransId, agreementStatus, billCode);

                    DBConnector.getInstances().updateTrustedHubTransaction(
                            trustedHubTransId,
                            pkiValidatorResp.getResponseCode(),
                            pkiValidatorResp.getXmlData(),
                            pkiValidatorResp.getSignedData(),
                            pkiValidatorResp.getPreTrustedHubTransId(),
                            null);

                    TransactionInfo tranResp = new TransactionInfo();
                    tranResp.setXmlData(pkiValidatorResp.getXmlData());
                    tranResp.setFileData(pkiValidatorResp.getFileData());

                    String jsonResp = Utils.processTransactionInfo(tranResp);
                    DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
                    return tranResp;
                } else if (workerType == 4) {
                    // OTP SMS
                    LOG.info("OTP SMS PARTS");
                    ProcessValidator pv = new ProcessValidator(wsContext, workersession);
                    ProcessValidatorResp pkiValidatorResp = pv.processData(transInfo, trustedHubTransId, agreementStatus, billCode);

                    DBConnector.getInstances().updateTrustedHubTransaction(
                            trustedHubTransId,
                            pkiValidatorResp.getResponseCode(),
                            pkiValidatorResp.getXmlData(),
                            pkiValidatorResp.getSignedData(),
                            pkiValidatorResp.getPreTrustedHubTransId(),
                            null);

                    TransactionInfo tranResp = new TransactionInfo();
                    tranResp.setXmlData(pkiValidatorResp.getXmlData());
                    tranResp.setFileData(pkiValidatorResp.getFileData());

                    String jsonResp = Utils.processTransactionInfo(tranResp);
                    DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
                    return tranResp;
                } else if (workerType == 6) {
                    // AGREEMENT
                    LOG.info("AGREEMENT PARTS");
                    //ProcessAgreement pa = new ProcessAgreement(wsContext, workersession);
                    //ProcessAgreementResp agreememtRes = pa.processData(transInfo, trustedHubTransId, billCode);
                    ProcessAgreement.init(wsContext, workersession);
                    ProcessAgreementResp agreememtRes = ProcessAgreement.processData(transInfo, trustedHubTransId, billCode);

                    DBConnector.getInstances().updateTrustedHubTransaction(
                            trustedHubTransId,
                            agreememtRes.getResponseCode(),
                            agreememtRes.getXmlData(),
                            agreememtRes.getSignedData(),
                            agreememtRes.getPreTrustedHubTransId(),
                            agreememtRes.getAgreementId());

                    TransactionInfo tranResp = new TransactionInfo();
                    tranResp.setXmlData(agreememtRes.getXmlData());

                    String jsonResp = Utils.processTransactionInfo(tranResp);
                    DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
                    return tranResp;
                } else if (workerType == 9) {
                    // SIGNSERVER VALIDATOR
                    LOG.info("SIGNSERVER VALIDATOR PARTS");
                    ProcessValidator pv = new ProcessValidator(wsContext, workersession);
                    ProcessValidatorResp pkiValidatorResp = pv.processData(transInfo, trustedHubTransId, agreementStatus, billCode);

                    DBConnector.getInstances().updateTrustedHubTransaction(
                            trustedHubTransId,
                            pkiValidatorResp.getResponseCode(),
                            pkiValidatorResp.getXmlData(),
                            pkiValidatorResp.getSignedData(),
                            pkiValidatorResp.getPreTrustedHubTransId(),
                            null);

                    TransactionInfo tranResp = new TransactionInfo();
                    tranResp.setXmlData(pkiValidatorResp.getXmlData());
                    tranResp.setFileData(pkiValidatorResp.getFileData());

                    String jsonResp = Utils.processTransactionInfo(tranResp);
                    DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
                    return tranResp;
                } else if (workerType == 10) {
                    // WPKI VALIDATOR
                    LOG.info("WPKI VALIDATOR PARTS");
                    ProcessValidator pv = new ProcessValidator(wsContext, workersession);
                    ProcessValidatorResp pkiValidatorResp = pv.processData(transInfo, trustedHubTransId, agreementStatus, billCode);

                    DBConnector.getInstances().updateTrustedHubTransaction(
                            trustedHubTransId,
                            pkiValidatorResp.getResponseCode(),
                            pkiValidatorResp.getXmlData(),
                            pkiValidatorResp.getSignedData(),
                            pkiValidatorResp.getPreTrustedHubTransId(),
                            null);

                    TransactionInfo tranResp = new TransactionInfo();
                    tranResp.setXmlData(pkiValidatorResp.getXmlData());
                    tranResp.setFileData(pkiValidatorResp.getFileData());

                    String jsonResp = Utils.processTransactionInfo(tranResp);
                    DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
                    return tranResp;
                } else if (workerType == 11) {
                    // DCSIGNER
                    LOG.info("DCSIGNER");
                    ProcessSigner ps = new ProcessSigner(wsContext, workersession);
                    ProcessSignerResp signerResp = ps.processData(transInfo, trustedHubTransId, agreementStatus, billCode);

                    DBConnector.getInstances().updateTrustedHubTransaction(
                            trustedHubTransId,
                            signerResp.getResponseCode(),
                            signerResp.getXmlData(),
                            signerResp.getSignedData(),
                            signerResp.getPreTrustedHubTransId(),
                            null);

                    TransactionInfo tranResp = new TransactionInfo();
                    tranResp.setXmlData(signerResp.getXmlData());
                    tranResp.setFileData(signerResp.getFileData());

                    String jsonResp = Utils.processTransactionInfo(tranResp);
                    DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
                    return tranResp;
                } else if (workerType == 12) {
                    LOG.info("U2F VALIDATOR PARTS");
                    ProcessValidator pv = new ProcessValidator(wsContext, workersession);
                    ProcessValidatorResp u2fValidatorResp = pv.processData(transInfo, trustedHubTransId, agreementStatus, billCode);

                    DBConnector.getInstances().updateTrustedHubTransaction(
                            trustedHubTransId,
                            u2fValidatorResp.getResponseCode(),
                            u2fValidatorResp.getXmlData(),
                            u2fValidatorResp.getSignedData(),
                            u2fValidatorResp.getPreTrustedHubTransId(),
                            null);

                    TransactionInfo tranResp = new TransactionInfo();
                    tranResp.setXmlData(u2fValidatorResp.getXmlData());
                    tranResp.setFileData(u2fValidatorResp.getFileData());

                    String jsonResp = Utils.processTransactionInfo(tranResp);
                    DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
                    return tranResp;

                } else if (workerType == 13) {
                    // GENERAL VALIDATOR
                    LOG.info("GENERAL VALIDATOR PARTS");
                    ProcessValidator pv = new ProcessValidator(wsContext, workersession);
                    ProcessValidatorResp pkiValidatorResp = pv.processData(transInfo, trustedHubTransId, agreementStatus, billCode);

                    DBConnector.getInstances().updateTrustedHubTransaction(
                            trustedHubTransId,
                            pkiValidatorResp.getResponseCode(),
                            pkiValidatorResp.getXmlData(),
                            pkiValidatorResp.getSignedData(),
                            pkiValidatorResp.getPreTrustedHubTransId(),
                            null);

                    TransactionInfo tranResp = new TransactionInfo();
                    tranResp.setXmlData(pkiValidatorResp.getXmlData());
                    tranResp.setFileData(pkiValidatorResp.getFileData());

                    String jsonResp = Utils.processTransactionInfo(tranResp);
                    DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
                    return tranResp;
                } else if (workerType == 14) {
                    // FILE PROCESSOR
                    LOG.info("FILE PROCESSOR PARTS");
                    ProcessFileManagement pfm = new ProcessFileManagement(wsContext, workersession);
                    ProcessFileManagementResp processFileManagementResp = pfm.processData(transInfo, trustedHubTransId, agreementStatus, billCode);

                    DBConnector.getInstances().updateTrustedHubTransaction(
                            trustedHubTransId,
                            processFileManagementResp.getResponseCode(),
                            processFileManagementResp.getXmlData(),
                            processFileManagementResp.getSignedData(),
                            processFileManagementResp.getPreTrustedHubTransId(),
                            null);

                    TransactionInfo tranResp = new TransactionInfo();
                    tranResp.setXmlData(processFileManagementResp.getXmlData());
                    tranResp.setFileData(processFileManagementResp.getFileData());

                    String jsonResp = Utils.processTransactionInfo(tranResp);
                    DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
                    return tranResp;

                } else {
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_NOWORKER,
                            Defines.ERROR_NOWORKER, channelName, user, billCode);

                    DBConnector.getInstances().updateTrustedHubTransaction(
                            trustedHubTransId,
                            Defines.CODE_NOWORKER,
                            pData,
                            signedData,
                            null,
                            null);

                    TransactionInfo transResp = new TransactionInfo(pData);
                    String jsonResp = Utils.processTransactionInfo(transResp);
                    DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
                    return transResp;
                }
            } catch (Exception e) {
                e.printStackTrace();
                String pData = ExtFunc.genResponseMessage(
                        Defines.CODE_INTERNALSYSTEM,
                        Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                DBConnector.getInstances().updateTrustedHubTransaction(
                        trustedHubTransId,
                        Defines.CODE_INTERNALSYSTEM,
                        pData,
                        signedData,
                        null,
                        null);

                TransactionInfo transResp = new TransactionInfo(pData);
                String jsonResp = Utils.processTransactionInfo(transResp);
                DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
                return transResp;
            }
        }
    }

    @WebMethod(operationName = "processAdminData")
    public TransactionInfo processAdminData(
            @WebParam(name = "ClientID") int ClientID,
            @WebParam(name = "transInfo") TransactionInfo transInfo,
            @WebParam(name = "sessionKey") String sessionKey)
            throws RequestFailedException, InternalServerException {
        String functionName = null;
        String workerIdOrName = null;

        String jsonRequest = Utils.processTransactionInfo(transInfo);
        int dataInId = DBConnector.getInstances().insertDataIn(jsonRequest);

        String unsignedData = "";
        String signedData = "";
        String xmlData = "";

        String channelName = "";
        String user = "";
        String clientBillCode = "";

        String username = "";
        String password = "";
        String timestamp = "";
        String signature = "";
        String pkcs1Signature = "";

        try {
            xmlData = transInfo.getXmlData();
            channelName = ExtFunc.getContent(Defines._CHANNEL, xmlData);
            user = ExtFunc.getContent(Defines._USER, xmlData);
            clientBillCode = ExtFunc.getContent(Defines._ID, xmlData);

        } catch (NullPointerException e) {
            LOG.error("Some params is NULL.");
        }

        workerIdOrName = functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);

        if (workerIdOrName.compareTo("") == 0) {
            workerIdOrName = functionName = "FunctionError";
        }

        String method = ExtFunc.getContent(Defines._METHOD, xmlData);
        String signatureMethod = ExtFunc.getContent(Defines._SIGNATUREMETHOD, xmlData);

        // Check agreement status
        int[] infoUser = DBConnector.getInstances().getAgreementStatusUser(user, channelName,
                ExtFunc.getWorkerType(functionName, method, signatureMethod));

        int agreementStatus = infoUser[0];
        int agreementId = infoUser[1];

        String billCode = DBConnector.getInstances().insertTrustedHubTransaction(
                user,
                getRequestIP(),
                workerIdOrName,
                clientBillCode,
                channelName,
                xmlData,
                unsignedData,
                functionName,
                dataInId,
                null,
                agreementId,
                true);

        int trustedHubTransId = ExtFunc.getTransId(billCode);

        if (sessionKey.compareTo("VG9taWNhLVRNUw==") != 0) {

            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_INVALIDLOGININFO,
                    Defines.ERROR_INVALIDLOGININFO, channelName, user, Defines.EMPTY);

            DBConnector.getInstances().updateTrustedHubTransaction(
                    trustedHubTransId,
                    Defines.CODE_INVALIDLOGININFO,
                    pData,
                    signedData,
                    null,
                    null);

            TransactionInfo transResp = new TransactionInfo(pData);
            String jsonResp = Utils.processTransactionInfo(transResp);
            DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
            return transResp;
        }

        if (transInfo == null) {
            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_INVALIDPARAMETER,
                    Defines.ERROR_INVALIDPARAMETER, channelName, user, Defines.EMPTY);

            DBConnector.getInstances().updateTrustedHubTransaction(
                    trustedHubTransId,
                    Defines.CODE_INVALIDPARAMETER,
                    pData,
                    signedData,
                    null,
                    null);

            TransactionInfo transResp = new TransactionInfo(pData);
            String jsonResp = Utils.processTransactionInfo(transResp);
            DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
            return transResp;
        }

        if (xmlData == null) {

            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_INVALIDPARAMETER,
                    Defines.ERROR_INVALIDPARAMETER, channelName, user, Defines.EMPTY);

            DBConnector.getInstances().updateTrustedHubTransaction(
                    trustedHubTransId,
                    Defines.CODE_INVALIDPARAMETER,
                    pData,
                    signedData,
                    null,
                    null);

            TransactionInfo transResp = new TransactionInfo(pData);
            String jsonResp = Utils.processTransactionInfo(transResp);
            DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
            return transResp;
        }

        if (channelName.equals("")) {

            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_INVALIDCHANNEL,
                    Defines.ERROR_INVALIDCHANNEL, channelName, user, Defines.EMPTY);

            DBConnector.getInstances().updateTrustedHubTransaction(
                    trustedHubTransId,
                    Defines.CODE_INVALIDCHANNEL,
                    pData,
                    signedData,
                    null,
                    null);

            TransactionInfo transResp = new TransactionInfo(pData);
            String jsonResp = Utils.processTransactionInfo(transResp);
            DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
            return transResp;
        }

        // do operation
        functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);

        if (functionName.compareTo(Defines.WORKER_AGREEMENT) != 0) {

            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_NOWORKER,
                    Defines.ERROR_NOWORKER, channelName, user, Defines.EMPTY);

            DBConnector.getInstances().updateTrustedHubTransaction(
                    trustedHubTransId,
                    Defines.CODE_NOWORKER,
                    pData,
                    signedData,
                    null,
                    null);

            TransactionInfo transResp = new TransactionInfo(pData);
            String jsonResp = Utils.processTransactionInfo(transResp);
            DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
            return transResp;
        }

        // AGREEMENT
        LOG.info("ADMIN AGREEMENT PARTS");
        //ProcessAgreement pa = new ProcessAgreement(wsContext, workersession);
        //ProcessAgreementResp agreememtRes = pa.processData(transInfo, trustedHubTransId, billCode);
        ProcessAgreement.init(wsContext, workersession);
        ProcessAgreementResp agreememtRes = ProcessAgreement.processData(transInfo, trustedHubTransId, billCode);

        DBConnector.getInstances().updateTrustedHubTransaction(
                trustedHubTransId,
                agreememtRes.getResponseCode(),
                agreememtRes.getXmlData(),
                agreememtRes.getSignedData(),
                agreememtRes.getPreTrustedHubTransId(),
                agreememtRes.getAgreementId());

        TransactionInfo tranResp = new TransactionInfo();
        tranResp.setXmlData(agreememtRes.getXmlData());

        String jsonResp = Utils.processTransactionInfo(tranResp);
        DBConnector.getInstances().insertDataOut(jsonResp, dataInId);
        return tranResp;
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
                    // System.out.println("MetaData Name: "+
                    // element.getNodeName());
                    // System.out.println("MetaData Value: "+
                    // element.getTextContent());
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

    private String getRequestIP() {
        MessageContext msgContext = wsContext.getMessageContext();
        HttpServletRequest request = (HttpServletRequest) msgContext.get(MessageContext.SERVLET_REQUEST);

        return request.getRemoteAddr();
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

    private int getWorkerId(String workerIdOrName) {
        final int retval;

        if (workerIdOrName.substring(0, 1).matches("\\d")) {
            retval = Integer.parseInt(workerIdOrName);
        } else {
            retval = getWorkerSession().getWorkerId(workerIdOrName);
        }
        return retval;
    }

    private RequestContext handleRequestContext(
            final List<Metadata> requestMetadata, final int workerId) {
        final HttpServletRequest servletRequest = (HttpServletRequest) wsContext.getMessageContext().get(MessageContext.SERVLET_REQUEST);
        String requestIP = getRequestIP();
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

    private List<Metadata> getResponseMetadata(
            final RequestContext requestContext) {
        final LinkedList<Metadata> result = new LinkedList<Metadata>();
        return result;
    }

    private X509Certificate[] getClientCertificates() {
        SOAPMessageContext jaxwsContext = (SOAPMessageContext) wsContext.getMessageContext();
        HttpServletRequest request = (HttpServletRequest) jaxwsContext.get(SOAPMessageContext.SERVLET_REQUEST);

        final X509Certificate[] certificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
        return certificates;
    }

    private String getContent(String tag, String xmlData) {
        try {
            String startTag = "<" + tag + ">";

            int hasTag = xmlData.indexOf(startTag);
            if (hasTag != -1) {
                String endTag = "</" + startTag.substring(1);
                int indexStart = xmlData.indexOf(startTag) + startTag.length();
                int indexEnd = xmlData.indexOf(endTag);
                return xmlData.substring(indexStart, indexEnd);
            }
        } catch (Exception e) {
            LOG.error("Something wrong: " + e.getMessage());
        }
        return "";
    }

    @WebMethod(operationName = "processRawData")
    public DataResponse processRawData(
            @WebParam(name = "worker") final String workerIdOrName,
            @WebParam(name = "metadata") List<Metadata> requestMetadata,
            @WebParam(name = "data") byte[] data) throws RequestFailedException, InternalServerException {
        final DataResponse result;
        try {
            final int workerId = getWorkerId(workerIdOrName);
            if (workerId < 1) {
                throw new RequestFailedException("No worker with the given name could be found");
            }
            final RequestContext requestContext = handleRequestContext(requestMetadata, workerId);

            final int requestId = random.nextInt();

            final ProcessRequest req = new GenericSignRequest(requestId, data);
            final ProcessResponse resp = getWorkerSession().process(workerId, req, requestContext);

            if (resp instanceof GenericSignResponse) {
                final GenericSignResponse signResponse = (GenericSignResponse) resp;
                if (signResponse.getRequestID() != requestId) {
                    LOG.error("Response ID " + signResponse.getRequestID() + " not matching request ID " + requestId);
                    throw new InternalServerException("Error in process operation, response id didn't match request id");
                }
                result = new DataResponse(requestId, signResponse.getProcessedData(), signResponse.getArchiveId(), signResponse.getSignerCertificate() == null ? null : signResponse.getSignerCertificate().getEncoded(), getResponseMetadata(requestContext));
            } else {
                LOG.error("Unexpected return type: " + resp.getClass().getName());
                throw new InternalServerException("Unexpected return type");
            }
        } catch (CertificateEncodingException ex) {
            LOG.error("Signer certificate could not be encoded", ex);
            throw new InternalServerException("Signer certificate could not be encoded");
        } catch (IllegalRequestException ex) {
            LOG.info("Request failed: " + ex.getMessage());
            if (LOG.isDebugEnabled()) {
                LOG.info("Request failed: " + ex.getMessage(), ex);
            }
            throw new RequestFailedException(ex.getMessage());
        } catch (CryptoTokenOfflineException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Service unvailable", ex);
            }
            throw new InternalServerException("Service unavailable: " + ex.getMessage());
        } catch (AuthorizationRequiredException ex) {
            LOG.info("Request failed: " + ex.getMessage());
            throw new RequestFailedException(ex.getMessage());
        } catch (AccessDeniedException ex) {
            LOG.info("Request failed: " + ex.getMessage());
            throw new RequestFailedException(ex.getMessage());
        } catch (SignServerException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Internal server error", ex);
            }
            throw new InternalServerException("Internal server error: " + ex.getMessage());
        }
        return result;
    }

    @WebMethod(operationName = "getInformation")
    public String getInformation() {
        String about = "v2.180605";
        return about;
    }
    /*
     * // OCB @WebMethod(operationName = "prepareCertificateForSignCloud")
     * public SignCloudResp prepareCertificateForSignCloud(SignCloudReq
     * signCloudReq) {
     *
     * SignCloudResp signCloudResp = new SignCloudResp(); try { if (signCloudReq
     * == null) { LOG.error("signCloudResp cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * // check CredentialData CredentialData credentialData =
     * signCloudReq.getCredentialData(); if (credentialData == null) {
     * LOG.error("credentialData cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * String username = credentialData.getUsername(); String password =
     * credentialData.getPassword(); String signature =
     * credentialData.getSignature(); String pkcs1Signature =
     * credentialData.getPkcs1Signature(); String timestamp =
     * credentialData.getTimestamp();
     *
     * if (SignCloudUtil.isNullOrEmpty(username)) { LOG.error("username cannot
     * be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * if (SignCloudUtil.isNullOrEmpty(password)) { LOG.error("password cannot
     * be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * if (SignCloudUtil.isNullOrEmpty(signature)) { LOG.error("signature cannot
     * be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * if (SignCloudUtil.isNullOrEmpty(pkcs1Signature)) {
     * LOG.error("pkcs1Signature cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * //if (SignCloudUtil.isNullOrEmpty(timestamp)) { // LOG.error("timestamp
     * cannot be NULL"); //
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * //
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * // return signCloudResp; //}
     *
     * // check relying party String relyingParty =
     * signCloudReq.getRelyingParty(); if
     * (SignCloudUtil.isNullOrEmpty(relyingParty)) { LOG.error("relyingParty
     * cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * //check agreementId String agreementId = signCloudReq.getAgreementID();
     * if (SignCloudUtil.isNullOrEmpty(agreementId)) { LOG.error("agreementId
     * cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * // check mobileNo String mobileNo =
     * "01678932887";//signCloudReq.getMobileNo(); if
     * (SignCloudUtil.isNullOrEmpty(mobileNo)) { LOG.error("mobileNo cannot be
     * NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * // check emailAddress String emailAddr =
     * "phuongvu_0203@yahoo.com";//signCloudReq.getEmail(); if
     * (SignCloudUtil.isNullOrEmpty(emailAddr)) { LOG.error("emailAddr cannot be
     * NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * // check cert profile String certProfile =
     * signCloudReq.getCertificateProfile(); if
     * (SignCloudUtil.isNullOrEmpty(certProfile)) { LOG.error("certProfile
     * cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     *
     * // check cert info AgreementDetails agreementDetails =
     * signCloudReq.getAgreementDetails(); if (agreementDetails == null) {
     * LOG.error("agreementDetails cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; } String personalName =
     * agreementDetails.getPersonName(); //String email =
     * agreementDetails.getEmail(); String locality =
     * agreementDetails.getLocation(); String stateProvince =
     * agreementDetails.getStateOrProvince(); String country =
     * agreementDetails.getCountry(); String passportId =
     * agreementDetails.getPassportId(); String personalId =
     * agreementDetails.getPersonalId();
     *
     * if (SignCloudUtil.isNullOrEmpty(personalName) //||
     * SignCloudUtil.isNullOrEmpty(email) ||
     * SignCloudUtil.isNullOrEmpty(locality) ||
     * SignCloudUtil.isNullOrEmpty(stateProvince) ||
     * SignCloudUtil.isNullOrEmpty(country)) { LOG.error("Somes DN atributes
     * cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * if (SignCloudUtil.isNullOrEmpty(passportId) &&
     * SignCloudUtil.isNullOrEmpty(personalId)) { LOG.error("passportId or
     * personalId atributes cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * String dn = "CN=" + SignCloudUtil.resolveDNAttribute(personalName) //+
     * ",E=" + email + ",L=" + SignCloudUtil.resolveDNAttribute(locality) +
     * ",ST=" + SignCloudUtil.resolveDNAttribute(stateProvince) + ",C=" +
     * country;
     *
     * if (SignCloudUtil.isNullOrEmpty(passportId)) { dn +=
     * ",0.9.2342.19200300.100.1.1=CMND:" + personalId; } else { dn +=
     * ",0.9.2342.19200300.100.1.1=HC:" + passportId; }
     *
     * LOG.info("DNString: " + dn); // Call ClientWS String xmlData =
     * "<Channel>" + relyingParty + "</Channel>\n" + "<User>" + agreementId +
     * "</User>\n" + "<ExternalBillCode>01009090</ExternalBillCode>\n" +
     * "<WorkerName>AgreementHandler</WorkerName>\n" +
     * "<Action>REGISTRATION</Action>\n" + "<Expiration>3650</Expiration>\n" +
     * "\n" + "<IsOTPSMS>True</IsOTPSMS>\n" + "<OTPSMS>" + mobileNo +
     * "</OTPSMS>\n" + "\n" + "<IsOTPEmail>True</IsOTPEmail>\n" + "<OTPEmail>" +
     * emailAddr + "</OTPEmail>" + "<IsSPKI>True</IsSPKI>\n" +
     * "<WorkerNameSigning>MultiSigner</WorkerNameSigning>\n" + "<SPKIEmail>" +
     * emailAddr + "</SPKIEmail>\n" + "<SPKISMS>" + mobileNo + "</SPKISMS>\n" +
     * "<SKeyType>PRIVATE</SKeyType>\n" + "<P11Info>TPM</P11Info>\n" + "\n" +
     * "<SPKICertType>Personal</SPKICertType>\n" + "<SPKICertProvider>FPT
     * Certification Authority</SPKICertProvider>\n" + "<SPKIDN>" + dn +
     * "</SPKIDN>\n" + "<SPKICertProfile>365</SPKICertProfile>";
     *
     * CAGCredential credential = new CAGCredential();
     * credential.setUsername(username); credential.setPassword(password);
     * credential.setSignature(signature); credential.setTimestamp(timestamp);
     * credential.setPkcs1Signature(pkcs1Signature);
     *
     * TransactionInfo transReq = new TransactionInfo();
     * transReq.setXmlData(xmlData); transReq.setCredentialData(credential);
     *
     * TransactionInfo transResp = processData(transReq);
     *
     * String responseXmlData = transResp.getXmlData(); int responseCode =
     * Integer.parseInt(ExtFunc.getContent("ResponseCode", responseXmlData)); if
     * (responseCode == Defines.CODE_SUCCESS) {
     *
     * xmlData = "<Channel>" + relyingParty + "</Channel>\n" + "<User>" +
     * agreementId + "</User>\n" +
     * "<ExternalBillCode>01009090</ExternalBillCode>\n" +
     * "<WorkerName>AgreementHandler</WorkerName>\n" +
     * "<Action>CHANGEINFO</Action>\n" + "<IsSPKI>True</IsSPKI>\n" +
     * "<IsInstallSCertificate>True</IsInstallSCertificate>";
     *
     * transReq = new TransactionInfo(); transReq.setXmlData(xmlData);
     * transReq.setCredentialData(credential);
     *
     * transResp = processData(transReq); responseXmlData =
     * transResp.getXmlData(); responseCode =
     * Integer.parseInt(ExtFunc.getContent("ResponseCode", responseXmlData));
     *
     * if (responseCode != 0) {
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_UNEXPECTED_EXCEPTION);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_UNEXPECTED_EXCEPTION);
     * return signCloudResp; }
     *
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_SUCCESS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_SUCCESS);
     * return signCloudResp; } else if (responseCode ==
     * Defines.CODE_INVALIDUSERAGREEMENT) {
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_AGREEEMENT_EXITS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_AGREEEMENT_EXITS);
     * return signCloudResp; } else {
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_UNEXPECTED_EXCEPTION);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_UNEXPECTED_EXCEPTION);
     * return signCloudResp; } } catch (Exception e) { e.printStackTrace();
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_UNEXPECTED_EXCEPTION);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_UNEXPECTED_EXCEPTION);
     * return signCloudResp; } } // OCB @WebMethod(operationName =
     * "prepareFileForSignCloud") public SignCloudResp
     * prepareFileForSignCloud(SignCloudReq signCloudReq) { SignCloudResp
     * signCloudResp = new SignCloudResp(); try { if (signCloudReq == null) {
     * LOG.error("signCloudResp cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * // check CredentialData CredentialData credentialData =
     * signCloudReq.getCredentialData(); if (credentialData == null) {
     * LOG.error("credentialData cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * String username = credentialData.getUsername(); String password =
     * credentialData.getPassword(); String signature =
     * credentialData.getSignature(); String pkcs1Signature =
     * credentialData.getPkcs1Signature(); String timestamp =
     * credentialData.getTimestamp();
     *
     * if (SignCloudUtil.isNullOrEmpty(username)) { LOG.error("username cannot
     * be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * if (SignCloudUtil.isNullOrEmpty(password)) { LOG.error("password cannot
     * be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * if (SignCloudUtil.isNullOrEmpty(signature)) { LOG.error("signature cannot
     * be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * if (SignCloudUtil.isNullOrEmpty(pkcs1Signature)) {
     * LOG.error("pkcs1Signature cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * // if (SignCloudUtil.isNullOrEmpty(timestamp)) { // LOG.error("timestamp
     * cannot be NULL"); //
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * //
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * // return signCloudResp; // }
     *
     * // check relying party String relyingParty =
     * signCloudReq.getRelyingParty(); if
     * (SignCloudUtil.isNullOrEmpty(relyingParty)) { LOG.error("relyingParty
     * cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * //check agreementId String agreementId = signCloudReq.getAgreementID();
     * if (SignCloudUtil.isNullOrEmpty(agreementId)) { LOG.error("agreementId
     * cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * // check signingFileData byte[] signingFileData =
     * signCloudReq.getSigningFileData(); if (signingFileData == null) {
     * LOG.error("signingFileData cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * // check mimeType String mimeType = signCloudReq.getMimeType(); if
     * (SignCloudUtil.isNullOrEmpty(mimeType)) { LOG.error("mimeType cannot be
     * NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * // check notificationTemplate String notificationTemplate =
     * signCloudReq.getNotificationTemplate(); if
     * (SignCloudUtil.isNullOrEmpty(notificationTemplate)) {
     * LOG.error("notificationTemplate cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * String notificationSubject = signCloudReq.getNotificationSubject();
     *
     * // authorizeMethod String otpMethod = "OTPSMS";
     *
     * int authorizeMethod = signCloudReq.getAuthorizeMethod(); if
     * (authorizeMethod == SignCloudConstant.AUTHORISATION_METHOD_EMAIL) {
     * otpMethod = "OTPEmail"; if
     * (SignCloudUtil.isNullOrEmpty(notificationSubject)) { notificationSubject
     * = "(no subject)"; }
     *
     * }
     *
     * // Call ClientWS String xmlData = null; if (authorizeMethod == 1) {
     * xmlData = "<Channel>" + relyingParty + "</Channel>\n" + "<User>" +
     * agreementId + "</User>\n" +
     * "<ExternalBillCode>01009090</ExternalBillCode>\n" +
     * "<FileType>pdf</FileType>\n" + "<MetaData>\n" + "
     * <ExternalStorage>P2P</ExternalStorage>\n" + "
     * <Method>OATHRequest</Method>\n" + " <OTPMethod>" + otpMethod +
     * "</OTPMethod>\n" + " <Subject>" + notificationSubject + "</Subject>\n" +
     * " <TransactionData>" + notificationTemplate + "</TransactionData>\n" +
     * "</MetaData>\n" + "<WorkerName>MultiSigner</WorkerName>"; } else {
     * xmlData = "<Channel>" + relyingParty + "</Channel>\n" + "<User>" +
     * agreementId + "</User>\n" +
     * "<ExternalBillCode>01009090</ExternalBillCode>\n" +
     * "<FileType>pdf</FileType>\n" + "<MetaData>\n" + "
     * <ExternalStorage>P2P</ExternalStorage>\n" + "
     * <Method>OATHRequest</Method>\n" + " <OTPMethod>" + otpMethod +
     * "</OTPMethod>\n" + " <TransactionData>" + notificationTemplate +
     * "</TransactionData>\n" + "</MetaData>\n" +
     * "<WorkerName>MultiSigner</WorkerName>"; }
     *
     * CAGCredential credential = new CAGCredential();
     * credential.setUsername(username); credential.setPassword(password);
     * credential.setSignature(signature); credential.setTimestamp(timestamp);
     * credential.setPkcs1Signature(pkcs1Signature);
     *
     * TransactionInfo transReq = new TransactionInfo();
     * transReq.setXmlData(xmlData); transReq.setFileData(signingFileData);
     * transReq.setCredentialData(credential);
     *
     * TransactionInfo transResp = processData(transReq);
     *
     * String responseXmlData = transResp.getXmlData(); int responseCode =
     * Integer.parseInt(ExtFunc.getContent("ResponseCode", responseXmlData)); if
     * (responseCode == Defines.CODE_OTP_STATUS_WAIT) { String otp =
     * ExtFunc.getContent("OTP", responseXmlData); LOG.info("Responeded OTP:
     * "+otp); if(SignCloudUtil.isNullOrEmpty(otp)) {
     * signCloudResp.setBillCode(ExtFunc.getContent("BillCode",
     * responseXmlData));
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_REQUEST_ACCEPTED);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_REQUEST_ACCEPTED);
     * } else { notificationTemplate =
     * notificationTemplate.replace("{AuthorizeCode}", otp);
     * notificationTemplate = notificationTemplate.replace("{OTP}", otp);
     *
     * signCloudResp.setAuthorizeMethod(authorizeMethod);
     * signCloudResp.setNotificationMessage(notificationTemplate);
     * signCloudResp.setNotificationSubject(notificationSubject);
     * signCloudResp.setBillCode(ExtFunc.getContent("BillCode",
     * responseXmlData));
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_REQUEST_ACCEPTED);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_REQUEST_ACCEPTED);
     * } return signCloudResp; } else if (responseCode ==
     * Defines.CODE_OTPLOCKED) {
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_AUTHORISATION_BLOCKED);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_AUTHORISATION_BLOCKED);
     * return signCloudResp; } else {
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_UNEXPECTED_EXCEPTION);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_UNEXPECTED_EXCEPTION);
     * return signCloudResp; } } catch (Exception e) { e.printStackTrace();
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_UNEXPECTED_EXCEPTION);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_UNEXPECTED_EXCEPTION);
     * return signCloudResp; } } // OCB @WebMethod(operationName =
     * "authorizeCounterSigningForSignCloud") public SignCloudResp
     * authorizeCounterSigningForSignCloud(SignCloudReq signCloudReq) {
     * SignCloudResp signCloudResp = new SignCloudResp(); try { if (signCloudReq
     * == null) { LOG.error("signCloudResp cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * // check CredentialData CredentialData credentialData =
     * signCloudReq.getCredentialData(); if (credentialData == null) {
     * LOG.error("credentialData cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * String username = credentialData.getUsername(); String password =
     * credentialData.getPassword(); String signature =
     * credentialData.getSignature(); String pkcs1Signature =
     * credentialData.getPkcs1Signature(); String timestamp =
     * credentialData.getTimestamp();
     *
     * if (SignCloudUtil.isNullOrEmpty(username)) { LOG.error("username cannot
     * be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * if (SignCloudUtil.isNullOrEmpty(password)) { LOG.error("password cannot
     * be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * if (SignCloudUtil.isNullOrEmpty(signature)) { LOG.error("signature cannot
     * be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * if (SignCloudUtil.isNullOrEmpty(pkcs1Signature)) {
     * LOG.error("pkcs1Signature cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * // if (SignCloudUtil.isNullOrEmpty(timestamp)) { // LOG.error("timestamp
     * cannot be NULL"); //
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * //
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * // return signCloudResp; // }
     *
     * // check relying party String relyingParty =
     * signCloudReq.getRelyingParty(); if
     * (SignCloudUtil.isNullOrEmpty(relyingParty)) { LOG.error("relyingParty
     * cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * //check agreementId String agreementId = signCloudReq.getAgreementID();
     * if (SignCloudUtil.isNullOrEmpty(agreementId)) { LOG.error("agreementId
     * cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * // check billCode String billCode = signCloudReq.getBillCode(); if
     * (SignCloudUtil.isNullOrEmpty(billCode)) { LOG.error("billCode cannot be
     * NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * // check authorizeCode String authorizeCode =
     * signCloudReq.getAuthorizeCode(); if
     * (SignCloudUtil.isNullOrEmpty(authorizeCode)) { LOG.error("authorizeCode
     * cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * // check metaData SignCloudMetaData signCloudMetaData =
     * signCloudReq.getSignCloudMetaData(); if (signCloudMetaData == null) {
     * LOG.error("signCloudMetaData cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * String signatureImage = (String)
     * SignCloudUtil.getMetaData(signCloudMetaData,
     * SignCloudConstant.METADATA_PDFSIGNATURE_SIGNATUREIMAGE); String pageNo =
     * (String) SignCloudUtil.getMetaData(signCloudMetaData,
     * SignCloudConstant.METADATA_PDFSIGNATURE_PAGENO); String coordinate =
     * (String) SignCloudUtil.getMetaData(signCloudMetaData,
     * SignCloudConstant.METADATA_PDFSIGNATURE_COORDINATE); String
     * visibleSignature = (String) SignCloudUtil.getMetaData(signCloudMetaData,
     * SignCloudConstant.METADATA_PDFSIGNATURE_VISIBLESIGNATURE); String
     * visualStatus = (String) SignCloudUtil.getMetaData(signCloudMetaData,
     * SignCloudConstant.METADATA_PDFSIGNATURE_VISUALSTATUS); String
     * imageAndText = (String) SignCloudUtil.getMetaData(signCloudMetaData,
     * SignCloudConstant.METADATA_PDFSIGNATURE_IMAGEANDTEXT); String
     * textDirection = (String) SignCloudUtil.getMetaData(signCloudMetaData,
     * SignCloudConstant.METADATA_PDFSIGNATURE_TEXTDIRECTION); String
     * showSignerInfo = (String) SignCloudUtil.getMetaData(signCloudMetaData,
     * SignCloudConstant.METADATA_PDFSIGNATURE_SHOWSIGNERINFO); String
     * signerPrefix = (String) SignCloudUtil.getMetaData(signCloudMetaData,
     * SignCloudConstant.METADATA_PDFSIGNATURE_SIGNERINFOPREFIX); String
     * showDateTime = (String) SignCloudUtil.getMetaData(signCloudMetaData,
     * SignCloudConstant.METADATA_PDFSIGNATURE_SHOWDATETIME); String
     * dateTimePrefix = (String) SignCloudUtil.getMetaData(signCloudMetaData,
     * SignCloudConstant.METADATA_PDFSIGNATURE_DATETIMEPREFIX); String
     * showReason = (String) SignCloudUtil.getMetaData(signCloudMetaData,
     * SignCloudConstant.METADATA_PDFSIGNATURE_SHOWREASON); String reasonPrefix
     * = (String) SignCloudUtil.getMetaData(signCloudMetaData,
     * SignCloudConstant.METADATA_PDFSIGNATURE_SIGNREASONPREFIX); String
     * signReason = (String) SignCloudUtil.getMetaData(signCloudMetaData,
     * SignCloudConstant.METADATA_PDFSIGNATURE_SIGNREASON); String showLocation
     * = (String) SignCloudUtil.getMetaData(signCloudMetaData,
     * SignCloudConstant.METADATA_PDFSIGNATURE_SHOWLOCATION); String location =
     * (String) SignCloudUtil.getMetaData(signCloudMetaData,
     * SignCloudConstant.METADATA_PDFSIGNATURE_LOCATION); String locationPrefix
     * = (String) SignCloudUtil.getMetaData(signCloudMetaData,
     * SignCloudConstant.METADATA_PDFSIGNATURE_LOCATIONPREFIX); String textColor
     * = (String) SignCloudUtil.getMetaData(signCloudMetaData,
     * SignCloudConstant.METADATA_PDFSIGNATURE_TEXTCOLOR);
     *
     *
     * // Call ClientWS String xmlData = "<Channel>" + relyingParty +
     * "</Channel>\n" + "<User>" + agreementId + "</User>\n" +
     * "<ExternalBillCode>01009090</ExternalBillCode>\n" +
     * "<FileType>pdf</FileType>\n" + "<MetaData>\n" + "
     * <ExternalStorage>P2P</ExternalStorage>\n" + "
     * <Method>OATHResponse</Method>\n" + " <OTP>" + authorizeCode + "</OTP>\n"
     * + " <BillCode>" + billCode + "</BillCode>\n" + " <SignatureImage>" +
     * signatureImage + "</SignatureImage>\n" + " <PageNo>" + pageNo +
     * "</PageNo>\n" + " <Coordinate>" + coordinate + "</Coordinate>\n" + "
     * <VisibleSignature>" + visibleSignature + "</VisibleSignature>\n" + "
     * <VisualStatus>" + visualStatus + "</VisualStatus>\n" + " <ImageAndText>"
     * + imageAndText + "</ImageAndText>\n" + " <TextDirection>" + textDirection
     * + "</TextDirection>\n" + " <ShowSignerInfo>" + showSignerInfo +
     * "</ShowSignerInfo>\n" + " <SignerInfoPrefix>" + signerPrefix +
     * "</SignerInfoPrefix>\n" + " <ShowDateTime>" + showDateTime +
     * "</ShowDateTime>\n" + " <DateTimePrefix>" + dateTimePrefix +
     * "</DateTimePrefix>\n" + " <ShowReason>" + showReason + "</ShowReason>\n"
     * + " <SignReasonPrefix>" + reasonPrefix + "</SignReasonPrefix>\n" + "
     * <SignReason>" + signReason + "</SignReason>\n" + " <ShowLocation>" +
     * showLocation + "</ShowLocation>\n" + " <Location>" + location +
     * "</Location>\n" + " <LocationPrefix>" + locationPrefix +
     * "</LocationPrefix>\n" + " <TextColor>" + textColor + "</TextColor>\n" +
     * "</MetaData>\n" + "<WorkerName>MultiSigner</WorkerName>";
     *
     * CAGCredential credential = new CAGCredential();
     * credential.setUsername(username); credential.setPassword(password);
     * credential.setSignature(signature); credential.setTimestamp(timestamp);
     * credential.setPkcs1Signature(pkcs1Signature);
     *
     * TransactionInfo transReq = new TransactionInfo();
     * transReq.setXmlData(xmlData); transReq.setCredentialData(credential);
     *
     * TransactionInfo transResp = processData(transReq);
     *
     * String responseXmlData = transResp.getXmlData(); int responseCode =
     * Integer.parseInt(ExtFunc.getContent("ResponseCode", responseXmlData)); if
     * (responseCode == Defines.CODE_SUCCESS) { // signserver xmlData =
     * "<Channel>" + relyingParty + "</Channel>\n" + "<User>fecredit</User>\n" +
     * "<ExternalBillCode>01009090</ExternalBillCode>\n" +
     * "<FileType>pdf</FileType>\n" + "<MetaData>\n" + "
     * <Password>12345678</Password>\n" + "
     * <ExternalStorage>P2P</ExternalStorage>\n" + "
     * <Method>SynchronousSign</Method>\n" + "</MetaData>\n" +
     * "<WorkerName>MultiSigner</WorkerName>";
     *
     * transReq = new TransactionInfo(); transReq.setXmlData(xmlData);
     * transReq.setCredentialData(credential);
     * transReq.setFileData(transResp.getFileData());
     *
     * transResp = processData(transReq); responseXmlData =
     * transResp.getXmlData(); responseCode =
     * Integer.parseInt(ExtFunc.getContent("ResponseCode", responseXmlData));
     *
     * if (responseCode != 0) {
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_UNEXPECTED_EXCEPTION);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_UNEXPECTED_EXCEPTION);
     * return signCloudResp; } if (signCloudReq.getMessagingMode() ==
     * SignCloudConstant.MESSAGING_MODE_SYNCHRONOUS) {
     * signCloudResp.setSignedFileData(transResp.getFileData());
     * signCloudResp.setMimeType("application/pdf");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_SUCCESS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_SUCCESS);
     * return signCloudResp; } else { // 0 and 1 ASYNCHRONOUS_CLIENTSERVER
     * SignCloudUtil.storeSignedFile(transResp.getFileData(), billCode);
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_SUCCESS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_SUCCESS);
     * return signCloudResp; } } else if (responseCode ==
     * Defines.CODE_OTP_STATUS_FAIL) { int remainingCounter =
     * Integer.parseInt(ExtFunc.getContent("LeftRetry", responseXmlData));
     * signCloudResp.setRemainingCounter(remainingCounter);
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_AUTHORISATION_CODE);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_AUTHORISATION_CODE);
     * return signCloudResp; } else if (responseCode == Defines.CODE_OTPLOCKED)
     * {
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_AUTHORISATION_BLOCKED);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_AUTHORISATION_BLOCKED);
     * return signCloudResp; } else if(responseCode ==
     * Defines.CODE_OTP_STATUS_TIME) {
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_AUTHORISATION_TIMEOUT);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_AUTHORISATION_TIMEOUT);
     * return signCloudResp; } else {
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_UNEXPECTED_EXCEPTION);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_UNEXPECTED_EXCEPTION);
     * return signCloudResp; } } catch (Exception e) { e.printStackTrace();
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_UNEXPECTED_EXCEPTION);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_UNEXPECTED_EXCEPTION);
     * return signCloudResp; } } // OCB @WebMethod(operationName =
     * "approveCertificateForSignCloud") public SignCloudResp
     * approveCertificateForSignCloud(SignCloudReq signCloudReq) { throw new
     * UnsupportedOperationException(); } // OCB @WebMethod(operationName =
     * "getCertificateDetailForSignCloud") public SignCloudResp
     * getCertificateDetailForSignCloud(SignCloudReq signCloudReq) { throw new
     * UnsupportedOperationException(); } // OCB @WebMethod(operationName =
     * "prepareRenewCertificateForSignCloud") public SignCloudResp
     * prepareRenewCertificateForSignCloud(SignCloudReq signCloudReq) { throw
     * new UnsupportedOperationException(); } // OCB @WebMethod(operationName =
     * "prepareRevokeCertificateForSignCloud") public SignCloudResp
     * prepareRevokeCertificateForSignCloud(SignCloudReq signCloudReq) { throw
     * new UnsupportedOperationException(); }
     *
     * @WebMethod(operationName = "downloadSignedFileForSignCloud") public
     * SignCloudResp downloadSignedFileForSignCloud(SignCloudReq signCloudReq) {
     * SignCloudResp signCloudResp = new SignCloudResp(); try { if (signCloudReq
     * == null) { LOG.error("signCloudResp cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * // check CredentialData CredentialData credentialData =
     * signCloudReq.getCredentialData(); if (credentialData == null) {
     * LOG.error("credentialData cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * String username = credentialData.getUsername(); String password =
     * credentialData.getPassword(); String signature =
     * credentialData.getSignature(); String pkcs1Signature =
     * credentialData.getPkcs1Signature(); String timestamp =
     * credentialData.getTimestamp();
     *
     * if (SignCloudUtil.isNullOrEmpty(username)) { LOG.error("username cannot
     * be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * if (SignCloudUtil.isNullOrEmpty(password)) { LOG.error("password cannot
     * be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * if (SignCloudUtil.isNullOrEmpty(signature)) { LOG.error("signature cannot
     * be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * if (SignCloudUtil.isNullOrEmpty(pkcs1Signature)) {
     * LOG.error("pkcs1Signature cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * // if (SignCloudUtil.isNullOrEmpty(timestamp)) { // LOG.error("timestamp
     * cannot be NULL"); //
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * //
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * // return signCloudResp; // }
     *
     * // check relying party String relyingParty =
     * signCloudReq.getRelyingParty(); if
     * (SignCloudUtil.isNullOrEmpty(relyingParty)) { LOG.error("relyingParty
     * cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * //check agreementId String agreementId = signCloudReq.getAgreementID();
     * if (SignCloudUtil.isNullOrEmpty(agreementId)) { LOG.error("agreementId
     * cannot be NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * // check billCode String billCode = signCloudReq.getBillCode(); if
     * (SignCloudUtil.isNullOrEmpty(billCode)) { LOG.error("billCode cannot be
     * NULL");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
     * return signCloudResp; }
     *
     * byte[] signedFileData = SignCloudUtil.getSignedFile(billCode); if
     * (signedFileData != null) { if(signedFileData.length != 0) {
     * signCloudResp.setSignedFileData(signedFileData);
     * signCloudResp.setMimeType("application/pdf");
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_SUCCESS);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_SUCCESS);
     * return signCloudResp; } }
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_UNEXPECTED_EXCEPTION);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_UNEXPECTED_EXCEPTION);
     * return signCloudResp; } catch (Exception e) { e.printStackTrace();
     * signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_UNEXPECTED_EXCEPTION);
     * signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_UNEXPECTED_EXCEPTION);
     * return signCloudResp; } }
     *
     * @WebMethod(operationName = "uploadFileForSignCloud") public SignCloudResp
     * uploadFileForSignCloud(SignCloudReq signCloudReq) { throw new
     * UnsupportedOperationException(); }
     *
     * @WebMethod(operationName = "downloadFileForSignCloud") public
     * SignCloudResp downloadFileForSignCloud(SignCloudReq signCloudReq) { throw
     * new UnsupportedOperationException(); }
     *
     * @WebMethod(operationName = "changePasscodeForSignCloud") public
     * SignCloudResp changePasscodeForSignCloud(SignCloudReq signCloudReq) {
     * throw new UnsupportedOperationException(); }
     *
     * @WebMethod(operationName = "forgetPasscodeForSignCloud") public
     * SignCloudResp forgetPasscodeForSignCloud(SignCloudReq signCloudReq) {
     * throw new UnsupportedOperationException(); }
     *
     * @WebMethod(operationName = "authorizeSingletonSigningForSignCloud")
     * public SignCloudResp authorizeSingletonSigningForSignCloud(SignCloudReq
     * signCloudReq) { throw new UnsupportedOperationException(); }
     *
     * @WebMethod(operationName = "prepareHashSigningForSignCloud") public
     * SignCloudResp prepareHashSigningForSignCloud(SignCloudReq signCloudReq) {
     * throw new UnsupportedOperationException(); }
     *
     * @WebMethod(operationName = "authorizeHashSigningForSignCloud") public
     * SignCloudResp authorizeHashSigningForSignCloud(SignCloudReq signCloudReq)
     * { throw new UnsupportedOperationException(); }
     *
     * @WebMethod(operationName = "assignCertificateForSignCloud") public
     * SignCloudResp assignCertificateForSignCloud(SignCloudReq signCloudReq) {
     * throw new UnsupportedOperationException(); }
     */
}