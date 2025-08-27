package org.signserver.clientws;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.*;
import java.util.regex.Pattern;

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
import org.signserver.common.dbdao.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.tomicalab.cag360.license.*;

import javax.xml.ws.handler.soap.SOAPMessageContext;

import java.util.Map;

import com.tomicalab.cag360.connector.ws.*;
import java.nio.charset.StandardCharsets;

import vn.mobileid.pkcs11basic.*;

import org.ejbca.util.CertTools;

public class ProcessAgreement {

    private static final Logger LOG = Logger.getLogger(ProcessAgreement.class);
    private static final Random random = new Random();
    private static final String HTTP_AUTH_BASIC_AUTHORIZATION = "Authorization";
    //private WebServiceContext wsContext;
    //private IWorkerSession.ILocal workersession;
    /*
     * public ProcessAgreement(WebServiceContext wsContext,
     * IWorkerSession.ILocal workersession) { this.wsContext = wsContext;
     * this.workersession = workersession; }
     */
    private static WebServiceContext wsContext;
    private static IWorkerSession.ILocal workersession;

    public static void init(WebServiceContext _wsContext,
            IWorkerSession.ILocal _workersession) {
        wsContext = _wsContext;
        workersession = _workersession;
    }

    public static synchronized ProcessAgreementResp processData(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
        String workerIdOrName = Defines.WORKER_AGREEMENT;
        String functionName = Defines.WORKER_AGREEMENT;
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


        String action = ExtFunc.getContent(Defines._ACTION, xmlData);

        ProcessAgreementResp resp = null;

        if (action.equals(Defines.AGREEMENT_ACTION_REG)) {
            resp = registerAgreement(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (action.equals(Defines.AGREEMENT_ACTION_CHAINF)) {
            resp = changeAgreementInfo(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (action.equals(Defines.AGREEMENT_ACTION_UNREG)) {
            resp = unregisterAgreement(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (action.equals(Defines.AGREEMENT_ACTION_MULTI_UNREG)) {
            resp = unregisterManyAgreement(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (action.equals(Defines.AGREEMENT_ACTION_VALIDA)) {
            resp = validateAgreement(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (action.equals(Defines.AGREEMENT_ACTION_GETAGR)) {
            resp = getAgreement(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (action.equals(Defines.AGREEMENT_ACTION_ACTIVATION)) {
            resp = activateAgreement(transInfo, trustedHubTransId, billCode);
            return resp;
        } else if (action.equals(Defines.AGREEMENT_ACTION_DEACTIVATION)) {
            resp = deActivationAgreement(transInfo, trustedHubTransId, billCode);
            return resp;
        } else {
            // Invalid action
            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_INVALIDACTION,
                    Defines.ERROR_INVALIDACTION, channelName, user, billCode);

            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
            processAgreementResp.setResponseCode(Defines.CODE_INVALIDACTION);
            processAgreementResp.setXmlData(pData);
            processAgreementResp.setSignedData(null);
            processAgreementResp.setPreTrustedHubTransId(null);
            return processAgreementResp;
        }
    }

    private static ProcessAgreementResp registerAgreement(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
        String workerIdOrName = Defines.WORKER_AGREEMENT;
        String functionName = Defines.WORKER_AGREEMENT;
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


        String action = ExtFunc.getContent(Defines._ACTION, xmlData);

        String isOtpSms = ExtFunc.getContent(Defines._ISOTPSMS, xmlData);
        String otpSms = ExtFunc.getContent(Defines._OTPSMS, xmlData);

        String isOtpEmail = ExtFunc.getContent(Defines._ISOTPEMAIL, xmlData);
        String otpEmail = ExtFunc.getContent(Defines._OTPEMAIL, xmlData);

        String isOtpHardware = ExtFunc.getContent(Defines._ISOTPHARDWARE,
                xmlData);
        String otpHardware = ExtFunc.getContent(Defines._OTPHARDWARE, xmlData);

        String isPKI = ExtFunc.getContent(Defines._ISPKI, xmlData);
        String pkiCertificate = ExtFunc.getContent(Defines._CERTIFICATE,
                xmlData);

        String isOtpSoftware = ExtFunc.getContent(Defines._ISOTPSOFTWARE,
                xmlData);

        String expiration = ExtFunc.getContent(Defines._EXPIRATION, xmlData);

        String branchId = ExtFunc.getContent(Defines._BranchID, xmlData);

        String isPKISigning = ExtFunc.getContent(Defines._ISPKISIGN, xmlData);

        String isWS;

        String spkiCertType = ExtFunc.getContent(Defines._SPKICERTTYPE, xmlData);

        String spkiCertProvider = ExtFunc.getContent(Defines._SPKICERTPROVIDER, xmlData);

        String spkiDn = ExtFunc.getContent(Defines._SPKIDN, xmlData);

        String spkiCertProfile = ExtFunc.getContent(Defines._SPKICERTPROFILE, xmlData);

        String workerSigning = ExtFunc.getContent(Defines._WORKERNAMESIGNING, xmlData);

        String spkiEmail = ExtFunc.getContent(Defines._SPKIEMAIL, xmlData);

        String spkiSMS = ExtFunc.getContent(Defines._SPKISMS, xmlData);

        String spkiKeyname = ExtFunc.getContent(Defines._SKEYNAME, xmlData);

        String spkiKeyType = ExtFunc.getContent(Defines._SKEYTYPE, xmlData);

        String spkiP11Info = ExtFunc.getContent(Defines._P11INFO, xmlData);

        String isLCDPKI = ExtFunc.getContent(Defines._ISLCDPKI, xmlData);

        String lcdpkiCertificate = ExtFunc.getContent(Defines._LCDCERTIFICATE,
                xmlData);

        String isPKISim = ExtFunc.getContent(Defines._ISPKISIM, xmlData);
        String pkiSim = ExtFunc.getContent(Defines._PKISIM, xmlData);
        String pkiSimVendor = ExtFunc.getContent(Defines._PKISIMVENDOR, xmlData);
        String wCertificate = ExtFunc.getContent(Defines._WCERTIFICATE, xmlData);


        String isU2F = ExtFunc.getContent(Defines._ISU2F, xmlData);
        String appId = ExtFunc.getContent(Defines._APPID, xmlData);


        if (!isOtpEmail.equals(Defines.TRUE)) {
            isOtpEmail = Defines.FALSE;
            otpEmail = Defines.NULL;
        }
        if (!isOtpHardware.equals(Defines.TRUE)) {
            isOtpHardware = Defines.FALSE;
            otpHardware = Defines.NULL;
        }
        if (!isOtpSms.equals(Defines.TRUE)) {
            isOtpSms = Defines.FALSE;
            otpSms = Defines.NULL;
        }
        if (!isOtpSoftware.equals(Defines.TRUE)) {
            isOtpSoftware = Defines.FALSE;
        }
        if (!isPKI.equals(Defines.TRUE)) {
            isPKI = Defines.FALSE;
            pkiCertificate = Defines.NULL;
        }

        if (!isPKISigning.equals(Defines.TRUE)) {
            isPKISigning = Defines.FALSE;
        }

        if (!spkiDn.equals("") || !spkiCertProvider.equals("")) {
            isWS = Defines.TRUE;
        } else {
            isWS = Defines.FALSE;
        }
        /*
         * if(!isWS.equals(Defines.TRUE)) { isWS = Defines.FALSE; }
         */

        if (!isLCDPKI.equals(Defines.TRUE)) {
            isLCDPKI = Defines.FALSE;
            lcdpkiCertificate = Defines.NULL;
        }

        if (!isPKISim.equals(Defines.TRUE)) {
            isPKISim = Defines.FALSE;
        }

        if (!isU2F.equals(Defines.TRUE)) {
            isU2F = Defines.FALSE;
        }

        if (isU2F.equals(Defines.TRUE)) {
            if (appId.equals("")) {
                LOG.error("Invalid U2F appId");
                String pData = ExtFunc.genResponseMessage(
                        Defines.CODE_INVALIDPARAMETER,
                        Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            }
        }

        // check user
        if (DBConnector.getInstances().checkUser(user, channelName)) {

            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_INVALIDUSERAGREEMENT,
                    Defines.ERROR_INVALIDUSERAGREEMENT, channelName, user, billCode);

            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
            processAgreementResp.setResponseCode(Defines.CODE_INVALIDUSERAGREEMENT);
            processAgreementResp.setXmlData(pData);
            processAgreementResp.setSignedData(null);
            processAgreementResp.setPreTrustedHubTransId(null);
            return processAgreementResp;
        }// end check user
        // check user format, don't accept "-" and "."
        // Neu la xac thuc PKI (PKISigning co worker la
        // multidisgner thi phai co email va sms)
        if (isPKISigning.equals(Defines.TRUE)) {
            if (isWS.equals(Defines.FALSE)) {
                if (workerSigning.equals("")
                        || spkiKeyname.equals("")
                        || spkiKeyType.equals("")) {

                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                if (!spkiEmail.equals("")) {
                    if (!ExtFunc.isValidEmail(spkiEmail)) {
                        LOG.error("Invalid Email");
                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_INVALIDPARAMETER,
                                Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }
                }

                if (!spkiSMS.equals("")) {
                    if (!ExtFunc.isValidPhoneNumber(spkiSMS)) {
                        LOG.error("Invalid Phone Number");
                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_INVALIDPARAMETER,
                                Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }
                }
            } else {
                if (workerSigning.equals("")
                        || spkiKeyType.equals("")
                        || spkiCertType.equals("")
                        || spkiCertProvider.equals("")
                        || spkiDn.equals("")
                        || spkiCertProfile.equals("")) {

                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                if (!ExtFunc.isNumeric(spkiCertProfile)) {
                    LOG.error("Invalid Certificate Profile: " + spkiCertProfile);
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                if (!spkiEmail.equals("")) {
                    if (!ExtFunc.isValidEmail(spkiEmail)) {
                        LOG.error("Invalid Email");
                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_INVALIDPARAMETER,
                                Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }
                }

                if (!spkiSMS.equals("")) {
                    if (!ExtFunc.isValidPhoneNumber(spkiSMS)) {
                        LOG.error("Invalid Phone Number");
                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_INVALIDPARAMETER,
                                Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }
                }
            }
        }

        if (isOtpEmail.equals(Defines.TRUE)) {
            if (!otpEmail.equals("")) {
                if (!ExtFunc.isValidEmail(otpEmail)) {

                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }
                /*
                 * if (DBConnector.getInstances().authCheckOTPEmail(user,
                 * otpEmail, channelName)) {
                 *
                 * String pData = ExtFunc.genResponseMessage(
                 * Defines.CODE_USEREMAILEXIT, Defines.ERROR_USEREMAILEXIT,
                 * channelName, user, billCode);
                 *
                 * String billCode =
                 * DBConnector.getInstances().writeLogToDataBaseOutside(workerIdOrName,
                 * username, ExtFunc.getRequestIP(wsContext), user,
                 * Defines.CODE_USEREMAILEXIT, idTag, channelName, xmlData,
                 * pData, unsignedData, signedData, functionName,
                 * trustedHubTransId);
                 *
                 * pData = ExtFunc.replaceBillCode(billCode, pData);
                 *
                 * return new TransactionInfo(pData); }
                 */
            } else {
                String pData = ExtFunc.genResponseMessage(
                        Defines.CODE_INVALIDPARAMETER,
                        Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            }
        }

        if (isOtpSms.equals(Defines.TRUE)) {
            if (!otpSms.equals("")) {
                if (!ExtFunc.isValidPhoneNumber(otpSms)) {
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }
                /*
                 * if (DBConnector.getInstances().authCheckOTPSMS(user, otpSms,
                 * channelName)) {
                 *
                 * String pData = ExtFunc.genResponseMessage(
                 * Defines.CODE_USERPHONEEXIT, Defines.ERROR_USERPHONEEXIT,
                 * channelName, user, billCode);
                 *
                 * String billCode =
                 * DBConnector.getInstances().writeLogToDataBaseOutside(workerIdOrName,
                 * username, ExtFunc.getRequestIP(wsContext), user,
                 * Defines.CODE_USERPHONEEXIT, idTag, channelName, xmlData,
                 * pData, unsignedData, signedData, functionName,
                 * trustedHubTransId);
                 *
                 * pData = ExtFunc.replaceBillCode(billCode, pData);
                 *
                 * return new TransactionInfo(pData); }
                 */
            } else {
                String pData = ExtFunc.genResponseMessage(
                        Defines.CODE_INVALIDPARAMETER,
                        Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            }
        }

        // Check expireation
        if (expiration.equals("")) {
            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_INVALIDPARAMETER,
                    Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
            processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
            processAgreementResp.setXmlData(pData);
            processAgreementResp.setSignedData(null);
            processAgreementResp.setPreTrustedHubTransId(null);
            return processAgreementResp;
        }

        int expire = 0;
        try {
            expire = Integer.parseInt(expiration);
        } catch (NumberFormatException e) {
            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_INVALIDPARAMETER,
                    Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
            processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
            processAgreementResp.setXmlData(pData);
            processAgreementResp.setSignedData(null);
            processAgreementResp.setPreTrustedHubTransId(null);
            return processAgreementResp;
        }
        if (expire <= 0) {
            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_INVALIDPARAMETER,
                    Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
            processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
            processAgreementResp.setXmlData(pData);
            processAgreementResp.setSignedData(null);
            processAgreementResp.setPreTrustedHubTransId(null);
            return processAgreementResp;
        }

        CertificateAgreementStatus certificateAgreementStatusTPKI = null;
        CertificateAgreementStatus certificateAgreementStatusLPKI = null;
        CertificateAgreementStatus certificateAgreementStatusWPKI = null;
        Integer endpointId = null;

        // Check certificate PKI
        if (isPKI.equals(Defines.TRUE)) {
            certificateAgreementStatusTPKI = isCertificateValid(channelName, user, pkiCertificate, trustedHubTransId);
            if (!certificateAgreementStatusTPKI.isValid()) {

                String pData = ExtFunc.genResponseMessage(
                        Defines.CODE_INVALIDCERTIFICATE,
                        Defines.ERROR_INVALIDCERTIFICATE, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            }

            String[] certs = ExtFunc.getCertificateComponents(pkiCertificate);

            if (DBConnector.getInstances().checkTPKICertificate(certs[5],
                    channelName, user)) {

                String pData = ExtFunc.genResponseMessage(
                        Defines.CODE_CERTIFICATEEXITED,
                        Defines.ERROR_CERTIFICATEEXITED, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_CERTIFICATEEXITED);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            }
        } // end check certificate pki

        // Check lcd certificate PKI
        if (isLCDPKI.equals(Defines.TRUE)) {
            certificateAgreementStatusLPKI = isCertificateValid(channelName, user, lcdpkiCertificate, trustedHubTransId);
            if (!certificateAgreementStatusLPKI.isValid()) {

                String pData = ExtFunc.genResponseMessage(
                        Defines.CODE_INVALIDCERTIFICATE,
                        Defines.ERROR_INVALIDCERTIFICATE, channelName, user, billCode);


                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            }

            String[] certs = ExtFunc.getCertificateComponents(lcdpkiCertificate);
            /*
             * if (DBConnector.getInstances().checkLCDPKICertificate(certs[5],
             * channelName, user)) { String pData = ExtFunc.genResponseMessage(
             * Defines.CODE_CERTIFICATEEXITED, Defines.ERROR_CERTIFICATEEXITED,
             * channelName, user, billCode);
             *
             * String billCode =
             * DBConnector.getInstances().writeLogToDataBaseOutside(workerIdOrName,
             * username, ExtFunc.getRequestIP(wsContext), user,
             * Defines.CODE_CERTIFICATEEXITED, idTag, channelName, xmlData,
             * pData, unsignedData, signedData, functionName,
             * trustedHubTransId);
             *
             * pData = ExtFunc.replaceBillCode(billCode, pData);
             * DBConnector.getInstances().updateEndpointLog(ExtFunc.getTransId(billCode)
             * , (certificateAgreementStatusTPKI !=
             * null)?certificateAgreementStatusTPKI.getEndpointId():null);
             * DBConnector.getInstances().updateEndpointLog(ExtFunc.getTransId(billCode)
             * , (certificateAgreementStatusLPKI !=
             * null)?certificateAgreementStatusLPKI.getEndpointId():null);
             * DBConnector.getInstances().updateEndpointLog(ExtFunc.getTransId(billCode)
             * , (certificateAgreementStatusWPKI !=
             * null)?certificateAgreementStatusWPKI.getEndpointId():null);
             * return new TransactionInfo(pData); }
             */

        } // end check lcd certificate pki

        // OTP
        if (isOtpHardware.equals(Defines.TRUE)) {
            // Check if serialNumber of OTP token is null
            if (otpHardware.equals("")) {

                String pData = ExtFunc.genResponseMessage(
                        Defines.CODE_INVALIDPARAMETER,
                        Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);


                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            }

            int checkOtpHardwareStatus = DBConnector.getInstances().authCheckOTPHardware(user, otpHardware, channelName);
            /*
             * if (checkOtpHardwareStatus == 1) { String pData =
             * ExtFunc.genResponseMessage( Defines.CODE_OTPHARDWAREEXIT,
             * Defines.ERROR_OTPHARDWAREEXIT, channelName, user, billCode);
             *
             * ProcessAgreementResp processAgreementResp = new
             * ProcessAgreementResp();
             * processAgreementResp.setResponseCode(Defines.CODE_OTPHARDWAREEXIT);
             * processAgreementResp.setXmlData(pData);
             * processAgreementResp.setSignedData(null);
             * processAgreementResp.setPreTrustedHubTransId(null); return
             * processAgreementResp; } else if(checkOtpHardwareStatus == 2) {
             * String pData = ExtFunc.genResponseMessage(
             * Defines.CODE_INVALID_OTPHARDWARE,
             * Defines.ERROR_INVALID_OTPHARDWARE, channelName, user, billCode);
             *
             * ProcessAgreementResp processAgreementResp = new
             * ProcessAgreementResp();
             * processAgreementResp.setResponseCode(Defines.CODE_INVALID_OTPHARDWARE);
             * processAgreementResp.setXmlData(pData);
             * processAgreementResp.setSignedData(null);
             * processAgreementResp.setPreTrustedHubTransId(null); return
             * processAgreementResp; } else { // checkOtpHardwareStatus = 0 -->
             * OK }
             */
            if (checkOtpHardwareStatus == 2) {
                String pData = ExtFunc.genResponseMessage(
                        Defines.CODE_INVALID_OTPHARDWARE,
                        Defines.ERROR_INVALID_OTPHARDWARE, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_INVALID_OTPHARDWARE);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            } else {
                // checkOtpHardwareStatus = 0 --> OK 
            }
        }

        String wpkiCert;
        String wpkiThumbprint;
        String wpkiActive;
        String wpkiVendor;
        String wpkiMsisdn;

        // pki sim
        if (isPKISim.equals(Defines.TRUE)) {

            String[] simVendor = DBConnector.getInstances().authCheckSimPKIVendor(pkiSimVendor);

            if (!pkiSim.equals("") && !pkiSimVendor.equals("")) {
                if (!ExtFunc.isValidPhoneNumber(pkiSim)) {
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);


                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                if (simVendor == null) {
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INVALID_SIM_VENDOR,
                            Defines.ERROR_INVALID_SIM_VENDOR, channelName, user, billCode);


                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALID_SIM_VENDOR);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }
                /*
                 * if (DBConnector.getInstances().authCheckSimPKI(user, pkiSim,
                 * channelName)) {
                 *
                 * String pData = ExtFunc.genResponseMessage(
                 * Defines.CODE_USERPHONEEXIT, Defines.ERROR_USERPHONEEXIT,
                 * channelName, user, billCode);
                 *
                 * String billCode =
                 * DBConnector.getInstances().writeLogToDataBaseOutside(workerIdOrName,
                 * username, ExtFunc.getRequestIP(wsContext), user,
                 * Defines.CODE_USERPHONEEXIT, idTag, channelName, xmlData,
                 * pData, unsignedData, signedData, functionName,
                 * trustedHubTransId);
                 *
                 * pData = ExtFunc.replaceBillCode(billCode, pData);
                 * DBConnector.getInstances().updateEndpointLog(ExtFunc.getTransId(billCode)
                 * , (certificateAgreementStatusTPKI !=
                 * null)?certificateAgreementStatusTPKI.getEndpointId():null);
                 * DBConnector.getInstances().updateEndpointLog(ExtFunc.getTransId(billCode)
                 * , (certificateAgreementStatusLPKI !=
                 * null)?certificateAgreementStatusLPKI.getEndpointId():null);
                 * DBConnector.getInstances().updateEndpointLog(ExtFunc.getTransId(billCode)
                 * , (certificateAgreementStatusWPKI !=
                 * null)?certificateAgreementStatusWPKI.getEndpointId():null);
                 * return new TransactionInfo(pData); }
                 */
            } else {
                String pData = ExtFunc.genResponseMessage(
                        Defines.CODE_INVALIDPARAMETER,
                        Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            }

            if (wCertificate.compareTo("") == 0) {
                // call MSSP to get certificate
                List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();

                org.signserver.clientws.Metadata user_pkisim = new org.signserver.clientws.Metadata(
                        Defines._USER, user);

                org.signserver.clientws.Metadata channelName_pkisim = new org.signserver.clientws.Metadata(
                        Defines._CHANNEL, channelName);

                org.signserver.clientws.Metadata phoneNo_pkisim = new org.signserver.clientws.Metadata(
                        Defines._PKISIM, pkiSim);

                org.signserver.clientws.Metadata vendor_pkisim = new org.signserver.clientws.Metadata(
                        Defines._PKISIMVENDOR, pkiSimVendor);

                org.signserver.clientws.Metadata method_pkisim = new org.signserver.clientws.Metadata(
                        Defines._METHOD, Defines.SIGNERAP_CERTQUERY);

                org.signserver.clientws.Metadata endpointconfigid_pkisim = new org.signserver.clientws.Metadata(
                        Defines._ENDPOINTCONFIGID, simVendor[1]);

                org.signserver.clientws.Metadata endpointconfigValue_pkisim = new org.signserver.clientws.Metadata(
                        Defines._ENDPOINTVALUE, simVendor[2]);

                org.signserver.clientws.Metadata trustedhub_trans_id = new org.signserver.clientws.Metadata(Defines._TRUSTEDHUBTRANSID, String.valueOf(trustedHubTransId));

                requestMetadata.add(user_pkisim);
                requestMetadata.add(channelName_pkisim);
                requestMetadata.add(phoneNo_pkisim);
                requestMetadata.add(vendor_pkisim);
                requestMetadata.add(method_pkisim);
                requestMetadata.add(endpointconfigid_pkisim);
                requestMetadata.add(endpointconfigValue_pkisim);
                requestMetadata.add(trustedhub_trans_id);

                final int requestId = random.nextInt();

                final int wId = getWorkerId(Defines.WORKER_SIGNERAP);

                final RequestContext requestContext = handleRequestContext(
                        requestMetadata, wId);

                final ProcessRequest req = new GenericSignRequest(requestId,
                        byteData);
                ProcessResponse resp = null;
                try {
                    resp = getWorkerSession().process(wId, req, requestContext);
                } catch (Exception e) {
                    LOG.error("Something wrong: " + e.getMessage());
                    e.printStackTrace();
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INTERNALSYSTEM,
                            Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                if (!(resp instanceof GenericSignResponse)) {
                    LOG.error("resp is not a instance of GenericSignResponse");

                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_UNEXPECTEDRETURNTYPE,
                            Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                } else {
                    final GenericSignResponse signResponse = (GenericSignResponse) resp;
                    if (signResponse.getRequestID() != requestId) {
                        LOG.error("Response ID " + signResponse.getRequestID()
                                + " not matching request ID " + requestId);

                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_NOTMATCHID,
                                Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_NOTMATCHID);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }
                    int responseCode = signResponse.getResponseCode();
                    String responseMessage = signResponse.getResponseMessage();
                    if (responseCode == Defines.CODE_SUCCESS) {
                        List<SignerInfoResponse> signerInfo = signResponse.getSignerInfoResponse();
                        for (int i = 0; i < signerInfo.size(); i++) {
                            if (signerInfo.get(i).isIsSigning()) {
                                wCertificate = signerInfo.get(i).getCertificate();
                                break;
                            }
                        }

                        if (wCertificate.compareTo("") == 0) {
                            LOG.error("Sim doesn't have any certificates");
                            LOG.error("Request to MSSP to get certificate. But response is NULL");
                            String pData = ExtFunc.genResponseMessage(
                                    Defines.CODE_MSSP_NOCERTIFICATE,
                                    Defines.MSSP_NOCERTIFICATE, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        }
                    } else {
                        LOG.error("Sim doesn't have any certificates");
                        String pData = ExtFunc.genResponseMessage(
                                responseCode,
                                responseMessage, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(responseCode);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }
                }
            }

            certificateAgreementStatusWPKI = isCertificateValid(channelName, user, wCertificate, trustedHubTransId);
            if (!certificateAgreementStatusWPKI.isValid()) {
                String pData = ExtFunc.genResponseMessage(
                        Defines.CODE_INVALIDCERTIFICATE,
                        Defines.ERROR_INVALIDCERTIFICATE, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            }
            String[] certs = ExtFunc.getCertificateComponents(wCertificate);
            wpkiCert = wCertificate;
            wpkiThumbprint = certs[5];
            wpkiActive = Defines.TRUE;
            wpkiVendor = pkiSimVendor;
            wpkiMsisdn = pkiSim;

        } else {
            wpkiCert = Defines.NULL;
            wpkiThumbprint = Defines.NULL;
            wpkiActive = Defines.FALSE;
            wpkiVendor = Defines.NULL;
            wpkiMsisdn = Defines.NULL;
        }

        String tpkiCert;
        String tpkiThumbprint;
        String tpkiActive;

        if (isPKI.equals(Defines.TRUE)) {
            String[] certs = ExtFunc.getCertificateComponents(pkiCertificate);
            tpkiCert = pkiCertificate;
            tpkiThumbprint = certs[5];
            tpkiActive = Defines.TRUE;
        } else {
            tpkiCert = Defines.NULL;
            tpkiThumbprint = Defines.NULL;
            tpkiActive = Defines.FALSE;
        }

        String signserverWorkerName;
        String signserverKeyName;
        String signserverWorkerConfig;
        String signserverSpkiEmail;
        String signserverSpkiSMS;
        String signserverSpkiKeyType;
        String signserverSpkiSlotId;
        String signserverSpkiModule;
        String signserverSpkiPin;
        String signserverSpkiLevel;
        int signserverSpkiP11InfoId;
        String[] certTypeKeyInfo = null;
        Ca ca = null;
        int certProfileId = 1;
        String spkiCsr = null;

        if (isPKISigning.compareTo(Defines.TRUE) == 0) {

            P11Info p11Info = null;
            if (spkiP11Info.compareTo("") != 0) {
                p11Info = DBConnector.getInstances().getP11Info(spkiP11Info);
            } else {
                p11Info = DBConnector.getInstances().getP11Info(null);
            }

            if (p11Info == null) {
                LOG.error("HSM slot has been used or not available in system");
                String pData = ExtFunc.genResponseMessage(
                        Defines.CODE_INVALID_P11INFO,
                        Defines.ERROR_INVALID_P11INFO, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_INVALID_P11INFO);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            }

            signserverWorkerName = channelName.concat("-").concat(user).concat("-").concat(workerSigning);
            signserverKeyName = spkiKeyname;
            signserverWorkerConfig = DBConnector.getInstances().authGetWorkerConfig(workerSigning);
            signserverSpkiEmail = spkiEmail;
            signserverSpkiSMS = spkiSMS;
            signserverSpkiKeyType = spkiKeyType;

            signserverSpkiSlotId = String.valueOf(p11Info.getSlotId());
            signserverSpkiModule = p11Info.getModule();
            signserverSpkiPin = p11Info.getPin();
            signserverSpkiLevel = p11Info.getLevel();
            signserverSpkiP11InfoId = p11Info.getP11InfoId();

            if (isWS.equals(Defines.TRUE)) {
                certTypeKeyInfo = DBConnector.getInstances().getCertTypeKeyInfo(spkiCertType);
                if (certTypeKeyInfo == null) {
                    LOG.error("Invalid Certificate Type");
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                List<CertTemplate> certTemplates = DBConnector.getInstances().getCertTemplate(Integer.parseInt(certTypeKeyInfo[3]));

                if (!ExtFunc.checkCertTemplate(spkiDn, certTemplates)) {
                    LOG.error("Invalid DN in your request");
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INVALID_SUBJECTDN,
                            Defines.ERROR_INVALID_SUBJECTDN, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALID_SUBJECTDN);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                certProfileId = DBConnector.getInstances().getCertProfileId(Integer.parseInt(spkiCertProfile));
                if (certProfileId == 1) {
                    LOG.error("Invalid Certificate Profile");
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                ca = DBConnector.getInstances().getCa(spkiCertProvider);

                if (ca == null) {
                    LOG.error("Invalid CA Certificate Provider");
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }
            }

        } else {
            signserverWorkerName = Defines.NULL;
            signserverKeyName = Defines.NULL;
            signserverWorkerConfig = Defines.NULL;
            signserverSpkiEmail = Defines.NULL;
            signserverSpkiSMS = Defines.NULL;
            signserverSpkiKeyType = Defines.NULL;

            signserverSpkiSlotId = Defines.NULL;
            signserverSpkiModule = Defines.NULL;
            signserverSpkiPin = Defines.NULL;
            signserverSpkiLevel = Defines.NULL;
            signserverSpkiP11InfoId = 1; // N/A
        }

        String lpkiCert;
        String lpkiThumbprint;
        String lpkiActive;

        if (isLCDPKI.equals(Defines.TRUE)) {
            String[] certs = ExtFunc.getCertificateComponents(lcdpkiCertificate);
            lpkiCert = lcdpkiCertificate;
            lpkiThumbprint = certs[5];
            lpkiActive = Defines.TRUE;
        } else {
            lpkiCert = Defines.NULL;
            lpkiThumbprint = Defines.NULL;
            lpkiActive = Defines.FALSE;
        }

        // 20180814
        String signserverPassword = null;
        if (isPKISigning.equals(Defines.TRUE)) {
            signserverPassword = DBConnector.getInstances().getGeneralPolicy().getFrontDefaultPassSignserver();
            if (DBConnector.getInstances().getGeneralPolicy().isFrontIsRandomSignServerPassword()) {
                signserverPassword = ExtFunc.getRandomSignserverPassword();
            }
        }

        if (isPKISigning.equals(Defines.TRUE)
                && isWS.equals(Defines.TRUE)) {
            if (signserverSpkiKeyType.equals(Defines.SPKI_KEYTYPE_USHARE)) {
                // USER SHARE
                signserverKeyName = channelName.concat("-").concat(ExtFunc.getDateFormat());
            } else if (signserverSpkiKeyType.equals(Defines.SPKI_KEYTYPE_CSHARE)) {
                // CHANNEL SHARE
                signserverKeyName = ExtFunc.getDateFormat();
            } else {
                // PRIVATE
                signserverKeyName = channelName.concat("-").concat(user).concat("-").concat(ExtFunc.getDateFormat());
            }
        }

        // insert agreement
        int agreementID = DBConnector.getInstances().insertAgreement(
                channelName,
                user,
                Defines.AGREEMENT_STATUS_ACTI,
                expire,
                idTag,
                branchId,
                // otpinformation
                otpSms,
                otpEmail,
                otpHardware,
                isOtpEmail.equals(Defines.TRUE),
                isOtpSms.equals(Defines.TRUE),
                isOtpHardware.equals(Defines.TRUE),
                isOtpSoftware.equals(Defines.TRUE),
                // single agreement details
                signserverWorkerName,
                signserverKeyName,
                signserverSpkiKeyType,
                signserverSpkiEmail,
                signserverSpkiSMS,
                signserverWorkerConfig,
                signserverSpkiSlotId,
                signserverSpkiModule,
                signserverSpkiPin,
                signserverSpkiLevel,
                signserverSpkiP11InfoId,
                signserverWorkerName.equals(Defines.NULL) ? false : true,
                signserverPassword,
                // pkiinformation
                tpkiCert,
                tpkiThumbprint,
                tpkiActive.equals(Defines.TRUE) ? true : false,
                lpkiCert,
                lpkiThumbprint,
                lpkiActive.equals(Defines.TRUE) ? true : false,
                wpkiCert,
                wpkiThumbprint,
                wpkiActive.equals(Defines.TRUE) ? true : false,
                wpkiMsisdn,
                wpkiVendor,
                isU2F.equals(Defines.TRUE) ? true : false,
                appId);

        if (agreementID == 1) {
            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_CREATEAGREEMENT,
                    Defines.ERROR_CREATEAGREEMENT, channelName, user, billCode);

            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
            processAgreementResp.setResponseCode(Defines.CODE_CREATEAGREEMENT);
            processAgreementResp.setXmlData(pData);
            processAgreementResp.setSignedData(null);
            processAgreementResp.setPreTrustedHubTransId(null);
            return processAgreementResp;
        } else {
            if (isPKISigning.equals(Defines.TRUE)
                    && !signserverWorkerConfig.equals(Defines.NULL)
                    && isWS.equals(Defines.TRUE)) {

                if (signserverSpkiKeyType.equals(Defines.SPKI_KEYTYPE_USHARE)) {
                    // USER SHARE
                    signserverKeyName = channelName.concat("-").concat(ExtFunc.getDateFormat());
                } else if (signserverSpkiKeyType.equals(Defines.SPKI_KEYTYPE_CSHARE)) {
                    // CHANNEL SHARE
                    signserverKeyName = ExtFunc.getDateFormat();
                } else {
                    // PRIVATE
                    signserverKeyName = channelName.concat("-").concat(user).concat("-").concat(ExtFunc.getDateFormat());
                }

                try {
                    Properties p = new Properties();
                    p.load(new ByteArrayInputStream(signserverWorkerConfig.getBytes()));
                    p.setProperty("WORKERGENID1.NAME", signserverWorkerName);
                    p.setProperty("WORKERGENID1.defaultKey", signserverKeyName);
                    p.setProperty("WORKERGENID1.slot", signserverSpkiSlotId);
                    p.setProperty("WORKERGENID1.sharedLibrary", signserverSpkiModule);

                    if (signserverSpkiLevel.compareTo(Defines.P11_LEVEL_BASIC) == 0) {
                        p.setProperty("WORKERGENID1.pin", signserverSpkiPin);
                    } else {
                        // avanced, so remove pin property
                        p.remove("WORKERGENID1.pin");
                    }
                    ByteArrayOutputStream os = new ByteArrayOutputStream();
                    p.store(os, null);
                    signserverWorkerConfig = new String(os.toByteArray());
                    os.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }

                int wUUID = AdminLayer.getInstance().addWorker(signserverWorkerConfig);

                if (wUUID == -1) {
                    LOG.error("Error while getting WorkerUUID from Signserver response");
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INTERNALSYSTEM,
                            Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    processAgreementResp.setAgreementId(agreementID);
                    return processAgreementResp;
                }

                Integer workerUUID = Integer.valueOf(wUUID);

                // reload worker
                AdminLayer.getInstance().reloadWorker(workerUUID.toString());

                /*
                 * update SignServerStatusID, WorkerUUID
                 *
                 *
                 */
                DBConnector.getInstances().updateSignerServerAgreement(
                        agreementID,
                        Integer.valueOf(Defines.SPKI_STATUS_WORKER),
                        null, signserverKeyName, null, null, null, null,
                        workerUUID, null, null, null, null, null, null, null, null, null, null, null);

                // GenKey
                String generateSignerKeyResp = AdminLayer.getInstance().generateSignerKey(
                        workerUUID,
                        certTypeKeyInfo[1],
                        certTypeKeyInfo[2],
                        signserverKeyName,
                        signserverSpkiPin);

                // reload worker
                AdminLayer.getInstance().reloadWorker(workerUUID.toString());

                // update SignServerStatusID
                DBConnector.getInstances().updateSignerServerAgreement(
                        agreementID,
                        Integer.valueOf(Defines.SPKI_STATUS_KEY),
                        null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null);

                // Generate csr
                if (signserverSpkiLevel.compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                    AdminLayer.getInstance().activateSigner(workerUUID, signserverSpkiPin);
                }

                String pkcs10CertificateRequestForKeyResp = AdminLayer.getInstance().getPKCS10CertificateRequestForKey(
                        workerUUID, certTypeKeyInfo[0], spkiDn, false, true);
                spkiCsr = pkcs10CertificateRequestForKeyResp;

                if (signserverSpkiLevel.compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                    AdminLayer.getInstance().deactivateSigner(workerUUID);
                }

                // update SignServerStatusID
                DBConnector.getInstances().updateSignerServerAgreement(
                        agreementID,
                        Integer.valueOf(Defines.SPKI_STATUS_CSR),
                        null,
                        null,
                        null,
                        pkcs10CertificateRequestForKeyResp,
                        null,
                        null,
                        null,
                        spkiDn,
                        null, null, null, null, Integer.valueOf(ca.getCaID()),
                        null, Integer.valueOf(certProfileId), null, null, Integer.valueOf(certTypeKeyInfo[3]));
            }
            // 20180814
            // send email notify signserver password
            GeneralPolicy gp = DBConnector.getInstances().getGeneralPolicy();
            if (gp.isFrontIsNotifySignServerPasswordByEmail()) {
                if (isPKISigning.equals(Defines.TRUE)) {
                    try {
                        // 20180815
                                    /*
                         * String template =
                         * gp.getFrontEmailTemplateSignServerUserCreate();
                         *
                         * Properties p = new Properties(); Reader reader = new
                         * InputStreamReader(new
                         * ByteArrayInputStream(template.getBytes()),
                         * StandardCharsets.UTF_8); p.load(reader); String
                         * subject = p.getProperty("SUBJECT"); String content =
                         * p.getProperty("CONTENT");
                         */
                        String[] template = DBConnector.getInstances().getBackOfficeParamsDetailClient(Defines.PARAMS_BACKOFFICE_MAIL_NEWACCOUNT_SIGNSERVER, true);
                        String subject = template[0];
                        String content = template[1];

                        content = content.replace(Defines.PATTERN_BOLD_OPEN, "<b>");
                        content = content.replace(Defines.PATTERN_BOLD_CLOSE, "</b>");
                        content = content.replace(Defines.PATTERN_NEW_LINE, "<br>");
                        content = content.replace(Defines.PATTERN_USERNAME, user);

                        if (signserverSpkiLevel.equals(Defines.P11_LEVEL_BASIC)) {
                            content = content.replace(Defines.PATTERN_PASSWORD, signserverPassword);
                        } else {
                            content = content.replace(Defines.PATTERN_PASSWORD, signserverSpkiPin);
                        }

                        final String threadChannelName = channelName;
                        final String threadUser = user;
                        final String threadSignserverSpkiEmail = signserverSpkiEmail;
                        final String threadSubject = subject;
                        final String threadContent = content;
                        new Thread(new Runnable() {

                            @Override
                            public void run() {
                                String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(Defines.CONNECTION_PARAMS_SMTP);
                                if (endpointParams != null) {
                                    EndpointServiceResp endpointServiceResp = EndpointService.getInstance().sendEmailNoLogging(
                                            threadChannelName,
                                            threadUser,
                                            threadSignserverSpkiEmail,
                                            threadSubject,
                                            threadContent,
                                            endpointParams[1],
                                            Integer.parseInt(endpointParams[2]));
                                    if (endpointServiceResp.getResponseCode() == 0) {
                                        LOG.info("Email contains password has been sent to " + threadSignserverSpkiEmail);
                                    } else {
                                        LOG.error("Failed to send email contains password to " + threadSignserverSpkiEmail);
                                    }
                                } else {
                                    LOG.error("No endpoint config to send email");
                                }
                            }
                        }).start();

                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        }

        String pData = ExtFunc.genResponseMessageWithSPKI(Defines.CODE_SUCCESS,
                Defines.SUCCESS, channelName, user,
                Defines.AGREEMENT_STATUS_ACTI, spkiCsr, billCode);


        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
        processAgreementResp.setResponseCode(Defines.CODE_SUCCESS);
        processAgreementResp.setXmlData(pData);
        processAgreementResp.setSignedData(null);
        processAgreementResp.setPreTrustedHubTransId(null);
        processAgreementResp.setAgreementId(agreementID);
        return processAgreementResp;
    }

    private static ProcessAgreementResp changeAgreementInfo(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
        String workerIdOrName = Defines.WORKER_AGREEMENT;
        String functionName = Defines.WORKER_AGREEMENT;
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


        String action = ExtFunc.getContent(Defines._ACTION, xmlData);

        int agreementID = DBConnector.getInstances().authGetArrangementID(
                channelName, user);
        if (agreementID == 0) {

            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_AGREEMENTNOTEXITS,
                    Defines.ERROR_AGREEMENTNOTEXITS, channelName, user, billCode);

            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
            processAgreementResp.setResponseCode(Defines.CODE_AGREEMENTNOTEXITS);
            processAgreementResp.setXmlData(pData);
            processAgreementResp.setSignedData(null);
            processAgreementResp.setPreTrustedHubTransId(null);
            return processAgreementResp;
        }

        String isOtpSms = ExtFunc.getContent(Defines._ISOTPSMS, xmlData);
        String otpSms = ExtFunc.getContent(Defines._OTPSMS, xmlData);

        String isOtpEmail = ExtFunc.getContent(Defines._ISOTPEMAIL, xmlData);
        String otpEmail = ExtFunc.getContent(Defines._OTPEMAIL, xmlData);

        String isOtpHardware = ExtFunc.getContent(Defines._ISOTPHARDWARE,
                xmlData);
        String otpHardware = ExtFunc.getContent(Defines._OTPHARDWARE, xmlData);

        String isPKI = ExtFunc.getContent(Defines._ISPKI, xmlData);
        String pkiCertificate = ExtFunc.getContent(Defines._CERTIFICATE,
                xmlData);

        String isOtpSoftware = ExtFunc.getContent(Defines._ISOTPSOFTWARE,
                xmlData);

        String isUnblockOTP = ExtFunc.getContent(Defines._ISUNBLOCKOTP, xmlData);

        String expiration = ExtFunc.getContent(Defines._EXPIRATION, xmlData);

        String isExtend = ExtFunc.getContent(Defines._ISEXTEND, xmlData);

        String isPKISigning = ExtFunc.getContent(Defines._ISPKISIGN, xmlData);

        String isWS;

        String spkiCertType = ExtFunc.getContent(Defines._SPKICERTTYPE, xmlData);

        String spkiCertProvider = ExtFunc.getContent(Defines._SPKICERTPROVIDER, xmlData);

        String spkiDn = ExtFunc.getContent(Defines._SPKIDN, xmlData);

        String spkiCertProfile = ExtFunc.getContent(Defines._SPKICERTPROFILE, xmlData);

        String _spkiCsr = null;

        String workerSigning = ExtFunc.getContent(Defines._WORKERNAMESIGNING, xmlData);
        String spkiEmail = ExtFunc.getContent(Defines._SPKIEMAIL, xmlData);
        String spkiSMS = ExtFunc.getContent(Defines._SPKISMS, xmlData);
        String spkiKeyname = ExtFunc.getContent(Defines._SKEYNAME, xmlData);
        String spkiKeyType = ExtFunc.getContent(Defines._SKEYTYPE, xmlData);
        String spkiP11Info = ExtFunc.getContent(Defines._P11INFO, xmlData);
        String currentPassword = ExtFunc.getContent(Defines._CURRENTPW, xmlData);
        String newPassword = ExtFunc.getContent(Defines._NEWPW, xmlData);
        String recovery = ExtFunc.getContent(Defines._SETRECOVERY, xmlData);
        String registered = ExtFunc.getContent(Defines._ISREGISTRED, xmlData);
        String isInstallCert = ExtFunc.getContent(Defines._ISINSTALLCERT, xmlData);
        String scertificate = ExtFunc.getContent(Defines._SPKICERT, xmlData);

        String isLCDPKI = ExtFunc.getContent(Defines._ISLCDPKI, xmlData);
        String lcdpkiCertificate = ExtFunc.getContent(Defines._LCDCERTIFICATE, xmlData);

        String isPKISim = ExtFunc.getContent(Defines._ISPKISIM, xmlData);
        String pkiSim = ExtFunc.getContent(Defines._PKISIM, xmlData);
        String pkiSimVendor = ExtFunc.getContent(Defines._PKISIMVENDOR, xmlData);
        String wCertificate = ExtFunc.getContent(Defines._WCERTIFICATE, xmlData);

        String isU2F = ExtFunc.getContent(Defines._ISU2F, xmlData);
        String appId = ExtFunc.getContent(Defines._APPID, xmlData);

        boolean isEffective = false;

        // OTP SMS
        if (!isOtpSms.equals("")) {
            if (!isOtpSms.equals(Defines.TRUE)) {
                isOtpSms = Defines.FALSE;
            }
            // Check OTP Method
            if (isOtpSms.equals(Defines.FALSE)) {
                boolean res = DBConnector.getInstances().authSetIsOTPSMSArrangement(agreementID, false);
                if (!res) {

                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_UPDATEOTPSMS,
                            Defines.ERROR_UPDATEOTPSMS, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UPDATEOTPSMS);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                res = DBConnector.getInstances().authSetOTPSMSArrangement(
                        agreementID, Defines.NULL);
                isEffective = true;
                if (!res) {
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_UPDATEOTPSMS,
                            Defines.ERROR_UPDATEOTPSMS, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UPDATEOTPSMS);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }
            } else {
                if (otpSms.compareTo("") == 0) {

                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                } else {
                    if (!ExtFunc.isValidPhoneNumber(otpSms)) {

                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_INVALIDPARAMETER,
                                Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }
                    /*
                     * if (DBConnector.getInstances().authCheckOTPSMS(user,
                     * otpSms, channelName)) {
                     *
                     * String pData = ExtFunc.genResponseMessage(
                     * Defines.CODE_USERPHONEEXIT, Defines.ERROR_USERPHONEEXIT,
                     * channelName, user, billCode);
                     *
                     * String billCode =
                     * DBConnector.getInstances().writeLogToDataBaseOutside(workerIdOrName,
                     * username, ExtFunc.getRequestIP(wsContext), user,
                     * Defines.CODE_USERPHONEEXIT, idTag, channelName, xmlData,
                     * pData, unsignedData, signedData, functionName,
                     * trustedHubTransId);
                     *
                     * pData = ExtFunc.replaceBillCode(billCode, pData);
                     *
                     * return new TransactionInfo(pData); }
                     */
                    boolean res = DBConnector.getInstances().authSetIsOTPSMSArrangement(agreementID, true);
                    if (!res) {

                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_UPDATEOTPSMS,
                                Defines.ERROR_UPDATEOTPSMS, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_UPDATEOTPSMS);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }
                    res = DBConnector.getInstances().authSetOTPSMSArrangement(
                            agreementID, otpSms);
                    isEffective = true;
                    if (!res) {

                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_UPDATEOTPSMS,
                                Defines.ERROR_UPDATEOTPSMS, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_UPDATEOTPSMS);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }
                }
            }

        } // end otp sms

        // OTPEmail
        if (!isOtpEmail.equals("")) {
            if (!isOtpEmail.equals(Defines.TRUE)) {
                isOtpEmail = Defines.FALSE;
            }
            // Check OTP Method
            if (isOtpEmail.equals(Defines.FALSE)) {
                boolean res = DBConnector.getInstances().authSetIsOTPEmailArrangement(agreementID, false);
                if (!res) {

                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_UPDATEOTPEMAIL,
                            Defines.ERROR_UPDATEOTPEMAIL, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UPDATEOTPEMAIL);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                res = DBConnector.getInstances().authSetOTPEmailArrangement(
                        agreementID, Defines.NULL);
                isEffective = true;
                if (!res) {
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_UPDATEOTPEMAIL,
                            Defines.ERROR_UPDATEOTPEMAIL, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UPDATEOTPEMAIL);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

            } else {
                if (otpEmail.compareTo("") == 0) {
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                } else {
                    if (!ExtFunc.isValidEmail(otpEmail)) {
                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_INVALIDPARAMETER,
                                Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }
                    /*
                     * if (DBConnector.getInstances().authCheckOTPEmail(user,
                     * otpEmail, channelName)) {
                     *
                     * String pData = ExtFunc.genResponseMessage(
                     * Defines.CODE_USEREMAILEXIT, Defines.ERROR_USEREMAILEXIT,
                     * channelName, user, billCode);
                     *
                     * String billCode =
                     * DBConnector.getInstances().writeLogToDataBaseOutside(workerIdOrName,
                     * username, ExtFunc.getRequestIP(wsContext), user,
                     * Defines.CODE_USEREMAILEXIT, idTag, channelName, xmlData,
                     * pData, unsignedData, signedData, functionName,
                     * trustedHubTransId);
                     *
                     * pData = ExtFunc.replaceBillCode(billCode, pData);
                     *
                     * return new TransactionInfo(pData); }
                     */
                    boolean res = DBConnector.getInstances().authSetIsOTPEmailArrangement(agreementID, true);
                    if (!res) {

                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_UPDATEOTPEMAIL,
                                Defines.ERROR_UPDATEOTPEMAIL, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_UPDATEOTPEMAIL);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }

                    res = DBConnector.getInstances().authSetOTPEmailArrangement(agreementID, otpEmail);
                    isEffective = true;
                    if (!res) {
                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_UPDATEOTPEMAIL,
                                Defines.ERROR_UPDATEOTPEMAIL, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_UPDATEOTPEMAIL);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }

                }
            }

        } // end OTP email

        // OTP hardware
        if (!isOtpHardware.equals("")) {
            if (!isOtpHardware.equals(Defines.TRUE)) {
                isOtpHardware = Defines.FALSE;
            }
            // Check OTP Method
            if (isOtpHardware.equals(Defines.FALSE)) {

                boolean res = DBConnector.getInstances().authSetIsOTPHardwareArrangement(agreementID, false);
                if (!res) {

                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_UPDATEOTPHARDWARE,
                            Defines.ERROR_UPDATEOTPHARDWARE, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UPDATEOTPHARDWARE);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }
                res = DBConnector.getInstances().authSetOTPHardwareArrangement(
                        agreementID, Defines.NULL);
                isEffective = true;
                if (!res) {
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_UPDATEOTPHARDWARE,
                            Defines.ERROR_UPDATEOTPHARDWARE, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UPDATEOTPHARDWARE);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

            } else {
                if (otpHardware.compareTo("") == 0) {

                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                } else {

                    int checkOtpHardwareStatus = DBConnector.getInstances().authCheckOTPHardware(user, otpHardware, channelName);
                    /*
                     * if (checkOtpHardwareStatus == 1) {
                     *
                     * String pData = ExtFunc.genResponseMessage(
                     * Defines.CODE_OTPHARDWAREEXIT,
                     * Defines.ERROR_OTPHARDWAREEXIT, channelName, user,
                     * billCode);
                     *
                     * ProcessAgreementResp processAgreementResp = new
                     * ProcessAgreementResp();
                     * processAgreementResp.setResponseCode(Defines.CODE_OTPHARDWAREEXIT);
                     * processAgreementResp.setXmlData(pData);
                     * processAgreementResp.setSignedData(null);
                     * processAgreementResp.setPreTrustedHubTransId(null);
                     * return processAgreementResp; } else
                     * if(checkOtpHardwareStatus == 2) {
                     *
                     * String pData = ExtFunc.genResponseMessage(
                     * Defines.CODE_INVALID_OTPHARDWARE,
                     * Defines.ERROR_INVALID_OTPHARDWARE, channelName, user,
                     * billCode);
                     *
                     * ProcessAgreementResp processAgreementResp = new
                     * ProcessAgreementResp();
                     * processAgreementResp.setResponseCode(Defines.CODE_INVALID_OTPHARDWARE);
                     * processAgreementResp.setXmlData(pData);
                     * processAgreementResp.setSignedData(null);
                     * processAgreementResp.setPreTrustedHubTransId(null);
                     * return processAgreementResp; } else { //
                     * checkOtpHardwareStatus = 0 --> OK }
                     */
                    if (checkOtpHardwareStatus == 2) {
                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_INVALID_OTPHARDWARE,
                                Defines.ERROR_INVALID_OTPHARDWARE, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_INVALID_OTPHARDWARE);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    } else {
                        // checkOtpHardwareStatus = 0 --> OK 
                    }

                    boolean res = DBConnector.getInstances().authSetIsOTPHardwareArrangement(agreementID, true);
                    if (!res) {

                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_UPDATEOTPHARDWARE,
                                Defines.ERROR_UPDATEOTPHARDWARE, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_UPDATEOTPHARDWARE);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }

                    res = DBConnector.getInstances().authSetOTPHardwareArrangement(agreementID,
                            otpHardware);
                    isEffective = true;
                    if (!res) {

                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_UPDATEOTPHARDWARE,
                                Defines.ERROR_UPDATEOTPHARDWARE, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_UPDATEOTPHARDWARE);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }
                }
            }
        } // End OTP Hardware

        // OTP Software
        if (!isOtpSoftware.equals("")) {
            if (!isOtpSoftware.equals(Defines.TRUE)) {
                isOtpSoftware = Defines.FALSE;
            }
            boolean res = DBConnector.getInstances().authSetIsOTPSoftwareArrangement(agreementID,
                    isOtpSoftware.equals(Defines.TRUE));
            isEffective = true;
            if (!res) {

                String pData = ExtFunc.genResponseMessage(
                        Defines.CODE_UPDATEOTPSOFTWARE,
                        Defines.ERROR_UPDATEOTPSOFTWARE, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_UPDATEOTPSOFTWARE);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            }
        } // End otp software

        CertificateAgreementStatus certificateAgreementStatusTPKI = null;
        CertificateAgreementStatus certificateAgreementStatusLPKI = null;
        CertificateAgreementStatus certificateAgreementStatusWPKI = null;
        Integer endpointId = null;

        // PKI
        if (!isPKI.equals("")) {
            if (!isPKI.equals(Defines.TRUE)) {
                isPKI = Defines.FALSE;
            }
            // Check PKI method
            if (isPKI.equals(Defines.FALSE)) {
                // update status in agreement
                boolean res = DBConnector.getInstances().authSetIsPKIArrangement(agreementID, false);
                if (!res) {

                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_UPDATEPKI,
                            Defines.ERROR_UPDATEPKI, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UPDATEPKI);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }
                // update in pkiinformation
                res = DBConnector.getInstances().authSetCertificateArrangement(
                        agreementID, Defines.NULL, Defines.NULL);
                isEffective = true;
                if (!res) {
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_UPDATEPKI,
                            Defines.ERROR_UPDATEPKI, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UPDATEPKI);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }
            } else {
                if (pkiCertificate.compareTo("") == 0) {

                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                } else {
                    // check validity

                    certificateAgreementStatusTPKI = isCertificateValid(channelName, user, pkiCertificate, trustedHubTransId);

                    if (!certificateAgreementStatusTPKI.isValid()) {

                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_INVALIDCERTIFICATE,
                                Defines.ERROR_INVALIDCERTIFICATE, channelName, user, billCode);


                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }
                    // check exitance
                    String[] certs = ExtFunc.getCertificateComponents(pkiCertificate);

                    if (DBConnector.getInstances().checkTPKICertificate(
                            certs[5], channelName, user)) {

                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_CERTIFICATEEXITED,
                                Defines.ERROR_CERTIFICATEEXITED, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_CERTIFICATEEXITED);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }

                    // update status in agreement
                    boolean res = DBConnector.getInstances().authSetIsPKIArrangement(agreementID, true);

                    if (!res) {

                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_UPDATEPKI,
                                Defines.ERROR_UPDATEPKI, channelName, user, billCode);


                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_UPDATEPKI);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }
                    // update in pkiinformation
                    res = DBConnector.getInstances().authSetCertificateArrangement(agreementID,
                            certs[5], pkiCertificate);
                    isEffective = true;
                    if (!res) {
                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_UPDATEPKI,
                                Defines.ERROR_UPDATEPKI, channelName, user, billCode);


                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_UPDATEPKI);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }

                }
            }
        } // End PKI updated

        // LCD PKI
        if (!isLCDPKI.equals("")) {
            if (!isLCDPKI.equals(Defines.TRUE)) {
                isLCDPKI = Defines.FALSE;
            }
            // Check LCD PKI method
            if (isLCDPKI.equals(Defines.FALSE)) {
                // update status in agreement
                boolean res = DBConnector.getInstances().authSetIsLCDPKIArrangement(agreementID, false);
                if (!res) {

                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_UPDATELCDPKI,
                            Defines.ERROR_UPDATELCDPKI, channelName, user, billCode);


                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UPDATELCDPKI);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }
                // update in lcd pkiinformation
                res = DBConnector.getInstances().authSetLCDCertificateArrangement(agreementID,
                        Defines.NULL, Defines.NULL);
                isEffective = true;
                if (!res) {
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_UPDATELCDPKI,
                            Defines.ERROR_UPDATELCDPKI, channelName, user, billCode);


                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UPDATELCDPKI);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }
            } else {
                if (lcdpkiCertificate.compareTo("") == 0) {
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);


                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                } else {
                    // check validity
                    certificateAgreementStatusLPKI = isCertificateValid(channelName, user, lcdpkiCertificate, trustedHubTransId);
                    if (!certificateAgreementStatusLPKI.isValid()) {

                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_INVALIDCERTIFICATE,
                                Defines.ERROR_INVALIDCERTIFICATE, channelName, user, billCode);


                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }
                    // check exitance
                    String[] certs = ExtFunc.getCertificateComponents(lcdpkiCertificate);
                    /*
                     * if (DBConnector.getInstances().checkLCDPKICertificate(
                     * certs[5], channelName, user)) {
                     *
                     * String pData = ExtFunc.genResponseMessage(
                     * Defines.CODE_CERTIFICATEEXITED,
                     * Defines.ERROR_CERTIFICATEEXITED, channelName, user,
                     * billCode);
                     *
                     * String billCode =
                     * DBConnector.getInstances().writeLogToDataBaseOutside(workerIdOrName,
                     * username, ExtFunc.getRequestIP(wsContext), user,
                     * Defines.CODE_CERTIFICATEEXITED, idTag, channelName,
                     * xmlData, pData, unsignedData, signedData, functionName,
                     * trustedHubTransId);
                     *
                     * pData = ExtFunc.replaceBillCode(billCode, pData);
                     * DBConnector.getInstances().updateEndpointLog(ExtFunc.getTransId(billCode)
                     * , (certificateAgreementStatusTPKI !=
                     * null)?certificateAgreementStatusTPKI.getEndpointId():null);
                     * DBConnector.getInstances().updateEndpointLog(ExtFunc.getTransId(billCode)
                     * , (certificateAgreementStatusLPKI !=
                     * null)?certificateAgreementStatusLPKI.getEndpointId():null);
                     * DBConnector.getInstances().updateEndpointLog(ExtFunc.getTransId(billCode)
                     * , (certificateAgreementStatusWPKI !=
                     * null)?certificateAgreementStatusWPKI.getEndpointId():null);
                     * return new TransactionInfo(pData); }
                     */
                    // update status in agreement
                    boolean res = DBConnector.getInstances().authSetIsLCDPKIArrangement(agreementID, true);

                    if (!res) {
                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_UPDATELCDPKI,
                                Defines.ERROR_UPDATELCDPKI, channelName, user, billCode);


                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_UPDATELCDPKI);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }
                    // update in pkiinformation
                    res = DBConnector.getInstances().authSetLCDCertificateArrangement(agreementID,
                            certs[5], lcdpkiCertificate);
                    isEffective = true;
                    if (!res) {
                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_UPDATELCDPKI,
                                Defines.ERROR_UPDATELCDPKI, channelName, user, billCode);


                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_UPDATELCDPKI);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }

                }
            }
        } // End LCD PKI updated

        // sim pki
        if (!isPKISim.equals("")) {
            if (!isPKISim.equals(Defines.TRUE)) {
                isPKISim = Defines.FALSE;
            }

            if (isPKISim.equals(Defines.FALSE)) {
                boolean res = DBConnector.getInstances().authSetIsSimPKIArrangement(agreementID, false);
                if (!res) {

                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_UPDATESIMPKI,
                            Defines.ERROR_UPDATESIMPKI, channelName, user, billCode);


                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UPDATESIMPKI);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                // update in sim pkiinformation
                res = DBConnector.getInstances().authSetSimCertificateArrangement(agreementID,
                        Defines.NULL, Defines.NULL,
                        Defines.NULL, Defines.NULL);
                isEffective = true;
                if (!res) {
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_UPDATESIMPKI,
                            Defines.ERROR_UPDATESIMPKI, channelName, user, billCode);


                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UPDATESIMPKI);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }
            } else {
                String[] simVendor = DBConnector.getInstances().authCheckSimPKIVendor(pkiSimVendor);
                if (!pkiSim.equals("") && !pkiSimVendor.equals("")) {
                    if (!ExtFunc.isValidPhoneNumber(pkiSim)) {

                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_INVALIDPARAMETER,
                                Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);


                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }


                    if (simVendor == null) {
                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_INVALID_SIM_VENDOR,
                                Defines.ERROR_INVALID_SIM_VENDOR, channelName, user, billCode);


                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_INVALID_SIM_VENDOR);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }
                    /*
                     * if (DBConnector.getInstances().authCheckSimPKI(user,
                     * pkiSim, channelName)) {
                     *
                     * String pData = ExtFunc.genResponseMessage(
                     * Defines.CODE_USERPHONEEXIT, Defines.ERROR_USERPHONEEXIT,
                     * channelName, user, billCode);
                     *
                     * String billCode =
                     * DBConnector.getInstances().writeLogToDataBaseOutside(workerIdOrName,
                     * username, ExtFunc.getRequestIP(wsContext), user,
                     * Defines.CODE_USERPHONEEXIT, idTag, channelName, xmlData,
                     * pData, unsignedData, signedData, functionName,
                     * trustedHubTransId);
                     *
                     * pData = ExtFunc.replaceBillCode(billCode, pData);
                     * DBConnector.getInstances().updateEndpointLog(ExtFunc.getTransId(billCode)
                     * , (certificateAgreementStatusTPKI !=
                     * null)?certificateAgreementStatusTPKI.getEndpointId():null);
                     * DBConnector.getInstances().updateEndpointLog(ExtFunc.getTransId(billCode)
                     * , (certificateAgreementStatusLPKI !=
                     * null)?certificateAgreementStatusLPKI.getEndpointId():null);
                     * DBConnector.getInstances().updateEndpointLog(ExtFunc.getTransId(billCode)
                     * , (certificateAgreementStatusWPKI !=
                     * null)?certificateAgreementStatusWPKI.getEndpointId():null);
                     * return new TransactionInfo(pData); }
                     */
                } else {

                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);


                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                GeneralPolicy gp = DBConnector.getInstances().getGeneralPolicy();
                String wpkiCert = Defines.NULL;
                String wpkiThumbprint = Defines.NULL;

                if (wCertificate.compareTo("") == 0) {
                    // call MSSP to get certificate
                    List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();

                    org.signserver.clientws.Metadata user_pkisim = new org.signserver.clientws.Metadata(
                            Defines._USER, user);

                    org.signserver.clientws.Metadata channelName_pkisim = new org.signserver.clientws.Metadata(
                            Defines._CHANNEL, channelName);

                    org.signserver.clientws.Metadata phoneNo_pkisim = new org.signserver.clientws.Metadata(
                            Defines._PKISIM, pkiSim);

                    org.signserver.clientws.Metadata vendor_pkisim = new org.signserver.clientws.Metadata(
                            Defines._PKISIMVENDOR, pkiSimVendor);

                    org.signserver.clientws.Metadata method_pkisim = new org.signserver.clientws.Metadata(
                            Defines._METHOD, Defines.SIGNERAP_CERTQUERY);

                    org.signserver.clientws.Metadata endpointconfigid_pkisim = new org.signserver.clientws.Metadata(
                            Defines._ENDPOINTCONFIGID, simVendor[1]);

                    org.signserver.clientws.Metadata endpointconfigValue_pkisim = new org.signserver.clientws.Metadata(
                            Defines._ENDPOINTVALUE, simVendor[2]);

                    org.signserver.clientws.Metadata trustedhub_trans_id = new org.signserver.clientws.Metadata(Defines._TRUSTEDHUBTRANSID, String.valueOf(trustedHubTransId));

                    requestMetadata.add(user_pkisim);
                    requestMetadata.add(channelName_pkisim);
                    requestMetadata.add(phoneNo_pkisim);
                    requestMetadata.add(vendor_pkisim);
                    requestMetadata.add(method_pkisim);
                    requestMetadata.add(endpointconfigid_pkisim);
                    requestMetadata.add(endpointconfigValue_pkisim);
                    requestMetadata.add(trustedhub_trans_id);

                    final int requestId = random.nextInt();

                    final int wId = getWorkerId(Defines.WORKER_SIGNERAP);

                    final RequestContext requestContext = handleRequestContext(
                            requestMetadata, wId);

                    final ProcessRequest req = new GenericSignRequest(requestId,
                            byteData);
                    ProcessResponse resp = null;
                    try {
                        resp = getWorkerSession().process(wId, req, requestContext);
                    } catch (Exception e) {
                        LOG.error("Something wrong: " + e.getMessage());
                        e.printStackTrace();
                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_INTERNALSYSTEM,
                                Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }

                    if (!(resp instanceof GenericSignResponse)) {
                        LOG.error("resp is not a instance of GenericSignResponse");

                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_UNEXPECTEDRETURNTYPE,
                                Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    } else {
                        final GenericSignResponse signResponse = (GenericSignResponse) resp;
                        if (signResponse.getRequestID() != requestId) {
                            LOG.error("Response ID " + signResponse.getRequestID()
                                    + " not matching request ID " + requestId);

                            String pData = ExtFunc.genResponseMessage(
                                    Defines.CODE_NOTMATCHID,
                                    Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_NOTMATCHID);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        }
                        int responseCode = signResponse.getResponseCode();
                        String responseMessage = signResponse.getResponseMessage();
                        if (responseCode == Defines.CODE_SUCCESS) {
                            List<SignerInfoResponse> signerInfo = signResponse.getSignerInfoResponse();
                            for (int i = 0; i < signerInfo.size(); i++) {
                                if (signerInfo.get(i).isIsSigning()) {
                                    wCertificate = signerInfo.get(i).getCertificate();
                                    break;
                                }
                            }

                            if (wCertificate.compareTo("") == 0) {
                                LOG.error("Sim doesn't have any certificates");
                                LOG.error("Request to MSSP to get certificate. But response is NULL");
                                String pData = ExtFunc.genResponseMessage(
                                        Defines.CODE_MSSP_NOCERTIFICATE,
                                        Defines.MSSP_NOCERTIFICATE, channelName, user, billCode);

                                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                                processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                                processAgreementResp.setXmlData(pData);
                                processAgreementResp.setSignedData(null);
                                processAgreementResp.setPreTrustedHubTransId(null);
                                return processAgreementResp;
                            }
                        } else {
                            LOG.error("Sim doesn't have any certificates");
                            String pData = ExtFunc.genResponseMessage(
                                    responseCode,
                                    responseMessage, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(responseCode);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        }
                    }
                }

                certificateAgreementStatusWPKI = isCertificateValid(channelName, user, wCertificate, trustedHubTransId);
                if (!certificateAgreementStatusWPKI.isValid()) {
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INVALIDCERTIFICATE,
                            Defines.ERROR_INVALIDCERTIFICATE, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }
                String[] certs = ExtFunc.getCertificateComponents(wCertificate);
                wpkiCert = wCertificate;
                wpkiThumbprint = certs[5];

                boolean res = DBConnector.getInstances().authSetIsSimPKIArrangement(agreementID, true);
                if (!res) {
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_UPDATESIMPKI,
                            Defines.ERROR_UPDATESIMPKI, channelName, user, billCode);


                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UPDATESIMPKI);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }
                // update in sim pkiinformation
                res = DBConnector.getInstances().authSetSimCertificateArrangement(agreementID,
                        wpkiThumbprint, wpkiCert, pkiSim, pkiSimVendor);

                isEffective = true;
                if (!res) {
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_UPDATESIMPKI,
                            Defines.ERROR_UPDATESIMPKI, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UPDATESIMPKI);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }
            }
        }

        // U2F
        if (!isU2F.equals("")) {
            if (!isU2F.equals(Defines.TRUE)) {
                isU2F = Defines.FALSE;
            }

            if (isU2F.equals(Defines.FALSE)) {
                boolean res = DBConnector.getInstances().setIsU2F(agreementID, false);
                if (!res) {
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INTERNALSYSTEM,
                            Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }
                res = DBConnector.getInstances().setU2FAgreement(agreementID, Defines.NULL);
                isEffective = true;
                if (!res) {
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INTERNALSYSTEM,
                            Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

            } else {
                if (appId.compareTo("") == 0) {
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                } else {
                    boolean res = DBConnector.getInstances().setIsU2F(agreementID, true);
                    if (!res) {
                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_INTERNALSYSTEM,
                                Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }

                    res = DBConnector.getInstances().setU2FAgreement(agreementID, appId);
                    isEffective = true;
                    if (!res) {
                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_INTERNALSYSTEM,
                                Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }
                }
            }
        }

        // Extend
        if (!isExtend.equals("")) {
            if (isExtend.equals(Defines.TRUE)) {
                int expire = 0;
                try {
                    expire = Integer.parseInt(expiration);
                } catch (NumberFormatException e) {

                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);


                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }
                if (expire <= 0) {
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);


                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }
                boolean res = DBConnector.getInstances().authSetExtendArrangement(agreementID, channelName,
                        expire);
                isEffective = true;
                if (!res) {

                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_UPDATEEXTEND,
                            Defines.ERROR_UPDATEEXTEND, channelName, user, billCode);


                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UPDATEEXTEND);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }
            }

        } // end extend

        if (!isPKISigning.equals("")) {
            if (!isPKISigning.equals(Defines.TRUE)) {
                isPKISigning = Defines.FALSE;
            }

            if (!spkiDn.equals("") || !spkiCertProvider.equals("")) {
                isWS = Defines.TRUE;
            } else {
                isWS = Defines.FALSE;
            }
            /*
             * if(!isWS.equals(Defines.TRUE)) { isWS = Defines.FALSE; }
             */

            if (isPKISigning.equals(Defines.TRUE)) {
                if (!workerSigning.equals("")) {
                    // register
                    String signserverWorkerName;
                    String signserverKeyName;
                    String signserverWorkerConfig;
                    String signserverSpkiEmail;
                    String signserverSpkiSMS;
                    String signserverSpkiKeyType;

                    String signserverSpkiSlotId;
                    String signserverSpkiModule;
                    String signserverSpkiPin;
                    String signserverSpkiLevel;
                    int signserverSpkiP11InfoId;
                    String[] certTypeKeyInfo = null;
                    Ca ca = null;
                    int certProfileId = 1;
                    String spkiCsr = null;

                    if (isWS.equals(Defines.FALSE)) {
                        if (spkiKeyname.equals("")
                                || spkiKeyType.equals("")) {
                            String pData = ExtFunc.genResponseMessage(
                                    Defines.CODE_INVALIDPARAMETER,
                                    Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);


                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        }
                        if (!spkiEmail.equals("")) {
                            if (!ExtFunc.isValidEmail(spkiEmail)) {
                                LOG.error("Invalid Email");
                                String pData = ExtFunc.genResponseMessage(
                                        Defines.CODE_INVALIDPARAMETER,
                                        Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);


                                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                                processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                                processAgreementResp.setXmlData(pData);
                                processAgreementResp.setSignedData(null);
                                processAgreementResp.setPreTrustedHubTransId(null);
                                return processAgreementResp;
                            }
                        }
                        if (!spkiSMS.equals("")) {
                            if (!ExtFunc.isValidPhoneNumber(spkiSMS)) {
                                LOG.error("Invalid Phone Number");
                                String pData = ExtFunc.genResponseMessage(
                                        Defines.CODE_INVALIDPARAMETER,
                                        Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);



                                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                                processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                                processAgreementResp.setXmlData(pData);
                                processAgreementResp.setSignedData(null);
                                processAgreementResp.setPreTrustedHubTransId(null);
                                return processAgreementResp;
                            }
                        }
                    } else {
                        if (workerSigning.equals("")
                                || spkiKeyType.equals("")
                                || spkiCertType.equals("")
                                || spkiCertProvider.equals("")
                                || spkiDn.equals("")
                                || spkiCertProfile.equals("")) {

                            String pData = ExtFunc.genResponseMessage(
                                    Defines.CODE_INVALIDPARAMETER,
                                    Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        }

                        if (!ExtFunc.isNumeric(spkiCertProfile)) {
                            LOG.error("Invalid Certificate Profile: " + spkiCertProfile);
                            String pData = ExtFunc.genResponseMessage(
                                    Defines.CODE_INVALIDPARAMETER,
                                    Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        }
                        if (!spkiEmail.equals("")) {
                            if (!ExtFunc.isValidEmail(spkiEmail)) {
                                LOG.error("Invalid Email");
                                String pData = ExtFunc.genResponseMessage(
                                        Defines.CODE_INVALIDPARAMETER,
                                        Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                                processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                                processAgreementResp.setXmlData(pData);
                                processAgreementResp.setSignedData(null);
                                processAgreementResp.setPreTrustedHubTransId(null);
                                return processAgreementResp;
                            }
                        }
                        if (!spkiSMS.equals("")) {
                            if (!ExtFunc.isValidPhoneNumber(spkiSMS)) {
                                LOG.error("Invalid Phone Number");
                                String pData = ExtFunc.genResponseMessage(
                                        Defines.CODE_INVALIDPARAMETER,
                                        Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                                processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                                processAgreementResp.setXmlData(pData);
                                processAgreementResp.setSignedData(null);
                                processAgreementResp.setPreTrustedHubTransId(null);
                                return processAgreementResp;
                            }
                        }
                    }

                    P11Info p11Info = null;
                    if (spkiP11Info.compareTo("") != 0) {
                        p11Info = DBConnector.getInstances().getP11Info(spkiP11Info);
                    } else {
                        p11Info = DBConnector.getInstances().getP11Info(null);
                    }

                    if (p11Info == null) {
                        LOG.error("HSM slot has been used or not available in system");
                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_INVALID_P11INFO,
                                Defines.ERROR_INVALID_P11INFO, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_INVALID_P11INFO);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }


                    signserverWorkerName = channelName.concat("-").concat(user).concat("-").concat(workerSigning);
                    //signserverKeyName = channelName.concat("-").concat(user).concat("-").concat(ExtFunc.getDateFormat());
                    signserverKeyName = spkiKeyname;
                    signserverWorkerConfig = DBConnector.getInstances().authGetWorkerConfig(workerSigning);
                    signserverSpkiEmail = spkiEmail;
                    signserverSpkiSMS = spkiSMS;
                    signserverSpkiKeyType = spkiKeyType;

                    signserverSpkiSlotId = String.valueOf(p11Info.getSlotId());
                    signserverSpkiModule = p11Info.getModule();
                    signserverSpkiPin = p11Info.getPin();
                    signserverSpkiLevel = p11Info.getLevel();
                    signserverSpkiP11InfoId = p11Info.getP11InfoId();

                    if (isWS.equals(Defines.TRUE)) {
                        certTypeKeyInfo = DBConnector.getInstances().getCertTypeKeyInfo(spkiCertType);
                        if (certTypeKeyInfo == null) {
                            LOG.error("Invalid Certificate Type");
                            String pData = ExtFunc.genResponseMessage(
                                    Defines.CODE_INVALIDPARAMETER,
                                    Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        }

                        List<CertTemplate> certTemplates = DBConnector.getInstances().getCertTemplate(Integer.parseInt(certTypeKeyInfo[3]));

                        if (!ExtFunc.checkCertTemplate(spkiDn, certTemplates)) {
                            LOG.error("Invalid DN in your request");
                            String pData = ExtFunc.genResponseMessage(
                                    Defines.CODE_INVALID_SUBJECTDN,
                                    Defines.ERROR_INVALID_SUBJECTDN, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_INVALID_SUBJECTDN);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        }

                        certProfileId = DBConnector.getInstances().getCertProfileId(Integer.parseInt(spkiCertProfile));
                        if (certProfileId == 1) {
                            LOG.error("Invalid Certificate Profile");
                            String pData = ExtFunc.genResponseMessage(
                                    Defines.CODE_INVALIDPARAMETER,
                                    Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        }

                        ca = DBConnector.getInstances().getCa(spkiCertProvider);

                        if (ca == null) {
                            LOG.error("Invalid CA Certificate Provider");
                            String pData = ExtFunc.genResponseMessage(
                                    Defines.CODE_INVALIDPARAMETER,
                                    Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        }
                    }

                    // 20180814
                    String signserverPassword = null;
                    if (isPKISigning.equals(Defines.TRUE)) {
                        signserverPassword = DBConnector.getInstances().getGeneralPolicy().getFrontDefaultPassSignserver();
                        if (DBConnector.getInstances().getGeneralPolicy().isFrontIsRandomSignServerPassword()) {
                            signserverPassword = ExtFunc.getRandomSignserverPassword();
                        }
                    }

                    if (isPKISigning.equals(Defines.TRUE)
                            && isWS.equals(Defines.TRUE)) {
                        if (signserverSpkiKeyType.equals(Defines.SPKI_KEYTYPE_USHARE)) {
                            // USER SHARE
                            signserverKeyName = channelName.concat("-").concat(ExtFunc.getDateFormat());
                        } else if (signserverSpkiKeyType.equals(Defines.SPKI_KEYTYPE_CSHARE)) {
                            // CHANNEL SHARE
                            signserverKeyName = ExtFunc.getDateFormat();
                        } else {
                            // PRIVATE
                            signserverKeyName = channelName.concat("-").concat(user).concat("-").concat(ExtFunc.getDateFormat());
                        }
                    }

                    boolean res = DBConnector.getInstances().authSetIsSignServerArrangement(
                            agreementID,
                            true,
                            signserverPassword,
                            signserverSpkiP11InfoId,
                            signserverWorkerName,
                            signserverKeyName,
                            signserverSpkiKeyType,
                            signserverSpkiEmail,
                            signserverSpkiSMS,
                            signserverWorkerConfig,
                            signserverSpkiSlotId,
                            signserverSpkiModule,
                            signserverSpkiPin,
                            signserverSpkiLevel);
                    isEffective = true;
                    if (!res) {
                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_UPDATE_SIGNSERVER,
                                Defines.ERROR_UPDATE_SIGNSERVER, channelName, user, billCode);


                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_UPDATE_SIGNSERVER);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    } else {
                        if (isPKISigning.equals(Defines.TRUE)
                                && !signserverWorkerConfig.equals(Defines.NULL)
                                && isWS.equals(Defines.TRUE)) {

                            if (signserverSpkiKeyType.equals(Defines.SPKI_KEYTYPE_USHARE)) {
                                // USER SHARE
                                signserverKeyName = channelName.concat("-").concat(ExtFunc.getDateFormat());
                            } else if (signserverSpkiKeyType.equals(Defines.SPKI_KEYTYPE_CSHARE)) {
                                // CHANNEL SHARE
                                signserverKeyName = ExtFunc.getDateFormat();
                            } else {
                                // PRIVATE
                                signserverKeyName = channelName.concat("-").concat(user).concat("-").concat(ExtFunc.getDateFormat());
                            }

                            try {
                                Properties p = new Properties();
                                p.load(new ByteArrayInputStream(signserverWorkerConfig.getBytes()));
                                p.setProperty("WORKERGENID1.NAME", signserverWorkerName);
                                p.setProperty("WORKERGENID1.defaultKey", signserverKeyName);
                                p.setProperty("WORKERGENID1.slot", signserverSpkiSlotId);
                                p.setProperty("WORKERGENID1.sharedLibrary", signserverSpkiModule);

                                if (signserverSpkiLevel.compareTo(Defines.P11_LEVEL_BASIC) == 0) {
                                    p.setProperty("WORKERGENID1.pin", signserverSpkiPin);
                                } else {
                                    // avanced, so remove pin property
                                    p.remove("WORKERGENID1.pin");
                                }
                                ByteArrayOutputStream os = new ByteArrayOutputStream();
                                p.store(os, null);
                                signserverWorkerConfig = new String(os.toByteArray());
                                os.close();
                            } catch (Exception e) {
                                e.printStackTrace();
                            }

                            int wUUID = AdminLayer.getInstance().addWorker(signserverWorkerConfig);

                            if (wUUID == -1) {
                                LOG.error("Error while getting WorkerUUID from Signserver response");
                                String pData = ExtFunc.genResponseMessage(
                                        Defines.CODE_INTERNALSYSTEM,
                                        Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                                processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                                processAgreementResp.setXmlData(pData);
                                processAgreementResp.setSignedData(null);
                                processAgreementResp.setPreTrustedHubTransId(null);
                                return processAgreementResp;
                            }

                            Integer workerUUID = Integer.valueOf(wUUID);

                            // reload worker
                            AdminLayer.getInstance().reloadWorker(workerUUID.toString());

                            /*
                             * update SignServerStatusID, WorkerUUID
                             *
                             *
                             */
                            DBConnector.getInstances().updateSignerServerAgreement(
                                    agreementID,
                                    Integer.valueOf(Defines.SPKI_STATUS_WORKER),
                                    null, signserverKeyName, null, null, null, null,
                                    workerUUID, null, null, null, null, null, null, null, null, null, null, null);

                            // GenKey
                            String generateSignerKeyResp = AdminLayer.getInstance().generateSignerKey(
                                    workerUUID,
                                    certTypeKeyInfo[1],
                                    certTypeKeyInfo[2],
                                    signserverKeyName,
                                    signserverSpkiPin);

                            // reload worker
                            AdminLayer.getInstance().reloadWorker(workerUUID.toString());

                            // update SignServerStatusID
                            DBConnector.getInstances().updateSignerServerAgreement(
                                    agreementID,
                                    Integer.valueOf(Defines.SPKI_STATUS_KEY),
                                    null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null);

                            // Generate csr
                            if (signserverSpkiLevel.compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                                AdminLayer.getInstance().activateSigner(workerUUID, signserverSpkiPin);
                            }

                            String pkcs10CertificateRequestForKeyResp = AdminLayer.getInstance().getPKCS10CertificateRequestForKey(
                                    workerUUID, certTypeKeyInfo[0], spkiDn, false, true);
                            spkiCsr = pkcs10CertificateRequestForKeyResp;
                            _spkiCsr = pkcs10CertificateRequestForKeyResp;

                            if (signserverSpkiLevel.compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                                AdminLayer.getInstance().deactivateSigner(workerUUID);
                            }

                            // update SignServerStatusID
                            DBConnector.getInstances().updateSignerServerAgreement(
                                    agreementID,
                                    Integer.valueOf(Defines.SPKI_STATUS_CSR),
                                    null,
                                    null,
                                    null,
                                    pkcs10CertificateRequestForKeyResp,
                                    null,
                                    null,
                                    null,
                                    spkiDn,
                                    null, null, null, null, Integer.valueOf(ca.getCaID()),
                                    null, Integer.valueOf(certProfileId), null, null, Integer.valueOf(certTypeKeyInfo[3]));
                        }
                        // 20180814
                        // send email notify signserver password
                        GeneralPolicy gp = DBConnector.getInstances().getGeneralPolicy();
                        if (gp.isFrontIsNotifySignServerPasswordByEmail()) {
                            if (isPKISigning.equals(Defines.TRUE)) {
                                try {
                                    // 20180815
                                                            /*
                                     * String template =
                                     * gp.getFrontEmailTemplateSignServerUserCreate();
                                     *
                                     * Properties p = new Properties(); Reader
                                     * reader = new InputStreamReader(new
                                     * ByteArrayInputStream(template.getBytes()),
                                     * StandardCharsets.UTF_8); p.load(reader);
                                     * String subject =
                                     * p.getProperty("SUBJECT"); String content
                                     * = p.getProperty("CONTENT");
                                     */
                                    String[] template = DBConnector.getInstances().getBackOfficeParamsDetailClient(Defines.PARAMS_BACKOFFICE_MAIL_NEWACCOUNT_SIGNSERVER, true);
                                    String subject = template[0];
                                    String content = template[1];

                                    content = content.replace(Defines.PATTERN_BOLD_OPEN, "<b>");
                                    content = content.replace(Defines.PATTERN_BOLD_CLOSE, "</b>");
                                    content = content.replace(Defines.PATTERN_NEW_LINE, "<br>");
                                    content = content.replace(Defines.PATTERN_USERNAME, user);

                                    if (signserverSpkiLevel.equals(Defines.P11_LEVEL_BASIC)) {
                                        content = content.replace(Defines.PATTERN_PASSWORD, signserverPassword);
                                    } else {
                                        content = content.replace(Defines.PATTERN_PASSWORD, signserverSpkiPin);
                                    }

                                    final String threadChannelName = channelName;
                                    final String threadUser = user;
                                    final String threadSignserverSpkiEmail = signserverSpkiEmail;
                                    final String threadSubject = subject;
                                    final String threadContent = content;
                                    new Thread(new Runnable() {

                                        @Override
                                        public void run() {
                                            String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(Defines.CONNECTION_PARAMS_SMTP);
                                            if (endpointParams != null) {
                                                EndpointServiceResp endpointServiceResp = EndpointService.getInstance().sendEmailNoLogging(
                                                        threadChannelName,
                                                        threadUser,
                                                        threadSignserverSpkiEmail,
                                                        threadSubject,
                                                        threadContent,
                                                        endpointParams[1],
                                                        Integer.parseInt(endpointParams[2]));
                                                if (endpointServiceResp.getResponseCode() == 0) {
                                                    LOG.info("Email contains password has been sent to " + threadSignserverSpkiEmail);
                                                } else {
                                                    LOG.error("Failed to send email contains password to " + threadSignserverSpkiEmail);
                                                }
                                            } else {
                                                LOG.error("No endpoint config to send email");
                                            }
                                        }
                                    }).start();
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                            }
                        }
                    }
                } else if (!currentPassword.equals("") && !newPassword.equals("")) {
                    // change password
                    if (newPassword.length() < 8) {
                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_INVALID_PASSWORD_LENGTH,
                                Defines.ERROR_INVALID_PASSWORD_LENGTH, channelName, user, billCode);


                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_INVALID_PASSWORD_LENGTH);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }

                    String[] signserverInfo = DBConnector.getInstances().authCertificateSPKI(channelName, user);

                    if (signserverInfo == null) {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_AGREEMENTNOTREADY,
                                Defines.ERROR_AGREEMENTNOTREADY, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_AGREEMENTNOTREADY);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(signedData);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }

                    if (signserverInfo[1].compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                        // check Signserver Agreement is locked or not
                        int errorCountSignServerStatus = DBConnector.getInstances().checkErrorCountSignServer(channelName, user);

                        if (errorCountSignServerStatus == 1) {
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_AGREEMENTNOTREADY,
                                    Defines.ERROR_AGREEMENTNOTREADY, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_AGREEMENTNOTREADY);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(signedData);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        } else if (errorCountSignServerStatus == 2) {
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_SIGNSERVER_PKI_LOCKED,
                                    Defines.ERROR_SIGNSERVER_PKI_LOCKED, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_SIGNSERVER_PKI_LOCKED);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(signedData);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        } else {
                            // errorCountSignServerStatus = 0 OK
                        }

                        // change HSM Pin
                        TokenManager tokenManager = new TokenManager();
                        if (tokenManager.initialize(signserverInfo[3], Long.parseLong(signserverInfo[2]))) {
                            if (!tokenManager.changeTokenPin(currentPassword, newPassword)) {
                                int[] response = DBConnector.getInstances().authCheckPassSignServer(user, channelName, String.valueOf(System.currentTimeMillis()));
                                int status = response[0];
                                int retry = response[1];
                                if (status == 1) {
                                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_PASSWORD,
                                            Defines.ERROR_INVALID_PASSWORD, channelName, user, retry, billCode);

                                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                                    processAgreementResp.setResponseCode(Defines.CODE_INVALID_PASSWORD);
                                    processAgreementResp.setXmlData(pData);
                                    processAgreementResp.setSignedData(signedData);
                                    processAgreementResp.setPreTrustedHubTransId(null);
                                    return processAgreementResp;
                                } else {
                                    String pData = ExtFunc.genResponseMessage(Defines.CODE_SIGNSERVER_PKI_LOCKED,
                                            Defines.ERROR_SIGNSERVER_PKI_LOCKED, channelName, user, billCode);

                                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                                    processAgreementResp.setResponseCode(Defines.CODE_SIGNSERVER_PKI_LOCKED);
                                    processAgreementResp.setXmlData(pData);
                                    processAgreementResp.setSignedData(signedData);
                                    processAgreementResp.setPreTrustedHubTransId(null);
                                    return processAgreementResp;
                                }
                            } else {
                                isEffective = true;
                                DBConnector.getInstances().resetErrorCountSignServer(channelName, user);
                            }
                            tokenManager.release();
                        } else {
                            LOG.error("Error while initializing HSM connection");
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(signedData);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        }
                    } else {
                        Object[] rv = DBConnector.getInstances().authChangePassSignServer(agreementID, currentPassword, newPassword);

                        int status = ((Integer) rv[0]).intValue();

                        if (status == 1) {
                            int reTry = ((Integer) rv[1]).intValue();
                            String pData = ExtFunc.genResponseMessage(
                                    Defines.CODE_INVALID_PASSWORD,
                                    Defines.ERROR_INVALID_PASSWORD, channelName, user, reTry, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_INVALID_PASSWORD);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        } else if (status == 2) {
                            String pData = ExtFunc.genResponseMessage(
                                    Defines.CODE_SIGNSERVER_PKI_LOCKED,
                                    Defines.ERROR_SIGNSERVER_PKI_LOCKED, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_SIGNSERVER_PKI_LOCKED);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        } else {
                            // ok
                            isEffective = true;
                        }
                    }
                } else if (recovery.equals(Defines.TRUE)) {

                    String[] signserverInfo = DBConnector.getInstances().authCertificateSPKI(channelName, user);

                    if (signserverInfo == null) {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_AGREEMENTNOTREADY,
                                Defines.ERROR_AGREEMENTNOTREADY, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_AGREEMENTNOTREADY);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(signedData);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }

                    GeneralPolicy generalPolicy = DBConnector.getInstances().getGeneralPolicy();
                    boolean isSendEmail = generalPolicy.isFrontIsForgotEmailSignserver();

                    if (isSendEmail) {
                        String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(Defines.CONNECTION_PARAMS_SMTP);

                        if (endpointParams == null) {
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                                    Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        }

                        String[] emailContentInfo = DBConnector.getInstances().getBackOfficeParamsDetailClient(Defines.PARAMS_BACKOFFICE_MAIL_SIGNSERVER, true);
                        String subject = emailContentInfo[0];
                        String content = emailContentInfo[1];

                        String newPwd = ExtFunc.generateRamdomNumber();

                        content = content.replace(Defines.PATTERN_NEW_LINE, "<br>");
                        content = content.replace(Defines.PATTERN_PASSWORD, newPwd);


                        String email = DBConnector.getInstances().authGetEmailSignServer(channelName, user);

                        EndpointServiceResp endpointServiceResp = EndpointService.getInstance().sendEmailNoLogging(channelName, user, email, subject, content, endpointParams[1], Integer.parseInt(endpointParams[2]));

                        if (endpointServiceResp.getResponseCode() == 0) {
                            isEffective = true;
                            if (signserverInfo[1].compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                                // init HSM Pin
                                TokenManager tokenManager = new TokenManager();
                                if (tokenManager.initialize(signserverInfo[3], Long.parseLong(signserverInfo[2]))) {
                                    if (!tokenManager.initTokenPin(signserverInfo[5], newPwd)) {
                                        LOG.error("Error while setting HSM UserPIN. Please check the SOPIN");
                                        String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_PASSWORD,
                                                Defines.ERROR_INVALID_PASSWORD, channelName, user, billCode);

                                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                                        processAgreementResp.setResponseCode(Defines.CODE_INVALID_PASSWORD);
                                        processAgreementResp.setXmlData(pData);
                                        processAgreementResp.setSignedData(signedData);
                                        processAgreementResp.setPreTrustedHubTransId(null);
                                        return processAgreementResp;
                                    }
                                    tokenManager.release();
                                } else {
                                    LOG.error("Error while initializing HSM connection");
                                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                                            Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                                    processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                                    processAgreementResp.setXmlData(pData);
                                    processAgreementResp.setSignedData(signedData);
                                    processAgreementResp.setPreTrustedHubTransId(null);
                                    return processAgreementResp;
                                }
                            } else {
                                DBConnector.getInstances().authResetPassSignserver(agreementID, newPwd);
                            }
                        } else {
                            // do nothing
                        }
                    } else {
                        // send sms
                        String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(Defines.CONNECTION_PARAMS_SMPP);

                        if (endpointParams == null) {
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_EXT_CONN_VENDOR,
                                    Defines.ERROR_INVALID_EXT_CONN_VENDOR, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        }

                        String[] smsContentInfo = DBConnector.getInstances().getBackOfficeParamsDetailClient(Defines.PARAMS_BACKOFFICE_SMS_SIGNSERVER, false);

                        String content = smsContentInfo[0];

                        String newPwd = ExtFunc.generateRamdomNumber();

                        content = content.replace(Defines.PATTERN_NEW_LINE, "<br>");
                        content = content.replace(Defines.PATTERN_PASSWORD, newPwd);


                        String phoneNo = DBConnector.getInstances().authGetPhoneSignServer(channelName, user);

                        EndpointServiceResp endpointServiceResp = EndpointService.getInstance().sendSmsNoLogging(channelName, user, phoneNo, content, endpointParams[1], Integer.parseInt(endpointParams[2]));

                        if (endpointServiceResp.getResponseCode() == 0) {
                            isEffective = true;

                            if (signserverInfo[1].compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                                // init HSM Pin
                                TokenManager tokenManager = new TokenManager();
                                if (tokenManager.initialize(signserverInfo[3], Long.parseLong(signserverInfo[2]))) {
                                    if (!tokenManager.initTokenPin(signserverInfo[5], newPwd)) {
                                        LOG.error("Error while setting HSM UserPIN. Please check the SOPIN");
                                        String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_PASSWORD,
                                                Defines.ERROR_INVALID_PASSWORD, channelName, user, billCode);

                                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                                        processAgreementResp.setResponseCode(Defines.CODE_INVALID_PASSWORD);
                                        processAgreementResp.setXmlData(pData);
                                        processAgreementResp.setSignedData(signedData);
                                        processAgreementResp.setPreTrustedHubTransId(null);
                                        return processAgreementResp;
                                    }
                                    tokenManager.release();
                                } else {
                                    LOG.error("Error while initializing HSM connection");
                                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                                            Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                                    processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                                    processAgreementResp.setXmlData(pData);
                                    processAgreementResp.setSignedData(signedData);
                                    processAgreementResp.setPreTrustedHubTransId(null);
                                    return processAgreementResp;
                                }
                            } else {
                                DBConnector.getInstances().authResetPassSignserver(agreementID, newPwd);
                            }
                        } else {
                            // do nothing
                        }
                    }
                } else if (registered.equals(Defines.TRUE)
                        || registered.equals(Defines.FALSE)) {
                    isEffective = true;
                    DBConnector.getInstances().authSAUpdateIsRegistered(agreementID, registered.equals(Defines.TRUE));
                } else if (!isInstallCert.equals("")) {
                    isEffective = true;

                    String[] signserverInfo = DBConnector.getInstances().authCertificateSPKI(channelName, user);
                    if (signserverInfo == null) {
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_AGREEMENTNOTREADY,
                                Defines.ERROR_AGREEMENTNOTREADY, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_AGREEMENTNOTREADY);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(signedData);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }

                    if (isInstallCert.equals(Defines.TRUE)) {
                        if (!scertificate.equals("")) {
                            String[] certComponents = ExtFunc.getCertificateComponents(scertificate);
                            if (certComponents == null) {
                                LOG.error("Invalid certificate");
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDCERTIFICATE,
                                        Defines.ERROR_INVALIDCERTIFICATE, channelName, user, billCode);

                                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                                processAgreementResp.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                                processAgreementResp.setXmlData(pData);
                                processAgreementResp.setSignedData(signedData);
                                processAgreementResp.setPreTrustedHubTransId(null);
                                return processAgreementResp;
                            }
                            String caName = ExtFunc.getCNFromDN(certComponents[2]);
                            Ca ca = DBConnector.getInstances().getCa(caName);
                            if (ca == null) {
                                LOG.error("Cannot find CA that issues certificate");
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDCERTIFICATE,
                                        Defines.ERROR_INVALIDCERTIFICATE, channelName, user, billCode);

                                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                                processAgreementResp.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                                processAgreementResp.setXmlData(pData);
                                processAgreementResp.setSignedData(signedData);
                                processAgreementResp.setPreTrustedHubTransId(null);
                                return processAgreementResp;
                            }
                            // check cert relation
                            X509Certificate caCert = null;
                            X509Certificate clientCert = null;
                            try {
                                caCert = ExtFunc.getCertificate(ca.getCert());
                                clientCert = ExtFunc.getCertificate(scertificate);
                            } catch (Exception e) {
                                e.printStackTrace();
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                                        Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                                processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                                processAgreementResp.setXmlData(pData);
                                processAgreementResp.setSignedData(signedData);
                                processAgreementResp.setPreTrustedHubTransId(null);
                                return processAgreementResp;
                            }
                            if (!ExtFunc.checkCertificateRelation(caCert, clientCert)) {
                                LOG.error("Certificate has been issued by a fake CA");
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDCERTIFICATE,
                                        Defines.ERROR_INVALIDCERTIFICATE, channelName, user, billCode);

                                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                                processAgreementResp.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                                processAgreementResp.setXmlData(pData);
                                processAgreementResp.setSignedData(signedData);
                                processAgreementResp.setPreTrustedHubTransId(null);
                                return processAgreementResp;
                            }

                            if (!ExtFunc.checkCertificateAndCsr(clientCert, signserverInfo[7])) {
                                LOG.error("Certificate and CSR don't have the same public key");
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDCERTIFICATE,
                                        Defines.ERROR_INVALIDCERTIFICATE, channelName, user, billCode);

                                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                                processAgreementResp.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                                processAgreementResp.setXmlData(pData);
                                processAgreementResp.setSignedData(signedData);
                                processAgreementResp.setPreTrustedHubTransId(null);
                                return processAgreementResp;
                            }

                            if (!scertificate.contains("-----BEGIN CERTIFICATE-----")) {
                                scertificate = "-----BEGIN CERTIFICATE-----\n" + scertificate + "\n-----END CERTIFICATE-----";
                            }

                            List<Certificate> signerCertChain = null;
                            try {
                                signerCertChain = CertTools.getCertsFromPEM(new ByteArrayInputStream(ca.getCert().getBytes()));
                            } catch (Exception e) {
                                e.printStackTrace();
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                                        Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                                processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                                processAgreementResp.setXmlData(pData);
                                processAgreementResp.setSignedData(signedData);
                                processAgreementResp.setPreTrustedHubTransId(null);
                                return processAgreementResp;
                            }

                            signerCertChain.add(0, (Certificate) clientCert);
                            // activate signer
                            if (signserverInfo[1].compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                                AdminLayer.getInstance().activateSigner(Integer.parseInt(signserverInfo[6]), signserverInfo[4]);
                            }

                            AdminLayer.getInstance().uploadSignerCertificate(Integer.parseInt(signserverInfo[6]),
                                    ExtFunc.asByteArray(clientCert));
                            AdminLayer.getInstance().uploadSignerCertificateChain(Integer.parseInt(signserverInfo[6]),
                                    ExtFunc.asByteArrayList(signerCertChain));
                            AdminLayer.getInstance().reloadWorker(signserverInfo[6]);
                            // deactivate signer
                            if (signserverInfo[1].compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                                AdminLayer.getInstance().deactivateSigner(Integer.parseInt(signserverInfo[6]));
                            }

                            int certStatus = 1;
                            if (ExtFunc.isNullOrEmpty(signserverInfo[0])) {
                                certStatus = Defines.CERT_STATUS_NEW;
                            } else {
                                certStatus = Defines.CERT_STATUS_RENEW;
                            }

                            DBConnector.getInstances().updateSignerServerAgreement(
                                    agreementID,
                                    Integer.valueOf(Defines.SPKI_STATUS_FINISH),
                                    null, null, null, null,
                                    scertificate,
                                    null,
                                    null, null,
                                    ExtFunc.getCNFromDN(certComponents[1]),
                                    clientCert.getNotBefore(),
                                    clientCert.getNotAfter(), certStatus, ca.getCaID(), null, null, null, certComponents[5], null);
                        } else {
                            // install from RA
                            String certificateResp = AdminLayer.getInstance().getCertificate(
                                    channelName,
                                    user,
                                    signserverInfo[8],
                                    ExtFunc.getEmailFromDN(signserverInfo[8]),
                                    signserverInfo[10] + ":0:0",
                                    signserverInfo[7],
                                    signserverInfo[9],
                                    trustedHubTransId);

                            if (!certificateResp.contains("-----BEGIN CERTIFICATE-----")) {
                                certificateResp = "-----BEGIN CERTIFICATE-----\n" + certificateResp + "\n-----END CERTIFICATE-----";
                            }

                            String[] certComponents = ExtFunc.getCertificateComponents(certificateResp);
                            if (certComponents == null) {
                                LOG.error("Invalid certificate");
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDCERTIFICATE,
                                        Defines.ERROR_INVALIDCERTIFICATE, channelName, user, billCode);

                                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                                processAgreementResp.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                                processAgreementResp.setXmlData(pData);
                                processAgreementResp.setSignedData(signedData);
                                processAgreementResp.setPreTrustedHubTransId(null);
                                return processAgreementResp;
                            }

                            Ca ca = DBConnector.getInstances().getCa(signserverInfo[9]);
                            if (ca == null) {
                                LOG.error("Cannot find CA that issues certificate");
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                                        Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                                processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                                processAgreementResp.setXmlData(pData);
                                processAgreementResp.setSignedData(signedData);
                                processAgreementResp.setPreTrustedHubTransId(null);
                                return processAgreementResp;
                            }

                            X509Certificate clientCert = null;
                            try {
                                clientCert = ExtFunc.getCertificate(certificateResp);
                            } catch (Exception e) {
                                e.printStackTrace();
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                                        Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                                processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                                processAgreementResp.setXmlData(pData);
                                processAgreementResp.setSignedData(signedData);
                                processAgreementResp.setPreTrustedHubTransId(null);
                                return processAgreementResp;
                            }

                            List<Certificate> signerCertChain = null;
                            try {
                                signerCertChain = CertTools.getCertsFromPEM(new ByteArrayInputStream(ca.getCert().getBytes()));
                            } catch (Exception e) {
                                e.printStackTrace();
                                String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                                        Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                                processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                                processAgreementResp.setXmlData(pData);
                                processAgreementResp.setSignedData(signedData);
                                processAgreementResp.setPreTrustedHubTransId(null);
                                return processAgreementResp;
                            }

                            signerCertChain.add(0, (Certificate) clientCert);
                            // activate signer
                            if (signserverInfo[1].compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                                AdminLayer.getInstance().activateSigner(Integer.parseInt(signserverInfo[6]), signserverInfo[4]);
                            }

                            AdminLayer.getInstance().uploadSignerCertificate(Integer.parseInt(signserverInfo[6]),
                                    ExtFunc.asByteArray(clientCert));
                            AdminLayer.getInstance().uploadSignerCertificateChain(Integer.parseInt(signserverInfo[6]),
                                    ExtFunc.asByteArrayList(signerCertChain));

                            AdminLayer.getInstance().reloadWorker(signserverInfo[6]);
                            // deactivate signer
                            if (signserverInfo[1].compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                                AdminLayer.getInstance().deactivateSigner(Integer.parseInt(signserverInfo[6]));
                            }

                            int certStatus = 1;
                            if (ExtFunc.isNullOrEmpty(signserverInfo[0])) {
                                certStatus = Defines.CERT_STATUS_NEW;
                            } else {
                                certStatus = Defines.CERT_STATUS_RENEW;
                            }

                            DBConnector.getInstances().updateSignerServerAgreement(
                                    agreementID,
                                    Integer.valueOf(Defines.SPKI_STATUS_FINISH),
                                    null, null, null, null,
                                    certificateResp,
                                    null,
                                    null, null,
                                    ExtFunc.getCNFromDN(certComponents[1]),
                                    clientCert.getNotBefore(),
                                    clientCert.getNotAfter(), certStatus, ca.getCaID(), null, null, null, certComponents[5], null);
                        }
                    }

                } else {
                    // not implement yet
                }
            }
        }

        if (isEffective) {
            // Done
            String pData = ExtFunc.genResponseMessageWithSPKIChange(
                    Defines.CODE_SUCCESS,
                    Defines.SUCCESS, _spkiCsr, channelName, user, billCode);


            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
            processAgreementResp.setResponseCode(Defines.CODE_SUCCESS);
            processAgreementResp.setXmlData(pData);
            processAgreementResp.setSignedData(null);
            processAgreementResp.setPreTrustedHubTransId(null);
            return processAgreementResp;
        }
        // Done

        String pData = ExtFunc.genResponseMessage(
                Defines.CODE_UNCHANGEDAGREEMENT,
                Defines.INFO_UNCHANGEAGREEMENT, channelName, user, billCode);


        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
        processAgreementResp.setResponseCode(Defines.CODE_UNCHANGEDAGREEMENT);
        processAgreementResp.setXmlData(pData);
        processAgreementResp.setSignedData(null);
        processAgreementResp.setPreTrustedHubTransId(null);
        return processAgreementResp;
    }

    private static ProcessAgreementResp unregisterAgreement(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
        String workerIdOrName = Defines.WORKER_AGREEMENT;
        String functionName = Defines.WORKER_AGREEMENT;
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


        String action = ExtFunc.getContent(Defines._ACTION, xmlData);

        int agreementID = DBConnector.getInstances().authGetArrangementID(
                channelName, user);
        if (agreementID == 0) {

            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_AGREEMENTNOTEXITS,
                    Defines.ERROR_AGREEMENTNOTEXITS, channelName, user, billCode);

            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
            processAgreementResp.setResponseCode(Defines.CODE_AGREEMENTNOTEXITS);
            processAgreementResp.setXmlData(pData);
            processAgreementResp.setSignedData(null);
            processAgreementResp.setPreTrustedHubTransId(null);
            return processAgreementResp;
        }

        String agreementStatus = ExtFunc.getContent(Defines._AGREEMENTSTATUS,
                xmlData);
        if (agreementStatus.equals("")) {

            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_INVALIDPARAMETER,
                    Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
            processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
            processAgreementResp.setXmlData(pData);
            processAgreementResp.setSignedData(null);
            processAgreementResp.setPreTrustedHubTransId(null);
            return processAgreementResp;
        }

        if (agreementStatus.equals(Defines.AGREEMENT_STATUS_CANC)) {
            String[] signserverInfo = DBConnector.getInstances().authCertificateSPKI(channelName, user);
            if (signserverInfo != null) {
                if (signserverInfo[1].compareTo(Defines.P11_LEVEL_AVANC) == 0) {
                    // init HSM Pin
                    TokenManager tokenManager = new TokenManager();
                    if (tokenManager.initialize(signserverInfo[3], Long.parseLong(signserverInfo[2]))) {
                        if (!tokenManager.initTokenPin(signserverInfo[5], signserverInfo[4])) {
                            LOG.error("Error while setting HSM UserPIN. Please check the SOPIN");
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALID_PASSWORD,
                                    Defines.ERROR_INVALID_PASSWORD, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_INVALID_PASSWORD);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(signedData);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        }
                        tokenManager.release();
                    } else {
                        LOG.error("Error while initializing HSM connection");
                        String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                                Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(signedData);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }
                }
                // remove and reload worker
                if (!ExtFunc.isNullOrEmpty(signserverInfo[6])) {
                    AdminLayer.getInstance().removeWorker(Integer.parseInt(signserverInfo[6]));
                }
                AdminLayer.getInstance().reloadWorker(signserverInfo[6]);

                // update SPKI Certificate to cancel
                DBConnector.getInstances().updateSignerServerAgreement(
                        agreementID,
                        null, null, null, null, null, null, null, null, null,
                        null, null, null, Defines.CERT_STATUS_CANCEL, null, null, null, null, null, null);
            }
        }

        int updateAgreement = DBConnector.getInstances().authUpdateAgreement(agreementID, agreementStatus);

        DBConnector.getInstances().authSANewUpdateCANC(agreementID);

        if (updateAgreement == 1) {

            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_INVALIDAGREESTATUS,
                    Defines.ERROR_INVALIDAGREESTATUS, channelName, user, billCode);

            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
            processAgreementResp.setResponseCode(Defines.CODE_INVALIDAGREESTATUS);
            processAgreementResp.setXmlData(pData);
            processAgreementResp.setSignedData(null);
            processAgreementResp.setPreTrustedHubTransId(null);
            return processAgreementResp;
        }

        // Done unregistration
        String pData = ExtFunc.genResponseMessage(
                Defines.CODE_SUCCESS,
                Defines.SUCCESS, channelName, user, billCode);

        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
        processAgreementResp.setResponseCode(Defines.CODE_SUCCESS);
        processAgreementResp.setXmlData(pData);
        processAgreementResp.setSignedData(null);
        processAgreementResp.setPreTrustedHubTransId(null);
        return processAgreementResp;
    }

    private static ProcessAgreementResp unregisterManyAgreement(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
        String workerIdOrName = Defines.WORKER_AGREEMENT;
        String functionName = Defines.WORKER_AGREEMENT;
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


        String action = ExtFunc.getContent(Defines._ACTION, xmlData);

        if (idTag.compareTo("") == 0) {
            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_INVALIDPARAMETER,
                    Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
            processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
            processAgreementResp.setXmlData(pData);
            processAgreementResp.setSignedData(null);
            processAgreementResp.setPreTrustedHubTransId(null);
            return processAgreementResp;
        }

        int numCancel = DBConnector.getInstances().authMultiUnregisteration(
                idTag);

        String muti_mess = Defines.AGREEMENT_ACTION_MULTI_UNREG_DES;
        muti_mess = muti_mess.replace("%d", String.valueOf(numCancel));

        String pData = ExtFunc.genResponseMessage(
                Defines.CODE_SUCCESS,
                Defines.SUCCESS, channelName, user, billCode);

        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
        processAgreementResp.setResponseCode(Defines.CODE_SUCCESS);
        processAgreementResp.setXmlData(pData);
        processAgreementResp.setSignedData(null);
        processAgreementResp.setPreTrustedHubTransId(null);
        return processAgreementResp;
    }

    private static ProcessAgreementResp validateAgreement(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
        String workerIdOrName = Defines.WORKER_AGREEMENT;
        String functionName = Defines.WORKER_AGREEMENT;
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

        String action = ExtFunc.getContent(Defines._ACTION, xmlData);

        String tpkiThumbPrint = ExtFunc.getContent(Defines._TTHUMBPRINT, xmlData);

        if (tpkiThumbPrint.equals("")) {
            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_INVALIDPARAMETER,
                    Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
            processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
            processAgreementResp.setXmlData(pData);
            processAgreementResp.setSignedData(null);
            processAgreementResp.setPreTrustedHubTransId(null);
            return processAgreementResp;
        }

        AgreementObject agreementObject = DBConnector.getInstances().getAgreementByTPKIThumbPrint(channelName, tpkiThumbPrint);

        if (agreementObject == null) {
            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_AGREEMENTNOTEXITS,
                    Defines.ERROR_AGREEMENTNOTEXITS, channelName, user, billCode);

            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
            processAgreementResp.setResponseCode(Defines.CODE_AGREEMENTNOTEXITS);
            processAgreementResp.setXmlData(pData);
            processAgreementResp.setSignedData(null);
            processAgreementResp.setPreTrustedHubTransId(null);
            return processAgreementResp;
        }


        String certificate = agreementObject.getCertificate();

        CertificateAgreementStatus certificateAgreementStatus = isCertificateValid(channelName, user, certificate, trustedHubTransId);
        if (!certificateAgreementStatus.isValid()) {

            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_INVALIDCERTIFICATE,
                    Defines.ERROR_INVALIDCERTIFICATE, channelName, user, billCode);

            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
            processAgreementResp.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
            processAgreementResp.setXmlData(pData);
            processAgreementResp.setSignedData(null);
            processAgreementResp.setPreTrustedHubTransId(null);
            return processAgreementResp;
        }

        String pData = ExtFunc.genResponseMessage(
                Defines.CODE_SUCCESS,
                Defines.SUCCESS, channelName, agreementObject, billCode);

        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
        processAgreementResp.setResponseCode(Defines.CODE_SUCCESS);
        processAgreementResp.setXmlData(pData);
        processAgreementResp.setSignedData(null);
        processAgreementResp.setPreTrustedHubTransId(null);
        return processAgreementResp;
    }

    private static ProcessAgreementResp getAgreement(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
        String workerIdOrName = Defines.WORKER_AGREEMENT;
        String functionName = Defines.WORKER_AGREEMENT;
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
        String agreementStatus = ExtFunc.getContent(Defines._AGREEMENTSTATUS, xmlData);

        if (agreementStatus.equals("")) {
            agreementStatus = null;
        }

        String action = ExtFunc.getContent(Defines._ACTION, xmlData);

        List<AgreementObject> agreements = DBConnector.getInstances().authGetAgreementInfo(channelName, user, idTag, agreementStatus);

        String signingCounterLimit = "0";
        String signingCounterLeft = "0";
        String signingCounterValue = "0";

        String workerName = channelName.concat("-").concat(user).concat("-").concat("MultiSigner");
        int workerId = getWorkerSession().getWorkerId(workerName);
        if (workerId != 0) {
            String keyUsageCounter = getWorkerSession().getCurrentWorkerConfig(workerId).getProperty("DISABLEKEYUSAGECOUNTER", null);
            signingCounterLimit = getWorkerSession().getCurrentWorkerConfig(workerId).getProperty("KEYUSAGELIMIT", null);
            if (signingCounterLimit != null) {
                if (signingCounterLimit.equalsIgnoreCase("-1")) {
                    signingCounterLimit = "UNLIMITED";
                } else {
                    //get KEYUSAGELIMIT as real value
                }
            } else {
                signingCounterLimit = "UNLIMITED";
            }

            try {
                long keyUsageCounterValue = getWorkerSession().getKeyUsageCounterValue(workerId); //up
                signingCounterValue = String.valueOf(keyUsageCounterValue);
                if (signingCounterLimit.equalsIgnoreCase("UNLIMITED")) {
                    signingCounterLeft = "UNLIMITED";
                } else {
                    long keyUsageCounterLimit = Long.parseLong(signingCounterLimit);
                    long keyUsageCounterLeft = keyUsageCounterLimit - keyUsageCounterValue;
                    if (keyUsageCounterLeft < 0) {
                        keyUsageCounterLeft = 0;
                    }
                    signingCounterLeft = String.valueOf(keyUsageCounterLeft);
                }
            } catch (CryptoTokenOfflineException e) {
                e.printStackTrace();
            }


        }

        String pData = ExtFunc.genResponseMessage(Defines.CODE_SUCCESS,
                Defines.SUCCESS, channelName, agreements, billCode, signingCounterLimit, signingCounterValue, signingCounterLeft);

        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
        processAgreementResp.setResponseCode(Defines.CODE_SUCCESS);
        processAgreementResp.setXmlData(pData);
        processAgreementResp.setSignedData(null);
        processAgreementResp.setPreTrustedHubTransId(null);
        return processAgreementResp;
    }

    private static ProcessAgreementResp activateAgreement(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
        String workerIdOrName = Defines.WORKER_AGREEMENT;
        String functionName = Defines.WORKER_AGREEMENT;
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

        String action = ExtFunc.getContent(Defines._ACTION, xmlData);
        String metaData = ExtFunc.getContent(Defines._METADATA, xmlData);

        int agreementID = DBConnector.getInstances().authGetArrangementID(
                channelName, user);
        if (agreementID == 0) {
            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_AGREEMENTNOTEXITS,
                    Defines.ERROR_AGREEMENTNOTEXITS, channelName, user, billCode);

            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
            processAgreementResp.setResponseCode(Defines.CODE_AGREEMENTNOTEXITS);
            processAgreementResp.setXmlData(pData);
            processAgreementResp.setSignedData(null);
            processAgreementResp.setPreTrustedHubTransId(null);
            return processAgreementResp;
        }

        String method = ExtFunc.getContent(Defines._METHOD, xmlData);

        if (method.compareTo(Defines._OTPEMAIL) == 0
                || method.compareTo(Defines._OTPSMS) == 0) {
            String requestType = ExtFunc.getContent(Defines._REQUESTTYPE, xmlData);
            String transactionData = ExtFunc.getContent(Defines._TRANSACTIONDATA, xmlData);
            String subject = ExtFunc.getContent(Defines._SUBJECT, xmlData);

            if (!DBConnector.getInstances().authCheckOTPMethodLinked(channelName, user, method)) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_AGREEMENTNOTREADY,
                        Defines.ERROR_AGREEMENTNOTREADY, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_AGREEMENTNOTREADY);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            }

            int hwOtpCheck = DBConnector.getInstances().checkHWOTP(channelName, user);
            if (hwOtpCheck == 1 || hwOtpCheck == 2) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_OTPLOCKED,
                        Defines.ERROR_OTPLOCKED, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_OTPLOCKED);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            } else if (hwOtpCheck == -1) {

                String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                        Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            }


            if (requestType.compareTo(Defines.WORKER_OATHREQUEST) == 0) {

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

                if (transactionData.equals("")) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                final int requestId = random.nextInt();
                final int workerId = getWorkerId(Defines.WORKER_OATHREQUEST);

                if (workerId < 1) {

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                            Defines.ERROR_NOWORKER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_NOWORKER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
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

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                if (!(resp instanceof GenericSignResponse)) {
                    LOG.error("resp is not a instance of GenericSignResponse");

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                            Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                } else {
                    final GenericSignResponse signResponse = (GenericSignResponse) resp;
                    if (signResponse.getRequestID() != requestId) {
                        LOG.error("Response ID " + signResponse.getRequestID()
                                + " not matching request ID " + requestId);

                        String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                                Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_NOTMATCHID);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
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

                                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                                processAgreementResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                                processAgreementResp.setXmlData(pData);
                                processAgreementResp.setSignedData(null);
                                processAgreementResp.setPreTrustedHubTransId(null);
                                return processAgreementResp;
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

                                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                                processAgreementResp.setResponseCode(Defines.CODE_INVALID_EXT_CONN_VENDOR);
                                processAgreementResp.setXmlData(pData);
                                processAgreementResp.setSignedData(null);
                                processAgreementResp.setPreTrustedHubTransId(null);
                                return processAgreementResp;
                            }

                            EndpointServiceResp endpointServiceResp = EndpointService.getInstance().sendSms(channelName, user, phoneNo, otpInformation, endpointParams[1], Integer.parseInt(endpointParams[2]), trustedHubTransId);

                        }

                        if (method.compareTo(Defines._OTPEMAIL) == 0) {
                            DBConnector.getInstances().authSetIsOTPEmailActive(agreementID, false);
                        } else {
                            DBConnector.getInstances().authSetIsOTPSMSActive(agreementID, false);
                        }

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_OTP_STATUS_WAIT);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    } else {
                        String pData = ExtFunc.genResponseMessage(responseCode,
                                responseMessage, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(responseCode);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }
                }
            } else if (requestType.compareTo(Defines.WORKER_OATHRESPONSE) == 0) {

                String _billCode = ExtFunc.getContent(Defines._BILLCODE, xmlData);
                int preTrustedHubTransId = ExtFunc.getTransId(_billCode);

                String _otp = ExtFunc.getContent(Defines._OTP, xmlData);

                List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();
                if (!metaData.equals("")) {
                    requestMetadata = getMetaData(metaData);
                }

                org.signserver.clientws.Metadata channelNameOTP = new org.signserver.clientws.Metadata(Defines._CHANNEL, channelName);
                org.signserver.clientws.Metadata userOTP = new org.signserver.clientws.Metadata(Defines._USER, user);
                requestMetadata.add(channelNameOTP);
                requestMetadata.add(userOTP);

                if (_otp.compareTo("") == 0
                        || _billCode.compareTo("") == 0) {

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processAgreementResp;
                }

                if (ExtFunc.getTransId(_billCode) == 1) {
                    LOG.error("Invalid billCode " + _billCode);
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processAgreementResp;
                }

                final int requestId = random.nextInt();
                final int workerId = getWorkerId(Defines.WORKER_OATHRESPONSE);

                if (workerId < 1) {

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                            Defines.ERROR_NOWORKER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_NOWORKER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processAgreementResp;
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

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processAgreementResp;
                }

                if (!(resp instanceof GenericSignResponse)) {
                    LOG.error("resp is not a instance of GenericSignResponse");

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                            Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processAgreementResp;
                } else {
                    final GenericSignResponse signResponse = (GenericSignResponse) resp;
                    if (signResponse.getRequestID() != requestId) {
                        LOG.error("Response ID " + signResponse.getRequestID()
                                + " not matching request ID " + requestId);

                        String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                                Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_NOTMATCHID);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(preTrustedHubTransId);
                        return processAgreementResp;

                    }

                    int responseCode = signResponse.getResponseCode();
                    String responseMessage = signResponse.getResponseMessage();

                    if (responseCode == Defines.CODE_SUCCESS) {
                        // SUCCESS
                        if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                            DBConnector.getInstances().increaseSuccessTransaction();
                        }

                        DBConnector.getInstances().resetErrorCounterHWOTP(channelName, user);

                        if (method.compareTo(Defines._OTPEMAIL) == 0) {
                            DBConnector.getInstances().authSetIsOTPEmailActive(agreementID, true);
                        } else {
                            DBConnector.getInstances().authSetIsOTPSMSActive(agreementID, true);
                        }

                        String pData = ExtFunc.genResponseOATHMessage(responseCode,
                                responseMessage, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(responseCode);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(preTrustedHubTransId);
                        return processAgreementResp;
                    } else if (responseCode == Defines.CODE_OTP_STATUS_FAIL) {

                        int otpCheck = DBConnector.getInstances().leftRetryHWOTP(channelName, user);
                        if (otpCheck == -100) {

                            String pData = ExtFunc.genResponseMessage(Defines.CODE_OTPLOCKED,
                                    Defines.ERROR_OTPLOCKED, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_OTPLOCKED);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(preTrustedHubTransId);
                            return processAgreementResp;
                        }

                        String pData = ExtFunc.genResponseOATHMessage(responseCode,
                                responseMessage, channelName, user, billCode, otpCheck);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(responseCode);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(preTrustedHubTransId);
                        return processAgreementResp;
                    } else {
                        String pData = ExtFunc.genResponseMessage(responseCode,
                                responseMessage, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(responseCode);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(preTrustedHubTransId);
                        return processAgreementResp;
                    }
                }

            } else if (requestType.compareTo(Defines.REQUEST_TYPE_FORCE_ACTI) == 0) {
                // SUCCESS
                if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                    DBConnector.getInstances().increaseSuccessTransaction();
                }

                DBConnector.getInstances().resetErrorCounterHWOTP(channelName, user);

                if (method.compareTo(Defines._OTPEMAIL) == 0) {
                    DBConnector.getInstances().authSetIsOTPEmailActive(agreementID, true);
                } else {
                    DBConnector.getInstances().authSetIsOTPSMSActive(agreementID, true);
                }

                String pData = ExtFunc.genResponseOATHMessage(Defines.CODE_SUCCESS,
                        Defines.SUCCESS, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_SUCCESS);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            } else {
                String pData = ExtFunc.genResponseMessage(
                        Defines.CODE_INVALID_TYPE_REQUEST,
                        Defines.ERROR_INVALID_TYPE_REQUEST, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_INVALID_TYPE_REQUEST);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            }
        } else if (method.compareTo(Defines._OTPHARDWARE) == 0) {
            String requestType = ExtFunc.getContent(Defines._REQUESTTYPE, xmlData);
            if (requestType.compareTo(Defines.REQUEST_TYPE_FORCE_ACTI) == 0) {
                if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                    DBConnector.getInstances().increaseSuccessTransaction();
                }

                DBConnector.getInstances().resetErrorCounterHWOTP(channelName, user);

                DBConnector.getInstances().authSetIsOTPHardwareActive(agreementID, true);

                String pData = ExtFunc.genResponseMessage(Defines.CODE_SUCCESS,
                        Defines.SUCCESS, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_SUCCESS);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            } else {
                if (!DBConnector.getInstances().authCheckOTPMethodLinked(channelName, user, method)) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_AGREEMENTNOTREADY,
                            Defines.ERROR_AGREEMENTNOTREADY, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_AGREEMENTNOTREADY);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                int hwOtpCheck = DBConnector.getInstances().checkHWOTP(channelName, user);
                if (hwOtpCheck == 1 || hwOtpCheck == 2) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_OTPLOCKED,
                            Defines.ERROR_OTPLOCKED, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_OTPLOCKED);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                } else if (hwOtpCheck == -1) {

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                            Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }
                // First. Deactive OTPHardware
                DBConnector.getInstances().authSetIsOTPHardwareActive(agreementID, false);

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
                final int workerId = getWorkerId(Defines.WORKER_OATHVALIDATOR);

                if (workerId < 1) {

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                            Defines.ERROR_NOWORKER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_NOWORKER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
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

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                if (!(resp instanceof GenericSignResponse)) {
                    LOG.error("resp is not a instance of GenericSignResponse");

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                            Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                } else {
                    final GenericSignResponse signResponse = (GenericSignResponse) resp;
                    if (signResponse.getRequestID() != requestId) {
                        LOG.error("Response ID " + signResponse.getRequestID()
                                + " not matching request ID " + requestId);

                        String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                                Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_NOTMATCHID);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;

                    }

                    int responseCode = signResponse.getResponseCode();
                    String responseMessage = signResponse.getResponseMessage();

                    if (responseCode == Defines.CODE_SUCCESS) {

                        if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                            DBConnector.getInstances().increaseSuccessTransaction();
                        }

                        DBConnector.getInstances().resetErrorCounterHWOTP(channelName, user);

                        DBConnector.getInstances().authSetIsOTPHardwareActive(agreementID, true);

                        String pData = ExtFunc.genResponseMessage(responseCode,
                                responseMessage, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(responseCode);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    } else {
                        if (responseCode == Defines.CODE_OTPLOCKED) {
                            // locked
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_OTPLOCKED,
                                    Defines.ERROR_OTPLOCKED, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_OTPLOCKED);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        } else if (responseCode == Defines.CODE_OTP_STATUS_FAIL) {
                            // invalid
                            String retry = new String(signResponse.getProcessedData());

                            int otpRetry = Integer.parseInt(retry);

                            String pData = ExtFunc.genResponseMessage(responseCode,
                                    responseMessage, channelName, user, otpRetry,
                                    billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(responseCode);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        } else if (responseCode == Defines.CODE_OTPNEEDSYNC) {
                            // synch

                            String pData = ExtFunc.genResponseMessage(responseCode,
                                    responseMessage, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(responseCode);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        } else if (responseCode == Defines.CODE_OTP_STATUS_DISABLE) {
                            // disable
                            String pData = ExtFunc.genResponseMessage(responseCode,
                                    responseMessage, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(responseCode);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        } else if (responseCode == Defines.CODE_OTP_STATUS_LOST) {
                            // lost
                            String pData = ExtFunc.genResponseMessage(responseCode,
                                    responseMessage, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(responseCode);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        } else {
                            // unknown exception
                            String pData = ExtFunc.genResponseMessage(responseCode,
                                    responseMessage, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(responseCode);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        }
                    }
                }
            }
        } else if (method.compareTo(Defines.SIGNATURE_METHOD_WPKI) == 0) {

            if (!DBConnector.getInstances().checkPKIMethodLinked(channelName, user, Defines.SIGNATURE_METHOD_WPKI)) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_CONTRACTSTATUS,
                        Defines.ERROR_CONTRACTSTATUS, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_CONTRACTSTATUS);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            }

            int hwPkiCheck = DBConnector.getInstances().checkHWPKI(channelName, user);
            if (hwPkiCheck == 1 || hwPkiCheck == 2) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_PKILOCKED,
                        Defines.ERROR_PKILOCKED, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_PKILOCKED);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            } else if (hwPkiCheck == -1) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                        Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            }

            String requestType = ExtFunc.getContent(Defines._REQUESTTYPE, xmlData);
            String[] pkiSim = DBConnector.getInstances().authGetPhoneNoSimPKI(channelName, user);

            if (pkiSim == null) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_CONTRACTSTATUS,
                        Defines.ERROR_CONTRACTSTATUS, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_CONTRACTSTATUS);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            }
            // First. De-activate WPKI method
            DBConnector.getInstances().authSetIsSimPKIActive(agreementID, false);

            if (requestType.compareTo(Defines.SIGNERAP_SIGREG) == 0) {
                List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();
                String dm = ExtFunc.getContent(Defines._DISPLAYMESSAGE, xmlData);
                String messageMode = ExtFunc.getContent(Defines._MESSAGEMODE, xmlData);

                if (messageMode.compareTo(Defines.SIGNERAP_ASYNC_REQ_RESP) != 0) {
                    messageMode = Defines.SIGNERAP_ASYNC;
                }

                if (dm.equals("")) {
                    dm = "Kich hoat hop dong PKI SIM - TRUSTEDHUB";
                }

                org.signserver.clientws.Metadata user_pkisim = new org.signserver.clientws.Metadata(
                        Defines._USER, user);

                org.signserver.clientws.Metadata channelName_pkisim = new org.signserver.clientws.Metadata(
                        Defines._CHANNEL, channelName);

                org.signserver.clientws.Metadata phoneNo_pkisim = new org.signserver.clientws.Metadata(
                        Defines._PKISIM, pkiSim[0]);

                org.signserver.clientws.Metadata vendor_pkisim = new org.signserver.clientws.Metadata(
                        Defines._PKISIMVENDOR, pkiSim[3]);

                org.signserver.clientws.Metadata algorithm_pkisim = new org.signserver.clientws.Metadata(
                        Defines._ALGORITHM, Defines.HASH_SHA1);

                org.signserver.clientws.Metadata displayMessage_pkisim = new org.signserver.clientws.Metadata(
                        Defines._DISPLAYMESSAGE, dm);

                org.signserver.clientws.Metadata messageMode_pkisim = new org.signserver.clientws.Metadata(
                        Defines._MESSAGEMODE, messageMode);

                org.signserver.clientws.Metadata method_pkisim = new org.signserver.clientws.Metadata(
                        Defines._METHOD, Defines.SIGNERAP_SIGREG);

                org.signserver.clientws.Metadata endpointconfigid_pkisim = new org.signserver.clientws.Metadata(
                        Defines._ENDPOINTCONFIGID, pkiSim[5]);

                org.signserver.clientws.Metadata endpointconfigValue_pkisim = new org.signserver.clientws.Metadata(
                        Defines._ENDPOINTVALUE, pkiSim[4]);

                org.signserver.clientws.Metadata trustedhub_trans_id = new org.signserver.clientws.Metadata(Defines._TRUSTEDHUBTRANSID, String.valueOf(trustedHubTransId));

                byteData = new byte[20];

                requestMetadata.add(user_pkisim);
                requestMetadata.add(channelName_pkisim);
                requestMetadata.add(phoneNo_pkisim);
                requestMetadata.add(vendor_pkisim);
                requestMetadata.add(algorithm_pkisim);
                requestMetadata.add(displayMessage_pkisim);
                requestMetadata.add(messageMode_pkisim);
                requestMetadata.add(method_pkisim);
                requestMetadata.add(endpointconfigid_pkisim);
                requestMetadata.add(endpointconfigValue_pkisim);
                requestMetadata.add(trustedhub_trans_id);

                final int requestId = random.nextInt();

                final int wId = getWorkerId(Defines.WORKER_SIGNERAP);

                final RequestContext requestContext = handleRequestContext(
                        requestMetadata, wId);

                final ProcessRequest req = new GenericSignRequest(requestId,
                        byteData);
                ProcessResponse resp = null;
                try {
                    resp = getWorkerSession().process(wId, req, requestContext);
                } catch (Exception e) {
                    LOG.error("Something wrong: " + e.getMessage());
                    e.printStackTrace();
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INTERNALSYSTEM,
                            Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                if (!(resp instanceof GenericSignResponse)) {
                    LOG.error("resp is not a instance of GenericSignResponse");

                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_UNEXPECTEDRETURNTYPE,
                            Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                } else {
                    final GenericSignResponse signResponse = (GenericSignResponse) resp;
                    if (signResponse.getRequestID() != requestId) {
                        LOG.error("Response ID " + signResponse.getRequestID()
                                + " not matching request ID " + requestId);

                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_NOTMATCHID,
                                Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_NOTMATCHID);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }
                    int responseCode = signResponse.getResponseCode();
                    String responseMessage = signResponse.getResponseMessage();
                    Integer endpointId = signResponse.getEndpointId();

                    if (responseCode == Defines.CODE_MSSP_REQUEST_ACCEPTED) {
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

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_MSSP_REQUEST_ACCEPTED);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    } else {
                        String pData = ExtFunc.genResponseMessage(
                                responseCode,
                                responseMessage, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(responseCode);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }
                }
            } else if (requestType.compareTo(Defines.SIGNERAP_STAREG) == 0) {

                String _billCode = ExtFunc.getContent(Defines._BILLCODE, xmlData);
                // auto add authCode in to requestMetadata
                int preTrustedHubTransId = ExtFunc.getTransId(_billCode);

                if (_billCode.compareTo("") == 0) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processAgreementResp;
                }

                if (ExtFunc.getTransId(_billCode) == 1) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processAgreementResp;
                }


                List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();

                if (!metaData.equals("")) {
                    requestMetadata = getMetaData(metaData);
                }

                org.signserver.clientws.Metadata user_pkisim = new org.signserver.clientws.Metadata(
                        Defines._USER, user);

                org.signserver.clientws.Metadata channelName_pkisim = new org.signserver.clientws.Metadata(
                        Defines._CHANNEL, channelName);

                org.signserver.clientws.Metadata phoneNo_pkisim = new org.signserver.clientws.Metadata(
                        Defines._PKISIM, pkiSim[0]);

                org.signserver.clientws.Metadata vendor_pkisim = new org.signserver.clientws.Metadata(
                        Defines._PKISIMVENDOR, pkiSim[3]);

                org.signserver.clientws.Metadata method_pkisim = new org.signserver.clientws.Metadata(
                        Defines._METHOD, Defines.SIGNERAP_CERTREG);

                org.signserver.clientws.Metadata endpointconfigid_pkisim = new org.signserver.clientws.Metadata(
                        Defines._ENDPOINTCONFIGID, pkiSim[5]);

                org.signserver.clientws.Metadata endpointconfigValue_pkisim = new org.signserver.clientws.Metadata(
                        Defines._ENDPOINTVALUE, pkiSim[4]);

                org.signserver.clientws.Metadata trustedhub_trans_id = new org.signserver.clientws.Metadata(Defines._TRUSTEDHUBTRANSID, String.valueOf(trustedHubTransId));

                byteData = new byte[20];

                requestMetadata.add(user_pkisim);
                requestMetadata.add(channelName_pkisim);
                requestMetadata.add(phoneNo_pkisim);
                requestMetadata.add(vendor_pkisim);
                requestMetadata.add(method_pkisim);
                requestMetadata.add(endpointconfigid_pkisim);
                requestMetadata.add(endpointconfigValue_pkisim);
                requestMetadata.add(trustedhub_trans_id);

                final int requestId = random.nextInt();

                final int wId = getWorkerId(Defines.WORKER_SIGNERAP);

                final RequestContext requestContext = handleRequestContext(
                        requestMetadata, wId);

                final ProcessRequest req = new GenericSignRequest(requestId,
                        byteData);
                ProcessResponse resp = null;
                try {
                    resp = getWorkerSession().process(wId, req, requestContext);
                } catch (Exception e) {
                    LOG.error("Something wrong: " + e.getMessage());
                    e.printStackTrace();
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INTERNALSYSTEM,
                            Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processAgreementResp;
                }

                if (!(resp instanceof GenericSignResponse)) {
                    LOG.error("resp is not a instance of GenericSignResponse");

                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_UNEXPECTEDRETURNTYPE,
                            Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(preTrustedHubTransId);
                    return processAgreementResp;
                } else {
                    final GenericSignResponse signResponse = (GenericSignResponse) resp;
                    if (signResponse.getRequestID() != requestId) {
                        LOG.error("Response ID " + signResponse.getRequestID()
                                + " not matching request ID " + requestId);

                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_NOTMATCHID,
                                Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_NOTMATCHID);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(preTrustedHubTransId);
                        return processAgreementResp;
                    }
                    int responseCode = signResponse.getResponseCode();
                    String responseMessage = signResponse.getResponseMessage();
                    Integer endpointId = signResponse.getEndpointId();
                    if (responseCode == Defines.CODE_SUCCESS) {

                        // reset error counter
                        DBConnector.getInstances().resetErrorCounterHWPKI(channelName, user);

                        String signingcert = null;
                        try {
                            signingcert = signResponse.getSignerCertificate() == null ? new String(
                                    Base64.encode(signResponse.getSignerCertificateChainBytes()))
                                    : new String(Base64.encode(signResponse.getSignerCertificate().getEncoded()));
                        } catch (CertificateEncodingException e) {
                            LOG.error("Something wrong: " + e.getMessage());
                            e.printStackTrace();
                            String pData = ExtFunc.genResponseMessage(
                                    Defines.CODE_INTERNALSYSTEM,
                                    Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);


                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(preTrustedHubTransId);
                            return processAgreementResp;
                        }
                        CertificateAgreementStatus certificateAgreementStatusWPKI = isCertificateValid(channelName, user, signingcert, trustedHubTransId);
                        if (!certificateAgreementStatusWPKI.isValid()) {

                            String pData = ExtFunc.genResponseMessage(
                                    Defines.CODE_INVALIDCERTIFICATE,
                                    Defines.ERROR_INVALIDCERTIFICATE, channelName, user, billCode);


                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(preTrustedHubTransId);
                            return processAgreementResp;
                        }

                        String[] certs = ExtFunc.getCertificateComponents(signingcert);

                        // update in sim pkiinformation
                        boolean res = DBConnector.getInstances().authSetSimCertificateArrangement(agreementID,
                                certs[5], signingcert, pkiSim[0], pkiSim[3]);

                        if (!res) {
                            String pData = ExtFunc.genResponseMessage(
                                    Defines.CODE_UPDATESIMPKI,
                                    Defines.ERROR_UPDATESIMPKI, channelName, user, billCode);


                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_UPDATESIMPKI);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(preTrustedHubTransId);
                            return processAgreementResp;
                        }

                        DBConnector.getInstances().authSetIsSimPKIActive(agreementID, true);

                        String pData = ExtFunc.genResponseMessage(
                                responseCode,
                                responseMessage, channelName, user, null, signingcert, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(responseCode);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(preTrustedHubTransId);
                        return processAgreementResp;
                    } else if (responseCode == Defines.CODE_MSSP_AUTH_FAILED) {
                        int pkiCheck = DBConnector.getInstances().leftRetryHWPKI(channelName, user);
                        if (pkiCheck == -100) {
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_PKILOCKED,
                                    Defines.ERROR_PKILOCKED, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_PKILOCKED);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        }

                        String pData = ExtFunc.genResponseMessage(responseCode,
                                responseMessage, channelName, user, pkiCheck, billCode);


                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(responseCode);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    } else {
                        String pData = ExtFunc.genResponseMessage(
                                responseCode,
                                responseMessage, channelName, user, billCode);


                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(responseCode);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(preTrustedHubTransId);
                        return processAgreementResp;
                    }
                }
            } else if (requestType.compareTo(Defines.REQUEST_TYPE_FORCE_ACTI) == 0) {
                String wCertificate = ExtFunc.getContent(Defines._WCERTIFICATE, xmlData);
                if (wCertificate.compareTo("") == 0) {
                    LOG.error("wCertificate is NULL or EMPTY");
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                CertificateAgreementStatus certificateAgreementStatusWPKI = isCertificateValid(channelName, user, wCertificate, trustedHubTransId);
                if (!certificateAgreementStatusWPKI.isValid()) {
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_INVALIDCERTIFICATE,
                            Defines.ERROR_INVALIDCERTIFICATE, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                String[] certs = ExtFunc.getCertificateComponents(wCertificate);

                // update in sim pkiinformation
                boolean res = DBConnector.getInstances().authSetSimCertificateArrangement(agreementID,
                        certs[5], wCertificate, pkiSim[0], pkiSim[3]);

                if (!res) {
                    String pData = ExtFunc.genResponseMessage(
                            Defines.CODE_UPDATESIMPKI,
                            Defines.ERROR_UPDATESIMPKI, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UPDATESIMPKI);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                DBConnector.getInstances().authSetIsSimPKIActive(agreementID, true);

                String pData = ExtFunc.genResponseMessage(
                        Defines.CODE_SUCCESS,
                        Defines.SUCCESS, channelName, user, null, wCertificate, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_SUCCESS);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            } else {
                String pData = ExtFunc.genResponseMessage(
                        Defines.CODE_INVALID_TYPE_REQUEST,
                        Defines.ERROR_INVALID_TYPE_REQUEST, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_INVALID_TYPE_REQUEST);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            }
        } else if (method.compareTo(Defines.SIGNATURE_METHOD_TPKI) == 0) {
            String requestType = ExtFunc.getContent(Defines._REQUESTTYPE, xmlData);

            if (!DBConnector.getInstances().checkPKIMethodLinked(channelName, user, Defines.SIGNATURE_METHOD_TPKI)) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_CONTRACTSTATUS,
                        Defines.ERROR_CONTRACTSTATUS, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_CONTRACTSTATUS);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            }

            int hwPkiCheck = DBConnector.getInstances().checkHWPKI(channelName, user);
            if (hwPkiCheck == 1 || hwPkiCheck == 2) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_PKILOCKED,
                        Defines.ERROR_PKILOCKED, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_PKILOCKED);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            } else if (hwPkiCheck == -1) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                        Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            }

            if (requestType.compareTo(Defines.REQUEST_TYPE_FORCE_ACTI) == 0) {

                if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                    DBConnector.getInstances().increaseSuccessTransaction();
                }
                DBConnector.getInstances().resetErrorCounterHWPKI(channelName, user);

                DBConnector.getInstances().authSetIsTPKIActive(agreementID, true);

                String pData = ExtFunc.genResponseMessage(
                        Defines.CODE_SUCCESS,
                        Defines.SUCCESS, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_SUCCESS);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            } else {
                signedData = ExtFunc.getContent(Defines._SIGNEDDATA, xmlData);
                String encoding = ExtFunc.getContent(Defines._ENCODING, xmlData);
                String signature = ExtFunc.getContent(Defines._SIGNATURE, xmlData);

                if (signature.compareTo("") == 0 || signedData.compareTo("") == 0) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                if (encoding.compareTo("") == 0) {
                    encoding = Defines.ENCODING_UTF16;
                }

                byteData = Base64.decode(signature);
                String[] pkiInformation = DBConnector.getInstances().authGetCertificateTPKI(channelName, user);
                String serialNumber = ExtFunc.getCertificateComponents(pkiInformation[0])[0];

                // First de-activate TPKI
                DBConnector.getInstances().authSetIsTPKIActive(agreementID, false);

                List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();
                if (!metaData.equals("")) {
                    requestMetadata = getMetaData(metaData);
                }

                org.signserver.clientws.Metadata channelNameOTP = new org.signserver.clientws.Metadata(Defines._CHANNEL, channelName);
                org.signserver.clientws.Metadata userOTP = new org.signserver.clientws.Metadata(Defines._USER, user);
                org.signserver.clientws.Metadata meta_serialCertificate = new org.signserver.clientws.Metadata(Defines._SERIALNUMBER, serialNumber);
                org.signserver.clientws.Metadata trustedhub_trans_id = new org.signserver.clientws.Metadata(Defines._TRUSTEDHUBTRANSID, String.valueOf(trustedHubTransId));
                org.signserver.clientws.Metadata signatureMethod = new org.signserver.clientws.Metadata(Defines._SIGNATUREMETHOD, Defines.SIGNATURE_METHOD_TPKI);

                requestMetadata.add(channelNameOTP);
                requestMetadata.add(userOTP);
                requestMetadata.add(meta_serialCertificate);
                requestMetadata.add(trustedhub_trans_id);
                requestMetadata.add(signatureMethod);

                final int requestId = random.nextInt();
                final int workerId = getWorkerId(Defines.WORKER_SIGNATUREVALIDATOR);

                if (workerId < 1) {

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                            Defines.ERROR_NOWORKER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_NOWORKER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
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

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                if (!(resp instanceof GenericSignResponse)) {
                    LOG.error("resp is not a instance of GenericSignResponse");

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                            Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                } else {
                    final GenericSignResponse signResponse = (GenericSignResponse) resp;
                    if (signResponse.getRequestID() != requestId) {
                        LOG.error("Response ID " + signResponse.getRequestID() + " not matching request ID " + requestId);

                        String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                                Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_NOTMATCHID);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;

                    }

                    int responseCode = signResponse.getResponseCode();
                    String responseMessage = signResponse.getResponseMessage();

                    List<SignerInfoResponse> signInfo = signResponse.getSignerInfoResponse();

                    if (responseCode == Defines.CODE_SUCCESS) {
                        if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                            DBConnector.getInstances().increaseSuccessTransaction();
                        }
                        DBConnector.getInstances().resetErrorCounterHWPKI(channelName, user);

                        DBConnector.getInstances().authSetIsTPKIActive(agreementID, true);

                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_SUCCESS,
                                Defines.SUCCESS, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_SUCCESS);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;

                    } else if (responseCode == Defines.CODE_INVALIDSIGNATURE) {
                        int pkiCheck = DBConnector.getInstances().leftRetryHWPKI(
                                channelName, user);
                        if (pkiCheck == -100) {
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_PKILOCKED,
                                    Defines.ERROR_PKILOCKED, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_PKILOCKED);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        }

                        String pData = ExtFunc.genResponseMessage(responseCode,
                                responseMessage, channelName, user, pkiCheck, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(responseCode);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;

                    } else {
                        String pData = ExtFunc.genResponseMessage(responseCode,
                                responseMessage, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(responseCode);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }
                }
            }
        } else if (method.compareTo(Defines.SIGNATURE_METHOD_LPKI) == 0) {
            String requestType = ExtFunc.getContent(Defines._REQUESTTYPE, xmlData);

            if (!DBConnector.getInstances().checkPKIMethodLinked(channelName, user, Defines.SIGNATURE_METHOD_LPKI)) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_CONTRACTSTATUS,
                        Defines.ERROR_CONTRACTSTATUS, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_CONTRACTSTATUS);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            }

            int hwPkiCheck = DBConnector.getInstances().checkHWPKI(channelName, user);
            if (hwPkiCheck == 1 || hwPkiCheck == 2) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_PKILOCKED,
                        Defines.ERROR_PKILOCKED, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_PKILOCKED);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            } else if (hwPkiCheck == -1) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
                        Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            }

            if (requestType.compareTo(Defines.REQUEST_TYPE_FORCE_ACTI) == 0) {
                if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                    DBConnector.getInstances().increaseSuccessTransaction();
                }
                DBConnector.getInstances().resetErrorCounterHWPKI(channelName, user);

                DBConnector.getInstances().authSetIsLPKIActive(agreementID, true);

                String pData = ExtFunc.genResponseMessage(
                        Defines.CODE_SUCCESS,
                        Defines.SUCCESS, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_SUCCESS);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            } else {
                signedData = ExtFunc.getContent(Defines._SIGNEDDATA, xmlData);
                String encoding = ExtFunc.getContent(Defines._ENCODING, xmlData);
                String signature = ExtFunc.getContent(Defines._SIGNATURE, xmlData);

                if (signature.compareTo("") == 0 || signedData.compareTo("") == 0) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_INVALIDPARAMETER,
                            Defines.ERROR_INVALIDPARAMETER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INVALIDPARAMETER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                if (encoding.compareTo("") == 0) {
                    encoding = Defines.ENCODING_UTF16;
                }

                byteData = Base64.decode(signature);
                String[] pkiInformation = DBConnector.getInstances().authGetCertificateLPKI(channelName, user);
                String serialNumber = ExtFunc.getCertificateComponents(pkiInformation[0])[0];
                String certificate = pkiInformation[0];

                // First de-activate LPKI
                DBConnector.getInstances().authSetIsLPKIActive(agreementID, false);

                List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();
                if (!metaData.equals("")) {
                    requestMetadata = getMetaData(metaData);
                }

                org.signserver.clientws.Metadata channelNameOTP = new org.signserver.clientws.Metadata(Defines._CHANNEL, channelName);
                org.signserver.clientws.Metadata userOTP = new org.signserver.clientws.Metadata(Defines._USER, user);
                org.signserver.clientws.Metadata meta_serialCertificate = new org.signserver.clientws.Metadata(Defines._SERIALNUMBER, serialNumber);
                org.signserver.clientws.Metadata trustedhub_trans_id = new org.signserver.clientws.Metadata(Defines._TRUSTEDHUBTRANSID, String.valueOf(trustedHubTransId));
                org.signserver.clientws.Metadata signatureMethod = new org.signserver.clientws.Metadata(Defines._SIGNATUREMETHOD, Defines.SIGNATURE_METHOD_LPKI);
                org.signserver.clientws.Metadata meta_certificate = new org.signserver.clientws.Metadata(Defines._CERTIFICATE, certificate);

                requestMetadata.add(channelNameOTP);
                requestMetadata.add(userOTP);
                requestMetadata.add(meta_serialCertificate);
                requestMetadata.add(trustedhub_trans_id);
                requestMetadata.add(signatureMethod);
                requestMetadata.add(meta_certificate);

                final int requestId = random.nextInt();
                final int workerId = getWorkerId(Defines.WORKER_SIGNATUREVALIDATOR);

                if (workerId < 1) {

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                            Defines.ERROR_NOWORKER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_NOWORKER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
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

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                if (!(resp instanceof GenericSignResponse)) {
                    LOG.error("resp is not a instance of GenericSignResponse");

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                            Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                } else {
                    final GenericSignResponse signResponse = (GenericSignResponse) resp;
                    if (signResponse.getRequestID() != requestId) {
                        LOG.error("Response ID " + signResponse.getRequestID() + " not matching request ID " + requestId);

                        String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                                Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_NOTMATCHID);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;

                    }

                    int responseCode = signResponse.getResponseCode();
                    String responseMessage = signResponse.getResponseMessage();

                    List<SignerInfoResponse> signInfo = signResponse.getSignerInfoResponse();

                    if (responseCode == Defines.CODE_SUCCESS) {
                        if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                            DBConnector.getInstances().increaseSuccessTransaction();
                        }
                        DBConnector.getInstances().resetErrorCounterHWPKI(channelName, user);

                        DBConnector.getInstances().authSetIsLPKIActive(agreementID, true);

                        String pData = ExtFunc.genResponseMessage(
                                Defines.CODE_SUCCESS,
                                Defines.SUCCESS, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_SUCCESS);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;

                    } else if (responseCode == Defines.CODE_INVALIDSIGNATURE) {
                        int pkiCheck = DBConnector.getInstances().leftRetryHWPKI(
                                channelName, user);
                        if (pkiCheck == -100) {
                            String pData = ExtFunc.genResponseMessage(Defines.CODE_PKILOCKED,
                                    Defines.ERROR_PKILOCKED, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_PKILOCKED);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        }

                        String pData = ExtFunc.genResponseMessage(responseCode,
                                responseMessage, channelName, user, pkiCheck, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(responseCode);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;

                    } else {
                        String pData = ExtFunc.genResponseMessage(responseCode,
                                responseMessage, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(responseCode);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }
                }
            }
        } else if (method.compareTo(Defines.WORKER_U2FVALIDATOR) == 0) {

            String requestType = ExtFunc.getContent(Defines._REQUESTTYPE, xmlData);
            String appId = DBConnector.getInstances().checkU2FLinked(channelName, user);

            if (appId == null) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_AGREEMENTNOTREADY,
                        Defines.ERROR_AGREEMENTNOTREADY, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_AGREEMENTNOTREADY);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            }

            if (!DBConnector.getInstances().checkU2FLock(channelName, user)) {
                String pData = ExtFunc.genResponseMessage(Defines.CODE_U2F_BLOCKED,
                        Defines.ERROR_U2F_BLOCKED, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_U2F_BLOCKED);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            }

            if (requestType.compareTo(Defines.U2F_REG_REQUEST) == 0) {

                // First de-activate
                DBConnector.getInstances().setU2FLinked(agreementID, false);

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

                org.signserver.clientws.Metadata method_metadata = new org.signserver.clientws.Metadata(
                        Defines._METHOD, requestType);

                requestMetadata.add(channelName_metadata);
                requestMetadata.add(user_metadata);
                requestMetadata.add(trustedhub_trans_id);
                requestMetadata.add(appId_metadata);
                requestMetadata.add(method_metadata);

                final int requestId = random.nextInt();
                final int workerId = getWorkerId(Defines.WORKER_U2FVALIDATOR);

                if (workerId < 1) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                            Defines.ERROR_NOWORKER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_NOWORKER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
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

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                if (!(resp instanceof GenericSignResponse)) {
                    LOG.error("resp is not a instance of GenericSignResponse");

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                            Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                } else {
                    final GenericSignResponse signResponse = (GenericSignResponse) resp;
                    if (signResponse.getRequestID() != requestId) {
                        LOG.error("Response ID " + signResponse.getRequestID()
                                + " not matching request ID " + requestId);

                        String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                                Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_NOTMATCHID);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;

                    }

                    int responseCode = signResponse.getResponseCode();
                    String responseMessage = signResponse.getResponseMessage();

                    if (responseCode == Defines.CODE_SUCCESS) {

                        if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                            DBConnector.getInstances().increaseSuccessTransaction();
                        }

                        String u2fJsonResp = signResponse.getResponseStrData();

                        String pData = ExtFunc.genResponseMessageForU2F(responseCode,
                                responseMessage, channelName, user, billCode, u2fJsonResp);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(responseCode);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    } else {
                        String pData = ExtFunc.genResponseMessage(responseCode,
                                responseMessage, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(responseCode);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    }
                }
            } else if (requestType.compareTo(Defines.U2F_REG_RESPONSE) == 0) {
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

                org.signserver.clientws.Metadata method_metadata = new org.signserver.clientws.Metadata(
                        Defines._METHOD, requestType);

                requestMetadata.add(channelName_metadata);
                requestMetadata.add(user_metadata);
                requestMetadata.add(trustedhub_trans_id);
                requestMetadata.add(appId_metadata);
                requestMetadata.add(method_metadata);

                final int requestId = random.nextInt();
                final int workerId = getWorkerId(Defines.WORKER_U2FVALIDATOR);

                if (workerId < 1) {
                    String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
                            Defines.ERROR_NOWORKER, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_NOWORKER);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
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

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                }

                if (!(resp instanceof GenericSignResponse)) {
                    LOG.error("resp is not a instance of GenericSignResponse");

                    String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
                            Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);

                    ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                    processAgreementResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
                    processAgreementResp.setXmlData(pData);
                    processAgreementResp.setSignedData(null);
                    processAgreementResp.setPreTrustedHubTransId(null);
                    return processAgreementResp;
                } else {
                    final GenericSignResponse signResponse = (GenericSignResponse) resp;
                    if (signResponse.getRequestID() != requestId) {
                        LOG.error("Response ID " + signResponse.getRequestID()
                                + " not matching request ID " + requestId);

                        String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
                                Defines.ERROR_NOTMATCHID, channelName, user, billCode);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(Defines.CODE_NOTMATCHID);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;

                    }

                    int responseCode = signResponse.getResponseCode();
                    String responseMessage = signResponse.getResponseMessage();

                    if (responseCode == Defines.CODE_SUCCESS) {
                        if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                            DBConnector.getInstances().increaseSuccessTransaction();
                        }

                        DBConnector.getInstances().setU2FLinked(agreementID, true);
                        // reset U2F ErrorCounter if <> 0
                        DBConnector.getInstances().resetErrorCounterU2F(channelName, user);

                        String u2fJsonResp = signResponse.getResponseStrData();

                        String pData = ExtFunc.genResponseMessageForU2F(responseCode,
                                responseMessage, channelName, user, billCode, u2fJsonResp);

                        ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                        processAgreementResp.setResponseCode(responseCode);
                        processAgreementResp.setXmlData(pData);
                        processAgreementResp.setSignedData(null);
                        processAgreementResp.setPreTrustedHubTransId(null);
                        return processAgreementResp;
                    } else {

                        int leftRetry = DBConnector.getInstances().getLeftU2FRetry(channelName, user);
                        if (leftRetry == -100) {
                            String pData = ExtFunc.genResponseMessage(
                                    Defines.CODE_U2F_BLOCKED,
                                    Defines.ERROR_U2F_BLOCKED, channelName, user, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(Defines.CODE_U2F_BLOCKED);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        } else {

                            String pData = ExtFunc.genResponseMessage(responseCode,
                                    responseMessage, channelName, user, leftRetry, billCode);

                            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                            processAgreementResp.setResponseCode(responseCode);
                            processAgreementResp.setXmlData(pData);
                            processAgreementResp.setSignedData(null);
                            processAgreementResp.setPreTrustedHubTransId(null);
                            return processAgreementResp;
                        }
                    }
                }
            } else if (requestType.compareTo(Defines.REQUEST_TYPE_FORCE_ACTI) == 0) {
                if (!License.getInstance().getLicenseType().equals("Unlimited")) {
                    DBConnector.getInstances().increaseSuccessTransaction();
                }

                DBConnector.getInstances().setU2FLinked(agreementID, true);
                // reset U2F ErrorCounter if <> 0
                DBConnector.getInstances().resetErrorCounterU2F(channelName, user);

                String pData = ExtFunc.genResponseMessage(
                        Defines.CODE_SUCCESS,
                        Defines.SUCCESS, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_SUCCESS);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            } else {
                String pData = ExtFunc.genResponseMessage(
                        Defines.CODE_INVALID_TYPE_REQUEST,
                        Defines.ERROR_INVALID_TYPE_REQUEST, channelName, user, billCode);

                ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
                processAgreementResp.setResponseCode(Defines.CODE_INVALID_TYPE_REQUEST);
                processAgreementResp.setXmlData(pData);
                processAgreementResp.setSignedData(null);
                processAgreementResp.setPreTrustedHubTransId(null);
                return processAgreementResp;
            }

        } else {
            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_INVALIDOTPMETHOD,
                    Defines.ERROR_INVALIDOTPMETHOD, channelName, user, billCode);

            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
            processAgreementResp.setResponseCode(Defines.CODE_INVALIDOTPMETHOD);
            processAgreementResp.setXmlData(pData);
            processAgreementResp.setSignedData(null);
            processAgreementResp.setPreTrustedHubTransId(null);
            return processAgreementResp;
        }
    }

    private static ProcessAgreementResp deActivationAgreement(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
        String workerIdOrName = Defines.WORKER_AGREEMENT;
        String functionName = Defines.WORKER_AGREEMENT;
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

        String action = ExtFunc.getContent(Defines._ACTION, xmlData);
        String metaData = ExtFunc.getContent(Defines._METADATA, xmlData);

        int agreementID = DBConnector.getInstances().authGetArrangementID(
                channelName, user);
        if (agreementID == 0) {
            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_AGREEMENTNOTEXITS,
                    Defines.ERROR_AGREEMENTNOTEXITS, channelName, user, billCode);

            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
            processAgreementResp.setResponseCode(Defines.CODE_AGREEMENTNOTEXITS);
            processAgreementResp.setXmlData(pData);
            processAgreementResp.setSignedData(null);
            processAgreementResp.setPreTrustedHubTransId(null);
            return processAgreementResp;
        }

        String method = ExtFunc.getContent(Defines._METHOD, xmlData);

        if (method.compareTo(Defines._OTPEMAIL) == 0
                || method.compareTo(Defines._OTPSMS) == 0) {
            if (method.compareTo(Defines._OTPEMAIL) == 0) {
                DBConnector.getInstances().authSetIsOTPEmailActive(agreementID, false);
            } else {
                DBConnector.getInstances().authSetIsOTPSMSActive(agreementID, false);
            }

            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_SUCCESS,
                    Defines.SUCCESS, channelName, user, billCode);

            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
            processAgreementResp.setResponseCode(Defines.CODE_SUCCESS);
            processAgreementResp.setXmlData(pData);
            processAgreementResp.setSignedData(null);
            processAgreementResp.setPreTrustedHubTransId(null);
            return processAgreementResp;

        } else if (method.compareTo(Defines._OTPHARDWARE) == 0) {

            DBConnector.getInstances().authSetIsOTPHardwareActive(agreementID, false);

            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_SUCCESS,
                    Defines.SUCCESS, channelName, user, billCode);

            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
            processAgreementResp.setResponseCode(Defines.CODE_SUCCESS);
            processAgreementResp.setXmlData(pData);
            processAgreementResp.setSignedData(null);
            processAgreementResp.setPreTrustedHubTransId(null);
            return processAgreementResp;
        } else if (method.compareTo(Defines.SIGNATURE_METHOD_TPKI) == 0) {

            DBConnector.getInstances().authSetIsTPKIActive(agreementID, false);
            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_SUCCESS,
                    Defines.SUCCESS, channelName, user, billCode);

            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
            processAgreementResp.setResponseCode(Defines.CODE_SUCCESS);
            processAgreementResp.setXmlData(pData);
            processAgreementResp.setSignedData(null);
            processAgreementResp.setPreTrustedHubTransId(null);
            return processAgreementResp;

        } else if (method.compareTo(Defines.SIGNATURE_METHOD_LPKI) == 0) {

            DBConnector.getInstances().authSetIsLPKIActive(agreementID, false);

            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_SUCCESS,
                    Defines.SUCCESS, channelName, user, billCode);

            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
            processAgreementResp.setResponseCode(Defines.CODE_SUCCESS);
            processAgreementResp.setXmlData(pData);
            processAgreementResp.setSignedData(null);
            processAgreementResp.setPreTrustedHubTransId(null);
            return processAgreementResp;

        } else if (method.compareTo(Defines.SIGNATURE_METHOD_WPKI) == 0) {

            DBConnector.getInstances().authSetIsSimPKIActive(agreementID, false);

            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_SUCCESS,
                    Defines.SUCCESS, channelName, user, billCode);

            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
            processAgreementResp.setResponseCode(Defines.CODE_SUCCESS);
            processAgreementResp.setXmlData(pData);
            processAgreementResp.setSignedData(null);
            processAgreementResp.setPreTrustedHubTransId(null);
            return processAgreementResp;
        } else if (method.compareTo(Defines.WORKER_U2FVALIDATOR) == 0) {

            DBConnector.getInstances().setU2FLinked(agreementID, false);

            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_SUCCESS,
                    Defines.SUCCESS, channelName, user, billCode);

            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
            processAgreementResp.setResponseCode(Defines.CODE_SUCCESS);
            processAgreementResp.setXmlData(pData);
            processAgreementResp.setSignedData(null);
            processAgreementResp.setPreTrustedHubTransId(null);
            return processAgreementResp;
        } else {
            String pData = ExtFunc.genResponseMessage(
                    Defines.CODE_INVALIDOTPMETHOD,
                    Defines.ERROR_INVALIDOTPMETHOD, channelName, user, billCode);

            ProcessAgreementResp processAgreementResp = new ProcessAgreementResp();
            processAgreementResp.setResponseCode(Defines.CODE_INVALIDOTPMETHOD);
            processAgreementResp.setXmlData(pData);
            processAgreementResp.setSignedData(null);
            processAgreementResp.setPreTrustedHubTransId(null);
            return processAgreementResp;
        }
    }

    private static CertificateAgreementStatus isCertificateValid(String channelName, String user, String certificate, int trustedHubTransId) {
        CertificateAgreementStatus certificateAgreementStatus = new CertificateAgreementStatus();
        try {

            if (certificate.indexOf("-----BEGIN CERTIFICATE-----") != -1) {
                certificate = certificate.replace("-----BEGIN CERTIFICATE-----", "");
            }
            if (certificate.indexOf("-----END CERTIFICATE-----") != -1) {
                certificate = certificate.replace("-----END CERTIFICATE-----", "");
            }

            ArrayList<Ca> caProviders = new ArrayList<Ca>();
            caProviders = DBConnector.getInstances().getCAProviders();

            X509Certificate cert = ExtFunc.convertToX509Cert(certificate);
            String authorityKeyIdentifier = ExtFunc.getIssuerKeyIdentifier(cert);

            String caCertificate = "";
            String ocspURL = "";
            String crlPath = "";
            String crlUrl = "";

            String caCertificate2 = "";
            String ocspURL2 = "";
            String crlPath2 = "";
            String crlUrl2 = "";

            int endpointConfigId = -1;
            int methodValidateCert = 0;
            int retryNumber = 3;
            boolean CAFound = false;

            for (Ca ca : caProviders) {
                if (ca.getSubjectKeyIdentifier1().compareToIgnoreCase(authorityKeyIdentifier) == 0
                        || ca.getSubjectKeyIdentifier2().compareToIgnoreCase(authorityKeyIdentifier) == 0) {
                    ocspURL = ca.getOcspUrl();
                    caCertificate = ca.getCert();
                    crlPath = ca.getCrlPath();
                    crlUrl = ca.getCrlUrl();

                    caCertificate2 = ca.getCert2();
                    ocspURL2 = ca.getOcspUrl2();
                    crlPath2 = ca.getCrlPath2();
                    crlUrl2 = ca.getCrlUrl2();

                    endpointConfigId = ca.getEndPointConfigID();
                    retryNumber = ca.getOcspRetry();
                    methodValidateCert = ca.getMethodValidateCert();
                    CAFound = true;
                    break;
                }
            }

            if (!CAFound) {
                LOG.error("CA " + cert.getIssuerDN().toString() + " not found.");
                certificateAgreementStatus.setValid(false);
                return certificateAgreementStatus;
            }

            // Check date validity
            if (!checkDataValidity(cert)) {
                certificateAgreementStatus.setValid(false);
                return certificateAgreementStatus;
            }

            switch (methodValidateCert) {
                case 0: // no check
                    LOG.info("No checking certificate status");
                    certificateAgreementStatus.setValid(true);
                    return certificateAgreementStatus;
                case 1: // CRL
                    LOG.info("CRL certificate status checking");
                    if (crlPath.compareTo("") != 0 && caCertificate.compareTo("") != 0) {

                        X509Certificate caX509 = ExtFunc.convertToX509Cert(caCertificate);

                        X509Certificate subX509 = cert;

                        boolean primaryCaX509 = true;

                        if (!ExtFunc.checkCertificateRelation(caX509, subX509)) {
                            if (caCertificate2 == null || caCertificate2.compareTo("") != 0) {
                                caX509 = ExtFunc.convertToX509Cert(caCertificate2);
                                crlPath = crlPath2;
                                ocspURL = ocspURL2;
                                crlUrl = crlUrl2;
                                primaryCaX509 = false;

                                if (!ExtFunc.checkCertificateRelation(caX509, subX509)) {
                                    certificateAgreementStatus.setValid(false);
                                    return certificateAgreementStatus;
                                }
                            } else {
                                certificateAgreementStatus.setValid(false);
                                return certificateAgreementStatus;
                            }
                        }

                        CRLStatus CRLVarification = CRLChecking.getInstance().check(caX509, subX509, crlPath, crlUrl, primaryCaX509, false, endpointConfigId);

                        if (!CRLVarification.getIsRevoked()) {
                            certificateAgreementStatus.setValid(true);
                            return certificateAgreementStatus;
                        } else {
                            certificateAgreementStatus.setValid(false);
                            return certificateAgreementStatus;
                        }
                    } else {
                        certificateAgreementStatus.setValid(false);
                        return certificateAgreementStatus;
                    }
                case 2: // OCSP
                    LOG.info("OCSP certificate status checking");
                    if (ocspURL.compareTo("") != 0 && caCertificate.compareTo("") != 0) {

                        X509Certificate caX509 = ExtFunc.convertToX509Cert(caCertificate);

                        X509Certificate subX509 = cert;

                        if (!ExtFunc.checkCertificateRelation(caX509, subX509)) {
                            if (caCertificate2 == null || caCertificate2.compareTo("") != 0) {
                                caX509 = ExtFunc.convertToX509Cert(caCertificate2);

                                crlPath = crlPath2;
                                ocspURL = ocspURL2;
                                crlUrl = crlUrl2;

                                if (!ExtFunc.checkCertificateRelation(caX509, subX509)) {
                                    certificateAgreementStatus.setValid(false);
                                    return certificateAgreementStatus;
                                }
                            } else {
                                certificateAgreementStatus.setValid(false);
                                return certificateAgreementStatus;
                            }
                        }

                        boolean ocspStatus = false;
                        OcspStatus ocsp_status = OCSPChecking.getInstance().check(channelName, user, ocspURL, subX509, caX509, retryNumber, endpointConfigId, trustedHubTransId);
                        ocspStatus = ocsp_status.getIsValid();

                        if (ocspStatus) {
                            certificateAgreementStatus.setValid(true);
                            return certificateAgreementStatus;
                        } else {
                            certificateAgreementStatus.setValid(false);
                            return certificateAgreementStatus;
                        }
                    } else {
                        certificateAgreementStatus.setValid(false);
                        return certificateAgreementStatus;
                    }
                default:
                    LOG.info("Signature validation and Certificate validation by OCSP (CRL if OCSP failure)");
                    if (crlPath.compareTo("") != 0 && ocspURL.compareTo("") != 0 && caCertificate.compareTo("") != 0) {

                        X509Certificate caX509 = ExtFunc.convertToX509Cert(caCertificate);

                        X509Certificate subX509 = cert;

                        boolean primaryCaX509 = true;

                        if (!ExtFunc.checkCertificateRelation(caX509, subX509)) {
                            if (caCertificate2 == null || caCertificate2.compareTo("") != 0) {
                                caX509 = ExtFunc.convertToX509Cert(caCertificate2);

                                crlPath = crlPath2;
                                ocspURL = ocspURL2;
                                crlUrl = crlUrl2;

                                if (!ExtFunc.checkCertificateRelation(caX509, subX509)) {
                                    certificateAgreementStatus.setValid(false);
                                    return certificateAgreementStatus;
                                }
                            } else {
                                certificateAgreementStatus.setValid(false);
                                return certificateAgreementStatus;
                            }
                        }

                        boolean ocspStatus = false;
                        boolean crlStatus = false;


                        OcspStatus ocsp_status = OCSPChecking.getInstance().check(channelName, user, ocspURL, subX509, caX509, retryNumber, endpointConfigId, trustedHubTransId);

                        if (ocsp_status.getCertificateState().equals(OcspStatus.ERROR)) {

                            CRLStatus CRLVarification = CRLChecking.getInstance().check(caX509, subX509, crlPath, crlUrl, primaryCaX509, false, endpointConfigId);

                            crlStatus = !CRLVarification.getIsRevoked();
                            if (crlStatus) {
                                certificateAgreementStatus.setValid(true);
                                return certificateAgreementStatus;
                            } else {
                                certificateAgreementStatus.setValid(false);
                                return certificateAgreementStatus;
                            }
                        } else {
                            ocspStatus = ocsp_status.getIsValid();
                            if (ocspStatus) {
                                certificateAgreementStatus.setValid(true);
                                return certificateAgreementStatus;
                            } else {
                                certificateAgreementStatus.setValid(false);
                                return certificateAgreementStatus;
                            }
                        }
                    }
            }
        } catch (Exception e) {
            LOG.error("Something wrong: " + e.getMessage());
            e.printStackTrace();
        }
        certificateAgreementStatus.setValid(false);
        return certificateAgreementStatus;
    }

    private static boolean checkDataValidity(X509Certificate x509) {
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

    private static int getWorkerId(String workerIdOrName) {
        final int retval;

        if (workerIdOrName.substring(0, 1).matches("\\d")) {
            retval = Integer.parseInt(workerIdOrName);
        } else {
            retval = getWorkerSession().getWorkerId(workerIdOrName);
        }
        return retval;
    }

    private static IWorkerSession.ILocal getWorkerSession() {
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

    private static RequestContext handleRequestContext(
            final List<Metadata> requestMetadata, final int workerId) {
        final HttpServletRequest servletRequest = (HttpServletRequest) wsContext.getMessageContext().get(MessageContext.SERVLET_REQUEST);
        String requestIP = ExtFunc.getRequestIP(wsContext);
        X509Certificate clientCertificate = getClientCertificate();
        final RequestContext requestContext = new RequestContext(
                clientCertificate, requestIP);

        IClientCredential credential;

        if (clientCertificate instanceof X509Certificate) {
            final X509Certificate cert = (X509Certificate) clientCertificate;
            //LOG.info("Authentication: certificate");
            credential = new CertificateClientCredential(cert.getSerialNumber().toString(16), cert.getIssuerDN().getName());
        } else {
            // Check is client supplied basic-credentials
            final String authorization = servletRequest.getHeader(HTTP_AUTH_BASIC_AUTHORIZATION);
            if (authorization != null) {
                //LOG.info("Authentication: password");

                final String decoded[] = new String(Base64.decode(authorization.split("\\s")[1])).split(":", 2);

                credential = new UsernamePasswordClientCredential(decoded[0],
                        decoded[1]);
            } else {
                //LOG.info("Authentication: none");
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

    private static String getIssuerName(String DN) {
        String issuer = DN;
        String issuerName = "";
        String[] pairs = issuer.split(",");
        for (String pair : pairs) {
            String[] paramvalue = pair.split("=");
            if (paramvalue[0].compareTo("CN") == 0
                    || paramvalue[0].compareTo(" CN") == 0) {
                issuerName = paramvalue[1];
                break;
            }
        }

        return issuerName;
    }

    private static X509Certificate getClientCertificate() {
        MessageContext msgContext = wsContext.getMessageContext();
        HttpServletRequest request = (HttpServletRequest) msgContext.get(MessageContext.SERVLET_REQUEST);
        X509Certificate[] certificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");

        if (certificates != null) {
            return certificates[0];
        }
        return null;
    }

    private static class CertificateAgreementStatus {

        private boolean isValid;

        public boolean isValid() {
            return isValid;
        }

        public void setValid(boolean isValid) {
            this.isValid = isValid;
        }
    }

    private static List<Metadata> getMetaData(String metaData) {
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