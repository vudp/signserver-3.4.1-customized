package org.signserver.common.util;

import java.io.*;
import java.security.cert.*;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;

import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;

import org.signserver.common.*;
import org.signserver.common.dbdao.*;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.nio.ByteBuffer;
import java.text.ParseException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.util.Store;
import org.apache.log4j.Logger;

import java.util.Collection;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.ejbca.util.CertTools;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mozilla.universalchardet.UniversalDetector;

import trustedhub.params.*;

public class ExtFunc {

    private static SecureRandom random = new SecureRandom();
    private static final Logger LOG = Logger.getLogger(ExtFunc.class);
    public static String SCRIPT_PATH_RSYNC = System.getProperty("jboss.server.home.dir") + "/" + "../../../../../file/rsync.sh";
    public static String SCRIPT_PATH_RESTARTWS = System.getProperty("jboss.server.home.dir") + "/" + "../../../../../file/restartws.sh";
    public static String C_MIMETYPE_XML = "application/xml";
    public static String C_MIMETYPE_OOXML = "application/x-zip-compressed";
    public static String C_MIMETYPE_OPENXML = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    public static String C_MIMETYPE_MSWORD = "application/msword";
    public static String C_MIMETYPE_PDF = "application/pdf";
    public static String C_MIMETYPE_TXT = "text/xml";
    public static String C_FILETYPE_XML = "xml";
    public static String C_FILETYPE_OFFICE = "doc";
    public static String C_FILETYPE_OFFICEX = "docx";
    public static String C_FILETYPE_EXCEL = "xls";
    public static String C_FILETYPE_EXCELX = "xlsx";
    public static String C_FILETYPE_POWERPOINT = "ppt";
    public static String C_FILETYPE_POWERPOINTX = "pptx";
    public static String C_FILETYPE_PDF = "pdf";
    public static String OS_VERSION_EL6 = "el6";
    public static String OS_VERSION_EL7 = "el7";
    public static String OS_VERSION_UNKNOWN = "Unknown";

    public static String getContent(String tag, String xmlData) {
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
            LOG.error(e.toString()+" - xmlData: "+xmlData);
            e.printStackTrace();
        }
        return "";
    }

    public static String replaceContentInXmlTag(String xmlData, String tagName, String content) {
        String c = getContent(tagName, xmlData);
        if (!c.equals("")) {
            xmlData = xmlData.replace(c, content);
        }
        return xmlData;
    }

    public static String genResponseMessage(int responseCode,
            String responseMessage, String billCode) {
        String data = "<ResponseCode>" + responseCode + "</ResponseCode>"
                + "<ResponseMessage>" + responseMessage + "</ResponseMessage>"
                + "<BillCode>" + billCode + "</BillCode>";
        return data;
    }

    public static String genFileDetailsResponseMessage(int responseCode,
            String responseMessage, String channel, String user,
            String billCode, String cert, List<FileDetail> fileDetails) {
        String data = "<Channel>" + channel + "</Channel>" + "<User>" + user
                + "</User>" + "<ResponseCode>" + responseCode
                + "</ResponseCode>" + "<ResponseMessage>" + responseMessage
                + "</ResponseMessage>";

        if (billCode != null) {
            data += "<BillCode>" + billCode + "</BillCode>";
        }

        if (cert != null) {
            data += "<SigningCertificate>" + cert + "</SigningCertificate>";
        }

        data += "<FileDetails>";
        for (int i = 0; i < fileDetails.size(); i++) {
            data += "<FileDetail>";
            data += "<OldFileId>" + fileDetails.get(i).getOldFileId() + "</OldFileId>";
            if (fileDetails.get(i).getNewFileId() != null) {
                data += "<NewFileId>" + fileDetails.get(i).getNewFileId() + "</NewFileId>";
            }
            if (fileDetails.get(i).getMimeType() != null) {
                data += "<MimeType>" + fileDetails.get(i).getMimeType() + "</MimeType>";
            }
            if (fileDetails.get(i).getDigest() != null) {
                data += "<Digest>" + fileDetails.get(i).getDigest() + "</Digest>";
            }
            data += "<Status>" + fileDetails.get(i).getStatus() + "</Status>";
            data += "<Message>" + fileDetails.get(i).getMessage() + "</Message>";
            data += "</FileDetail>";
        }
        data += "</FileDetails>";
        return data;
    }

    public static String genFileDetailsResponseMessage(String cert, List<FileDetail> fileDetails) {
        String data = "";

        if (cert != null) {
            data += "<SigningCertificate>" + cert + "</SigningCertificate>";
        }

        data += "<FileDetails>";
        for (int i = 0; i < fileDetails.size(); i++) {
            data += "<FileDetail>";
            data += "<OldFileId>" + fileDetails.get(i).getOldFileId() + "</OldFileId>";
            if (fileDetails.get(i).getNewFileId() != null) {
                data += "<NewFileId>" + fileDetails.get(i).getNewFileId() + "</NewFileId>";
            }
            if (fileDetails.get(i).getMimeType() != null) {
                data += "<MimeType>" + fileDetails.get(i).getMimeType() + "</MimeType>";
            }
            if (fileDetails.get(i).getDigest() != null) {
                data += "<Digest>" + fileDetails.get(i).getDigest() + "</Digest>";
            }
            data += "<Status>" + fileDetails.get(i).getStatus() + "</Status>";
            data += "<Message>" + fileDetails.get(i).getMessage() + "</Message>";
            data += "</FileDetail>";
        }
        data += "</FileDetails>";
        return data;
    }

    public static String genFileDetailsResponseMessage(int responseCode,
            String responseMessage, String channel, String user,
            String billCode, String externalStorageResponseStatus) {
        String data = "<Channel>" + channel + "</Channel>" + "<User>" + user
                + "</User>" + "<ResponseCode>" + responseCode
                + "</ResponseCode>" + "<ResponseMessage>" + responseMessage
                + "</ResponseMessage>";

        if (billCode != null) {
            data += "<BillCode>" + billCode + "</BillCode>";
        }

        if (externalStorageResponseStatus != null) {
            data += externalStorageResponseStatus;
        }
        return data;
    }

    public static String genFileDetailsResponseMessage(int responseCode,
            String responseMessage, String channel, String user,
            String billCode, String externalStorageResponseStatus, String status) {
        String data = "<Channel>" + channel + "</Channel>" + "<User>" + user
                + "</User>" + "<ResponseCode>" + responseCode
                + "</ResponseCode>" + "<ResponseMessage>" + responseMessage
                + "</ResponseMessage>";

        if (billCode != null) {
            data += "<BillCode>" + billCode + "</BillCode>";
        }

        if (externalStorageResponseStatus != null) {
            data += externalStorageResponseStatus;
        }

        if (status != null) {
            data += "<ErrorDetail>" + status + "</ErrorDetail>";
        }
        return data;
    }

    public static String genFileDetailsValidatorResponseMessage(int responseCode,
            String responseMessage, String channel, String user,
            String billCode, List<FileDetail> fileDetails) {

        String data = "<Channel>" + channel + "</Channel>" + "<User>" + user
                + "</User>" + "<ResponseCode>" + responseCode
                + "</ResponseCode>" + "<ResponseMessage>" + responseMessage
                + "</ResponseMessage>";

        if (billCode != null) {
            data += "<BillCode>" + billCode + "</BillCode>";
        }

        data += "<FileDetails>";
        for (int i = 0; i < fileDetails.size(); i++) {
            data += "<FileDetail>";
            data += "<FileId>" + fileDetails.get(i).getFileId() + "</FileId>";
            data += "<MimeType>" + fileDetails.get(i).getMimeType() + "</MimeType>";
            data += "<Status>" + fileDetails.get(i).getStatus() + "</Status>";
            data += "<Message>" + fileDetails.get(i).getMessage() + "</Message>";
            List<SignerInfoResponse> signerInfoResponse = fileDetails.get(i).getSignerInfoResponse();
            if (signerInfoResponse != null) {
                SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
                data += "<SignerInfos>";
                for (int j = 0; j < signerInfoResponse.size(); j++) {
                    data += "<SignerInfo>";
                    data += "<SerialNumber>"
                            + signerInfoResponse.get(j).getSerilaNumber()
                            + "</SerialNumber>";
                    data += "<SubjectName>" + signerInfoResponse.get(j).getSubjectName()
                            + "</SubjectName>";
                    data += "<IssuerName>" + signerInfoResponse.get(j).getIssuerName()
                            + "</IssuerName>";
                    data += "<DateValid>"
                            + dateFormat.format(signerInfoResponse.get(j).getNotBefore())
                            + "</DateValid>";
                    data += "<DateExpired>"
                            + dateFormat.format(signerInfoResponse.get(j).getNotAfter())
                            + "</DateExpired>";

                    if (signerInfoResponse.get(j).getSigningTime() != null) {
                        data += "<SigningTime>"
                                + dateFormat.format(signerInfoResponse.get(j).getSigningTime())
                                + "</SigningTime>";
                    }

                    data += "<Certificate>"
                            + signerInfoResponse.get(j).getCertificate()
                            + "</Certificate>";
                    data += "</SignerInfo>";
                }
                data += "</SignerInfos>";
            }
            data += "</FileDetail>";
        }
        data += "</FileDetails>";
        return data;
    }

    public static String genResponseMessage(int responseCode,
            String responseMessage, String channel, String user,
            String agreementStatus, String billCode) {
        String data = "<Channel>" + channel + "</Channel>";
        if (!isNullOrEmpty(user)) {
            data += "<User>" + user + "</User>";
        }
        data += "<ResponseCode>" + responseCode
                + "</ResponseCode>" + "<ResponseMessage>" + responseMessage
                + "</ResponseMessage>" + "<BillCode>" + billCode
                + "</BillCode>" + "<AgreementStatus>" + agreementStatus
                + "</AgreementStatus>";
        return data;
    }

    public static String genResponseMessageWithSPKI(int responseCode,
            String responseMessage, String channel, String user,
            String agreementStatus, String csr, String billCode) {
        String data = "<Channel>" + channel + "</Channel>";
        if (!isNullOrEmpty(user)) {
            data += "<User>" + user + "</User>";
        }
        data += "<ResponseCode>" + responseCode
                + "</ResponseCode>" + "<ResponseMessage>" + responseMessage
                + "</ResponseMessage>" + "<BillCode>" + billCode
                + "</BillCode>" + "<AgreementStatus>" + agreementStatus
                + "</AgreementStatus>";
        if (csr != null) {
            data += "<SPKICSR>" + csr + "</SPKICSR>";
        }
        return data;
    }

    public static String genResponseMessage(int responseCode,
            String responseMessage, String channel, String user, int otpRestry,
            String billCode) {
        String data = "<Channel>" + channel + "</Channel>";
        if (!isNullOrEmpty(user)) {
            data += "<User>" + user + "</User>";
        }
        data += "<ResponseCode>" + responseCode
                + "</ResponseCode>" + "<ResponseMessage>" + responseMessage
                + "</ResponseMessage>" + "<LeftRetry>" + otpRestry
                + "</LeftRetry>" + "<BillCode>" + billCode + "</BillCode>";
        return data;
    }

    public static String genResponseOATHMessage(int responseCode,
            String responseMessage, String channel, String user, String billCode) {
        String data = "<Channel>" + channel + "</Channel>";
        if (!isNullOrEmpty(user)) {
            data += "<User>" + user + "</User>";
        }
        data += "<ResponseCode>" + responseCode
                + "</ResponseCode>" + "<ResponseMessage>" + responseMessage
                + "</ResponseMessage>" + "<BillCode>" + billCode
                + "</BillCode>";
        return data;
    }

    public static String genResponseMessageDc(int responseCode,
            String responseMessage, String channel, String user, String requestId, String billCode) {
        String data = "<Channel>" + channel + "</Channel>";
        if (!isNullOrEmpty(user)) {
            data += "<User>" + user + "</User>";
        }
        data += "<ResponseCode>" + responseCode
                + "</ResponseCode>" + "<ResponseMessage>" + responseMessage
                + "</ResponseMessage>"
                + "<TransactionCode>" + requestId + "</TransactionCode>"
                + "<BillCode>" + billCode + "</BillCode>";
        return data;
    }

    public static String genResponseMessageDc(int responseCode,
            String responseMessage, String channel, String user, byte[] dtbs, String billCode) {
        String data = "<Channel>" + channel + "</Channel>";
        if (!isNullOrEmpty(user)) {
            data += "<User>" + user + "</User>";
        }
        data += "<ResponseCode>" + responseCode
                + "</ResponseCode>" + "<ResponseMessage>" + responseMessage
                + "</ResponseMessage>"
                + "<BillCode>" + billCode + "</BillCode>"
                + "<DataToBeSigned>" + DatatypeConverter.printHexBinary(dtbs) + "</DataToBeSigned>";
        return data;
    }

    public static String genResponseOATHMessage(int responseCode,
            String responseMessage, String channel, String user,
            String billCode, int otpRestry) {
        String data = "<Channel>" + channel + "</Channel>";
        if (!isNullOrEmpty(user)) {
            data += "<User>" + user + "</User>";
        }
        data += "<ResponseCode>" + responseCode
                + "</ResponseCode>" + "<ResponseMessage>" + responseMessage
                + "</ResponseMessage>" + "<BillCode>" + billCode
                + "</BillCode>" + "<LeftRetry>" + otpRestry + "</LeftRetry>";
        return data;
    }

    public static String genResponseMessage(int responseCode,
            String responseMessage, String channel, String user, String billCode) {
        String data = "<Channel>" + channel + "</Channel>";
        if (!isNullOrEmpty(user)) {
            data += "<User>" + user + "</User>";
        }
        data += "<ResponseCode>" + responseCode
                + "</ResponseCode>" + "<ResponseMessage>" + responseMessage
                + "</ResponseMessage>" + "<BillCode>" + billCode
                + "</BillCode>";
        return data;
    }

    public static String genResponseMessageForU2F(int responseCode,
            String responseMessage, String channel, String user, String billCode, String u2fResp) {
        String data = "<Channel>" + channel + "</Channel>";
        if (!isNullOrEmpty(user)) {
            data += "<User>" + user + "</User>";
        }
        data += "<ResponseCode>" + responseCode
                + "</ResponseCode>" + "<ResponseMessage>" + responseMessage
                + "</ResponseMessage>" + "<BillCode>" + billCode
                + "</BillCode>"
                + "<U2FResponse>" + u2fResp + "</U2FResponse>";
        return data;
    }

    public static String genResponseMessageWithSPKIChange(int responseCode,
            String responseMessage, String csr, String channel, String user, String billCode) {
        String data = "<Channel>" + channel + "</Channel>";
        if (!isNullOrEmpty(user)) {
            data += "<User>" + user + "</User>";
        }
        data += "<ResponseCode>" + responseCode
                + "</ResponseCode>" + "<ResponseMessage>" + responseMessage
                + "</ResponseMessage>" + "<BillCode>" + billCode
                + "</BillCode>";
        if (csr != null) {
            data += "<SPKICSR>" + csr + "</SPKICSR>";
        }
        return data;
    }

    public static String genResponseMessage(int responseCode,
            String responseMessage, String channel, String user,
            String fileType, String cert, String billCode) {
        String data = "<Channel>" + channel + "</Channel>";
        if (!isNullOrEmpty(user)) {
            data += "<User>" + user + "</User>";
        }
        data += "<ResponseCode>" + responseCode
                + "</ResponseCode>" + "<ResponseMessage>" + responseMessage
                + "</ResponseMessage>" + "<BillCode>" + billCode
                + "</BillCode>";
        if (fileType != null && !fileType.equals("")) {
            data += "<FileType>" + fileType.toLowerCase() + "</FileType>";
        }
        if (cert != null) {
            data += "<SigningCertificate>" + cert + "</SigningCertificate>";
        }
        return data;
    }

    public static String genResponseMessageForSignerAPAuth(int responseCode,
            String responseMessage, String channel, String user,
            String signingCert, String authCert, String billCode) {
        String data = "<Channel>" + channel + "</Channel>";
        if (!isNullOrEmpty(user)) {
            data += "<User>" + user + "</User>";
        }
        data += "<ResponseCode>" + responseCode
                + "</ResponseCode>" + "<ResponseMessage>" + responseMessage
                + "</ResponseMessage>" + "<BillCode>" + billCode
                + "</BillCode>";

        if (signingCert != null) {
            String[] sCert = getCertificateComponents(signingCert);
            data += "<SigningCertificate>";
            data += "<Certificate>" + signingCert + "</Certificate>";
            data += "<SerialNumber>" + sCert[0] + "</SerialNumber>";
            data += "<SubjectName>" + sCert[1] + "</SubjectName>";
            data += "<IssuerName>" + sCert[2] + "</IssuerName>";
            data += "<DateValid>" + sCert[3] + "</DateValid>";
            data += "<DateExpired>" + sCert[4] + "</DateExpired>";
            data += "<ThumbPrint>" + sCert[5] + "</ThumbPrint>";
            data += "</SigningCertificate>";
        }

        if (authCert != null) {
            String[] auCert = getCertificateComponents(authCert);
            data += "<AuthenticationCertificate>";
            data += "<Certificate>" + authCert + "</Certificate>";
            data += "<SerialNumber>" + auCert[0] + "</SerialNumber>";
            data += "<SubjectName>" + auCert[1] + "</SubjectName>";
            data += "<IssuerName>" + auCert[2] + "</IssuerName>";
            data += "<DateValid>" + auCert[3] + "</DateValid>";
            data += "<DateExpired>" + auCert[4] + "</DateExpired>";
            data += "<ThumbPrint>" + auCert[5] + "</ThumbPrint>";
            data += "</AuthenticationCertificate>";
        }


        return data;
    }

    public static String genResponseMessage(
            int responseCode,
            String responseMessage,
            String channel,
            String user,
            String fileType,
            String fileId,
            String cert,
            String billCode) {
        String data = "<Channel>" + channel + "</Channel>";
        if (!isNullOrEmpty(user)) {
            data += "<User>" + user + "</User>";
        }
        data += "<ResponseCode>" + responseCode
                + "</ResponseCode>" + "<ResponseMessage>" + responseMessage
                + "</ResponseMessage>" + "<BillCode>" + billCode
                + "</BillCode>";
        if (fileType != null && !fileType.equals("")) {
            data += "<FileType>" + fileType.toLowerCase() + "</FileType>";
        }
        if (fileId != null) {
            data += "<FileId>" + fileId + "</FileId>";
        }
        if (cert != null) {
            data += "<SigningCertificate>" + cert + "</SigningCertificate>";
        }
        return data;
    }

    public static String genResponseMessageForFileProcessor(
            int responseCode,
            String responseMessage,
            String channel,
            String user,
            String fileName,
            String mimeType,
            String fileId,
            String billCode) {
        String data = "<Channel>" + channel + "</Channel>";
        if (!isNullOrEmpty(user)) {
            data += "<User>" + user + "</User>";
        }
        data += "<ResponseCode>" + responseCode
                + "</ResponseCode>" + "<ResponseMessage>" + responseMessage
                + "</ResponseMessage>" + "<BillCode>" + billCode
                + "</BillCode>";

        if (fileId != null) {
            data += "<FileId>" + fileId + "</FileId>";
        }
        if (fileName != null) {
            data += "<FileName>" + fileName + "</FileName>";
        }
        if (mimeType != null) {
            data += "<MimeType>" + mimeType + "</MimeType>";
        }

        return data;
    }

    public static String genResponseMessage(int responseCode,
            String responseMessage, String channel, String user,
            List<SignerInfoResponse> signerInfo, String billCode) {
        String data = "<Channel>" + channel + "</Channel>";
        if (!isNullOrEmpty(user)) {
            data += "<User>" + user + "</User>";
        }
        data += "<ResponseCode>" + responseCode
                + "</ResponseCode>" + "<ResponseMessage>" + responseMessage
                + "</ResponseMessage>" + "<BillCode>" + billCode
                + "</BillCode>";

        SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
        if (signerInfo != null) {
            String tmp = "<SignerInfos>";
            for (int i = 0; i < signerInfo.size(); i++) {
                tmp += "<SignerInfo>";
                tmp += "<SerialNumber>"
                        + signerInfo.get(i).getSerilaNumber()
                        + "</SerialNumber>";
                tmp += "<SubjectName>" + signerInfo.get(i).getSubjectName()
                        + "</SubjectName>";
                tmp += "<IssuerName>" + signerInfo.get(i).getIssuerName()
                        + "</IssuerName>";
                tmp += "<DateValid>"
                        + dateFormat.format(signerInfo.get(i).getNotBefore())
                        + "</DateValid>";
                tmp += "<DateExpired>"
                        + dateFormat.format(signerInfo.get(i).getNotAfter())
                        + "</DateExpired>";

                if (signerInfo.get(i).getSigningTime() != null) {
                    tmp += "<SigningTime>"
                            + dateFormat.format(signerInfo.get(i).getSigningTime())
                            + "</SigningTime>";
                }

                tmp += "<Certificate>"
                        + signerInfo.get(i).getCertificate()
                        + "</Certificate>";

                if (signerInfo.get(i).getOwnerInfos() != null) {
                    tmp += "<SystemUsers>";
                    List<OwnerInfo> ownerInfos = signerInfo.get(i).getOwnerInfos();
                    for (OwnerInfo ownerInfo : ownerInfos) {
                        tmp += "<SystemUser>";
                        tmp += "<User>" + ownerInfo.getCif() + "</User>";
                        tmp += "<Channel>" + ownerInfo.getChannelName() + "</Channel>";
                        tmp += "<SignatureMethod>" + ownerInfo.getAgreementType() + "</SignatureMethod>";
                        tmp += "</SystemUser>";
                    }
                    tmp += "</SystemUsers>";
                }
                tmp += "</SignerInfo>";
            }
            tmp += "</SignerInfos>";
            data += tmp;
        }
        return data;
    }

    public static String genResponseMessage(int responseCode,
            String responseMessage, 
            String channel,
            List<AgreementObject> agreements, 
            String billCode,
            String limitSigningCounter,
            String signingCounter,
            String remainingSigningCounter) {
        String data = "";
        if (agreements.size() == 0) {
            data = "<Channel>" + channel + "</Channel>" + "<ResponseCode>"
                    + responseCode + "</ResponseCode>" + "<ResponseMessage>"
                    + responseMessage + "</ResponseMessage>" + "<BillCode>"
                    + billCode + "</BillCode>"
                    + "<NumOfAgreementFound>0</NumOfAgreementFound>";
        } else {
            data = "<Channel>" + channel + "</Channel>" + "<ResponseCode>"
                    + responseCode + "</ResponseCode>" + "<ResponseMessage>"
                    + responseMessage + "</ResponseMessage>" + "<BillCode>"
                    + billCode + "</BillCode>" + "<NumOfAgreementFound>"
                    + agreements.size() + "</NumOfAgreementFound>"
                    + "<SigningCounterLimit>"
                    + limitSigningCounter + "</SigningCounterLimit>"
                    + "<SigningCounter>"
                    + signingCounter + "</SigningCounter>"
                    + "<SigningCounterLeft>"
                    + remainingSigningCounter + "</SigningCounterLeft>"
                    + "<Agreements>";
            for (int i = 0; i < agreements.size(); i++) {
                data += "<Agreement>";
                data += "<User>" + agreements.get(i).getUser() + "</User>";
                data += "<Remark>" + agreements.get(i).getRemark() + "</Remark>";
                data += "<Channel>" + agreements.get(i).getChannel() + "</Channel>";
                data += "<AgreementStatus>" + agreements.get(i).getAgreementStatus() + "</AgreementStatus>";

                if (agreements.get(i).isIsOtpSms()) {
                    data += "<IsOTPSMS>True</IsOTPSMS>";
                    data += "<OTPSMS>" + agreements.get(i).getOtpSms() + "</OTPSMS>";
                    data += "<IsOTPSMSLinked>" + (agreements.get(i).isIsOtpSmsLinked() == true ? "True" : "False") + "</IsOTPSMSLinked>";
                } else {
                    data += "<IsOTPSMS>False</IsOTPSMS>";
                }

                if (agreements.get(i).isIsOtpEmail()) {
                    data += "<IsOTPEmail>True</IsOTPEmail>";
                    data += "<OTPEmail>" + agreements.get(i).getOtpEmail() + "</OTPEmail>";
                    data += "<IsOTPEmailLinked>" + (agreements.get(i).isIsOtpEmailLinked() == true ? "True" : "False") + "</IsOTPEmailLinked>";
                } else {
                    data += "<IsOTPEmail>False</IsOTPEmail>";
                }

                if (agreements.get(i).isIsOtpHardware()) {
                    data += "<IsOTPHardware>True</IsOTPHardware>";
                    data += "<OTPHardware>" + agreements.get(i).getOtpHardware() + "</OTPHardware>";
                    data += "<IsOTPHardwareLinked>" + (agreements.get(i).isIsOtpHardwareLinked() == true ? "True" : "False") + "</IsOTPHardwareLinked>";
                } else {
                    data += "<IsOTPHardware>False</IsOTPHardware>";
                }

                if (agreements.get(i).isIsOtpSoftware()) {
                    data += "<IsOTPSoftware>True</IsOTPSoftware>";
                    data += "<IsOTPSoftwareLinked>" + (agreements.get(i).isIsOtpSoftwareLinked() == true ? "True" : "False") + "</IsOTPSoftwareLinked>";
                } else {
                    data += "<IsOTPSoftware>False</IsOTPSoftware>";
                }

                if (agreements.get(i).isIsPki()) {
                    data += "<IsTPKI>True</IsTPKI>";
                    data += "<TCertificate>" + agreements.get(i).getCertificate() + "</TCertificate>";
                    data += "<TPKIThumbPrint>" + agreements.get(i).getTpkiThumbPrint() + "</TPKIThumbPrint>";
                    data += "<TPKILinked>" + (agreements.get(i).isIsTPKILinked() == true ? "True" : "False") + "</TPKILinked>";
                } else {
                    data += "<IsTPKI>False</IsTPKI>";
                }

                if (agreements.get(i).isIsLcdPki()) {
                    data += "<IsLPKI>True</IsLPKI>";
                    data += "<LCertificate>" + agreements.get(i).getLcdCertificate() + "</LCertificate>";
                    data += "<LPKIThumbPrint>" + agreements.get(i).getLpkiThumbPrint() + "</LPKIThumbPrint>";
                    data += "<LPKILinked>" + (agreements.get(i).isIsLPKILinked() == true ? "True" : "False") + "</LPKILinked>";
                } else {
                    data += "<IsLPKI>False</IsLPKI>";
                }

                if (agreements.get(i).isIsSimPKI()) {
                    data += "<IsWPKI>True</IsWPKI>";
                    data += "<PKISim>" + agreements.get(i).getPkiSim() + "</PKISim>";
                    data += "<WCertificate>" + agreements.get(i).getSimCertificate() + "</WCertificate>";
                    data += "<WPKIThumbPrint>" + agreements.get(i).getWpkiThumbPrint() + "</WPKIThumbPrint>";
                    data += "<WPKILinked>" + (agreements.get(i).isIsWPKILinked() == true ? "True" : "False") + "</WPKILinked>";
                } else {
                    data += "<IsWPKI>False</IsWPKI>";
                }


                if (agreements.get(i).isIsSignserver()) {
                    data += "<IsSPKI>True</IsSPKI>";
                    if (agreements.get(i).isIsSPKILinked()) {
                        data += "<IsSPKILinked>True</IsSPKILinked>";
                    } else {
                        data += "<IsSPKILinked>False</IsSPKILinked>";
                    }
                    data += "<SCertificate>" + agreements.get(i).getsCertificate() + "</SCertificate>";
                    data += "<SPKIThumbPrint>" + agreements.get(i).getSpkiThumbPrint() + "</SPKIThumbPrint>";
                } else {
                    data += "<IsSPKI>False</IsSPKI>";
                }

                SimpleDateFormat sf = new SimpleDateFormat("dd/MM/yyyy");

                data += "<CreatedDate>"
                        + sf.format(agreements.get(i).getCreatedDate())
                        + "</CreatedDate>";
                data += "<EffectiveDate>"
                        + sf.format(agreements.get(i).getEffectiveDate())
                        + "</EffectiveDate>";
                data += "<ExpiredDate>"
                        + sf.format(agreements.get(i).getExpiredDate())
                        + "</ExpiredDate>";
                data += "</Agreement>";
            }
            data += "</Agreements>";
        }
        return data;
    }

    public static String genResponseMessage(int responseCode,
            String responseMessage, String channel,
            AgreementObject agreements, String billCode) {
        String data = "<Channel>" + channel + "</Channel>" + "<ResponseCode>"
                + responseCode + "</ResponseCode>" + "<ResponseMessage>"
                + responseMessage + "</ResponseMessage>" + "<BillCode>"
                + billCode + "</BillCode>";
        data += "<Agreement>";
        data += "<User>" + agreements.getUser() + "</User>";
        data += "<Channel>" + agreements.getChannel() + "</Channel>";
        data += "<AgreementStatus>" + agreements.getAgreementStatus() + "</AgreementStatus>";
        data += "<IsTPKI>True</IsTPKI>";
        data += "<TCertificate>" + agreements.getCertificate() + "</TCertificate>";
        data += "<TPKIThumbPrint>" + agreements.getTpkiThumbPrint() + "</TPKIThumbPrint>";
        data += "<TPKILinked>" + (agreements.isIsTPKILinked() == true ? "True" : "False") + "</TPKILinked>";
        SimpleDateFormat sf = new SimpleDateFormat("dd/MM/yyyy");
        data += "<CreatedDate>"
                + sf.format(agreements.getCreatedDate())
                + "</CreatedDate>";
        data += "<EffectiveDate>"
                + sf.format(agreements.getEffectiveDate())
                + "</EffectiveDate>";
        data += "<ExpiredDate>"
                + sf.format(agreements.getExpiredDate())
                + "</ExpiredDate>";
        data += "</Agreement>";
        return data;
    }

    public static byte[] padSHA1Oid(byte[] hashedData) throws Exception {

        DERObjectIdentifier sha1oid_ = new DERObjectIdentifier(
                "1.3.14.3.2.26");
        AlgorithmIdentifier sha1aid_ = new AlgorithmIdentifier(
                sha1oid_, null);
        DigestInfo di = new DigestInfo(sha1aid_, hashedData);

        byte[] plainSig = di.getEncoded(ASN1Encoding.DER);

        return plainSig;
    }

    public static String[] getCertificateComponents(String certstr) {
        String[] tmp = new String[6];
        try {

            if (certstr.indexOf("-----BEGIN CERTIFICATE-----") != -1) {
                certstr = certstr.replace("-----BEGIN CERTIFICATE-----", "");
            }
            if (certstr.indexOf("-----END CERTIFICATE-----") != -1) {
                certstr = certstr.replace("-----END CERTIFICATE-----", "");
            }

            DateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");

            CertificateFactory certFactory1 = CertificateFactory.getInstance("X.509");
            InputStream in = new ByteArrayInputStream(
                    DatatypeConverter.parseBase64Binary(certstr));
            X509Certificate cert = (X509Certificate) certFactory1.generateCertificate(in);
            tmp[0] = cert.getSerialNumber().toString(16);
            tmp[1] = cert.getSubjectDN().toString();
            tmp[2] = cert.getIssuerDN().toString();
            tmp[3] = formatter.format(cert.getNotBefore());
            tmp[4] = formatter.format(cert.getNotAfter());
            tmp[5] = getThumbPrint(certstr);

            if (tmp[0].length() < 4) {
                tmp[0] = tmp[0] + "00";
            }
        } catch (Exception e) {
            e.printStackTrace();
            tmp = null;
        }
        return tmp;
    }

    public static String getDateFormat(Date date) {
        String timeStamp = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(Calendar.getInstance().getTime());
        String tail = new BigInteger(130, random).toString(32).toUpperCase();
        return timeStamp.concat(tail.substring(0, 4));
    }

    public static String getRegularDateFormat(Date date) {
        String timeStamp = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(date);
        return timeStamp;
    }

    public static String getDateFormat() {
        String timeStamp = new SimpleDateFormat("yyyyMMddHHmmss").format(Calendar.getInstance().getTime());
        return timeStamp;
    }

    public static int getTransId(String billCode) {
        String[] parts = billCode.split("-");
        int id = 1;
        try {
            id = Integer.parseInt(parts[parts.length - 1]);
        } catch (Exception e) {
            LOG.error("Error while parsing transaction id");
        }
        return id;
    }
    private static char[] SPECIAL_CHARACTERS = {' ', '!', '"', '#', '$', '%',
        '*', '+', ',', ':', '<', '=', '>', '?', '@', '[', '\\', ']', '^',
        '`', '|', '~', 'À', 'Á', 'Â', 'Ã', 'È', 'É', 'Ê', 'Ì', 'Í', 'Ò',
        'Ó', 'Ô', 'Õ', 'Ù', 'Ú', 'Ý', 'à', 'á', 'â', 'ã', 'è', 'é', 'ê',
        'ì', 'í', 'ò', 'ó', 'ô', 'õ', 'ù', 'ú', 'ý', 'Ă', 'ă', 'Đ', 'đ',
        'Ĩ', 'ĩ', 'Ũ', 'ũ', 'Ơ', 'ơ', 'Ư', 'ư', 'Ạ', 'ạ', 'Ả', 'ả', 'Ấ',
        'ấ', 'Ầ', 'ầ', 'Ẩ', 'ẩ', 'Ẫ', 'ẫ', 'Ậ', 'ậ', 'Ắ', 'ắ', 'Ằ', 'ằ',
        'Ẳ', 'ẳ', 'Ẵ', 'ẵ', 'Ặ', 'ặ', 'Ẹ', 'ẹ', 'Ẻ', 'ẻ', 'Ẽ', 'ẽ', 'Ế',
        'ế', 'Ề', 'ề', 'Ể', 'ể', 'Ễ', 'ễ', 'Ệ', 'ệ', 'Ỉ', 'ỉ', 'Ị', 'ị',
        'Ọ', 'ọ', 'Ỏ', 'ỏ', 'Ố', 'ố', 'Ồ', 'ồ', 'Ổ', 'ổ', 'Ỗ', 'ỗ', 'Ộ',
        'ộ', 'Ớ', 'ớ', 'Ờ', 'ờ', 'Ở', 'ở', 'Ỡ', 'ỡ', 'Ợ', 'ợ', 'Ụ', 'ụ',
        'Ủ', 'ủ', 'Ứ', 'ứ', 'Ừ', 'ừ', 'Ử', 'ử', 'Ữ', 'ữ', 'Ự', 'ự',};
    private static char[] REPLACEMENTS = {' ', '!', '"', '#', '$', '%', '*',
        '+', ',', ':', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '`',
        '|', '~', 'A', 'A', 'A', 'A', 'E', 'E', 'E', 'I', 'I', 'O', 'O',
        'O', 'O', 'U', 'U', 'Y', 'a', 'a', 'a', 'a', 'e', 'e', 'e', 'i',
        'i', 'o', 'o', 'o', 'o', 'u', 'u', 'y', 'A', 'a', 'D', 'd', 'I',
        'i', 'U', 'u', 'O', 'o', 'U', 'u', 'A', 'a', 'A', 'a', 'A', 'a',
        'A', 'a', 'A', 'a', 'A', 'a', 'A', 'a', 'A', 'a', 'A', 'a', 'A',
        'a', 'A', 'a', 'A', 'a', 'E', 'e', 'E', 'e', 'E', 'e', 'E', 'e',
        'E', 'e', 'E', 'e', 'E', 'e', 'E', 'e', 'I', 'i', 'I', 'i', 'O',
        'o', 'O', 'o', 'O', 'o', 'O', 'o', 'O', 'o', 'O', 'o', 'O', 'o',
        'O', 'o', 'O', 'o', 'O', 'o', 'O', 'o', 'O', 'o', 'U', 'u', 'U',
        'u', 'U', 'u', 'U', 'u', 'U', 'u', 'U', 'u', 'U', 'u',};

    public static String toUrlFriendly(String s) {
        int maxLength = Math.min(s.length(), 236);
        char[] buffer = new char[maxLength];
        int n = 0;
        for (int i = 0; i < maxLength; i++) {
            char ch = s.charAt(i);
            buffer[n] = removeAccent(ch);
            // skip not printable characters
            if (buffer[n] > 31) {
                n++;
            }
        }
        // skip trailing slashes
        while (n > 0 && buffer[n - 1] == '/') {
            n--;
        }
        return String.valueOf(buffer, 0, n);
    }

    public static char removeAccent(char ch) {
        int index = Arrays.binarySearch(SPECIAL_CHARACTERS, ch);
        if (index >= 0) {
            ch = REPLACEMENTS[index];
        }
        return ch;
    }

    public static String removeAccent(String s) {
        StringBuilder sb = new StringBuilder(s);
        for (int i = 0; i < sb.length(); i++) {
            sb.setCharAt(i, removeAccent(sb.charAt(i)));
        }
        return sb.toString();
    }
    public static final Pattern VALID_EMAIL_ADDRESS_REGEX =
            Pattern.compile("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,6}$", Pattern.CASE_INSENSITIVE);

    public static boolean isValidEmail(String email) {
        Matcher matcher = VALID_EMAIL_ADDRESS_REGEX.matcher(email);
        return matcher.find();
    }

    public static boolean isValidPhoneNumber(String phoneNo) {
        //return phoneNo.matches("-?\\d+(\\.\\d+)?");
        return phoneNo.matches("^[\\+|0]?( |[1-9])+( |[0-9]{4,20})");
    }

    public static boolean isNumeric(String code) {
        try {
            Long.parseLong(code);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public static boolean checkCertificateRelation(X509Certificate caCert,
            X509Certificate clientCert) {
        boolean res = false;
        try {
            clientCert.verify(caCert.getPublicKey());
            res = true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return res;
    }

    public static boolean checkCertificateAndCsr(X509Certificate cert, String req) {
        boolean res = false;
        try {

            if (req.indexOf("-----BEGIN CERTIFICATE REQUEST-----") != -1) {
                req = req.replace("-----BEGIN CERTIFICATE REQUEST-----", "");
            }
            if (req.indexOf("-----END CERTIFICATE REQUEST-----") != -1) {
                req = req.replace("-----END CERTIFICATE REQUEST-----", "");
            }

            PKCS10CertificationRequest csr =
                    new PKCS10CertificationRequest(DatatypeConverter.parseBase64Binary(req));
            byte[] csrPubKey = csr.getPublicKey().getEncoded();
            byte[] certPubKey = cert.getPublicKey().getEncoded();
            if (Arrays.equals(csrPubKey, certPubKey)) {
                res = true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return res;
    }

    public static String getThumbPrint(String base64str) {
        try {
            InputStream is = new ByteArrayInputStream(
                    DatatypeConverter.parseBase64Binary(base64str));
            CertificateFactory x509CertFact = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) x509CertFact.generateCertificate(is);

            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] der = cert.getEncoded();
            md.update(der);
            byte[] digest = md.digest();
            return DatatypeConverter.printHexBinary(digest);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    public static String convertTimeFormat(String pattern) {
        String result = null;
        try {
            SimpleDateFormat sf = new SimpleDateFormat("yyyyMMdd");
            Date d = sf.parse(pattern);
            SimpleDateFormat sf2 = new SimpleDateFormat("dd-MMM-yy");
            result = sf2.format(d);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public static String getRequestIP(WebServiceContext wsContext) {
        MessageContext msgContext = wsContext.getMessageContext();
        HttpServletRequest request = (HttpServletRequest) msgContext.get(MessageContext.SERVLET_REQUEST);

        return request.getRemoteAddr();
    }

    public static X509Certificate getClientCertificate(
            WebServiceContext wsContext) {
        MessageContext msgContext = wsContext.getMessageContext();
        HttpServletRequest request = (HttpServletRequest) msgContext.get(MessageContext.SERVLET_REQUEST);
        X509Certificate[] certificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");

        if (certificates != null) {
            return certificates[0];
        }
        return null;
    }

    public static int getWorkerType(String workerName, String otpMethod, String signatureMethod) {
        // highest = 14
        if (workerName.compareTo(Defines.WORKER_FILEPROCESSER) == 0) {
            return 14;
        }

        if ((workerName.indexOf("Validator") != -1 && workerName.indexOf("OATH") == -1)) {
            // co Validator nhung khong co OATH
            if (workerName.compareTo(Defines.WORKER_U2FVALIDATOR) == 0) {
                return 12;
            }
            if (workerName.compareTo(Defines.WORKER_GENERALVALIDATOR) == 0) {
                return 13;
            }
            if (signatureMethod.compareTo(Defines.SIGNATURE_METHOD_LPKI) == 0) {
                return 7; // LPKI
            } else if (signatureMethod.compareTo(Defines.SIGNATURE_METHOD_WPKI) == 0) {
                return 10; // WPKI
            } else if (signatureMethod.compareTo(Defines.SIGNATURE_METHOD_TPKI) == 0) {
                return 2; // TPKI
            } else if (signatureMethod.compareTo(Defines.SIGNATURE_METHOD_SPKI) == 0) {
                return 9; // SPKI
            } else {
                return 2; // TPKI by default
            }
        }
        if (workerName.indexOf("OATH") != -1) {
            if (workerName.equals(Defines.WORKER_OATHVALIDATOR)
                    || workerName.equals(Defines.WORKER_OATHSYNC)
                    || workerName.equals(Defines.WORKER_OATHUNLOCK)) {
                return 1;// otp hardware information
            } else {
                if (otpMethod.equals(Defines._OTPEMAIL)) {
                    return 3; // otp email
                } else {
                    return 4; // otp sms
                }
            }
        }
        if (workerName.indexOf("Signer") != -1) {
            if (workerName.indexOf(Defines.WORKER_SIGNERAP) != -1) {
                return 8; // WPKI
            }
            if (workerName.indexOf(Defines.WORKER_DCSIGNER) != -1) {
                return 11;
            }
            return 5;
        }
        return 6; // agreement
    }
    final static String alphabet = "ABCDEFGHIJKLMNOPQRSTUVW";
    final static int N = alphabet.length();
    static Random r = new Random();

    public static String generateApTransId() {
        String transId = String.valueOf(alphabet.charAt(r.nextInt(N)))
                + System.currentTimeMillis();
        return transId;
    }

    public static String[] generateApTransIdAndRequestId() {
        String transId = String.valueOf(alphabet.charAt(r.nextInt(N)))
                + System.nanoTime();
        String[] str = new String[2];
        str[0] = transId;
        str[1] = transId.substring(transId.length() - 6);
        return str;
    }

    public static X509Certificate getCertificate(String base64)
            throws Exception {

        if (base64.indexOf("-----BEGIN CERTIFICATE-----") != -1) {
            base64 = base64.replace("-----BEGIN CERTIFICATE-----", "");
        }
        if (base64.indexOf("-----END CERTIFICATE-----") != -1) {
            base64 = base64.replace("-----END CERTIFICATE-----", "");
        }

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(
                DatatypeConverter.parseBase64Binary(base64));
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);
        return cert;
    }

    private static byte[] getX509Der(String base64Str)
            throws Exception {
        byte[] binary = null;
        if (base64Str.indexOf("-----BEGIN CERTIFICATE-----") != -1) {
            binary = base64Str.getBytes();
        } else {
            binary = DatatypeConverter.parseBase64Binary(base64Str);
        }
        return binary;
    }

    public static X509Certificate getX509Object(String pem) {
        X509Certificate x509 = null;
        try {
            CertificateFactory certFactoryChild = CertificateFactory.getInstance("X.509", "BC");
            InputStream inChild = new ByteArrayInputStream(
                    getX509Der(pem));
            x509 = (X509Certificate) certFactoryChild.generateCertificate(inChild);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return x509;
    }

    public static X509Certificate getCertificate(byte[] encoded)
            throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(encoded);
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);
        return cert;
    }

    public static boolean verifyPKCS1Signature(byte[] data, byte[] signature,
            String base64Certificate) throws Exception {
        X509Certificate x509 = ExtFunc.getCertificate(base64Certificate);

        Signature sig = Signature.getInstance("NONEwithRSA");
        sig.initVerify(x509.getPublicKey());
        sig.update(data);
        return sig.verify(signature);
    }

    public static List<Certificate> getCertificateChain(String caCert1, String caCert2, X509Certificate cert) {
        X509Certificate endCert = null;
        X509Certificate ca1 = null;
        X509Certificate ca2 = null;
        endCert = cert;
        ca1 = getX509Object(caCert1);
        try {
            endCert.verify(ca1.getPublicKey());
            Collection<Certificate> certChain = CertTools.getCertsFromPEM(new ByteArrayInputStream(caCert1.getBytes()));
            certChain.add((Certificate) endCert);

            List<Certificate> certificates = new ArrayList(certChain);
            Collections.reverse(certificates);
            return certificates;
        } catch (Exception e) {
            LOG.warn("First CA certificate isn't the one who issues end-user certificate. Try the second one");
            ca2 = getX509Object(caCert2);
            try {
                endCert.verify(ca2.getPublicKey());
                Collection<Certificate> certChain = CertTools.getCertsFromPEM(new ByteArrayInputStream(caCert2.getBytes()));
                certChain.add((Certificate) endCert);

                List<Certificate> certificates = new ArrayList(certChain);
                Collections.reverse(certificates);
                return certificates;
            } catch (Exception exx) {
                exx.printStackTrace();
                return null;
            }
        }
    }

    public static boolean verifyPKCS7Signature(byte[] data, byte[] signature,
            String serialNumber) throws Exception {
        CMSProcessableByteArray cmsByteArray = new CMSProcessableByteArray(data);
        CMSSignedData sp = new CMSSignedData(cmsByteArray, signature);
        Store certStore = sp.getCertificates();
        SignerInformationStore signers = sp.getSignerInfos();
        Collection c = signers.getSigners();
        Iterator it = c.iterator();
        BigInteger serialNo = new BigInteger(serialNumber, 16);
        boolean verificationResult = false;
        while (it.hasNext()) {
            try {
                SignerInformation signer = (SignerInformation) it.next();
                Collection certCollection = certStore.getMatches(signer.getSID());
                Iterator certIt = certCollection.iterator();
                while (certIt.hasNext()) {
                    X509CertificateHolder cert = (X509CertificateHolder) certIt.next();
                    if (serialNo.compareTo(cert.getSerialNumber()) == 0) {
                        verificationResult = verificationResult
                                || signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));
                    } else {
                        LOG.error("Invalid signing certificate and agreement one aren't matched");
                    }
                }
            } catch (Exception e) {
                LOG.error("Invalid signature: " + e.getMessage());
            }
        }
        return verificationResult;
    }

    public static byte[] randomHex(int length) {
        Random randomno = new Random();
        byte[] nbyte = new byte[length];
        randomno.nextBytes(nbyte);
        return nbyte;
    }

    public static String getEpcProperty(String data, String tag) {
        String value = null;
        String[] group = data.split(";");
        for (int i = 0; i < group.length; i++) {
            String[] pairs = group[i].split("=");
            if (pairs[0].compareTo(tag) == 0) {
                value = pairs[1];
            }
        }
        return value;
    }

    public static void executeExternalShellScript(String scriptPath) {
        try {
            ProcessBuilder pb = new ProcessBuilder(scriptPath);
            Process p = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    p.getInputStream()));
            String line = null;
            while ((line = reader.readLine()) != null) {
                LOG.info(line);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String replaceBillCode(String billCode, String data) {
        String new_str = "<BillCode>" + billCode + "</BillCode>";
        String old_str = "<BillCode></BillCode>";
        return data.replace(old_str, new_str);
    }

    public static String checkFileType(byte[] fileData, String extension) {
        try {
            byte[] b = new byte[fileData.length];
            b = fileData;
            String mime = MineType.getMimeType(b, extension);

            if (mime.compareTo(C_MIMETYPE_PDF) == 0) {
                return C_FILETYPE_PDF;
            }

            if (mime.compareTo(C_MIMETYPE_MSWORD) == 0
                    || mime.compareTo(C_MIMETYPE_OOXML) == 0
                    || mime.compareTo(C_MIMETYPE_OPENXML) == 0) {
                return C_FILETYPE_OFFICE;
            }

            return C_FILETYPE_XML;
        } catch (Exception e) {
            return C_FILETYPE_XML;
        }
    }

    public static String checkMimeType(byte[] fileData, String extension) {
        return MineType.getMimeType(fileData, extension);
    }

    public static byte[] hash(byte[] data, String algorithm) {
        byte[] hashedData = null;
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            md.update(data);
            hashedData = md.digest();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return hashedData;
    }

    public static X509Certificate convertToX509Cert(String certificateString) throws CertificateException {
        X509Certificate certificate = null;
        CertificateFactory cf = null;
        try {
            if (certificateString.indexOf("-----BEGIN CERTIFICATE-----") != -1) {
                certificateString = certificateString.replace("-----BEGIN CERTIFICATE-----", "");
            }
            if (certificateString.indexOf("-----END CERTIFICATE-----") != -1) {
                certificateString = certificateString.replace("-----END CERTIFICATE-----", "");
            }
            byte[] certificateData = DatatypeConverter.parseBase64Binary(certificateString);
            cf = CertificateFactory.getInstance("X.509");
            certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateData));
        } catch (CertificateException e) {
            throw new CertificateException(e);
        }
        return certificate;
    }

    public static String getSubjectName(String DN) {
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

    public static boolean isNullOrEmpty(String value) {
        if (value == null) {
            return true;
        }
        if (value.compareTo("") == 0) {
            return true;
        }
        return false;
    }

    public static boolean isNull(String value) {
        if (value == null) {
            return true;
        }
        return false;
    }

    public static String replaceFileDataInJason(String json, String keyMain) {
        String result = null;
        try {
            result = doReplaceFileDataInJason(new JSONObject(json), keyMain, "...").toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    private static JSONObject doReplaceFileDataInJason(JSONObject obj, String keyMain,
            String newValue) throws Exception {
        String result = null;
        Iterator iterator = obj.keys();
        String key = null;
        while (iterator.hasNext()) {
            key = (String) iterator.next();
            // if object is just string we change value in key
            if ((obj.optJSONArray(key) == null)
                    && (obj.optJSONObject(key) == null)) {
                if ((key.equals(keyMain))) {
                    // put new value
                    obj.remove(key);
                    obj.put(key, newValue);
                    return obj;
                }
            }
            // if it's jsonobject
            if (obj.optJSONObject(key) != null) {
                doReplaceFileDataInJason(obj.getJSONObject(key), keyMain, newValue);
            }

            // if it's jsonarray
            if (obj.optJSONArray(key) != null) {
                JSONArray jArray = obj.getJSONArray(key);
                for (int i = 0; i < jArray.length(); i++) {
                    doReplaceFileDataInJason(jArray.getJSONObject(i), keyMain, newValue);
                }
            }
        }
        return obj;
    }
    /*
     * public static String replaceJasonValueTooLong(String json) { String
     * result = null; try { result = doReplaceJasonValueTooLong(new
     * JSONObject(json)).toString(); } catch(Exception e) { e.printStackTrace();
     * } return result; }
     *
     * private static JSONObject doReplaceJasonValueTooLong(JSONObject obj)
     * throws Exception { String result = null; Iterator iterator = obj.keys();
     * String key = null; while (iterator.hasNext()) { key = (String)
     * iterator.next(); // if object is just string we change value in key if
     * ((obj.optJSONArray(key) == null) && (obj.optJSONObject(key) == null)) {
     *
     * String value = obj.get(key).toString(); if(value.length() > 20) {
     * obj.remove(key); obj.put(key, value.substring(0, 20).concat("..."));
     * //return obj; } } // if it's jsonobject if (obj.optJSONObject(key) !=
     * null) { doReplaceJasonValueTooLong(obj.getJSONObject(key)); }
     *
     * // if it's jsonarray if (obj.optJSONArray(key) != null) { JSONArray
     * jArray = obj.getJSONArray(key); for (int i = 0; i < jArray.length(); i++)
     * { doReplaceJasonValueTooLong(jArray.getJSONObject(i)); } } } return obj;
     * }
     */

    public static String getCNFromDN(String DN) {
        /*
         * String CN = ""; String[] pairs = DN.split(","); for (String pair :
         * pairs) { String[] paramvalue = pair.split("="); if
         * (paramvalue[0].compareTo("CN") == 0 || paramvalue[0].compareTo(" CN")
         * == 0) { CN = paramvalue[1]; break; } } return CN;
         */
        X500Name subject = new X500Name(DN);
        RDN[] rdn = subject.getRDNs();
        String cn = null;
        for (int i = 0; i < rdn.length; i++) {
            AttributeTypeAndValue[] attributeTypeAndValue = rdn[i].getTypesAndValues();
            if (attributeTypeAndValue[0].getType().toString().equals("2.5.4.3")) {
                cn = attributeTypeAndValue[0].getValue().toString();
            }
        }
        return cn;
    }

    public static String getEmailFromDN(String DN) {
        X500Name subject = new X500Name(DN);
        RDN[] rdn = subject.getRDNs();
        String e = null;
        for (int i = 0; i < rdn.length; i++) {
            AttributeTypeAndValue[] attributeTypeAndValue = rdn[i].getTypesAndValues();
            if (attributeTypeAndValue[0].getType().toString().equals("1.2.840.113549.1.9.1")) {
                e = attributeTypeAndValue[0].getValue().toString();
            }
        }
        return e;
    }

    public static Date convertToGMT(Date utcTime) throws Exception {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        simpleDateFormat.setTimeZone(TimeZone.getTimeZone("Etc/GMT-14"));
        String s = simpleDateFormat.format(utcTime);
        SimpleDateFormat sf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        return sf.parse(s);
    }

    public static boolean verifyDcSignature(String certificate, String signature, String data) {
        boolean rv = false;
        try {
            byte[] dtbs = padSHA1Oid(DatatypeConverter.parseHexBinary(data));
            Signature s = Signature.getInstance("NONEwithRSA");
            s.initVerify(getCertificate(certificate).getPublicKey());
            s.update(dtbs);
            rv = s.verify(DatatypeConverter.parseBase64Binary(signature));
            return rv;
        } catch (Exception e) {
            LOG.error(e.toString());
        }
        return rv;
    }

    public static boolean isCACertificate(X509Certificate caCert) {
        boolean keyUsage = false;
        try {
            keyUsage = caCert.getKeyUsage()[5];
        } catch (NullPointerException e) {
            keyUsage = false;
        }
        int basicConstraint = caCert.getBasicConstraints();
        boolean rv = (keyUsage && (basicConstraint != -1));
        return rv;
    }

    public static String generateRamdomNumber() {
        Random rnd = new Random();
        int n = 10000000 + rnd.nextInt(90000000);
        return String.valueOf(n);
    }

    public static String getMonitorDatePattern(Date dateTime) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        return sdf.format(dateTime);
    }

    public static String getMasterDBAdrr(String dbHost) {
        int start = dbHost.indexOf("//");
        int end = dbHost.lastIndexOf(":");
        String b = dbHost.substring(start + 2, end);
        String[] split = b.split(",");
        return split[0];
    }

    public static String getHostName() {
        String hostname = "Unknown hostname";
        try {
            InetAddress addr;
            addr = InetAddress.getLocalHost();
            hostname = addr.getHostName();
        } catch (UnknownHostException ex) {
            ex.printStackTrace();
        }
        return hostname;
    }

    public static String detectCharset(byte[] fileData) {
        String encoding = "UTF-8";
        ByteArrayInputStream bis = null;
        try {
            byte[] buf = new byte[4096];
            bis = new ByteArrayInputStream(fileData);
            // (1)
            UniversalDetector detector = new UniversalDetector(null);
            // (2)
            int nread;
            while ((nread = bis.read(buf)) > 0 && !detector.isDone()) {
                detector.handleData(buf, 0, nread);
            }
            // (3)
            detector.dataEnd();
            bis.close();
            // (4)
            encoding = detector.getDetectedCharset();
            if (encoding != null) {
                LOG.info("Encoding detected: " + encoding);
            } else {
                LOG.info("No encoding detected. Default is UTF-8");
                encoding = "UTF-8";
            }
            // (5)
            detector.reset();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encoding;
    }

    public static String getSignatureHashAlgorithm(X509Certificate x509) {
        String signatureAlgo = x509.getSigAlgName().toLowerCase();
        String hashAlgo = "sha1";
        try {
            String str[] = signatureAlgo.split("with");
            hashAlgo = str[0];
        } catch (Exception e) {
            e.printStackTrace();
        }
        return hashAlgo;
    }

    public static String getUUID() {
        return java.util.UUID.randomUUID().toString();
    }

    public static String readFile(String fileName) throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(fileName));
        try {
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();

            while (line != null) {
                sb.append(line);
                sb.append("\n");
                line = br.readLine();
            }
            return sb.toString();
        } finally {
            br.close();
        }
    }

    public static long getMinutesBetweenTwoDate(Date d1, Date d2) {
        long diff = d2.getTime() - d1.getTime();
        long diffMinutes = diff / (60 * 1000) % 60;
        return diffMinutes;
    }

    public static int compareDate(Date date1, Date date2) {
        if (date1.after(date2)) {
            return -1;
        }

        if (date1.before(date2)) {
            return 1;
        }

        if (date1.equals(date2)) {
            return 0;
        }
        return -2;
    }

    public static String encrypt(String plainText) {
        String result = null;
        try {
            result = DatatypeConverter.printBase64Binary(Cryptography.encryptTdes(plainText.getBytes()));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public static String decrypt(String encryptedText) {
        String result = null;
        try {
            result = new String(Cryptography.decryptTdes(DatatypeConverter.parseBase64Binary(encryptedText)));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public static boolean[] getKeyUsage(X509Certificate x509) {
        /*
         * digitalSignature (0), nonRepudiation (1), keyEncipherment (2),
         * dataEncipherment (3), keyAgreement (4), keyCertSign (5), --> true
         * ONLY for CAs cRLSign (6), encipherOnly (7), decipherOnly (8)
         *
         *
         */
        return x509.getKeyUsage();
    }

    public static int getBasicConstraint(X509Certificate x509) {
        return x509.getBasicConstraints();
    }

    public static String getOSVersion() {
        String osVersion = System.getProperty("os.version");
        String arch = null;
        if (osVersion.contains(OS_VERSION_EL6)) {
            arch = OS_VERSION_EL6;
        } else if (osVersion.contains(OS_VERSION_EL7)) {
            arch = OS_VERSION_EL7;
        } else {
            arch = OS_VERSION_UNKNOWN;
        }
        return arch;
    }

    public static String getNetworkInterfaceName(String ipLink) {
        String enterfaceName = null;
        try {
            BufferedReader bufReader = new BufferedReader(new StringReader(ipLink));
            String line = null;
            while ((line = bufReader.readLine()) != null) {
                String[] words = line.split(" ");
                if (isNumeric(words[0].replace(":", ""))) {
                    enterfaceName = words[1].replace(":", "");
                    if (enterfaceName.equals("lo")) {
                        continue;
                    } else {
                        break;
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return enterfaceName;
    }

    public static String getWorkerUUID(String res) {
        String id = null;
        try {
            String key = "for worker ";
            int index = res.indexOf(key);
            id = res.substring(index + key.length(), index + key.length() + 1);
            String nextId = res.substring(index + key.length() + 1, index + key.length() + 2);

            if (!nextId.equals(" ")) {
                int tmp = Integer.valueOf(id) * 10 + Integer.valueOf(nextId);
                id = String.valueOf(tmp);
            }
            String nextId2 = res.substring(index + key.length() + 2, index + key.length() + 3);
            if (!nextId2.equals(" ")) {
                int tmp = Integer.valueOf(id) * 10 + Integer.valueOf(nextId2);
                id = String.valueOf(tmp);
            }
        } catch (java.lang.NumberFormatException ex) {
        }
        return id;
    }

    public static boolean checkCertTemplate(String dn, List<CertTemplate> list) {
        X500Name subject = new X500Name(dn);
        RDN[] rdn = subject.getRDNs();
        boolean finalResult = true;
        for (int i = 0; i < list.size(); i++) {
            CertTemplate certTemplate = list.get(i);
            String attrSystem = OIDManager.getOID(certTemplate.getAttrCode()) + "=" + (certTemplate.getPrefix() == null ? "" : certTemplate.getPrefix());
            boolean eachAttrValid = false;
            for (int j = 0; j < rdn.length; j++) {
                AttributeTypeAndValue[] attributeTypeAndValue = rdn[j].getTypesAndValues();
                String attr = attributeTypeAndValue[0].getType().toString() + "=" + attributeTypeAndValue[0].getValue().toString();
                if (attr.contains(attrSystem)) {
                    eachAttrValid = true;
                    break;
                } else {
                    eachAttrValid = false;
                    continue;
                }
            }
            finalResult &= eachAttrValid;
        }
        return finalResult;
    }

    public static List<byte[]> asByteArrayList(
            final List<Certificate> signerChain) {
        final List<byte[]> result = new LinkedList<byte[]>();
        try {
            for (final Certificate cert : signerChain) {
                result.add(cert.getEncoded());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public static byte[] asByteArray(final X509Certificate signerCert) {
        byte[] result = null;
        try {
            result = signerCert.getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public static String calculateVerificationCode(byte[] documentHash) {
        byte[] digest = hash256(documentHash);
        ByteBuffer byteBuffer = ByteBuffer.wrap(digest);
        int shortBytes = Short.SIZE / Byte.SIZE; // Short.BYTES in java 8

        int rightMostBytesIndex = byteBuffer.limit() - shortBytes;
        short twoRightmostBytes = byteBuffer.getShort(rightMostBytesIndex);
        short twoLeftmostBytes = byteBuffer.getShort(0);

        int rightPositiveInteger = ((int) twoRightmostBytes) & 0xffff;
        int leftPositiveInteger = ((int) twoLeftmostBytes) & 0xffff;

        String rightCode = String.valueOf(rightPositiveInteger);
        String leftCode = String.valueOf(leftPositiveInteger);

        String rightPaddedCode = "0000" + rightCode;
        String leftPaddedCode = "0000" + leftCode;
        String finalCode = rightPaddedCode.substring(rightPaddedCode.length() - 3) + leftPaddedCode.substring(leftPaddedCode.length() - 3);
        return finalCode;
    }

    private static byte[] hash256(byte[] data) {
        byte[] hashData = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(data);
            hashData = md.digest();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return hashData;
    }

    public static byte[] getP7B(List<Certificate> chain) {
        byte[] p7b = null;
        try {
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            CMSProcessableByteArray msg = new CMSProcessableByteArray("signedData".getBytes());
            JcaCertStore store = new JcaCertStore(chain);
            gen.addCertificates(store);
            CMSSignedData signedData = gen.generate(msg);
            p7b = signedData.getEncoded();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return p7b;
    }

    public static String getRandomSignserverPassword() {
        Random rnd = new Random();
        int n = 10000000 + rnd.nextInt(90000000);
        return String.valueOf(n);
    }

    public static String getCertFileNameFromSubjectDn(String subjectDn, String username) {

        String PREFIX_PERSONAL_CODE = "CMND:";
        String PREFIX_PERSONAL_PASSPORT_CODE = "HC:";
        String PREFIX_ENTERPRISE_TAX_CODE = "MST:";
        String PREFIX_ENTERPRISE_BUDGET_CODE = "MNS:";

        X500Name subject = new X500Name(subjectDn);
        RDN[] rdn = subject.getRDNs();
        String result = "";
        boolean isSet = false;
        for (int j = 0; j < rdn.length; j++) {
            AttributeTypeAndValue[] attributeTypeAndValue = rdn[j].getTypesAndValues();
            String value = attributeTypeAndValue[0].getValue().toString();
            if (value.contains(PREFIX_ENTERPRISE_TAX_CODE) || value.contains(PREFIX_ENTERPRISE_BUDGET_CODE)) {
                if (value.contains(PREFIX_ENTERPRISE_TAX_CODE)) {
                    result = value.substring(PREFIX_ENTERPRISE_TAX_CODE.length());
                } else {
                    result = value.substring(PREFIX_ENTERPRISE_BUDGET_CODE.length());
                }
                isSet = true;
            } else if (value.contains(PREFIX_PERSONAL_CODE) || value.contains(PREFIX_PERSONAL_PASSPORT_CODE)) {
                if (!isSet) {
                    if (value.contains(PREFIX_PERSONAL_CODE)) {
                        result = value.substring(PREFIX_PERSONAL_CODE.length());
                    } else {
                        result = value.substring(PREFIX_PERSONAL_PASSPORT_CODE.length());
                    }
                }
            }
        }

        if (result.equals("")) {
            result = username;
        }

        return result;
    }

    public static boolean checkDataValidity(X509Certificate x509) {
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
    public static final String OID_CN = "2.5.4.3";
    public static final String OID_EMAIL = "1.2.840.113549.1.9.1";
    public static final String OID_UID = "0.9.2342.19200300.100.1.1";
    public static final String OID_PHONE = "2.5.4.20";
    public static final String OID_ST = "2.5.4.8";
    public static final String OID_O = "2.5.4.10";
    public static final String OID_L = "2.5.4.7";
    public static final String OID_OU = "2.5.4.11";
    public static final String OID_T = "2.5.4.12";
    public static final String OID_C = "2.5.4.6";
    public static final String OID_G = "2.5.4.42";

    public static String getCommonName(String dn) {
        X500Name subject = new X500Name(dn);
        RDN[] rdn = subject.getRDNs();
        for (int j = 0; j < rdn.length; j++) {
            AttributeTypeAndValue[] attributeTypeAndValue = rdn[j].getTypesAndValues();
            if (attributeTypeAndValue[0].getType().toString().equals(OID_CN)) {
                return attributeTypeAndValue[0].getValue().toString();
            }
        }
        return null;
    }

    public static String getTitle(String dn) {
        X500Name subject = new X500Name(dn);
        RDN[] rdn = subject.getRDNs();
        for (int j = 0; j < rdn.length; j++) {
            AttributeTypeAndValue[] attributeTypeAndValue = rdn[j].getTypesAndValues();
            if (attributeTypeAndValue[0].getType().toString().equals(OID_T)) {
                return attributeTypeAndValue[0].getValue().toString();
            }
        }
        return null;
    }

    public static String getOrganization(String dn) {
        X500Name subject = new X500Name(dn);
        RDN[] rdn = subject.getRDNs();
        for (int j = 0; j < rdn.length; j++) {
            AttributeTypeAndValue[] attributeTypeAndValue = rdn[j].getTypesAndValues();
            if (attributeTypeAndValue[0].getType().toString().equals(OID_O)) {
                return attributeTypeAndValue[0].getValue().toString();
            }
        }
        return null;
    }

    public static String getOrganizationUnit(String dn) {
        X500Name subject = new X500Name(dn);
        RDN[] rdn = subject.getRDNs();
        for (int j = 0; j < rdn.length; j++) {
            AttributeTypeAndValue[] attributeTypeAndValue = rdn[j].getTypesAndValues();
            if (attributeTypeAndValue[0].getType().toString().equals(OID_OU)) {
                return attributeTypeAndValue[0].getValue().toString();
            }
        }
        return null;
    }

    public static Date getDateTime(String dateTime, String format) {
        try {
            SimpleDateFormat sdf = new SimpleDateFormat(format);
            sdf.setTimeZone(TimeZone.getTimeZone(System.getProperty("user.timezone")));
            return sdf.parse(dateTime);
        } catch (ParseException ex) {
            LOG.error("Invalid DateTimeFormat (" + dateTime + "/" + format + "). Using NOW()");
            Calendar cal = Calendar.getInstance();
            return cal.getTime();
        }
    }

    public static String getSubjectKeyIdentifier(X509Certificate cert) {
        byte[] extensionValue = cert.getExtensionValue("2.5.29.14");
        if (DEROctetString.getInstance(extensionValue) == null) {
            LOG.error("WARNING!!!. SubjectKeyIdentifier not found for CA " + cert.getSubjectDN().toString());
            return "";
        }
        byte[] octets = DEROctetString.getInstance(extensionValue).getOctets();
        SubjectKeyIdentifier subjectKeyIdentifier = SubjectKeyIdentifier.getInstance(octets);
        byte[] keyIdentifier = subjectKeyIdentifier.getKeyIdentifier();
        //String keyIdentifierHex = new String(Hex.encode(keyIdentifier));
        String keyIdentifierHex = DatatypeConverter.printHexBinary(keyIdentifier).toLowerCase();
        return keyIdentifierHex;
    }

    public static String getIssuerKeyIdentifier(X509Certificate cert) {
        byte[] extensionValue = cert.getExtensionValue("2.5.29.35");
        if (DEROctetString.getInstance(extensionValue) == null) {
            LOG.error("WARNING!!!. IssuerKeyIdentifier not found for CA " + cert.getSubjectDN().toString());
            return "";
        }
        byte[] octets = DEROctetString.getInstance(extensionValue).getOctets();
        AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(octets);
        byte[] keyIdentifier = authorityKeyIdentifier.getKeyIdentifier();
//        String keyIdentifierHex = new String(Hex.encode(keyIdentifier));
        String keyIdentifierHex = DatatypeConverter.printHexBinary(keyIdentifier).toLowerCase();
        return keyIdentifierHex;
    }
}