package org.signserver.validationservice.server.multivalidator;

import org.signserver.common.*;
import org.signserver.common.util.*;
import org.signserver.common.dbdao.*;

import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.*;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;

import java.io.*;

import java.security.*;
import java.security.cert.*;
import java.util.*;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.parsers.DocumentBuilderFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.signserver.validationservice.server.*;

public class XMLValidator implements MultiValidatorInterface {

    private static final Logger LOG = Logger.getLogger(XMLValidator.class);
    private static final String DEFAULT_XPATH_NAMESPACE = "Id";
    private static final String DEFAULT_DATE_PATTERN_SECOND = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX";
    private static final String DEFAULT_DATE_PATTERN_FIRST = "yyyy-MM-dd'T'HH:mm:ssXXX"; //ISO 8601 time zone
    private static final String DEFAULT_SIGNINGTIME_TAG = "SigningTime";
    private static final String DEFAULT_TIMESTAMP_TAG = "xades:EncapsulatedTimeStamp";
    private String xpathNamespace;
    private String signingTimeTag;
    private String datePattern;
    private String user;
    private String channelName;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public XMLValidator(String xpathNamespace, String signingTimeTag, String datePattern, String channelName, String user) {
        if (xpathNamespace != null) {
            this.xpathNamespace = xpathNamespace;
        } else {
            this.xpathNamespace = DEFAULT_XPATH_NAMESPACE;
        }

        if (signingTimeTag != null) {
            this.signingTimeTag = signingTimeTag;
        } else {
            this.signingTimeTag = DEFAULT_SIGNINGTIME_TAG;
        }

        if (datePattern != null) {
            this.datePattern = datePattern;
        } else {
            this.datePattern = DEFAULT_DATE_PATTERN_FIRST;
        }

        this.channelName = channelName;
        this.user = user;
    }

    public MultiValidatorResponse verify(byte[] data, String serialNumber, ArrayList<Ca> caProviders, int trustedhubTransId) {
        MultiValidatorResponse response = new MultiValidatorResponse();
        List<SignerInfoResponse> listSignerInfoResponse = new ArrayList<SignerInfoResponse>();
        try {

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(data));

//            XPath xpath = XPathFactory.newInstance().newXPath();
//            XPathExpression expr = xpath.compile("//*[@" + this.xpathNamespace + "]");
//
//            NodeList nodeList = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
//
//            for (int i = 0; i < nodeList.getLength(); i++) {
//                Element elem = (Element) nodeList.item(i);
//                Attr attr = (Attr) elem.getAttributes().getNamedItem(this.xpathNamespace);
//                elem.setIdAttributeNode(attr, true);
//            }

            XPath xpath = XPathFactory.newInstance().newXPath();

            XPathExpression expr = xpath.compile("//*[@Id]");
            NodeList nodeList = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);

            for (int i = 0; i < nodeList.getLength(); i++) {
                Element elem = (Element) nodeList.item(i);
                elem.setIdAttributeNS(null, "Id", true);
            }

            expr = xpath.compile("//*[@id]");
            nodeList = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);

            for (int i = 0; i < nodeList.getLength(); i++) {
                Element elem = (Element) nodeList.item(i);
                elem.setIdAttributeNS(null, "id", true);
            }


            NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");

            if (nl.getLength() == 0) {
                response.setResponseCode(Defines.CODE_SIGNEDDOC);
                response.setResponseMessage(Defines.ERROR_SIGNEDDOC);
                return response;
            }

            XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

            boolean isMatchSerialNumer = false;

            for (int i = 0; i < nl.getLength(); i++) {
                boolean isSignatureValid = false;
                KeyInfoKeySelector keySelector = new KeyInfoKeySelector();

                DOMValidateContext valContext = new DOMValidateContext(keySelector, nl.item(i));

                XMLSignature signature = fac.unmarshalXMLSignature(valContext);

                isSignatureValid = signature.validate(valContext);

                Date signingTime = null;
                List<TimeStampToken> timeStampTokenList = new ArrayList<TimeStampToken>();
                getTimestampToken(nl.item(i), timeStampTokenList);
                if (timeStampTokenList.size() != 0) {
                    // no check TSA
//                    TSAVerifier tsaVerifier = new TSAVerifier();
//                    TSAVerifierResp tsaVerifierResp = tsaVerifier.verify(this.channelName, this.user, timeStampTokenList.get(0), trustedhubTransId);
//                    if (tsaVerifierResp.getResponseCode() != Defines.CODE_SUCCESS) {
//                        response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
//                        response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
//                        return response;
//                    }
                    signingTime = timeStampTokenList.get(0).getTimeStampInfo().getGenTime();
                } else {
                    List<Date> result = new ArrayList();
                    getSigningTime(nl.item(i), this.signingTimeTag, this.datePattern, result);
                    if (result.size() > 0) {
                        signingTime = result.get(0);
                    }
                }

                X509Certificate cert = null;
                X509Certificate[] certChain = keySelector.getCertChain();

                for (int j = 0; j < certChain.length; j++) {
                    if (!ExtFunc.isCACertificate(certChain[j])) {
                        cert = certChain[j];
                        break;
                    }
                }

                if (cert == null) {
                    response.setResponseCode(Defines.CODE_NOX509ELEMENT);
                    response.setResponseMessage(Defines.ERROR_NOX509ELEMENT);
                    continue;
                }

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
                    response.setResponseCode(Defines.CODE_INVALIDISSUERCERT);
                    response.setResponseMessage(Defines.ERROR_INVALIDISSUERCERT);
                    return response;
                }


                if (serialNumber != null) {
                    BigInteger serialNo = new BigInteger(serialNumber, 16);
                    if (cert.getSerialNumber().compareTo(serialNo) == 0) {
                        isMatchSerialNumer = true;
                    }

                    if (signingTime != null) {
                        try {
                            cert.checkValidity(signingTime);
                        } catch (CertificateExpiredException ex) {
                            LOG.error("Certificate has been expired");
                            response.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                            response.setResponseMessage(Defines.ERROR_INVALIDCERTIFICATE);
                            return response;
                        } catch (CertificateNotYetValidException ex) {
                            LOG.error("Certificate is not valid yet");
                            response.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                            response.setResponseMessage(Defines.ERROR_INVALIDCERTIFICATE);
                            return response;
                        }
                    }

                    SignerInfoResponse signerInfoRes = new SignerInfoResponse(DatatypeConverter.printBase64Binary(cert.getEncoded()), cert.getSerialNumber().toString(16), ExtFunc.getCNFromDN(cert.getIssuerDN().getName()), ExtFunc.getCNFromDN(cert.getSubjectDN().getName()), cert.getNotBefore(),
                            cert.getNotAfter());
                    signerInfoRes.setSigningTime(signingTime);

                    switch (methodValidateCert) {
                        case 0:
                            LOG.info("Only signature validation");
                            if (isSignatureValid) {
                                // i signature is valid
                                listSignerInfoResponse.add(signerInfoRes);
                                continue;
                            } else {
                                response.setResponseCode(Defines.CODE_INVALIDSIGNATURE);
                                response.setResponseMessage(Defines.ERROR_INVALIDSIGNATURE);
                                return response;
                            }
                        case 1:
                            LOG.info("Signature validation and Certificate validation by CRL");
                            if (crlPath.compareTo("") != 0 && caCertificate.compareTo("") != 0) {
                                X509Certificate subX509 = cert;

                                X509Certificate caX509 = ExtFunc.convertToX509Cert(caCertificate);

                                boolean primaryCaX509 = true;

                                if (!ExtFunc.checkCertificateRelation(caX509, subX509)) {
                                    if (caCertificate2 == null
                                            || caCertificate2.compareTo("") != 0) {

                                        caX509 = ExtFunc.convertToX509Cert(caCertificate2);
                                        crlPath = crlPath2;
                                        ocspURL = ocspURL2;
                                        crlUrl = crlUrl2;
                                        primaryCaX509 = false;

                                        if (!ExtFunc.checkCertificateRelation(caX509, subX509)) {

                                            response.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                                            response.setResponseMessage(Defines.ERROR_INVALIDCERTIFICATE);
                                            return response;
                                        }
                                    } else {

                                        response.setResponseCode(Defines.CODE_INVALIDCAINFO);
                                        response.setResponseMessage(Defines.ERROR_INVALIDCAINFO);
                                        return response;
                                    }
                                }

                                CRLStatus CRLVarification = CRLChecking.getInstance().check(caX509, subX509, crlPath, crlUrl, primaryCaX509, false, endpointConfigId);

                                if (!isSignatureValid) {

                                    response.setResponseCode(Defines.CODE_INVALIDSIGNATURE);
                                    response.setResponseMessage(Defines.ERROR_INVALIDSIGNATURE);
                                    return response;
                                } else {
                                    if (!CRLVarification.getIsRevoked()) {
                                        // i signature is valid
                                        // go to i+1 signature
                                        listSignerInfoResponse.add(signerInfoRes);
                                        continue;
                                    } else {
                                        if (CRLVarification.getCertificateState().compareTo(
                                                CRLStatus.REVOKED) == 0) {
                                            if (signingTime != null) {
                                                java.util.Date revokingTime = CRLVarification.getRevokeDate();
                                                LOG.info("Certificate revoked. Revoked Date: " + revokingTime.toString());
                                                LOG.info("Signing Date: " + signingTime.toString());
                                                int checkDateAgain = ExtFunc.compareDate(signingTime, revokingTime);
                                                if (checkDateAgain == 1 || checkDateAgain == 0) {
                                                    // i signature is valid
                                                    // go to i+1 signature
                                                    listSignerInfoResponse.add(signerInfoRes);
                                                    continue;
                                                } else {
                                                    response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_REVOKED);
                                                    response.setResponseMessage(Defines.INFO_CERTIFICATE_REVOKED);
                                                    return response;
                                                }
                                            } else {
                                                response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_REVOKED);
                                                response.setResponseMessage(Defines.INFO_CERTIFICATE_REVOKED);
                                                return response;
                                            }
                                        } else {
                                            LOG.error("Error while checking certificate status");
                                            response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_ERROR);
                                            response.setResponseMessage(Defines.INFO_CERTIFICATE_ERROR);
                                            return response;
                                        }
                                    }
                                }
                            } else {

                                response.setResponseCode(Defines.CODE_INVALIDCAINFO);
                                response.setResponseMessage(Defines.ERROR_INVALIDCAINFO);
                                return response;
                            }
                        case 2:
                            LOG.info("Signature validation and Certificate validation by OCSP");
                            if (ocspURL.compareTo("") != 0 && caCertificate.compareTo("") != 0) {
                                X509Certificate subX509 = cert;

                                X509Certificate caX509 = ExtFunc.convertToX509Cert(caCertificate);

                                if (!ExtFunc.checkCertificateRelation(caX509, subX509)) {
                                    if (caCertificate2 == null || caCertificate2.compareTo("") != 0) {

                                        caX509 = ExtFunc.convertToX509Cert(caCertificate2);

                                        crlPath = crlPath2;
                                        ocspURL = ocspURL2;
                                        crlUrl = crlUrl2;

                                        if (!ExtFunc.checkCertificateRelation(caX509, subX509)) {
                                            response.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                                            response.setResponseMessage(Defines.ERROR_INVALIDCERTIFICATE);
                                            return response;
                                        }
                                    } else {
                                        response.setResponseCode(Defines.CODE_INVALIDCAINFO);
                                        response.setResponseMessage(Defines.ERROR_INVALIDCAINFO);
                                        return response;
                                    }
                                }

                                boolean ocspStatus = false;
                                OcspStatus ocsp_status = OCSPChecking.getInstance().check(channelName, user, ocspURL, subX509, caX509, retryNumber, endpointConfigId, trustedhubTransId);
                                ocspStatus = ocsp_status.getIsValid();

                                if (!isSignatureValid) {
                                    response.setResponseCode(Defines.CODE_INVALIDSIGNATURE);
                                    response.setResponseMessage(Defines.ERROR_INVALIDSIGNATURE);
                                    return response;
                                } else {
                                    if (ocspStatus) {
                                        // i signature is valid
                                        listSignerInfoResponse.add(signerInfoRes);
                                        continue;
                                    } else {
                                        if (ocsp_status.getCertificateState().compareTo(OcspStatus.REVOKED) == 0) {
                                            java.util.Date revokingTime = ocsp_status.getRevokeDate();
                                            LOG.info("Certificate revoked. Revoked Date: " + revokingTime.toString());
                                            LOG.info("Signing Date: " + signingTime.toString());
                                            int checkDateAgain = ExtFunc.compareDate(signingTime, revokingTime);
                                            if (checkDateAgain == 1 || checkDateAgain == 0) {
                                                // i signature is valid
                                                listSignerInfoResponse.add(signerInfoRes);
                                                continue;
                                            } else {
                                                response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_REVOKED);
                                                response.setResponseMessage(Defines.INFO_CERTIFICATE_REVOKED);
                                                return response;
                                            }
                                        } else if (ocsp_status.getCertificateState().compareTo(OcspStatus.UNKNOWN) == 0) {
                                            response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_UNKNOWN);
                                            response.setResponseMessage(Defines.INFO_CERTIFICATE_UNKNOWN);
                                            return response;
                                        } else {
                                            response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_ERROR);
                                            response.setResponseMessage(Defines.INFO_CERTIFICATE_ERROR);
                                            return response;
                                        }
                                    }
                                }
                            } else {
                                response.setResponseCode(Defines.CODE_INVALIDCAINFO);
                                response.setResponseMessage(Defines.ERROR_INVALIDCAINFO);
                                return response;
                            }
                        default:
                            LOG.info("Signature validation and Certificate validation by OCSP (CRL if OCSP failure)");
                            if (crlPath.compareTo("") != 0 && ocspURL.compareTo("") != 0 && caCertificate.compareTo("") != 0) {
                                X509Certificate subX509 = cert;

                                X509Certificate caX509 = ExtFunc.convertToX509Cert(caCertificate);

                                boolean primaryCaX509 = true;

                                if (!ExtFunc.checkCertificateRelation(caX509, subX509)) {
                                    if (caCertificate2 == null || caCertificate2.compareTo("") != 0) {

                                        caX509 = ExtFunc.convertToX509Cert(caCertificate2);

                                        crlPath = crlPath2;
                                        ocspURL = ocspURL2;
                                        crlUrl = crlUrl2;
                                        primaryCaX509 = false;

                                        if (!ExtFunc.checkCertificateRelation(caX509, subX509)) {
                                            response.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                                            response.setResponseMessage(Defines.ERROR_INVALIDCERTIFICATE);
                                            return response;
                                        }
                                    } else {
                                        response.setResponseCode(Defines.CODE_INVALIDCAINFO);
                                        response.setResponseMessage(Defines.ERROR_INVALIDCAINFO);
                                        return response;
                                    }
                                }

                                boolean ocspStatus = false;
                                boolean crlStatus = false;
                                OcspStatus ocsp_status = OCSPChecking.getInstance().check(channelName, user, ocspURL, subX509, caX509, retryNumber, endpointConfigId, trustedhubTransId);
                                if (ocsp_status.getCertificateState().equals(OcspStatus.ERROR)) {
                                    //isCRLCheck = true;
                                    CRLStatus CRLVarification = CRLChecking.getInstance().check(caX509, subX509, crlPath, crlUrl, primaryCaX509, false, endpointConfigId);
                                    if (!isSignatureValid) {
                                        response.setResponseCode(Defines.CODE_INVALIDSIGNATURE);
                                        response.setResponseMessage(Defines.ERROR_INVALIDSIGNATURE);
                                        return response;
                                    } else {
                                        if (!CRLVarification.getIsRevoked()) {
                                            // i signature is valid
                                            listSignerInfoResponse.add(signerInfoRes);
                                            continue;
                                        } else {
                                            if (CRLVarification.getCertificateState().compareTo(CRLStatus.REVOKED) == 0) {
                                                java.util.Date revokingTime = CRLVarification.getRevokeDate();
                                                int checkDateAgain = ExtFunc.compareDate(signingTime, revokingTime);

                                                if (checkDateAgain == 1 || checkDateAgain == 0) {
                                                    // i signature is valid
                                                    listSignerInfoResponse.add(signerInfoRes);
                                                    continue;
                                                } else {
                                                    response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_REVOKED);
                                                    response.setResponseMessage(Defines.INFO_CERTIFICATE_REVOKED);
                                                    return response;
                                                }

                                            } else {
                                                response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_ERROR);
                                                response.setResponseMessage(Defines.INFO_CERTIFICATE_ERROR);
                                                return response;
                                            }
                                        }
                                    }
                                } else {
                                    ocspStatus = ocsp_status.getIsValid();
                                    if (!isSignatureValid) {
                                        response.setResponseCode(Defines.CODE_INVALIDSIGNATURE);
                                        response.setResponseMessage(Defines.ERROR_INVALIDSIGNATURE);
                                        return response;
                                    } else {
                                        if (ocspStatus) {
                                            // i signature is valid
                                            listSignerInfoResponse.add(signerInfoRes);
                                            continue;
                                        } else {
                                            if (ocsp_status.getCertificateState().compareTo(OcspStatus.REVOKED) == 0) {
                                                java.util.Date revokingTime = ocsp_status.getRevokeDate();
                                                LOG.info("Certificate revoked. Revoked Date: " + revokingTime.toString());
                                                LOG.info("Signing Date: " + signingTime.toString());
                                                int checkDateAgain = ExtFunc.compareDate(signingTime, revokingTime);
                                                if (checkDateAgain == 1 || checkDateAgain == 0) {
                                                    // i signature is valid
                                                    listSignerInfoResponse.add(signerInfoRes);
                                                    continue;
                                                } else {
                                                    response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_REVOKED);
                                                    response.setResponseMessage(Defines.INFO_CERTIFICATE_REVOKED);
                                                    return response;
                                                }
                                            } else if (ocsp_status.getCertificateState().compareTo(OcspStatus.UNKNOWN) == 0) {
                                                response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_UNKNOWN);
                                                response.setResponseMessage(Defines.INFO_CERTIFICATE_UNKNOWN);
                                                return response;
                                            } else {
                                                response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_ERROR);
                                                response.setResponseMessage(Defines.INFO_CERTIFICATE_ERROR);
                                                return response;
                                            }
                                        }
                                    }
                                }
                            } else {
                                response.setResponseCode(Defines.CODE_INVALIDCAINFO);
                                response.setResponseMessage(Defines.ERROR_INVALIDCAINFO);
                                return response;
                            }
                    } // end switch
                    //
                } else {
                    //GeneralValidator
                    isMatchSerialNumer = true;
                    if (signingTime != null) {
                        try {
                            cert.checkValidity(signingTime);
                        } catch (CertificateExpiredException ex) {
                            LOG.error("Certificate has been expired");
                            response.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                            response.setResponseMessage(Defines.ERROR_INVALIDCERTIFICATE);
                            return response;
                        } catch (CertificateNotYetValidException ex) {
                            LOG.error("Certificate is not valid yet");
                            response.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                            response.setResponseMessage(Defines.ERROR_INVALIDCERTIFICATE);
                            return response;
                        }
                    }

                    SignerInfoResponse signerInfoRes = new SignerInfoResponse(DatatypeConverter.printBase64Binary(cert.getEncoded()), cert.getSerialNumber().toString(16), ExtFunc.getCNFromDN(cert.getIssuerDN().getName()), ExtFunc.getCNFromDN(cert.getSubjectDN().getName()), cert.getNotBefore(),
                            cert.getNotAfter());
                    signerInfoRes.setSigningTime(signingTime);

                    List<OwnerInfo> ownerInfos = DBConnector.getInstances().authGetAgreementValidation(
                            ExtFunc.getThumbPrint(DatatypeConverter.printBase64Binary(cert.getEncoded())), signingTime);

                    if (ownerInfos != null) {
                        signerInfoRes.setOwnerInfos(ownerInfos);
                    }

                    switch (methodValidateCert) {
                        case 0:
                            LOG.info("Only signature validation");
                            if (isSignatureValid) {
                                // i signature is valid
                                listSignerInfoResponse.add(signerInfoRes);
                                continue;
                            } else {
                                response.setResponseCode(Defines.CODE_INVALIDSIGNATURE);
                                response.setResponseMessage(Defines.ERROR_INVALIDSIGNATURE);
                                return response;
                            }
                        case 1:
                            LOG.info("Signature validation and Certificate validation by CRL");
                            if (crlPath.compareTo("") != 0 && caCertificate.compareTo("") != 0) {
                                X509Certificate subX509 = cert;

                                X509Certificate caX509 = ExtFunc.convertToX509Cert(caCertificate);

                                boolean primaryCaX509 = true;

                                if (!ExtFunc.checkCertificateRelation(caX509, subX509)) {
                                    if (caCertificate2 == null
                                            || caCertificate2.compareTo("") != 0) {

                                        caX509 = ExtFunc.convertToX509Cert(caCertificate2);
                                        crlPath = crlPath2;
                                        ocspURL = ocspURL2;
                                        crlUrl = crlUrl2;
                                        primaryCaX509 = false;

                                        if (!ExtFunc.checkCertificateRelation(caX509, subX509)) {

                                            response.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                                            response.setResponseMessage(Defines.ERROR_INVALIDCERTIFICATE);
                                            return response;
                                        }
                                    } else {

                                        response.setResponseCode(Defines.CODE_INVALIDCAINFO);
                                        response.setResponseMessage(Defines.ERROR_INVALIDCAINFO);
                                        return response;
                                    }
                                }

                                CRLStatus CRLVarification = CRLChecking.getInstance().check(caX509, subX509, crlPath, crlUrl, primaryCaX509, false, endpointConfigId);

                                if (!isSignatureValid) {

                                    response.setResponseCode(Defines.CODE_INVALIDSIGNATURE);
                                    response.setResponseMessage(Defines.ERROR_INVALIDSIGNATURE);
                                    return response;
                                } else {
                                    if (!CRLVarification.getIsRevoked()) {
                                        // i signature is valid
                                        // go to i+1 signature
                                        listSignerInfoResponse.add(signerInfoRes);
                                        continue;
                                    } else {
                                        if (CRLVarification.getCertificateState().compareTo(
                                                CRLStatus.REVOKED) == 0) {
                                            if (signingTime != null) {
                                                java.util.Date revokingTime = CRLVarification.getRevokeDate();
                                                LOG.info("Certificate revoked. Revoked Date: " + revokingTime.toString());
                                                LOG.info("Signing Date: " + signingTime.toString());
                                                int checkDateAgain = ExtFunc.compareDate(
                                                        signingTime, revokingTime);
                                                if (checkDateAgain == 1 || checkDateAgain == 0) {
                                                    // i signature is valid
                                                    // go to i+1 signature
                                                    listSignerInfoResponse.add(signerInfoRes);
                                                    continue;
                                                } else {
                                                    response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_REVOKED);
                                                    response.setResponseMessage(Defines.INFO_CERTIFICATE_REVOKED);
                                                    return response;
                                                }
                                            } else {
                                                response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_REVOKED);
                                                response.setResponseMessage(Defines.INFO_CERTIFICATE_REVOKED);
                                                return response;
                                            }
                                        } else {
                                            LOG.error("Error while checking certificate status");
                                            response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_ERROR);
                                            response.setResponseMessage(Defines.INFO_CERTIFICATE_ERROR);
                                            return response;
                                        }
                                    }
                                }
                            } else {
                                response.setResponseCode(Defines.CODE_INVALIDCAINFO);
                                response.setResponseMessage(Defines.ERROR_INVALIDCAINFO);
                                return response;
                            }
                        case 2:
                            LOG.info("Signature validation and Certificate validation by OCSP");
                            if (ocspURL.compareTo("") != 0 && caCertificate.compareTo("") != 0) {
                                X509Certificate subX509 = cert;

                                X509Certificate caX509 = ExtFunc.convertToX509Cert(caCertificate);

                                if (!ExtFunc.checkCertificateRelation(caX509, subX509)) {
                                    if (caCertificate2 == null || caCertificate2.compareTo("") != 0) {

                                        caX509 = ExtFunc.convertToX509Cert(caCertificate2);

                                        crlPath = crlPath2;
                                        ocspURL = ocspURL2;
                                        crlUrl = crlUrl2;

                                        if (!ExtFunc.checkCertificateRelation(caX509, subX509)) {
                                            response.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                                            response.setResponseMessage(Defines.ERROR_INVALIDCERTIFICATE);
                                            return response;
                                        }
                                    } else {
                                        response.setResponseCode(Defines.CODE_INVALIDCAINFO);
                                        response.setResponseMessage(Defines.ERROR_INVALIDCAINFO);
                                        return response;
                                    }
                                }

                                boolean ocspStatus = false;
                                OcspStatus ocsp_status = OCSPChecking.getInstance().check(channelName, user, ocspURL, subX509, caX509, retryNumber, endpointConfigId, trustedhubTransId);
                                ocspStatus = ocsp_status.getIsValid();

                                if (!isSignatureValid) {
                                    response.setResponseCode(Defines.CODE_INVALIDSIGNATURE);
                                    response.setResponseMessage(Defines.ERROR_INVALIDSIGNATURE);
                                    return response;
                                } else {
                                    if (ocspStatus) {
                                        // i signature is valid
                                        listSignerInfoResponse.add(signerInfoRes);
                                        continue;
                                    } else {
                                        if (ocsp_status.getCertificateState().compareTo(OcspStatus.REVOKED) == 0) {
                                            java.util.Date revokingTime = ocsp_status.getRevokeDate();
                                            LOG.info("Certificate revoked. Revoked Date: " + revokingTime.toString());
                                            LOG.info("Signing Date: " + signingTime.toString());
                                            int checkDateAgain = ExtFunc.compareDate(signingTime, revokingTime);
                                            if (checkDateAgain == 1 || checkDateAgain == 0) {
                                                // i signature is valid
                                                listSignerInfoResponse.add(signerInfoRes);
                                                continue;
                                            } else {
                                                response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_REVOKED);
                                                response.setResponseMessage(Defines.INFO_CERTIFICATE_REVOKED);
                                                return response;
                                            }
                                        } else if (ocsp_status.getCertificateState().compareTo(OcspStatus.UNKNOWN) == 0) {
                                            response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_UNKNOWN);
                                            response.setResponseMessage(Defines.INFO_CERTIFICATE_UNKNOWN);
                                            return response;
                                        } else {
                                            response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_ERROR);
                                            response.setResponseMessage(Defines.INFO_CERTIFICATE_ERROR);
                                            return response;
                                        }
                                    }
                                }
                            } else {
                                response.setResponseCode(Defines.CODE_INVALIDCAINFO);
                                response.setResponseMessage(Defines.ERROR_INVALIDCAINFO);
                                return response;
                            }
                        default:
                            LOG.info("Signature validation and Certificate validation by OCSP (CRL if OCSP failure)");
                            if (crlPath.compareTo("") != 0 && ocspURL.compareTo("") != 0 && caCertificate.compareTo("") != 0) {
                                X509Certificate subX509 = cert;

                                X509Certificate caX509 = ExtFunc.convertToX509Cert(caCertificate);

                                boolean primaryCaX509 = true;

                                if (!ExtFunc.checkCertificateRelation(caX509, subX509)) {
                                    if (caCertificate2 == null || caCertificate2.compareTo("") != 0) {

                                        caX509 = ExtFunc.convertToX509Cert(caCertificate2);

                                        crlPath = crlPath2;
                                        ocspURL = ocspURL2;
                                        crlUrl = crlUrl2;
                                        primaryCaX509 = false;

                                        if (!ExtFunc.checkCertificateRelation(caX509, subX509)) {
                                            response.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                                            response.setResponseMessage(Defines.ERROR_INVALIDCERTIFICATE);
                                            return response;
                                        }
                                    } else {
                                        response.setResponseCode(Defines.CODE_INVALIDCAINFO);
                                        response.setResponseMessage(Defines.ERROR_INVALIDCAINFO);
                                        return response;
                                    }
                                }

                                boolean ocspStatus = false;
                                boolean crlStatus = false;
                                OcspStatus ocsp_status = OCSPChecking.getInstance().check(channelName, user, ocspURL, subX509, caX509, retryNumber, endpointConfigId, trustedhubTransId);
                                if (ocsp_status.getCertificateState().equals(OcspStatus.ERROR)) {
                                    //isCRLCheck = true;
                                    CRLStatus CRLVarification = CRLChecking.getInstance().check(caX509, subX509, crlPath, crlUrl, primaryCaX509, false, endpointConfigId);
                                    if (!isSignatureValid) {
                                        response.setResponseCode(Defines.CODE_INVALIDSIGNATURE);
                                        response.setResponseMessage(Defines.ERROR_INVALIDSIGNATURE);
                                        return response;
                                    } else {
                                        if (!CRLVarification.getIsRevoked()) {
                                            // i signature is valid
                                            listSignerInfoResponse.add(signerInfoRes);
                                            continue;
                                        } else {
                                            if (CRLVarification.getCertificateState().compareTo(CRLStatus.REVOKED) == 0) {
                                                java.util.Date revokingTime = CRLVarification.getRevokeDate();
                                                int checkDateAgain = ExtFunc.compareDate(signingTime, revokingTime);

                                                if (checkDateAgain == 1 || checkDateAgain == 0) {
                                                    // i signature is valid
                                                    listSignerInfoResponse.add(signerInfoRes);
                                                    continue;
                                                } else {
                                                    response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_REVOKED);
                                                    response.setResponseMessage(Defines.INFO_CERTIFICATE_REVOKED);
                                                    return response;
                                                }

                                            } else {
                                                response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_ERROR);
                                                response.setResponseMessage(Defines.INFO_CERTIFICATE_ERROR);
                                                return response;
                                            }
                                        }
                                    }
                                } else {
                                    ocspStatus = ocsp_status.getIsValid();
                                    if (!isSignatureValid) {
                                        response.setResponseCode(Defines.CODE_INVALIDSIGNATURE);
                                        response.setResponseMessage(Defines.ERROR_INVALIDSIGNATURE);
                                        return response;
                                    } else {
                                        if (ocspStatus) {
                                            // i signature is valid
                                            listSignerInfoResponse.add(signerInfoRes);
                                            continue;
                                        } else {
                                            if (ocsp_status.getCertificateState().compareTo(OcspStatus.REVOKED) == 0) {
                                                java.util.Date revokingTime = ocsp_status.getRevokeDate();
                                                LOG.info("Certificate revoked. Revoked Date: " + revokingTime.toString());
                                                LOG.info("Signing Date: " + signingTime.toString());
                                                int checkDateAgain = ExtFunc.compareDate(signingTime, revokingTime);
                                                if (checkDateAgain == 1 || checkDateAgain == 0) {
                                                    // i signature is valid
                                                    listSignerInfoResponse.add(signerInfoRes);
                                                    continue;
                                                } else {
                                                    response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_REVOKED);
                                                    response.setResponseMessage(Defines.INFO_CERTIFICATE_REVOKED);
                                                    return response;
                                                }
                                            } else if (ocsp_status.getCertificateState().compareTo(OcspStatus.UNKNOWN) == 0) {
                                                response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_UNKNOWN);
                                                response.setResponseMessage(Defines.INFO_CERTIFICATE_UNKNOWN);
                                                return response;
                                            } else {
                                                response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_ERROR);
                                                response.setResponseMessage(Defines.INFO_CERTIFICATE_ERROR);
                                                return response;
                                            }
                                        }
                                    }
                                }
                            } else {
                                response.setResponseCode(Defines.CODE_INVALIDCAINFO);
                                response.setResponseMessage(Defines.ERROR_INVALIDCAINFO);
                                return response;
                            }
                    } // end switch

                } // end if-else serialNumber null or not
            } // end for signature

            if (!isMatchSerialNumer && serialNumber != null) {
                response.setResponseCode(Defines.CODE_INVALIDCERTSERIAL);
                response.setResponseMessage(Defines.ERROR_INVALIDCERTSERIAL);
                return response;
            }

            // all signature valid
            response.setListSignerInfoResponse(listSignerInfoResponse);
            response.setResponseCode(Defines.CODE_SUCCESS);
            response.setResponseMessage(Defines.SUCCESS);
            return response;

        } catch (Exception e) {
            e.printStackTrace();
            response.setResponseCode(Defines.CODE_INVALIDSIGNATURE);
            response.setResponseMessage(Defines.ERROR_INVALIDSIGNATURE);
            return response;
        }
    }

    public MultiValidatorResponse verify(byte[] data, String password, String serialNumber, ArrayList<Ca> caProviders, int trustedhubTransId) {
        // Not override yet
        return null;
    }

    private void getSigningTime(Node node, String signingTimeTag, String pattern, List<Date> result) {
        Date signingTime = null;
        try {
            if (node.getNodeName().contains(signingTimeTag)) {
                String value = node.getTextContent();
                SimpleDateFormat sdf = null;
                try {
                    sdf = new SimpleDateFormat(pattern);
                    signingTime = sdf.parse(value);
                } catch (ParseException e) {
                    try {
                        sdf = new SimpleDateFormat(DEFAULT_DATE_PATTERN_SECOND);
                        signingTime = sdf.parse(value);
                    } catch (ParseException ex) {
                        ex.printStackTrace();
                    }
                }
                result.add(signingTime);
            }
            NodeList nodeList = node.getChildNodes();
            for (int i = 0; i < nodeList.getLength(); i++) {
                Node currentNode = nodeList.item(i);
                if (currentNode.getNodeType() == Node.ELEMENT_NODE) {
                    getSigningTime(currentNode, signingTimeTag, pattern, result);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void getTimestampToken(Node node, List<TimeStampToken> timeStampTokenList) {
        try {
            if (node.getNodeName().contains(DEFAULT_TIMESTAMP_TAG)) {
                String value = node.getTextContent();
                TimeStampToken timeStampToken = new TimeStampToken(new CMSSignedData(DatatypeConverter.parseBase64Binary(value)));
                timeStampTokenList.add(timeStampToken);
            }
            NodeList nodeList = node.getChildNodes();
            for (int i = 0; i < nodeList.getLength(); i++) {
                Node currentNode = nodeList.item(i);
                if (currentNode.getNodeType() == Node.ELEMENT_NODE) {
                    getTimestampToken(currentNode, timeStampTokenList);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static class KeyInfoKeySelector extends KeySelector implements KeySelectorResult {

        private X509Certificate certificate;
        private X509Certificate[] certChain;

        @Override
        public KeySelectorResult select(KeyInfo keyInfo,
                KeySelector.Purpose purpose, AlgorithmMethod method,
                XMLCryptoContext context) throws KeySelectorException {
            ArrayList certList = new ArrayList();
            if (null == keyInfo) {
                throw new KeySelectorException("no ds:KeyInfo present");
            }
            List<XMLStructure> keyInfoContent = keyInfo.getContent();
            this.certificate = null;
            for (XMLStructure keyInfoStructure : keyInfoContent) {
                if (false == (keyInfoStructure instanceof X509Data)) {
                    continue;
                }
                X509Data x509Data = (X509Data) keyInfoStructure;
                List<Object> x509DataList = x509Data.getContent();
                for (Object x509DataObject : x509DataList) {
                    if (false == (x509DataObject instanceof X509Certificate)) {
                        continue;
                    }
                    certList.add(x509DataObject);
                }
                if (!certList.isEmpty()) {
                    this.certChain = (X509Certificate[]) certList.toArray(new X509Certificate[0]);
                    this.certificate = (X509Certificate) this.certChain[0];
                    return this;
                }
            }
            throw new KeySelectorException("No key found!");
        }

        @Override
        public Key getKey() {
            return this.certificate.getPublicKey();
        }

        /**
         * Gives back the X509 certificate used during the last signature
         * verification operation.
         *
         * @return
         */
        public X509Certificate getCertificate() {
            return this.certificate;
        }

        public X509Certificate[] getCertChain() {
            return certChain;
        }
    }
}