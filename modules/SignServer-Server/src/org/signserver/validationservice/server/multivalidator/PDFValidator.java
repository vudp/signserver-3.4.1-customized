package org.signserver.validationservice.server.multivalidator;

import org.signserver.common.*;
import org.signserver.common.util.*;
import org.signserver.common.dbdao.*;
import java.math.BigInteger;
import java.security.Security;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.PdfPKCS7;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampToken;
import java.util.*;

import org.apache.log4j.Logger;
import org.signserver.validationservice.server.*;

public class PDFValidator implements MultiValidatorInterface {

    private static final Logger LOG = Logger.getLogger(PDFValidator.class);
    private String user;
    private String channelName;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public PDFValidator(String channelName, String user) {
        this.channelName = channelName;
        this.user = user;
    }

    public MultiValidatorResponse verify(
            byte[] data,
            String serialNumber,
            ArrayList<Ca> caProviders,
            int trustedhubTransId) {
        // Not override yet
        return null;
    }

    public MultiValidatorResponse verify(
            byte[] data,
            String password,
            String serialNumber,
            ArrayList<Ca> caProviders,
            int trustedhubTransId) {
        MultiValidatorResponse response = new MultiValidatorResponse();
        List<SignerInfoResponse> listSignerInfoResponse = new ArrayList<SignerInfoResponse>();
        try {
            PdfReader reader = new PdfReader(data, (password != null) ? password.getBytes() : null);
            AcroFields af = reader.getAcroFields();
            ArrayList<String> names = af.getSignatureNames();
            if (names.size() != 0) {
                boolean isMatchSerialNumer = false;
                for (String name : names) {
                    boolean isSignatureValid = false;
                    PdfPKCS7 pk = af.verifySignature(name);
                    isSignatureValid = isSignatureValid || pk.verify();
                    X509Certificate cert = pk.getSigningCertificate();
                    Date signingTime = pk.getSignDate().getTime();

                    TimeStampToken timestampToken = pk.getTimeStampToken();
                    timestampToken = null; // disable TSA check

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
                        if (serialNo.compareTo(cert.getSerialNumber()) == 0) {
                            isMatchSerialNumer = true;
                            try {
                                cert.checkValidity(signingTime);
                            } catch (CertificateExpiredException ex) {

                                response.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                                response.setResponseMessage(Defines.ERROR_INVALIDCERTIFICATE);
                                return response;

                            } catch (CertificateNotYetValidException ex) {

                                response.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                                response.setResponseMessage(Defines.ERROR_INVALIDCERTIFICATE);
                                return response;
                            }

                            if (timestampToken != null) {
                                TSAVerifier tsaVerifier = new TSAVerifier();
                                TSAVerifierResp tsaVerifierResp = tsaVerifier.verify(this.channelName, this.user, timestampToken, trustedhubTransId);
                                if (tsaVerifierResp.getResponseCode() != Defines.CODE_SUCCESS) {
                                    response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
                                    response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
                                    return response;
                                }
                            }

                            SignerInfoResponse signerInfoRes = new SignerInfoResponse(DatatypeConverter.printBase64Binary(cert.getEncoded()), cert.getSerialNumber().toString(16), ExtFunc.getCNFromDN(cert.getIssuerDN().getName()), ExtFunc.getCNFromDN(cert.getSubjectDN().getName()), cert.getNotBefore(),
                                    cert.getNotAfter());
                            signerInfoRes.setSigningTime(signingTime);

                            switch (methodValidateCert) {
                                case 0: //Only signature
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
                                    //--------------------
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

                                        CRLStatus CRLVarification = CRLChecking.getInstance().check(
                                                caX509,
                                                subX509,
                                                crlPath,
                                                crlUrl,
                                                primaryCaX509,
                                                false,
                                                endpointConfigId);

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
                                //--------------------
                                case 2: //Signature and Cert via OCSP
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
                                        OcspStatus ocsp_status = OCSPChecking.getInstance().check(
                                                channelName,
                                                user,
                                                ocspURL,
                                                subX509,
                                                caX509,
                                                retryNumber,
                                                endpointConfigId,
                                                trustedhubTransId);
                                        if (ocsp_status.getCertificateState().equals(OcspStatus.ERROR)) {
                                            //isCRLCheck = true;
                                            CRLStatus CRLVarification = CRLChecking.getInstance().check(
                                                    caX509,
                                                    subX509,
                                                    crlPath,
                                                    crlUrl,
                                                    primaryCaX509,
                                                    false,
                                                    endpointConfigId);
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
                            }
                        } else {
                            continue;
                        }
                    } else {
                        // GeneralValidator
                        isMatchSerialNumer = true;
                        try {
                            cert.checkValidity(signingTime);
                        } catch (CertificateExpiredException ex) {

                            response.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                            response.setResponseMessage(Defines.ERROR_INVALIDCERTIFICATE);
                            return response;

                        } catch (CertificateNotYetValidException ex) {

                            response.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                            response.setResponseMessage(Defines.ERROR_INVALIDCERTIFICATE);
                            return response;
                        }

                        if (timestampToken != null) {
                            TSAVerifier tsaVerifier = new TSAVerifier();
                            TSAVerifierResp tsaVerifierResp = tsaVerifier.verify(this.channelName, this.user, timestampToken, trustedhubTransId);
                            if (tsaVerifierResp.getResponseCode() != Defines.CODE_SUCCESS) {
                                response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
                                response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
                                return response;
                            }
                        }

                        SignerInfoResponse signerInfoRes = new SignerInfoResponse(
                                DatatypeConverter.printBase64Binary(cert.getEncoded()), cert.getSerialNumber().toString(16), ExtFunc.getCNFromDN(cert.getIssuerDN().getName()), ExtFunc.getCNFromDN(cert.getSubjectDN().getName()), cert.getNotBefore(),
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
                        }
                    } // end if-else serialNumber null or not
                } // end for multiple signatures
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
            } else {
                response.setResponseCode(Defines.CODE_SIGNEDDOC);
                response.setResponseMessage(Defines.ERROR_SIGNEDDOC);
                return response;
            }
        } catch (Exception e) {
            e.printStackTrace();
            response.setResponseCode(Defines.CODE_INVALIDSIGNATURE);
            response.setResponseMessage(Defines.ERROR_INVALIDSIGNATURE);
            return response;
        }
    }
}