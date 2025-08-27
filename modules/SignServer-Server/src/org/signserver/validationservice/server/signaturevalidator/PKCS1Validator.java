package org.signserver.validationservice.server.signaturevalidator;

import java.security.*;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.xml.bind.DatatypeConverter;

import java.util.List;

import org.apache.log4j.Logger;
import org.signserver.validationservice.server.*;
import org.signserver.common.*;
import org.signserver.common.util.*;
import org.signserver.common.dbdao.*;

public class PKCS1Validator implements SignatureValidatorInterface {

    private static final Logger LOG = Logger.getLogger(PKCS1Validator.class);

    public PKCS1Validator() {
    }

    public SignatureValidatorResponse verify(String channelName, String user, byte[] data, byte[] signature, String serialNumber, ArrayList<Ca> caProviders, int trustedhubTransId) {
        // Not implement yet
        return null;
    }

    public SignatureValidatorResponse verify(String channelName, String user, byte[] data, byte[] signature, String certificate, String serialNumber, ArrayList<Ca> caProviders, int trustedhubTransId) {
        SignatureValidatorResponse response = new SignatureValidatorResponse();
        List<SignerInfoResponse> listSignerInfoResponse = new ArrayList<SignerInfoResponse>();
        try {
            X509Certificate x509 = ExtFunc.convertToX509Cert(certificate);

            String authorityKeyIdentifier = ExtFunc.getIssuerKeyIdentifier(x509);

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
                LOG.error("CA " + x509.getIssuerDN().toString() + " not found.");
                response.setResponseCode(Defines.CODE_INVALIDISSUERCERT);
                response.setResponseMessage(Defines.ERROR_INVALIDISSUERCERT);
                return response;
            }

            // signing time = current date
            java.util.Date signingTime = new java.util.Date();
            try {
                x509.checkValidity(signingTime);
            } catch (CertificateExpiredException ex) {
                response.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                response.setResponseMessage(Defines.ERROR_INVALIDCERTIFICATE);
                return response;
            } catch (CertificateNotYetValidException ex) {
                response.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                response.setResponseMessage(Defines.ERROR_INVALIDCERTIFICATE);
                return response;
            }

            SignerInfoResponse signerInfoRes = new SignerInfoResponse(
                    DatatypeConverter.printBase64Binary(x509.getEncoded()), x509.getSerialNumber().toString(16), ExtFunc.getCNFromDN(x509.getIssuerDN().getName()), ExtFunc.getCNFromDN(x509.getSubjectDN().getName()), x509.getNotBefore(), x509.getNotAfter());

            signerInfoRes.setSigningTime(signingTime);


            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(x509.getPublicKey());
            sig.update(data);
            boolean verificationResult = sig.verify(signature);

            switch (methodValidateCert) {
                case 0: //Only signature
                    LOG.info("Only signature validation");
                    if (verificationResult) {
                        // i signature is valid
                        listSignerInfoResponse.add(signerInfoRes);
                        response.setListSignerInfoResponse(listSignerInfoResponse);
                        response.setResponseCode(Defines.CODE_SUCCESS);
                        response.setResponseMessage(Defines.SUCCESS);
                        return response;
                    } else {
                        listSignerInfoResponse.add(signerInfoRes);
                        response.setListSignerInfoResponse(listSignerInfoResponse);
                        response.setResponseCode(Defines.CODE_INVALIDSIGNATURE);
                        response.setResponseMessage(Defines.ERROR_INVALIDSIGNATURE);
                        return response;
                    }
                case 1: //Signature and Cert via CRL
                    LOG.info("Signature validation and Certificate validation by CRL");
                    if (crlPath.compareTo("") != 0 && caCertificate.compareTo("") != 0) {
                        X509Certificate subX509 = x509;

                        X509Certificate caX509 = ExtFunc.convertToX509Cert(caCertificate);

                        boolean primaryCaX509 = true;

                        if (!ExtFunc.checkCertificateRelation(caX509, subX509)) {
                            if (caCertificate2 != null || caCertificate2.compareTo("") != 0) {

                                caX509 = ExtFunc.convertToX509Cert(caCertificate2);
                                crlPath = crlPath2;
                                ocspURL = ocspURL2;
                                crlUrl = crlUrl2;
                                primaryCaX509 = false;

                                if (!ExtFunc.checkCertificateRelation(caX509, subX509)) {
                                    listSignerInfoResponse.add(signerInfoRes);
                                    response.setListSignerInfoResponse(listSignerInfoResponse);
                                    response.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                                    response.setResponseMessage(Defines.ERROR_INVALIDCERTIFICATE);
                                    return response;
                                }
                            } else {
                                listSignerInfoResponse.add(signerInfoRes);
                                response.setListSignerInfoResponse(listSignerInfoResponse);
                                response.setResponseCode(Defines.CODE_INVALIDCAINFO);
                                response.setResponseMessage(Defines.ERROR_INVALIDCAINFO);
                                return response;
                            }
                        }

                        CRLStatus CRLVarification = CRLChecking.getInstance().check(caX509, subX509, crlPath, crlUrl, primaryCaX509, false, endpointConfigId);

                        if (!verificationResult) {
                            listSignerInfoResponse.add(signerInfoRes);
                            response.setListSignerInfoResponse(listSignerInfoResponse);
                            response.setResponseCode(Defines.CODE_INVALIDSIGNATURE);
                            response.setResponseMessage(Defines.ERROR_INVALIDSIGNATURE);
                            return response;
                        } else {
                            if (!CRLVarification.getIsRevoked()) {
                                // i signature is valid
                                listSignerInfoResponse.add(signerInfoRes);
                                response.setListSignerInfoResponse(listSignerInfoResponse);
                                response.setResponseCode(Defines.CODE_SUCCESS);
                                response.setResponseMessage(Defines.SUCCESS);
                                return response;
                            } else {
                                if (CRLVarification.getCertificateState().compareTo(CRLStatus.REVOKED) == 0) {
                                    java.util.Date revokingTime = CRLVarification.getRevokeDate();
                                    LOG.info("Certificate revoked. Revoked Date: " + revokingTime.toString());
                                    LOG.info("Signing Date: " + signingTime.toString());
                                    int checkDateAgain = ExtFunc.compareDate(signingTime, revokingTime);
                                    if (checkDateAgain == 1 || checkDateAgain == 0) {
                                        // i signature is valid
                                        listSignerInfoResponse.add(signerInfoRes);
                                        response.setListSignerInfoResponse(listSignerInfoResponse);
                                        response.setResponseCode(Defines.CODE_SUCCESS);
                                        response.setResponseMessage(Defines.SUCCESS);
                                        return response;
                                    } else {
                                        listSignerInfoResponse.add(signerInfoRes);
                                        response.setListSignerInfoResponse(listSignerInfoResponse);
                                        response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_REVOKED);
                                        response.setResponseMessage(Defines.INFO_CERTIFICATE_REVOKED);
                                        return response;
                                    }

                                } else {
                                    listSignerInfoResponse.add(signerInfoRes);
                                    response.setListSignerInfoResponse(listSignerInfoResponse);
                                    response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_ERROR);
                                    response.setResponseMessage(Defines.INFO_CERTIFICATE_ERROR);
                                    return response;
                                }
                            }
                        }
                    } else {
                        listSignerInfoResponse.add(signerInfoRes);
                        response.setListSignerInfoResponse(listSignerInfoResponse);
                        response.setResponseCode(Defines.CODE_INVALIDCAINFO);
                        response.setResponseMessage(Defines.ERROR_INVALIDCAINFO);
                        return response;
                    }
                case 2: //Signature and Cert via OCSP
                    LOG.info("Signature validation and Certificate validation by OCSP");
                    if (ocspURL.compareTo("") != 0 && caCertificate.compareTo("") != 0) {
                        X509Certificate subX509 = x509;

                        X509Certificate caX509 = ExtFunc.convertToX509Cert(caCertificate);

                        if (!ExtFunc.checkCertificateRelation(caX509, subX509)) {
                            if (caCertificate2 == null || caCertificate2.compareTo("") != 0) {

                                caX509 = ExtFunc.convertToX509Cert(caCertificate2);

                                crlPath = crlPath2;
                                ocspURL = ocspURL2;
                                crlUrl = crlUrl2;

                                if (!ExtFunc.checkCertificateRelation(caX509, subX509)) {
                                    listSignerInfoResponse.add(signerInfoRes);
                                    response.setListSignerInfoResponse(listSignerInfoResponse);
                                    response.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                                    response.setResponseMessage(Defines.ERROR_INVALIDCERTIFICATE);
                                    return response;
                                }
                            } else {
                                listSignerInfoResponse.add(signerInfoRes);
                                response.setListSignerInfoResponse(listSignerInfoResponse);
                                response.setResponseCode(Defines.CODE_INVALIDCAINFO);
                                response.setResponseMessage(Defines.ERROR_INVALIDCAINFO);
                                return response;
                            }
                        }


                        boolean ocspStatus = false;
                        OcspStatus ocsp_status = OCSPChecking.getInstance().check(channelName, user, ocspURL, subX509, caX509, retryNumber, endpointConfigId, trustedhubTransId);
                        ocspStatus = ocsp_status.getIsValid();

                        if (!verificationResult) {

                            listSignerInfoResponse.add(signerInfoRes);
                            response.setListSignerInfoResponse(listSignerInfoResponse);
                            response.setResponseCode(Defines.CODE_INVALIDSIGNATURE);
                            response.setResponseMessage(Defines.ERROR_INVALIDSIGNATURE);
                            return response;
                        } else {
                            if (ocspStatus) {
                                // i signature is valid

                                listSignerInfoResponse.add(signerInfoRes);
                                response.setListSignerInfoResponse(listSignerInfoResponse);
                                response.setResponseCode(Defines.CODE_SUCCESS);
                                response.setResponseMessage(Defines.SUCCESS);
                                return response;
                            } else {
                                if (ocsp_status.getCertificateState().compareTo(OcspStatus.REVOKED) == 0) {
                                    java.util.Date revokingTime = ocsp_status.getRevokeDate();
                                    LOG.info("Certificate revoked. Revoked Date: " + revokingTime.toString());
                                    LOG.info("Signing Date: " + signingTime.toString());
                                    int checkDateAgain = ExtFunc.compareDate(signingTime, revokingTime);
                                    if (checkDateAgain == 1 || checkDateAgain == 0) {
                                        // i signature is valid

                                        listSignerInfoResponse.add(signerInfoRes);
                                        response.setListSignerInfoResponse(listSignerInfoResponse);
                                        response.setResponseCode(Defines.CODE_SUCCESS);
                                        response.setResponseMessage(Defines.SUCCESS);
                                        return response;
                                    } else {

                                        listSignerInfoResponse.add(signerInfoRes);
                                        response.setListSignerInfoResponse(listSignerInfoResponse);
                                        response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_REVOKED);
                                        response.setResponseMessage(Defines.INFO_CERTIFICATE_REVOKED);
                                        return response;
                                    }
                                } else if (ocsp_status.getCertificateState().compareTo(OcspStatus.UNKNOWN) == 0) {

                                    listSignerInfoResponse.add(signerInfoRes);
                                    response.setListSignerInfoResponse(listSignerInfoResponse);
                                    response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_UNKNOWN);
                                    response.setResponseMessage(Defines.INFO_CERTIFICATE_UNKNOWN);
                                    return response;
                                } else {

                                    listSignerInfoResponse.add(signerInfoRes);
                                    response.setListSignerInfoResponse(listSignerInfoResponse);
                                    response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_ERROR);
                                    response.setResponseMessage(Defines.INFO_CERTIFICATE_ERROR);
                                    return response;
                                }
                            }
                        }
                    } else {
                        listSignerInfoResponse.add(signerInfoRes);
                        response.setListSignerInfoResponse(listSignerInfoResponse);
                        response.setResponseCode(Defines.CODE_INVALIDCAINFO);
                        response.setResponseMessage(Defines.ERROR_INVALIDCAINFO);
                        return response;
                    }
                default: // Signature and OCSP, if OCSP failure check CRL
                    LOG.info("Signature validation and Certificate validation by OCSP (CRL if OCSP failure)");
                    if (crlPath.compareTo("") != 0 && ocspURL.compareTo("") != 0 && caCertificate.compareTo("") != 0) {
                        X509Certificate subX509 = x509;

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
                                    listSignerInfoResponse.add(signerInfoRes);
                                    response.setListSignerInfoResponse(listSignerInfoResponse);
                                    response.setResponseCode(Defines.CODE_INVALIDCERTIFICATE);
                                    response.setResponseMessage(Defines.ERROR_INVALIDCERTIFICATE);
                                    return response;
                                }
                            } else {
                                listSignerInfoResponse.add(signerInfoRes);
                                response.setListSignerInfoResponse(listSignerInfoResponse);
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
                            if (!verificationResult) {

                                listSignerInfoResponse.add(signerInfoRes);
                                response.setListSignerInfoResponse(listSignerInfoResponse);
                                response.setResponseCode(Defines.CODE_INVALIDSIGNATURE);
                                response.setResponseMessage(Defines.ERROR_INVALIDSIGNATURE);
                                return response;
                            } else {
                                if (!CRLVarification.getIsRevoked()) {
                                    // i signature is valid

                                    listSignerInfoResponse.add(signerInfoRes);
                                    response.setListSignerInfoResponse(listSignerInfoResponse);
                                    response.setResponseCode(Defines.CODE_SUCCESS);
                                    response.setResponseMessage(Defines.SUCCESS);
                                    return response;
                                } else {
                                    if (CRLVarification.getCertificateState().compareTo(CRLStatus.REVOKED) == 0) {
                                        java.util.Date revokingTime = CRLVarification.getRevokeDate();
                                        int checkDateAgain = ExtFunc.compareDate(signingTime, revokingTime);

                                        if (checkDateAgain == 1 || checkDateAgain == 0) {
                                            // i signature is valid

                                            listSignerInfoResponse.add(signerInfoRes);
                                            response.setListSignerInfoResponse(listSignerInfoResponse);
                                            response.setResponseCode(Defines.CODE_SUCCESS);
                                            response.setResponseMessage(Defines.SUCCESS);
                                            return response;
                                        } else {

                                            listSignerInfoResponse.add(signerInfoRes);
                                            response.setListSignerInfoResponse(listSignerInfoResponse);
                                            response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_REVOKED);
                                            response.setResponseMessage(Defines.INFO_CERTIFICATE_REVOKED);
                                            return response;
                                        }

                                    } else {

                                        listSignerInfoResponse.add(signerInfoRes);
                                        response.setListSignerInfoResponse(listSignerInfoResponse);
                                        response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_ERROR);
                                        response.setResponseMessage(Defines.INFO_CERTIFICATE_ERROR);
                                        return response;
                                    }
                                }
                            }
                        } else {
                            ocspStatus = ocsp_status.getIsValid();
                            if (!verificationResult) {

                                listSignerInfoResponse.add(signerInfoRes);
                                response.setListSignerInfoResponse(listSignerInfoResponse);
                                response.setResponseCode(Defines.CODE_INVALIDSIGNATURE);
                                response.setResponseMessage(Defines.ERROR_INVALIDSIGNATURE);
                                return response;
                            } else {
                                if (ocspStatus) {
                                    // i signature is valid

                                    listSignerInfoResponse.add(signerInfoRes);
                                    response.setListSignerInfoResponse(listSignerInfoResponse);
                                    response.setResponseCode(Defines.CODE_SUCCESS);
                                    response.setResponseMessage(Defines.SUCCESS);
                                    return response;
                                } else {
                                    if (ocsp_status.getCertificateState().compareTo(OcspStatus.REVOKED) == 0) {
                                        java.util.Date revokingTime = ocsp_status.getRevokeDate();
                                        LOG.info("Certificate revoked. Revoked Date: " + revokingTime.toString());
                                        LOG.info("Signing Date: " + signingTime.toString());
                                        int checkDateAgain = ExtFunc.compareDate(signingTime, revokingTime);
                                        if (checkDateAgain == 1 || checkDateAgain == 0) {
                                            // i signature is valid

                                            listSignerInfoResponse.add(signerInfoRes);
                                            response.setListSignerInfoResponse(listSignerInfoResponse);
                                            response.setResponseCode(Defines.CODE_SUCCESS);
                                            response.setResponseMessage(Defines.SUCCESS);
                                            return response;
                                        } else {

                                            listSignerInfoResponse.add(signerInfoRes);
                                            response.setListSignerInfoResponse(listSignerInfoResponse);
                                            response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_REVOKED);
                                            response.setResponseMessage(Defines.INFO_CERTIFICATE_REVOKED);
                                            return response;
                                        }
                                    } else if (ocsp_status.getCertificateState().compareTo(OcspStatus.UNKNOWN) == 0) {

                                        listSignerInfoResponse.add(signerInfoRes);
                                        response.setListSignerInfoResponse(listSignerInfoResponse);
                                        response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_UNKNOWN);
                                        response.setResponseMessage(Defines.INFO_CERTIFICATE_UNKNOWN);
                                        return response;
                                    } else {

                                        listSignerInfoResponse.add(signerInfoRes);
                                        response.setListSignerInfoResponse(listSignerInfoResponse);
                                        response.setResponseCode(Defines.CODE_INFO_CERTIFICATE_ERROR);
                                        response.setResponseMessage(Defines.INFO_CERTIFICATE_ERROR);
                                        return response;
                                    }
                                }
                            }
                        }
                    } else {
                        listSignerInfoResponse.add(signerInfoRes);
                        response.setListSignerInfoResponse(listSignerInfoResponse);
                        response.setResponseCode(Defines.CODE_INVALIDCAINFO);
                        response.setResponseMessage(Defines.ERROR_INVALIDCAINFO);
                        return response;
                    }
            }
        } catch (Exception e) {
            e.printStackTrace();
            response.setResponseCode(Defines.CODE_INVALIDSIGNATURE);
            response.setResponseMessage(Defines.ERROR_INVALIDSIGNATURE);
            return response;
        }
    }
}