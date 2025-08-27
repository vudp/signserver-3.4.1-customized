package org.signserver.validationservice.server.signaturevalidator;

import java.math.BigInteger;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.*;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.util.Store;

import java.util.List;

import org.apache.log4j.Logger;
import org.signserver.validationservice.server.*;
import org.signserver.common.*;
import org.signserver.common.util.*;
import org.signserver.common.dbdao.*;

public class CapicomValidator implements SignatureValidatorInterface {

    private static final Logger LOG = Logger.getLogger(CapicomValidator.class);

    public CapicomValidator() {
    }

    public SignatureValidatorResponse verify(String channelName, String user, byte[] data, byte[] signature, String certificate, String serialNumber, ArrayList<Ca> caProviders, int trustedhubTransId) {
        // Not implement yet
        return null;
    }

    public SignatureValidatorResponse verify(
            String channelName,
            String user,
            byte[] data,
            byte[] signature,
            String serialNumber,
            ArrayList<Ca> caProviders,
            int trustedhubTransId) {
        SignatureValidatorResponse response = new SignatureValidatorResponse();
        List<SignerInfoResponse> listSignerInfoResponse = new ArrayList<SignerInfoResponse>();
        try {
            CMSProcessableByteArray cmsByteArray = new CMSProcessableByteArray(data);
            CMSSignedData sp = new CMSSignedData(cmsByteArray, signature);
            Store certStore = sp.getCertificates();
            SignerInformationStore signers = sp.getSignerInfos();

            Collection c = signers.getSigners();
            Iterator it = c.iterator();
            BigInteger serialNo = null;
            if (!ExtFunc.isNullOrEmpty(serialNumber)) {
                serialNo = new BigInteger(serialNumber, 16);
            }

            boolean verificationResult = false;
            java.util.Date signingTime = null;
            while (it.hasNext()) {
                try {
                    SignerInformation signer = (SignerInformation) it.next();
                    Collection certCollection = certStore.getMatches(signer.getSID());
                    Iterator certIt = certCollection.iterator();
                    while (certIt.hasNext()) {

                        X509CertificateHolder cert = (X509CertificateHolder) certIt.next();
                        X509Certificate X509Signer = new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert);

                        if (serialNo != null) {
                            if (serialNo.compareTo(cert.getSerialNumber()) != 0) {
                                response.setResponseCode(Defines.CODE_INVALIDCERTSERIAL);
                                response.setResponseMessage(Defines.ERROR_INVALIDCERTSERIAL);
                                return response;
                            }
                        }

                        verificationResult = verificationResult || signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));
                        if (signer.getSignedAttributes() != null) {
                            org.bouncycastle.asn1.cms.Attribute attr = signer.getSignedAttributes().get(CMSAttributes.signingTime);
                            if (attr != null) {
                                if (attr.getAttrValues() != null) {
                                    if (attr.getAttrValues().getObjectAt(0) != null) {
                                        Time t = Time.getInstance(attr.getAttrValues().getObjectAt(0));
                                        if (t != null) {
                                            signingTime = t.getDate();
                                        }
                                    }
                                }
                            }
                        }

                        String authorityKeyIdentifier = ExtFunc.getIssuerKeyIdentifier(X509Signer);

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
                            if (ExtFunc.isNullOrEmpty(authorityKeyIdentifier)) {
                                X509Certificate caCert01 = ExtFunc.convertToX509Cert(ca.getCert());
                                X509Certificate caCert02 = ExtFunc.convertToX509Cert(ca.getCert2());
                                if ((ExtFunc.getCommonName(X509Signer.getIssuerDN().toString()).equals(ExtFunc.getCommonName(caCert01.getSubjectDN().toString()))
                                        && ExtFunc.checkCertificateRelation(caCert01, X509Signer))
                                        || (ExtFunc.getCommonName(X509Signer.getIssuerDN().toString()).equals(ExtFunc.getCommonName(caCert02.getSubjectDN().toString()))
                                        && ExtFunc.checkCertificateRelation(caCert02, X509Signer))) {
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
                            } else {
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
                        }

                        if (!CAFound) {
                            LOG.error("CA " + X509Signer.getIssuerDN().toString() + " not found.");
                            response.setResponseCode(Defines.CODE_INVALIDISSUERCERT);
                            response.setResponseMessage(Defines.ERROR_INVALIDISSUERCERT);
                            return response;
                        }

                        if (signingTime != null) {
                            try {
                                X509Signer.checkValidity(signingTime);
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

                        SignerInfoResponse signerInfoRes = new SignerInfoResponse(
                                DatatypeConverter.printBase64Binary(X509Signer.getEncoded()), X509Signer.getSerialNumber().toString(16), ExtFunc.getCNFromDN(X509Signer.getIssuerDN().getName()), ExtFunc.getCNFromDN(X509Signer.getSubjectDN().getName()), X509Signer.getNotBefore(), X509Signer.getNotAfter());
                        if (signingTime != null) {
                            signerInfoRes.setSigningTime(signingTime);
                        }
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
                                    X509Certificate subX509 = new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert);

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
                                                if (signingTime != null) {
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
                                    X509Certificate subX509 = new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert);

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
                                                if (signingTime != null) {
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
                            default:
                                LOG.info("Signature validation and Certificate validation by OCSP (CRL if OCSP failure)");
                                if (crlPath.compareTo("") != 0 && ocspURL.compareTo("") != 0 && caCertificate.compareTo("") != 0) {
                                    System.out.println("caCertificate: " + caCertificate);
                                    X509Certificate subX509 = new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert);

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
                                                    if (signingTime != null) {
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
                                                    if (signingTime != null) {
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

                    } // end while cert
                } catch (Exception e) {
                    e.printStackTrace();
                    LOG.error("Exception. Details: " + e.toString());
                    response.setResponseCode(Defines.CODE_INVALIDSIGNATURE);
                    response.setResponseMessage(Defines.ERROR_INVALIDSIGNATURE);
                    return response;
                }
            } // end while signature
        } catch (Exception e) {
            e.printStackTrace();
            LOG.error("Exception. Details: " + e.toString());
            response.setResponseCode(Defines.CODE_INVALIDSIGNATURE);
            response.setResponseMessage(Defines.ERROR_INVALIDSIGNATURE);
            return response;
        }
        response.setResponseCode(Defines.CODE_INVALIDSIGNATURE);
        response.setResponseMessage(Defines.ERROR_INVALIDSIGNATURE);
        return response;
    }
}