package org.signserver.common;

import org.signserver.common.util.*;
import org.signserver.common.dbdao.*;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;
import javax.xml.bind.DatatypeConverter;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;

import java.util.*;

import org.apache.log4j.Logger;

public class TSAVerifier {

    private static final Logger LOG = Logger.getLogger(TSAVerifier.class);

    public TSAVerifierResp verify(String channelName, String user, TimeStampToken timestampToken, int trustedhubTransId) {
        TSAVerifierResp response = new TSAVerifierResp();
        try {
            Store stores = timestampToken.getCertificates();
            Collection certCollection = stores.getMatches(timestampToken.getSID());
            Iterator certIt = certCollection.iterator();
            X509CertificateHolder x509CertificateHolder = (X509CertificateHolder) certIt.next();
            Certificate x509Cert = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(x509CertificateHolder.getEncoded()));
            X509Certificate cert = (X509Certificate) x509Cert;

            final JcaSimpleSignerInfoVerifierBuilder verifierBuilder = new JcaSimpleSignerInfoVerifierBuilder();
            final SignerInformationVerifier verifier = verifierBuilder.build(cert);

            timestampToken.validate(verifier);
            boolean isValid = true;

            String subjectDn = cert.getSubjectDN().toString();
            String subjectName = "";
            String[] pairs = subjectDn.split(",");

            for (String pair : pairs) {
                String[] paramvalue = pair.split("=");
                if (paramvalue[0].compareTo("CN") == 0
                        || paramvalue[0].compareTo(" CN") == 0) {
                    subjectName = paramvalue[1];
                    break;
                }
            }

            Tsa tsa = DBConnector.getInstances().getTSA(subjectName);

            if (tsa == null) {
                LOG.error("Not found TSA provider " + subjectName + " in system");
                response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
                response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
                response.setStatus(false);
                return response;
            }

            String certThumbprint = DatatypeConverter.printHexBinary(ExtFunc.hash(cert.getEncoded(), Defines.HASH_SHA1));
            if (certThumbprint.compareToIgnoreCase(tsa.getThumbprint()) != 0) {
                LOG.error("Invalid TSA provider. Thumbprint doesn't match");
                response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
                response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
                response.setStatus(false);
                return response;
            }

            X509Certificate tsaCACert = ExtFunc.convertToX509Cert(tsa.getTsaCACert());
            if (!ExtFunc.checkCertificateRelation(tsaCACert, cert)) {
                LOG.error("Invalid TSA provider. Relation between TSA certificate and root certificate");
                response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
                response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
                response.setStatus(false);
                return response;
            }

            Date signingTime = timestampToken.getTimeStampInfo().getGenTime();

            try {
                cert.checkValidity(signingTime);
            } catch (CertificateExpiredException ex) {
                LOG.error("Timestamp certificate has been expired");
                response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
                response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
                response.setStatus(false);
                return response;
            } catch (CertificateNotYetValidException ex) {
                LOG.error("Timestamp certificate is not valid yet");
                response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
                response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
                response.setStatus(false);
                return response;
            }


            int methodValidateCert = (int) (Math.scalb(tsa.isCheckOcsp() ? 1 : 0, 1) + Math.scalb(tsa.isCheckCrl() ? 1 : 0, 0));

            switch (methodValidateCert) {
                case 0:
                    LOG.info("Only timestamp signature validation");
                    response.setResponseCode(Defines.CODE_SUCCESS);
                    response.setResponseMessage(Defines.SUCCESS);
                    response.setStatus(true);
                    return response;
                case 1:
                    LOG.info("Timestamp signature validation and Certificate validation by CRL");
                    if (tsa.getCrlPath().compareTo("") != 0 && tsa.getTsaCACert().compareTo("") != 0) {
                        CRLStatus CRLVarification = CRLChecking.getInstance().check(tsaCACert, cert, tsa.getCrlPath(), tsa.getCrlUrl(), true, true, tsa.getEndpointConfigId());
                        if (!isValid) {
                            LOG.error("Timestamp signature invalid");
                            response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
                            response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
                            response.setStatus(false);
                            return response;
                        } else {
                            if (!CRLVarification.getIsRevoked()) {
                                // CRL valid
                                LOG.info("Timestamp signature valid");
                                response.setResponseCode(Defines.CODE_SUCCESS);
                                response.setResponseMessage(Defines.SUCCESS);
                                response.setStatus(true);
                                return response;
                            } else {
                                if (CRLVarification.getCertificateState().compareTo(CRLStatus.REVOKED) == 0) {
                                    java.util.Date revokingTime = CRLVarification.getRevokeDate();
                                    LOG.info("Certificate revoked. Revoked Date: " + revokingTime.toString());
                                    LOG.info("Signing Date: " + signingTime.toString());
                                    int checkDateAgain = ExtFunc.compareDate(signingTime, revokingTime);
                                    if (checkDateAgain == 1 || checkDateAgain == 0) {
                                        // CRL Valid
                                        LOG.info("Timestamp signature valid");
                                        response.setResponseCode(Defines.CODE_SUCCESS);
                                        response.setResponseMessage(Defines.SUCCESS);
                                        response.setStatus(true);
                                        return response;
                                    } else {
                                        // CRL revoked
                                        LOG.error("Timestamp signature invalid. Signing cert revoked");
                                        response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
                                        response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
                                        response.setStatus(false);
                                        return response;
                                    }
                                } else {
                                    LOG.error("Error while checking certificate status");
                                    response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
                                    response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
                                    response.setStatus(false);
                                    return response;
                                }
                            }
                        }
                    } else {
                        LOG.error("Invalid TSA Info. Not found TSA CRL and TSA certificate");
                        response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
                        response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
                        response.setStatus(false);
                        return response;
                    }
                case 2:
                    LOG.info("Timestamp Signature validation and Certificate validation by OCSP");
                    if (tsa.getCrlUrl().compareTo("") != 0 && tsa.getTsaCACert().compareTo("") != 0) {

                        X509Certificate caX509 = ExtFunc.convertToX509Cert(tsa.getTsaCACert());
                        boolean ocspStatus = false;

                        int retryNumber = tsa.getCheckOcspRetry();

                        OcspStatus ocsp_status = OCSPChecking.getInstance().check(channelName, user, tsa.getOcspUrl(), cert, caX509, retryNumber, tsa.getEndpointConfigId(), trustedhubTransId);
                        ocspStatus = ocsp_status.getIsValid();

                        if (!isValid) {
                            LOG.error("Timestamp signature invalid");
                            response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
                            response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
                            response.setStatus(false);
                            return response;
                        } else {
                            if (ocspStatus) {
                                LOG.info("Timestamp signature valid");
                                response.setResponseCode(Defines.CODE_SUCCESS);
                                response.setResponseMessage(Defines.SUCCESS);
                                response.setStatus(true);
                                return response;
                            } else {
                                if (ocsp_status.getCertificateState().compareTo(OcspStatus.REVOKED) == 0) {
                                    java.util.Date revokingTime = ocsp_status.getRevokeDate();
                                    LOG.info("Certificate revoked. Revoked Date: " + revokingTime.toString());
                                    LOG.info("Signing Date: " + signingTime.toString());
                                    int checkDateAgain = ExtFunc.compareDate(signingTime, revokingTime);
                                    if (checkDateAgain == 1 || checkDateAgain == 0) {
                                        LOG.info("Timestamp signature valid");
                                        response.setResponseCode(Defines.CODE_SUCCESS);
                                        response.setResponseMessage(Defines.SUCCESS);
                                        response.setStatus(true);
                                        return response;
                                    } else {
                                        LOG.error("Timestamp signature invalid. Signing cert revoked");
                                        response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
                                        response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
                                        response.setStatus(false);
                                        return response;
                                    }

                                } else if (ocsp_status.getCertificateState().compareTo(OcspStatus.UNKNOWN) == 0) {
                                    LOG.error("Timestamp signature invalid. Signing cert unknown");
                                    response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
                                    response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
                                    response.setStatus(false);
                                    return response;
                                } else {
                                    LOG.error("Timestamp signature invalid. Error while checking certificate status");
                                    response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
                                    response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
                                    response.setStatus(false);
                                    return response;
                                }
                            }
                        }
                    } else {
                        LOG.error("Invalid TSA Info. Not found TSA CRL and TSA certificate");
                        response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
                        response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
                        response.setStatus(false);
                        return response;
                    }
                default:
                    LOG.info("Timestamp Signature validation and Certificate validation by OCSP (CRL if OCSP failure)");
                    if (tsa.getCrlPath().compareTo("") != 0 && tsa.getCrlUrl().compareTo("") != 0 && tsa.getTsaCACert().compareTo("") != 0) {
                        X509Certificate caX509 = ExtFunc.convertToX509Cert(tsa.getTsaCACert());
                        boolean ocspStatus = false;
                        boolean crlStatus = false;
                        int retryNumber = tsa.getCheckOcspRetry();
                        OcspStatus ocsp_status = OCSPChecking.getInstance().check(channelName, user, tsa.getOcspUrl(), cert, caX509, retryNumber, tsa.getEndpointConfigId(), trustedhubTransId);
                        if (ocsp_status.getCertificateState().equals(OcspStatus.ERROR)) {
                            CRLStatus CRLVarification = CRLChecking.getInstance().check(caX509, cert, tsa.getCrlPath(), tsa.getCrlUrl(), true, true, tsa.getEndpointConfigId());
                            if (!isValid) {
                                LOG.error("Timestamp signature invalid");
                                response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
                                response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
                                response.setStatus(false);
                                return response;
                            } else {
                                if (!CRLVarification.getIsRevoked()) {
                                    LOG.info("Timestamp signature valid");
                                    response.setResponseCode(Defines.CODE_SUCCESS);
                                    response.setResponseMessage(Defines.SUCCESS);
                                    response.setStatus(true);
                                    return response;
                                } else {
                                    if (CRLVarification.getCertificateState().compareTo(CRLStatus.REVOKED) == 0) {
                                        java.util.Date revokingTime = CRLVarification.getRevokeDate();
                                        LOG.info("Certificate revoked. Revoked Date: " + revokingTime.toString());
                                        LOG.info("Signing Date: " + signingTime.toString());
                                        int checkDateAgain = ExtFunc.compareDate(signingTime, revokingTime);
                                        if (checkDateAgain == 1 || checkDateAgain == 0) {
                                            // CRL Valid
                                            LOG.info("Timestamp signature valid");
                                            response.setResponseCode(Defines.CODE_SUCCESS);
                                            response.setResponseMessage(Defines.SUCCESS);
                                            response.setStatus(true);
                                            return response;
                                        } else {
                                            // CRL revoked
                                            LOG.error("Timestamp signature invalid. Signing cert revoked");
                                            response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
                                            response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
                                            response.setStatus(false);
                                            return response;
                                        }

                                    } else {
                                        LOG.error("Error while checking certificate status");
                                        response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
                                        response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
                                        response.setStatus(false);
                                        return response;
                                    }
                                }
                            }
                        } else {
                            ocspStatus = ocsp_status.getIsValid();
                            if (!isValid) {
                                LOG.error("Timestamp signature invalid");
                                response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
                                response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
                                response.setStatus(false);
                                return response;
                            } else {
                                if (ocspStatus) {
                                    LOG.info("Timestamp signature valid");
                                    response.setResponseCode(Defines.CODE_SUCCESS);
                                    response.setResponseMessage(Defines.SUCCESS);
                                    response.setStatus(true);
                                    return response;
                                } else {
                                    if (ocsp_status.getCertificateState().compareTo(OcspStatus.REVOKED) == 0) {

                                        java.util.Date revokingTime = ocsp_status.getRevokeDate();
                                        LOG.info("Certificate revoked. Revoked Date: " + revokingTime.toString());
                                        LOG.info("Signing Date: " + signingTime.toString());
                                        int checkDateAgain = ExtFunc.compareDate(signingTime, revokingTime);
                                        if (checkDateAgain == 1 || checkDateAgain == 0) {
                                            LOG.info("Timestamp signature valid");
                                            response.setResponseCode(Defines.CODE_SUCCESS);
                                            response.setResponseMessage(Defines.SUCCESS);
                                            response.setStatus(true);
                                            return response;
                                        } else {
                                            LOG.error("Timestamp signature invalid. Signing cert revoked");
                                            response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
                                            response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
                                            response.setStatus(false);
                                            return response;
                                        }

                                    } else if (ocsp_status.getCertificateState().compareTo(OcspStatus.UNKNOWN) == 0) {
                                        LOG.error("Timestamp signature invalid. Signing cert unknown");
                                        response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
                                        response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
                                        response.setStatus(false);
                                        return response;
                                    } else {
                                        LOG.error("Timestamp signature invalid. Error while checking certificate status");
                                        response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
                                        response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
                                        response.setStatus(false);
                                        return response;
                                    }
                                }
                            }
                        }
                    } else {
                        LOG.error("Invalid TSA Info. Not found TSA CRL and TSA certificate");
                        response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
                        response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
                        response.setStatus(false);
                        return response;
                    }

            }

        } catch (Exception e) {
            e.printStackTrace();
            LOG.error("Error while checking timestamp signature. Details: " + e.toString());
        }
        response.setResponseCode(Defines.CODE_INVALID_TIMESTAMP);
        response.setResponseMessage(Defines.ERROR_INVALID_TIMESTAMP);
        response.setStatus(false);
        return response;
    }
}