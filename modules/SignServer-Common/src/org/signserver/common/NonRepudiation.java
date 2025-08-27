package org.signserver.common;

import java.security.cert.*;
import java.util.*;
import org.signserver.common.util.*;
import org.signserver.common.dbdao.*;
import javax.xml.bind.DatatypeConverter;
import java.security.Security;

import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.apache.log4j.Logger;

public class NonRepudiation {

    private static final Logger LOG = Logger.getLogger(NonRepudiation.class);

    public NonRepudiation() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public NonRepudiationResponse check(byte[] data, byte[] signature) {

        NonRepudiationResponse response = new NonRepudiationResponse();

        try {
            ArrayList<Ca> caProviders = DBConnector.getInstances().getCAProviders();

            CMSProcessableByteArray cmsByteArray = new CMSProcessableByteArray(data);
            CMSSignedData sp = new CMSSignedData(cmsByteArray, signature);
            Store certStore = sp.getCertificates();
            SignerInformationStore signers = sp.getSignerInfos();

            Collection c = signers.getSigners();
            Iterator it = c.iterator();

            boolean verificationResult = false;
            Date signingTime;

            while (it.hasNext()) {
                try {
                    SignerInformation signer = (SignerInformation) it.next();
                    Collection certCollection = certStore.getMatches(signer.getSID());
                    Iterator certIt = certCollection.iterator();
                    while (certIt.hasNext()) {
                        X509CertificateHolder cert = (X509CertificateHolder) certIt.next();
                        X509Certificate X509Signer = new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert);

                        verificationResult = verificationResult || signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));
                        org.bouncycastle.asn1.cms.Attribute attr = signer.getSignedAttributes().get(CMSAttributes.signingTime);
                        Time t = Time.getInstance(attr.getAttrValues().getObjectAt(0));
                        signingTime = t.getDate();

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
                            LOG.error("CA " + X509Signer.getIssuerDN().toString() + " not found.");
                            response.setResponseCode(Defines.CODE_INVALIDISSUERCERT);
                            response.setResponseMessage(Defines.ERROR_INVALIDISSUERCERT);
                            return response;
                        }

                        X509Certificate subX509 = new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert);
                        response.setCertificate(DatatypeConverter.printBase64Binary(subX509.getEncoded()));
                        response.setSigningTime(signingTime);

                        try {
                            subX509.checkValidity(signingTime);
                        } catch (CertificateExpiredException ex) {
                            LOG.error("Certificate has been expired");
                            response.setResponseCode(NonRepudiationResponse.NONREPUDIATION_CODE_ERROR);
                            response.setResponseMessage(Defines.ERROR_INVALIDCERTIFICATE);
                            return response;
                        } catch (CertificateNotYetValidException ex) {
                            LOG.error("Certificate is not valid yet");
                            response.setResponseCode(NonRepudiationResponse.NONREPUDIATION_CODE_ERROR);
                            response.setResponseMessage(Defines.ERROR_INVALIDCERTIFICATE);
                            return response;
                        }

                        LOG.info("Signature validation and Certificate validation by CRL");
                        if (crlPath.compareTo("") != 0 && caCertificate.compareTo("") != 0) {
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
                                        LOG.error("Certificate has been signed by untrusted CA");
                                        response.setResponseCode(NonRepudiationResponse.NONREPUDIATION_CODE_ERROR);
                                        response.setResponseMessage(Defines.ERROR_INVALIDCERTIFICATE);
                                        return response;
                                    }
                                } else {
                                    LOG.error("Second CA certificate is null or empty");
                                    response.setResponseCode(NonRepudiationResponse.NONREPUDIATION_CODE_ERROR);
                                    response.setResponseMessage(Defines.ERROR_INVALIDCAINFO);
                                    return response;
                                }
                            }

                            CRLStatus CRLVarification = CRLChecking.getInstance().check(caX509, subX509, crlPath, crlUrl, primaryCaX509, false, endpointConfigId);

                            if (!verificationResult) {
                                // invalid signature
                                response.setResponseCode(NonRepudiationResponse.NONREPUDIATION_CODE_INVALIDSIGNATURE);
                                response.setResponseMessage(NonRepudiationResponse.NONREPUDIATION_MESS_INVALIDSIGNATURE);
                                return response;
                            } else {
                                // valid signature 
                                if (!CRLVarification.getIsRevoked()) {
                                    // good certificate
                                    response.setResponseCode(NonRepudiationResponse.NONREPUDIATION_CODE_VALIDSIGNATURE);
                                    response.setResponseMessage(NonRepudiationResponse.NONREPUDIATION_MESS_VALIDSIGNATURE);
                                    return response;
                                } else {
                                    if (CRLVarification.getCertificateState().compareTo(CRLStatus.REVOKED) == 0) {
                                        java.util.Date revokingTime = CRLVarification.getRevokeDate();
                                        LOG.info("Certificate revoked. Revoked Date: " + revokingTime.toString());
                                        LOG.info("Signing Date: " + signingTime.toString());
                                        int checkDateAgain = ExtFunc.compareDate(signingTime, revokingTime);
                                        if (checkDateAgain == 1 || checkDateAgain == 0) {
                                            // revoked after signing
                                            response.setResponseCode(NonRepudiationResponse.NONREPUDIATION_CODE_VALIDSIGNATURE);
                                            response.setResponseMessage(NonRepudiationResponse.NONREPUDIATION_MESS_VALIDSIGNATURE);
                                            return response;
                                        } else {
                                            // revoked before signing
                                            String notification = " (Revoked on " + ExtFunc.getDateFormat(revokingTime) + ")";
                                            response.setResponseCode(NonRepudiationResponse.NONREPUDIATION_CODE_REVOKED);
                                            response.setResponseMessage(NonRepudiationResponse.NONREPUDIATION_MESS_REVOKED + notification);
                                            return response;
                                        }

                                    } else {
                                        // error while checking certificate status
                                        response.setResponseCode(NonRepudiationResponse.NONREPUDIATION_CODE_ERROR);
                                        response.setResponseMessage(Defines.INFO_CERTIFICATE_ERROR);
                                        return response;
                                    }
                                }
                            }
                        } else {
                            LOG.error("Cannot find CRL Path or CA certificate in system");
                            response.setResponseCode(NonRepudiationResponse.NONREPUDIATION_CODE_ERROR);
                            response.setResponseMessage(Defines.ERROR_INVALIDCAINFO);
                            return response;
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    LOG.error("Error while analysising signature");
                    response.setResponseCode(NonRepudiationResponse.NONREPUDIATION_CODE_INVALIDSIGNATURE);
                    response.setResponseMessage(NonRepudiationResponse.NONREPUDIATION_MESS_INVALIDSIGNATURE);
                    return response;
                }
            }
            // no signature found
            LOG.error("No signature found in request");
            response.setResponseCode(NonRepudiationResponse.NONREPUDIATION_CODE_ERROR);
            response.setResponseMessage(Defines.ERROR_NOCAPICOMSIGNATURE);
            return response;
        } catch (Exception e) {
            e.printStackTrace();
            LOG.error("Error while analysising signature");
            response.setResponseCode(NonRepudiationResponse.NONREPUDIATION_CODE_INVALIDSIGNATURE);
            response.setResponseMessage(NonRepudiationResponse.NONREPUDIATION_MESS_INVALIDSIGNATURE);
            return response;
        }
    }
}