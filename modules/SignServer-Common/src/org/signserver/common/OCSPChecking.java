package org.signserver.common;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPRespStatus;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Vector;

import org.apache.log4j.Logger;
import org.signserver.common.util.*;

public class OCSPChecking {

    private static final Logger LOG = Logger.getLogger(OCSPChecking.class);
    private static OCSPChecking instance;

    public OCSPChecking() {
    }

    public static OCSPChecking getInstance() {
        if (instance == null) {
            instance = new OCSPChecking();
        }
        return instance;
    }

    public OcspStatus check(
            String channelName,
            String user,
            String ocspURL,
            X509Certificate cert,
            X509Certificate issuerCert,
            int retry,
            int endpointConfigId,
            int trustedhubTransId) {
        EndpointServiceResp endpointServiceResp = null;
        try {
            OCSPReq request = generateOCSPRequest(issuerCert, cert.getSerialNumber());
            byte[] array = request.getEncoded();

            endpointServiceResp = EndpointService.getInstance().checkOcsp(
                    channelName,
                    user,
                    array,
                    ocspURL,
                    retry,
                    endpointConfigId,
                    trustedhubTransId);

            if (endpointServiceResp.getResponseData() == null) {
                LOG.info("Cannot check OCSP through endpoint. Try using through local service.");
                LocalService localService = new LocalService();
                endpointServiceResp = localService.checkOcsp(
                        channelName,
                        user,
                        array,
                        ocspURL,
                        retry,
                        endpointConfigId,
                        trustedhubTransId);
            }

            if (endpointServiceResp.getResponseData() == null) {
                LOG.error("OCSP response NULL. Although using LocalService");
                return new OcspStatus(OcspStatus.ERROR, false, endpointServiceResp.getEndpointId());
            }

            OCSPResp ocspResponse = new OCSPResp(endpointServiceResp.getResponseData());
            if (OCSPRespStatus.SUCCESSFUL == ocspResponse.getStatus()) {
                LOG.info("OCSP response fine");
            }

            BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();

            if (basicResponse.getResponses() != null) {
                try {
                    X509Certificate ocspSigner = null;
                    X509Certificate[] certs = basicResponse.getCerts("BC");
                    for (int i = 0; i < certs.length; i++) {
                        boolean[] keyUsage = ExtFunc.getKeyUsage(certs[i]);
                        if (keyUsage != null) {
                            if (!keyUsage[5]) {
                                ocspSigner = certs[i];
                                try {
                                    ocspSigner.verify(issuerCert.getPublicKey());
                                } catch (NoSuchAlgorithmException ex) {
                                    LOG.error("[NoSuchAlgorithmException] Invalid Ocsp siganture due to invalid CA");
                                    return new OcspStatus(OcspStatus.ERROR, false, endpointServiceResp.getEndpointId(), null);
                                } catch (InvalidKeyException ex) {
                                    LOG.info("[InvalidKeyException] Invalid Ocsp siganture due to invalid CA");
                                    return new OcspStatus(OcspStatus.ERROR, false, endpointServiceResp.getEndpointId(), null);
                                } catch (NoSuchProviderException ex) {
                                    LOG.info("[NoSuchProviderException] Invalid Ocsp siganture due to invalid CA");
                                    return new OcspStatus(OcspStatus.ERROR, false, endpointServiceResp.getEndpointId(), null);
                                } catch (SignatureException ex) {
                                    LOG.info("[SignatureException] Invalid Ocsp siganture due to invalid CA");
                                    return new OcspStatus(OcspStatus.ERROR, false, endpointServiceResp.getEndpointId(), null);
                                } catch (CertificateException ex) {
                                    LOG.info("[CertificateException] Invalid Ocsp siganture due to invalid CA");
                                    return new OcspStatus(OcspStatus.ERROR, false, endpointServiceResp.getEndpointId(), null);
                                }
                                break;
                            }
                        } else {
                            int basicConstraint = ExtFunc.getBasicConstraint(certs[i]);
                            if (basicConstraint == -1) {
                                ocspSigner = certs[i];
                                try {
                                    ocspSigner.verify(issuerCert.getPublicKey());
                                } catch (NoSuchAlgorithmException ex) {
                                    LOG.error("[NoSuchAlgorithmException] Invalid Ocsp siganture due to invalid CA");
                                    return new OcspStatus(OcspStatus.ERROR, false, endpointServiceResp.getEndpointId(), null);
                                } catch (InvalidKeyException ex) {
                                    LOG.info("[InvalidKeyException] Invalid Ocsp siganture due to invalid CA");
                                    return new OcspStatus(OcspStatus.ERROR, false, endpointServiceResp.getEndpointId(), null);
                                } catch (NoSuchProviderException ex) {
                                    LOG.info("[NoSuchProviderException] Invalid Ocsp siganture due to invalid CA");
                                    return new OcspStatus(OcspStatus.ERROR, false, endpointServiceResp.getEndpointId(), null);
                                } catch (SignatureException ex) {
                                    LOG.info("[SignatureException] Invalid Ocsp siganture due to invalid CA");
                                    return new OcspStatus(OcspStatus.ERROR, false, endpointServiceResp.getEndpointId(), null);
                                } catch (CertificateException ex) {
                                    LOG.info("[CertificateException] Invalid Ocsp siganture due to invalid CA");
                                    return new OcspStatus(OcspStatus.ERROR, false, endpointServiceResp.getEndpointId(), null);
                                }
                                break;
                            }
                        }
                    }

                    if (ocspSigner == null) {
                        ocspSigner = issuerCert;
                    }

                    boolean validOcspSignature = basicResponse.verify(ocspSigner.getPublicKey(), "BC");
                    if (!validOcspSignature) {
                        LOG.error("Invalid Ocsp siganture due to invalid CA");
                        return new OcspStatus(OcspStatus.ERROR, false, endpointServiceResp.getEndpointId(), null);
                    }

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            SingleResp[] responses = (basicResponse == null) ? null : basicResponse.getResponses();

            if (responses != null && responses.length == 1) {
                SingleResp resp = responses[0];
                Object status = resp.getCertStatus();
                if (status instanceof org.bouncycastle.ocsp.RevokedStatus) {
                    LOG.info("Certificate is revoked at " + ((org.bouncycastle.ocsp.RevokedStatus) status).getRevocationTime());
                    return new OcspStatus(OcspStatus.REVOKED, false, endpointServiceResp.getEndpointId(), ((org.bouncycastle.ocsp.RevokedStatus) status).getRevocationTime());
                } else if (status instanceof org.bouncycastle.ocsp.UnknownStatus) {
                    return new OcspStatus(OcspStatus.UNKNOWN, false, endpointServiceResp.getEndpointId(), null);
                } else {
                    return new OcspStatus(OcspStatus.GOOD, true, endpointServiceResp.getEndpointId(), null);
                }
            } else {
                LOG.info("OCSP response NULL or length != 1");
                return new OcspStatus(OcspStatus.ERROR, false, endpointServiceResp.getEndpointId(), null);
            }
        } catch (Exception e) {
            e.printStackTrace();
            LOG.info(e.toString());
            return new OcspStatus(OcspStatus.ERROR, false, (endpointServiceResp != null) ? endpointServiceResp.getEndpointId() : null, null);
        }
    }

    private OCSPReq generateOCSPRequest(X509Certificate issuerCert,
            BigInteger serialNumber) throws Exception {
        // CertID structure is used to uniquely identify certificates that are
        // the subject of
        // an OCSP request or response and has an ASN.1 definition. CertID
        // structure is defined in RFC 2560
        CertificateID id = new CertificateID(CertificateID.HASH_SHA1,
                issuerCert, serialNumber);

        // basic request generation with nonce
        OCSPReqGenerator generator = new OCSPReqGenerator();
        generator.addRequest(id);

        // create details for nonce extension. The nonce extension is used to
        // bind
        // a request to a response to prevent replay attacks. As the name
        // implies,
        // the nonce value is something that the client should only use once
        // within a reasonably small period.
        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
        Vector objectIdentifiers = new Vector();
        Vector values = new Vector();

        // to create the request Extension
        objectIdentifiers.add(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        values.add(new X509Extension(false, new DEROctetString(nonce.toByteArray())));
        generator.setRequestExtensions(new X509Extensions(objectIdentifiers,
                values));

        return generator.generate();
    }
}