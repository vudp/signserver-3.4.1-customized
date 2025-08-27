package org.signserver.common;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.security.SignatureException;
import java.security.cert.X509CRL;
import java.util.Date;
import java.util.HashMap;

import org.apache.log4j.Logger;

import java.security.cert.*;

import org.signserver.common.util.*;
import org.apache.commons.io.IOUtils;

public class CRLChecking {

    private final Logger LOG = Logger.getLogger(CRLChecking.class);
    private static HashMap<String, byte[]> crlData;
    private static CRLChecking instance;

    public static CRLChecking getInstance() {
        if (instance == null) {
            instance = new CRLChecking();
        }
        return instance;
    }

    private CRLChecking() {
        crlData = new HashMap<String, byte[]>();
    }

    public CRLStatus check(
            X509Certificate x509Ca,
            X509Certificate x509,
            String pathToCrl,
            String crlUrl,
            boolean primaryCaX509,
            boolean isTSA,
            int endpointConfigId) {
        try {
            byte[] crlByte = crlData.get(pathToCrl);

            if (crlByte == null) {
                LOG.info("Load crl " + pathToCrl + " into HashMap");
                crlByte = IOUtils.toByteArray(new FileInputStream(pathToCrl));
                crlData.put(pathToCrl, crlByte);
            }

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL x509crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(crlByte));

            Date nextUpdate = x509crl.getNextUpdate();
            Date currentDate = new Date();

            long diff = ExtFunc.getMinutesBetweenTwoDate(currentDate, nextUpdate);

            if (diff <= 0) {
                LOG.info("Download new CRL due to current one has been expired!");
                crlByte = QueryCrl.reloadCrlFileAndGetByte(crlUrl, pathToCrl, endpointConfigId);

                if (crlByte == null) {
                    LOG.info("Cannot download CRL due to invalid url or network policy!");
                    if (!isTSA) {
                        if (primaryCaX509) {
                            DBConnector.getInstances().CAUpdateDownloadableCRL(
                                    ExtFunc.getSubjectName(x509Ca.getSubjectDN().toString()),
                                    false,
                                    null);
                        } else {
                            DBConnector.getInstances().CAUpdateDownloadableCRL(
                                    ExtFunc.getSubjectName(x509Ca.getSubjectDN().toString()),
                                    null,
                                    false);
                        }
                    } else {
                        DBConnector.getInstances().updateDownloadableCrlTsa(ExtFunc.getSubjectName(x509.getSubjectDN().toString()), false);
                    }
                    return new CRLStatus(CRLStatus.REVOKED, true);
                } else {
                    if (!isTSA) {
                        if (primaryCaX509) {
                            DBConnector.getInstances().CAUpdateDownloadableCRL(
                                    ExtFunc.getSubjectName(x509Ca.getSubjectDN().toString()),
                                    true,
                                    null);
                        } else {
                            DBConnector.getInstances().CAUpdateDownloadableCRL(
                                    ExtFunc.getSubjectName(x509Ca.getSubjectDN().toString()),
                                    null,
                                    true);
                        }
                    } else {
                        DBConnector.getInstances().updateDownloadableCrlTsa(ExtFunc.getSubjectName(x509.getSubjectDN().toString()), true);
                    }
                }

                crlData.put(pathToCrl, crlByte);
                x509crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(crlByte));
            }

            // check relation with CA
            try {
                x509crl.verify(x509Ca.getPublicKey());
            } catch (SignatureException e) {
                LOG.info("CRL doesn't belong to trusted CA!");
                e.printStackTrace();
                return new CRLStatus(CRLStatus.ERROR, true);
            }


            if (x509crl.isRevoked(x509)) {
                LOG.info("Certificate is revoked at " + x509crl.getRevokedCertificate(x509).getRevocationDate());
                return new CRLStatus(CRLStatus.REVOKED, x509crl.getRevokedCertificate(x509).getRevocationDate());
            }

            LOG.info("Certificate is good!");
            return new CRLStatus(CRLStatus.GOOD, false);

        } catch (Exception e) {
            e.printStackTrace();
            return new CRLStatus(CRLStatus.ERROR, true);
        }
    }
}