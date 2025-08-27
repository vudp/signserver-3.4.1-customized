/**
 * ***********************************************************************
 *
 *                                                                       *
 *
 * SignServer: The OpenSource Automated Signing Server *
 *
 *                                                                       *
 *
 * This software is free software; you can redistribute it and/or *
 *
 * modify it under the terms of the GNU Lesser General Public *
 *
 * License as published by the Free Software Foundation; either *
 *
 * version 2.1 of the License, or any later version. *
 *
 *                                                                       *
 *
 * See terms of license at gnu.org. *
 *
 *                                                                       *
 *
 ************************************************************************
 */
package org.signserver.module.multisigner;

import java.io.ByteArrayInputStream;
import java.io.File;

import org.apache.commons.io.IOUtils;

import java.io.ByteArrayOutputStream;
import java.security.cert.*;
import java.security.PrivateKey;
import java.util.*;
import java.io.*;
import java.security.Provider;

import org.signserver.module.multisigner.oath.*;

import java.util.Collection;

import org.signserver.common.*;
import org.signserver.common.util.*;
import org.signserver.module.multisigner.pdfsigner.*;
import org.signserver.module.multisigner.xmlsigner.*;
import org.signserver.module.multisigner.officesigner.*;
import org.signserver.server.WorkerContext;

import javax.persistence.EntityManager;

import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.signers.BaseSigner;
import org.apache.log4j.Logger;
import org.apache.commons.lang.StringEscapeUtils;

public class MultiSigner extends BaseSigner {

    private static final String CONTENT_TYPE = "application/octet-stream";
    private String WORKERNAME = "MultiSigner";
    private String ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
    private int ResponseCode = Defines.CODE_INTERNALSYSTEM;
    private Properties propertiesData = null;
    private byte[] ResponseData = null;
    public static final Logger LOG = Logger.getLogger(MultiSigner.class);

    @Override
    public void init(int workerId, WorkerConfig config,
            WorkerContext workerContext, EntityManager workerEM) {
        // TODO Auto-generated method stub
        super.init(workerId, config, workerContext, workerEM);
    }

    @Override
    public ProcessResponse processData(ProcessRequest signRequest,
            RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {


        ProcessResponse signResponse;
        MultiSignerResponse multiSignerResponse = new MultiSignerResponse();

        ISignRequest sReq = (ISignRequest) signRequest;

        // Check that the request contains a valid GenericSignRequest object

        // with a byte[].
        if (!(signRequest instanceof GenericSignRequest)) {
            throw new IllegalRequestException(
                    "Recieved request wasn't a expected GenericSignRequest.");
        }

        String fileType = RequestMetadata.getInstance(requestContext).get(Defines._FILETYPE);

        String method = RequestMetadata.getInstance(requestContext).get(Defines._METHOD);

        String visibleSignature = RequestMetadata.getInstance(requestContext).get(Defines._VISIBLESIGNATURE);
        String coordinate = RequestMetadata.getInstance(requestContext).get(Defines._COORDINATE);
        String textStatusPosition = RequestMetadata.getInstance(requestContext).get(Defines._TEXTSTATUSPOSITION);
        String pageNo = RequestMetadata.getInstance(requestContext).get(Defines._PAGENO);
        String signReason = RequestMetadata.getInstance(requestContext).get(Defines._SIGNREASON);
        String visualStatus = RequestMetadata.getInstance(requestContext).get(Defines._VISUALSTATUS);
        String signatureImage = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATUREIMAGE);
        String certificate = RequestMetadata.getInstance(requestContext).get(Defines._CERTIFICATE);
        String signerInfoPrefix = RequestMetadata.getInstance(requestContext).get(Defines._SIGNERINFOPREFIX);
        String dateTimePrefix = RequestMetadata.getInstance(requestContext).get(Defines._DATETIMEPREFIX);
        String signReasonPrefix = RequestMetadata.getInstance(requestContext).get(Defines._SIGNREASONPREFIX);
        String imageAndText = RequestMetadata.getInstance(requestContext).get(Defines._IMAGEANDTEXT);
        String showSignerInfoOnly = RequestMetadata.getInstance(requestContext).get(Defines._SHOWSIGNERINFOONLY);
        String showDateTimeOnly = RequestMetadata.getInstance(requestContext).get(Defines._SHOWDATETIMEONLY);
        String tsaProvider = RequestMetadata.getInstance(requestContext).get(Defines._TSA_PROVIDER);

        String location = RequestMetadata.getInstance(requestContext).get(Defines._LOCATION);
        String locationPrefix = RequestMetadata.getInstance(requestContext).get(Defines._LOCATIONPREFIX);
        String texColor = RequestMetadata.getInstance(requestContext).get(Defines._TEXTCOLOR);
        String textDirection = RequestMetadata.getInstance(requestContext).get(Defines._TEXTDIRECTION);
        String showSignerInfo = RequestMetadata.getInstance(requestContext).get(Defines._SHOWSIGNERINFO);
        String showDateTime = RequestMetadata.getInstance(requestContext).get(Defines._SHOWDATETIME);
        String showReason = RequestMetadata.getInstance(requestContext).get(Defines._SHOWREASON);
        String showLocation = RequestMetadata.getInstance(requestContext).get(Defines._SHOWLOCATION);
        String signingTime = RequestMetadata.getInstance(requestContext).get(Defines._SIGNINGTIME);
        String lockAfterSigning = RequestMetadata.getInstance(requestContext).get(Defines._LOCKAFTERSIGNING);
        String datetimeFormat = RequestMetadata.getInstance(requestContext).get(Defines._DATETIMEFORMAT);

        String hashAlgo = RequestMetadata.getInstance(requestContext).get(Defines._ALGORITHM);
        String p11InfoLevel = RequestMetadata.getInstance(requestContext).get(Defines._P11INFOLEVEL);

        int trustedhubTransId = Integer.parseInt(RequestMetadata.getInstance(requestContext).get(Defines._TRUSTEDHUBTRANSID));


        String channelName = RequestMetadata.getInstance(requestContext).get(Defines._CHANNEL);
        String user = RequestMetadata.getInstance(requestContext).get(Defines._USER);

        String signerPassword = RequestMetadata.getInstance(requestContext).get(Defines._PASSWORD);

        if (signerPassword != null) {
            signerPassword = StringEscapeUtils.unescapeXml(signerPassword);
        }

        byte[] data = "OK".getBytes();

        final String archiveId = createArchiveId(data, (String) requestContext.get(RequestContext.TRANSACTION_ID));

        // check license for MultiSigner
        LOG.info("Checking license for MultiSigner.");
        License licInfo = License.getInstance();
        if (licInfo.getStatusCode() != 0) {
            return new GenericSignResponse(sReq.getRequestID(), archiveId, Defines.CODE_INFO_LICENSE, licInfo.getStatusDescription());
        } else {
            if (!licInfo.checkWorker(WORKERNAME)) {
                return new GenericSignResponse(sReq.getRequestID(), archiveId, Defines.CODE_INFO_LICENSE_NOTSUPPORT, Defines.ERROR_INFO_LICENSE_NOTSUPPORT);
            }
        }

        // get signing key and construct KeyInfo to be included in signature
        PrivateKey signingPrivateKey = getCryptoToken().getPrivateKey(ICryptoToken.PURPOSE_SIGN);

        String signingProvider = getCryptoToken().getProvider(ICryptoToken.PURPOSE_SIGN);

        X509Certificate signingCertificate = (X509Certificate) getSigningCertificate();
        // return result

        byte[] signedbytes = null;

        if (method.compareTo(Defines.WORKER_OATHRESPONSE) != 0) {
            data = (byte[]) sReq.getRequestData();
        }

        if (method.compareTo(Defines.WORKER_OATHREQUEST) == 0) {
            LOG.info("OATHRequest");
            int signserverAgreementStatus = DBConnector.getInstances().authCheckSignServerStatus(channelName, user);
            if (signserverAgreementStatus == 0) {
                try {
                    multiSignerResponse = OATHRequest.getInstance().processData(channelName, user);
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            } else if (signserverAgreementStatus == 1
                    || signserverAgreementStatus == 2) {
                // temporary locked
                multiSignerResponse.setResponseCode(Defines.CODE_SIGNSERVER_PKI_LOCKED);
                multiSignerResponse.setResponseMessage(Defines.ERROR_SIGNSERVER_PKI_LOCKED);
                multiSignerResponse.setSignedData(null);
            } else {
                // 3
                // no agreement found
                multiSignerResponse.setResponseCode(Defines.CODE_AGREEMENTNOTEXITS);
                multiSignerResponse.setResponseMessage(Defines.ERROR_AGREEMENTNOTEXITS);
                multiSignerResponse.setSignedData(null);
            }
        } else if (method.compareTo(Defines.WORKER_OATHRESPONSE) == 0) {
            LOG.info("OATHResponse");
            int signserverAgreementStatus = DBConnector.getInstances().authCheckSignServerStatus(channelName, user);
            if (signserverAgreementStatus == 0) {
                multiSignerResponse = OATHResponse.getInstance().processData(channelName, user, requestContext);
                if (multiSignerResponse.getResponseCode() == Defines.CODE_SUCCESS) {
                    String[] otpInformation = multiSignerResponse.getArrayData();
                    String streamPath = otpInformation[6];
                    fileType = otpInformation[7];

                    propertiesData = new Properties();
                    if (otpInformation[16] != null) {
                        propertiesData.setProperty(Defines._FILEID, otpInformation[16]);
                    } else {
                        propertiesData.setProperty(Defines._FILEID, "");
                    }

                    if (otpInformation[18] != null) {
                        propertiesData.setProperty(Defines._FILENAME, otpInformation[18]);
                    } else {
                        propertiesData.setProperty(Defines._FILENAME, "");
                    }

                    if (otpInformation[17] != null) {
                        propertiesData.setProperty(Defines._MIMETYPE, otpInformation[17]);
                    } else {
                        propertiesData.setProperty(Defines._MIMETYPE, "");
                    }

                    if (otpInformation[20] != null) {
                        propertiesData.setProperty(Defines._DISPLAYVALUE, otpInformation[20]);
                    } else {
                        propertiesData.setProperty(Defines._DISPLAYVALUE, "");
                    }

                    try {
                        data = IOUtils.toByteArray(new FileInputStream(streamPath));
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                    if (fileType.compareToIgnoreCase(ExtFunc.C_FILETYPE_PDF) == 0) {
                        Collection<Certificate> certs = getSigningCertificateChain();
                        String password = RequestMetadata.getInstance(requestContext).get(RequestContext.METADATA_PDFPASSWORD);
                        if (password == null) {
                            password = RequestMetadata.getInstance(requestContext).get(RequestContext.METADATA_pDFPASSWORD);
                        }
                        PDFSignerParameters params = new PDFSignerParameters(workerId, config);

                        java.util.Properties signaturePro = new java.util.Properties();

                        if (!ExtFunc.isNullOrEmpty(visibleSignature)) {
                            signaturePro.setProperty(Defines._VISIBLESIGNATURE, visibleSignature);
                        }
                        if (!ExtFunc.isNullOrEmpty(coordinate)) {
                            signaturePro.setProperty(Defines._COORDINATE, coordinate);
                        }
                        if (!ExtFunc.isNullOrEmpty(textStatusPosition)) {
                            signaturePro.setProperty(Defines._TEXTSTATUSPOSITION, textStatusPosition);
                        }
                        if (!ExtFunc.isNullOrEmpty(pageNo)) {
                            signaturePro.setProperty(Defines._PAGENO, pageNo);
                        }
                        if (!ExtFunc.isNullOrEmpty(signReason)) {
                            signaturePro.setProperty(Defines._SIGNREASON, signReason);
                        }
                        if (!ExtFunc.isNullOrEmpty(visualStatus)) {
                            signaturePro.setProperty(Defines._VISUALSTATUS, visualStatus);
                        }
                        if (!ExtFunc.isNullOrEmpty(signatureImage)) {
                            signaturePro.setProperty(Defines._SIGNATUREIMAGE, signatureImage);
                        }
                        if (!ExtFunc.isNull(signerInfoPrefix)) {
                            signaturePro.setProperty(Defines._SIGNERINFOPREFIX, signerInfoPrefix);
                        }
                        if (!ExtFunc.isNull(dateTimePrefix)) {
                            signaturePro.setProperty(Defines._DATETIMEPREFIX, dateTimePrefix);
                        }
                        if (!ExtFunc.isNull(signReasonPrefix)) {
                            signaturePro.setProperty(Defines._SIGNREASONPREFIX, signReasonPrefix);
                        }
                        if (!ExtFunc.isNullOrEmpty(imageAndText)) {
                            signaturePro.setProperty(Defines._IMAGEANDTEXT, imageAndText);
                        }
                        if (!ExtFunc.isNullOrEmpty(showSignerInfoOnly)) {
                            signaturePro.setProperty(Defines._SHOWSIGNERINFOONLY, showSignerInfoOnly);
                        }
                        if (!ExtFunc.isNullOrEmpty(showDateTimeOnly)) {
                            signaturePro.setProperty(Defines._SHOWDATETIMEONLY, showDateTimeOnly);
                        }
                        if (!ExtFunc.isNullOrEmpty(hashAlgo)) {
                            signaturePro.setProperty(Defines._ALGORITHM, hashAlgo);
                        }
                        if (!ExtFunc.isNullOrEmpty(tsaProvider)) {
                            signaturePro.setProperty(Defines._TSA_PROVIDER, tsaProvider);
                        }

                        if (!ExtFunc.isNullOrEmpty(location)) {
                            signaturePro.setProperty(Defines._LOCATION, location);
                        }
                        if (!ExtFunc.isNullOrEmpty(locationPrefix)) {
                            signaturePro.setProperty(Defines._LOCATIONPREFIX, locationPrefix);
                        }
                        if (!ExtFunc.isNullOrEmpty(texColor)) {
                            signaturePro.setProperty(Defines._TEXTCOLOR, texColor);
                        }
                        if (!ExtFunc.isNullOrEmpty(textDirection)) {
                            signaturePro.setProperty(Defines._TEXTDIRECTION, textDirection);
                        }
                        if (!ExtFunc.isNullOrEmpty(showSignerInfo)) {
                            signaturePro.setProperty(Defines._SHOWSIGNERINFO, showSignerInfo);
                        }
                        if (!ExtFunc.isNullOrEmpty(showDateTime)) {
                            signaturePro.setProperty(Defines._SHOWDATETIME, showDateTime);
                        }
                        if (!ExtFunc.isNullOrEmpty(showReason)) {
                            signaturePro.setProperty(Defines._SHOWREASON, showReason);
                        }
                        if (!ExtFunc.isNullOrEmpty(showLocation)) {
                            signaturePro.setProperty(Defines._SHOWLOCATION, showLocation);
                        }
                        if (!ExtFunc.isNullOrEmpty(signingTime)) {
                            signaturePro.setProperty(Defines._SIGNINGTIME, signingTime);
                        }
                        if (!ExtFunc.isNullOrEmpty(lockAfterSigning)) {
                            signaturePro.setProperty(Defines._LOCKAFTERSIGNING, lockAfterSigning);
                        }
                        if (!ExtFunc.isNullOrEmpty(datetimeFormat)) {
                            signaturePro.setProperty(Defines._DATETIMEFORMAT, datetimeFormat);
                        }

                        multiSignerResponse = PDFSigner.getInstance().processData(
                                data,
                                params,
                                password,
                                signaturePro,
                                certs,
                                signingCertificate,
                                signingPrivateKey,
                                channelName,
                                user,
                                trustedhubTransId,
                                getCryptoToken().getProvider(ICryptoToken.PROVIDERUSAGE_SIGN));

                    } else if (fileType.compareToIgnoreCase(ExtFunc.C_FILETYPE_XML) == 0) {
                        List<Certificate> chain = getSigningCertificateChain();
                        multiSignerResponse = XMLSigner.getInstance().processData(data, signingCertificate, signingPrivateKey, signingProvider, config, chain, requestContext, channelName, user, trustedhubTransId);
                    } else {
                        multiSignerResponse = OfficeSigner.getInstance().processData(data, signReason, signingCertificate, getCryptoToken().getPrivateKey(ICryptoToken.PURPOSE_SIGN), getCryptoToken().getProvider(ICryptoToken.PROVIDERUSAGE_SIGN));

                    }
                    // delete tmp file
                    new File(streamPath).delete();
                }
            } else if (signserverAgreementStatus == 1
                    || signserverAgreementStatus == 2) {
                // temporary locked
                multiSignerResponse.setResponseCode(Defines.CODE_SIGNSERVER_PKI_LOCKED);
                multiSignerResponse.setResponseMessage(Defines.ERROR_SIGNSERVER_PKI_LOCKED);
                multiSignerResponse.setSignedData(null);
            } else {
                // 3
                // no agreement found
                multiSignerResponse.setResponseCode(Defines.CODE_AGREEMENTNOTEXITS);
                multiSignerResponse.setResponseMessage(Defines.ERROR_AGREEMENTNOTEXITS);
                multiSignerResponse.setSignedData(null);
            }
        } else if (method.compareTo(Defines.WORKER_OATHVALIDATOR) == 0) {
            LOG.info("OATHValidator");
            int signserverAgreementStatus = DBConnector.getInstances().authCheckSignServerStatus(channelName, user);
            if (signserverAgreementStatus == 0) {
                multiSignerResponse = OATHValidator.getInstance().processData(channelName, user, requestContext);
                if (multiSignerResponse.getResponseCode() == Defines.CODE_SUCCESS) {
                    if (fileType.compareToIgnoreCase(ExtFunc.C_FILETYPE_PDF) == 0) {
                        Collection<Certificate> certs = getSigningCertificateChain();

                        String password = RequestMetadata.getInstance(requestContext).get(RequestContext.METADATA_PDFPASSWORD);
                        if (password == null) {
                            password = RequestMetadata.getInstance(requestContext).get(RequestContext.METADATA_pDFPASSWORD);
                        }
                        PDFSignerParameters params = new PDFSignerParameters(workerId, config);

                        java.util.Properties signaturePro = new java.util.Properties();

                        if (!ExtFunc.isNullOrEmpty(visibleSignature)) {
                            signaturePro.setProperty(Defines._VISIBLESIGNATURE, visibleSignature);
                        }
                        if (!ExtFunc.isNullOrEmpty(coordinate)) {
                            signaturePro.setProperty(Defines._COORDINATE, coordinate);
                        }
                        if (!ExtFunc.isNullOrEmpty(textStatusPosition)) {
                            signaturePro.setProperty(Defines._TEXTSTATUSPOSITION, textStatusPosition);
                        }
                        if (!ExtFunc.isNullOrEmpty(pageNo)) {
                            signaturePro.setProperty(Defines._PAGENO, pageNo);
                        }
                        if (!ExtFunc.isNullOrEmpty(signReason)) {
                            signaturePro.setProperty(Defines._SIGNREASON, signReason);
                        }
                        if (!ExtFunc.isNullOrEmpty(visualStatus)) {
                            signaturePro.setProperty(Defines._VISUALSTATUS, visualStatus);
                        }
                        if (!ExtFunc.isNullOrEmpty(signatureImage)) {
                            signaturePro.setProperty(Defines._SIGNATUREIMAGE, signatureImage);
                        }
                        if (!ExtFunc.isNull(signerInfoPrefix)) {
                            signaturePro.setProperty(Defines._SIGNERINFOPREFIX, signerInfoPrefix);
                        }
                        if (!ExtFunc.isNull(dateTimePrefix)) {
                            signaturePro.setProperty(Defines._DATETIMEPREFIX, dateTimePrefix);
                        }
                        if (!ExtFunc.isNull(signReasonPrefix)) {
                            signaturePro.setProperty(Defines._SIGNREASONPREFIX, signReasonPrefix);
                        }
                        if (!ExtFunc.isNullOrEmpty(imageAndText)) {
                            signaturePro.setProperty(Defines._IMAGEANDTEXT, imageAndText);
                        }
                        if (!ExtFunc.isNullOrEmpty(showSignerInfoOnly)) {
                            signaturePro.setProperty(Defines._SHOWSIGNERINFOONLY, showSignerInfoOnly);
                        }
                        if (!ExtFunc.isNullOrEmpty(showDateTimeOnly)) {
                            signaturePro.setProperty(Defines._SHOWDATETIMEONLY, showDateTimeOnly);
                        }
                        if (!ExtFunc.isNullOrEmpty(hashAlgo)) {
                            signaturePro.setProperty(Defines._ALGORITHM, hashAlgo);
                        }
                        if (!ExtFunc.isNullOrEmpty(tsaProvider)) {
                            signaturePro.setProperty(Defines._TSA_PROVIDER, tsaProvider);
                        }

                        if (!ExtFunc.isNullOrEmpty(location)) {
                            signaturePro.setProperty(Defines._LOCATION, location);
                        }
                        if (!ExtFunc.isNullOrEmpty(locationPrefix)) {
                            signaturePro.setProperty(Defines._LOCATIONPREFIX, locationPrefix);
                        }
                        if (!ExtFunc.isNullOrEmpty(texColor)) {
                            signaturePro.setProperty(Defines._TEXTCOLOR, texColor);
                        }
                        if (!ExtFunc.isNullOrEmpty(textDirection)) {
                            signaturePro.setProperty(Defines._TEXTDIRECTION, textDirection);
                        }
                        if (!ExtFunc.isNullOrEmpty(showSignerInfo)) {
                            signaturePro.setProperty(Defines._SHOWSIGNERINFO, showSignerInfo);
                        }
                        if (!ExtFunc.isNullOrEmpty(showDateTime)) {
                            signaturePro.setProperty(Defines._SHOWDATETIME, showDateTime);
                        }
                        if (!ExtFunc.isNullOrEmpty(showReason)) {
                            signaturePro.setProperty(Defines._SHOWREASON, showReason);
                        }
                        if (!ExtFunc.isNullOrEmpty(showLocation)) {
                            signaturePro.setProperty(Defines._SHOWLOCATION, showLocation);
                        }
                        if (!ExtFunc.isNullOrEmpty(signingTime)) {
                            signaturePro.setProperty(Defines._SIGNINGTIME, signingTime);
                        }
                        if (!ExtFunc.isNullOrEmpty(lockAfterSigning)) {
                            signaturePro.setProperty(Defines._LOCKAFTERSIGNING, lockAfterSigning);
                        }
                        if (!ExtFunc.isNullOrEmpty(datetimeFormat)) {
                            signaturePro.setProperty(Defines._DATETIMEFORMAT, datetimeFormat);
                        }

                        multiSignerResponse = PDFSigner.getInstance().processData(
                                data,
                                params,
                                password,
                                signaturePro,
                                certs,
                                signingCertificate,
                                signingPrivateKey,
                                channelName,
                                user,
                                trustedhubTransId,
                                getCryptoToken().getProvider(ICryptoToken.PROVIDERUSAGE_SIGN));
                    } else if (fileType.compareToIgnoreCase(ExtFunc.C_FILETYPE_XML) == 0) {
                        List<Certificate> chain = getSigningCertificateChain();
                        multiSignerResponse = XMLSigner.getInstance().processData(data, signingCertificate, signingPrivateKey, signingProvider, config, chain, requestContext, channelName, user, trustedhubTransId);
                    } else {
                        multiSignerResponse = OfficeSigner.getInstance().processData(data, signReason, signingCertificate, getCryptoToken().getPrivateKey(ICryptoToken.PURPOSE_SIGN), getCryptoToken().getProvider(ICryptoToken.PROVIDERUSAGE_SIGN));

                    }
                }
            } else if (signserverAgreementStatus == 1
                    || signserverAgreementStatus == 2) {
                // temporary locked
                multiSignerResponse.setResponseCode(Defines.CODE_SIGNSERVER_PKI_LOCKED);
                multiSignerResponse.setResponseMessage(Defines.ERROR_SIGNSERVER_PKI_LOCKED);
                multiSignerResponse.setSignedData(null);
            } else {
                // 3
                // no agreement found
                multiSignerResponse.setResponseCode(Defines.CODE_AGREEMENTNOTEXITS);
                multiSignerResponse.setResponseMessage(Defines.ERROR_AGREEMENTNOTEXITS);
                multiSignerResponse.setSignedData(null);
            }

        } else {
            if (!DBConnector.getInstances().authSAGetIsRegistered(channelName, user)) {
                // unregistered
                multiSignerResponse.setResponseCode(Defines.CODE_AGREEMENTNOTREADY);
                multiSignerResponse.setResponseMessage(Defines.ERROR_AGREEMENTNOTREADY);
                multiSignerResponse.setSignedData(null);
            } else {
                if (p11InfoLevel.compareTo(Defines.P11_LEVEL_BASIC) == 0) {
                    // Basic P11
                    int[] response = DBConnector.getInstances().authCheckPassSignServer(user, channelName, signerPassword);
                    int status = response[0];
                    int retry = response[1];
                    if (status == 1) {
                        multiSignerResponse.setResponseCode(Defines.CODE_INVALID_PASSWORD);
                        multiSignerResponse.setResponseMessage(Defines.ERROR_INVALID_PASSWORD);
                        multiSignerResponse.setSignedData(String.valueOf(retry).getBytes());
                    } else if (status == 2) {
                        multiSignerResponse.setResponseCode(Defines.CODE_SIGNSERVER_PKI_LOCKED);
                        multiSignerResponse.setResponseMessage(Defines.ERROR_SIGNSERVER_PKI_LOCKED);
                        multiSignerResponse.setSignedData(null);
                    } else {
                        if (fileType.compareToIgnoreCase(ExtFunc.C_FILETYPE_PDF) == 0) {
                            Collection<Certificate> certs = getSigningCertificateChain();

                            String password = RequestMetadata.getInstance(requestContext).get(RequestContext.METADATA_PDFPASSWORD);
                            if (password == null) {
                                password = RequestMetadata.getInstance(requestContext).get(RequestContext.METADATA_pDFPASSWORD);
                            }
                            PDFSignerParameters params = new PDFSignerParameters(workerId, config);

                            java.util.Properties signaturePro = new java.util.Properties();

                            if (!ExtFunc.isNullOrEmpty(visibleSignature)) {
                                signaturePro.setProperty(Defines._VISIBLESIGNATURE, visibleSignature);
                            }
                            if (!ExtFunc.isNullOrEmpty(coordinate)) {
                                signaturePro.setProperty(Defines._COORDINATE, coordinate);
                            }
                            if (!ExtFunc.isNullOrEmpty(textStatusPosition)) {
                                signaturePro.setProperty(Defines._TEXTSTATUSPOSITION, textStatusPosition);
                            }
                            if (!ExtFunc.isNullOrEmpty(pageNo)) {
                                signaturePro.setProperty(Defines._PAGENO, pageNo);
                            }
                            if (!ExtFunc.isNullOrEmpty(signReason)) {
                                signaturePro.setProperty(Defines._SIGNREASON, signReason);
                            }
                            if (!ExtFunc.isNullOrEmpty(visualStatus)) {
                                signaturePro.setProperty(Defines._VISUALSTATUS, visualStatus);
                            }
                            if (!ExtFunc.isNullOrEmpty(signatureImage)) {
                                signaturePro.setProperty(Defines._SIGNATUREIMAGE, signatureImage);
                            }
                            if (!ExtFunc.isNull(signerInfoPrefix)) {
                                signaturePro.setProperty(Defines._SIGNERINFOPREFIX, signerInfoPrefix);
                            }
                            if (!ExtFunc.isNull(dateTimePrefix)) {
                                signaturePro.setProperty(Defines._DATETIMEPREFIX, dateTimePrefix);
                            }
                            if (!ExtFunc.isNull(signReasonPrefix)) {
                                signaturePro.setProperty(Defines._SIGNREASONPREFIX, signReasonPrefix);
                            }
                            if (!ExtFunc.isNullOrEmpty(imageAndText)) {
                                signaturePro.setProperty(Defines._IMAGEANDTEXT, imageAndText);
                            }
                            if (!ExtFunc.isNullOrEmpty(showSignerInfoOnly)) {
                                signaturePro.setProperty(Defines._SHOWSIGNERINFOONLY, showSignerInfoOnly);
                            }
                            if (!ExtFunc.isNullOrEmpty(showDateTimeOnly)) {
                                signaturePro.setProperty(Defines._SHOWDATETIMEONLY, showDateTimeOnly);
                            }
                            if (!ExtFunc.isNullOrEmpty(hashAlgo)) {
                                signaturePro.setProperty(Defines._ALGORITHM, hashAlgo);
                            }
                            if (!ExtFunc.isNullOrEmpty(tsaProvider)) {
                                signaturePro.setProperty(Defines._TSA_PROVIDER, tsaProvider);
                            }

                            if (!ExtFunc.isNullOrEmpty(location)) {
                                signaturePro.setProperty(Defines._LOCATION, location);
                            }
                            if (!ExtFunc.isNullOrEmpty(locationPrefix)) {
                                signaturePro.setProperty(Defines._LOCATIONPREFIX, locationPrefix);
                            }
                            if (!ExtFunc.isNullOrEmpty(texColor)) {
                                signaturePro.setProperty(Defines._TEXTCOLOR, texColor);
                            }
                            if (!ExtFunc.isNullOrEmpty(textDirection)) {
                                signaturePro.setProperty(Defines._TEXTDIRECTION, textDirection);
                            }
                            if (!ExtFunc.isNullOrEmpty(showSignerInfo)) {
                                signaturePro.setProperty(Defines._SHOWSIGNERINFO, showSignerInfo);
                            }
                            if (!ExtFunc.isNullOrEmpty(showDateTime)) {
                                signaturePro.setProperty(Defines._SHOWDATETIME, showDateTime);
                            }
                            if (!ExtFunc.isNullOrEmpty(showReason)) {
                                signaturePro.setProperty(Defines._SHOWREASON, showReason);
                            }
                            if (!ExtFunc.isNullOrEmpty(showLocation)) {
                                signaturePro.setProperty(Defines._SHOWLOCATION, showLocation);
                            }
                            if (!ExtFunc.isNullOrEmpty(signingTime)) {
                                signaturePro.setProperty(Defines._SIGNINGTIME, signingTime);
                            }
                            if (!ExtFunc.isNullOrEmpty(lockAfterSigning)) {
                                signaturePro.setProperty(Defines._LOCKAFTERSIGNING, lockAfterSigning);
                            }
                            if (!ExtFunc.isNullOrEmpty(datetimeFormat)) {
                                signaturePro.setProperty(Defines._DATETIMEFORMAT, datetimeFormat);
                            }

                            multiSignerResponse = PDFSigner.getInstance().processData(
                                    data,
                                    params,
                                    password,
                                    signaturePro,
                                    certs,
                                    signingCertificate,
                                    signingPrivateKey,
                                    channelName,
                                    user,
                                    trustedhubTransId,
                                    getCryptoToken().getProvider(ICryptoToken.PROVIDERUSAGE_SIGN));

                        } else if (fileType.compareToIgnoreCase(ExtFunc.C_FILETYPE_XML) == 0) {
                            List<Certificate> chain = getSigningCertificateChain();
                            multiSignerResponse = XMLSigner.getInstance().processData(data, signingCertificate, signingPrivateKey, signingProvider, config, chain, requestContext, channelName, user, trustedhubTransId);
                        } else {
                            multiSignerResponse = OfficeSigner.getInstance().processData(data, signReason, signingCertificate, getCryptoToken().getPrivateKey(ICryptoToken.PURPOSE_SIGN), getCryptoToken().getProvider(ICryptoToken.PROVIDERUSAGE_SIGN));
                        }
                    }
                } else {
                    // Avanced P11
                    if (fileType.compareToIgnoreCase(ExtFunc.C_FILETYPE_PDF) == 0) {
                        Collection<Certificate> certs = getSigningCertificateChain();

                        //LOG.info("getSigningCertificateChain null is null 2: "+certs==null);

                        String password = RequestMetadata.getInstance(requestContext).get(RequestContext.METADATA_PDFPASSWORD);
                        if (password == null) {
                            password = RequestMetadata.getInstance(requestContext).get(RequestContext.METADATA_pDFPASSWORD);
                        }
                        PDFSignerParameters params = new PDFSignerParameters(workerId, config);

                        java.util.Properties signaturePro = new java.util.Properties();

                        if (!ExtFunc.isNullOrEmpty(visibleSignature)) {
                            signaturePro.setProperty(Defines._VISIBLESIGNATURE, visibleSignature);
                        }
                        if (!ExtFunc.isNullOrEmpty(coordinate)) {
                            signaturePro.setProperty(Defines._COORDINATE, coordinate);
                        }
                        if (!ExtFunc.isNullOrEmpty(textStatusPosition)) {
                            signaturePro.setProperty(Defines._TEXTSTATUSPOSITION, textStatusPosition);
                        }
                        if (!ExtFunc.isNullOrEmpty(pageNo)) {
                            signaturePro.setProperty(Defines._PAGENO, pageNo);
                        }
                        if (!ExtFunc.isNullOrEmpty(signReason)) {
                            signaturePro.setProperty(Defines._SIGNREASON, signReason);
                        }
                        if (!ExtFunc.isNullOrEmpty(visualStatus)) {
                            signaturePro.setProperty(Defines._VISUALSTATUS, visualStatus);
                        }
                        if (!ExtFunc.isNullOrEmpty(signatureImage)) {
                            signaturePro.setProperty(Defines._SIGNATUREIMAGE, signatureImage);
                        }
                        if (!ExtFunc.isNull(signerInfoPrefix)) {
                            signaturePro.setProperty(Defines._SIGNERINFOPREFIX, signerInfoPrefix);
                        }
                        if (!ExtFunc.isNull(dateTimePrefix)) {
                            signaturePro.setProperty(Defines._DATETIMEPREFIX, dateTimePrefix);
                        }
                        if (!ExtFunc.isNull(signReasonPrefix)) {
                            signaturePro.setProperty(Defines._SIGNREASONPREFIX, signReasonPrefix);
                        }
                        if (!ExtFunc.isNullOrEmpty(imageAndText)) {
                            signaturePro.setProperty(Defines._IMAGEANDTEXT, imageAndText);
                        }
                        if (!ExtFunc.isNullOrEmpty(showSignerInfoOnly)) {
                            signaturePro.setProperty(Defines._SHOWSIGNERINFOONLY, showSignerInfoOnly);
                        }
                        if (!ExtFunc.isNullOrEmpty(showDateTimeOnly)) {
                            signaturePro.setProperty(Defines._SHOWDATETIMEONLY, showDateTimeOnly);
                        }
                        if (!ExtFunc.isNullOrEmpty(hashAlgo)) {
                            signaturePro.setProperty(Defines._ALGORITHM, hashAlgo);
                        }
                        if (!ExtFunc.isNullOrEmpty(tsaProvider)) {
                            signaturePro.setProperty(Defines._TSA_PROVIDER, tsaProvider);
                        }

                        if (!ExtFunc.isNullOrEmpty(location)) {
                            signaturePro.setProperty(Defines._LOCATION, location);
                        }
                        if (!ExtFunc.isNullOrEmpty(locationPrefix)) {
                            signaturePro.setProperty(Defines._LOCATIONPREFIX, locationPrefix);
                        }
                        if (!ExtFunc.isNullOrEmpty(texColor)) {
                            signaturePro.setProperty(Defines._TEXTCOLOR, texColor);
                        }
                        if (!ExtFunc.isNullOrEmpty(textDirection)) {
                            signaturePro.setProperty(Defines._TEXTDIRECTION, textDirection);
                        }
                        if (!ExtFunc.isNullOrEmpty(showSignerInfo)) {
                            signaturePro.setProperty(Defines._SHOWSIGNERINFO, showSignerInfo);
                        }
                        if (!ExtFunc.isNullOrEmpty(showDateTime)) {
                            signaturePro.setProperty(Defines._SHOWDATETIME, showDateTime);
                        }
                        if (!ExtFunc.isNullOrEmpty(showReason)) {
                            signaturePro.setProperty(Defines._SHOWREASON, showReason);
                        }
                        if (!ExtFunc.isNullOrEmpty(showLocation)) {
                            signaturePro.setProperty(Defines._SHOWLOCATION, showLocation);
                        }
                        if (!ExtFunc.isNullOrEmpty(signingTime)) {
                            signaturePro.setProperty(Defines._SIGNINGTIME, signingTime);
                        }
                        if (!ExtFunc.isNullOrEmpty(lockAfterSigning)) {
                            signaturePro.setProperty(Defines._LOCKAFTERSIGNING, lockAfterSigning);
                        }
                        if (!ExtFunc.isNullOrEmpty(datetimeFormat)) {
                            signaturePro.setProperty(Defines._DATETIMEFORMAT, datetimeFormat);
                        }

                        multiSignerResponse = PDFSigner.getInstance().processData(
                                data,
                                params,
                                password,
                                signaturePro,
                                certs,
                                signingCertificate,
                                signingPrivateKey,
                                channelName,
                                user,
                                trustedhubTransId,
                                getCryptoToken().getProvider(ICryptoToken.PROVIDERUSAGE_SIGN));

                    } else if (fileType.compareToIgnoreCase(ExtFunc.C_FILETYPE_XML) == 0) {
                        List<Certificate> chain = getSigningCertificateChain();
                        multiSignerResponse = XMLSigner.getInstance().processData(data, signingCertificate, signingPrivateKey, signingProvider, config, chain, requestContext, channelName, user, trustedhubTransId);
                    } else {
                        multiSignerResponse = OfficeSigner.getInstance().processData(data, signReason, signingCertificate, getCryptoToken().getPrivateKey(ICryptoToken.PURPOSE_SIGN), getCryptoToken().getProvider(ICryptoToken.PROVIDERUSAGE_SIGN));
                    }
                }
            }
        }

        ResponseCode = multiSignerResponse.getResponseCode();
        ResponseMessage = multiSignerResponse.getResponseMessage();
        ResponseData = multiSignerResponse.getSignedData();
        String isResponseOtp = config.getProperties().getProperty("RESPONSE_OTP", Defines.FALSE);
        boolean responseOtp = Boolean.parseBoolean(isResponseOtp);

        if (method.compareTo(Defines.WORKER_OATHREQUEST) == 0) {
            // ResponseData is OTP Code
        } else if (method.compareTo(Defines.WORKER_OATHRESPONSE) == 0) {
            // ResponseData is signed data
            data = "OK".getBytes();
        } else if (method.compareTo(Defines.WORKER_OATHVALIDATOR) == 0) {
            // ResponseData is signed data
        } else {
            // ResponseData is signed data or retry
        }

        final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE, CONTENT_TYPE, ResponseData, archiveId));
        signResponse = new GenericSignResponse(sReq.getRequestID(), ResponseData, getSigningCertificate(), null, archiveId, archivables, ResponseCode, ResponseMessage, null, propertiesData);

        if (method.compareTo(Defines.WORKER_OATHREQUEST) == 0) {
            ((GenericSignResponse) signResponse).setResponseOTP(responseOtp);
        }

        return signResponse;

    }
}
