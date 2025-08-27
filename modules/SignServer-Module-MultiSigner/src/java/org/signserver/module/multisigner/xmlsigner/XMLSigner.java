/**
 * ***********************************************************************
 *                                                                       *
 * SignServer: The OpenSource Automated Signing Server * * This software is free
 * software; you can redistribute it and/or * modify it under the terms of the
 * GNU Lesser General Public * License as published by the Free Software
 * Foundation; either * version 2.1 of the License, or any later version. * *
 * See terms of license at gnu.org. * *
 * ***********************************************************************
 */
package org.signserver.module.multisigner.xmlsigner;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;

import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.*;
import javax.xml.xpath.*;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.parsers.DocumentBuilder;

import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.apache.log4j.Logger;
import org.signserver.common.*;
import org.signserver.common.util.*;
import org.signserver.module.multisigner.*;
import org.w3c.dom.Document;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.Init;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.crypto.dsig.spec.XPathFilter2ParameterSpec;
import javax.xml.crypto.dsig.spec.XPathType;
/*
 * import es.uji.crypto.xades.jxades.security.xml.impl.*; import
 * es.uji.crypto.xades.jxades.security.xml.*; import
 * es.uji.crypto.xades.jxades.security.xml.XAdES.*;
 */
import xades4j.production.EPESSigner;
import xades4j.production.TSigner;

/**
 * A Signer signing XML documents.
 *
 * Implements a ISigner and have the following properties: No properties yet
 *
 * @author Markus Kilås
 * @version $Id: XMLSigner.java 2841 2012-10-16 08:31:40Z netmackan $
 */
public class XMLSigner {

    private static XMLSigner instance = null;

    public static XMLSigner getInstance() {
        if (instance == null) {
            instance = new XMLSigner();
        }
        return instance;
    }

    static {
        System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
    }
    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(XMLSigner.class);
    private static final String CONTENT_TYPE = "text/xml";
    private static final String TSA_PROVIDER = "TSA_PROVIDER";
    private static final String WORKERNAME = "XMLSigner";
    private String ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
    private int ResponseCode = Defines.CODE_INTERNALSYSTEM;
    private static final String XMLTYPE = "XMLTYPE";
    private static final String TSA_URL = "TSA_URL";
    private static final String TSA_USERNAME = "TSA_USERNAME";
    private static final String TSA_PASSWORD = "TSA_PASSWORD";
    private static final String XMLDSIG = "DSIG";
    private static final String XMLDSIG_EXT = "DSIG_EXT";
    private static final String XMLDSIG_EXT_TAX_01 = "DSIG_EXT_TAX_01";
    private static final String XMLXADESEPES = "XADES_EPES";
    private static final String XMLXADEST = "XADES_T";
    private static final String XMLXADESEPESNOSIGNINFO = "XADES_EPES_NO_SIGN_INFO";
    private static final String XMLDSIG_TVAN = "DSIG_TVAN";
    private static final String XML20211120 = "PreserveWhitespace";
    private static final String XMLDSIG_MULTINODE = "DSIG_MULTINODE";
    private static final String XML_NAMED_ITEM = "NAMED_ITEM";
    private static final String XML_NAMED_ITEM_DEFAULT = "Id";
    private static final String XML_CANONICALIZATION_METHOD = "CANONICALIZATION_METHOD";
    private static final String XML_KEYINFO_INCLUDED = "KEYINFO_INCLUDED";
    private String xmlType;
    private static final String HASH_ALG_SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";
    private static final String HASH_ALG_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
    private static final String HASH_ALG_SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512";
    private static final String SIGNATURE_METHOD_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    private static final String SIGNATURE_METHOD_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    private static final String SIGNATURE_METHOD_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    private static final String CANONICALIZATIONMETHOD_INCLUSIVE = "INCLUSIVE";
    private static final String CANONICALIZATIONMETHOD_INCLUSIVE_WITH_COMMENTS = "INCLUSIVE_WITH_COMMENTS";
    private static final String CANONICALIZATIONMETHOD_EXCLUSIVE = "EXCLUSIVE";
    private static final String CANONICALIZATIONMETHOD_EXCLUSIVE_WITH_COMMENTS = "EXCLUSIVE_WITH_COMMENTS";
    private static final String DEFAULT_TIME_SIGNING_TARGET = "TimeSignature";

//    private SignaturePolicyInfoProvider policyInfoProvider;
    public MultiSignerResponse processData(byte[] xmlBytes, X509Certificate x509, PrivateKey privKey, String provider, WorkerConfig config, List<Certificate> chain, RequestContext requestContext, String channelName, String user, int trustedhubTransId) {
        xmlType = ((config.getProperties().getProperty(XMLTYPE) == null) ? "DSIG" : config.getProperties().getProperty(XMLTYPE));
        String xmlProfile = RequestMetadata.getInstance(requestContext).get(Defines._XMLPROFILE);
        if (!ExtFunc.isNullOrEmpty(xmlProfile)) {
            xmlType = xmlProfile;
        }
        byte[] signedbytes = null;
        MultiSignerResponse signResponse = null;
        try {
            if (xmlType.compareTo(XMLXADESEPES) == 0) {
                String namedItem = XML_NAMED_ITEM_DEFAULT;
                String attributeName = RequestMetadata.getInstance(requestContext).get(Defines._ATTRIBUTENAME);
                if (!ExtFunc.isNullOrEmpty(attributeName)) {
                    namedItem = attributeName;
                } else {
                    if (config.getProperties().getProperty(XML_NAMED_ITEM) != null) {
                        namedItem = config.getProperties().getProperty(XML_NAMED_ITEM);
                    }
                }

                String signDataID = RequestMetadata.getInstance(requestContext).get(Defines._SIGNDATAID);
                String signatureId = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATUREID);
                String locationSignature = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATURELOCATION);
                String hashAlgorithm = getHashAlg(x509, RequestMetadata.getInstance(requestContext).get(Defines._ALGORITHM));
                //Certificate chain
                Certificate[] certs = (Certificate[]) chain.toArray(new Certificate[chain.size()]);
                signedbytes = signXMLEPES(
                        xmlBytes,
                        privKey,
                        x509,
                        signDataID,
                        signatureId,
                        locationSignature,
                        hashAlgorithm,
                        true,
                        namedItem);
                if (signedbytes == null) {
                    ResponseCode = Defines.CODE_INTERNALSYSTEM;
                    ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                } else {
                    ResponseCode = Defines.CODE_SUCCESS;
                    ResponseMessage = Defines.SUCCESS;
                }
            } else if (xmlType.compareTo(XMLXADESEPESNOSIGNINFO) == 0) {

                String namedItem = XML_NAMED_ITEM_DEFAULT;
                String attributeName = RequestMetadata.getInstance(requestContext).get(Defines._ATTRIBUTENAME);
                if (!ExtFunc.isNullOrEmpty(attributeName)) {
                    namedItem = attributeName;
                } else {
                    if (config.getProperties().getProperty(XML_NAMED_ITEM) != null) {
                        namedItem = config.getProperties().getProperty(XML_NAMED_ITEM);
                    }
                }

                String signDataID = RequestMetadata.getInstance(requestContext).get(Defines._SIGNDATAID);
                String signatureId = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATUREID);
                String locationSignature = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATURELOCATION);
                String hashAlgorithm = getHashAlg(x509, RequestMetadata.getInstance(requestContext).get(Defines._ALGORITHM));
                //Certificate chain
                Certificate[] certs = (Certificate[]) chain.toArray(new Certificate[chain.size()]);
                signedbytes = signXMLEPES(xmlBytes, privKey, x509, signDataID, signatureId, locationSignature, hashAlgorithm, false, namedItem);
                if (signedbytes == null) {
                    ResponseCode = Defines.CODE_INTERNALSYSTEM;
                    ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                } else {
                    ResponseCode = Defines.CODE_SUCCESS;
                    ResponseMessage = Defines.SUCCESS;
                }
            } else if (xmlType.compareTo(XMLXADEST) == 0) {
                String signDataID = RequestMetadata.getInstance(requestContext).get(Defines._SIGNDATAID);
                String signatureId = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATUREID);
                String locationSignature = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATURELOCATION);
                String hashAlgorithm = getHashAlg(x509, RequestMetadata.getInstance(requestContext).get(Defines._ALGORITHM));

                String tsaProvider = null;

                tsaProvider = RequestMetadata.getInstance(requestContext).get(TSA_PROVIDER);

                if (tsaProvider == null) {
                    tsaProvider = config.getProperties().getProperty(TSA_PROVIDER);
                }

                //Certificate chain
                Certificate[] certs = (Certificate[]) chain.toArray(new Certificate[chain.size()]);
                signedbytes = signXMLT(xmlBytes, privKey, x509, signDataID, signatureId, locationSignature, hashAlgorithm, true, tsaProvider, channelName, user, trustedhubTransId);
                if (signedbytes == null) {
                    ResponseCode = Defines.CODE_INTERNALSYSTEM;
                    ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                } else {
                    ResponseCode = Defines.CODE_SUCCESS;
                    ResponseMessage = Defines.SUCCESS;
                }
            } else if (xmlType.compareTo(XMLDSIG_EXT) == 0) {
                String xPaths = RequestMetadata.getInstance(requestContext).get("XPaths");
                String timeSigningTag = RequestMetadata.getInstance(requestContext).get("TimeSigningTagName");
                String timeSigningFormat = RequestMetadata.getInstance(requestContext).get("TimeSigningFormat");
                String locationSignature = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATURELOCATION);
                String hashAlgorithm = getHashAlg(x509, RequestMetadata.getInstance(requestContext).get(Defines._ALGORITHM));
                String signAlgorithm = getSigAlg(x509, RequestMetadata.getInstance(requestContext).get(Defines._ALGORITHM));
                String[] sXpath = xPaths.split(";");
                Certificate[] certs = (Certificate[]) chain.toArray(new Certificate[chain.size()]);
                signedbytes = signXMLFileXPath(
                        privKey,
                        certs,
                        xmlBytes,
                        sXpath,
                        timeSigningTag,
                        timeSigningFormat,
                        locationSignature,
                        hashAlgorithm,
                        signAlgorithm);
                if (signedbytes == null) {
                    ResponseCode = Defines.CODE_INTERNALSYSTEM;
                    ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                } else {
                    ResponseCode = Defines.CODE_SUCCESS;
                    ResponseMessage = Defines.SUCCESS;
                }

            } else if (xmlType.compareTo(XMLDSIG_EXT_TAX_01) == 0) {
                String xPaths = RequestMetadata.getInstance(requestContext).get("XPaths");
                String timeSigningTag = RequestMetadata.getInstance(requestContext).get("TimeSigningTagName");
                String timeSigningFormat = RequestMetadata.getInstance(requestContext).get("TimeSigningFormat");
                String timeSigningTarget = RequestMetadata.getInstance(requestContext).get("TimeSigningTarget");

                if (timeSigningTarget == null) {
                    timeSigningTarget = config.getProperties().getProperty(DEFAULT_TIME_SIGNING_TARGET);
                    if (timeSigningTarget == null) {
                        timeSigningTarget = DEFAULT_TIME_SIGNING_TARGET;
                    }
                }

                String signatureId = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATUREID);
                String locationSignature = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATURELOCATION);
                String hashAlgorithm = getHashAlg(x509, RequestMetadata.getInstance(requestContext).get(Defines._ALGORITHM));
                String signAlgorithm = getSigAlg(x509, RequestMetadata.getInstance(requestContext).get(Defines._ALGORITHM));
                String[] sXpath = xPaths.split(";");
                Certificate[] certs = (Certificate[]) chain.toArray(new Certificate[chain.size()]);
                signedbytes = signXMLFileXPath(
                        privKey,
                        certs,
                        xmlBytes,
                        sXpath,
                        locationSignature,
                        signatureId,
                        hashAlgorithm,
                        signAlgorithm,
                        timeSigningTag,
                        timeSigningFormat,
                        timeSigningTarget);
                if (signedbytes == null) {
                    ResponseCode = Defines.CODE_INTERNALSYSTEM;
                    ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                } else {
                    ResponseCode = Defines.CODE_SUCCESS;
                    ResponseMessage = Defines.SUCCESS;
                }
            } else if (xmlType.compareToIgnoreCase(XMLDSIG_TVAN) == 0) {
                String signDataID = RequestMetadata.getInstance(requestContext).get(Defines._SIGNDATAID);
                String signatureId = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATUREID);
                String locationSignature = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATURELOCATION);
                String hashAlgorithm = getHashAlg(x509, RequestMetadata.getInstance(requestContext).get(Defines._ALGORITHM));
                String signAlgorithm = getSigAlg(x509, RequestMetadata.getInstance(requestContext).get(Defines._ALGORITHM));
                if (signDataID != null) {
                    if (signDataID.compareTo("") != 0) {
                        signDataID = "#" + signDataID;
                    }
                } else {
                    signDataID = "";
                }

                String namedItem = null;

                String attributeName = RequestMetadata.getInstance(requestContext).get(Defines._ATTRIBUTENAME);
                if (!ExtFunc.isNullOrEmpty(attributeName)) {
                    namedItem = attributeName;
                } else {
                    if (config.getProperties().getProperty(XML_NAMED_ITEM) != null) {
                        namedItem = config.getProperties().getProperty(XML_NAMED_ITEM);
                    }
                }

                String canonicalizationMethod = CanonicalizationMethod.INCLUSIVE;
                if (config.getProperties().getProperty(XML_CANONICALIZATION_METHOD) != null) {
                    canonicalizationMethod = config.getProperties().getProperty(XML_CANONICALIZATION_METHOD);
                }

                boolean keyValueIncluded = false;

                String keyInfoIncluded = RequestMetadata.getInstance(requestContext).get(Defines._INCLUDEKEYINFO);
                if (!ExtFunc.isNullOrEmpty(keyInfoIncluded)) {
                    keyValueIncluded = Boolean.parseBoolean(keyInfoIncluded);
                } else {
                    if (config.getProperties().getProperty(XML_KEYINFO_INCLUDED) != null) {
                        keyValueIncluded = Boolean.parseBoolean(config.getProperties().getProperty(XML_KEYINFO_INCLUDED));
                    }
                }

                boolean signingTimeIncluded = false;
                String includeSigningTime = RequestMetadata.getInstance(requestContext).get(Defines._INCLUDESIGNINGTIME);
                if (!ExtFunc.isNullOrEmpty(includeSigningTime)) {
                    signingTimeIncluded = Boolean.parseBoolean(includeSigningTime);
                }

                String formatTimeSign = RequestMetadata.getInstance(requestContext).get(Defines._DATETIMEFORMAT);

                String tagTimeSign = RequestMetadata.getInstance(requestContext).get(Defines._TAGSIGNINGTIME);
                if (ExtFunc.isNullOrEmpty(tagTimeSign)) {
                    tagTimeSign = "SigningTime";
                }

                String signingTime = RequestMetadata.getInstance(requestContext).get(Defines._SIGNINGTIME);
                String signingTimeID = RequestMetadata.getInstance(requestContext).get(Defines._SIGNINGTIMEID);
                if (ExtFunc.isNullOrEmpty(signingTimeID)) {
                    signingTimeID = "SigningTimeId";
                }

                String timestampObjectId = RequestMetadata.getInstance(requestContext).get(Defines._SIGNINGTIMEOBJECTID);
                String signProsObjectId = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATUREPROPERTIESOBJECTID);
                signedbytes = signXMLTVan(
                        xmlBytes,
                        privKey,
                        x509,
                        signDataID,
                        signatureId,
                        locationSignature,
                        hashAlgorithm,
                        signAlgorithm,
                        namedItem,
                        canonicalizationMethod,
                        keyValueIncluded,
                        signingTimeIncluded,
                        timestampObjectId,
                        signProsObjectId,
                        signingTimeID,
                        formatTimeSign,
                        tagTimeSign,
                        signingTime);
                if (signedbytes == null) {
                    ResponseCode = Defines.CODE_INTERNALSYSTEM;
                    ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                } else {
                    ResponseCode = Defines.CODE_SUCCESS;
                    ResponseMessage = Defines.SUCCESS;
                }
            } else if (xmlType.compareToIgnoreCase(XML20211120) == 0) {
                String signDataID = RequestMetadata.getInstance(requestContext).get(Defines._SIGNDATAID);
                String signatureId = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATUREID);
                String locationSignature = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATURELOCATION);

                String formatTimeSign = RequestMetadata.getInstance(requestContext).get(Defines._DATETIMEFORMAT);

                String tagTimeSign = RequestMetadata.getInstance(requestContext).get(Defines._TAGSIGNINGTIME);
                if (ExtFunc.isNullOrEmpty(tagTimeSign)) {
                    tagTimeSign = "SigningTime";
                }

                String signingTime = RequestMetadata.getInstance(requestContext).get(Defines._SIGNINGTIME);

                String timestampObjectId = RequestMetadata.getInstance(requestContext).get(Defines._SIGNINGTIMEOBJECTID);
                if (ExtFunc.isNullOrEmpty(timestampObjectId)) {
                    timestampObjectId = "TimeStamp";
                }
                
                String signProsObjectId = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATUREPROPERTIESOBJECTID);
                String signingTimeXMLNS = RequestMetadata.getInstance(requestContext).get(Defines._SIGNINGTIMEXMLNS);
                String signaturePropertiesXMLNS = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATUREPROPERTIESXMLNS);
              
                
                boolean omitXmlDeclaration = 
                        RequestMetadata.getInstance(requestContext).get(Defines._OMITXMLDECLARATION) == null?false
                        :Boolean.parseBoolean(RequestMetadata.getInstance(requestContext).get(Defines._OMITXMLDECLARATION));

                Date sTime = null;

                if (ExtFunc.isNullOrEmpty(formatTimeSign)) {
                    formatTimeSign = "yyyy-MM-dd'T'HH:mm:ss";
                }

                if (!ExtFunc.isNullOrEmpty(signingTime)) {
                    sTime = ExtFunc.getDateTime(signingTime, formatTimeSign);
                } else {
                    Calendar cal = Calendar.getInstance();
                    sTime = cal.getTime();
                }

                String sSGDT = new SimpleDateFormat(formatTimeSign).format(sTime);

                DigestAlgorithm da = DigestAlgorithm.SHA256;

                String hashAlgo = RequestMetadata.getInstance(requestContext).get(Defines._ALGORITHM);
                if (ExtFunc.isNullOrEmpty(hashAlgo)) {
                    da = DigestAlgorithm.SHA256;
                } else {
                    if (hashAlgo.compareToIgnoreCase("sha1") == 0 || hashAlgo.compareToIgnoreCase("sha-1") == 0) {
                        da = DigestAlgorithm.SHA1;
                    } else if (hashAlgo.compareToIgnoreCase("sha512") == 0 || hashAlgo.compareToIgnoreCase("sha-512") == 0) {
                        da = DigestAlgorithm.SHA512;
                    } else {
                        da = DigestAlgorithm.SHA256;
                    }
                }

                XMLSigner20211120 xmlsigner = new XMLSigner20211120(
                        signDataID,
                        signatureId,
                        locationSignature,
                        x509,
                        xmlBytes,
                        da,
                        timestampObjectId,
                        signProsObjectId,
                        signaturePropertiesXMLNS,
                        signingTimeXMLNS,
                        sSGDT,
                        tagTimeSign,
                        privKey,
                        provider,
                        omitXmlDeclaration);

                signedbytes = xmlsigner.sign();

                if (signedbytes == null) {
                    ResponseCode = Defines.CODE_INTERNALSYSTEM;
                    ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                } else {
                    ResponseCode = Defines.CODE_SUCCESS;
                    ResponseMessage = Defines.SUCCESS;
                }
            } else if (xmlType.compareTo(XMLDSIG_MULTINODE) == 0) {
                String xpathExpression = RequestMetadata.getInstance(requestContext).get(Defines._XPATHEXPRESSION);
                String signatureId = RequestMetadata.getInstance(requestContext).get(Defines._SIGNATUREID);
                String canonicalizationMethod = RequestMetadata.getInstance(requestContext).get(Defines._CANONICALIZATIONMETHOD);
                canonicalizationMethod = getCanonicalizationMethod(canonicalizationMethod);
                String hashAlgorithm = getHashAlg(x509, RequestMetadata.getInstance(requestContext).get(Defines._ALGORITHM));
                String sigAlgorithm = getSigAlg(x509, RequestMetadata.getInstance(requestContext).get(Defines._ALGORITHM));

                String namedItem = XML_NAMED_ITEM_DEFAULT;
                String attributeName = RequestMetadata.getInstance(requestContext).get(Defines._ATTRIBUTENAME);
                if (!ExtFunc.isNullOrEmpty(attributeName)) {
                    namedItem = attributeName;
                } else {
                    if (config.getProperties().getProperty(XML_NAMED_ITEM) != null) {
                        namedItem = config.getProperties().getProperty(XML_NAMED_ITEM);
                    }
                }

                signedbytes = signXMLMultiNode(
                        xmlBytes,
                        privKey,
                        x509,
                        signatureId,
                        hashAlgorithm,
                        sigAlgorithm,
                        namedItem,
                        xpathExpression,
                        canonicalizationMethod);
                if (signedbytes == null) {
                    ResponseCode = Defines.CODE_INTERNALSYSTEM;
                    ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                } else {
                    ResponseCode = Defines.CODE_SUCCESS;
                    ResponseMessage = Defines.SUCCESS;
                }
            } else {
                String hashAlgorithm = getHashAlg(x509, RequestMetadata.getInstance(requestContext).get(Defines._ALGORITHM));
                String sigAlgorithm = getSigAlg(x509, RequestMetadata.getInstance(requestContext).get(Defines._ALGORITHM));
                signedbytes = signXMLDSig(xmlBytes, privKey, x509, hashAlgorithm, sigAlgorithm);
                if (signedbytes == null) {
                    ResponseCode = Defines.CODE_INTERNALSYSTEM;
                    ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
                } else {
                    ResponseCode = Defines.CODE_SUCCESS;
                    ResponseMessage = Defines.SUCCESS;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            return new MultiSignerResponse(Defines.CODE_INTERNALSYSTEM, Defines.ERROR_INTERNALSYSTEM);
        }
        return new MultiSignerResponse(signedbytes, ResponseCode, ResponseMessage);
    }

    private static String getSignatureMethod(final PrivateKey key)
            throws NoSuchAlgorithmException {
        String result;

        if ("DSA".equals(key.getAlgorithm())) {
            result = SignatureMethod.DSA_SHA1;
        } else if ("RSA".equals(key.getAlgorithm())) {
            result = SignatureMethod.RSA_SHA1;
        } else {
            throw new NoSuchAlgorithmException("XMLSigner does not support algorithm: " + key.getAlgorithm());
        }

        return result;
    }
    /*
     * private byte[] signXMLEPES(byte[] data, PrivateKey privKey,
     * X509Certificate cert , String uri, String sigId, String sPlace, String
     * hashAlgorithm, boolean includeInfo) throws Exception { SignatureOptions
     * signatureOptions = new SignatureOptions();
     * signatureOptions.setCertificate(cert);
     * signatureOptions.setPrivateKey(privKey);
     * signatureOptions.setDigestMethod(hashAlgorithm);
     * signatureOptions.setIncludeSubjectAndIssuerInfo(includeInfo);
     *
     * XAdESSigner xAdESSigner = new XAdESSigner();
     * xAdESSigner.setSignatureOptions(signatureOptions);
     * xAdESSigner.setSignatureLocation(sPlace);
     * xAdESSigner.setSignaturePrefix(sigId==null?"SigId-"+ExtFunc.getUUID():sigId);
     * List<String> refsIdList = null; if(uri != null) { refsIdList = new
     * ArrayList<String>(); refsIdList.add(uri); }
     * xAdESSigner.setRefsIdList(refsIdList); return xAdESSigner.sign(data); }
     */

    private byte[] signXMLEPES(
            byte[] data,
            PrivateKey privKey,
            X509Certificate cert,
            String uri,
            String sigId,
            String sPlace,
            String hashAlgorithm,
            boolean includeInfo,
            String attributeName) throws Exception {
        List<X509Certificate> certChain = new ArrayList<X509Certificate>();
        certChain.add(cert);
        EPESSigner epesSigner = new EPESSigner();
        byte[] signedData = epesSigner.sign(data, certChain, privKey, sPlace, sigId, includeInfo, attributeName);
        return signedData;
    }

    private byte[] signXMLT(byte[] data, PrivateKey privKey, X509Certificate cert, String uri, String sigId, String sPlace, String hashAlgorithm, boolean includeInfo, String tsaProvider, String channelName, String user, int trustedhubTransId) throws Exception {
        List<X509Certificate> certChain = new ArrayList<X509Certificate>();
        certChain.add(cert);
        TSigner tSigner = new TSigner();
        byte[] signedData = tSigner.sign(data, certChain, privKey, sPlace, sigId, includeInfo, tsaProvider, channelName, user, trustedhubTransId);
        return signedData;
    }

    private byte[] signXMLTVan(
            byte[] data,
            PrivateKey privKey,
            X509Certificate cert,
            String uri,
            String sigId,
            String sPlace,
            String hashAlgorithm,
            String sigAlgorithm,
            String namedItem,
            String canonicalizationMethod,
            boolean keyValueIncluded,
            boolean signingTimeIncluded,
            String timestampObjectId,
            String signProsObjectId,
            String signingTimeID,
            String formatTimeSign,
            String signingTimeTagName,
            String signingTime) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(data));


        if (!ExtFunc.isNullOrEmpty(namedItem)) {
            // Loop through the doc and tag every element with an ID attribute as an XML ID node.
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("//*[@" + namedItem + "]");
            NodeList nodeList = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
            for (int i = 0; i < nodeList.getLength(); i++) {
                Element elem = (Element) nodeList.item(i);
                Attr attr = (Attr) elem.getAttributes().getNamedItem(namedItem);
                elem.setIdAttributeNode(attr, true);
            }
        } else {
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
        }
        // Create a DOM XMLSignatureFactory that will be used to generate the
        // enveloped signature
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        List<Reference> reflist = new ArrayList<Reference>();
        Reference ref = null;
        XMLObject timeStampObj = null;
        ref = fac.newReference(uri,
                fac.newDigestMethod(hashAlgorithm, null), //DigestMethod.SHA1
                Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
                null, null);

        reflist.add(ref);

        if (signingTimeIncluded) {
            Date sTime = null;

            if (ExtFunc.isNullOrEmpty(formatTimeSign)) {
                formatTimeSign = "yyyy-MM-dd'T'HH:mm:ss";
            }

            if (!ExtFunc.isNullOrEmpty(signingTime)) {
                sTime = ExtFunc.getDateTime(signingTime, formatTimeSign);
            } else {
                Calendar cal = Calendar.getInstance();
                sTime = cal.getTime();
            }

            Element nodeSigningTime = doc.createElement(signingTimeTagName);
            String sSGDT = new SimpleDateFormat(formatTimeSign).format(sTime);

            nodeSigningTime.setTextContent(sSGDT);

            DOMStructure domObject = new DOMStructure(nodeSigningTime);
            SignatureProperty sigProperty = (SignatureProperty) fac.newSignatureProperty(
                    Collections.singletonList(domObject),
                    "#" + sigId,
                    signingTimeID);

            SignatureProperties sigProperties = fac.newSignatureProperties(Collections.singletonList(sigProperty), signProsObjectId);

            timeStampObj = fac.newXMLObject(Collections.singletonList(sigProperties), timestampObjectId, null, null);
            Reference refDate = fac.newReference("#" + timestampObjectId,
                    fac.newDigestMethod(hashAlgorithm, null)); //DigestMethod.SHA1
            reflist.add(refDate);
        }

        if (canonicalizationMethod == null) {
            canonicalizationMethod = CanonicalizationMethod.INCLUSIVE;
        } else {
            if (!canonicalizationMethod.equals(CanonicalizationMethod.EXCLUSIVE)
                    && !canonicalizationMethod.equals(CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS)
                    && !canonicalizationMethod.equals(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS)) {
                canonicalizationMethod = CanonicalizationMethod.INCLUSIVE;
            }
        }

        // Create the SignedInfo
        SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(canonicalizationMethod,
                (C14NMethodParameterSpec) null),
                fac.newSignatureMethod(sigAlgorithm, null), // SignatureMethod.RSA_SHA1
                reflist);

        /*
         * KeyInfoFactory kif = fac.getKeyInfoFactory(); //KeyValue kv =
         * kif.newKeyValue(kp.getPublic()); X509Data x509d =
         * kif.newX509Data(Collections.singletonList(cert)); // Create a KeyInfo
         * and add the KeyValue to it KeyInfo ki =
         * kif.newKeyInfo(Collections.singletonList(x509d));
         */
        final KeyInfoFactory kifactory = fac.getKeyInfoFactory();
        final KeyValue keyValue = kifactory.newKeyValue(cert.getPublicKey());
        final java.util.Vector<XMLStructure> kiCont = new java.util.Vector<XMLStructure>();
        if (keyValueIncluded) {
            kiCont.add(keyValue);
        }

        final List<Object> x509Content = new ArrayList<Object>();
        //final X509IssuerSerial issuer = kifactory.newX509IssuerSerial(x509ce.getIssuerX500Principal().getName(), x509ce.getSerialNumber());
        x509Content.add(cert.getSubjectX500Principal().getName());
        //x509Content.add(issuer);
        x509Content.add(cert);
        final X509Data x509Data = kifactory.newX509Data(x509Content);
        kiCont.add(x509Data);
        KeyInfo ki = kifactory.newKeyInfo(kiCont);

        DOMSignContext dsc = null;

        if (sPlace == null) {
            dsc = new DOMSignContext(privKey, doc.getDocumentElement());
        } else {
            Element e = doc.getDocumentElement();
            NodeList nl = doc.getElementsByTagName(sPlace);
            if (nl.getLength() > 0) {
                e = (Element) nl.item(nl.getLength() - 1); // last found
                dsc = new DOMSignContext(privKey, e);
            } else {
                Element newElement = doc.createElement(sPlace);
                e.appendChild(newElement);
                dsc = new DOMSignContext(privKey, newElement);
            }

        }


        // Create the XMLSignature (but don't sign it yet)
        javax.xml.crypto.dsig.XMLSignature signature = fac.newXMLSignature(
                si,
                ki,
                (timeStampObj != null) ? Collections.singletonList(timeStampObj) : null,
                sigId,
                null);
        // Marshal, generate (and sign) the enveloped signature
        signature.sign(dsc);

        // output the resulting document
        //OutputStream os = System.out;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.setOutputProperty(OutputKeys.STANDALONE, "yes");
        trans.transform(new DOMSource(doc), new StreamResult(bos));
        byte[] signedData = bos.toByteArray();
        return signedData;
    }

    private byte[] signXMLMultiNode(
            byte[] data,
            PrivateKey privKey,
            X509Certificate cert,
            String sigId,
            String hashAlgorithm,
            String sigAlgorithm,
            String namedItem,
            String xpathExpression,
            String canonicalizationMethod) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(
                new ByteArrayInputStream(data));
        // Loop through the doc and tag every element with an ID attribute as an
        // XML ID node.
        XPath xpath = XPathFactory.newInstance().newXPath();

        XPathExpression expr = null;
        if (ExtFunc.isNullOrEmpty(xpathExpression)) {
            expr = xpath.compile("//*[@" + namedItem + "]");
        } else {
            expr = xpath.compile(xpathExpression);
        }

        NodeList nodeList = (NodeList) expr.evaluate(doc,
                XPathConstants.NODESET);

        for (int i = 0; i < nodeList.getLength(); i++) {
            Element elem = (Element) nodeList.item(i);
            Attr attr = (Attr) elem.getAttributes().getNamedItem(namedItem);
            elem.setIdAttributeNode(attr, true);
            // Create a DOM XMLSignatureFactory that will be used to generate the
            // enveloped signature
            XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
            // Create a Reference to the enveloped document (in this case we are
            // signing the whole document, so a URI of "" signifies that) and
            // also specify the SHA1 digest algorithm and the ENVELOPED Transform.
            Reference ref = fac.newReference("#" + elem.getAttribute(namedItem), fac.newDigestMethod(
                    hashAlgorithm, null), // DigestMethod.SHA1
                    Collections.singletonList(fac.newTransform(Transform.ENVELOPED,
                    (TransformParameterSpec) null)), null, null);
            // Reference ref = fac.newReference("#object",
            // fac.newDigestMethod(DigestMethod.SHA1, null));
            // Create the SignedInfo
            SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(
                    canonicalizationMethod,
                    (C14NMethodParameterSpec) null), fac.newSignatureMethod(sigAlgorithm, null),
                    Collections.singletonList(ref));

            KeyInfoFactory kif = fac.getKeyInfoFactory();
            // KeyValue kv = kif.newKeyValue(kp.getPublic());
            X509Data x509d = kif.newX509Data(Collections.singletonList(cert));
            // Create a KeyInfo and add the KeyValue to it
            KeyInfo ki = kif.newKeyInfo(Collections.singletonList(x509d));
            DOMSignContext dsc = null;

            Element e = (Element) nodeList.item(i).getParentNode();
            dsc = new DOMSignContext(privKey, e);
            // Create the XMLSignature (but don't sign it yet)
            javax.xml.crypto.dsig.XMLSignature signature = fac.newXMLSignature(si,
                    ki, null, sigId, null);
            // Marshal, generate (and sign) the enveloped signature
            signature.sign(dsc);
        }
        // output the resulting document
        // OutputStream os = System.out;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.setOutputProperty(OutputKeys.STANDALONE, "yes");
        trans.transform(new DOMSource(doc), new StreamResult(bos));
        return bos.toByteArray();
    }

    private byte[] signXMLDSig(
            byte[] data,
            PrivateKey privKey,
            X509Certificate cert,
            String hashAlgorithm,
            String sigAlgorithm) {
        byte[] signedbytes = null;
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);

            DocumentBuilder builder = dbf.newDocumentBuilder();

            final Document doc = builder.parse(new ByteArrayInputStream(data));

            Init.init();

            ElementProxy.setDefaultPrefix(Constants.SignatureSpecNS, "");

            final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            final XMLSignature sig = new XMLSignature(doc, null, sigAlgorithm); // XMLSignature.ALGO_ID_SIGNATURE_RSA

            final Transforms transforms = new Transforms(doc);

            transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);

            sig.addDocument("", transforms, hashAlgorithm); // Constants.ALGO_ID_DIGEST_SHA1

            sig.sign(privKey);

            sig.addKeyInfo(cert);

            sig.addKeyInfo(cert.getPublicKey());

            doc.getDocumentElement().appendChild(sig.getElement());

            TransformerFactory tf = TransformerFactory.newInstance();

            Transformer trans;

            trans = tf.newTransformer();
            trans.transform(new DOMSource(doc), new StreamResult(outputStream));
            signedbytes = outputStream.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return signedbytes;
    }

    private byte[] signXMLFileXPath(
            PrivateKey privateKey,
            Certificate[] certChain,
            byte[] fileData,
            String[] xpathSignature,
            String sNameTimeSign,
            String sFormatTimeSign,
            String sPlace,
            String hashAlgorithm,
            String signAlgorithm) {
        byte[] signedbytes = null;
        try {
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            dbFactory.setNamespaceAware(true);
            Document doc = dbFactory.newDocumentBuilder().parse(new ByteArrayInputStream(fileData));
            String providerName = System.getProperty("jsr106Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
            final XMLSignatureFactory sigFactory = XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(providerName).newInstance());
            String referenceURI = null;
            XPathExpression expr = null;
            NodeList nodes;
            List<Transform> listTransform = Collections.synchronizedList(new ArrayList<Transform>());
            List<XPathType> xpaths = new ArrayList<XPathType>();
            Transform transform = null;
            TransformParameterSpec param = null;
            XPathFactory factory = XPathFactory.newInstance();
            XPath xpath = factory.newXPath();
            for (int i = 0; i < xpathSignature.length; i++) {
                String path = "//" + xpathSignature[i].substring(xpathSignature[i].lastIndexOf("/") + 1);
                expr = xpath.compile(path);
                nodes = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
                if (nodes.getLength() < 1) {
                    throw new Exception("Không tìm thấy node qua PATH: " + xpathSignature[i]);
                }
                //            transform = sigFactory.newTransform(Transform.XPATH, new XPathFilterParameterSpec(path));
                //            listTransform.add(transform);
                xpaths.add(new XPathType(path, XPathType.Filter.INTERSECT));
            }
            referenceURI = "";
            transform = sigFactory.newTransform(Transform.XPATH2, new XPathFilter2ParameterSpec(xpaths));
            listTransform.add(transform);
            transform = sigFactory.newTransform(CanonicalizationMethod.ENVELOPED, (TransformParameterSpec) null);
            listTransform.add(transform);
            X509Certificate cert = (X509Certificate) certChain[0];
            PublicKey publicKey = cert.getPublicKey();
            Reference ref = sigFactory.newReference(referenceURI, sigFactory.newDigestMethod(hashAlgorithm, null), listTransform, null, null); //DigestMethod.SHA1
            Element dateTimeStamp = doc.createElement("DateTimeStamp");
            //        dateTimeStamp.setAttribute("DateTime", new Date().toString());
            String sSGDT = new SimpleDateFormat(sFormatTimeSign).format(new Date());
            dateTimeStamp.setTextContent(sSGDT);
            DOMStructure domObject = new DOMStructure(dateTimeStamp);
            SignatureProperty sigProperty = (SignatureProperty) sigFactory.newSignatureProperty(
                    Collections.singletonList(domObject),
                    "signatureProperties",
                    sNameTimeSign);
            SignatureProperties sigProperties = sigFactory.newSignatureProperties(
                    Collections.singletonList(sigProperty), null);
            XMLObject timeStampObj = sigFactory.newXMLObject(
                    Collections.singletonList(sigProperties), null, null, null);
            Reference refDate = sigFactory.newReference("#" + sNameTimeSign,
                    sigFactory.newDigestMethod(hashAlgorithm, null)); //DigestMethod.SHA1
            List<Reference> reflist = new ArrayList<Reference>();
            reflist.add(ref);
            reflist.add(refDate);
            List<String> prefix = Collections.synchronizedList(new ArrayList<String>());
            prefix.add(ExcC14NParameterSpec.DEFAULT);
            param = new ExcC14NParameterSpec(prefix);
            SignedInfo signedInfo = sigFactory.newSignedInfo(sigFactory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS, (C14NMethodParameterSpec) param),
                    sigFactory.newSignatureMethod(signAlgorithm, null), reflist); // SignatureMethod.RSA_SHA1

            KeyInfoFactory keyInfoFactory = sigFactory.getKeyInfoFactory();
            List x509Content = new ArrayList();
            x509Content.add(cert.getSubjectX500Principal().getName() + "|TGKY=" + sSGDT);
            x509Content.add(cert);
            X509Data x509Data = keyInfoFactory.newX509Data(x509Content);
            KeyValue keyValue = keyInfoFactory.newKeyValue(publicKey);
            KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Arrays.asList(keyValue, x509Data));
            //DOMSignContext dsc = new DOMSignContext(privateKey, doc.getDocumentElement());
            Element e = doc.getDocumentElement();
            NodeList nl = doc.getElementsByTagName((sPlace == null) ? xpathSignature[0] : sPlace);
            if (nl.getLength() > 0) {
                e = (Element) nl.item(0);
            }
            DOMSignContext dsc = new DOMSignContext(privateKey, e);
            dsc.setURIDereferencer(new URIDereferencer() {

                @Override
                public Data dereference(URIReference uriReference, XMLCryptoContext context) throws URIReferenceException {
                    final String providerName = System.getProperty(
                            "jsr105Provider",
                            "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
                    XMLSignatureFactory fac = null;
                    try {
                        fac = XMLSignatureFactory.getInstance("DOM",
                                (Provider) Class.forName(providerName).newInstance());
                    } catch (InstantiationException e) {
                        e.printStackTrace();
                    } catch (IllegalAccessException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    } catch (ClassNotFoundException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                    Data data = fac.getURIDereferencer().dereference(uriReference,
                            context);
                    return data;
                }
            });
            javax.xml.crypto.dsig.XMLSignature signature = sigFactory.newXMLSignature(signedInfo, keyInfo, Collections.singletonList(timeStampObj), "signatureProperties", null);
            signature.sign(dsc);
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            Transformer trans = TransformerFactory.newInstance().newTransformer();
            trans.transform(new DOMSource(doc), new StreamResult(os));
            os.flush();
            byte[] signedFile = os.toByteArray();
            String signedXml = new String(signedFile);
            signedXml = signedXml.replace(" xmlns=\"\"", "");
            signedbytes = signedXml.getBytes();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return signedbytes;
    }

    private static byte[] signXMLFileXPath(
            PrivateKey privateKey,
            Certificate[] certChain,
            byte[] fileData,
            String[] xpathSignature,
            String sPlace,
            String signatureId,
            String hashAlgorithm,
            String signAlgorithm,
            String dateTimeTagName,
            String dateTimeFormat,
            String dateTimeTarget) {
        byte[] signedbytes = null;
        try {
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            dbFactory.setNamespaceAware(true);
            Document doc = dbFactory.newDocumentBuilder().parse(new ByteArrayInputStream(fileData));
            String providerName = System.getProperty("jsr106Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
            final XMLSignatureFactory sigFactory = XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(providerName).newInstance());
            String referenceURI = null;
            XPathExpression expr = null;
            NodeList nodes;
            List<Transform> listTransform = Collections.synchronizedList(new ArrayList<Transform>());
            List<XPathType> xpaths = new ArrayList<XPathType>();
            Transform transform = null;
            TransformParameterSpec param = null;
            XPathFactory factory = XPathFactory.newInstance();
            XPath xpath = factory.newXPath();
            for (int i = 0; i < xpathSignature.length; i++) {
                String path = "//" + xpathSignature[i].substring(xpathSignature[i].lastIndexOf("/") + 1);
                expr = xpath.compile(path);
                nodes = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
                if (nodes.getLength() < 1) {
                    throw new Exception("Không tìm th?y node qua PATH: " + xpathSignature[i]);
                }
                //            transform = sigFactory.newTransform(Transform.XPATH, new XPathFilterParameterSpec(path));
                //            listTransform.add(transform);
                xpaths.add(new XPathType(path, XPathType.Filter.INTERSECT));
            }
            referenceURI = "";
            transform = sigFactory.newTransform(Transform.XPATH2, new XPathFilter2ParameterSpec(xpaths));
            listTransform.add(transform);
            transform = sigFactory.newTransform(CanonicalizationMethod.ENVELOPED, (TransformParameterSpec) null);
            listTransform.add(transform);
            X509Certificate cert = (X509Certificate) certChain[0];
            PublicKey publicKey = cert.getPublicKey();
            Reference ref = sigFactory.newReference(referenceURI, sigFactory.newDigestMethod(hashAlgorithm, null), listTransform, null, null); //DigestMethod.SHA1

            Element dateTimeStamp = doc.createElement(dateTimeTagName);
            String sSGDT = new SimpleDateFormat(dateTimeFormat).format(new Date());
            dateTimeStamp.setTextContent(sSGDT);
            DOMStructure domObject = new DOMStructure(dateTimeStamp);
            SignatureProperty sigProperty = (SignatureProperty) sigFactory.newSignatureProperty(Collections.singletonList(domObject),
                    "signatureProperties",
                    dateTimeTarget);
            SignatureProperties sigProperties = sigFactory.newSignatureProperties(
                    Collections.singletonList(sigProperty), null);
            XMLObject timeStampObj = sigFactory.newXMLObject(
                    Collections.singletonList(sigProperties), null, null, null);
            Reference refDate = sigFactory.newReference("#" + dateTimeTarget,
                    sigFactory.newDigestMethod(hashAlgorithm, null)); //DigestMethod.SHA1
            List<Reference> reflist = new ArrayList<Reference>();
            reflist.add(ref);
            reflist.add(refDate);
//            List<String> prefix = Collections.synchronizedList(new ArrayList<String>());
//            prefix.add(ExcC14NParameterSpec.DEFAULT);
//            param = new ExcC14NParameterSpec(prefix);
            SignedInfo signedInfo = sigFactory.newSignedInfo(
                    sigFactory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS, (C14NMethodParameterSpec) param),
                    sigFactory.newSignatureMethod(signAlgorithm, null), reflist); // SignatureMethod.RSA_SHA1

            KeyInfoFactory keyInfoFactory = sigFactory.getKeyInfoFactory();
            List x509Content = new ArrayList();
            x509Content.add(cert.getSubjectX500Principal().getName() + "|TGKY=" + sSGDT);
            //x509Content.add(cert.getSubjectX500Principal().getName());
            x509Content.add(cert);

            final KeyInfoFactory kifactory = sigFactory.getKeyInfoFactory();
            //final KeyValue keyValue = kifactory.newKeyValue(cert.getPublicKey());

            final Vector<XMLStructure> kiCont = new Vector<XMLStructure>();
            //kiCont.add(keyValue);

            //final List<Object> x509Object = new ArrayList<Object>();
            //x509Object.add(cert.getSubjectX500Principal().getName());
            //x509Object.add(cert);
            final X509Data x509Data = kifactory.newX509Data(x509Content);
            kiCont.add(x509Data);
            KeyInfo keyInfo = kifactory.newKeyInfo(kiCont);

            //KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Arrays.asList(keyValue, x509Data));
            //DOMSignContext dsc = new DOMSignContext(privateKey, doc.getDocumentElement());
            Element e = doc.getDocumentElement();
            NodeList nl = doc.getElementsByTagName((sPlace == null) ? xpathSignature[0] : sPlace);
            if (nl.getLength() > 0) {
                e = (Element) nl.item(0);
            }
            DOMSignContext dsc = new DOMSignContext(privateKey, e);
            dsc.setURIDereferencer(new URIDereferencer() {

                @Override
                public Data dereference(URIReference uriReference, XMLCryptoContext context) throws URIReferenceException {
                    final String providerName = System.getProperty(
                            "jsr105Provider",
                            "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
                    XMLSignatureFactory fac = null;
                    try {
                        fac = XMLSignatureFactory.getInstance("DOM",
                                (Provider) Class.forName(providerName).newInstance());
                    } catch (InstantiationException e) {
                        e.printStackTrace();
                    } catch (IllegalAccessException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    } catch (ClassNotFoundException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                    Data data = fac.getURIDereferencer().dereference(uriReference,
                            context);
                    return data;
                }
            });
            javax.xml.crypto.dsig.XMLSignature signature = sigFactory.newXMLSignature(
                    signedInfo,
                    keyInfo,
                    Collections.singletonList(timeStampObj), // null
                    signatureId, // signatureId
                    null);
            signature.sign(dsc);
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            Transformer trans = TransformerFactory.newInstance().newTransformer();
            trans.transform(new DOMSource(doc), new StreamResult(os));
            os.flush();
            byte[] signedFile = os.toByteArray();
            String signedXml = new String(signedFile);
            signedXml = signedXml.replace(" xmlns=\"\"", "");
            signedbytes = signedXml.getBytes();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return signedbytes;
    }

    private static String getHashAlg(X509Certificate x509, String inputAlg) {
        if (inputAlg == null) {
            String hashAlgo = ExtFunc.getSignatureHashAlgorithm(x509);
            if (hashAlgo.compareToIgnoreCase("sha256") == 0) {
                return HASH_ALG_SHA256;
            } else if (hashAlgo.compareToIgnoreCase("sha512") == 0) {
                return HASH_ALG_SHA512;
            } else {
                return HASH_ALG_SHA1;
            }
        } else {
            if (inputAlg.compareToIgnoreCase("sha256") == 0) {
                return HASH_ALG_SHA256;
            } else if (inputAlg.compareToIgnoreCase("sha512") == 0) {
                return HASH_ALG_SHA512;
            } else {
                return HASH_ALG_SHA1;
            }
        }
    }

    private static String getSigAlg(X509Certificate x509, String inputAlg) {
        if (inputAlg == null) {
            String hashAlgo = ExtFunc.getSignatureHashAlgorithm(x509);
            if (hashAlgo.compareToIgnoreCase("sha256") == 0) {
                return SIGNATURE_METHOD_SHA256;
            } else if (hashAlgo.compareToIgnoreCase("sha512") == 0) {
                return SIGNATURE_METHOD_SHA512;
            } else {
                return SIGNATURE_METHOD_SHA1;
            }
        } else {
            if (inputAlg.compareToIgnoreCase("sha256") == 0) {
                return SIGNATURE_METHOD_SHA256;
            } else if (inputAlg.compareToIgnoreCase("sha512") == 0) {
                return SIGNATURE_METHOD_SHA512;
            } else {
                return SIGNATURE_METHOD_SHA1;
            }
        }
    }

    private static String getCanonicalizationMethod(String requireCanonicalizationMethod) {
        if (ExtFunc.isNullOrEmpty(requireCanonicalizationMethod)) {
            return CanonicalizationMethod.INCLUSIVE;
        }

        if (requireCanonicalizationMethod.equalsIgnoreCase(CANONICALIZATIONMETHOD_INCLUSIVE)) {
            return CanonicalizationMethod.INCLUSIVE;
        } else if (requireCanonicalizationMethod.equalsIgnoreCase(CANONICALIZATIONMETHOD_INCLUSIVE_WITH_COMMENTS)) {
            return CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS;
        } else if (requireCanonicalizationMethod.equalsIgnoreCase(CANONICALIZATIONMETHOD_EXCLUSIVE)) {
            return CanonicalizationMethod.EXCLUSIVE;
        } else {
            return CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS;
        }
    }
    /*
     * private void setUp() throws Exception { policyInfoProvider = new
     * SignaturePolicyInfoProvider() { @Override public SignaturePolicyBase
     * getSignaturePolicy() { return new SignaturePolicyIdentifierProperty( new
     * xades4j.properties.ObjectIdentifier("oid:/1.2.4.0.9.4.5",
     * IdentifierType.OIDAsURI, "Policy description"), new
     * ByteArrayInputStream("Test policy input stream".getBytes()))
     * .withLocationUrl("http://www.example.com/policy"); } }; }
     */
}
