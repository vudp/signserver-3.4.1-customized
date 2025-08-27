/*************************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.xmlsigner;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.ArrayList;

import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.dom.DOMStructure;
import javax.persistence.EntityManager;
import javax.sql.XADataSource;
import javax.xml.crypto.dsig.*;
import javax.xml.xpath.*;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.parsers.DocumentBuilder;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.apache.log4j.Logger;
import org.signserver.common.*;
import org.signserver.common.util.*;
import org.signserver.server.WorkerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.signers.BaseSigner;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.Init;
import org.apache.commons.io.IOUtils;

import javax.xml.crypto.Data;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
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
import xades4j.UnsupportedAlgorithmException;
import xades4j.algorithms.Algorithm;
import xades4j.algorithms.GenericAlgorithm;
import xades4j.production.EnvelopedXmlObject;
import xades4j.production.SignedDataObjects;
import xades4j.production.XadesBesSigningProfile;
import xades4j.production.XadesSigner;
import xades4j.production.XadesSigningProfile;
import xades4j.production.XadesTSigningProfile;
import xades4j.properties.AllDataObjsCommitmentTypeProperty;
import xades4j.properties.SignerRoleProperty;
import xades4j.providers.KeyInfoCertificatesProvider;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.SignaturePropertiesCollector;
import xades4j.providers.SigningCertChainException;
import xades4j.providers.TimeStampTokenProvider;
import xades4j.providers.impl.DefaultAlgorithmsProviderEx;
import xades4j.providers.impl.DefaultSignaturePropertiesProvider;
import xades4j.providers.impl.ExtendedTimeStampTokenProvider;
import xades4j.verification.UnexpectedJCAException;
*/

/**
 * A Signer signing XML documents.
 * 
 * Implements a ISigner and have the following properties:
 * No properties yet
 * 
 * @author Markus Kilås
 * @version $Id: XMLSigner.java 2841 2012-10-16 08:31:40Z netmackan $
 */
public class XMLSigner extends BaseSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(XMLSigner.class);
    private static final String CONTENT_TYPE = "text/xml";
    private String WORKERNAME = "XMLSigner";
    private String ResponseMessage = Defines.ERROR_INTERNALSYSTEM;
	private int ResponseCode = Defines.CODE_INTERNALSYSTEM;
    private String XMLTYPE = "XMLTYPE";
    private String TSA_URL = "TSA_URL";
    private String TSA_USERNAME = "TSA_USERNAME";
    private String TSA_PASSWORD = "TSA_PASSWORD";
    private String XMLDSIG = "DSIG";
    private String XMLDSIG_EXT = "DSIG_EXT";
    private String XMLXADEST = "XADES-T";
    private String XMLXADESBES = "XADES-BES";
    private String XMLDSIG_TVAN = "DSIG_TVAN";
    private String xmlType;

    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext, final EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
    }

    public ProcessResponse processData(ProcessRequest signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        ProcessResponse signResponse;
        ISignRequest sReq = (ISignRequest) signRequest;

        // Check that the request contains a valid GenericSignRequest object with a byte[].
        //final String userContract = RequestMetadata.getInstance(requestContext).get("UsernameContract");
        if (!(signRequest instanceof GenericSignRequest)) {
        	//DBConnector.getInstances().writeLogToDataBaseOutside(WORKERNAME, userContract, "[IllegalRequestException] Server: Recieved request wasn't a expected GenericSignRequest.", 201);
            throw new IllegalRequestException("Recieved request wasn't a expected GenericSignRequest.");
        }
        if (!(sReq.getRequestData() instanceof byte[])) {
        	//DBConnector.getInstances().writeLogToDataBaseOutside(WORKERNAME, userContract, "[IllegalRequestException] Server: Recieved request data wasn't a expected byte[].", 202);
            throw new IllegalRequestException("Recieved request data wasn't a expected byte[].");
        }

        byte[] data = (byte[]) sReq.getRequestData();
        String archiveId = createArchiveId(data, (String) requestContext.get(RequestContext.TRANSACTION_ID));

        // check license for XMLSigner
        LOG.info("Checking license for XMLSigner.");
        License licInfo = License.getInstance();
        if(licInfo.getStatusCode() != 0) {
        	return new GenericSignResponse(sReq.getRequestID(), archiveId, Defines.CODE_INFO_LICENSE, licInfo.getStatusDescription());
        } else {
        	if(!licInfo.checkWorker(WORKERNAME)) {
        		return new GenericSignResponse(sReq.getRequestID(), archiveId
        				, Defines.CODE_INFO_LICENSE_NOTSUPPORT, Defines.ERROR_INFO_LICENSE_NOTSUPPORT);
        	}
        }
        
        X509Certificate cert = (X509Certificate)this.getSigningCertificate();

        // Private key
        PrivateKey privKey = getCryptoToken().getPrivateKey(ICryptoToken.PURPOSE_SIGN);
        
        
        
        xmlType = ((config.getProperties().getProperty(XMLTYPE) == null) ? "DSIG" : config.getProperties().getProperty(XMLTYPE));
        
        
	byte[] signedbytes = null;
	try {
		if(xmlType.compareTo(XMLXADEST) == 0 || xmlType.compareTo(XMLXADESBES) == 0) {
			//Certificate chain
	        List<Certificate> chain = getSigningCertificateChain();
			Certificate[] certs = (Certificate[])chain.toArray(new Certificate[chain.size()]);
			signedbytes = sign(data, privKey, certs);
		} else if(xmlType.compareTo(XMLDSIG_EXT) == 0) {
			String xPaths = RequestMetadata.getInstance(requestContext).get("XPaths");
			String timeSigningTag = RequestMetadata.getInstance(requestContext).get("TimeSigningTagName");
			String timeSigningFormat = RequestMetadata.getInstance(requestContext).get("TimeSigningFormat");
			String locationSignature = RequestMetadata.getInstance(requestContext).get("SignatureLocation");
			String[] sXpath = xPaths.split(";");
			List<Certificate> chain = getSigningCertificateChain();
			Certificate[] certs = (Certificate[])chain.toArray(new Certificate[chain.size()]);
			signedbytes = signXMLFileXPath(privKey, certs, data, sXpath, timeSigningTag, timeSigningFormat, locationSignature);
		} else if(xmlType.compareTo(XMLDSIG_TVAN) == 0) {
			String signDataID = RequestMetadata.getInstance(requestContext).get("SignDataID");
			String signatureId = RequestMetadata.getInstance(requestContext).get("SignatureID");
			String locationSignature = RequestMetadata.getInstance(requestContext).get("SignatureLocation");
			X509Certificate x509 = (X509Certificate) getSigningCertificate();
			if(signDataID != null) {
				if(signDataID.compareTo("") != 0) {
					signDataID = "#"+signDataID;
				}
			} else {
				signDataID = "";
			}
			signedbytes = signXMLTVan(data, privKey, x509, signDataID, signatureId, locationSignature);
		} else {
			X509Certificate x509 = (X509Certificate) getSigningCertificate();
			signedbytes = signXMLDSig(data, privKey, x509);
		}
	} catch(Exception e) {
		e.printStackTrace();
		return new GenericSignResponse(sReq.getRequestID(), archiveId, Defines.CODE_XMLEXP, Defines.ERROR_XMLEXP);
	} 

    final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE, CONTENT_TYPE, signedbytes, archiveId));

    if (signRequest instanceof GenericServletRequest) {
        signResponse = new GenericServletResponse(sReq.getRequestID(), signedbytes, getSigningCertificate(), archiveId, archivables, CONTENT_TYPE);
    } else {
    	ResponseCode = Defines.CODE_SUCCESS;
        ResponseMessage = Defines.SUCCESS;
        signResponse = new GenericSignResponse(sReq.getRequestID(), signedbytes, getSigningCertificate(), null, archiveId, archivables, ResponseCode, ResponseMessage);
    }
    return signResponse;
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
    
    final String SIGNATURE_METHOD_RSA_SHA256 =
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    final String SIGNATURE_METHOD_RSA_SHA384 =
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
    final String SIGNATURE_METHOD_RSA_SHA512 =
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    final String SIGNATURE_METHOD_ECDSA_SHA1 =
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";
    final String SIGNATURE_METHOD_ECDSA_SHA256 =
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    final String SIGNATURE_METHOD_ECDSA_SHA384 =
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
    final String SIGNATURE_METHOD_ECDSA_SHA512 =
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
	
	public final String COMMITMENT_TYPES_NONE = "NONE";
	private Collection<AllDataObjsCommitmentTypeProperty> commitmentTypes;
	private XAdESSignerParameters parameters;
	private String signatureAlgorithm;
    private String claimedRoleDefault;
    private boolean claimedRoleFromUsername;
    private boolean hasSetIncludeCertificateLevels = true;
    private int includeCertificateLevels = 1;
    
    private static Class<? extends TimeStampTokenProvider> timeStampTokenProviderImplementation =
            ExtendedTimeStampTokenProvider.class;
    
    
    protected List<X509Certificate> includedX509Certificates(List<X509Certificate> certs) {
        if (hasSetIncludeCertificateLevels) {
            return certs.subList(0, Math.min(includeCertificateLevels, certs.size()));
        } else {
            // there should always be at least one cert in the chain
            return certs.subList(0, 1);
        }
    }
	
    private class SignaturePropertiesProvider extends DefaultSignaturePropertiesProvider {

        private String claimedRole;
        
        public SignaturePropertiesProvider(final String claimedRole) {
            this.claimedRole = claimedRole;
        }
        
        @Override
        public void provideProperties(
                SignaturePropertiesCollector signaturePropsCol) {
            super.provideProperties(signaturePropsCol);
            signaturePropsCol.setSignerRole(new SignerRoleProperty(claimedRole));
        }

    }
    
    private class AlgorithmsProvider extends DefaultAlgorithmsProviderEx {

        @Override
        public Algorithm getSignatureAlgorithm(String keyAlgorithmName)
                throws UnsupportedAlgorithmException {
            if (signatureAlgorithm == null) {
                if ("EC".equals(keyAlgorithmName)) {
                    // DefaultAlgorithmsProviderEx only handles RSA and DSA
                    return new GenericAlgorithm(SIGNATURE_METHOD_ECDSA_SHA1);
                }
                // use default xades4j behavior when not configured for the worker
                return super.getSignatureAlgorithm(keyAlgorithmName);
            }
            
            if ("SHA1withRSA".equals(signatureAlgorithm)) {
                return new GenericAlgorithm(SignatureMethod.RSA_SHA1);
            } else if ("SHA256withRSA".equals(signatureAlgorithm)) {
                return new GenericAlgorithm(SIGNATURE_METHOD_RSA_SHA256);
            } else if ("SHA384withRSA".equals(signatureAlgorithm)) {
                return new GenericAlgorithm(SIGNATURE_METHOD_RSA_SHA384); 
            } else if ("SHA512withRSA".equals(signatureAlgorithm)) {
                return new GenericAlgorithm(SIGNATURE_METHOD_RSA_SHA512);
            } else if ("SHA1withDSA".equals(signatureAlgorithm)) {
                return new GenericAlgorithm(SignatureMethod.DSA_SHA1);
            } else if ("SHA1withECDSA".equals(signatureAlgorithm)) {
                return new GenericAlgorithm(SIGNATURE_METHOD_ECDSA_SHA1);
            } else if ("SHA256withECDSA".equals(signatureAlgorithm)) {
                return new GenericAlgorithm(SIGNATURE_METHOD_ECDSA_SHA256);
            } else if ("SHA384withECDSA".equals(signatureAlgorithm)) {
                return new GenericAlgorithm(SIGNATURE_METHOD_ECDSA_SHA384);
            } else if ("SHA512withECDSA".equals(signatureAlgorithm)) {
                return new GenericAlgorithm(SIGNATURE_METHOD_ECDSA_SHA512);
            } else {
                throw new UnsupportedAlgorithmException("Unsupported signature algorithm", signatureAlgorithm);
            }
        }
    }
    
    private enum CommitmentTypes {
        PROOF_OF_APPROVAL(AllDataObjsCommitmentTypeProperty.proofOfApproval()),
        PROOF_OF_CREATION(AllDataObjsCommitmentTypeProperty.proofOfCreation()),
        PROOF_OF_DELIVERY(AllDataObjsCommitmentTypeProperty.proofOfDelivery()),
        PROOF_OF_ORIGIN(AllDataObjsCommitmentTypeProperty.proofOfOrigin()),
        PROOF_OF_RECEIPT(AllDataObjsCommitmentTypeProperty.proofOfReceipt()),
        PROOF_OF_SENDER(AllDataObjsCommitmentTypeProperty.proofOfSender());
        
        CommitmentTypes(AllDataObjsCommitmentTypeProperty commitmentType) {
            prop = commitmentType;
        }
        
        AllDataObjsCommitmentTypeProperty getProp() {
            return prop;
        }
        
        AllDataObjsCommitmentTypeProperty prop;
    }
    
	private void init(String xmlType) {
		Profiles form = null;
		if(xmlType.compareTo(XMLXADEST) == 0)
			xmlType = "T";
		else
			xmlType = "BES";
		final String xadesForm = xmlType;
		form = Profiles.valueOf(xadesForm);
		
        TSAParameters tsa = null;
        if (form == Profiles.T) {
        	
            String tsaUrl = config.getProperties().getProperty(TSA_URL);
            String tsaUsername = 
            		((config.getProperties().getProperty(TSA_USERNAME) == null) ? "" : config.getProperties().getProperty(TSA_USERNAME));
            String tsaPassword = 
            		((config.getProperties().getProperty(TSA_PASSWORD) == null) ? "" : config.getProperties().getProperty(TSA_PASSWORD));
            
            tsa = new TSAParameters(tsaUrl, tsaUsername, tsaPassword);
        }
        final String commitmentTypesProperty = "NONE";
        commitmentTypes = new LinkedList<AllDataObjsCommitmentTypeProperty>();
        if (commitmentTypesProperty != null) {
            if ("".equals(commitmentTypesProperty)) {
                System.out.println("Commitment types can not be empty");
            } else if (!COMMITMENT_TYPES_NONE.equals(commitmentTypesProperty)) {
                for (final String part : commitmentTypesProperty.split(",")) {
                    final String type = part.trim();

                    try {
                        commitmentTypes.add(CommitmentTypes.valueOf(type).getProp());
                    } catch (IllegalArgumentException e) {
                    	System.out.println("Unknown commitment type: " + type);
                    }
                }
            }
        }
        
        parameters = new XAdESSignerParameters(form, tsa);
        signatureAlgorithm = "SHA1withRSA";
        
        claimedRoleDefault = "CAG360";
        claimedRoleFromUsername = Boolean.parseBoolean(Boolean.FALSE.toString());
	}
    
	private byte[] sign(byte[] raw_data, PrivateKey privKey, Certificate[] chain)
	throws Exception {
		init(xmlType);
        byte[] signedbytes = null;
        
        UsernamePasswordClientCredential cred = null;
        final Object o = "CAG360";
        
        if (o instanceof UsernamePasswordClientCredential) {
            cred = (UsernamePasswordClientCredential) o;
        }
        
        final String username = cred != null ? cred.getUsername() : null;
        final String claimedRole =
                username != null && claimedRoleFromUsername ? username : claimedRoleDefault;
        if (claimedRoleFromUsername && claimedRoleDefault == null && username == null) {
            throw new Exception("Received a request with no user name set, while configured to get claimed role from user name and no default value for claimed role is set.");
            
        }

        // Parse
        final XadesSigner signer = createSigner(parameters, claimedRole, privKey, chain);
        final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        final DocumentBuilder builder = factory.newDocumentBuilder();
        final Document doc = builder.parse(new ByteArrayInputStream(raw_data));

        // Sign
        final Node node = doc.getDocumentElement();
        SignedDataObjects dataObjs = new SignedDataObjects(new EnvelopedXmlObject(node));

        for (final AllDataObjsCommitmentTypeProperty commitmentType : commitmentTypes) {
            dataObjs = dataObjs.withCommitmentType(commitmentType);
        }

        signer.sign(dataObjs, doc);
        
        // Render result
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(bout));
        signedbytes = bout.toByteArray();
        
        return signedbytes;
	}
	
    private XadesSigner createSigner(final XAdESSignerParameters params, final String claimedRole, PrivateKey key, Certificate[] chain)
            throws Exception {
        // Setup key and certificiates
        final List<X509Certificate> xchain = new LinkedList<X509Certificate>();
        for (Certificate cert : chain) {
            if (cert instanceof X509Certificate) {
                xchain.add((X509Certificate) cert);
            }
        }
        final KeyingDataProvider kdp = new CertificateAndChainKeyingDataProvider(xchain, key);
        
        // Signing profile
        XadesSigningProfile xsp;                   
        
        switch (params.getXadesForm()) {
            case BES:
                xsp = new XadesBesSigningProfile(kdp);
                break;
            case T:
                // add timestamp token provider
                xsp = new XadesTSigningProfile(kdp)
                            .withTimeStampTokenProvider(timeStampTokenProviderImplementation)
                            .withBinding(TSAParameters.class, params.getTsaParameters());
                break;
            case C:
            case EPES:
            default:
                throw new Exception("Unsupported XAdES profile configured");
        }
        
        xsp = xsp.withAlgorithmsProviderEx(new AlgorithmsProvider());
        
        if (claimedRole != null) {
            xsp = xsp.withSignaturePropertiesProvider(new SignaturePropertiesProvider(claimedRole));
        }
        
        // Include the configured number of certificates in the KeyInfo
        xsp.withKeyInfoCertificatesProvider(new KeyInfoCertificatesProvider() {
            @Override
            public List<X509Certificate> getCertificates(List<X509Certificate> list) throws SigningCertChainException, UnexpectedJCAException {
                return includedX509Certificates(list);
            }
        });
   
        return (XadesSigner) xsp.newSigner();
    }
    
    public enum Profiles {
        BES,
        C,
        EPES,
        T
    }
    
    private byte[] signXMLTVan(byte[] data, PrivateKey privKey, X509Certificate cert
    		, String uri, String sigId, String sPlace) throws Exception {
    	DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    	dbf.setNamespaceAware(true);
    	Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(data));
    	// Loop through the doc and tag every element with an ID attribute as an XML ID node.
    	XPath xpath = XPathFactory.newInstance().newXPath();
    	XPathExpression expr = xpath.compile("//*[@Id]");
    	NodeList nodeList = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
    	for (int i=0; i<nodeList.getLength() ; i++) {
    	  Element elem = (Element) nodeList.item(i);
    	  Attr attr = (Attr) elem.getAttributes().getNamedItem("Id");
    	  elem.setIdAttributeNode(attr, true);
    	}
    	
        // Create a DOM XMLSignatureFactory that will be used to generate the
        // enveloped signature
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        // Create a Reference to the enveloped document (in this case we are
        // signing the whole document, so a URI of "" signifies that) and
        // also specify the SHA1 digest algorithm and the ENVELOPED Transform.
        Reference ref = fac.newReference(uri,
        		fac.newDigestMethod(DigestMethod.SHA1, null),
             Collections.singletonList
              (fac.newTransform
                (Transform.ENVELOPED, (TransformParameterSpec) null)),
             null, null);
        
//        Reference ref = fac.newReference("#object",
//                fac.newDigestMethod(DigestMethod.SHA1, null));

        // Create the SignedInfo
        SignedInfo si = fac.newSignedInfo
            (fac.newCanonicalizationMethod
             (CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
              (C14NMethodParameterSpec) null),
             fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
             Collections.singletonList(ref));

        
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        //KeyValue kv = kif.newKeyValue(kp.getPublic());
        X509Data x509d = kif.newX509Data(Collections.singletonList(cert));

        // Create a KeyInfo and add the KeyValue to it
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(x509d));
        
        DOMSignContext dsc = null;
        
        if(sPlace == null) {
        	dsc = new DOMSignContext
                    (privKey, doc.getDocumentElement());
        } else {
        	Element e = doc.getDocumentElement();
            NodeList nl = doc.getElementsByTagName(sPlace);
            if(nl.getLength()>0) {
            	e = (Element)nl.item(0);
            	dsc = new DOMSignContext(privKey, e);
            } else {
            	Element newElement = doc.createElement(sPlace);
                e.appendChild(newElement);
                dsc = new DOMSignContext(privKey, newElement);
            }
            
        }
        
        // Create the XMLSignature (but don't sign it yet)
        javax.xml.crypto.dsig.XMLSignature signature = fac.newXMLSignature(si, ki, null, sigId, null);
        // Marshal, generate (and sign) the enveloped signature
        signature.sign(dsc);

        // output the resulting document
        //OutputStream os = System.out;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.setOutputProperty(OutputKeys.STANDALONE, "yes");
        trans.transform(new DOMSource(doc), new StreamResult(bos));
        return bos.toByteArray();
    }
    
    
    private byte[] signXMLDSig(byte[] data, PrivateKey privKey, X509Certificate cert) throws Exception {
    	byte[] signedbytes = null;
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        
        DocumentBuilder builder = dbf.newDocumentBuilder();
        
		final Document doc = builder.parse(new ByteArrayInputStream(data));

		Init.init();

		ElementProxy.setDefaultPrefix(Constants.SignatureSpecNS, "");

		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		final XMLSignature sig = new XMLSignature(doc, null, XMLSignature.ALGO_ID_SIGNATURE_RSA);

		final Transforms transforms = new Transforms(doc);

		transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);

		sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);

		sig.sign(privKey);

		sig.addKeyInfo(cert);

		sig.addKeyInfo(cert.getPublicKey());

		doc.getDocumentElement().appendChild(sig.getElement());

		TransformerFactory tf = TransformerFactory.newInstance();

		Transformer trans;

		trans = tf.newTransformer();

		trans.transform(new DOMSource(doc), new StreamResult(outputStream));
		return signedbytes = outputStream.toByteArray();
    }
    
    private byte[] signXMLFileXPath(PrivateKey privateKey, Certificate[] certChain, byte[] fileData, String[] xpathSignature, String sNameTimeSign, String sFormatTimeSign, String sPlace) throws Exception {
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
        Reference ref = sigFactory.newReference(referenceURI, sigFactory.newDigestMethod(DigestMethod.SHA1, null), listTransform, null, null);
        Element dateTimeStamp = doc.createElement("DateTimeStamp");
//        dateTimeStamp.setAttribute("DateTime", new Date().toString());
        String sSGDT = new SimpleDateFormat(sFormatTimeSign).format(new Date());
        dateTimeStamp.setTextContent(sSGDT);
        DOMStructure domObject = new DOMStructure(dateTimeStamp);
        SignatureProperty sigProperty
                = (SignatureProperty) sigFactory.newSignatureProperty(
                        Collections.singletonList(domObject),
                        "signatureProperties",
                        sNameTimeSign);
        SignatureProperties sigProperties = sigFactory.newSignatureProperties(
                Collections.singletonList(sigProperty), null);
        XMLObject timeStampObj = sigFactory.newXMLObject(
                Collections.singletonList(sigProperties), null, null, null);
        Reference refDate = sigFactory.newReference("#"+sNameTimeSign,
                sigFactory.newDigestMethod(DigestMethod.SHA1, null));
        List<Reference> reflist = new ArrayList<Reference>();
        reflist.add(ref);
        reflist.add(refDate);
		List<String> prefix = Collections.synchronizedList(new ArrayList<String>());
		prefix.add(ExcC14NParameterSpec.DEFAULT);
		param = new ExcC14NParameterSpec(prefix);
        SignedInfo signedInfo
                = sigFactory.newSignedInfo(sigFactory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS, (C14NMethodParameterSpec) param),
                        sigFactory.newSignatureMethod(SignatureMethod.RSA_SHA1, null), reflist);
        
        KeyInfoFactory keyInfoFactory = sigFactory.getKeyInfoFactory();
        List x509Content = new ArrayList();
        x509Content.add(cert.getSubjectX500Principal().getName() + "|TGKY=" + sSGDT);
        x509Content.add(cert);
        X509Data x509Data = keyInfoFactory.newX509Data(x509Content);
        KeyValue keyValue = keyInfoFactory.newKeyValue(publicKey);
        KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Arrays.asList(keyValue, x509Data));
        //DOMSignContext dsc = new DOMSignContext(privateKey, doc.getDocumentElement());
        Element e = doc.getDocumentElement();
        NodeList nl = doc.getElementsByTagName((sPlace==null)?xpathSignature[0]:sPlace);
        if(nl.getLength()>0)
        	e = (Element)nl.item(0);
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
                            (Provider) Class.forName(providerName)
                            .newInstance());
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
        return signedXml.getBytes();
    }
}
