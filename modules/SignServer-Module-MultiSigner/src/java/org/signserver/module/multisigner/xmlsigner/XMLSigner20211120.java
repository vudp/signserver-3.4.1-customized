/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.module.multisigner.xmlsigner;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import org.apache.log4j.Logger;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.signserver.common.util.ExtFunc;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 *
 * @author mobileid
 */
public class XMLSigner20211120 {

    private static final Logger LOG = Logger.getLogger(XMLSigner20211120.class);

    static {
        Security.addProvider(new BouncyCastleProvider());
        Init.init();
    }
    private String signingAttributeID;
    private String signatureID;
    private String signaturePosition;
    private X509Certificate signingCertificate;
    private byte[] xmlDocument;
    private DigestAlgorithm hashAlgo;
    //signing time
    private String signingTimeObjectID;
    private String signingTimeSignaturePropertyID;
    private String signaturePropertiesXMLNS;
    private String signingTimeXMLNS;
    private String signingTimeValue;
    private String signingTimeTAG;
    final private static boolean USING_NS = false;
    final private static String DEFAULT_SIGNING_TIME_TAG = "SigningTime";
    private PrivateKey privateKey;
    private String provider;
    private boolean omitXmlDeclaration;

    public XMLSigner20211120(
            String signingAttributeID,
            String signatureID,
            String signaturePosition,
            X509Certificate signingCertificate,
            byte[] xmlDocument,
            DigestAlgorithm hashAlgo,
            String signingTimeObjectID,
            String signingTimeSignaturePropertyID,
            String signaturePropertiesXMLNS,
            String signingTimeXMLNS,
            String signingTimeValue,
            String signingTimeTAG,
            PrivateKey key,
            String provider,
            boolean omitXmlDeclaration) {
        this.signingAttributeID = signingAttributeID;
        this.signatureID = signatureID;
        this.signaturePosition = signaturePosition;
        this.signingCertificate = signingCertificate;
        this.xmlDocument = xmlDocument;
        this.hashAlgo = hashAlgo;
        this.signingTimeObjectID = signingTimeObjectID;
        this.signingTimeSignaturePropertyID = signingTimeSignaturePropertyID;
        this.signingTimeXMLNS = signingTimeXMLNS;
        this.signaturePropertiesXMLNS = signaturePropertiesXMLNS;
        this.signingTimeValue = signingTimeValue;
        this.signingTimeTAG = signingTimeTAG;
        this.privateKey = key;
        this.provider = provider;
        this.omitXmlDeclaration = omitXmlDeclaration;
    }

    public byte[] sign() throws Exception {
        InputStream is = new ByteArrayInputStream(xmlDocument);
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document originalDocument = dbf.newDocumentBuilder().parse(is);
        is.close();

        // get node to be signed
        Node signingParentNode = null;
        Node signingNode = null;
        XPath xpath = XPathFactory.newInstance().newXPath();
        XPathExpression expr = xpath.compile("//*[@Id='" + signingAttributeID + "']");
        NodeList nodeList = (NodeList) expr.evaluate(originalDocument, XPathConstants.NODESET);
        //Constants._ATT_ID = "Id";
        if (nodeList.getLength() == 0) {
            expr = xpath.compile("//*[@id='" + signingAttributeID + "']");
            nodeList = (NodeList) expr.evaluate(originalDocument, XPathConstants.NODESET);
            //Constants._ATT_ID = "id";
        }
        if (nodeList.getLength() == 0) {
            throw new Exception("Id " + signingAttributeID + " not found");
        } else {
            signingNode = nodeList.item(0);
            signingParentNode = signingNode.getParentNode();
        }

        //Ch�n node signature t?o t?m v�o file c?n k�
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.newDocument();

        Element signature = prepareSignature(signingNode);
        Element tmpNode = (Element) originalDocument.importNode(signature, true);

        if (signaturePosition != null) {
            if (!signaturePosition.equals("")) {
                String[] parts = signaturePosition.split("/");
                Document ownerDoc = signingParentNode.getOwnerDocument();
                if (parts.length == 1) {
                    NodeList nl = ownerDoc.getElementsByTagName(parts[0]);
                    if (nl.getLength() == 0) {
                        Element e = ownerDoc.createElement(parts[0]);
                        e.appendChild(tmpNode);
                        signingParentNode.appendChild(e);
                    } else if (nl.getLength() == 1) {
                        Element e = (Element) nl.item(0);
                        e.appendChild(tmpNode);
                    } else {
                        Element e = (Element) nl.item(nl.getLength() - 1);
                        e.appendChild(tmpNode);
                    }
                } else {
                    xpath = XPathFactory.newInstance().newXPath();
                    NodeList nl = (NodeList) xpath.evaluate(signingParentNode.getNodeName() + "/" + signaturePosition, ownerDoc, XPathConstants.NODESET);
                    if (nl.getLength() > 0) {
                        Element sigPosElement = (Element) nl.item(nl.getLength() - 1);
                        sigPosElement.appendChild(tmpNode);
                    } else {
                        Element signaturePositionElement;
                        if (signingParentNode.getNodeType() == 9) {
                            signaturePositionElement = findPosition(ownerDoc, false, signaturePosition);
                        } else {
                            signaturePositionElement = findPosition(ownerDoc, true, signaturePosition);
                        }
                        signaturePositionElement.appendChild(tmpNode);
                    }
                }
            } else {
                signingParentNode.appendChild(tmpNode);
            }
        } else {
            signingParentNode.appendChild(tmpNode);
        }

        //L?y to�n b? th? SignedInfo d� t?o t?m d? k�, dua v�o 1 document, v� t?o attr xmlns (b?t bu?c)
        Node signedInfo = signature.getElementsByTagName("SignedInfo").item(0);
        Element signedInfoEle = (Element) doc.importNode((Element) signedInfo, true);
        signedInfoEle.setAttribute("xmlns", "http://www.w3.org/2000/09/xmldsig#");
        doc.appendChild(signedInfoEle);

        //format l?i d?nh d?ng d? li?u xml theo chu?n
        Canonicalizer c14n = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
        byte[] transformed = c14n.canonicalizeSubtree(doc);
        //hash
        byte[] hash = ExtFunc.hash(transformed, hashAlgo.name());
        //luu cache document dang x? l� theo sessionId, tr? v? hash v� sessionId
        //LOG.info("VUDP - hash: " + DatatypeConverter.printHexBinary(hash));
        byte[] data2sign = null;
        String hashAlgorithm = getHashAlgorithm(hash);
        if (hashAlgorithm.compareToIgnoreCase(HASH_SHA512) == 0
                || hashAlgorithm.compareToIgnoreCase(HASH_SHA512_) == 0) {
            data2sign = paddingSHA512OID(hash);
        } else if (hashAlgorithm.compareToIgnoreCase(HASH_SHA256) == 0
                || hashAlgorithm.compareToIgnoreCase(HASH_SHA256_) == 0) {

            data2sign = paddingSHA256OID(hash);
        } else if (hashAlgorithm.compareToIgnoreCase(HASH_SHA384) == 0
                || hashAlgorithm.compareToIgnoreCase(HASH_SHA384_) == 0) {
            data2sign = paddingSHA384OID(hash);
        } else if (hashAlgorithm.compareToIgnoreCase(HASH_MD5) == 0) {
            data2sign = paddingMD5OID(hash);
        } else {
            data2sign = paddingSHA1OID(hash);
        }

        //LOG.info("VUDP - data2sign: " + DatatypeConverter.printHexBinary(data2sign));
        //LOG.info("VUDP - provider: " + provider);
        Signature s = Signature.getInstance("NONEwithRSA", provider);
        s.initSign(privateKey);
        s.update(data2sign);

        byte[] rawSignature = s.sign();
        //LOG.info("VUDP - rawSignature: " + DatatypeConverter.printHexBinary(rawSignature));
        //LOG.info("VUDP - rawSignature: " + DatatypeConverter.printBase64Binary(rawSignature));
        //byte[] rawSignature = signHashWithInfo(hash, privateKey, hashAlgo);

        if (rawSignature == null) {
            LOG.error("Error while signing xml file");
            throw new Exception("Error while signing xml file");
        }
        NodeList sigValueList = originalDocument.getElementsByTagName("SignatureValue");
        if (ExtFunc.isNullOrEmpty(signatureID)) {
            //l?y node cu?i c�ng
            sigValueList.item(sigValueList.getLength() - 1).setTextContent(DatatypeConverter.printBase64Binary(rawSignature));
        } else {
            int index = -1;
            for (int i = 0; i < sigValueList.getLength(); i++) {
                //Ki?m tra th? cha id = $signatureTagId?
                Node parent = sigValueList.item(i).getParentNode();
                Node attrId = parent.getAttributes().getNamedItem("Id");
                if (attrId != null && attrId.getTextContent().equals(signatureID)) {
                    index = i;
                }
            }
            if (index == -1) {
                throw new Exception("Could not find SignatureValue node for wrapping");
            }
            sigValueList.item(index).setTextContent(DatatypeConverter.printBase64Binary(rawSignature));
        }
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();

        if (omitXmlDeclaration) {
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        }

        DOMSource source = new DOMSource(originalDocument);
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        StreamResult result = new StreamResult(os);
        transformer.transform(source, result);
        byte[] signedData = os.toByteArray();
        os.close();
        return signedData;
    }

    private Element findPosition(Document document, boolean checkExited, String direct) throws Exception {
        Element redirect;
        String[] textArray = direct.split("/");
        String directPath = "";
        for (int i = 0; i < textArray.length; i++) {
            if ("".equals(textArray[i])) {
                continue;
            }
            if (i == 0) {
                directPath = directPath + textArray[i];
                continue;
            }
            if (i == 1 && "".equals(directPath)) {
                directPath = directPath + textArray[i];
                continue;
            }
            directPath = directPath + "/" + textArray[i];
        }

        String[] paths = directPath.split("/");

        if (checkExited) {
            redirect = (Element) document.getDocumentElement();
            if (redirect.getFirstChild().equals(redirect.getElementsByTagName(paths[0]).item(0))) {
                redirect = null;
            } else {
                for (String path : paths) {
                    Element check = (Element) redirect.getElementsByTagName(path).item(0);
                    if (check == null) {
                        Element child = document.createElement(path);
                        redirect.appendChild(child);
                        redirect = child;
                    } else {
                        redirect = check;
                    }
                }
            }
        } else {
            redirect = (Element) document.getDocumentElement();
            for (String path : paths) {
                Element check = (Element) redirect.getElementsByTagName(path).item(0);
                if (check == null) {
                    Element child = document.createElement(path);
                    redirect.appendChild(child);
                    redirect = child;
                } else {
                    redirect = check;
                }
            }
        }
        return redirect;
    }

    private Element prepareSignature(Node signingNode) throws Exception {
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);

        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.newDocument();

        //root signature node
        Element sigElement = doc.createElement("Signature");
        if (!ExtFunc.isNullOrEmpty(signatureID)) {
            sigElement.setAttribute("Id", signatureID);
        }
        sigElement.setAttribute("xmlns", "http://www.w3.org/2000/09/xmldsig#");

        //signedInfo node
        Element signedInfo = doc.createElement("SignedInfo");
        //signedInfo-canonicalizationMethod node
        Element canonicalizationMethod = doc.createElement("CanonicalizationMethod");
        canonicalizationMethod.setAttribute("Algorithm", USING_NS ? "http://www.w3.org/2001/10/xml-exc-c14n#"
                : "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
        signedInfo.appendChild(canonicalizationMethod);
        //signedInfo-SignatureMethod node
        Element signatureMethod = doc.createElement("SignatureMethod");
        signatureMethod.setAttribute("Algorithm", hashAlgo.getSignatureMethod());
        signedInfo.appendChild(signatureMethod);

        //SignedInfo-Reference node
        Element reference = doc.createElement("Reference");
        reference.setAttribute("URI", "#" + signingAttributeID);
        signedInfo.appendChild(reference);
        Element transforms = doc.createElement("Transforms");
        Element transform1 = doc.createElement("Transform");
        transform1.setAttribute("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature"); //http://www.w3.org/2001/10/xml-exc-c14n#
        transforms.appendChild(transform1);
        if (USING_NS) {
            Element transform2 = doc.createElement("Transform");
            transform2.setAttribute("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#");
            transforms.appendChild(transform2);
        }

        reference.appendChild(transforms);

        Element digestMethod = doc.createElement("DigestMethod");
        digestMethod.setAttribute("Algorithm", hashAlgo.getHashMethod());
        reference.appendChild(digestMethod);
        //t�nh to�n base64 cua digestValue
        Element digestValue = doc.createElement("DigestValue");
        digestValue.setTextContent(getDigestForRemote(signingNode));
        reference.appendChild(digestValue);
        signedInfo.appendChild(reference);

        //TimeStamp node
        Element timestampObject = doc.createElement("Object");
        if (!ExtFunc.isNullOrEmpty(signingTimeObjectID)) {
            timestampObject.setAttribute("Id", signingTimeObjectID);
        }

        Element signatureProperties = doc.createElement("SignatureProperties");

        if (signaturePropertiesXMLNS != null) {
            signatureProperties.setAttribute("xmlns", signaturePropertiesXMLNS);
        }

        timestampObject.appendChild(signatureProperties);

        Element signatureProperty = doc.createElement("SignatureProperty");
        if (!ExtFunc.isNullOrEmpty(signingTimeSignaturePropertyID)) {
            signatureProperty.setAttribute("Id", signingTimeSignaturePropertyID);
        }
        if (!ExtFunc.isNullOrEmpty(signatureID)) {
            signatureProperty.setAttribute("Target", "#" + signatureID);
        }
        signatureProperties.appendChild(signatureProperty);

        if (ExtFunc.isNullOrEmpty(signingTimeTAG)) {
            signingTimeTAG = DEFAULT_SIGNING_TIME_TAG;
        }

        Element signingTime = doc.createElement(signingTimeTAG);
        if (!ExtFunc.isNullOrEmpty(signingTimeXMLNS)) {
            signingTime.setAttribute("xmlns", signingTimeXMLNS);
        }
        signingTime.setTextContent(signingTimeValue);
        signatureProperty.appendChild(signingTime);

        //SignedInfo-Reference TimeStamp node
        Element timeStampReference = doc.createElement("Reference");
        timeStampReference.setAttribute("URI", "#" + signingTimeObjectID);
        /*
         * Element timeStampTransforms = doc.createElement("Transforms");
         * Element timeStampTransform1 = doc.createElement("Transform");
         * timeStampTransform1.setAttribute("Algorithm",
         * "http://www.w3.org/2001/10/xml-exc-c14n#");
         * timeStampTransforms.appendChild(timeStampTransform1); if (USING_NS) {
         * Element timeStampTransform2 = doc.createElement("Transform");
         * timeStampTransform2.setAttribute("Algorithm",
         * "http://www.w3.org/2001/10/xml-exc-c14n#");
         * timeStampTransforms.appendChild(timeStampTransform2); }
         *
         * timeStampReference.appendChild(timeStampTransforms);
         */
        Element timeStampDigestMethod = doc.createElement("DigestMethod");
        timeStampDigestMethod.setAttribute("Algorithm", hashAlgo.getHashMethod());
        timeStampReference.appendChild(timeStampDigestMethod);
        //t�nh to�n base64 cua digestValue
        Element timeStampDigestValue = doc.createElement("DigestValue");
        timeStampDigestValue.setTextContent(getHashOfSigningTimeObject(
                signingTimeObjectID,
                signingTimeSignaturePropertyID,
                signatureID,
                signaturePropertiesXMLNS,
                signingTimeXMLNS,
                signingTimeValue,
                hashAlgo));
        timeStampReference.appendChild(timeStampDigestValue);
        signedInfo.appendChild(timeStampReference);

        sigElement.appendChild(signedInfo);

        //signatureValue node
        Element signatureValue = doc.createElement("SignatureValue");
//        signatureValue.setTextContent("");
        sigElement.appendChild(signatureValue);

        //keyInfo node
        Element keyInfo = doc.createElement("KeyInfo");
        Element x509Data = doc.createElement("X509Data");

        Element x509SubjectName = doc.createElement("X509SubjectName");
        x509SubjectName.setTextContent(signingCertificate.getSubjectDN().getName());
        x509Data.appendChild(x509SubjectName);

        Element x509Certificate = doc.createElement("X509Certificate");
        x509Certificate.setTextContent(DatatypeConverter.printBase64Binary(signingCertificate.getEncoded()));
        x509Data.appendChild(x509Certificate);
        keyInfo.appendChild(x509Data);
        sigElement.appendChild(keyInfo);

        sigElement.appendChild(timestampObject);

        doc.appendChild(sigElement);
        return sigElement;
    }

    private String getDigestForRemote(Node signingNode) throws Exception {
        //format l?i d?nh d?ng d? li?u xml theo chu?n
        Canonicalizer c14n = USING_NS
                ? Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS) : Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        byte[] transformed = c14n.canonicalizeSubtree(signingNode);

        //hash d? li?u d� d?nh d?ng
        return DatatypeConverter.printBase64Binary(ExtFunc.hash(transformed, hashAlgo.name()));
    }

    private String getHashOfSigningTimeObject(
            String objectID,
            String signaturePropertyID,
            String target,
            String signaturePropertiesXMLNS,
            String signingTimeValueXmlNS,
            String signingTimeValue,
            DigestAlgorithm hashAlgo) throws Exception {
        String value = "";
        if (ExtFunc.isNullOrEmpty(signaturePropertyID)) {
            if (ExtFunc.isNullOrEmpty(signingTimeValueXmlNS)) {
                value = "<Object xmlns=\"http://www.w3.org/2000/09/xmldsig#\" "
                        + "Id=\"" + objectID + "\">"
                        + "<SignatureProperties" + (signaturePropertiesXMLNS == null ? "" : " xmlns=\"" + signaturePropertiesXMLNS + "\"") + "><SignatureProperty "
                        + "Target=\"#" + target + "\">"
                        + "<SigningTime>" + signingTimeValue + "</SigningTime></SignatureProperty></SignatureProperties></Object>";
            } else {
                value = "<Object xmlns=\"http://www.w3.org/2000/09/xmldsig#\" "
                        + "Id=\"" + objectID + "\">"
                        + "<SignatureProperties" + (signaturePropertiesXMLNS == null ? "" : " xmlns=\"" + signaturePropertiesXMLNS + "\"") + "><SignatureProperty "
                        + "Target=\"#" + target + "\">"
                        + "<SigningTime xmlns=\"" + signingTimeValueXmlNS + "\">" + signingTimeValue + "</SigningTime></SignatureProperty></SignatureProperties></Object>";
            }
        } else {
            if (ExtFunc.isNullOrEmpty(signingTimeValueXmlNS)) {
                value = "<Object "
                        + "xmlns=\"http://www.w3.org/2000/09/xmldsig#\" "
                        + "Id=\"" + objectID + "\">"
                        + "<SignatureProperties" + (signaturePropertiesXMLNS == null ? "" : " xmlns=\"" + signaturePropertiesXMLNS + "\"") + "><SignatureProperty "
                        + "Id=\"" + signaturePropertyID + "\" "
                        + "Target=\"#" + target + "\">"
                        + "<SigningTime>" + signingTimeValue + "</SigningTime></SignatureProperty></SignatureProperties></Object>";
            } else {
                value = "<Object "
                        + "xmlns=\"http://www.w3.org/2000/09/xmldsig#\" "
                        + "Id=\"" + objectID + "\">"
                        + "<SignatureProperties" + (signaturePropertiesXMLNS == null ? "" : " xmlns=\"" + signaturePropertiesXMLNS + "\"") + "><SignatureProperty "
                        + "Id=\"" + signaturePropertyID + "\" "
                        + "Target=\"#" + target + "\">"
                        + "<SigningTime xmlns=\"" + signingTimeValueXmlNS + "\">" + signingTimeValue + "</SigningTime></SignatureProperty></SignatureProperties></Object>";
            }
        }
        return DatatypeConverter.printBase64Binary(ExtFunc.hash(value.getBytes(), hashAlgo.name()));
    }

    private String getHashAlgorithm(byte[] hashData) {
        int len = hashData.length;
        switch (len) {
            case HASH_MD5_LEN:
                return HASH_MD5;
            case HASH_MD5_LEN_PADDED:
                return HASH_MD5;
            case HASH_SHA1_LEN:
                return HASH_SHA1;
            case HASH_SHA1_LEN_PADDED:
                return HASH_SHA1;
            case HASH_SHA256_LEN:
                return HASH_SHA256;
            case HASH_SHA256_LEN_PADDED:
                return HASH_SHA256;
            case HASH_SHA384_LEN:
                return HASH_SHA384;
            case HASH_SHA384_LEN_PADDED:
                return HASH_SHA384;
            case HASH_SHA512_LEN:
                return HASH_SHA512;
            case HASH_SHA512_LEN_PADDED:
                return HASH_SHA512;
            default:
                return HASH_SHA1;
        }
    }
    final public static int HASH_MD5_LEN = 16;
    final public static int HASH_MD5_LEN_PADDED = 34;
    final public static int HASH_SHA1_LEN = 20;
    final public static int HASH_SHA1_LEN_PADDED = 35;
    final public static int HASH_SHA256_LEN = 32;
    final public static int HASH_SHA256_LEN_PADDED = 51;
    final public static int HASH_SHA384_LEN = 48;
    final public static int HASH_SHA384_LEN_PADDED = 67;
    final public static int HASH_SHA512_LEN = 64;
    final public static int HASH_SHA512_LEN_PADDED = 83;
    final public static String HASH_MD5 = "MD5";
    final public static String HASH_SHA1 = "SHA-1";
    final public static String HASH_SHA256 = "SHA-256";
    final public static String HASH_SHA384 = "SHA-384";
    final public static String HASH_SHA512 = "SHA-512";
    final public static String HASH_SHA1_ = "SHA1";
    final public static String HASH_SHA256_ = "SHA256";
    final public static String HASH_SHA384_ = "SHA384";
    final public static String HASH_SHA512_ = "SHA512";

    private byte[] paddingSHA1OID(byte[] hashedData) throws Exception {
        LOG.debug("Padding SHA-1 OID");
        DigestAlgorithmIdentifierFinder hashAlgorithmFinder = new DefaultDigestAlgorithmIdentifierFinder();
        AlgorithmIdentifier hashingAlgorithmIdentifier = hashAlgorithmFinder.find(HASH_SHA1);
        DigestInfo digestInfo = new DigestInfo(hashingAlgorithmIdentifier, hashedData);
        return digestInfo.getEncoded();
    }

    private byte[] paddingSHA256OID(byte[] hashedData) throws Exception {
        LOG.debug("Padding SHA-256 OID");
        DigestAlgorithmIdentifierFinder hashAlgorithmFinder = new DefaultDigestAlgorithmIdentifierFinder();
        AlgorithmIdentifier hashingAlgorithmIdentifier = hashAlgorithmFinder.find(HASH_SHA256);
        DigestInfo digestInfo = new DigestInfo(hashingAlgorithmIdentifier, hashedData);
        return digestInfo.getEncoded();
    }

    private byte[] paddingSHA384OID(byte[] hashedData) throws Exception {
        LOG.debug("Padding SHA-384 OID");
        DigestAlgorithmIdentifierFinder hashAlgorithmFinder = new DefaultDigestAlgorithmIdentifierFinder();
        AlgorithmIdentifier hashingAlgorithmIdentifier = hashAlgorithmFinder.find(HASH_SHA384);
        DigestInfo digestInfo = new DigestInfo(hashingAlgorithmIdentifier, hashedData);
        return digestInfo.getEncoded();
    }

    private byte[] paddingSHA512OID(byte[] hashedData) throws Exception {
        LOG.debug("Padding SHA-512 OID");
        DigestAlgorithmIdentifierFinder hashAlgorithmFinder = new DefaultDigestAlgorithmIdentifierFinder();
        AlgorithmIdentifier hashingAlgorithmIdentifier = hashAlgorithmFinder.find(HASH_SHA512);
        DigestInfo digestInfo = new DigestInfo(hashingAlgorithmIdentifier, hashedData);
        return digestInfo.getEncoded();
    }

    private byte[] paddingMD5OID(byte[] hashedData) throws Exception {
        LOG.debug("Padding MD5 OID");
        DigestAlgorithmIdentifierFinder hashAlgorithmFinder = new DefaultDigestAlgorithmIdentifierFinder();
        AlgorithmIdentifier hashingAlgorithmIdentifier = hashAlgorithmFinder.find(HASH_MD5);
        DigestInfo digestInfo = new DigestInfo(hashingAlgorithmIdentifier, hashedData);
        return digestInfo.getEncoded();
    }

    private byte[] signHashWithInfo(byte[] hash, PrivateKey privateKey, DigestAlgorithm algo) throws Exception {

        ASN1ObjectIdentifier oidObject = new ASN1ObjectIdentifier(algo.getOid());

        AlgorithmIdentifier identifier = new AlgorithmIdentifier(oidObject, null);
        DigestInfo di = new DigestInfo(identifier, hash);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", provider);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(di.getEncoded());
    }
}
