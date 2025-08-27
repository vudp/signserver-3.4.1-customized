package xades4j.production;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import xades4j.properties.IdentifierType;
import xades4j.properties.ObjectIdentifier;
import xades4j.properties.SignaturePolicyBase;
import xades4j.properties.SignaturePolicyIdentifierProperty;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.SignaturePolicyInfoProvider;
import xades4j.providers.impl.ExtingKeyingDataProvider;
import xades4j.utils.DOMHelper;

public class EPESSigner {

    private SignaturePolicyInfoProvider policyInfoProvider;

    public EPESSigner() {
        // TODO Auto-generated constructor stub
        try {
            setUp();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private void setUp() throws Exception {
        policyInfoProvider = new SignaturePolicyInfoProvider() {

            @Override
            public SignaturePolicyBase getSignaturePolicy() {
                /*
                 * return new SignaturePolicyIdentifierProperty( new
                 * ObjectIdentifier("oid:/1.2.4.0.9.4.5",
                 * IdentifierType.OIDAsURI, "Policy description"), new
                 * ByteArrayInputStream("Test policy input stream".getBytes()))
                 * .withLocationUrl("http://www.example.com/policy");
                 */
                return new SignaturePolicyIdentifierProperty(
                        new ObjectIdentifier("oid:/1.2.4.0.9.4.5", IdentifierType.OIDAsURI),
                        new ByteArrayInputStream("Mobile-ID Trustedhub policy input stream".getBytes()));
            }
        };
    }

    public byte[] sign(
            byte[] data, 
            List<X509Certificate> certs, 
            PrivateKey privateKey, 
            String signatureLocation, 
            String signatureId, 
            boolean includeSubjectName,
            String attributeName) throws Exception {

        KeyingDataProvider keyingProviderMy = new ExtingKeyingDataProvider(certs, privateKey);
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();

        Document doc = db.parse(new ByteArrayInputStream(data));

        //Element elem = doc.getDocumentElement();
        //DOMHelper.useIdAsXmlId(elem);


        Element elem = null;
        XPath xpath = XPathFactory.newInstance().newXPath();
        XPathExpression expr = xpath.compile("//*[@"+attributeName+"]");
        NodeList nodeList = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
        if (nodeList.getLength() > 0) {
            for (int i = 0; i < nodeList.getLength(); i++) {
                elem = (Element) nodeList.item(i);
                Attr attr = (Attr) elem.getAttributes().getNamedItem(attributeName);
                elem.setIdAttributeNode(attr, true);
            }
        } else {
            elem = doc.getDocumentElement();
            DOMHelper.useIdAsXmlId(elem);
        }

        SignerEPES signer = (SignerEPES) new XadesEpesSigningProfile(keyingProviderMy, policyInfoProvider).newSigner();
        //new Enveloped(signer).sign(elemToSign);
        new Enveloped(signer).sign(elem, signatureLocation, signatureId, includeSubjectName);

        TransformerFactory tf = TransformerFactory.newInstance();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        tf.newTransformer().transform(
                new DOMSource(doc),
                new StreamResult(out));
        byte[] signedData = out.toByteArray();
        out.close();
        return signedData;
    }
}
