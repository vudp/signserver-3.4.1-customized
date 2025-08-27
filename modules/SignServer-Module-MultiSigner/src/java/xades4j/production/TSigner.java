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

import xades4j.algorithms.Algorithm;
import xades4j.algorithms.ExclusiveCanonicalXMLWithoutComments;
import xades4j.properties.SignaturePolicyBase;
import xades4j.properties.SignaturePolicyImpliedProperty;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.providers.SignaturePolicyInfoProvider;
import xades4j.providers.impl.DefaultAlgorithmsProviderEx;
import xades4j.providers.impl.ExtingKeyingDataProvider;
import xades4j.providers.impl.HttpTimeStampTokenProvider;
import xades4j.providers.impl.EndpointTSAProvider;
import xades4j.providers.impl.TSAHttpData;
import xades4j.utils.DOMHelper;

import com.google.inject.Inject;

public class TSigner {
	
	private static String tsaProvider;
	private static int trustedhubTransId;
	private static String channelName;
	private static String user;
	
	static class TestTimeStampTokenProvider extends EndpointTSAProvider
    {
        @Inject
        public TestTimeStampTokenProvider(MessageDigestEngineProvider messageDigestProvider)
        {
            super(messageDigestProvider, tsaProvider, channelName, user, trustedhubTransId);
        }
    }

    static class ExclusiveC14nForTimeStampsAlgorithmsProvider extends DefaultAlgorithmsProviderEx
    {
        @Override
        public Algorithm getCanonicalizationAlgorithmForTimeStampProperties()
        {
            return new ExclusiveCanonicalXMLWithoutComments("dsign", "xades"); //ds
        }

        @Override
        public Algorithm getCanonicalizationAlgorithmForSignature()
        {
            return new ExclusiveCanonicalXMLWithoutComments();
        }
    }
	
	public byte[] sign(byte[] data, List<X509Certificate> certs, PrivateKey privateKey
			, String signatureLocation, String signatureId, boolean includeSubjectName, String tsaProvider, String channelName, String user, int trustedhubTransId) throws Exception {
		
		this.tsaProvider = tsaProvider;
		this.trustedhubTransId = trustedhubTransId;
		this.channelName = channelName;
		this.user = user;
		
		KeyingDataProvider keyingProviderMy = new ExtingKeyingDataProvider(certs, privateKey);
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
		Document doc = db.parse(new ByteArrayInputStream(data));
        //Element elem = doc.getDocumentElement();
        //DOMHelper.useIdAsXmlId(elem);
		
		Element elem = null;
        XPath xpath = XPathFactory.newInstance().newXPath();
    	XPathExpression expr = xpath.compile("//*[@Id]");
    	NodeList nodeList = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
    	if(nodeList.getLength() > 0) {
	    	for (int i=0; i<nodeList.getLength() ; i++) {
	    	  elem = (Element) nodeList.item(i);
	    	  Attr attr = (Attr) elem.getAttributes().getNamedItem("Id");
	    	  elem.setIdAttributeNode(attr, true);
	    	}
    	} else {
    		elem = doc.getDocumentElement();
    		DOMHelper.useIdAsXmlId(elem);
    	}
        
        SignerT signer = (SignerT) new XadesTSigningProfile(keyingProviderMy)
        	.withTimeStampTokenProvider(TestTimeStampTokenProvider.class)
        	.withAlgorithmsProviderEx(ExclusiveC14nForTimeStampsAlgorithmsProvider.class)
        	.newSigner();
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
