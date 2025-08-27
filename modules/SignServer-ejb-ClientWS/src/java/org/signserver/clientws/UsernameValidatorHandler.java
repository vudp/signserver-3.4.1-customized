package org.signserver.clientws;
 
import java.io.IOException;
import java.util.Iterator;
import java.util.Set;
import javax.xml.namespace.QName;
import javax.xml.soap.Node;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPConstants;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFault;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPMessage;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;
import javax.xml.ws.soap.SOAPFaultException;
 
public class UsernameValidatorHandler implements SOAPHandler<SOAPMessageContext>{
 
   @Override
   public boolean handleMessage(SOAPMessageContext context) {
 
	System.out.println("Server : handleMessage()......");
 
	Boolean isRequest = (Boolean) context.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
 
	//for response message only, true for outbound messages, false for inbound
	if(!isRequest){
 
	try{
	    SOAPMessage soapMsg = context.getMessage();
	    SOAPEnvelope soapEnv = soapMsg.getSOAPPart().getEnvelope();
            SOAPHeader soapHeader = soapEnv.getHeader();
 
            //if no header, add one
	    if (soapHeader == null){
	            soapHeader = soapEnv.addHeader();
	            //throw exception
	            generateSOAPErrMessage(soapMsg, "No SOAP header.");
	     }
 
	    
	    
	    
             //Get client mac address from SOAP header
	     Iterator it = soapHeader.extractHeaderElements(SOAPConstants.URI_SOAP_ACTOR_NEXT);
 
	     //if no header block for next actor found? throw exception
	     if (it == null || !it.hasNext()){
	      	generateSOAPErrMessage(soapMsg, "No header block for next actor.");
             }
 
//	     String macValueCompare = "F0-7B-CB-9F-6C-1F";
//	     String username = "tcchtnn";
//	     String password = "123456789";
//	     String signature = "s123456789";
//	     String digiSign= "ds123456789";
//	     System.out.println("[MacAdressValidatorHandler-handleMessage] before for");
//	     
//	     for (Iterator iterator = soapHeader.extractHeaderElements(SOAPConstants.URI_SOAP_ACTOR_NEXT); iterator.hasNext();) {
//				Node node = (Node) iterator.next();
//				String key = node.getNodeName();
//				System.out.println("[MacAdressValidatorHandler-handleMessage] key get node name: "+key);
//				System.out.println("[MacAdressValidatorHandler-handleMessage] key get prefix: "+node.getPrefix());
//				System.out.println("[MacAdressValidatorHandler-handleMessage] key get baseURI: "+node.getBaseURI());
//				System.out.println("[MacAdressValidatorHandler-handleMessage] key get namespaceURI: "+node.getNamespaceURI());
//		}
	     //if no mac address found? throw exception
	     Node macNode = (Node) it.next();
	     String macValue = (macNode == null) ? null : macNode.getValue();
	     System.out.println("[UsernameValidatorHandler-handleMessage] macnode: "+macValue);
// 
//	      if (macValue == null){
//	      	  generateSOAPErrMessage(soapMsg, "No mac address in header block.");
//	      }
// 
//	       //if mac address is not match, throw exception
//	       if(!macValue.equals("F0-7B-CB-9F-6C-1F")){
//	       	   generateSOAPErrMessage(soapMsg, "Invalid mac address, access is denied.");
//	       }
 
	       //tracking
	       soapMsg.writeTo(System.out);
 
		}catch(SOAPException e){
			System.err.println(e);
		}catch(IOException e){
			System.err.println(e);
		}
 
	    }
 
	  //continue other handler chain
	  return true;
	}
 
	@Override
	public boolean handleFault(SOAPMessageContext context) {
 
		System.out.println("UsernameValidatorHandler-Server : handleFault()......");
 
		return true;
	}
 
	@Override
	public void close(MessageContext context) {
		System.out.println("UsernameValidatorHandler-Server : close()......");
	}
 
	@Override
	public Set<QName> getHeaders() {
		System.out.println("UsernameValidatorHandler-Server : getHeaders()......");
		return null;
	}
 
     private void generateSOAPErrMessage(SOAPMessage msg, String reason) {
       try {
          SOAPBody soapBody = msg.getSOAPPart().getEnvelope().getBody();
          SOAPFault soapFault = soapBody.addFault();
          soapFault.setFaultString(reason);
          throw new SOAPFaultException(soapFault); 
       }
       catch(SOAPException e) { }
    }
 
}