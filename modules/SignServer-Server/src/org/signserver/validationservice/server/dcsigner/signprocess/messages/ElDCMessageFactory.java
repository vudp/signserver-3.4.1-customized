package org.signserver.validationservice.server.dcsigner.signprocess.messages;

import java.util.*;
import org.w3c.dom.*;
import org.signserver.validationservice.server.dcsigner.signprocess.*;
import java.io.*;
import javax.xml.parsers.*;

public class ElDCMessageFactory
{
    HashMap<String, Class<?>> registeredClasses;
    
    protected void registerDefaultMessageClasses() {
        this.registerClass("Message.Base", ElDCBaseMessage.class);
        this.registerClass("Message.Unsupported", ElDCUnsupportedMessage.class);
        this.registerClass("Message.Error", ElDCErrorMessage.class);
        this.registerClass("Message.OperationRequest", ElDCOperationRequestMessage.class);
        this.registerClass("Message.OperationResponse", ElDCOperationResponseMessage.class);
        this.registerClass("Message.Batch", ElDCBatchMessage.class);
    }
    
    public ElDCMessageFactory() {
        this.registeredClasses = new HashMap<String, Class<?>>();
        this.registerDefaultMessageClasses();
    }
    
    public ElDCBaseMessage createInstance(final String s) {
        if (s != null && s.length() != 0) {
            final Class<?> clazz = this.registeredClasses.get(s);
            if (clazz != null) {
                try {
                    return (ElDCBaseMessage)clazz.newInstance();
                }
                catch (Exception ex) {
                    return new ElDCUnsupportedMessage();
                }
            }
        }
        return new ElDCUnsupportedMessage();
    }
    
    public ElDCBaseMessage createInstance(final Element element) throws Exception {
        final ElDCBaseMessage instance = this.createInstance(ElDCUtils.loadStringFromXML(element, "MessageType", "", true));
        instance.loadFromXML(element);
        return instance;
    }
    
    public ElDCBaseMessage createInstance(final InputStream is) throws Exception {
        return this.createInstance(DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(is).getDocumentElement());
    }
    
    public void registerClass(final String s, final Class<?> clazz) {
        this.registeredClasses.put(s, clazz);
    }
}
