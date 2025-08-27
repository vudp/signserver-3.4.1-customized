package org.signserver.validationservice.server.dcsigner.signprocess;

import java.util.*;
import org.signserver.validationservice.server.dcsigner.signprocess.messages.*;
import org.w3c.dom.*;
import java.io.*;
import javax.xml.transform.dom.*;
import javax.xml.transform.stream.*;
import javax.xml.parsers.*;
import javax.xml.transform.*;

public class ElDCAsyncState
{
    protected String generator;
    protected ElDCAsyncState innerState;
    protected ElDCBatchMessage messages;
    protected ArrayList<String> stateSubtypes;
    protected String stateType;
    protected short[] userData;
    protected static final String defaultGeneratorName = "SecureBlackbox (Java Applet)";
    
    public ElDCAsyncState() {
        this.innerState = null;
        this.generator = "SecureBlackbox (Java Applet)";
        this.messages = new ElDCBatchMessage();
        this.stateSubtypes = new ArrayList<String>();
        this.stateType = "State.Generic";
        this.userData = null;
    }
    
    public ElDCAsyncState(final ElDCAsyncState innerState) {
        this();
        this.innerState = innerState;
    }
    
    public void clear() {
        this.generator = "SecureBlackbox (Java Applet)";
        this.innerState = null;
        this.stateType = "State.Generic";
        this.stateSubtypes.clear();
        this.messages.clear();
        this.userData = null;
    }
    
    public ElDCBaseMessage findMessageByName(final String s) {
        for (int i = 0; i < this.messages.getCount(); ++i) {
            if (this.messages.getMessage(i).getName().equalsIgnoreCase(s)) {
                return this.messages.getMessage(i);
            }
        }
        return null;
    }
    
    public String getGenerator() {
        return this.generator;
    }
    
    public ElDCAsyncState getInnerState() {
        return this.innerState;
    }
    
    public ElDCBatchMessage getMessages() {
        return this.messages;
    }
    
    public ArrayList<String> getStateSubtypes() {
        return this.stateSubtypes;
    }
    
    public String getStateType() {
        return this.stateType;
    }
    
    public short[] getUserData() {
        return this.userData;
    }
    
    public void loadFromXML(final InputStream is) throws Exception {
        this.loadFromXML(DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(is));
    }
    
    public void loadFromXML(final Document document) throws Exception {
        this.loadFromXML(document.getDocumentElement());
    }
    
    public void loadFromXML(final Element element) throws Exception {
        this.clear();
        if (!element.getNodeName().equalsIgnoreCase("SecureBlackboxAsyncState")) {
            throw new ElDCAsyncStateException("Invalid asynchronous state format");
        }
        this.innerState = null;
        this.stateType = ElDCUtils.loadStringFromXML(element, "Type", "State.Generic", false);
        ElDCUtils.loadListFromXML(element, "Subtypes", "Subtype", this.stateSubtypes, false);
        this.generator = ElDCUtils.loadStringFromXML(element, "Generator", "", false);
        this.userData = ElDCUtils.base16DecodeShorts(ElDCUtils.loadStringFromXML(element, "UserData", "", false));
        this.messages.clear();
        final NodeList childNodes = element.getChildNodes();
        for (int length = childNodes.getLength(), i = 0; i < length; ++i) {
            final Node item = childNodes.item(i);
            if (item.getNodeType() == 1) {
                if (item.getNodeName().equalsIgnoreCase("RootMessage")) {
                    this.messages.loadFromXML((Element)item);
                    if (this.innerState != null) {
                        break;
                    }
                }
                else if (item.getNodeName().equalsIgnoreCase("InnerState")) {
                    (this.innerState = new ElDCAsyncState()).loadFromXML((Element)item);
                    if (this.messages.getCount() > 0) {
                        break;
                    }
                }
            }
        }
    }
    
    public void saveToXML(final OutputStream outputStream) throws ParserConfigurationException, TransformerException {
        final Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
        document.setXmlStandalone(true);
        this.saveToXML(document);
        TransformerFactory.newInstance().newTransformer().transform(new DOMSource(document), new StreamResult(outputStream));
    }
    
    public void saveToXML(final Document document) {
        if (document.getDocumentElement() == null) {
            document.appendChild(document.createElement("SecureBlackboxAsyncState"));
        }
        this.saveToXML(document.getDocumentElement());
    }
    
    public void saveToXML(final Element element) {
        ElDCUtils.saveStringToXML(element, "Type", this.stateType);
        ElDCUtils.saveListToXML(element, "Subtypes", "Subtype", this.stateSubtypes);
        ElDCUtils.saveStringToXML(element, "Generator", this.generator);
        ElDCUtils.saveBinaryToXML(element, "UserData", this.userData);
        final Document ownerDocument = element.getOwnerDocument();
        final Element element2 = ownerDocument.createElement("RootMessage");
        element.appendChild(element2);
        this.messages.saveToXML(element2);
        if (this.innerState != null) {
            final Element element3 = ownerDocument.createElement("InnerState");
            element.appendChild(element3);
            this.innerState.saveToXML(element3);
        }
    }
    
    public void setStateSubtypes(final ArrayList<String> list) {
        if (this.stateSubtypes == list) {
            return;
        }
        this.stateSubtypes.clear();
        if (list == null) {
            return;
        }
        for (int i = 0; i < list.size(); ++i) {
            this.stateSubtypes.add(new String(list.get(i)));
        }
    }
    
    public void setStateType(final String s) {
        this.stateType = new String(s);
    }
    
    public void setUserData(final short[] array) {
        if (this.userData == array) {
            return;
        }
        this.userData = null;
        if (array == null) {
            return;
        }
        ElDCUtils.checkByteArray(array);
        this.userData = array.clone();
    }
    
    public boolean subtypePresent(final String s) {
        for (int size = this.stateSubtypes.size(), i = 0; i < size; ++i) {
            if (this.stateSubtypes.get(i).equalsIgnoreCase(s)) {
                return true;
            }
        }
        return false;
    }
}
