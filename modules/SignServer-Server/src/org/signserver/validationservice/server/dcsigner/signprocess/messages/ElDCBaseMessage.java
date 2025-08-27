package org.signserver.validationservice.server.dcsigner.signprocess.messages;

import java.util.*;
import java.security.*;
import org.signserver.validationservice.server.dcsigner.signprocess.*;
import org.w3c.dom.*;

public class ElDCBaseMessage
{
    protected static String typeID;
    protected String id;
    protected String name;
    protected ElDCBaseMessage originalMessage;
    protected ArrayList<ElDCMessageParameter> parameters;
    
    protected void assignParameters(final ArrayList<ElDCMessageParameter> list) {
        this.parameters.clear();
        for (int i = 0; i < list.size(); ++i) {
            this.parameters.add(list.get(i).clone());
        }
    }
    
    protected void customLoadFromXML(final Element element) throws Exception {
    }
    
    protected void customSaveToXML(final Element element) {
    }
    
    protected void generateID() {
        final SecureRandom secureRandom = new SecureRandom();
        final byte[] array = new byte[16];
        secureRandom.nextBytes(array);
        this.id = ElDCUtils.base16Encode(array);
    }
    
    protected String getMessageTypeID() {
        return "Message.Base";
    }
    
    public ElDCBaseMessage() {
        this.generateID();
        this.name = "";
        this.parameters = new ArrayList<ElDCMessageParameter>();
        this.originalMessage = null;
    }
    
    public ElDCBaseMessage(final ElDCBaseMessage elDCBaseMessage) {
        this();
        this.originalMessage = elDCBaseMessage.clone();
    }
    
    public void assign(final ElDCBaseMessage elDCBaseMessage) throws ElDCMessageException {
        this.id = new String(elDCBaseMessage.getID());
        this.name = new String(elDCBaseMessage.getName());
        this.assignParameters(elDCBaseMessage.getParameters());
        if (elDCBaseMessage.getOriginalMessage() == null) {
            this.originalMessage = null;
        }
        else {
            this.originalMessage = elDCBaseMessage.getOriginalMessage().clone();
        }
    }
    
    public ElDCBaseMessage clone() {
        final ElDCBaseMessage elDCBaseMessage = new ElDCBaseMessage();
        try {
            elDCBaseMessage.assign(this);
        }
        catch (ElDCMessageException ex) {}
        return elDCBaseMessage;
    }
    
    public ElDCBaseMessage clone(final boolean b) {
        final ElDCBaseMessage clone = this.clone();
        if (b) {
            clone.generateID();
        }
        return clone;
    }
    
    public String getID() {
        return this.id;
    }
    
    public String getName() {
        return this.name;
    }
    
    public ElDCBaseMessage getOriginalMessage() {
        return this.originalMessage;
    }
    
    public ArrayList<ElDCMessageParameter> getParameters() {
        return this.parameters;
    }
    
    public void loadFromXML(final Element element) throws Exception {
        final String loadStringFromXML = ElDCUtils.loadStringFromXML(element, "MessageType", "", false);
        if (!loadStringFromXML.equalsIgnoreCase(this.getMessageTypeID())) {
            throw new ElDCMessageException(String.format("Unsupported message type: %s", loadStringFromXML));
        }
        this.id = ElDCUtils.loadStringFromXML(element, "MessageID", "", false);
        this.name = ElDCUtils.loadStringFromXML(element, "Name", "", false);
        this.parameters.clear();
        ElDCUtils.loadParametersFromXML(element, "Pars", "Par", this.parameters, false);
        this.originalMessage = null;
        final NodeList childNodes = element.getChildNodes();
        for (int length = childNodes.getLength(), i = 0; i < length; ++i) {
            final Node item = childNodes.item(i);
            if (item.getNodeType() == 1 && item.getNodeName().equalsIgnoreCase("OriginalMessage")) {
                this.originalMessage = new ElDCMessageFactory().createInstance((Element)item);
                break;
            }
        }
        this.customLoadFromXML(element);
    }
    
    public void saveToXML(final Element element) {
        ElDCUtils.saveStringToXML(element, "MessageType", this.getMessageTypeID());
        ElDCUtils.saveStringToXML(element, "MessageID", this.id);
        ElDCUtils.saveStringToXML(element, "Name", this.name);
        ElDCUtils.saveParametersToXML(element, "Pars", "Par", this.parameters);
        if (this.originalMessage != null) {
            final Element element2 = element.getOwnerDocument().createElement("OriginalMessage");
            element.appendChild(element2);
            this.originalMessage.saveToXML(element2);
        }
        this.customSaveToXML(element);
    }
    
    public void setID(final String id) {
        this.id = id;
    }
    
    public void setName(final String name) {
        this.name = name;
    }
}
