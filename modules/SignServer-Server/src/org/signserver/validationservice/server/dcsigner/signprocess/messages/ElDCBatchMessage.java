package org.signserver.validationservice.server.dcsigner.signprocess.messages;

import java.util.*;

import org.signserver.validationservice.server.dcsigner.*;
import org.signserver.validationservice.server.dcsigner.signprocess.ElDCMessageException;

import org.w3c.dom.*;

public class ElDCBatchMessage extends ElDCBaseMessage
{
    protected ArrayList<ElDCBaseMessage> messages;
    
    protected String getMessageTypeID() {
        return "Message.Batch";
    }
    
    public ElDCBatchMessage() {
        this.messages = new ArrayList<ElDCBaseMessage>();
    }
    
    public ElDCBatchMessage(final ElDCBaseMessage elDCBaseMessage) {
        super(elDCBaseMessage);
        this.messages = new ArrayList<ElDCBaseMessage>();
    }
    
    public void assign(final ElDCBaseMessage elDCBaseMessage) throws ElDCMessageException {
        if (!(elDCBaseMessage instanceof ElDCBatchMessage)) {
            throw new ElDCMessageException(String.format("Cannot assign an object of class %s to an object of class %s", elDCBaseMessage.getClass().getName(), this.getClass().getName()));
        }
        super.assign(elDCBaseMessage);
        this.messages.clear();
        for (int i = 0; i < ((ElDCBatchMessage)elDCBaseMessage).messages.size(); ++i) {
            this.messages.add(((ElDCBatchMessage)elDCBaseMessage).messages.get(i).clone());
        }
    }
    
    public ElDCBaseMessage clone() {
        final ElDCBatchMessage elDCBatchMessage = new ElDCBatchMessage();
        try {
            elDCBatchMessage.assign(this);
        }
        catch (ElDCMessageException ex) {}
        return elDCBatchMessage;
    }
    
    public int getCount() {
        return this.messages.size();
    }
    
    public ElDCBaseMessage getMessage(final int n) {
        return this.messages.get(n);
    }
    
    public int add(final ElDCBaseMessage elDCBaseMessage, final boolean b) {
        this.messages.add(b ? elDCBaseMessage.clone() : elDCBaseMessage);
        return this.messages.size() - 1;
    }
    
    public void clear() {
        this.messages.clear();
    }
    
    public void remove(final int n) {
        this.messages.remove(n);
    }
    
    protected void customLoadFromXML(final Element element) throws Exception {
        this.messages.clear();
        final ElDCMessageFactory elDCMessageFactory = new ElDCMessageFactory();
        final NodeList childNodes = element.getChildNodes();
        for (int length = childNodes.getLength(), i = 0; i < length; ++i) {
            final Node item = childNodes.item(i);
            if (item.getNodeType() == 1 && item.getNodeName().equalsIgnoreCase("BatchElement")) {
                this.messages.add(elDCMessageFactory.createInstance((Element)item));
            }
        }
    }
    
    protected void customSaveToXML(final Element element) {
        for (int i = 0; i < this.messages.size(); ++i) {
            final Element element2 = element.getOwnerDocument().createElement("BatchElement");
            element.appendChild(element2);
            this.messages.get(i).saveToXML(element2);
        }
    }
}
