package org.signserver.validationservice.server.dcsigner.signprocess.messages;

import org.signserver.validationservice.server.dcsigner.signprocess.*;

public class ElDCUnsupportedMessage extends ElDCBaseMessage
{
    protected String getMessageTypeID() {
        return "Message.Unsupported";
    }
    
    public ElDCUnsupportedMessage() {
    }
    
    public ElDCUnsupportedMessage(final ElDCBaseMessage elDCBaseMessage) {
        super(elDCBaseMessage);
    }
    
    public void assign(final ElDCBaseMessage elDCBaseMessage) throws ElDCMessageException {
        if (!(elDCBaseMessage instanceof ElDCUnsupportedMessage)) {
            throw new ElDCMessageException(String.format("Cannot assign an object of class %s to an object of class %s", elDCBaseMessage.getClass().getName(), this.getClass().getName()));
        }
        super.assign(elDCBaseMessage);
    }
    
    public ElDCBaseMessage clone() {
        final ElDCUnsupportedMessage elDCUnsupportedMessage = new ElDCUnsupportedMessage();
        try {
            elDCUnsupportedMessage.assign(this);
        }
        catch (ElDCMessageException ex) {}
        return elDCUnsupportedMessage;
    }
}
