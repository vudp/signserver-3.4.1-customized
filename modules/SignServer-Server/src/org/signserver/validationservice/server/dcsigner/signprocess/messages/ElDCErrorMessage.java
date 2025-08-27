package org.signserver.validationservice.server.dcsigner.signprocess.messages;

import org.w3c.dom.*;
import org.signserver.validationservice.server.dcsigner.signprocess.*;

public class ElDCErrorMessage extends ElDCBaseMessage
{
    protected int code;
    protected String errorMessage;
    
    protected void customLoadFromXML(final Element element) throws ElDCException {
        this.code = ElDCUtils.loadIntFromXML(element, "Code", 0, false);
        this.errorMessage = ElDCUtils.loadStringFromXML(element, "ErrorMessage", "", false);
    }
    
    protected void customSaveToXML(final Element element) {
        ElDCUtils.saveIntToXML(element, "Code", this.code);
        ElDCUtils.saveStringToXML(element, "ErrorMessage", this.errorMessage);
    }
    
    protected String getMessageTypeID() {
        return "Message.Error";
    }
    
    public ElDCErrorMessage() {
        this.code = 0;
        this.errorMessage = "";
    }
    
    public ElDCErrorMessage(final ElDCBaseMessage elDCBaseMessage) {
        super(elDCBaseMessage);
        this.code = 0;
        this.errorMessage = "";
    }
    
    public void assign(final ElDCBaseMessage elDCBaseMessage) throws ElDCMessageException {
        if (!(elDCBaseMessage instanceof ElDCErrorMessage)) {
            throw new ElDCMessageException(String.format("Cannot assign an object of class %s to an object of class %s", elDCBaseMessage.getClass().getName(), this.getClass().getName()));
        }
        super.assign(elDCBaseMessage);
        this.code = ((ElDCErrorMessage)elDCBaseMessage).code;
        this.errorMessage = new String(((ElDCErrorMessage)elDCBaseMessage).errorMessage);
    }
    
    public ElDCBaseMessage clone() {
        final ElDCErrorMessage elDCErrorMessage = new ElDCErrorMessage();
        try {
            elDCErrorMessage.assign(this);
        }
        catch (ElDCMessageException ex) {}
        return elDCErrorMessage;
    }
    
    public int getCode() {
        return this.code;
    }
    
    public String getErrorMessage() {
        return this.errorMessage;
    }
    
    public void setCode(final int code) {
        this.code = code;
    }
    
    public void setErrorMessage(final String s) {
        if (s != null) {
            this.errorMessage = new String(s);
        }
    }
}
