package org.signserver.validationservice.server.dcsigner.signprocess.messages;

import org.w3c.dom.*;
import org.signserver.validationservice.server.dcsigner.signprocess.*;

public class ElDCOperationRequestMessage extends ElDCBaseMessage
{
    protected ElDCOperation operation;
    protected String operationID;
    protected byte[] source;
    protected byte[] hashAlgorithm;
    protected boolean includeKeysInResponse;
    
    protected String getMessageTypeID() {
        return "Message.OperationRequest";
    }
    
    protected void customLoadFromXML(final Element element) throws ElDCException {
        this.operation = ElDCOperation.fromString(ElDCUtils.loadStringFromXML(element, "Operation", "Unknown", false));
        this.operationID = ElDCUtils.loadStringFromXML(element, "OperationID", "", false);
        this.source = ElDCUtils.base16DecodeBytes(ElDCUtils.loadStringFromXML(element, "Source", "", false));
        this.hashAlgorithm = ElDCUtils.base16DecodeBytes(ElDCUtils.loadStringFromXML(element, "HashAlgorithm", "", false));
        this.includeKeysInResponse = ElDCUtils.stringToBoolean(ElDCUtils.loadStringFromXML(element, "IncludeKeys", "true", false));
    }
    
    protected void customSaveToXML(final Element element) {
        ElDCUtils.saveStringToXML(element, "Operation", this.operation.toString());
        ElDCUtils.saveStringToXML(element, "OperationID", this.operationID);
        ElDCUtils.saveStringToXML(element, "Source", ElDCUtils.base16Encode(this.source));
        ElDCUtils.saveStringToXML(element, "HashAlgorithm", ElDCUtils.base16Encode(this.hashAlgorithm));
        ElDCUtils.saveStringToXML(element, "IncludeKeys", ElDCUtils.booleanToString(this.includeKeysInResponse));
    }
    
    public ElDCOperationRequestMessage() {
        this.operation = ElDCOperation.DC_UNKNOWN;
        this.operationID = "";
        this.source = new byte[0];
        this.hashAlgorithm = new byte[0];
        this.includeKeysInResponse = true;
    }
    
    public ElDCOperationRequestMessage(final ElDCBaseMessage elDCBaseMessage) {
        super(elDCBaseMessage);
        this.operation = ElDCOperation.DC_UNKNOWN;
        this.operationID = "";
        this.source = new byte[0];
        this.hashAlgorithm = new byte[0];
        this.includeKeysInResponse = true;
    }
    
    public void assign(final ElDCBaseMessage elDCBaseMessage) throws ElDCMessageException {
        if (!(elDCBaseMessage instanceof ElDCOperationRequestMessage)) {
            throw new ElDCMessageException(String.format("Cannot assign an object of class %s to an object of class %s", elDCBaseMessage.getClass().getName(), this.getClass().getName()));
        }
        super.assign(elDCBaseMessage);
        this.operation = ((ElDCOperationRequestMessage)elDCBaseMessage).operation;
        this.operationID = new String(((ElDCOperationRequestMessage)elDCBaseMessage).operationID);
        this.source = ((ElDCOperationRequestMessage)elDCBaseMessage).source.clone();
        this.hashAlgorithm = ((ElDCOperationRequestMessage)elDCBaseMessage).hashAlgorithm.clone();
        this.includeKeysInResponse = ((ElDCOperationRequestMessage)elDCBaseMessage).includeKeysInResponse;
    }
    
    public ElDCBaseMessage clone() {
        final ElDCOperationRequestMessage elDCOperationRequestMessage = new ElDCOperationRequestMessage();
        try {
            elDCOperationRequestMessage.assign(this);
        }
        catch (ElDCMessageException ex) {}
        return elDCOperationRequestMessage;
    }
    
    public ElDCOperation getOperation() {
        return this.operation;
    }
    
    public String getOperationID() {
        return this.operationID;
    }
    
    public byte[] getSource() {
        return this.source;
    }
    
    public byte[] getHashAlgorithm() {
        return this.hashAlgorithm;
    }
    
    public boolean getIncludeKeysInResponse() {
        return this.includeKeysInResponse;
    }
    
    public void setOperation(final ElDCOperation operation) {
        this.operation = operation;
    }
    
    public void setOperationID(final String s) {
        this.operationID = new String(s);
    }
    
    public void setSource(final byte[] array) {
        this.source = ((array == null) ? new byte[0] : array.clone());
    }
    
    public void setHashAlgorithm(final byte[] array) {
        this.hashAlgorithm = ((array == null) ? new byte[0] : this.source.clone());
    }
    
    public void setIncludeKeysInResponse(final boolean includeKeysInResponse) {
        this.includeKeysInResponse = includeKeysInResponse;
    }
}
