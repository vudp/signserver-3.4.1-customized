package org.signserver.validationservice.server.dcsigner.signprocess.messages;

import java.util.*;
import org.w3c.dom.*;
import org.signserver.validationservice.server.dcsigner.signprocess.*;

public class ElDCOperationResponseMessage extends ElDCBaseMessage
{
    protected ElDCOperation operation;
    protected byte[] operationResult;
    protected ArrayList<ElDCMessageParameter> keysRDN;
    
    protected String getMessageTypeID() {
        return "Message.OperationResponse";
    }
    
    protected void customLoadFromXML(final Element element) throws ElDCException {
        this.operation = ElDCOperation.fromString(ElDCUtils.loadStringFromXML(element, "Operation", "Unknown", false));
        this.operationResult = ElDCUtils.base16DecodeBytes(ElDCUtils.loadStringFromXML(element, "OperationResult", "", false));
        this.keysRDN.clear();
        ElDCUtils.loadParametersFromXML(element, "Keys", "Key", this.keysRDN, false);
    }
    
    protected void customSaveToXML(final Element element) {
        ElDCUtils.saveStringToXML(element, "Operation", this.operation.toString());
        ElDCUtils.saveBinaryToXML(element, "OperationResult", this.operationResult);
        ElDCUtils.saveParametersToXML(element, "Keys", "Key", this.keysRDN);
    }
    
    protected void assignKeys(final ArrayList<ElDCMessageParameter> list) {
        this.keysRDN.clear();
        for (int i = 0; i < list.size(); ++i) {
            this.keysRDN.add(list.get(i).clone());
        }
    }
    
    public ElDCOperationResponseMessage() {
        this.operation = ElDCOperation.DC_UNKNOWN;
        this.operationResult = new byte[0];
        this.keysRDN = new ArrayList<ElDCMessageParameter>();
    }
    
    public ElDCOperationResponseMessage(final ElDCBaseMessage elDCBaseMessage) {
        super(elDCBaseMessage);
        this.operation = ElDCOperation.DC_UNKNOWN;
        this.operationResult = new byte[0];
        this.keysRDN = new ArrayList<ElDCMessageParameter>();
    }
    
    public void assign(final ElDCBaseMessage elDCBaseMessage) throws ElDCMessageException {
        if (!(elDCBaseMessage instanceof ElDCOperationResponseMessage)) {
            throw new ElDCMessageException(String.format("Cannot assign an object of class %s to an object of class %s", elDCBaseMessage.getClass().getName(), this.getClass().getName()));
        }
        super.assign(elDCBaseMessage);
        this.operation = ((ElDCOperationResponseMessage)elDCBaseMessage).operation;
        this.operationResult = ((ElDCOperationResponseMessage)elDCBaseMessage).operationResult.clone();
        this.assignKeys(((ElDCOperationResponseMessage)elDCBaseMessage).keysRDN);
    }
    
    public ElDCBaseMessage clone() {
        final ElDCOperationResponseMessage elDCOperationResponseMessage = new ElDCOperationResponseMessage();
        try {
            elDCOperationResponseMessage.assign(this);
        }
        catch (ElDCMessageException ex) {}
        return elDCOperationResponseMessage;
    }
    
    public ElDCOperation getOperation() {
        return this.operation;
    }
    
    public byte[] getOperationResult() {
        return this.operationResult;
    }
    
    public ArrayList<ElDCMessageParameter> getKeysRDN() {
        return this.keysRDN;
    }
    
    public void setOperation(final ElDCOperation operation) {
        this.operation = operation;
    }
    
    public void setOperationResult(final byte[] array) {
        this.operationResult = array.clone();
    }
    
    public void setKeysRDN(final ArrayList<ElDCMessageParameter> list) {
        this.assignKeys(list);
    }
}
