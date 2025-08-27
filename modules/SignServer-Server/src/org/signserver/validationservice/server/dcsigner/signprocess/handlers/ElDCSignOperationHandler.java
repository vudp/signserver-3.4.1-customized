package org.signserver.validationservice.server.dcsigner.signprocess.handlers;

import org.signserver.validationservice.server.dcsigner.signprocess.*;
import org.signserver.validationservice.server.dcsigner.signprocess.messages.*;
import java.util.*;

public class ElDCSignOperationHandler extends ElDCOperationHandler
{
    protected ElDCSignRequestListener signRequestListener;
    
    public ElDCSignOperationHandler() {
        this.signRequestListener = null;
    }
    
    public boolean isOperationSupported(final ElDCOperation elDCOperation, final String s) {
        boolean b = elDCOperation == ElDCOperation.DC_RAW_SIGN;
        if (b) {
            if (s != null && s.length() != 0) {
                b = (this.indexOfOperationID(s) >= 0);
            }
            else {
                b = (this.acceptedOperationIDs.size() == 0 || this.indexOfOperationID(s) >= 0);
            }
        }
        return b;
    }
    
    public ElDCBaseMessage process(final ElDCOperationRequestMessage elDCOperationRequestMessage) throws Exception {
        try {
            final ElDCOperationResponseMessage elDCOperationResponseMessage = new ElDCOperationResponseMessage(elDCOperationRequestMessage);
            elDCOperationResponseMessage.setOperation(ElDCOperation.DC_RAW_SIGN);
            elDCOperationResponseMessage.setOperationResult(this.sign(elDCOperationRequestMessage.getSource(), elDCOperationRequestMessage.getHashAlgorithm(), elDCOperationRequestMessage.getIncludeKeysInResponse(), elDCOperationResponseMessage.getKeysRDN(), elDCOperationResponseMessage.getParameters()));
            //elDCOperationResponseMessage.setOperationResult(null);
            return elDCOperationResponseMessage;
        }
        catch (Exception ex) {
            final ElDCErrorMessage elDCErrorMessage = new ElDCErrorMessage(elDCOperationRequestMessage);
            elDCErrorMessage.setErrorMessage(ex.getMessage());
            elDCErrorMessage.setCode(-1);
            return elDCErrorMessage;
        }
    }
    
    public byte[] sign(final byte[] array, final byte[] array2, final boolean b, final ArrayList<ElDCMessageParameter> list, final ArrayList<ElDCMessageParameter> list2) throws Exception {
        if (this.signRequestListener != null) {
            return this.signRequestListener.signRequested(new ElDCSignRequestEvent(this, array, array2, b, list, list2));
        }
        return null;
    }
    
    public void addSignRequestListener(final ElDCSignRequestListener signRequestListener) throws TooManyListenersException {
        if (signRequestListener != null) {
            if (this.signRequestListener != signRequestListener) {
                throw new TooManyListenersException();
            }
            this.signRequestListener = signRequestListener;
        }
    }
    
    public void removeSignRequestListener(final ElDCSignRequestListener elDCSignRequestListener) {
        if (this.signRequestListener == elDCSignRequestListener) {
            this.signRequestListener = null;
        }
    }
}
