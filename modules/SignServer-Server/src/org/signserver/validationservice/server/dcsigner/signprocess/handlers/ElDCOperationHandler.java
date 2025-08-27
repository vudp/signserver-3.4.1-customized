package org.signserver.validationservice.server.dcsigner.signprocess.handlers;

import java.util.*;
import org.signserver.validationservice.server.dcsigner.signprocess.messages.*;
import org.signserver.validationservice.server.dcsigner.signprocess.*;

public class ElDCOperationHandler
{
    protected ArrayList<String> acceptedOperationIDs;
    
    protected int indexOfOperationID(final String s) {
        for (int i = 0; i < this.acceptedOperationIDs.size(); ++i) {
            if (this.acceptedOperationIDs.get(i).equals(s)) {
                return i;
            }
        }
        return -1;
    }
    
    public ElDCOperationHandler() {
        this.acceptedOperationIDs = new ArrayList<String>();
    }
    
    public boolean isOperationSupported(final ElDCOperation elDCOperation, final String s) {
        return false;
    }
    
    public ElDCBaseMessage process(final ElDCOperationRequestMessage elDCOperationRequestMessage) throws Exception {
        throw new ElDCServerException("Unsupported operation");
    }
    
    public ArrayList<String> getAcceptedOperationIDs() {
        return this.acceptedOperationIDs;
    }
    
    public void setAcceptedOperationIDs(final ArrayList<String> list) {
        if (this.acceptedOperationIDs == list) {
            return;
        }
        this.acceptedOperationIDs.clear();
        if (list == null) {
            return;
        }
        for (int i = 0; i < list.size(); ++i) {
            this.acceptedOperationIDs.add(new String(list.get(i)));
        }
    }
}
