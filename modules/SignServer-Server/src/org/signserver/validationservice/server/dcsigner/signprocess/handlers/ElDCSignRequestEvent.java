package org.signserver.validationservice.server.dcsigner.signprocess.handlers;

import java.util.*;
import org.signserver.validationservice.server.dcsigner.signprocess.messages.*;

public class ElDCSignRequestEvent extends EventObject
{
    private static final long serialVersionUID = 1L;
    protected byte[] data;
    protected byte[] hashAlgorithm;
    protected boolean includeKeys;
    protected ArrayList<ElDCMessageParameter> keys;
    protected ArrayList<ElDCMessageParameter> parameters;
    
    public ElDCSignRequestEvent(final ElDCSignOperationHandler elDCSignOperationHandler, final byte[] data, final byte[] hashAlgorithm, final boolean includeKeys, final ArrayList<ElDCMessageParameter> keys, final ArrayList<ElDCMessageParameter> parameters) {
        super(elDCSignOperationHandler);
        this.data = data;
        this.hashAlgorithm = hashAlgorithm;
        this.includeKeys = includeKeys;
        this.keys = keys;
        this.parameters = parameters;
    }
    
    public byte[] getData() {
        return this.data;
    }
    
    public byte[] getHashAlgorithm() {
        return this.hashAlgorithm;
    }
    
    public boolean getIncludeKeys() {
        return this.includeKeys;
    }
    
    public ArrayList<ElDCMessageParameter> getKeys() {
        return this.keys;
    }
    
    public ArrayList<ElDCMessageParameter> getParameters() {
        return this.parameters;
    }
}
