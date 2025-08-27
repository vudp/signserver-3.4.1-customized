package org.signserver.validationservice.server.dcsigner.signprocess.messages;

import org.signserver.validationservice.server.dcsigner.signprocess.*;

public class ElDCMessageParameter
{
    protected short[] oid;
    protected short tag;
    protected short[] value;
    
    public ElDCMessageParameter() {
        this.oid = new short[0];
        this.tag = 0;
        this.value = new short[0];
    }
    
    public void assign(final ElDCMessageParameter elDCMessageParameter) {
        this.oid = elDCMessageParameter.oid.clone();
        this.tag = elDCMessageParameter.tag;
        this.value = elDCMessageParameter.value.clone();
    }
    
    public ElDCMessageParameter clone() {
        final ElDCMessageParameter elDCMessageParameter = new ElDCMessageParameter();
        elDCMessageParameter.assign(this);
        return elDCMessageParameter;
    }
    
    public short[] getOID() {
        return this.oid;
    }
    
    public short getTag() {
        return this.tag;
    }
    
    public short[] getValue() {
        return this.value;
    }
    
    public void setOID(final short[] array) {
        ElDCUtils.checkByteArray(array);
        this.oid = array.clone();
    }
    
    public void setOID(final String s) {
        this.oid = new short[s.length()];
        for (int i = 0; i < s.length(); ++i) {
            this.oid[i] = (short)s.charAt(i);
        }
    }
    
    public void setTag(final short tag) {
        if (tag < 0 || tag > 255) {
            throw new IllegalArgumentException();
        }
        this.tag = tag;
    }
    
    public void setValue(final short[] array) {
        ElDCUtils.checkByteArray(array);
        this.value = array.clone();
    }
    
    public void setValue(final byte[] array) {
        this.value = new short[array.length];
        for (int i = 0; i < array.length; ++i) {
            this.value[i] = (short)((array[i] < 0) ? (256 + array[i]) : array[i]);
        }
    }
}
