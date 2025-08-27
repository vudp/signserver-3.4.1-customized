package org.signserver.validationservice.server.dcsigner.signprocess.handlers;

import java.security.cert.*;
import java.security.cert.Certificate;

import org.signserver.validationservice.server.dcsigner.signprocess.messages.*;
import org.signserver.validationservice.server.dcsigner.signprocess.*;

import java.security.*;
import java.util.*;
import java.lang.reflect.*;

import javax.xml.bind.DatatypeConverter;

public class ElDCX509SignOperationHandler extends ElDCSignOperationHandler
{
    protected KeyStore keyStore;
    protected Key signingKey;
    protected Certificate signingCertificate;
    
    public byte[] sign(final byte[] array, final byte[] array2, final boolean b, final ArrayList<ElDCMessageParameter> list, final ArrayList<ElDCMessageParameter> list2) throws Exception {
        if (this.signingKey == null || this.signingCertificate == null) {
            throw new ElDCServerException("There are no signing certificates nor keys");
        }
        
        if (b) {
            final ElDCMessageParameter elDCMessageParameter = new ElDCMessageParameter();
            elDCMessageParameter.setOID("signing-certificate@eldos.com");
            elDCMessageParameter.setTag((short)4);
            elDCMessageParameter.setValue(this.signingCertificate.getEncoded());
            list.add(elDCMessageParameter);
            
            
            if (this.keyStore != null) {
                Enumeration<String> aliases;
                try {
                    aliases = this.keyStore.aliases();
                }
                catch (KeyStoreException ex4) {
                    aliases = null;
                }
                if (aliases != null) {
                    while (aliases.hasMoreElements()) {
                        final byte[] encoded = this.keyStore.getCertificate(aliases.nextElement()).getEncoded();
                        final ElDCMessageParameter elDCMessageParameter2 = new ElDCMessageParameter();
                        elDCMessageParameter2.setOID("certificate@eldos.com");
                        elDCMessageParameter2.setTag((short)4);
                        elDCMessageParameter2.setValue(encoded);
                        list.add(elDCMessageParameter2);
                    }
                }
            }
            
        
        }
        
        if (!((PrivateKey)this.signingKey).getAlgorithm().equals("RSA")) {
            throw new ElDCServerException("Only RSA keys and certificates are supported");
        }
        Signature signature;
        try {
            signature = Signature.getInstance("NONEwithRSA");
            signature.initSign((PrivateKey)this.signingKey);
        }
        catch (NoSuchAlgorithmException ex) {
            throw new ElDCServerException(String.format("The specified algorithm is not supported.\nError: %s", ex.getMessage()));
        }
        catch (InvalidKeyException ex2) {
            throw new ElDCServerException(String.format("The key cannot be used to sign the data.\nError: %s", ex2.getMessage()));
        }
        byte[] sign;
        
        if (signature.getProvider().getName().equals("SunMSCAPI")) {
            final String base16Encode = ElDCUtils.base16Encode(array2);
            String s;
            if (base16Encode.equals("2A864886F70D0202")) {
                s = "MD2";
            }
            else if (base16Encode.equals("2A864886F70D0205")) {
                s = "MD5";
            }
            else if (base16Encode.equals("2B0E03021A")) {
                s = "SHA-1";
            }
            else {
                if (base16Encode.equals("608648016503040201")) {
                    s = "SHA-256";
                }
                else if (base16Encode.equals("608648016503040202")) {
                    s = "SHA-384";
                }
                else {
                    if (!base16Encode.equals("608648016503040203")) {
                        throw new ElDCServerException(String.format("Unknown hash algorithm: %s", base16Encode));
                    }
                    s = "SHA-512";
                }
                if (signature.getProvider().getVersion() < 1.7) {
                    throw new ElDCServerException(String.format("The hash algorithm %s is supported since JRE %s", s, "7"));
                }
            }
            if (signature.getProvider().getVersion() < 1.7) {
                signature = Signature.getInstance("SHA1withRSA");
                signature.initSign((PrivateKey)this.signingKey);
            }
            final long longValue = (Long)ElDCUtils.findMethod(this.signingKey, "getHCryptProvider").invoke(this.signingKey, new Object[0]);
            final long longValue2 = (Long)ElDCUtils.findMethod(this.signingKey, "getHCryptKey").invoke(this.signingKey, new Object[0]);
            final Object value = ElDCUtils.findField(signature, "sigSpi").get(signature);
            final Method method = ElDCUtils.findMethod(value, "signHash");
            Object o;
            if (signature.getProvider().getVersion() < 1.7) {
                try {
                    o = method.invoke(value, false, array, array.length, s, longValue, longValue2);
                }
                catch (IllegalArgumentException ex5) {
                    o = method.invoke(value, array, array.length, s, longValue, longValue2);
                }
            }
            else {
                o = method.invoke(value, false, array, array.length, s, longValue, longValue2);
            }
            sign = (byte[])ElDCUtils.findMethod(value, "convertEndianArray").invoke(value, o);
        }
        
        else {
        
            final byte[] array3 = new byte[10 + array2.length + array.length];
            int n = 0;
            array3[n++] = 48;
            array3[n++] = (byte)(8 + array2.length + array.length);
            array3[n++] = 48;
            array3[n++] = (byte)(4 + array2.length);
            array3[n++] = 6;
            array3[n++] = (byte)array2.length;
            System.arraycopy(array2, 0, array3, n, array2.length);
            int n2 = n + array2.length;
            array3[n2++] = 5;
            array3[n2++] = 0;
            array3[n2++] = 4;
            array3[n2++] = (byte)array.length;
            System.arraycopy(array, 0, array3, n2, array.length);
            try {
            	System.out.println(DatatypeConverter.printHexBinary(array3));
                signature.update(array3);
                sign = signature.sign();
            }
            catch (SignatureException ex3) {
                throw new ElDCServerException(String.format("Failed to sign the data.\nError: %s", ex3.getMessage()));
            }
            
        }
        
        return sign;
    }
    
    public KeyStore getKeyStore() {
        return this.keyStore;
    }
    
    public void setKeyStore(final KeyStore keyStore) {
        this.keyStore = keyStore;
    }
    
    public void setSigningCertificate(final Certificate signingCertificate, final Key signingKey) {
        this.signingCertificate = signingCertificate;
        this.signingKey = signingKey;
    }
}
