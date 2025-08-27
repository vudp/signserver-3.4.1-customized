package org.signserver.clientws;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.xml.bind.DatatypeConverter;
import org.signserver.crypto.Base64;

public class PKCS11Util {

    private static String pincode;
    private static KeyStore keystore;
    private static String providerName;

//	public static String[] getAliasKey(String configFileName, String pin)
//	{
//		try
//		{
//			Provider p = new sun.security.pkcs11.SunPKCS11(configFileName);
//	        Security.addProvider(p);
//	        keystore = null;
//	        keystore = KeyStore.getInstance("PKCS11", p);
//	        providerName = p.getName();
//	        keystore.load(null, pin.toCharArray());
//	        
//	        Enumeration<String> aliases = keystore.aliases();
//	        
//	        List<String> listKey = new ArrayList<String>();
//	        while(aliases.hasMoreElements()) {
//	        	String alias = aliases.nextElement();
//	        	listKey.add(alias);
//	        }
//	        pincode = pin;
//	        return listKey.toArray(new String[listKey.size()]);
//		}
//		catch(Exception e)
//		{
//			e.printStackTrace();
//		}
//		return null;
//	}
    public static PrivateKey getPrivateKeyFromFile(String filepath) throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {


        // Read Private Key.
        File filePrivateKey = new File(filepath);
        FileInputStream fis = new FileInputStream(filepath);
        byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
        fis.read(encodedPrivateKey);
        fis.close();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                encodedPrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        return privateKey;
    }

    public static PublicKey getPublicKeyFromFile(String filepath) throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    	System.out.println("[PKCS11Util-getPublicKeyFromFile] checkpoint 0");
    	File filePublicKey = new File(filepath);

        FileInputStream fis = new FileInputStream(filepath);
        System.out.println("[PKCS11Util-getPublicKeyFromFile] checkpoint 01");
        byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
        fis.read(encodedPublicKey);
        fis.close();
        System.out.println("[PKCS11Util-getPublicKeyFromFile] checkpoint 1");
        
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                encodedPublicKey);
        System.out.println("[PKCS11Util-getPublicKeyFromFile] checkpoint 2");
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        if (publicKey == null) {
        	System.out.println("[PKCS11Util-getPublicKeyFromFile] publickey is null");
        } else 
        	System.out.println("[PKCS11Util-getPublicKeyFromFile] load pblickey: "+publicKey);
        return publicKey;
    }
    
    public static PublicKey getPublicKeyFromString(String data) {
    	PublicKey pubKeyString = null;
    	try {
    	X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.decode(data.getBytes()));
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    pubKeyString = kf.generatePublic(spec);
    	}  	catch (Exception e) {
    		
    	}
	    return pubKeyString;
    }

    public static String PKCS1Sig(String data, String encode, PrivateKey privKey) {
        try {
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initSign(privKey);
            sig.update(data.getBytes(encode));
            return DatatypeConverter.printBase64Binary(sig.sign());
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (SignatureException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    public static boolean VerifyPKCS1Sig(String data, String sig, String encode, PublicKey pubKey) {
        try {
//            Certificate cert = (Certificate) keystore.getCertificate(aliasKey);
//            PublicKey pubKey = (PublicKey) cert.getPublicKey();
            
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initVerify(pubKey);
            signature.update(data.getBytes(encode));
            return signature.verify(DatatypeConverter.parseBase64Binary(sig));

        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (SignatureException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return false;
    }
}
