/*************************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.server.cryptotokens;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

import java.util.*;

import javax.xml.bind.DatatypeConverter;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.ECKeyUtil;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.ejbca.core.model.ca.catoken.PKCS11CAToken;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.keystore.KeyStoreContainer;
import org.ejbca.util.keystore.KeyStoreContainerFactory;
import org.signserver.common.*;
import org.signserver.common.util.Defines;
import org.signserver.common.util.ExtFunc;
import org.signserver.server.KeyUsageCounterHash;
/*
import SecureBlackbox.Base.JNI;
import SecureBlackbox.Base.SBConstants;
import SecureBlackbox.Base.SBUtils;
import SecureBlackbox.Base.TElMemoryCertStorage;
import SecureBlackbox.Base.TElMessageSigner;
*/
import SecureBlackbox.Base.TElX509Certificate;
/*
import SecureBlackbox.Base.TSBInteger;
import SecureBlackbox.Base.TSBMessageSignatureType;
import SecureBlackbox.PKI.SBPKCS11Base;
import SecureBlackbox.PKI.TElPKCS11CertStorage;
import SecureBlackbox.PKI.TElPKCS11SessionInfo;

import com.tomicalab.cryptos.CryptoS;

import org.signserver.validationservice.server.IValidator;
*/

/**
 * Class used to connect to a PKCS11 HSM.
 *
 * Properties:
 *   sharedLibrary
 *   slot
 *   defaultKey
 *   pin
 *   attributesFile
 *
 * @see org.signserver.server.cryptotokens.ICryptoToken
 * @author Tomas Gustavsson, Philip Vendil
 * @version $Id: PKCS11CryptoToken.java 3452 2013-04-20 21:32:59Z netmackan $
 */
public class PKCS11CryptoToken extends CryptoTokenBase implements ICryptoToken,
        IKeyGenerator {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(PKCS11CryptoToken.class);
    
    private Properties properties;

    private char[] authenticationCode;
    
    //private TElPKCS11CertStorage telPKCS11CertStorage;
    //private TElPKCS11SessionInfo session;
    //private TElX509Certificate telX509Certificate;
    //private String defaultKey;
    //private static boolean firstSign = false;

    public PKCS11CryptoToken() throws InstantiationException {
        catoken = new PKCS11CAToken();
        //CryptoS.getInstance(IValidator.class, 1);
    }

    /**
     * Method initializing the PKCS11 device
     *
     */
    @Override
    public void init(final int workerId, final Properties props) {
        LOG.debug(">init");
        String signaturealgoritm = props.getProperty(WorkerConfig.SIGNERPROPERTY_SIGNATUREALGORITHM);
        this.properties = fixUpProperties(props);
        try {
            LOG.info("PKCS11CryptoToken Init for workerId: "+workerId);
            ((PKCS11CAToken) catoken).init(properties, null, signaturealgoritm, workerId);
            LOG.info("PKCS11CryptoToken Init for workerId: "+workerId+" finished");
        } catch (Exception e) {
            LOG.error("Error initializing PKCS11CryptoToken : " + e.toString());
            //LOG.error("Error initializing PKCS11CryptoToken : " + e.getMessage(), e);
        }
        String authCode = properties.getProperty("pin");
        if (authCode != null) {
            try {
                this.activate(authCode);
            } catch (Exception e) {
                LOG.error("Error auto activating PKCS11CryptoToken : " + e.getMessage(), e);
            }
        }
        LOG.debug("<init");
        
    }

    @Override
    public void activate(String authenticationcode)
            throws CryptoTokenAuthenticationFailureException,
            CryptoTokenOfflineException {
    	//LOG.info("PKCS11CryptoToken activate");
        this.authenticationCode = authenticationcode == null ? null
                : authenticationcode.toCharArray();
        super.activate(authenticationcode);
    }

    /**
     * @see IKeyGenerator#generateKey(java.lang.String, java.lang.String, java.lang.String, char[])
     */
    @Override
    public void generateKey(final String keyAlgorithm, String keySpec,
            String alias, char[] authCode) throws CryptoTokenOfflineException,
            IllegalArgumentException {

        if (keySpec == null) {
            throw new IllegalArgumentException("Missing keyspec parameter");
        }
        if (alias == null) {
            throw new IllegalArgumentException("Missing alias parameter");
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("keyAlgorithm: " + keyAlgorithm + ", keySpec: " + keySpec
                    + ", alias: " + alias);
        }
        try {

            final Provider provider = Security.getProvider(
                    getProvider(ICryptoToken.PROVIDERUSAGE_SIGN));
            if (LOG.isDebugEnabled()) {
                LOG.debug("provider: " + provider);
            }

            // Keyspec for DSA is prefixed with "dsa"
            if (keyAlgorithm != null && keyAlgorithm.equalsIgnoreCase("DSA")
                    && !keySpec.contains("dsa")) {
                keySpec = "dsa" + keySpec;
            }

            KeyStore.ProtectionParameter pp;
            if (authCode == null) {
                LOG.debug("authCode == null");
                final String pin = properties.getProperty("pin");
                if (pin != null) {
                    LOG.debug("pin specified");
                    pp = new KeyStore.PasswordProtection(pin.toCharArray());
                } else if (authenticationCode != null) {
                    LOG.debug("Using autentication code");
                    pp = new KeyStore.PasswordProtection(authenticationCode);
                } else {
                    LOG.debug("pin == null");
                    pp = new KeyStore.ProtectionParameter() {
                    };
                }
            } else {
                LOG.debug("authCode specified");
                pp = new KeyStore.PasswordProtection(authCode);
            }

            final String sharedLibrary = properties.getProperty("sharedLibrary");
            final String slot = properties.getProperty("slot");
            final String attributesFile = properties.getProperty("attributesFile");

            if (LOG.isDebugEnabled()) {
                LOG.debug("sharedLibrary: " + sharedLibrary + ", slot: "
                        + slot + ", attributesFile: " + attributesFile);
            }
            // count key and get alias
            // KeyAndAlias kaa = countKeystore(sharedLibrary, authCode, slot);
            
            License licInfo = License.getInstance();
            if(licInfo.getStatusCode() != 0) {
            	throw new IllegalArgumentException("Invalid license");
            } else {
            	// count key and get alias
            	int count = DBConnector.getInstances().countKeyStore();
            	if(!licInfo.checkKeystore(count)) {
            		throw new IllegalArgumentException("Keystore number has been exceeded for this license");
            	}
            }
            LOG.info("Generating keypair with alias: "+alias);
            
            final KeyStoreContainer store = KeyStoreContainerFactory.getInstance(KeyStoreContainer.KEYSTORE_TYPE_PKCS11,
                    sharedLibrary, null,
                    slot,
                    attributesFile, pp);
            store.setPassPhraseLoadSave(authCode);
            store.generate(keySpec, alias);
            
            LOG.info("Synchronization processing...");
            ExtFunc.executeExternalShellScript(ExtFunc.SCRIPT_PATH_RSYNC);
            
        } catch (Exception ex) {
            LOG.error(ex, ex);
            throw new CryptoTokenOfflineException(ex);
        }
    }
    
	private KeyAndAlias countKeystore(String pkcs11Module, char[] pin, String slot) {
		int counter = 0;
		KeyAndAlias kaa = new KeyAndAlias();
		try {
			UUID uuid = UUID.randomUUID();
			String configValue = "name = PROVIDER" + uuid.toString()
					+ "\r\nlibrary = " + pkcs11Module + "\r\nslot = " + slot
					+ "\r\ndisabledMechanisms={ CKM_SHA1_RSA_PKCS }\r\n";
			Provider p = new sun.security.pkcs11.SunPKCS11(
					new ByteArrayInputStream(configValue.getBytes()));
			Security.addProvider(p);
			KeyStore keystore = KeyStore.getInstance("PKCS11", p);
			keystore.load(null, pin);
			Enumeration<String> aliases = keystore.aliases();
			ArrayList<String> als = new ArrayList<String>();
			while (aliases.hasMoreElements()) {
				counter++;
				als.add(aliases.nextElement());
			}
			kaa.setTotalKeyStore(counter);
			kaa.setAlias(als);
		} catch(Exception e) {
			e.printStackTrace();
		}
		return kaa;
	}
	
	private class KeyAndAlias {
		
		int totalKeyStore;
		ArrayList<String> alias;
		
		public int getTotalKeyStore() {
			return totalKeyStore;
		}

		public void setTotalKeyStore(int totalKeyStore) {
			this.totalKeyStore = totalKeyStore;
		}

		public ArrayList<String> getAlias() {
			return alias;
		}

		public void setAlias(ArrayList<String> alias) {
			this.alias = alias;
		}
	}

    private KeyStore getKeyStore(final char[] authCode)
            throws KeyStoreException {
        KeyStore.ProtectionParameter pp;
        if (authCode == null) {
            LOG.debug("authCode == null");
            final String pin = properties.getProperty("pin");
            if (pin == null) {
                LOG.debug("pin == null");
                pp = new KeyStore.ProtectionParameter() {};
            } else {
                LOG.debug("pin specified");
                pp = new KeyStore.PasswordProtection(pin.toCharArray());
            }
        } else {
            LOG.debug("authCode specified");
            pp = new KeyStore.PasswordProtection(authCode);
        }

        final Provider provider = Security.getProvider(
                getProvider(ICryptoToken.PROVIDERUSAGE_SIGN));
        if (LOG.isDebugEnabled()) {
            LOG.debug("provider: " + provider);
        }
        final KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11",
                provider, pp);

        return builder.getKeyStore();
    }
    
    @Override
    public boolean destroyKey(int purpose, String authCode, String alias) {
    	try {
    		char[] pin = authCode.toCharArray();
    		final KeyStore keyStore = getKeyStore(pin);
    		
    		X509Certificate x509 = (X509Certificate) keyStore
					.getCertificate(alias);
			
			java.security.interfaces.RSAPublicKey pubK 
							= (java.security.interfaces.RSAPublicKey) x509.getPublicKey();
			String modolus = pubK.getModulus().toString(16).toLowerCase();
			String encoded = DatatypeConverter.printHexBinary(pubK.getEncoded()).toLowerCase();
			
			boolean isCert = false;
			boolean isPub = false;
			boolean isPri = false;
			
			if (x509 == null) {
				LOG.info("No key found to delete.");
			} else {
				Module _pkcs11Module = Module.getInstance(this.properties.getProperty("sharedLibrary"));

			    Token token;
			    token = Util.selectToken(_pkcs11Module, this.properties.getProperty("slot"));

			    if (token == null) {
			      LOG.error("We have no token to proceed. Finished.");
			      throw new TokenException("No token found!");
			    }

			    Session session;
			    session = Util.openAuthorizedSession(token,
				          Token.SessionReadWriteBehavior.RW_SESSION, new String(pin));

				// find certificate
				X509PublicKeyCertificate x509PubKeyCertTemplate = new X509PublicKeyCertificate();
				session.findObjectsInit(x509PubKeyCertTemplate);

				Object[] temp_X509cer = session.findObjects(16);

				session.findObjectsFinal();
				Object certToDelete = null;
				Object pubToDelete = null;
				Object priToDelete = null;
				
				for(int i=0; i<temp_X509cer.length; i++) {
					CK_ATTRIBUTE[] getCKAValueAttrList = new CK_ATTRIBUTE[1];
					getCKAValueAttrList[0] = new CK_ATTRIBUTE();
					getCKAValueAttrList[0].type = PKCS11Constants.CKA_LABEL;
					
					_pkcs11Module.getPKCS11Module().C_GetAttributeValue(session.getSessionHandle()
							, temp_X509cer[i].getObjectHandle(), getCKAValueAttrList, true);
					
					char[] eLabel = (char[]) getCKAValueAttrList[0].pValue;
					String _eLabel = new String(eLabel);
					if(alias.compareToIgnoreCase(_eLabel) == 0) {
						certToDelete = temp_X509cer[i];
						isCert = true;
						break;
					}
				}
				
				// find public key
				RSAPublicKey temp_publickey = new RSAPublicKey();
				session.findObjectsInit(temp_publickey);
				Object[] temp_rsapublickey = session.findObjects(16);
				session.findObjectsFinal();
				for(int i=0; i<temp_rsapublickey.length; i++) {
					CK_ATTRIBUTE[] getCKAValueAttrList = new CK_ATTRIBUTE[1];
					getCKAValueAttrList[0] = new CK_ATTRIBUTE();
					getCKAValueAttrList[0].type = PKCS11Constants.CKA_MODULUS;
					_pkcs11Module.getPKCS11Module().C_GetAttributeValue(session.getSessionHandle()
							, temp_rsapublickey[i].getObjectHandle(), getCKAValueAttrList, true);
					
					byte[] modulus = (byte[]) getCKAValueAttrList[0].pValue;
					String _modolus = DatatypeConverter.printHexBinary(modulus).toLowerCase();
					if(_modolus.compareToIgnoreCase(modolus) == 0) {
						pubToDelete = temp_rsapublickey[i];
						isPub = true;
						break;
					}
				}
				
				// find private key
				RSAPrivateKey templateSignatureKey = new RSAPrivateKey();
				templateSignatureKey.getSign().setBooleanValue(Boolean.TRUE);
				session.findObjectsInit(templateSignatureKey);
				Object[] temp_rsaprivatekey = session.findObjects(16);
				session.findObjectsFinal();
				
				for(int i=0; i<temp_rsaprivatekey.length; i++) {
					CK_ATTRIBUTE[] getCKAValueAttrList = new CK_ATTRIBUTE[1];
					getCKAValueAttrList[0] = new CK_ATTRIBUTE();
					getCKAValueAttrList[0].type = PKCS11Constants.CKA_MODULUS;
					_pkcs11Module.getPKCS11Module().C_GetAttributeValue(session.getSessionHandle()
							, temp_rsaprivatekey[i].getObjectHandle(), getCKAValueAttrList, true);
					
					byte[] modulus = (byte[]) getCKAValueAttrList[0].pValue;
					String _modolus = DatatypeConverter.printHexBinary(modulus).toLowerCase();
					if(_modolus.compareToIgnoreCase(modolus) == 0) {
						priToDelete = temp_rsaprivatekey[i];
						isPri = true;
						break;
					} else {
						//LOG.info("iaik pri modulus="+_modolus);
					}
				}
				
				if(isCert == true && isPub == true
						&& isPri == true) {
					LOG.info("\n\nFound certificate to be deleted");
					//LOG.info(certToDelete);
					LOG.info("\n\nFound public key to be deleted");
					//LOG.info(pubToDelete);
					LOG.info("\n\nFound private key to be deleted");
					//LOG.info(priToDelete);
					session.destroyObject(certToDelete);
					LOG.info("Certificate deteled");
					session.destroyObject(pubToDelete);
					LOG.info("Public Key deteled");
					session.destroyObject(priToDelete);
					LOG.info("Private Key deteled");
					return true;
				} else {
					if(!isCert)
						LOG.info("Not found certificate object");
					if(!isPub)
						LOG.info("Not found public key object");
					if(!isPri)
						LOG.info("Not found private key object");
				}
			}
    	} catch(Exception e) {
    		LOG.error(e.getMessage());
    		e.printStackTrace();
    	}
        return false;
    }

    /**
     * @see ICryptoToken#testKey(java.lang.String, char[])
     */
    @Override
    public Collection<KeyTestResult> testKey(String alias, char[] authCode)
            throws CryptoTokenOfflineException, KeyStoreException {
        LOG.debug(">testKey");
        final Collection<KeyTestResult> result = new LinkedList<KeyTestResult>();

        final byte signInput[] = "Lillan gick on the roaden ut.".getBytes();

        final KeyStore keyStore = getKeyStore(authCode);

        try {
            final Enumeration<String> e = keyStore.aliases();
            while (e.hasMoreElements()) {
                final String keyAlias = e.nextElement();
                if (alias.equalsIgnoreCase(ICryptoToken.ALL_KEYS)
                        || alias.equals(keyAlias)) {
                    if (keyStore.isKeyEntry(keyAlias)) {
                        String status;
                        String publicKeyHash = null;
                        boolean success = false;
                        try {
                            final PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, authCode);
                            final Certificate cert = keyStore.getCertificate(keyAlias);
                            if (cert != null) {
                                final KeyPair keyPair = new KeyPair(cert.getPublicKey(), privateKey);
                                publicKeyHash = createKeyHash(keyPair.getPublic());
                                final String sigAlg = suggestSigAlg(keyPair.getPublic());
                                if (sigAlg == null) {
                                    status = "Unknown key algorithm: "
                                            + keyPair.getPublic().getAlgorithm();
                                } else {
                                    Signature signature = Signature.getInstance(sigAlg, keyStore.getProvider());
                                    signature.initSign(keyPair.getPrivate());
                                    signature.update(signInput);
                                    byte[] signBA = signature.sign();

                                    Signature verifySignature = Signature.getInstance(sigAlg);
                                    verifySignature.initVerify(keyPair.getPublic());
                                    verifySignature.update(signInput);
                                    success = verifySignature.verify(signBA);
                                    status = success ? "" : "Test signature inconsistent";
                                }
                            } else {
                                status = "Not testing keys with alias "
                                        + keyAlias + ". No certificate exists.";
                            }
                        } catch (ClassCastException ce) {
                            status = "Not testing keys with alias "
                                    + keyAlias + ". Not a private key.";
                        } catch (Exception ex) {
                            LOG.error("Error testing key: " + keyAlias, ex);
                            status = ex.getMessage();
                        }
                        result.add(new KeyTestResult(keyAlias, success, status,
                                publicKeyHash));
                    }
                }
            }
        } catch (KeyStoreException ex) {
            throw new CryptoTokenOfflineException(ex);
        }

        LOG.debug("<testKey");
        return result;
    }

    // TODO: The genCertificateRequest method is mostly a duplicate of the one in CryptoTokenBase, PKCS11CryptoTooken, KeyStoreCryptoToken and SoftCryptoToken.
    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info,
            final boolean explicitEccParameters, boolean defaultKey)
            throws CryptoTokenOfflineException {
        LOG.debug(">genCertificateRequest PKCS11CryptoToken");
        Base64SignerCertReqData retval = null;
        if (info instanceof PKCS10CertReqInfo) {
            PKCS10CertReqInfo reqInfo = (PKCS10CertReqInfo) info;
            PKCS10CertificationRequest pkcs10;

            final String alias;
            if (defaultKey) {
                alias = properties.getProperty("defaultKey");
            } else {
                alias = properties.getProperty("nextCertSignKey");
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("defaultKey: " + defaultKey);
                LOG.debug("alias: " + alias);
                LOG.debug("signatureAlgorithm: "
                        + reqInfo.getSignatureAlgorithm());
                LOG.debug("subjectDN: " + reqInfo.getSubjectDN());
                LOG.debug("explicitEccParameters: " + explicitEccParameters);
            }
            try {
                final KeyStore keyStore = getKeyStore(authenticationCode);

                final PrivateKey privateKey = (PrivateKey) keyStore.getKey(
                        alias, authenticationCode);
                final Certificate cert = keyStore.getCertificate(alias);
                if (cert == null) {
                    throw new CryptoTokenOfflineException("Certificate request error: No key with the configured alias");
                }

                PublicKey publicKey = cert.getPublicKey();

                // Handle ECDSA key with explicit parameters
                if (explicitEccParameters
                        && publicKey.getAlgorithm().contains("EC")) {
                    publicKey = ECKeyUtil.publicToExplicitParameters(publicKey,
                            "BC");
                }

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Public key SHA1: " + CryptoTokenBase.createKeyHash(
                            cert.getPublicKey()));
                    LOG.debug("Public key SHA256: "
                            + KeyUsageCounterHash.create(cert.getPublicKey()));
                }

                // Generate request
                final JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Name(CertTools.stringToBCDNString(reqInfo.getSubjectDN())), publicKey);
		System.out.println("[PKCS11CrytoToken] CertTool DN: "+CertTools.stringToBCDNString(reqInfo.getSubjectDN()));
                final ContentSigner contentSigner = new JcaContentSignerBuilder(reqInfo.getSignatureAlgorithm()).setProvider(getProvider(ICryptoToken.PROVIDERUSAGE_SIGN)).build(privateKey);
                pkcs10 = builder.build(contentSigner);
		System.out.println("[PKCS11CrytoToken] PKCS10: "+ new String(Base64.encode(pkcs10.getEncoded())));
                retval = new Base64SignerCertReqData(Base64.encode(pkcs10.getEncoded()));
            } catch (IOException e) {
                LOG.error("Certificate request error: " + e.getMessage(), e);
            } catch (OperatorCreationException e) {
                LOG.error("Certificate request error: signer could not be initialized", e);
            } catch (UnrecoverableKeyException e) {
                LOG.error("Certificate request error: " + e.getMessage(), e);
            } catch (KeyStoreException e) {
                LOG.error("Certificate request error: " + e.getMessage(), e);
            } catch (NoSuchAlgorithmException e) {
                LOG.error("Certificate request error: " + e.getMessage(), e);
            } catch (NoSuchProviderException e) {
                LOG.error("Certificate request error: " + e.getMessage(), e);
            }

        }
        LOG.debug("<genCertificateRequest PKCS11CryptoToken");
        return retval;
    }

    @Override
    public KeyStore getKeyStore() throws UnsupportedOperationException,
            CryptoTokenOfflineException, KeyStoreException {
        return getKeyStore(authenticationCode); // TODO: check loaded etc
    }
    
    @Override
    public TElX509Certificate getTElX509Certificate() {
    	/*
		if(telX509Certificate == null) {
			LOG.info("telX509Certificate is NULL");
			for(int i=0; i<telPKCS11CertStorage.getCount(); i++) {
				TElX509Certificate Cert = telPKCS11CertStorage.getCertificate(i);
				if(Cert.getSubjectName().CommonName.compareTo(this.defaultKey) == 0) {
					telX509Certificate = Cert;
					break;
				}
			}
    	}
		return telX509Certificate;
		*/
    	throw new UnsupportedOperationException(
                "Operation not supported by crypto token.");
    }
    /*
    private void signSomeThing(TElX509Certificate telX509Certificate) {
    	try {
    		
    		TElMemoryCertStorage certStorage = new TElMemoryCertStorage();
    		certStorage.add(telX509Certificate, true);
    		
    		TElMessageSigner signer = new TElMessageSigner(null);
            signer.setCertStorage(certStorage);
    		signer.setRecipientCerts(certStorage);
    		signer.setSignatureType(TSBMessageSignatureType.mstPublicKey);
    		
    		signer.setHashAlgorithm(SBConstants.SB_ALGORITHM_DGST_SHA1);
    		
    		byte[] datatosign = "signsomething".getBytes("UTF-16LE");
    		
    		TSBInteger iSize = new TSBInteger();
    		byte[] outbuf = new byte[0];
    		
    		
    		signer.sign(datatosign, outbuf, iSize, true);
            outbuf = new byte[iSize.value];
            int i = signer.sign(datatosign, outbuf, iSize, true);
    		if (i == 0) {
    			LOG.info("The operation signSomeThing to activate signer was completed successfully");
    		} else {
    			LOG.error("The operation signSomeThing to activate signer get error #" + i + " occured while signing");
    		}
    	} catch(Exception e) {
    		e.printStackTrace();
    	}
    }
    */
}
