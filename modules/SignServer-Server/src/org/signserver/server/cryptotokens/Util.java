package org.signserver.server.cryptotokens;

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.TokenInfo;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import iaik.pkcs.pkcs11.wrapper.PKCS11;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import iaik.utils.CryptoUtils;
import iaik.x509.X509Certificate;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

/**
 * This class contains only static methods. It is the place for all functions that are used by
 * several classes in this package.
 * 
 * @author Karl Scheibelhofer
 */
public class Util {

  /**
   * Maps mechanism strings to their codes as Long.
   */
  protected static Hashtable mechansimCodes_;

  /**
   * Converts the names of mechanisms to their long value code.
   * 
   * @param mechansimName
   *          The name of the mechanism to get the code; e.g. "CKM_RSA_PKCS".
   * @return The code of the mechanism or null, if this name is unknown.
   * @preconditions (mechansimName <> null)
   * 
   */
  public static Long mechanismCodeToString(String mechansimName) {
    if (mechansimName == null) {
      throw new NullPointerException("Argument \"mechansimName\" must not be null.");
    }

    Long mechanismCode;

    if (mechansimName.startsWith("0x")) {
      // we try to parse it as hex encoded long
      mechanismCode = new Long(Long.parseLong(mechansimName, 16));
    } else {
      if (mechansimCodes_ == null) {
        mechansimCodes_ = new Hashtable(160);
        mechansimCodes_.put("CKM_RSA_PKCS_KEY_PAIR_GEN", new Long(0x00000000));
        mechansimCodes_.put("CKM_RSA_PKCS", new Long(0x00000001));
        mechansimCodes_.put("CKM_RSA_9796", new Long(0x00000002));
        mechansimCodes_.put("CKM_RSA_X_509", new Long(0x00000003));
        mechansimCodes_.put("CKM_MD2_RSA_PKCS", new Long(0x00000004));
        mechansimCodes_.put("CKM_MD5_RSA_PKCS", new Long(0x00000005));
        mechansimCodes_.put("CKM_SHA1_RSA_PKCS", new Long(0x00000006));
        mechansimCodes_.put("CKM_RIPEMD128_RSA_PKCS", new Long(0x00000007));
        mechansimCodes_.put("CKM_RIPEMD160_RSA_PKCS", new Long(0x00000008));
        mechansimCodes_.put("CKM_RSA_PKCS_OAEP", new Long(0x00000009));
        mechansimCodes_.put("CKM_DSA_KEY_PAIR_GEN", new Long(0x00000010));
        mechansimCodes_.put("CKM_DSA", new Long(0x00000011));
        mechansimCodes_.put("CKM_DSA_SHA1", new Long(0x00000012));
        mechansimCodes_.put("CKM_DH_PKCS_KEY_PAIR_GEN", new Long(0x00000020));
        mechansimCodes_.put("CKM_DH_PKCS_DERIVE", new Long(0x00000021));
        mechansimCodes_.put("CKM_RC2_KEY_GEN", new Long(0x00000100));
        mechansimCodes_.put("CKM_RC2_ECB", new Long(0x00000101));
        mechansimCodes_.put("CKM_RC2_CBC", new Long(0x00000102));
        mechansimCodes_.put("CKM_RC2_MAC", new Long(0x00000103));
        mechansimCodes_.put("CKM_RC2_MAC_GENERAL", new Long(0x00000104));
        mechansimCodes_.put("CKM_RC2_CBC_PAD", new Long(0x00000105));
        mechansimCodes_.put("CKM_RC4_KEY_GEN", new Long(0x00000110));
        mechansimCodes_.put("CKM_RC4", new Long(0x00000111));
        mechansimCodes_.put("CKM_DES_KEY_GEN", new Long(0x00000120));
        mechansimCodes_.put("CKM_DES_ECB", new Long(0x00000121));
        mechansimCodes_.put("CKM_DES_CBC", new Long(0x00000122));
        mechansimCodes_.put("CKM_DES_MAC", new Long(0x00000123));
        mechansimCodes_.put("CKM_DES_MAC_GENERAL", new Long(0x00000124));
        mechansimCodes_.put("CKM_DES_CBC_PAD", new Long(0x00000125));
        mechansimCodes_.put("CKM_DES2_KEY_GEN", new Long(0x00000130));
        mechansimCodes_.put("CKM_DES3_KEY_GEN", new Long(0x00000131));
        mechansimCodes_.put("CKM_DES3_ECB", new Long(0x00000132));
        mechansimCodes_.put("CKM_DES3_CBC", new Long(0x00000133));
        mechansimCodes_.put("CKM_DES3_MAC", new Long(0x00000134));
        mechansimCodes_.put("CKM_DES3_MAC_GENERAL", new Long(0x00000135));
        mechansimCodes_.put("CKM_DES3_CBC_PAD", new Long(0x00000136));
        mechansimCodes_.put("CKM_CDMF_KEY_GEN", new Long(0x00000140));
        mechansimCodes_.put("CKM_CDMF_ECB", new Long(0x00000141));
        mechansimCodes_.put("CKM_CDMF_CBC", new Long(0x00000142));
        mechansimCodes_.put("CKM_CDMF_MAC", new Long(0x00000143));
        mechansimCodes_.put("CKM_CDMF_MAC_GENERAL", new Long(0x00000144));
        mechansimCodes_.put("CKM_CDMF_CBC_PAD", new Long(0x00000145));
        mechansimCodes_.put("CKM_MD2", new Long(0x00000200));
        mechansimCodes_.put("CKM_MD2_HMAC", new Long(0x00000201));
        mechansimCodes_.put("CKM_MD2_HMAC_GENERAL", new Long(0x00000202));
        mechansimCodes_.put("CKM_MD5", new Long(0x00000210));
        mechansimCodes_.put("CKM_MD5_HMAC", new Long(0x00000211));
        mechansimCodes_.put("CKM_MD5_HMAC_GENERAL", new Long(0x00000212));
        mechansimCodes_.put("CKM_SHA_1", new Long(0x00000220));
        mechansimCodes_.put("CKM_SHA_1_HMAC", new Long(0x00000221));
        mechansimCodes_.put("CKM_SHA_1_HMAC_GENERAL", new Long(0x00000222));
        mechansimCodes_.put("CKM_RIPEMD128", new Long(0x00000230));
        mechansimCodes_.put("CKM_RIPEMD128_HMAC", new Long(0x00000231));
        mechansimCodes_.put("CKM_RIPEMD128_HMAC_GENERAL", new Long(0x00000232));
        mechansimCodes_.put("CKM_RIPEMD160", new Long(0x00000240));
        mechansimCodes_.put("CKM_RIPEMD160_HMAC", new Long(0x00000241));
        mechansimCodes_.put("CKM_RIPEMD160_HMAC_GENERAL", new Long(0x00000242));
        mechansimCodes_.put("CKM_CAST_KEY_GEN", new Long(0x00000300));
        mechansimCodes_.put("CKM_CAST_ECB", new Long(0x00000301));
        mechansimCodes_.put("CKM_CAST_CBC", new Long(0x00000302));
        mechansimCodes_.put("CKM_CAST_MAC", new Long(0x00000303));
        mechansimCodes_.put("CKM_CAST_MAC_GENERAL", new Long(0x00000304));
        mechansimCodes_.put("CKM_CAST_CBC_PAD", new Long(0x00000305));
        mechansimCodes_.put("CKM_CAST3_KEY_GEN", new Long(0x00000310));
        mechansimCodes_.put("CKM_CAST3_ECB", new Long(0x00000311));
        mechansimCodes_.put("CKM_CAST3_CBC", new Long(0x00000312));
        mechansimCodes_.put("CKM_CAST3_MAC", new Long(0x00000313));
        mechansimCodes_.put("CKM_CAST3_MAC_GENERAL", new Long(0x00000314));
        mechansimCodes_.put("CKM_CAST3_CBC_PAD", new Long(0x00000315));
        mechansimCodes_.put("CKM_CAST5_KEY_GEN", new Long(0x00000320));
        mechansimCodes_.put("CKM_CAST128_KEY_GEN", new Long(0x00000320));
        mechansimCodes_.put("CKM_CAST5_ECB", new Long(0x00000321));
        mechansimCodes_.put("CKM_CAST128_ECB", new Long(0x00000321));
        mechansimCodes_.put("CKM_CAST5_CBC", new Long(0x00000322));
        mechansimCodes_.put("CKM_CAST128_CBC", new Long(0x00000322));
        mechansimCodes_.put("CKM_CAST5_MAC", new Long(0x00000323));
        mechansimCodes_.put("CKM_CAST128_MAC", new Long(0x00000323));
        mechansimCodes_.put("CKM_CAST5_MAC_GENERAL", new Long(0x00000324));
        mechansimCodes_.put("CKM_CAST128_MAC_GENERAL", new Long(0x00000324));
        mechansimCodes_.put("CKM_CAST5_CBC_PAD", new Long(0x00000325));
        mechansimCodes_.put("CKM_CAST128_CBC_PAD", new Long(0x00000325));
        mechansimCodes_.put("CKM_RC5_KEY_GEN", new Long(0x00000330));
        mechansimCodes_.put("CKM_RC5_ECB", new Long(0x00000331));
        mechansimCodes_.put("CKM_RC5_CBC", new Long(0x00000332));
        mechansimCodes_.put("CKM_RC5_MAC", new Long(0x00000333));
        mechansimCodes_.put("CKM_RC5_MAC_GENERAL", new Long(0x00000334));
        mechansimCodes_.put("CKM_RC5_CBC_PAD", new Long(0x00000335));
        mechansimCodes_.put("CKM_IDEA_KEY_GEN", new Long(0x00000340));
        mechansimCodes_.put("CKM_IDEA_ECB", new Long(0x00000341));
        mechansimCodes_.put("CKM_IDEA_CBC", new Long(0x00000342));
        mechansimCodes_.put("CKM_IDEA_MAC", new Long(0x00000343));
        mechansimCodes_.put("CKM_IDEA_MAC_GENERAL", new Long(0x00000344));
        mechansimCodes_.put("CKM_IDEA_CBC_PAD", new Long(0x00000345));
        mechansimCodes_.put("CKM_GENERIC_SECRET_KEY_GEN", new Long(0x00000350));
        mechansimCodes_.put("CKM_CONCATENATE_BASE_AND_KEY", new Long(0x00000360));
        mechansimCodes_.put("CKM_CONCATENATE_BASE_AND_DATA", new Long(0x00000362));
        mechansimCodes_.put("CKM_CONCATENATE_DATA_AND_BASE", new Long(0x00000363));
        mechansimCodes_.put("CKM_XOR_BASE_AND_DATA", new Long(0x00000364));
        mechansimCodes_.put("CKM_EXTRACT_KEY_FROM_KEY", new Long(0x00000365));
        mechansimCodes_.put("CKM_SSL3_PRE_MASTER_KEY_GEN", new Long(0x00000370));
        mechansimCodes_.put("CKM_SSL3_MASTER_KEY_DERIVE", new Long(0x00000371));
        mechansimCodes_.put("CKM_SSL3_KEY_AND_MAC_DERIVE", new Long(0x00000372));
        mechansimCodes_.put("CKM_SSL3_MD5_MAC", new Long(0x00000380));
        mechansimCodes_.put("CKM_SSL3_SHA1_MAC", new Long(0x00000381));
        mechansimCodes_.put("CKM_MD5_KEY_DERIVATION", new Long(0x00000390));
        mechansimCodes_.put("CKM_MD2_KEY_DERIVATION", new Long(0x00000391));
        mechansimCodes_.put("CKM_SHA1_KEY_DERIVATION", new Long(0x00000392));
        mechansimCodes_.put("CKM_PBE_MD2_DES_CBC", new Long(0x000003A0));
        mechansimCodes_.put("CKM_PBE_MD5_DES_CBC", new Long(0x000003A1));
        mechansimCodes_.put("CKM_PBE_MD5_CAST_CBC", new Long(0x000003A2));
        mechansimCodes_.put("CKM_PBE_MD5_CAST3_CBC", new Long(0x000003A3));
        mechansimCodes_.put("CKM_PBE_MD5_CAST5_CBC", new Long(0x000003A4));
        mechansimCodes_.put("CKM_PBE_MD5_CAST128_CBC", new Long(0x000003A4));
        mechansimCodes_.put("CKM_PBE_SHA1_CAST5_CBC", new Long(0x000003A5));
        mechansimCodes_.put("CKM_PBE_SHA1_CAST128_CBC", new Long(0x000003A5));
        mechansimCodes_.put("CKM_PBE_SHA1_RC4_128", new Long(0x000003A6));
        mechansimCodes_.put("CKM_PBE_SHA1_RC4_40", new Long(0x000003A7));
        mechansimCodes_.put("CKM_PBE_SHA1_DES3_EDE_CBC", new Long(0x000003A8));
        mechansimCodes_.put("CKM_PBE_SHA1_DES2_EDE_CBC", new Long(0x000003A9));
        mechansimCodes_.put("CKM_PBE_SHA1_RC2_128_CBC", new Long(0x000003AA));
        mechansimCodes_.put("CKM_PBE_SHA1_RC2_40_CBC", new Long(0x000003AB));
        mechansimCodes_.put("CKM_PKCS5_PBKD2", new Long(0x000003B0));
        mechansimCodes_.put("CKM_PBA_SHA1_WITH_SHA1_HMAC", new Long(0x000003C0));
        mechansimCodes_.put("CKM_KEY_WRAP_LYNKS", new Long(0x00000400));
        mechansimCodes_.put("CKM_KEY_WRAP_SET_OAEP", new Long(0x00000401));
        mechansimCodes_.put("CKM_SKIPJACK_KEY_GEN", new Long(0x00001000));
        mechansimCodes_.put("CKM_SKIPJACK_ECB64", new Long(0x00001001));
        mechansimCodes_.put("CKM_SKIPJACK_CBC64", new Long(0x00001002));
        mechansimCodes_.put("CKM_SKIPJACK_OFB64", new Long(0x00001003));
        mechansimCodes_.put("CKM_SKIPJACK_CFB64", new Long(0x00001004));
        mechansimCodes_.put("CKM_SKIPJACK_CFB32", new Long(0x00001005));
        mechansimCodes_.put("CKM_SKIPJACK_CFB16", new Long(0x00001006));
        mechansimCodes_.put("CKM_SKIPJACK_CFB8", new Long(0x00001007));
        mechansimCodes_.put("CKM_SKIPJACK_WRAP", new Long(0x00001008));
        mechansimCodes_.put("CKM_SKIPJACK_PRIVATE_WRAP", new Long(0x00001009));
        mechansimCodes_.put("CKM_SKIPJACK_RELAYX", new Long(0x0000100a));
        mechansimCodes_.put("CKM_KEA_KEY_PAIR_GEN", new Long(0x00001010));
        mechansimCodes_.put("CKM_KEA_KEY_DERIVE", new Long(0x00001011));
        mechansimCodes_.put("CKM_FORTEZZA_TIMESTAMP", new Long(0x00001020));
        mechansimCodes_.put("CKM_BATON_KEY_GEN", new Long(0x00001030));
        mechansimCodes_.put("CKM_BATON_ECB128", new Long(0x00001031));
        mechansimCodes_.put("CKM_BATON_ECB96", new Long(0x00001032));
        mechansimCodes_.put("CKM_BATON_CBC128", new Long(0x00001033));
        mechansimCodes_.put("CKM_BATON_COUNTER", new Long(0x00001034));
        mechansimCodes_.put("CKM_BATON_SHUFFLE", new Long(0x00001035));
        mechansimCodes_.put("CKM_BATON_WRAP", new Long(0x00001036));
        mechansimCodes_.put("CKM_ECDSA_KEY_PAIR_GEN", new Long(0x00001040));
        mechansimCodes_.put("CKM_ECDSA", new Long(0x00001041));
        mechansimCodes_.put("CKM_ECDSA_SHA1", new Long(0x00001042));
        mechansimCodes_.put("CKM_JUNIPER_KEY_GEN", new Long(0x00001060));
        mechansimCodes_.put("CKM_JUNIPER_ECB128", new Long(0x00001061));
        mechansimCodes_.put("CKM_JUNIPER_CBC128", new Long(0x00001062));
        mechansimCodes_.put("CKM_JUNIPER_COUNTER", new Long(0x00001063));
        mechansimCodes_.put("CKM_JUNIPER_SHUFFLE", new Long(0x00001064));
        mechansimCodes_.put("CKM_JUNIPER_WRAP", new Long(0x00001065));
        mechansimCodes_.put("CKM_FASTHASH", new Long(0x00001070));
        mechansimCodes_.put("CKM_VENDOR_DEFINED", new Long(0x80000000));
      }

      mechanismCode = (Long) mechansimCodes_.get(mechansimName);
    }

    return mechanismCode;
  }

  /**
   * Lists all available tokens of the given module and lets the user select one, if there is more
   * than one available.
   * 
   * @param pkcs11Module
   *          The PKCS#11 module to use.
   * @param output
   *          The output stream to write the user prompts to.
   * @param input
   *          The input stream where to read user input from.
   * @return The selected token or null, if no token is available or the user canceled the action.
   * @exception TokenException
   *              If listing the tokens failed.
   * @exception IOException
   *              If writing a user prompt faild or if reading user input failed.
   * @preconditions (pkcs11Module <> null) and (output <> null) and (input <> null)
   * 
   */
  public static Token selectToken(Module pkcs11Module) throws TokenException, IOException {
    return selectToken(pkcs11Module, null);
  }

  /**
   * Lists all available tokens of the given module and lets the user select one, if there is more
   * than one available. Supports token preselection.
   * 
   * @param pkcs11Module
   *          The PKCS#11 module to use.
   * @param output
   *          The output stream to write the user prompts to.
   * @param input
   *          The input stream where to read user input from.
   * @return The selected token or null, if no token is available or the user canceled the action.
   * @exception TokenException
   *              If listing the tokens failed.
   * @exception IOException
   *              If writing a user prompt faild or if reading user input failed.
   * @preconditions (pkcs11Module <> null) and (output <> null) and (input <> null)
   * 
   */
  public static Token selectToken(Module pkcs11Module, String slot) throws TokenException, IOException {
    if (pkcs11Module == null) {
      throw new NullPointerException("Argument \"pkcs11Module\" must not be null.");
    }

    System.out
        .println("################################################################################");
    System.out.println("getting list of all tokens");
    Slot[] slotsWithToken = pkcs11Module
        .getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
    Token[] tokens = new Token[slotsWithToken.length];
    Hashtable tokenIDtoToken = new Hashtable(tokens.length);

    for (int i = 0; i < slotsWithToken.length; i++) {
      System.out
          .println("________________________________________________________________________________");
      tokens[i] = slotsWithToken[i].getToken();
      TokenInfo tokenInfo = tokens[i].getTokenInfo();
      long tokenID = tokens[i].getTokenID();
      tokenIDtoToken.put(new Long(tokenID), tokens[i]);
      System.out.println("Token ID: " + tokenID);
      System.out.println(tokenInfo);
      System.out
          .println("________________________________________________________________________________");
    }
    System.out
        .println("################################################################################");

    System.out
        .println("################################################################################");
    Token token = null;
    Long selectedTokenID = null;
    if (tokens.length == 0) {
      System.out.println("There is no slot with a present token.");
    } else if (tokens.length == 1) {
      System.out.println("Taking token with ID: " + tokens[0].getTokenID());
      selectedTokenID = new Long(tokens[0].getTokenID());
      token = tokens[0];
    } else {
      boolean gotTokenID = false;
      while (!gotTokenID) {
       
        String tokenIDstring;
        tokenIDstring = slot;
        System.out.print(slot + "\n");

        if (tokenIDstring.equalsIgnoreCase("x")) {
          break;
        }
        try {
          selectedTokenID = new Long(tokenIDstring);
          token = (Token) tokenIDtoToken.get(selectedTokenID);
          if (token != null) {
            gotTokenID = true;
          } else {
            System.out.println("A token with the entered ID \"" + tokenIDstring
                + "\" does not exist. Try again.");
          }
        } catch (NumberFormatException ex) {
          System.out.println("The entered ID \"" + tokenIDstring
              + "\" is invalid. Try again.");
        }
      }
    }
    System.out
        .println("################################################################################");

    return token;
  }

  /**
   * Opens an authorized session for the given token. If the token requires the user to login for
   * private operations, the method loggs in the user.
   * 
   * @param token
   *          The token to open a session for.
   * @param rwSession
   *          If the session should be a read-write session. This may be
   *          Token.SessionReadWriteBehavior.RO_SESSION or
   *          Token.SessionReadWriteBehavior.RW_SESSION.
   * @param output
   *          The output stream to write the user prompts to.
   * @param input
   *          The input stream where to read user input from.
   * @return The selected token or null, if no token is available or the user canceled the action.
   * @exception TokenException
   *              If listing the tokens failed.
   * @exception IOException
   *              If writing a user prompt faild or if reading user input failed.
   * @preconditions (token <> null) and (output <> null) and (input <> null)
   * @postconditions (result <> null)
   */
  public static Session openAuthorizedSession(Token token, boolean rwSession) throws TokenException, IOException {
    return openAuthorizedSession(token, rwSession, null);
  }

  /**
   * Opens an authorized session for the given token. If the token requires the user to login for
   * private operations, the method loggs in the user.
   * 
   * @param token
   *          The token to open a session for.
   * @param rwSession
   *          If the session should be a read-write session. This may be
   *          Token.SessionReadWriteBehavior.RO_SESSION or
   *          Token.SessionReadWriteBehavior.RW_SESSION.
   * @param output
   *          The output stream to write the user prompts to.
   * @param input
   *          The input stream where to read user input from.
   * @return The selected token or null, if no token is available or the user canceled the action.
   * @exception TokenException
   *              If listing the tokens failed.
   * @exception IOException
   *              If writing a user prompt faild or if reading user input failed.
   * @preconditions (token <> null) and (output <> null) and (input <> null)
   * @postconditions (result <> null)
   */
  public static Session openAuthorizedSession(Token token, boolean rwSession, String pin) throws TokenException,
      IOException {
    if (token == null) {
      throw new NullPointerException("Argument \"token\" must not be null.");
    }

    System.out
        .println("################################################################################");
    System.out.println("opening session");
    Session session = token.openSession(Token.SessionType.SERIAL_SESSION, rwSession,
        null, null);

    TokenInfo tokenInfo = token.getTokenInfo();
    if (tokenInfo.isLoginRequired()) {
      if (tokenInfo.isProtectedAuthenticationPath()) {
        System.out.print("Please enter the user-PIN at the PIN-pad of your reader.");
        session.login(Session.UserType.USER, null); // the token prompts the PIN by other means;
                                                    // e.g. PIN-pad
      } else {
        String userPINString;
        userPINString = pin;
        try {
        	session.login(Session.UserType.USER, userPINString.toCharArray());
        } catch(PKCS11Exception e) {
        	if(e.getErrorCode() == PKCS11Constants.CKR_USER_ALREADY_LOGGED_IN) {
        		session.logout();
        		session.login(Session.UserType.USER, userPINString.toCharArray());
        	}
        }
      }
    }
    System.out
        .println("################################################################################");

    return session;
  }


  /**
   * Gets a string representation of the given PKCS#11 certificate.
   * 
   * @param certificate
   *          The PKCS#11 certificate.
   * @return The string representing the certificate.
   */
  public static String toString(X509PublicKeyCertificate certificate) {
    String certificateString = null;

    if (certificate != null) {
      try {
        X509Certificate correspondingCertificate = new X509Certificate(certificate
            .getValue().getByteArrayValue());
        certificateString = correspondingCertificate.toString(true);
      } catch (Exception ex) {
        certificateString = certificate.toString();
      }
    }

    return certificateString;
  }

}
