package org.signserver.validationservice.server.dcsigner.signprocess;

import java.util.*;
import org.signserver.validationservice.server.dcsigner.signprocess.messages.*;
import org.w3c.dom.*;
import java.lang.reflect.*;

public final class ElDCUtils
{
    public static final String ASYNC_STATE_NAME = "SecureBlackboxAsyncState";
    public static final String TYPE_NAME = "Type";
    public static final String GENERATOR_NAME = "Generator";
    public static final String SUBTYPE_NAME = "Subtype";
    public static final String SUBTYPES_NAME = "Subtypes";
    public static final String USER_DATA_NAME = "UserData";
    public static final String ROOT_MESSAGE_NAME = "RootMessage";
    public static final String INNER_STATE_NAME = "InnerState";
    public static final String MESSAGE_TYPE_NAME = "MessageType";
    public static final String MESSAGE_ID_NAME = "MessageID";
    public static final String NAME_NAME = "Name";
    public static final String PARS_NAME = "Pars";
    public static final String PAR_NAME = "Par";
    public static final String ORIGINAL_MESSAGE_NAME = "OriginalMessage";
    public static final String BATCH_ELEMENT_NAME = "BatchElement";
    public static final String ERROR_MESSAGE_NAME = "ErrorMessage";
    public static final String ERROR_CODE_NAME = "Code";
    public static final String OPERATION_NAME = "Operation";
    public static final String OPERATION_ID_NAME = "OperationID";
    public static final String SOURCE_NAME = "Source";
    public static final String HASH_ALGORITHM_NAME = "HashAlgorithm";
    public static final String INCLUDE_KEYS_NAME = "IncludeKeys";
    public static final String OPERATION_RESULT_NAME = "OperationResult";
    public static final String KEYS_NAME = "Keys";
    public static final String KEY_NAME = "Key";
    public static final String OID_ATTRIBUTE = "oid";
    public static final String TAG_ATTRIBUTE = "tag";
    public static final String STATE_GENERIC_VALUE = "State.Generic";
    public static final String MESSAGE_BASE_VALUE = "Message.Base";
    public static final String MESSAGE_BATCH_VALUE = "Message.Batch";
    public static final String MESSAGE_UNSUPPORTED_VALUE = "Message.Unsupported";
    public static final String MESSAGE_ERROR_VALUE = "Message.Error";
    public static final String MESSAGE_OPERATION_REQUEST_VALUE = "Message.OperationRequest";
    public static final String MESSAGE_OPERATION_RESPONSE_VALUE = "Message.OperationResponse";
    public static final String OPERATION_UNKNOWN_VALUE = "Unknown";
    public static final String OPERATION_RAW_SIGN_VALUE = "Sign.Raw";
    public static final String SB_AST_STANDARD = "standard";
    public static final String SB_AST_PKCS1SIG = "pkcs1sig";
    public static final String SB_OID_DC_SIGNING_CERTIFICATE = "signing-certificate@eldos.com";
    public static final String SB_OID_DC_CERTIFICATE = "certificate@eldos.com";
    public static final String UPPER_BASE16_ALPHABET = "0123456789ABCDEF";
    public static final String BOOLEAN_FALSE_VALUE = "false";
    public static final String BOOLEAN_TRUE_VALUE = "true";
    public static final String ERROR_UNSUPPORTED_MESSAGE_TYPE = "Unsupported message type: %s";
    public static final String ERROR_CANNOT_ASSIGN = "Cannot assign an object of class %s to an object of class %s";
    public static final String ERROR_ELEMENT_NOT_FOUND = "Element with name '%s' is not found";
    public static final String ERROR_INVALID_BOOLEAN_VALUE = "'%s' is not a valid boolean value";
    public static final String ERROR_INVALID_HEX_DIGIT = "Character '%c' is not a hexidecimal digit";
    public static final String ERROR_AT_POSITION = "%s at position %d";
    public static final String ERROR_INVALID_ASYNC_STATE_FORMAT = "Invalid asynchronous state format";
    public static final String ERROR_UNSUPPORTED_STATE_TYPE = "Unsupported state type: %s";
    public static final String ERROR_UNSUPPORTED_STATE_ROOT = "Unsupported state root document: %s";
    public static final String ERROR_OUT_OF_BYTE_RANGE = "All values must be in range 0-255";
    public static final String ERROR_UNEXPECTED_MESSAGE = "Unexpected message";
    public static final String ERROR_UNSUPPORTED_OPERATION = "Unsupported operation";
    public static final String ERROR_NO_SIGNING_KEYS = "There are no signing certificates nor keys";
    public static final String ERROR_ONLY_RSA_SUPPORTED = "Only RSA keys and certificates are supported";
    public static final String ERROR_ALGORITHM_NOT_SUPPORTED = "The specified algorithm is not supported.\nError: %s";
    public static final String ERROR_CANNOT_USE_KEY = "The key cannot be used to sign the data.\nError: %s";
    public static final String ERROR_SIGNING_FAILED = "Failed to sign the data.\nError: %s";
    public static final String ERROR_OUT_OF_ANSI_CHARSET = "Character '%c' at position %d cannot be converted to byte";
    public static final String ERROR_UNKNOWN_HASH_ALGORITHM = "Unknown hash algorithm: %s";
    public static final String ERROR_UNSUPPORTED_HASH_ALGORITHM = "The hash algorithm %s is supported since JRE %s";
    public static final short SB_ASN1_OCTETSTRING = 4;
    public static final String SB_OID_MD2 = "2A864886F70D0202";
    public static final String SB_OID_MD5 = "2A864886F70D0205";
    public static final String SB_OID_SHA1 = "2B0E03021A";
    public static final String SB_OID_SHA256 = "608648016503040201";
    public static final String SB_OID_SHA384 = "608648016503040202";
    public static final String SB_OID_SHA512 = "608648016503040203";
    
    public static final String loadStringFromXML(final Element element, final String s, final String s2, final boolean b) throws ElDCException {
        final NodeList childNodes = element.getChildNodes();
        for (int length = childNodes.getLength(), i = 0; i < length; ++i) {
            final Node item = childNodes.item(i);
            if (item.getNodeType() == 1 && item.getNodeName().equalsIgnoreCase(s)) {
                final NodeList childNodes2 = item.getChildNodes();
                for (int length2 = childNodes2.getLength(), j = 0; j < length2; ++j) {
                    final Node item2 = childNodes2.item(j);
                    if (item2.getNodeType() == 3) {
                        return item2.getNodeValue();
                    }
                }
            }
        }
        if (b) {
            throw new ElDCValueNotFoundException(String.format("Element with name '%s' is not found", s));
        }
        return s2;
    }
    
    public static final int loadIntFromXML(final Element element, final String s, final int n, final boolean b) throws ElDCValueNotFoundException {
        final NodeList childNodes = element.getChildNodes();
        for (int length = childNodes.getLength(), i = 0; i < length; ++i) {
            final Node item = childNodes.item(i);
            if (item.getNodeType() == 1 && item.getNodeName().equalsIgnoreCase(s)) {
                final NodeList childNodes2 = item.getChildNodes();
                for (int length2 = childNodes2.getLength(), j = 0; j < length2; ++j) {
                    final Node item2 = childNodes2.item(j);
                    if (item2.getNodeType() == 3) {
                        final String nodeValue = item2.getNodeValue();
                        try {
                            return Integer.parseInt(nodeValue);
                        }
                        catch (Exception ex) {
                            return n;
                        }
                    }
                }
            }
        }
        if (b) {
            throw new ElDCValueNotFoundException(String.format("Element with name '%s' is not found", s));
        }
        return n;
    }
    
    public static final void loadListFromXML(final Element element, final String s, final String s2, final ArrayList<String> list, final boolean b) throws ElDCValueNotFoundException {
        final NodeList childNodes = element.getChildNodes();
        for (int length = childNodes.getLength(), i = 0; i < length; ++i) {
            final Node item = childNodes.item(i);
            if (item.getNodeType() == 1 && item.getNodeName().equalsIgnoreCase(s)) {
                final NodeList childNodes2 = item.getChildNodes();
                for (int length2 = childNodes2.getLength(), j = 0; j < length2; ++j) {
                    final Node item2 = childNodes2.item(j);
                    if (item2.getNodeType() == 1 && item2.getNodeName().equalsIgnoreCase(s2)) {
                        String nodeValue = "";
                        final NodeList childNodes3 = item2.getChildNodes();
                        for (int length3 = childNodes3.getLength(), k = 0; k < length3; ++k) {
                            final Node item3 = childNodes3.item(k);
                            if (item3.getNodeType() == 3) {
                                nodeValue = item3.getNodeValue();
                                break;
                            }
                        }
                        list.add(nodeValue);
                    }
                }
                return;
            }
        }
        if (b) {
            throw new ElDCValueNotFoundException(String.format("Element with name '%s' is not found", s));
        }
    }
    
    public static final void loadParametersFromXML(final Element element, final String s, final String s2, final ArrayList<ElDCMessageParameter> list, final boolean b) throws ElDCValueNotFoundException {
        final NodeList childNodes = element.getChildNodes();
        for (int length = childNodes.getLength(), i = 0; i < length; ++i) {
            final Node item = childNodes.item(i);
            if (item.getNodeType() == 1 && item.getNodeName().equalsIgnoreCase(s)) {
                final NodeList childNodes2 = item.getChildNodes();
                for (int length2 = childNodes2.getLength(), j = 0; j < length2; ++j) {
                    final Node item2 = childNodes2.item(j);
                    if (item2.getNodeType() == 1 && item2.getNodeName().equalsIgnoreCase(s2)) {
                        final ElDCMessageParameter elDCMessageParameter = new ElDCMessageParameter();
                        final Node namedItem = item2.getAttributes().getNamedItem("oid");
                        if (namedItem != null) {
                            elDCMessageParameter.setOID(base16DecodeShorts(namedItem.getNodeValue()));
                        }
                        final Node namedItem2 = item2.getAttributes().getNamedItem("tag");
                        if (namedItem2 != null) {
                            elDCMessageParameter.setTag(Short.valueOf(namedItem2.getNodeValue()));
                        }
                        final NodeList childNodes3 = item2.getChildNodes();
                        for (int length3 = childNodes3.getLength(), k = 0; k < length3; ++k) {
                            final Node item3 = childNodes3.item(k);
                            if (item3.getNodeType() == 3) {
                                elDCMessageParameter.setValue(base16DecodeShorts(item3.getNodeValue()));
                                break;
                            }
                        }
                        list.add(elDCMessageParameter);
                    }
                }
                return;
            }
        }
        if (b) {
            throw new ElDCValueNotFoundException(String.format("Element with name '%s' is not found", s));
        }
    }
    
    public static final void saveStringToXML(final Element element, final String s, final String s2) {
        final Element element2 = element.getOwnerDocument().createElement(s);
        element2.appendChild(element.getOwnerDocument().createTextNode(s2));
        element.appendChild(element2);
    }
    
    public static final void saveBinaryToXML(final Element element, final String s, final byte[] array) {
        final Element element2 = element.getOwnerDocument().createElement(s);
        element2.appendChild(element.getOwnerDocument().createTextNode(base16Encode(array)));
        element.appendChild(element2);
    }
    
    public static final void saveBinaryToXML(final Element element, final String s, final short[] array) {
        final Element element2 = element.getOwnerDocument().createElement(s);
        element2.appendChild(element.getOwnerDocument().createTextNode(base16Encode(array)));
        element.appendChild(element2);
    }
    
    public static final void saveIntToXML(final Element element, final String s, final int n) {
        final Element element2 = element.getOwnerDocument().createElement(s);
        element2.appendChild(element.getOwnerDocument().createTextNode(String.valueOf(n)));
        element.appendChild(element2);
    }
    
    public static final void saveListToXML(final Element element, final String s, final String s2, final ArrayList<String> list) {
        final Document ownerDocument = element.getOwnerDocument();
        final Element element2 = ownerDocument.createElement(s);
        element.appendChild(element2);
        for (int i = 0; i < list.size(); ++i) {
            final Element element3 = ownerDocument.createElement(s2);
            element3.appendChild(ownerDocument.createTextNode(list.get(i)));
            element2.appendChild(element3);
        }
    }
    
    public static final void saveParametersToXML(final Element element, final String s, final String s2, final ArrayList<ElDCMessageParameter> list) {
        final Document ownerDocument = element.getOwnerDocument();
        final Element element2 = ownerDocument.createElement(s);
        element.appendChild(element2);
        for (int size = list.size(), i = 0; i < size; ++i) {
            final Element element3 = ownerDocument.createElement(s2);
            element3.setAttribute("oid", base16Encode(list.get(i).getOID()));
            element3.setAttribute("tag", Short.toString(list.get(i).getTag()));
            element3.appendChild(ownerDocument.createTextNode(base16Encode(list.get(i).getValue())));
            element2.appendChild(element3);
        }
    }
    
    private static final short hexCharToShort(final char c) {
        if (c >= '0' && c <= '9') {
            return (short)(c - '0');
        }
        if (c >= 'A' && c <= 'F') {
            return (short)(c - '7');
        }
        if (c >= 'a' && c <= 'f') {
            return (short)(c - 'W');
        }
        throw new IllegalArgumentException(String.format("Character '%c' is not a hexidecimal digit", c));
    }
    
    public static final short[] base16DecodeShorts(final String s) throws IllegalArgumentException {
        if (s == null || s.length() == 0) {
            return new short[0];
        }
        if ((s.length() & 0x1) != 0x0) {
            throw new IllegalArgumentException();
        }
        final char[] charArray = s.toCharArray();
        final int n = charArray.length >> 1;
        final short[] array = new short[n];
        for (int i = 0; i < n; ++i) {
            final int n2 = i << 1;
            short hexCharToShort;
            try {
                hexCharToShort = hexCharToShort(charArray[n2]);
            }
            catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException(String.format("%s at position %d", ex.getMessage(), n2));
            }
            short hexCharToShort2;
            try {
                hexCharToShort2 = hexCharToShort(charArray[n2 + 1]);
            }
            catch (IllegalArgumentException ex2) {
                throw new IllegalArgumentException(String.format("%s at position %d", ex2.getMessage(), n2 + 1));
            }
            array[i] = (short)(hexCharToShort << 4 | hexCharToShort2);
        }
        return array;
    }
    
    public static final byte[] base16DecodeBytes(final String s) {
        if (s == null || s.length() == 0) {
            return new byte[0];
        }
        if ((s.length() & 0x1) != 0x0) {
            throw new IllegalArgumentException();
        }
        final char[] charArray = s.toCharArray();
        final int n = charArray.length >> 1;
        final byte[] array = new byte[n];
        for (int i = 0; i < n; ++i) {
            final int n2 = i << 1;
            short hexCharToShort;
            try {
                hexCharToShort = hexCharToShort(charArray[n2]);
            }
            catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException(String.format("%s at position %d", ex.getMessage(), n2));
            }
            short hexCharToShort2;
            try {
                hexCharToShort2 = hexCharToShort(charArray[n2 + 1]);
            }
            catch (IllegalArgumentException ex2) {
                throw new IllegalArgumentException(String.format("%s at position %d", ex2.getMessage(), n2 + 1));
            }
            array[i] = (byte)(hexCharToShort << 4 | hexCharToShort2);
        }
        return array;
    }
    
    public static final String base16Encode(final short[] array) throws IllegalArgumentException {
        if (array == null) {
            return "";
        }
        final int length = array.length;
        final char[] array2 = new char[length << 1];
        for (int i = 0; i < length; ++i) {
            if (array[i] < 0 || array[i] > 255) {
                throw new IllegalArgumentException(String.format("Value %d at index %d is out of range", array[i], i));
            }
            array2[i << 1] = "0123456789ABCDEF".charAt(array[i] >>> 4);
            array2[(i << 1) + 1] = "0123456789ABCDEF".charAt(array[i] & 0xF);
        }
        return new String(array2);
    }
    
    public static final String base16Encode(final byte[] array) {
        if (array == null) {
            return "";
        }
        final int length = array.length;
        final char[] array2 = new char[length << 1];
        for (int i = 0; i < length; ++i) {
            final int n = (array[i] < 0) ? (256 + array[i]) : array[i];
            array2[i << 1] = "0123456789ABCDEF".charAt(n >>> 4);
            array2[(i << 1) + 1] = "0123456789ABCDEF".charAt(n & 0xF);
        }
        return new String(array2);
    }
    
    public static final void checkByteArray(final short[] array) {
        for (int i = 0; i < array.length; ++i) {
            if (array[i] < 0 || array[i] > 255) {
                throw new IllegalArgumentException("All values must be in range 0-255");
            }
        }
    }
    
    public static final String booleanToString(final boolean b) {
        return b ? "true" : "false";
    }
    
    public static final boolean stringToBoolean(final String s) {
        if (s.equalsIgnoreCase("false")) {
            return false;
        }
        if (s.equalsIgnoreCase("true")) {
            return true;
        }
        throw new IllegalArgumentException(String.format("'%s' is not a valid boolean value", s));
    }
    
    public static final byte[] bytesOfString(final String s) {
        if (s == null) {
            return null;
        }
        final int length = s.length();
        final byte[] array = new byte[length];
        for (int i = 0; i < length; ++i) {
            final char char1 = s.charAt(i);
            if (char1 > '\u00ff') {
                throw new IllegalArgumentException(String.format("Character '%c' at position %d cannot be converted to byte", char1, i));
            }
            array[i] = (byte)char1;
        }
        return array;
    }
    
    public static Field findField(final Object o, final String s) {
        Class<?> clazz = o.getClass();
        do {
            final Field[] declaredFields = clazz.getDeclaredFields();
            for (int i = 0; i < declaredFields.length; ++i) {
                if (declaredFields[i].getName() == s) {
                    if (!declaredFields[i].isAccessible()) {
                        declaredFields[i].setAccessible(true);
                    }
                    return declaredFields[i];
                }
            }
            clazz = clazz.getSuperclass();
        } while (clazz != null);
        return null;
    }
    
    public static Method findMethod(final Object o, final String s) {
        Class<?> clazz = o.getClass();
        do {
            final Method[] declaredMethods = clazz.getDeclaredMethods();
            for (int i = 0; i < declaredMethods.length; ++i) {
                if (declaredMethods[i].getName() == s) {
                    if (!declaredMethods[i].isAccessible()) {
                        declaredMethods[i].setAccessible(true);
                    }
                    return declaredMethods[i];
                }
            }
            clazz = clazz.getSuperclass();
        } while (clazz != null);
        return null;
    }
}
