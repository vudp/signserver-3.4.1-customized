package org.signserver.common;

import java.util.Hashtable;

/**
 *
 * @author PHUONGVU
 */
public class OIDManager {
    private static final String C = "2.5.4.6";
    private static final String O = "2.5.4.10";
    private static final String OU = "2.5.4.11";
    private static final String T = "2.5.4.12";
    private static final String CN = "2.5.4.3";
    private static final String SN = "2.5.4.5";
    private static final String STREET = "2.5.4.9";
    private static final String SERIALNUMBER = SN;
    private static final String L = "2.5.4.7";
    private static final String ST = "2.5.4.8";
    private static final String SURNAME = "2.5.4.4";
    private static final String GIVENNAME = "2.5.4.42";
    private static final String INITIALS = "2.5.4.43";
    private static final String GENERATION = "2.5.4.44";
    private static final String UNIQUE_IDENTIFIER = "2.5.4.45";
    private static final String BUSINESS_CATEGORY = "2.5.4.15";
    private static final String POSTAL_CODE = "2.5.4.17";
    private static final String DN_QUALIFIER = "2.5.4.46";
    private static final String PSEUDONYM = "2.5.4.65";
    private static final String DATE_OF_BIRTH = "1.3.6.1.5.5.7.9.1";
    private static final String PLACE_OF_BIRTH = "1.3.6.1.5.5.7.9.2";
    private static final String GENDER = "1.3.6.1.5.5.7.9.3";
    private static final String COUNTRY_OF_CITIZENSHIP = "1.3.6.1.5.5.7.9.4";
    private static final String COUNTRY_OF_RESIDENCE = "1.3.6.1.5.5.7.9.5";
    private static final String NAME_AT_BIRTH = "1.3.36.8.3.14";
    private static final String POSTAL_ADDRESS = "2.5.4.16";
    private static final String DMD_NAME = "2.5.4.54";
    private static final String TELEPHONE_NUMBER = "2.5.4.20";
    private static final String NAME = "2.5.4.41";
    private static final String E = "1.2.840.113549.1.9.1";
    private static final String DC = "0.9.2342.19200300.100.1.25";
    private static final String UID = "0.9.2342.19200300.100.1.1";
    public static String UnstructuredName = "1.2.840.113549.1.9.8";
    public static String UnstructuredAddress = "1.2.840.113549.1.9.2";
    
    private static final Hashtable oid2attr = new Hashtable();
    private static final Hashtable attr2oid = new Hashtable();
    
    static {
        oid2attr.put(C, "C");
        oid2attr.put(O, "O");
        oid2attr.put(T, "T");
        oid2attr.put(OU, "OU");
        oid2attr.put(CN, "CN");
        oid2attr.put(L, "L");
        oid2attr.put(ST, "ST");
        oid2attr.put(SN, "SERIALNUMBER");
        oid2attr.put(E, "E");
        oid2attr.put(DC, "DC");
        oid2attr.put(UID, "UID");
        oid2attr.put(STREET, "STREET");
        oid2attr.put(SURNAME, "SURNAME");
        oid2attr.put(GIVENNAME, "GIVENNAME");
        oid2attr.put(INITIALS, "INITIALS");
        oid2attr.put(GENERATION, "GENERATION");
        oid2attr.put(UnstructuredAddress, "unstructuredAddress");
        oid2attr.put(UnstructuredName, "unstructuredName");
        oid2attr.put(UNIQUE_IDENTIFIER, "UniqueIdentifier");
        oid2attr.put(DN_QUALIFIER, "DN");
        oid2attr.put(PSEUDONYM, "Pseudonym");
        oid2attr.put(POSTAL_ADDRESS, "PostalAddress");
        oid2attr.put(NAME_AT_BIRTH, "NameAtBirth");
        oid2attr.put(COUNTRY_OF_CITIZENSHIP, "CountryOfCitizenship");
        oid2attr.put(COUNTRY_OF_RESIDENCE, "CountryOfResidence");
        oid2attr.put(GENDER, "Gender");
        oid2attr.put(PLACE_OF_BIRTH, "PlaceOfBirth");
        oid2attr.put(DATE_OF_BIRTH, "DateOfBirth");
        oid2attr.put(POSTAL_CODE, "PostalCode");
        oid2attr.put(BUSINESS_CATEGORY, "BusinessCategory");
        oid2attr.put(TELEPHONE_NUMBER, "TelephoneNumber");
        oid2attr.put(NAME, "Name");
        
        attr2oid.put("c", C);
        attr2oid.put("o", O);
        attr2oid.put("t", T);
        attr2oid.put("ou", OU);
        attr2oid.put("cn", CN);
        attr2oid.put("l", L);
        attr2oid.put("st", ST);
        attr2oid.put("s", ST);
        attr2oid.put("sn", SN);
        attr2oid.put("serialnumber", SN);
        attr2oid.put("street", STREET);
        attr2oid.put("emailaddress", E);
        attr2oid.put("dc", DC);
        attr2oid.put("e", E);
        attr2oid.put("uid", UID);
        attr2oid.put("0.9.2342.19200300.100.1.1", UID);
        attr2oid.put("surname", SURNAME);
        attr2oid.put("givenname", GIVENNAME);
        attr2oid.put("initials", INITIALS);
        attr2oid.put("generation", GENERATION);
        attr2oid.put("unstructuredaddress", UnstructuredAddress);
        attr2oid.put("unstructuredname", UnstructuredName);
        attr2oid.put("uniqueidentifier", UNIQUE_IDENTIFIER);
        attr2oid.put("dn", DN_QUALIFIER);
        attr2oid.put("pseudonym", PSEUDONYM);
        attr2oid.put("postaladdress", POSTAL_ADDRESS);
        attr2oid.put("nameofbirth", NAME_AT_BIRTH);
        attr2oid.put("countryofcitizenship", COUNTRY_OF_CITIZENSHIP);
        attr2oid.put("countryofresidence", COUNTRY_OF_RESIDENCE);
        attr2oid.put("gender", GENDER);
        attr2oid.put("placeofbirth", PLACE_OF_BIRTH);
        attr2oid.put("dateofbirth", DATE_OF_BIRTH);
        attr2oid.put("postalcode", POSTAL_CODE);
        attr2oid.put("businesscategory", BUSINESS_CATEGORY);
        attr2oid.put("telephonenumber", TELEPHONE_NUMBER);
        attr2oid.put("name", NAME);
    }
    
    public static String getOID(String attribute) {
        return (String) attr2oid.get(attribute.toLowerCase());
    }
    
    public static String getAttribute(String oid) {
        return (String) oid2attr.get(oid);
    }
}