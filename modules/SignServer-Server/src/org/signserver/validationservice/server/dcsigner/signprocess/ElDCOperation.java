package org.signserver.validationservice.server.dcsigner.signprocess;

public enum ElDCOperation
{
    DC_UNKNOWN, 
    DC_RAW_SIGN;
    
    public String toString() {
        switch (this) {
            case DC_RAW_SIGN: {
                return "Sign.Raw";
            }
            default: {
                return "Unknown";
            }
        }
    }
    
    public static ElDCOperation fromString(final String s) {
        if (s.equalsIgnoreCase("Sign.Raw")) {
            return ElDCOperation.DC_RAW_SIGN;
        }
        return ElDCOperation.DC_UNKNOWN;
    }
}
