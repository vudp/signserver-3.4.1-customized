package org.signserver.validationservice.server.dcsigner.signprocess;

public class ElDCException extends Exception
{
    private static final long serialVersionUID = 1L;
    
    public ElDCException() {
        super("");
    }
    
    public ElDCException(final String s) {
        super(s);
    }
}
