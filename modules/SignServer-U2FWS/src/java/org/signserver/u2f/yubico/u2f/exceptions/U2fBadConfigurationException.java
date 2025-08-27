package org.signserver.u2f.yubico.u2f.exceptions;

public class U2fBadConfigurationException extends RuntimeException {
    public U2fBadConfigurationException(String message) {
        super(message);
    }

    public U2fBadConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}
