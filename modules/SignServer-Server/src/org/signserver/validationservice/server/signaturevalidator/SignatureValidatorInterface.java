package org.signserver.validationservice.server.signaturevalidator;

import java.util.*;
import org.signserver.validationservice.server.*;
import org.signserver.common.dbdao.*;

public interface SignatureValidatorInterface {
	public SignatureValidatorResponse verify(String channelName, String user, byte[] data, byte[] signature, String serialNumber, ArrayList<Ca> caProviders, int trustedhubTransId);
	public SignatureValidatorResponse verify(String channelName, String user, byte[] data, byte[] signature, String certificate, String serialNumber, ArrayList<Ca> caProviders, int trustedhubTransId);
}