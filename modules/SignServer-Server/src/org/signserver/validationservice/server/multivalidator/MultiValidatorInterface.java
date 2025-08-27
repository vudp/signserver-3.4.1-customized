package org.signserver.validationservice.server.multivalidator;

import org.signserver.validationservice.server.*;
import org.signserver.common.dbdao.*;
import java.util.*;

public interface MultiValidatorInterface {
	public MultiValidatorResponse verify(byte[] data, String serialNumber, ArrayList<Ca> caProviders, int trustedhubTransId);
	public MultiValidatorResponse verify(byte[] data, String password, String serialNumber, ArrayList<Ca> caProviders, int trustedhubTransId);
}