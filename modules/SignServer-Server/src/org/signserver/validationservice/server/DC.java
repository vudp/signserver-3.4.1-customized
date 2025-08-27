package org.signserver.validationservice.server;

import java.util.Properties;

public interface DC {
	public DCResponse signInit(byte[] fileData, Properties signaturePro);
//        public DCResponse signInit(byte[] fileData, Properties signaturePro, X509Certificate[] certificates);
	public DCResponse signFinal(String dcStreamDataPath, String dcStreamSignPath, byte[] signature, String base64Cert);
}