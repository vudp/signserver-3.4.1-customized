package org.signserver.validationservice.server.dcsigner;

import java.security.cert.Certificate;
import java.util.ArrayList;

import javax.xml.bind.DatatypeConverter;

import org.signserver.validationservice.server.dcsigner.signprocess.ElDCServerException;
import org.signserver.validationservice.server.dcsigner.signprocess.handlers.ElDCSignOperationHandler;
import org.signserver.validationservice.server.dcsigner.signprocess.messages.ElDCMessageParameter;

public class CustomOperationHandler extends ElDCSignOperationHandler {
	protected Certificate signingCertificate;
	private byte[] dataToSign;
	private byte[] signature;

	public byte[] sign(final byte[] array, final byte[] array2,
			final boolean b, final ArrayList<ElDCMessageParameter> list,
			final ArrayList<ElDCMessageParameter> list2) throws Exception {
		
		this.dataToSign = array;
		if (this.signingCertificate == null) {
			
			//throw new ElDCServerException("There are no signing certificate");
		}
		
		if (b) {
			final ElDCMessageParameter elDCMessageParameter = new ElDCMessageParameter();
			elDCMessageParameter.setOID("signing-certificate@eldos.com");
			elDCMessageParameter.setTag((short) 4);
			elDCMessageParameter.setValue(this.signingCertificate.getEncoded());
			list.add(elDCMessageParameter);

		}
		
		if(this.signature == null) {
			
			System.out.println("Signature is null");
			System.out.println(DatatypeConverter.printHexBinary(array));
		}
		return signature;
	}

	public void setSigningCertificate(final Certificate signingCertificate) {
		this.signingCertificate = signingCertificate;
	}
	
	public void setSignature(byte[] signature) {
		this.signature = signature;
	}

	public byte[] getDataToSign() {
		return this.dataToSign;
	}
}
