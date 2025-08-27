package xades4j.providers.impl;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import xades4j.providers.KeyingDataProvider;
import xades4j.providers.SigningCertChainException;
import xades4j.providers.SigningKeyException;
import xades4j.verification.UnexpectedJCAException;

public class ExtingKeyingDataProvider implements KeyingDataProvider {
	
	private List<X509Certificate> signingCertificateChain;
	private PrivateKey signingKey;
	
	public ExtingKeyingDataProvider(
			Certificate[] certs, PrivateKey signingKey) {
		for(int i=0; i<certs.length; i++) {
			signingCertificateChain = new ArrayList<X509Certificate>();
			signingCertificateChain.add((X509Certificate)certs[i]);
		}
		this.signingKey = signingKey;
	}
	
	
	public ExtingKeyingDataProvider(
			List<X509Certificate> signingCertificateChain, PrivateKey signingKey) {
		this.signingCertificateChain = signingCertificateChain;
		this.signingKey = signingKey;
	}

	public void setSigningCertificateChain(
			List<X509Certificate> signingCertificateChain) {
		this.signingCertificateChain = signingCertificateChain;
	}

	public void setSigningKey(PrivateKey signingKey) {
		this.signingKey = signingKey;
	}

	@Override
	public List<X509Certificate> getSigningCertificateChain()
			throws SigningCertChainException, UnexpectedJCAException {
		// TODO Auto-generated method stub
		return signingCertificateChain;
	}

	@Override
	public PrivateKey getSigningKey(X509Certificate signingCert)
			throws SigningKeyException, UnexpectedJCAException {
		// TODO Auto-generated method stub
		return signingKey;
	}

	public PrivateKey getSigningKey() {
		return signingKey;
	}

}
