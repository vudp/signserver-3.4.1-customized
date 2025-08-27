package org.signserver.clientws;

public class SignProcessObject {

	/*public enum CryptoStandard {
		CMS, CADES
	}

	private String ID;
	private byte[] cert;
	private String srcFilePath;
	private String destFilePath;
	private Certificate[] chain;

	private PdfSignatureAppearance appearance;
	private ExternalDigest digest;
	private ExternalSignature signature;
	private TSAClient tsc;
	private int estimatedSize;
	private PdfPKCS7 sgn;
	private byte[] hash;
	private Calendar cal;

	public SignProcessObject(String iD, byte[] cert, String srcFilePath) {
		ID = iD;
		this.cert = cert;
		this.srcFilePath = srcFilePath;
		this.destFilePath = UtilFuncs.FOLDER_PROCESS + ID + "signed.pdf";
		List<Certificate> testList = new ArrayList<Certificate>();
		testList = getCertChainFromBytes(cert);
		// System.out.println("[UtilFuncs-getDataTobeSigned] length list cer add"+
		// testList.size());
		chain = (Certificate[]) testList.toArray(new Certificate[testList
				.size()]);
	}

	public String getID() {
		return ID;
	}

	public void setID(String iD) {
		ID = iD;
	}

	public byte[] getCert() {
		return cert;
	}

	public void setCert(byte[] cert) {
		this.cert = cert;
	}

	public String getSrcFilePath() {
		return srcFilePath;
	}

	public void setSrcFilePath(String srcFilePath) {
		this.srcFilePath = srcFilePath;
	}

	public byte[] getDataTobeSigned() {

		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		try {
			return sign(pathSourcePDF, String.format(DEST_PATH, 1), chain,
					DigestAlgorithms.SHA1, provider.getName(),
					MakeSignature.CryptoStandard.CMS, "Test 1", "Ghent",
					signFromClient);
		} catch (Exception ex) {
			System.out
					.println("[UtilFuncs-getDataTobeSigned] return exception:"
							+ ex);
		}
		return null;

	}

	private byte[] sign(String src, String dest, Certificate[] chain,
			String digestAlgorithm, String provider,
			MakeSignature.CryptoStandard subfilter, String reason,
			String location, byte[] signFromClient)
			throws GeneralSecurityException, IOException, DocumentException {
		System.out.println("[SignPDFPKCS1GUI-sign] start");
		// Creating the reader and the stamper
		PdfReader reader = new PdfReader(src);
		FileOutputStream os = new FileOutputStream(dest);
		PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
		// Creating the appearance
		appearance = stamper.getSignatureAppearance();
		appearance.setReason(reason);
		appearance.setLocation(location);
		appearance.setVisibleSignature(new Rectangle(400, 700, 500, 800), 1,
				"sig");
		// Creating the signature
		digest = new BouncyCastleDigest();
		signature = new MyPdfSigner(digestAlgorithm, provider, null);

		tsc = null;
		tsc = getTimeStampClient(
				"http://192.168.1.239/miniHSM/tsa?workerName=TimeStampSigner",
				null, null);

		System.out.println("[UtilFuncs-sign] before signDetached");
//		MakeSignature.signDetached(appearance, digest, signature, chain, null,
//				null, tsc, 0, subfilter);

		*//**
		 * SIGN DETACH ADD CODE HERE
		 *//*
		// public static void signDetached(PdfSignatureAppearance sap=
		// appearance(OK),
		// ExternalDigest externalDigest = digest (OK),
		// ExternalSignature externalSignature = signature,
		// Certificate[] chain = chain (OK),
		// Collection<CrlClient> crlList,
		// OcspClient ocspClient = null,
		// TSAClient tsaClient = tsc ,
		// int estimatedSize,
		// CryptoStandard sigtype = MakeSignature.CryptoStandard.CMS) throws
		// IOException, DocumentException, GeneralSecurityException {
		// System.out.println("[MakeSignature-signDetached] boutLen when start: "+sap.getBoutLen());
		Collection<byte[]> crlBytes = null;
		int i = 0;
		while (crlBytes == null && i < chain.length)
			crlBytes = processCrl(chain[i++], null);
		if (estimatedSize == 0) {
			estimatedSize = 8192;
			if (crlBytes != null) {
				for (byte[] element : crlBytes) {
					estimatedSize += element.length + 10;
				}
			}
			if (ocspClient != null)
				estimatedSize += 4192;
			if (tsc != null)
				estimatedSize += 4192;
		}
		// System.out.println("[MakeSignature-signDetached] before set chain:"+chain[0].toString());
		appearance.setCertificate(chain[0]);
		// System.out.println("[MakeSignature-signDetached] after set chain");
		PdfSignature dic = new PdfSignature(
				PdfName.ADOBE_PPKLITE,
				MakeSignature.CryptoStandard.CMS == CryptoStandard.CADES ? PdfName.ETSI_CADES_DETACHED
						: PdfName.ADBE_PKCS7_DETACHED);
		dic.setReason(appearance.getReason());
		dic.setLocation(appearance.getLocation());
		dic.setContact(appearance.getContact());
		dic.setDate(new PdfDate(appearance.getSignDate())); // time-stamp will
															// over-rule this
		appearance.setCryptoDictionary(dic);

		// System.out.println("[MakeSignature-signDetached] after set CrytoDictionary");
		HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
		exc.put(PdfName.CONTENTS, new Integer(estimatedSize * 2 + 2));
		// System.out.println("[MakeSignature-signDetached] before preClose");
		appearance.preClose(exc);

		// System.out.println("[MakeSignature-signDetached] boutLen: "+appearance.getBoutLen());

		String hashAlgorithm = signature.getHashAlgorithm();
		sgn = new PdfPKCS7(null, chain, hashAlgorithm, null, digest,
				false);
		InputStream data = appearance.getRangeStream();
		// System.out.println("[MakeSignature-signDetached] data length: "+data.toString());
		hash = DigestAlgorithms.digest(data,
				digest.getMessageDigest(hashAlgorithm));
		cal = Calendar.getInstance();
		byte[] ocsp = null;
		// if (chain.length >= 2 && ocspClient != null) {
		// ocsp = ocspClient.getEncoded((X509Certificate) chain[0],
		// (X509Certificate) chain[1], null);
		// }
		byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, cal, null,
				crlBytes, MakeSignature.CryptoStandard.CMS);
		byte[] extSignature = signature.sign(sh);

		if (extSignature != null) {
			sgn.setExternalDigest(extSignature, null,
					signature.getEncryptionAlgorithm());

			byte[] encodedSig = sgn.getEncodedPKCS7(hash, cal, tsc, ocsp,
					crlBytes, MakeSignature.CryptoStandard.CMS);

			if (estimatedSize + 2 < encodedSig.length)
				throw new IOException("Not enough space");

			byte[] paddedSig = new byte[estimatedSize];
			System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);

			PdfDictionary dic2 = new PdfDictionary();
			dic2.put(PdfName.CONTENTS,
					new PdfString(paddedSig).setHexWriting(true));
			appearance.close(dic2);
		}
		// System.out.println("[MakeSignature-signDetached] end signdetach");

		*//******************************//*

		System.out.println("[UtilFuncs-sign] after signDetached");
		return ((MyPdfSigner) signature).getDataToSignSendClient();
	}

	public byte[] attachSignToFilePdf(byte[] signClient) {
		byte[] extSignature = signClient;

		if (extSignature != null) {
			sgn.setExternalDigest(extSignature, null,
					signature.getEncryptionAlgorithm());

			byte[] encodedSig = sgn.getEncodedPKCS7(hash, cal, tsc, null,
					null, MakeSignature.CryptoStandard.CMS);

			if (estimatedSize + 2 < encodedSig.length)
				throw new IOException("Not enough space");

			byte[] paddedSig = new byte[estimatedSize];
			System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);

			PdfDictionary dic2 = new PdfDictionary();
			dic2.put(PdfName.CONTENTS,
					new PdfString(paddedSig).setHexWriting(true));
			appearance.close(dic2);
		}
	}

	public byte[] getStreamByteOfFilePdf(String name) {

		String filePath = FOLDER_PROCESS + name + "signed.pdf";
		InputStream is = null;
		try {
			is = new BufferedInputStream(new FileInputStream(filePath));
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		try {
			while (is.available() > 0) {
				bos.write(is.read());
			}
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		byte[] byteArray = bos.toByteArray();
		return byteArray;
	}

	private TSAClient getTimeStampClient(String url, String username,
			String password) {
		return new TSAClientBouncyCastle(url, username, password);
	}

	public List<Certificate> getCertChainFromBytes(byte[] certsByte) {
		Security.addProvider(new BouncyCastleProvider());
		List<Certificate> listCert = new ArrayList<Certificate>();
		Certificate cert = null;
		String regex = "544F4D494341425249444745";
		String str_byte = DatatypeConverter.printHexBinary(certsByte);
		String[] str_certs = str_byte.split(regex);
		for (int i = 0; i < str_certs.length; i++) {
			try {
				CertificateFactory cf = CertificateFactory.getInstance("X.509",
						"BC");
				byte[] a = DatatypeConverter.parseHexBinary(str_certs[i]);
				cert = cf.generateCertificate(new ByteArrayInputStream(
						DatatypeConverter.parseHexBinary(str_certs[i])));

				listCert.add(cert);
			} catch (CertificateException e) {
				System.out
						.println("[UtilFuncs-getCertChainFromBytes] exception1 ");
				e.printStackTrace();
			} catch (NoSuchProviderException e) {
				System.out
						.println("[UtilFuncs-getCertChainFromBytes] exception2 ");
				e.printStackTrace();
			}
		}
		return listCert;
	}

	public Collection<byte[]> processCrl(Certificate cert,
			Collection<CrlClient> crlList) {
		if (crlList == null)
			return null;
		ArrayList<byte[]> crlBytes = new ArrayList<byte[]>();
		for (CrlClient cc : crlList) {
			if (cc == null)
				continue;
			LOGGER.info("Processing " + cc.getClass().getName());
			Collection<byte[]> b = cc.getEncoded((X509Certificate) cert, null);
			if (b == null)
				continue;
			crlBytes.addAll(b);
		}
		if (crlBytes.isEmpty())
			return null;
		else
			return crlBytes;
	}*/

}