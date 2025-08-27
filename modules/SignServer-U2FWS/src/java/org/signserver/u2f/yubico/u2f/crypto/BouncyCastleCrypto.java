/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package org.signserver.u2f.yubico.u2f.crypto;

import org.signserver.u2f.yubico.u2f.exceptions.U2fBadInputException;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.ECNamedCurveTable;

import org.bouncycastle.math.ec.ECPoint;

import java.security.spec.X509EncodedKeySpec;

import java.security.*;
import java.security.cert.X509Certificate;

public class BouncyCastleCrypto implements Crypto {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    public void checkSignature(X509Certificate attestationCertificate, byte[] signedBytes, byte[] signature)
            throws U2fBadInputException {
        checkSignature(attestationCertificate.getPublicKey(), signedBytes, signature);
    }

    @Override
    public void checkSignature(PublicKey publicKey, byte[] signedBytes, byte[] signature)
            throws U2fBadInputException {
        try {
            Signature ecdsaSignature = Signature.getInstance("SHA256withECDSA");
            ecdsaSignature.initVerify(publicKey);
            ecdsaSignature.update(signedBytes);
            if (!ecdsaSignature.verify(signature)) {
                throw new U2fBadInputException("Signature is invalid");
            }
        } catch (GeneralSecurityException e) { //This should not happen
        	
            throw new RuntimeException(e);
        }
    }

    @Override
    public PublicKey decodePublicKey(byte[] encodedPublicKey) throws U2fBadInputException {
    	Security.addProvider(new BouncyCastleProvider());
        try {
            X9ECParameters curve = SECNamedCurves.getByName("secp256r1");
            ECPoint point;
            try {
                point = curve.getCurve().decodePoint(encodedPublicKey);
            } catch (RuntimeException e) {
                throw new U2fBadInputException("Could not parse user public key", e);
            }
            
            ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            
            ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(point, ecParameterSpec);
            
            KeyFactory keyFac = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
            
            return keyFac.generatePublic(
                    ecPublicKeySpec
            );
        } catch (GeneralSecurityException e) { //This should not happen
        	e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] hash(byte[] bytes) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] hash(String str) {
        return hash(str.getBytes());
    }
}
