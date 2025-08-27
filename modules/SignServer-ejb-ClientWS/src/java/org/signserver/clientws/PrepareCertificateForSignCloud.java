package org.signserver.clientws;

import org.apache.log4j.Logger;

public class PrepareCertificateForSignCloud {
/*
    private static final Logger LOG = Logger.getLogger(PrepareCertificateForSignCloud.class);
    

    public SignCloudResp processData(SignCloudReq signCloudReq) {

        SignCloudResp signCloudResp = new SignCloudResp();
        try {
            if (signCloudReq == null) {
                LOG.error("signCloudResp cannot be NULL");
                signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
                signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
                return signCloudResp;
            }

            // check CredentialData
            CredentialData credentialData = signCloudReq.getCredentialData();
            if (credentialData == null) {
                LOG.error("credentialData cannot be NULL");
                signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
                signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
                return signCloudResp;
            }

            String username = credentialData.getUsername();
            String password = credentialData.getPassword();
            String signature = credentialData.getSignature();
            String pkcs1Signature = credentialData.getPkcs1Signature();
            String timestamp = credentialData.getTimestamp();

            if (SignCloudUtil.isNullOrEmpty(username)) {
                LOG.error("username cannot be NULL");
                signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
                signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
                return signCloudResp;
            }

            if (SignCloudUtil.isNullOrEmpty(password)) {
                LOG.error("password cannot be NULL");
                signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
                signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
                return signCloudResp;
            }

            if (SignCloudUtil.isNullOrEmpty(signature)) {
                LOG.error("signature cannot be NULL");
                signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
                signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
                return signCloudResp;
            }

            if (SignCloudUtil.isNullOrEmpty(pkcs1Signature)) {
                LOG.error("pkcs1Signature cannot be NULL");
                signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
                signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
                return signCloudResp;
            }

            if (SignCloudUtil.isNullOrEmpty(timestamp)) {
                LOG.error("timestamp cannot be NULL");
                signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
                signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
                return signCloudResp;
            }

            // check relying party
            String relyingParty = signCloudReq.getRelyingParty();
            if (SignCloudUtil.isNullOrEmpty(relyingParty)) {
                LOG.error("relyingParty cannot be NULL");
                signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
                signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
                return signCloudResp;
            }

            //check agreementId
            String agreementId = signCloudReq.getAgreementId();
            if (SignCloudUtil.isNullOrEmpty(agreementId)) {
                LOG.error("agreementId cannot be NULL");
                signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
                signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
                return signCloudResp;
            }

            // check mobileNo
            String mobileNo = signCloudReq.getMobileNo();
            if (SignCloudUtil.isNullOrEmpty(mobileNo)) {
                LOG.error("mobileNo cannot be NULL");
                signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
                signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
                return signCloudResp;
            }

            // check emailAddress
            String emailAddr = signCloudReq.getEmail();
            if (SignCloudUtil.isNullOrEmpty(emailAddr)) {
                LOG.error("emailAddr cannot be NULL");
                signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
                signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
                return signCloudResp;
            }

            // check cert profile
            String certProfile = signCloudReq.getCertificateProfile();
            if (SignCloudUtil.isNullOrEmpty(certProfile)) {
                LOG.error("certProfile cannot be NULL");
                signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
                signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
                return signCloudResp;
            }


            // check cert info
            AgreementDetails agreementDetails = signCloudReq.getAgreementDetails();
            if (agreementDetails == null) {
                LOG.error("agreementDetails cannot be NULL");
                signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
                signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
                return signCloudResp;
            }
            String personalName = agreementDetails.getPersonName();
            String email = agreementDetails.getEmail();
            String locality = agreementDetails.getLocation();
            String stateProvince = agreementDetails.getStateOrProvince();
            String country = agreementDetails.getCountry();

            if (SignCloudUtil.isNullOrEmpty(personalName)
                    || SignCloudUtil.isNullOrEmpty(email)
                    || SignCloudUtil.isNullOrEmpty(locality)
                    || SignCloudUtil.isNullOrEmpty(stateProvince)
                    || SignCloudUtil.isNullOrEmpty(country)) {
                LOG.error("Somes DN atributes cannot be NULL");
                signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_INVALID_PARAMS);
                signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_INVALID_PARAMS);
                return signCloudResp;
            }

            String dn = "CN=" + SignCloudUtil.resolveDNAttribute(personalName)
                    + ",E=" + email
                    + ",L=" + SignCloudUtil.resolveDNAttribute(locality)
                    + ",ST=" + SignCloudUtil.resolveDNAttribute(stateProvince)
                    + ",C=" + country;
            LOG.info("DNString: " + dn);
            // Call ClientWS
            String xmlData = "<Channel>" + relyingParty + "</Channel>\n"
                    + "<User>" + agreementId + "</User>\n"
                    + "<ExternalBillCode>01009090</ExternalBillCode>\n"
                    + "<WorkerName>AgreementHandler</WorkerName>\n"
                    + "<Action>REGISTRATION</Action>\n"
                    + "<Expiration>3650</Expiration>\n"
                    + "\n"
                    + "<IsSPKI>True</IsSPKI>\n"
                    + "<WorkerNameSigning>MultiSigner</WorkerNameSigning>\n"
                    + "<SPKIEmail>" + emailAddr + "</SPKIEmail>\n"
                    + "<SPKISMS>" + mobileNo + "</SPKISMS>\n"
                    + "<SKeyType>PRIVATE</SKeyType>\n"
                    + "<P11Info>TPM</P11Info>\n"
                    + "\n"
                    + "<SPKICertType>Personal</SPKICertType>\n"
                    + "<SPKICertProvider>FPT Certification Authority</SPKICertProvider>\n"
                    + "<SPKIDN>" + dn + "</SPKIDN>\n"
                    + "<SPKICertProfile>365</SPKICertProfile>";

            CAGCredential credential = new CAGCredential();
            credential.setUsername(username);
            credential.setPassword(password);
            credential.setSignature(signature);
            credential.setTimestamp(timestamp);
            credential.setPkcs1Signature(pkcs1Signature);

            TransactionInfo transReq = new TransactionInfo();
            transReq.setXmlData(xmlData);
            transReq.setCredentialData(credential);

            ClientWS clientWS = new ClientWS();
            TransactionInfo transResp = clientWS.processData(transReq);

            signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_SUCCESS);
            signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_SUCCESS);
            return signCloudResp;
        } catch (Exception e) {
            e.printStackTrace();
            signCloudResp.setResponseCode(SignCloudConstant.RESPONSE_CODE_UNEXPECTED_EXCEPTION);
            signCloudResp.setResponseMessage(SignCloudConstant.RESPONSE_MESS_UNEXPECTED_EXCEPTION);
            return signCloudResp;
        }
    }
    */
}