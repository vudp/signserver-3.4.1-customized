/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.common;

import org.apache.log4j.Logger;

/**
 *
 * @author mobileid
 */
public class LocalService implements EndpointInterface {

    private static final Logger LOG = Logger.getLogger(LocalService.class);

    public byte[] downloadCrl(String crlUrl, int endpointConfigId) {
        return LocalServiceUtils.downloadCrl(crlUrl);
    }

    public EndpointServiceResp checkOcsp(String channelName, String user, byte[] ocspData, String ocspUrl, int ocspRetry, int endpointConfigId, int trustedhubTransId) {
        EndpointServiceResp endpointServiceResp = new EndpointServiceResp();
        endpointServiceResp.setResponseData(LocalServiceUtils.checkOcsp(ocspUrl, ocspData));
        endpointServiceResp.setEndpointId(-1);
        return endpointServiceResp;
    }

    public EndpointServiceResp sendEmail(String channelName, String user, String email, String subject, String content, String properties, int endpointConfigId, int trustedhubTransId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public EndpointServiceResp sendEmailNoLogging(String channelName, String user, String email, String subject, String content, String properties, int endpointConfigId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public EndpointServiceResp sendEmailNoLogging(String channelName, String user, String email, String subject, String content, byte[] attachment, String fileName, String properties, int endpointConfigId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public EndpointServiceResp sendSms(String channelName, String user, String phoneNo, String content, String properties, int endpointConfigId, int trustedhubTransId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public EndpointServiceResp sendSmsNoLogging(String channelName, String user, String phoneNo, String content, String properties, int endpointConfigId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public EndpointServiceResponse getRemoteFile(String channelName, String user, String externalStorage, String properties, String fileId, int endpointConfigId, int trustedhubTransId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public EndpointServiceResponse setRemoteFile(String channelName, String user, String externalStorage, String properties, String fileId, byte[] signedFile, String fileDisplayValue, String fileMineType, String fileName, String citizenId, String applicationId, String userHandle, int endpointConfigId, int trustedhubTransId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public EndpointServiceResponse getMultiRemoteFile(String channelName, String user, String externalStorage, String properties, String fileId, int endpointConfigId, int trustedhubTransId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public EndpointServiceResponse requestMobileSignature(String channelName, String user, String pkiSim, String vendor, String messageMode, String transactionCode, String signatureFormat, String displayData, byte[] plainSig, String properties, int endpointConfigId, int trustedhubTransId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public EndpointServiceResponse requestMobileSignatureStatus(String channelName, String user, String vendor, String msspId, String authCode, String properties, int endpointConfigId, int trustedhubTransId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public EndpointServiceResponse requestMobileCertificate(String channelName, String user, String pkiSim, String vendor, String transactionCode, String properties, int endpointConfigId, int trustedhubTransId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public EndpointServiceResp getCertificate(String channelName, String user, String subjectDn, String email, String dayPattern, String csr, String properties, int endpointConfigId, Integer trustedhubTransId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public EndpointServiceResp getTSAResponse(String channelName, String user, byte[] tsaData, String properties, int endpointConfigId, int trustedhubTransId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public EndpointServiceResp getU2FRegistrationRequest(String channelName, String user, String appId, String properties, int endpointConfigId, int trustedhubTransId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public EndpointServiceResp getU2FRegistrationResponse(String channelName, String user, String registrationData, String clientData, String sessionId, String properties, int endpointConfigId, int trustedhubTransId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public EndpointServiceResp getU2FSignRequest(String channelName, String user, String appId, String properties, int endpointConfigId, int trustedhubTransId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public EndpointServiceResp getU2FSignResponse(String channelName, String user, String appId, String signatureData, String clientData, String challenge, String sessionId, String properties, int endpointConfigId, int trustedhubTransId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
