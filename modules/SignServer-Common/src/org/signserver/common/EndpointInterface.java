/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.common;

/**
 *
 * @author mobileid
 */
public interface EndpointInterface {
    public byte[] downloadCrl(String crlUrl, int endpointConfigId);
    
    public EndpointServiceResp sendEmail(
            String channelName,
            String user,
            String email,
            String subject,
            String content,
            String properties,
            int endpointConfigId,
            int trustedhubTransId);
    
    public EndpointServiceResp sendEmailNoLogging(
            String channelName,
            String user,
            String email,
            String subject,
            String content,
            String properties,
            int endpointConfigId);
    
    public EndpointServiceResp sendEmailNoLogging(
            String channelName,
            String user,
            String email,
            String subject,
            String content,
            byte[] attachment,
            String fileName,
            String properties,
            int endpointConfigId);
    
    public EndpointServiceResp sendSms(
            String channelName, 
            String user,
            String phoneNo, 
            String content, 
            String properties, 
            int endpointConfigId, 
            int trustedhubTransId);
    
    public EndpointServiceResp sendSmsNoLogging(
            String channelName, 
            String user,
            String phoneNo, 
            String content, 
            String properties, 
            int endpointConfigId);
    
    public EndpointServiceResponse getRemoteFile(
            String channelName,
            String user, 
            String externalStorage, 
            String properties,
            String fileId, 
            int endpointConfigId, 
            int trustedhubTransId);
    
    public EndpointServiceResponse setRemoteFile(
            String channelName,
            String user, 
            String externalStorage, 
            String properties,
            String fileId, 
            byte[] signedFile, 
            String fileDisplayValue,
            String fileMineType, 
            String fileName,
            String citizenId, 
            String applicationId, 
            String userHandle, 
            int endpointConfigId, 
            int trustedhubTransId);
    
    public EndpointServiceResponse getMultiRemoteFile(
            String channelName,
            String user, 
            String externalStorage, 
            String properties,
            String fileId, 
            int endpointConfigId, 
            int trustedhubTransId);
    
    public EndpointServiceResponse requestMobileSignature(
            String channelName,
            String user,
            String pkiSim,
            String vendor,
            String messageMode,
            String transactionCode,
            String signatureFormat,
            String displayData,
            byte[] plainSig,
            String properties,
            int endpointConfigId,
            int trustedhubTransId);
    
    public EndpointServiceResponse requestMobileSignatureStatus(
            String channelName,
            String user,
            String vendor,
            String msspId,
            String authCode,
            String properties,
            int endpointConfigId,
            int trustedhubTransId);
    
    public EndpointServiceResponse requestMobileCertificate(
            String channelName,
            String user, 
            String pkiSim, 
            String vendor, 
            String transactionCode,
            String properties, 
            int endpointConfigId, 
            int trustedhubTransId);
    
    public EndpointServiceResp checkOcsp(
            String channelName, 
            String user,
            byte[] ocspData, 
            String ocspUrl, 
            int ocspRetry, 
            int endpointConfigId, 
            int trustedhubTransId);
    
    public EndpointServiceResp getCertificate(
            String channelName, 
            String user,
            String subjectDn, 
            String email, 
            String dayPattern, 
            String csr, 
            String properties, 
            int endpointConfigId, 
            Integer trustedhubTransId);
    
    public EndpointServiceResp getTSAResponse(
            String channelName, 
            String user,
            byte[] tsaData,
            String properties,
            int endpointConfigId,
            int trustedhubTransId);
    
    public EndpointServiceResp getU2FRegistrationRequest(
            String channelName, 
            String user,
            String appId, 
            String properties, 
            int endpointConfigId, 
            int trustedhubTransId);
    
    public EndpointServiceResp getU2FRegistrationResponse(
            String channelName, 
            String user,
            String registrationData, 
            String clientData, 
            String sessionId, 
            String properties, 
            int endpointConfigId, 
            int trustedhubTransId);
    
    public EndpointServiceResp getU2FSignRequest(
            String channelName, 
            String user,
            String appId, 
            String properties, 
            int endpointConfigId, 
            int trustedhubTransId);
    
    public EndpointServiceResp getU2FSignResponse(
            String channelName, 
            String user,
            String appId, 
            String signatureData, 
            String clientData, 
            String challenge, 
            String sessionId, 
            String properties, 
            int endpointConfigId, 
            int trustedhubTransId);
}
