package org.signserver.common;

import vn.mobile_id.endpoint.service.datatype.*;
import vn.mobile_id.endpoint.service.datatype.params.*;
import vn.mobile_id.endpoint.client.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonGenerator;

import org.signserver.common.dbdao.*;
import org.signserver.common.util.*;
import org.apache.log4j.Logger;

import java.io.ByteArrayInputStream;
import java.util.*;

public class EndpointService implements EndpointInterface {

    private final static String FUNCTION_SENDEMAIL = "sendEmail";
    private final static String FUNCTION_SENDEMAILNOLOGGING = "sendEmailNoLogging";
    private final static String FUNCTION_SENDSMS = "sendSms";
    private final static String FUNCTION_SENDSMSNOLOGGING = "sendSmsNoLogging";
    private final static String FUNCTION_PROCESSREMOTEFILE = "processRemoteFile";
    private final static String FUNCTION_REQUESTMOBILESIGNATURE = "requestMobileSignature";
    private final static String FUNCTION_REQUESTMOBILESIGNATURESTATUS = "requestMobileSignatureStatus";
    private final static String FUNCTION_REQUESTMOBILECERTIFICATE = "requestMobileCertificate";
    private final static String FUNCTION_DOWNLOADCRL = "downloadCrl";
    private final static String FUNCTION_CHECKOCSP = "checkOcsp";
    private final static String FUNCTION_GETCERTIFICATE = "getCertificate";
    private final static String FUNCTION_GETTSARESPONSE = "getTSAResponse";
    private final static String FUNCTION_U2FVALIDATOR = "u2fValidator";
    private final static String PROPERTY_JSON_FILEDATA = "fileData";
    private final static String PROPERTY_JSON_CRLDATA = "crlData";
    private final static String PROPERTY_JSON_OCSPDATA = "ocspData";
    private final static String PROPERTY_JSON_TSA_REQ = "tsaEncodedRequest";
    private final static String PROPERTY_JSON_TSA_RESP = "tsaResponse";
    private final static Logger LOG = Logger.getLogger(EndpointService.class);
    private static EndpointService instance;

    public static EndpointService getInstance() {
        if (instance == null) {
            instance = new EndpointService();
        }
        return instance;
    }

    private EndpointService() {
    }

    public byte[] downloadCrl(String crlUrl, int endpointConfigId) {
        String payload = null;
        byte[] crlData = null;
        try {
            // get endpoint info
            List<EndPointConfig> epc = DBConnector.getInstances().getEndPointConfig();
            EndPointConfig endPointConfig = new EndPointConfig();
            for (int i = 0; i < epc.size(); i++) {
                if (epc.get(i).getEndPointConfigID() == endpointConfigId) {
                    endPointConfig = epc.get(i);
                    break;
                }
            }

            Request request = new Request();
            request.setAction(FUNCTION_DOWNLOADCRL);

            CrlParams crlParams = new CrlParams();
            crlParams.setCrlUrl(crlUrl);

            request.setCrlParams(crlParams);

            ObjectMapper op = new ObjectMapper();

            payload = op.writeValueAsString(request);
            Endpoint ep = new Endpoint(endPointConfig.getUrl());
            ep.setKeyID(endPointConfig.getKeyID());
            ep.setAppID(endPointConfig.getAppID());
            ep.setKeyValue(endPointConfig.getKeyValue());
            ep.setClientIP(endPointConfig.getHostname());

            String respPayload = ep.call(payload);
            Response response = op.readValue(respPayload, Response.class);

            if (response.getStatus().getResponseCode() == 0) {
                LOG.info("Crl has been downloaded from " + crlUrl);
                crlData = response.getCrlParams().getCrlData();
            } else {
                LOG.error("Error while downloading crl. Details: "
                        + response.getStatus().getMessageDetails());
            }

        } catch (Exception e) {
            LOG.error("Error while calling endpoint service. Details: "+e.toString());
        }
        return crlData;
    }

    public EndpointServiceResp sendEmail(
            String channelName,
            String user,
            String email,
            String subject,
            String content,
            String properties,
            int endpointConfigId,
            int trustedhubTransId) {
        String payload = null;
        int endpointId = -1;
        int responseCode = -1;
        try {
            Properties databasePros = new Properties();
            databasePros.load(new ByteArrayInputStream(properties.getBytes()));

            HashMap<String, String> connProperties = new HashMap<String, String>();

            Enumeration em = databasePros.keys();
            while (em.hasMoreElements()) {
                String k = (String) em.nextElement();
                String v = databasePros.getProperty(k);
                connProperties.put(k, v);
            }

            ConnectionParams connectionParams = new ConnectionParams();
            connectionParams.setConnectionParams(connProperties);

            // get endpoint info
            List<EndPointConfig> epc = DBConnector.getInstances().getEndPointConfig();
            EndPointConfig endPointConfig = new EndPointConfig();
            for (int i = 0; i < epc.size(); i++) {
                if (epc.get(i).getEndPointConfigID() == endpointConfigId) {
                    endPointConfig = epc.get(i);
                    break;
                }
            }

            Request request = new Request();
            request.setAction(FUNCTION_SENDEMAIL);

            EmailParams emailParams = new EmailParams();
            emailParams.setEmailAddress(email);
            emailParams.setEmailSubject(subject);
            emailParams.setEmailContent(content);
            emailParams.setConnectionParams(connectionParams);

            request.setEmailParams(emailParams);

            ObjectMapper op = new ObjectMapper();

            payload = op.writeValueAsString(request);
            Endpoint ep = new Endpoint(endPointConfig.getUrl());
            ep.setKeyID(endPointConfig.getKeyID());
            ep.setAppID(endPointConfig.getAppID());
            ep.setKeyValue(endPointConfig.getKeyValue());
            ep.setClientIP(endPointConfig.getHostname());

            String respPayload = ep.call(payload);
            Response response = op.readValue(respPayload, Response.class);

            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName, user, FUNCTION_SENDEMAIL, null, null, null,
                    email, payload, respPayload, trustedhubTransId);

            if (response.getStatus().getResponseCode() == 0) {
                LOG.info("Email has been sent to " + email);
            } else {
                LOG.error("Failed to send email. Details: "
                        + response.getStatus().getMessageDetails());
            }

            responseCode = response.getStatus().getResponseCode();

        } catch (Exception e) {
            LOG.error("Error while calling endpoint service.");
            e.printStackTrace();
            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName, user, FUNCTION_SENDEMAIL, null, null, null,
                    email, payload, Defines.ERROR_ENDPOINTEXP, trustedhubTransId);
        }
        return new EndpointServiceResp(responseCode, endpointId);
    }

    public EndpointServiceResp sendEmailNoLogging(
            String channelName,
            String user,
            String email,
            String subject,
            String content,
            String properties,
            int endpointConfigId) {
        String payload = null;
        int endpointId = -1;
        int responseCode = -1;
        try {

            Properties databasePros = new Properties();
            databasePros.load(new ByteArrayInputStream(properties.getBytes()));

            HashMap<String, String> connProperties = new HashMap<String, String>();

            Enumeration em = databasePros.keys();
            while (em.hasMoreElements()) {
                String k = (String) em.nextElement();
                String v = databasePros.getProperty(k);
                connProperties.put(k, v);
            }

            ConnectionParams connectionParams = new ConnectionParams();
            connectionParams.setConnectionParams(connProperties);

            // get endpoint info
            List<EndPointConfig> epc = DBConnector.getInstances().getEndPointConfig();
            EndPointConfig endPointConfig = new EndPointConfig();
            for (int i = 0; i < epc.size(); i++) {
                if (epc.get(i).getEndPointConfigID() == endpointConfigId) {
                    endPointConfig = epc.get(i);
                    break;
                }
            }

            Request request = new Request();
            request.setAction(FUNCTION_SENDEMAILNOLOGGING);

            EmailParams emailParams = new EmailParams();
            emailParams.setEmailAddress(email);
            emailParams.setEmailSubject(subject);
            emailParams.setEmailContent(content);
            emailParams.setConnectionParams(connectionParams);

            request.setEmailParams(emailParams);

            ObjectMapper op = new ObjectMapper();

            payload = op.writeValueAsString(request);
            Endpoint ep = new Endpoint(endPointConfig.getUrl());
            ep.setKeyID(endPointConfig.getKeyID());
            ep.setAppID(endPointConfig.getAppID());
            ep.setKeyValue(endPointConfig.getKeyValue());
            ep.setClientIP(endPointConfig.getHostname());

            String respPayload = ep.call(payload);
            Response response = op.readValue(respPayload, Response.class);

            if (response.getStatus().getResponseCode() == 0) {
                LOG.info("Email has been sent to " + email);
            } else {
                LOG.error("Failed to send email. Details: "
                        + response.getStatus().getMessageDetails());
            }

            responseCode = response.getStatus().getResponseCode();

        } catch (Exception e) {
            LOG.error("Error while calling endpoint service.");
            e.printStackTrace();
        }
        return new EndpointServiceResp(responseCode, endpointId);
    }

    public EndpointServiceResp sendEmailNoLogging(
            String channelName,
            String user,
            String email,
            String subject,
            String content,
            byte[] attachment,
            String fileName,
            String properties,
            int endpointConfigId) {
        String payload = null;
        int endpointId = -1;
        int responseCode = -1;
        try {

            Properties databasePros = new Properties();
            databasePros.load(new ByteArrayInputStream(properties.getBytes()));

            HashMap<String, String> connProperties = new HashMap<String, String>();

            Enumeration em = databasePros.keys();
            while (em.hasMoreElements()) {
                String k = (String) em.nextElement();
                String v = databasePros.getProperty(k);
                connProperties.put(k, v);
            }

            ConnectionParams connectionParams = new ConnectionParams();
            connectionParams.setConnectionParams(connProperties);

            // get endpoint info
            List<EndPointConfig> epc = DBConnector.getInstances().getEndPointConfig();
            EndPointConfig endPointConfig = new EndPointConfig();
            for (int i = 0; i < epc.size(); i++) {
                if (epc.get(i).getEndPointConfigID() == endpointConfigId) {
                    endPointConfig = epc.get(i);
                    break;
                }
            }

            Request request = new Request();
            request.setAction(FUNCTION_SENDEMAILNOLOGGING);

            EmailParams emailParams = new EmailParams();
            emailParams.setEmailAddress(email);
            emailParams.setEmailSubject(subject);
            emailParams.setEmailContent(content);
            emailParams.setAttachment(attachment);
            emailParams.setFileName(fileName);
            emailParams.setConnectionParams(connectionParams);

            request.setEmailParams(emailParams);

            ObjectMapper op = new ObjectMapper();

            payload = op.writeValueAsString(request);
            Endpoint ep = new Endpoint(endPointConfig.getUrl());
            ep.setKeyID(endPointConfig.getKeyID());
            ep.setAppID(endPointConfig.getAppID());
            ep.setKeyValue(endPointConfig.getKeyValue());
            ep.setClientIP(endPointConfig.getHostname());

            String respPayload = ep.call(payload);
            Response response = op.readValue(respPayload, Response.class);

            if (response.getStatus().getResponseCode() == 0) {
                LOG.info("Email has been sent to " + email);
            } else {
                LOG.error("Failed to send email. Details: "
                        + response.getStatus().getMessageDetails());
            }

            responseCode = response.getStatus().getResponseCode();

        } catch (Exception e) {
            LOG.error("Error while calling endpoint service.");
            e.printStackTrace();
        }
        return new EndpointServiceResp(responseCode, endpointId);
    }

    public EndpointServiceResp sendSms(
            String channelName,
            String user,
            String phoneNo,
            String content,
            String properties,
            int endpointConfigId,
            int trustedhubTransId) {
        String payload = null;
        int endpointId = -1;
        int responseCode = -1;
        try {

            Properties databasePros = new Properties();
            databasePros.load(new ByteArrayInputStream(properties.getBytes()));

            HashMap<String, String> connProperties = new HashMap<String, String>();

            Enumeration em = databasePros.keys();
            while (em.hasMoreElements()) {
                String k = (String) em.nextElement();
                String v = databasePros.getProperty(k);
                connProperties.put(k, v);
            }

            ConnectionParams connectionParams = new ConnectionParams();
            connectionParams.setConnectionParams(connProperties);

            // get endpoint info
            List<EndPointConfig> epc = DBConnector.getInstances().getEndPointConfig();
            EndPointConfig endPointConfig = new EndPointConfig();
            for (int i = 0; i < epc.size(); i++) {
                if (epc.get(i).getEndPointConfigID() == endpointConfigId) {
                    endPointConfig = epc.get(i);
                    break;
                }
            }

            Request request = new Request();
            request.setAction(FUNCTION_SENDSMS);

            SMSParams smsParams = new SMSParams();
            smsParams.setSmsPhoneNo(phoneNo);
            smsParams.setSmsContent(content);
            smsParams.setConnectionParams(connectionParams);

            request.setSmsParams(smsParams);

            ObjectMapper op = new ObjectMapper();

            payload = op.writeValueAsString(request);
            Endpoint ep = new Endpoint(endPointConfig.getUrl());
            ep.setKeyID(endPointConfig.getKeyID());
            ep.setAppID(endPointConfig.getAppID());
            ep.setKeyValue(endPointConfig.getKeyValue());
            ep.setClientIP(endPointConfig.getHostname());

            String respPayload = ep.call(payload);
            Response response = op.readValue(respPayload, Response.class);

            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName, user, FUNCTION_SENDSMS, null, null, phoneNo,
                    null, payload, respPayload, trustedhubTransId);

            if (response.getStatus().getResponseCode() == 0) {
                LOG.info("Sms has been sent to " + phoneNo);
            } else {
                LOG.error("Failed to send sms. Details: "
                        + response.getStatus().getMessageDetails());
            }

            responseCode = response.getStatus().getResponseCode();

        } catch (Exception e) {
            LOG.error("Error while calling endpoint service.");
            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName, user, FUNCTION_SENDSMS, null, null, phoneNo,
                    null, payload, Defines.ERROR_ENDPOINTEXP, trustedhubTransId);
            e.printStackTrace();
        }
        return new EndpointServiceResp(responseCode, endpointId);
    }

    public EndpointServiceResp sendSmsNoLogging(
            String channelName,
            String user,
            String phoneNo,
            String content,
            String properties,
            int endpointConfigId) {
        String payload = null;
        int endpointId = -1;
        int responseCode = -1;
        try {

            Properties databasePros = new Properties();
            databasePros.load(new ByteArrayInputStream(properties.getBytes()));

            HashMap<String, String> connProperties = new HashMap<String, String>();

            Enumeration em = databasePros.keys();
            while (em.hasMoreElements()) {
                String k = (String) em.nextElement();
                String v = databasePros.getProperty(k);
                connProperties.put(k, v);
            }

            ConnectionParams connectionParams = new ConnectionParams();
            connectionParams.setConnectionParams(connProperties);

            // get endpoint info
            List<EndPointConfig> epc = DBConnector.getInstances().getEndPointConfig();
            EndPointConfig endPointConfig = new EndPointConfig();
            for (int i = 0; i < epc.size(); i++) {
                if (epc.get(i).getEndPointConfigID() == endpointConfigId) {
                    endPointConfig = epc.get(i);
                    break;
                }
            }

            Request request = new Request();
            request.setAction(FUNCTION_SENDSMSNOLOGGING);

            SMSParams smsParams = new SMSParams();
            smsParams.setSmsPhoneNo(phoneNo);
            smsParams.setSmsContent(content);
            smsParams.setConnectionParams(connectionParams);

            request.setSmsParams(smsParams);

            ObjectMapper op = new ObjectMapper();

            payload = op.writeValueAsString(request);
            Endpoint ep = new Endpoint(endPointConfig.getUrl());
            ep.setKeyID(endPointConfig.getKeyID());
            ep.setAppID(endPointConfig.getAppID());
            ep.setKeyValue(endPointConfig.getKeyValue());
            ep.setClientIP(endPointConfig.getHostname());

            String respPayload = ep.call(payload);
            Response response = op.readValue(respPayload, Response.class);

            if (response.getStatus().getResponseCode() == 0) {
                LOG.info("Sms has been sent to " + phoneNo);
            } else {
                LOG.error("Failed to send sms. Details: "
                        + response.getStatus().getMessageDetails());
            }

            responseCode = response.getStatus().getResponseCode();

        } catch (Exception e) {
            LOG.error("Error while calling endpoint service.");
            e.printStackTrace();
        }
        return new EndpointServiceResp(responseCode, endpointId);
    }

    public EndpointServiceResponse getRemoteFile(
            String channelName,
            String user,
            String externalStorage,
            String properties,
            String fileId,
            int endpointConfigId,
            int trustedhubTransId) {
        String payload = null;
        Response response = null;
        int endpointId = -1;
        EndpointServiceResponse endpointResponse = null;
        try {
            // get endpoint info
            List<EndPointConfig> epc = DBConnector.getInstances().getEndPointConfig();
            EndPointConfig endPointConfig = new EndPointConfig();
            for (int i = 0; i < epc.size(); i++) {
                if (epc.get(i).getEndPointConfigID() == endpointConfigId) {
                    endPointConfig = epc.get(i);
                    break;
                }
            }

            Request request = new Request();
            request.setAction(FUNCTION_PROCESSREMOTEFILE);
            RemoteFileReq remoteFileReq = new RemoteFileReq();
            remoteFileReq.setType(externalStorage);
            remoteFileReq.setMethod(RemoteFileReq.METHOD_GET);

            FileParams fileParams = new FileParams();
            fileParams.setFileId(fileId);

            remoteFileReq.setFileParams(fileParams);

            Properties databasePros = new Properties();
            databasePros.load(new ByteArrayInputStream(properties.getBytes()));

            HashMap<String, String> connProperties = new HashMap<String, String>();

            Enumeration em = databasePros.keys();
            while (em.hasMoreElements()) {
                String k = (String) em.nextElement();
                String v = databasePros.getProperty(k);
                connProperties.put(k, v);
            }

            ConnectionParams connectionParams = new ConnectionParams();
            connectionParams.setConnectionParams(connProperties);

            remoteFileReq.setConnectionParams(connectionParams);

            request.setRemoteFileReq(remoteFileReq);

            ObjectMapper op = new ObjectMapper();
            String respPayload = null;

            payload = op.writeValueAsString(request);
            Endpoint ep = new Endpoint(endPointConfig.getUrl());
            ep.setKeyID(endPointConfig.getKeyID());
            ep.setAppID(endPointConfig.getAppID());
            ep.setKeyValue(endPointConfig.getKeyValue());
            ep.setClientIP(endPointConfig.getHostname());

            respPayload = ep.call(payload);
            response = op.readValue(respPayload, Response.class);

            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName,
                    user,
                    FUNCTION_PROCESSREMOTEFILE,
                    fileId,
                    null,
                    null,
                    null,
                    ExtFunc.replaceFileDataInJason(payload,
                    PROPERTY_JSON_FILEDATA),
                    ExtFunc.replaceFileDataInJason(respPayload,
                    PROPERTY_JSON_FILEDATA), trustedhubTransId);

        } catch (Exception e) {
            LOG.error("Error while calling endpoint service.");
            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName,
                    user,
                    FUNCTION_PROCESSREMOTEFILE,
                    fileId,
                    null,
                    null,
                    null,
                    ExtFunc.replaceFileDataInJason(payload,
                    PROPERTY_JSON_FILEDATA), Defines.ERROR_ENDPOINTEXP,
                    trustedhubTransId);
            e.printStackTrace();
        }
        endpointResponse = new EndpointServiceResponse(endpointId, response);
        return endpointResponse;
    }

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
            int trustedhubTransId) {
        String payload = null;
        Response response = null;
        int endpointId = -1;
        EndpointServiceResponse endpointResponse = null;
        try {
            // get endpoint info
            List<EndPointConfig> epc = DBConnector.getInstances().getEndPointConfig();
            EndPointConfig endPointConfig = new EndPointConfig();
            for (int i = 0; i < epc.size(); i++) {
                if (epc.get(i).getEndPointConfigID() == endpointConfigId) {
                    endPointConfig = epc.get(i);
                    break;
                }
            }

            Request request = new Request();
            request.setAction(FUNCTION_PROCESSREMOTEFILE);
            RemoteFileReq remoteFileReq = new RemoteFileReq();
            remoteFileReq.setType(externalStorage);
            remoteFileReq.setMethod(RemoteFileReq.METHOD_SUBMIT);

            FileParams fileParams = new FileParams();
            fileParams.setFileId(fileId);
            fileParams.setFileData(signedFile);
            fileParams.setDisplayValue(fileDisplayValue);
            fileParams.setMimeType(fileMineType);
            fileParams.setFileName(fileName);
            fileParams.setCitizenId(citizenId);
            fileParams.setApplicationId(applicationId);
            fileParams.setUserId(userHandle);

            remoteFileReq.setFileParams(fileParams);

            Properties databasePros = new Properties();
            databasePros.load(new ByteArrayInputStream(properties.getBytes()));

            HashMap<String, String> connProperties = new HashMap<String, String>();

            Enumeration em = databasePros.keys();
            while (em.hasMoreElements()) {
                String k = (String) em.nextElement();
                String v = databasePros.getProperty(k);
                connProperties.put(k, v);
            }

            ConnectionParams connectionParams = new ConnectionParams();
            connectionParams.setConnectionParams(connProperties);

            remoteFileReq.setConnectionParams(connectionParams);

            request.setRemoteFileReq(remoteFileReq);

            ObjectMapper op = new ObjectMapper();

            payload = op.writeValueAsString(request);
            Endpoint ep = new Endpoint(endPointConfig.getUrl());
            ep.setKeyID(endPointConfig.getKeyID());
            ep.setAppID(endPointConfig.getAppID());
            ep.setKeyValue(endPointConfig.getKeyValue());
            ep.setClientIP(endPointConfig.getHostname());

            String respPayload = ep.call(payload);
            response = op.readValue(respPayload, Response.class);

            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName,
                    user,
                    FUNCTION_PROCESSREMOTEFILE,
                    fileId,
                    null,
                    null,
                    null,
                    ExtFunc.replaceFileDataInJason(payload,
                    PROPERTY_JSON_FILEDATA),
                    ExtFunc.replaceFileDataInJason(respPayload,
                    PROPERTY_JSON_FILEDATA), trustedhubTransId);
        } catch (Exception e) {
            LOG.error("Error while calling endpoint service.");
            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName,
                    user,
                    FUNCTION_PROCESSREMOTEFILE,
                    fileId,
                    null,
                    null,
                    null,
                    ExtFunc.replaceFileDataInJason(payload,
                    PROPERTY_JSON_FILEDATA), Defines.ERROR_ENDPOINTEXP,
                    trustedhubTransId);
            e.printStackTrace();
        }
        endpointResponse = new EndpointServiceResponse(endpointId, response);
        return endpointResponse;
    }

    public EndpointServiceResponse getMultiRemoteFile(
            String channelName,
            String user,
            String externalStorage,
            String properties,
            String fileId,
            int endpointConfigId,
            int trustedhubTransId) {
        Response response = null;
        String payload = null;
        int endpointId = -1;
        EndpointServiceResponse endpointResponse = null;
        try {
            // get endpoint info
            List<EndPointConfig> epc = DBConnector.getInstances().getEndPointConfig();
            EndPointConfig endPointConfig = new EndPointConfig();
            for (int i = 0; i < epc.size(); i++) {
                if (epc.get(i).getEndPointConfigID() == endpointConfigId) {
                    endPointConfig = epc.get(i);
                    break;
                }
            }

            Request request = new Request();
            request.setAction(FUNCTION_PROCESSREMOTEFILE);
            RemoteFileReq remoteFileReq = new RemoteFileReq();
            remoteFileReq.setType(externalStorage);
            remoteFileReq.setMethod(RemoteFileReq.METHOD_GET_MULTI);

            String[] fileIds = fileId.split(";");
            List<FileParams> arrayOfFileParams = new ArrayList<FileParams>();

            for (int i = 0; i < fileIds.length; i++) {

                FileParams fileParams = new FileParams();
                fileParams.setFileId(fileIds[i]);

                arrayOfFileParams.add(fileParams);
            }

            remoteFileReq.setArrayOfFileParams(arrayOfFileParams);

            Properties databasePros = new Properties();
            databasePros.load(new ByteArrayInputStream(properties.getBytes()));

            HashMap<String, String> connProperties = new HashMap<String, String>();

            Enumeration em = databasePros.keys();
            while (em.hasMoreElements()) {
                String k = (String) em.nextElement();
                String v = databasePros.getProperty(k);
                connProperties.put(k, v);
            }

            ConnectionParams connectionParams = new ConnectionParams();
            connectionParams.setConnectionParams(connProperties);

            remoteFileReq.setConnectionParams(connectionParams);

            request.setRemoteFileReq(remoteFileReq);

            ObjectMapper op = new ObjectMapper();
            String respPayload = null;

            payload = op.writeValueAsString(request);
            Endpoint ep = new Endpoint(endPointConfig.getUrl());
            ep.setKeyID(endPointConfig.getKeyID());
            ep.setAppID(endPointConfig.getAppID());
            ep.setKeyValue(endPointConfig.getKeyValue());
            ep.setClientIP(endPointConfig.getHostname());

            respPayload = ep.call(payload);
            response = op.readValue(respPayload, Response.class);

            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName,
                    user,
                    FUNCTION_PROCESSREMOTEFILE,
                    fileId,
                    null,
                    null,
                    null,
                    ExtFunc.replaceFileDataInJason(payload,
                    PROPERTY_JSON_FILEDATA),
                    ExtFunc.replaceFileDataInJason(respPayload,
                    PROPERTY_JSON_FILEDATA), trustedhubTransId);

        } catch (Exception e) {
            LOG.error("Error while calling endpoint service.");
            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName,
                    user,
                    FUNCTION_PROCESSREMOTEFILE,
                    fileId,
                    null,
                    null,
                    null,
                    ExtFunc.replaceFileDataInJason(payload,
                    PROPERTY_JSON_FILEDATA), Defines.ERROR_ENDPOINTEXP,
                    trustedhubTransId);
            e.printStackTrace();
        }
        endpointResponse = new EndpointServiceResponse(endpointId, response);
        return endpointResponse;
    }

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
            int trustedhubTransId) {
        Response response = null;
        String payload = null;
        int endpointId = -1;
        EndpointServiceResponse endpointResponse = null;
        try {

            Properties databasePros = new Properties();
            databasePros.load(new ByteArrayInputStream(properties.getBytes()));

            HashMap<String, String> connProperties = new HashMap<String, String>();

            Enumeration em = databasePros.keys();
            while (em.hasMoreElements()) {
                String k = (String) em.nextElement();
                String v = databasePros.getProperty(k);
                connProperties.put(k, v);
            }

            ConnectionParams connectionParams = new ConnectionParams();
            connectionParams.setConnectionParams(connProperties);

            // get endpoint info
            List<EndPointConfig> epc = DBConnector.getInstances().getEndPointConfig();
            EndPointConfig endPointConfig = new EndPointConfig();
            for (int i = 0; i < epc.size(); i++) {
                if (epc.get(i).getEndPointConfigID() == endpointConfigId) {
                    endPointConfig = epc.get(i);
                    break;
                }
            }

            Request request = new Request();
            request.setAction(FUNCTION_REQUESTMOBILESIGNATURE);

            MSSSignatureReq mssSignatureReq = new MSSSignatureReq();
            mssSignatureReq.setMobileNumber(pkiSim);
            mssSignatureReq.setVendor(vendor);
            mssSignatureReq.setMessageMode(messageMode);
            mssSignatureReq.setApTransactionId(transactionCode);
            mssSignatureReq.setSignatureFormat(signatureFormat);
            mssSignatureReq.setDtbd(displayData);
            mssSignatureReq.setDtbs(plainSig);
            mssSignatureReq.setConnectionParams(connectionParams);

            request.setMssSignatureReq(mssSignatureReq);

            ObjectMapper op = new ObjectMapper();

            payload = op.writeValueAsString(request);
            Endpoint ep = new Endpoint(endPointConfig.getUrl());
            ep.setKeyID(endPointConfig.getKeyID());
            ep.setAppID(endPointConfig.getAppID());
            ep.setKeyValue(endPointConfig.getKeyValue());
            ep.setClientIP(endPointConfig.getHostname());

            String respPayload = ep.call(payload);
            response = op.readValue(respPayload, Response.class);

            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName, user, FUNCTION_REQUESTMOBILESIGNATURE, null,
                    null, pkiSim, null, payload, respPayload, trustedhubTransId);

        } catch (Exception e) {
            LOG.error("Error while calling endpoint service.");
            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName, user, FUNCTION_REQUESTMOBILESIGNATURE, null,
                    null, pkiSim, null, payload, Defines.ERROR_ENDPOINTEXP,
                    trustedhubTransId);
            e.printStackTrace();
        }
        endpointResponse = new EndpointServiceResponse(endpointId, response);
        return endpointResponse;
    }

    public EndpointServiceResponse requestMobileSignatureStatus(
            String channelName,
            String user,
            String vendor,
            String msspId,
            String authCode,
            String properties,
            int endpointConfigId,
            int trustedhubTransId) {

        Response response = null;
        String payload = null;
        int endpointId = -1;
        EndpointServiceResponse endpointResponse = null;
        try {

            Properties databasePros = new Properties();
            databasePros.load(new ByteArrayInputStream(properties.getBytes()));

            HashMap<String, String> connProperties = new HashMap<String, String>();

            Enumeration em = databasePros.keys();
            while (em.hasMoreElements()) {
                String k = (String) em.nextElement();
                String v = databasePros.getProperty(k);
                connProperties.put(k, v);
            }

            ConnectionParams connectionParams = new ConnectionParams();
            connectionParams.setConnectionParams(connProperties);

            // get endpoint info
            List<EndPointConfig> epc = DBConnector.getInstances().getEndPointConfig();
            EndPointConfig endPointConfig = new EndPointConfig();
            for (int i = 0; i < epc.size(); i++) {
                if (epc.get(i).getEndPointConfigID() == endpointConfigId) {
                    endPointConfig = epc.get(i);
                    break;
                }
            }

            Request request = new Request();
            request.setAction(FUNCTION_REQUESTMOBILESIGNATURESTATUS);

            MSSStatusReq mssStatusReq = new MSSStatusReq();
            mssStatusReq.setVendor(vendor);
            mssStatusReq.setApTransactionId(ExtFunc.generateApTransId());
            mssStatusReq.setMsspTransactionId(msspId);
            mssStatusReq.setAuthenticationCode(authCode);
            mssStatusReq.setConnectionParams(connectionParams);

            request.setMssStatusReq(mssStatusReq);

            ObjectMapper op = new ObjectMapper();

            payload = op.writeValueAsString(request);
            Endpoint ep = new Endpoint(endPointConfig.getUrl());
            ep.setKeyID(endPointConfig.getKeyID());
            ep.setAppID(endPointConfig.getAppID());
            ep.setKeyValue(endPointConfig.getKeyValue());
            ep.setClientIP(endPointConfig.getHostname());

            String respPayload = ep.call(payload);
            response = op.readValue(respPayload, Response.class);

            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName, user, FUNCTION_REQUESTMOBILESIGNATURESTATUS,
                    null, null, null, null, payload, respPayload, trustedhubTransId);
        } catch (Exception e) {
            LOG.error("Error while calling endpoint service.");
            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName, user, FUNCTION_REQUESTMOBILESIGNATURESTATUS,
                    null, null, null, null, payload, Defines.ERROR_ENDPOINTEXP,
                    trustedhubTransId);
            e.printStackTrace();
        }
        endpointResponse = new EndpointServiceResponse(endpointId, response);
        return endpointResponse;
    }

    public EndpointServiceResponse requestMobileCertificate(
            String channelName,
            String user,
            String pkiSim,
            String vendor,
            String transactionCode,
            String properties,
            int endpointConfigId,
            int trustedhubTransId) {
        Response response = null;
        String payload = null;
        int endpointId = -1;
        EndpointServiceResponse endpointResponse = null;
        try {

            Properties databasePros = new Properties();
            databasePros.load(new ByteArrayInputStream(properties.getBytes()));

            HashMap<String, String> connProperties = new HashMap<String, String>();

            Enumeration em = databasePros.keys();
            while (em.hasMoreElements()) {
                String k = (String) em.nextElement();
                String v = databasePros.getProperty(k);
                connProperties.put(k, v);
            }

            ConnectionParams connectionParams = new ConnectionParams();
            connectionParams.setConnectionParams(connProperties);

            // get endpoint info
            List<EndPointConfig> epc = DBConnector.getInstances().getEndPointConfig();
            EndPointConfig endPointConfig = new EndPointConfig();
            for (int i = 0; i < epc.size(); i++) {
                if (epc.get(i).getEndPointConfigID() == endpointConfigId) {
                    endPointConfig = epc.get(i);
                    break;
                }
            }

            Request request = new Request();
            request.setAction(FUNCTION_REQUESTMOBILECERTIFICATE);

            MSSSignatureReq mssSignatureReq = new MSSSignatureReq();
            mssSignatureReq.setMobileNumber(pkiSim);
            mssSignatureReq.setVendor(vendor);
            mssSignatureReq.setApTransactionId(transactionCode);
            mssSignatureReq.setConnectionParams(connectionParams);

            request.setMssSignatureReq(mssSignatureReq);

            ObjectMapper op = new ObjectMapper();

            payload = op.writeValueAsString(request);
            Endpoint ep = new Endpoint(endPointConfig.getUrl());
            ep.setKeyID(endPointConfig.getKeyID());
            ep.setAppID(endPointConfig.getAppID());
            ep.setKeyValue(endPointConfig.getKeyValue());
            ep.setClientIP(endPointConfig.getHostname());

            String respPayload = ep.call(payload);
            response = op.readValue(respPayload, Response.class);

            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName, user, FUNCTION_REQUESTMOBILESIGNATURE, null,
                    null, pkiSim, null, payload, respPayload, trustedhubTransId);

        } catch (Exception e) {
            LOG.error("Error while calling endpoint service.");
            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName, user, FUNCTION_REQUESTMOBILESIGNATURE, null,
                    null, pkiSim, null, payload, Defines.ERROR_ENDPOINTEXP,
                    trustedhubTransId);
            e.printStackTrace();
        }
        endpointResponse = new EndpointServiceResponse(endpointId, response);
        return endpointResponse;
    }

    public EndpointServiceResp checkOcsp(
            String channelName,
            String user,
            byte[] ocspData,
            String ocspUrl,
            int ocspRetry,
            int endpointConfigId,
            int trustedhubTransId) {
        Response response = null;
        String payload = null;
        EndpointServiceResp endpointServiceResp = new EndpointServiceResp();
        int endpointId = -1;
        try {
            // get endpoint info
            List<EndPointConfig> epc = DBConnector.getInstances().getEndPointConfig();
            EndPointConfig endPointConfig = new EndPointConfig();
            for (int i = 0; i < epc.size(); i++) {
                if (epc.get(i).getEndPointConfigID() == endpointConfigId) {
                    endPointConfig = epc.get(i);
                    break;
                }
            }

            Request request = new Request();
            request.setAction(FUNCTION_CHECKOCSP);

            OcspParams ocspParams = new OcspParams();
            ocspParams.setOcspUrl(ocspUrl);
            ocspParams.setOcspData(ocspData);
            ocspParams.setOcspRetry(ocspRetry);

            request.setOcspParams(ocspParams);

            ObjectMapper op = new ObjectMapper();

            payload = op.writeValueAsString(request);
            Endpoint ep = new Endpoint(endPointConfig.getUrl());
            ep.setKeyID(endPointConfig.getKeyID());
            ep.setAppID(endPointConfig.getAppID());
            ep.setKeyValue(endPointConfig.getKeyValue());
            ep.setClientIP(endPointConfig.getHostname());

            String respPayload = ep.call(payload);
            response = op.readValue(respPayload, Response.class);

            if (response.getStatus().getResponseCode() == 0) {
                endpointServiceResp.setResponseData(response.getOcspParams().getOcspData());
            } else {
                LOG.error("Error while checking ocsp status");
                endpointServiceResp.setResponseData(null);
            }

            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName,
                    user,
                    FUNCTION_CHECKOCSP,
                    null,
                    null,
                    null,
                    null,
                    ExtFunc.replaceFileDataInJason(payload,
                    PROPERTY_JSON_OCSPDATA),
                    ExtFunc.replaceFileDataInJason(respPayload,
                    PROPERTY_JSON_OCSPDATA), trustedhubTransId);
        } catch (Exception e) {
            LOG.error("Error while calling endpoint service. Details: "+e.toString());
            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName,
                    user,
                    FUNCTION_CHECKOCSP,
                    null,
                    null,
                    null,
                    null,
                    ExtFunc.replaceFileDataInJason(payload,
                    PROPERTY_JSON_OCSPDATA), Defines.ERROR_ENDPOINTEXP,
                    trustedhubTransId);
        }
        endpointServiceResp.setEndpointId(endpointId);
        return endpointServiceResp;
    }

    public EndpointServiceResp getCertificate(
            String channelName,
            String user,
            String subjectDn,
            String email,
            String dayPattern,
            String csr,
            String properties,
            int endpointConfigId,
            Integer trustedhubTransId) {
        String payload = null;
        int endpointId = -1;
        int responseCode = -1;
        try {

            Properties databasePros = new Properties();
            databasePros.load(new ByteArrayInputStream(properties.getBytes()));

            HashMap<String, String> connProperties = new HashMap<String, String>();

            Enumeration em = databasePros.keys();
            while (em.hasMoreElements()) {
                String k = (String) em.nextElement();
                String v = databasePros.getProperty(k);
                connProperties.put(k, v);
            }

            ConnectionParams connectionParams = new ConnectionParams();
            connectionParams.setConnectionParams(connProperties);

            // get endpoint info
            List<EndPointConfig> epc = DBConnector.getInstances().getEndPointConfig();
            EndPointConfig endPointConfig = new EndPointConfig();
            for (int i = 0; i < epc.size(); i++) {
                if (epc.get(i).getEndPointConfigID() == endpointConfigId) {
                    endPointConfig = epc.get(i);
                    break;
                }
            }

            Request request = new Request();
            request.setAction(FUNCTION_GETCERTIFICATE);

            CertificateReq certificateReq = new CertificateReq();

            certificateReq.setCsr(csr);
            certificateReq.setDayPattern(dayPattern);
            certificateReq.setEmail(email);
            certificateReq.setSubjectDn(subjectDn);
            certificateReq.setUserId(user);
            certificateReq.setConnectionParams(connectionParams);

            request.setCertificateReq(certificateReq);


            ObjectMapper op = new ObjectMapper();
            op.getFactory().configure(JsonGenerator.Feature.ESCAPE_NON_ASCII, true);
            payload = op.writeValueAsString(request);
            Endpoint ep = new Endpoint(endPointConfig.getUrl());
            ep.setKeyID(endPointConfig.getKeyID());
            ep.setAppID(endPointConfig.getAppID());
            ep.setKeyValue(endPointConfig.getKeyValue());
            ep.setClientIP(endPointConfig.getHostname());

            String respPayload = ep.call(payload);
            Response response = op.readValue(respPayload, Response.class);

            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName, user, FUNCTION_GETCERTIFICATE, null, null, null,
                    null, payload, respPayload, trustedhubTransId);

            if (response.getStatus().getResponseCode() == 0) {
                EndpointServiceResp endpointServiceResp = new EndpointServiceResp();
                endpointServiceResp.setEndpointId(endpointId);
                endpointServiceResp.setResponseCode(response.getStatus().getResponseCode());
                endpointServiceResp.setResponseData(response.getCertificateResp().getCertificate().getBytes());
                return endpointServiceResp;
            } else {
                LOG.error("Failed to get certificate. Details: "
                        + response.getStatus().getMessageDetails());
            }

            responseCode = response.getStatus().getResponseCode();

        } catch (Exception e) {
            LOG.error("Error while calling endpoint service.");
            e.printStackTrace();
            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName, user, FUNCTION_GETCERTIFICATE, null, null, null,
                    email, payload, Defines.ERROR_ENDPOINTEXP, trustedhubTransId);
        }
        return new EndpointServiceResp(responseCode, endpointId);
    }

    public EndpointServiceResp getTSAResponse(
            String channelName,
            String user,
            byte[] tsaData,
            String properties,
            int endpointConfigId,
            int trustedhubTransId) {
        String payload = null;
        int endpointId = -1;
        int responseCode = -1;
        try {

            Properties databasePros = new Properties();
            databasePros.load(new ByteArrayInputStream(properties.getBytes()));

            HashMap<String, String> connProperties = new HashMap<String, String>();

            Enumeration em = databasePros.keys();
            while (em.hasMoreElements()) {
                String k = (String) em.nextElement();
                String v = databasePros.getProperty(k);
                connProperties.put(k, v);
            }

            ConnectionParams connectionParams = new ConnectionParams();
            connectionParams.setConnectionParams(connProperties);

            // get endpoint info
            List<EndPointConfig> epc = DBConnector.getInstances().getEndPointConfig();
            EndPointConfig endPointConfig = new EndPointConfig();
            for (int i = 0; i < epc.size(); i++) {
                if (epc.get(i).getEndPointConfigID() == endpointConfigId) {
                    endPointConfig = epc.get(i);
                    break;
                }
            }

            Request request = new Request();
            request.setAction(FUNCTION_GETTSARESPONSE);

            TSAParams tsaParams = new TSAParams();
            tsaParams.setConnectionParams(connectionParams);
            tsaParams.setTsaEncodedRequest(tsaData);

            request.setTsaParams(tsaParams);


            ObjectMapper op = new ObjectMapper();

            payload = op.writeValueAsString(request);
            Endpoint ep = new Endpoint(endPointConfig.getUrl());
            ep.setKeyID(endPointConfig.getKeyID());
            ep.setAppID(endPointConfig.getAppID());
            ep.setKeyValue(endPointConfig.getKeyValue());
            ep.setClientIP(endPointConfig.getHostname());

            String respPayload = ep.call(payload);
            Response response = op.readValue(respPayload, Response.class);

            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName, user, FUNCTION_GETTSARESPONSE, null, null, null,
                    null, ExtFunc.replaceFileDataInJason(payload,
                    PROPERTY_JSON_TSA_REQ), ExtFunc.replaceFileDataInJason(respPayload,
                    PROPERTY_JSON_TSA_RESP), trustedhubTransId);

            if (response.getStatus().getResponseCode() == 0) {
                EndpointServiceResp endpointServiceResp = new EndpointServiceResp();
                endpointServiceResp.setEndpointId(endpointId);
                endpointServiceResp.setResponseCode(response.getStatus().getResponseCode());
                endpointServiceResp.setResponseData(response.getTsaParams().getTsaResponse());
                return endpointServiceResp;
            } else {
                LOG.error("Failed to get TSA response. Details: "
                        + response.getStatus().getMessageDetails());
            }
            responseCode = response.getStatus().getResponseCode();
        } catch (Exception e) {
            LOG.error("Error while calling endpoint service.");
            e.printStackTrace();
            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName, user, FUNCTION_GETTSARESPONSE, null, null, null,
                    null, payload, Defines.ERROR_ENDPOINTEXP, trustedhubTransId);
        }
        return new EndpointServiceResp(responseCode, endpointId);
    }

    public EndpointServiceResp getU2FRegistrationRequest(
            String channelName,
            String user,
            String appId,
            String properties,
            int endpointConfigId,
            int trustedhubTransId) {
        String payload = null;
        int endpointId = -1;
        int responseCode = -1;
        try {

            Properties databasePros = new Properties();
            databasePros.load(new ByteArrayInputStream(properties.getBytes()));

            HashMap<String, String> connProperties = new HashMap<String, String>();

            Enumeration em = databasePros.keys();
            while (em.hasMoreElements()) {
                String k = (String) em.nextElement();
                String v = databasePros.getProperty(k);
                connProperties.put(k, v);
            }

            ConnectionParams connectionParams = new ConnectionParams();
            connectionParams.setConnectionParams(connProperties);

            // get endpoint info
            List<EndPointConfig> epc = DBConnector.getInstances().getEndPointConfig();
            EndPointConfig endPointConfig = new EndPointConfig();
            for (int i = 0; i < epc.size(); i++) {
                if (epc.get(i).getEndPointConfigID() == endpointConfigId) {
                    endPointConfig = epc.get(i);
                    break;
                }
            }

            Request request = new Request();
            request.setAction(FUNCTION_U2FVALIDATOR);

            U2FReq u2fReq = new U2FReq();
            u2fReq.setMethod(U2FReq.U2F_METHOD_REG_REQ);
            u2fReq.setUsername(user);
            u2fReq.setAppId(appId);
            u2fReq.setConnectionParams(connectionParams);

            request.setU2fReq(u2fReq);


            ObjectMapper op = new ObjectMapper();

            payload = op.writeValueAsString(request);
            Endpoint ep = new Endpoint(endPointConfig.getUrl());
            ep.setKeyID(endPointConfig.getKeyID());
            ep.setAppID(endPointConfig.getAppID());
            ep.setKeyValue(endPointConfig.getKeyValue());
            ep.setClientIP(endPointConfig.getHostname());

            String respPayload = ep.call(payload);
            Response response = op.readValue(respPayload, Response.class);

            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName, user, FUNCTION_U2FVALIDATOR, null, null, null,
                    null, payload, respPayload, trustedhubTransId);

            if (response.getStatus().getResponseCode() == 0) {
                EndpointServiceResp endpointServiceResp = new EndpointServiceResp();
                endpointServiceResp.setEndpointId(endpointId);
                endpointServiceResp.setResponseCode(response.getStatus().getResponseCode());
                endpointServiceResp.setResponseJsonData(response.getU2fResp().getJsonResponse());
                return endpointServiceResp;
            } else {
                LOG.error("Failed to get U2F response. Details: "
                        + response.getStatus().getMessageDetails());
            }
            responseCode = response.getStatus().getResponseCode();
        } catch (Exception e) {
            LOG.error("Error while calling endpoint service.");
            e.printStackTrace();
            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName, user, FUNCTION_U2FVALIDATOR, null, null, null,
                    null, payload, Defines.ERROR_ENDPOINTEXP, trustedhubTransId);
        }
        return new EndpointServiceResp(responseCode, endpointId);
    }

    public EndpointServiceResp getU2FRegistrationResponse(
            String channelName,
            String user,
            String registrationData,
            String clientData,
            String sessionId,
            String properties,
            int endpointConfigId,
            int trustedhubTransId) {
        String payload = null;
        int endpointId = -1;
        int responseCode = -1;
        try {

            Properties databasePros = new Properties();
            databasePros.load(new ByteArrayInputStream(properties.getBytes()));

            HashMap<String, String> connProperties = new HashMap<String, String>();

            Enumeration em = databasePros.keys();
            while (em.hasMoreElements()) {
                String k = (String) em.nextElement();
                String v = databasePros.getProperty(k);
                connProperties.put(k, v);
            }

            ConnectionParams connectionParams = new ConnectionParams();
            connectionParams.setConnectionParams(connProperties);

            // get endpoint info
            List<EndPointConfig> epc = DBConnector.getInstances().getEndPointConfig();
            EndPointConfig endPointConfig = new EndPointConfig();
            for (int i = 0; i < epc.size(); i++) {
                if (epc.get(i).getEndPointConfigID() == endpointConfigId) {
                    endPointConfig = epc.get(i);
                    break;
                }
            }

            Request request = new Request();
            request.setAction(FUNCTION_U2FVALIDATOR);

            U2FReq u2fReq = new U2FReq();
            u2fReq.setMethod(U2FReq.U2F_METHOD_REG_RESP);
            u2fReq.setClientData(clientData);
            u2fReq.setRegistrationData(registrationData);
            u2fReq.setSessionId(sessionId);
            u2fReq.setConnectionParams(connectionParams);

            request.setU2fReq(u2fReq);


            ObjectMapper op = new ObjectMapper();

            payload = op.writeValueAsString(request);
            Endpoint ep = new Endpoint(endPointConfig.getUrl());
            ep.setKeyID(endPointConfig.getKeyID());
            ep.setAppID(endPointConfig.getAppID());
            ep.setKeyValue(endPointConfig.getKeyValue());
            ep.setClientIP(endPointConfig.getHostname());

            String respPayload = ep.call(payload);
            Response response = op.readValue(respPayload, Response.class);

            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName, user, FUNCTION_U2FVALIDATOR, null, null, null,
                    null, payload, respPayload, trustedhubTransId);

            if (response.getStatus().getResponseCode() == 0) {
                EndpointServiceResp endpointServiceResp = new EndpointServiceResp();
                endpointServiceResp.setEndpointId(endpointId);
                endpointServiceResp.setResponseCode(response.getStatus().getResponseCode());
                endpointServiceResp.setResponseJsonData(response.getU2fResp().getJsonResponse());
                return endpointServiceResp;
            } else {
                LOG.error("Failed to get U2F response. Details: "
                        + response.getStatus().getMessageDetails());
            }
            responseCode = response.getStatus().getResponseCode();
        } catch (Exception e) {
            LOG.error("Error while calling endpoint service.");
            e.printStackTrace();
            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName, user, FUNCTION_U2FVALIDATOR, null, null, null,
                    null, payload, Defines.ERROR_ENDPOINTEXP, trustedhubTransId);
        }
        return new EndpointServiceResp(responseCode, endpointId);
    }

    public EndpointServiceResp getU2FSignRequest(
            String channelName,
            String user,
            String appId,
            String properties,
            int endpointConfigId,
            int trustedhubTransId) {
        String payload = null;
        int endpointId = -1;
        int responseCode = -1;
        try {

            Properties databasePros = new Properties();
            databasePros.load(new ByteArrayInputStream(properties.getBytes()));

            HashMap<String, String> connProperties = new HashMap<String, String>();

            Enumeration em = databasePros.keys();
            while (em.hasMoreElements()) {
                String k = (String) em.nextElement();
                String v = databasePros.getProperty(k);
                connProperties.put(k, v);
            }

            ConnectionParams connectionParams = new ConnectionParams();
            connectionParams.setConnectionParams(connProperties);

            // get endpoint info
            List<EndPointConfig> epc = DBConnector.getInstances().getEndPointConfig();
            EndPointConfig endPointConfig = new EndPointConfig();
            for (int i = 0; i < epc.size(); i++) {
                if (epc.get(i).getEndPointConfigID() == endpointConfigId) {
                    endPointConfig = epc.get(i);
                    break;
                }
            }

            Request request = new Request();
            request.setAction(FUNCTION_U2FVALIDATOR);

            U2FReq u2fReq = new U2FReq();
            u2fReq.setMethod(U2FReq.U2F_METHOD_AUTH_REQ);
            u2fReq.setUsername(user);
            u2fReq.setAppId(appId);
            u2fReq.setConnectionParams(connectionParams);

            request.setU2fReq(u2fReq);


            ObjectMapper op = new ObjectMapper();

            payload = op.writeValueAsString(request);
            Endpoint ep = new Endpoint(endPointConfig.getUrl());
            ep.setKeyID(endPointConfig.getKeyID());
            ep.setAppID(endPointConfig.getAppID());
            ep.setKeyValue(endPointConfig.getKeyValue());
            ep.setClientIP(endPointConfig.getHostname());

            String respPayload = ep.call(payload);
            Response response = op.readValue(respPayload, Response.class);

            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName, user, FUNCTION_U2FVALIDATOR, null, null, null,
                    null, payload, respPayload, trustedhubTransId);

            if (response.getStatus().getResponseCode() == 0) {
                EndpointServiceResp endpointServiceResp = new EndpointServiceResp();
                endpointServiceResp.setEndpointId(endpointId);
                endpointServiceResp.setResponseCode(response.getStatus().getResponseCode());
                endpointServiceResp.setResponseJsonData(response.getU2fResp().getJsonResponse());
                return endpointServiceResp;
            } else {
                LOG.error("Failed to get U2F response. Details: "
                        + response.getStatus().getMessageDetails());
            }
            responseCode = response.getStatus().getResponseCode();
        } catch (Exception e) {
            LOG.error("Error while calling endpoint service.");
            e.printStackTrace();
            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName, user, FUNCTION_U2FVALIDATOR, null, null, null,
                    null, payload, Defines.ERROR_ENDPOINTEXP, trustedhubTransId);
        }
        return new EndpointServiceResp(responseCode, endpointId);
    }

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
            int trustedhubTransId) {
        String payload = null;
        int endpointId = -1;
        int responseCode = -1;
        try {

            Properties databasePros = new Properties();
            databasePros.load(new ByteArrayInputStream(properties.getBytes()));

            HashMap<String, String> connProperties = new HashMap<String, String>();

            Enumeration em = databasePros.keys();
            while (em.hasMoreElements()) {
                String k = (String) em.nextElement();
                String v = databasePros.getProperty(k);
                connProperties.put(k, v);
            }

            ConnectionParams connectionParams = new ConnectionParams();
            connectionParams.setConnectionParams(connProperties);

            // get endpoint info
            List<EndPointConfig> epc = DBConnector.getInstances().getEndPointConfig();
            EndPointConfig endPointConfig = new EndPointConfig();
            for (int i = 0; i < epc.size(); i++) {
                if (epc.get(i).getEndPointConfigID() == endpointConfigId) {
                    endPointConfig = epc.get(i);
                    break;
                }
            }

            Request request = new Request();
            request.setAction(FUNCTION_U2FVALIDATOR);

            U2FReq u2fReq = new U2FReq();
            u2fReq.setMethod(U2FReq.U2F_METHOD_AUTH_RESP);
            u2fReq.setClientData(clientData);
            u2fReq.setSignatureData(signatureData);
            u2fReq.setAppId(appId);
            u2fReq.setSessionId(sessionId);
            u2fReq.setChallenge(challenge);
            u2fReq.setConnectionParams(connectionParams);

            request.setU2fReq(u2fReq);


            ObjectMapper op = new ObjectMapper();

            payload = op.writeValueAsString(request);
            Endpoint ep = new Endpoint(endPointConfig.getUrl());
            ep.setKeyID(endPointConfig.getKeyID());
            ep.setAppID(endPointConfig.getAppID());
            ep.setKeyValue(endPointConfig.getKeyValue());
            ep.setClientIP(endPointConfig.getHostname());

            String respPayload = ep.call(payload);
            Response response = op.readValue(respPayload, Response.class);

            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName, user, FUNCTION_U2FVALIDATOR, null, null, null,
                    null, payload, respPayload, trustedhubTransId);

            if (response.getStatus().getResponseCode() == 0) {
                EndpointServiceResp endpointServiceResp = new EndpointServiceResp();
                endpointServiceResp.setEndpointId(endpointId);
                endpointServiceResp.setResponseCode(response.getStatus().getResponseCode());
                endpointServiceResp.setResponseJsonData(response.getU2fResp().getJsonResponse());
                return endpointServiceResp;
            } else {
                LOG.error("Failed to get U2F response. Details: "
                        + response.getStatus().getMessageDetails());
            }
            responseCode = response.getStatus().getResponseCode();
        } catch (Exception e) {
            LOG.error("Error while calling endpoint service.");
            e.printStackTrace();
            endpointId = DBConnector.getInstances().insertEndpointLog(
                    channelName, user, FUNCTION_U2FVALIDATOR, null, null, null,
                    null, payload, Defines.ERROR_ENDPOINTEXP, trustedhubTransId);
        }
        return new EndpointServiceResp(responseCode, endpointId);
    }
}