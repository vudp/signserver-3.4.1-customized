package org.signserver.clientws;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.*;
import java.util.regex.Pattern;

import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebService;
import javax.naming.NamingException;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;
import javax.jws.HandlerChain;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.*;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.CertificateClientCredential;
import org.signserver.server.IClientCredential;
import org.signserver.server.UsernamePasswordClientCredential;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;

import java.io.*;

import org.signserver.clientws.*;
import org.signserver.common.*;
import org.signserver.common.util.*;
import org.signserver.common.dbdao.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.tomicalab.cag360.license.*;

import javax.xml.ws.handler.soap.SOAPMessageContext;

import java.util.Map;

import com.tomicalab.cag360.connector.ws.*;

import vn.mobileid.pkcs11basic.*;

import org.ejbca.util.CertTools;

public class ProcessFileManagement {

	private static final Logger LOG = Logger.getLogger(ProcessFileManagement.class);
	private final Random random = new Random();

	private static final String HTTP_AUTH_BASIC_AUTHORIZATION = "Authorization";

	private WebServiceContext wsContext;

	private IWorkerSession.ILocal workersession;

	public ProcessFileManagement(WebServiceContext wsContext,
			IWorkerSession.ILocal workersession) {
		this.wsContext = wsContext;
		this.workersession = workersession;
	}

	public ProcessFileManagementResp processData(TransactionInfo transInfo, int trustedHubTransId, int agreementStatus, String billCode) {
		String workerIdOrName = Defines.WORKER_FILEPROCESSER;
		String functionName = Defines.WORKER_FILEPROCESSER;
		String sslSubDn = "";
		String sslIseDn = "";
		String sslSnb = "";
		String unsignedData = "";
		String signedData = "";

		String xmlData = transInfo.getXmlData();
		CAGCredential cagCredential = transInfo.getCredentialData();
		byte[] byteData = transInfo.getFileData();

		String username = cagCredential.getUsername();
		String channelName = ExtFunc.getContent(Defines._CHANNEL, xmlData);
		String user = ExtFunc.getContent(Defines._USER, xmlData);
		String idTag = ExtFunc.getContent(Defines._ID, xmlData);


		String action = ExtFunc.getContent(Defines._ACTION, xmlData);

		if (agreementStatus == 1) {
			String pData = ExtFunc.genResponseMessage(Defines.CODE_AGREEMENTNOTEXITS,
					Defines.ERROR_AGREEMENTNOTEXITS, channelName, user, billCode);
			
			ProcessFileManagementResp processFileManagementResp = new ProcessFileManagementResp();
			processFileManagementResp.setResponseCode(Defines.CODE_AGREEMENTNOTEXITS);
			processFileManagementResp.setXmlData(pData);
			processFileManagementResp.setSignedData(null);
			processFileManagementResp.setPreTrustedHubTransId(null);
			return processFileManagementResp;
			
		} else if (agreementStatus == 4 || agreementStatus == 2
				|| agreementStatus == 3 || agreementStatus == 6
				|| agreementStatus == 7) {
			
			String pData = ExtFunc.genResponseMessage(Defines.CODE_CONTRACTSTATUS,
					Defines.ERROR_CONTRACTSTATUS, channelName, user, billCode);
			
			ProcessFileManagementResp processFileManagementResp = new ProcessFileManagementResp();
			processFileManagementResp.setResponseCode(Defines.CODE_CONTRACTSTATUS);
			processFileManagementResp.setXmlData(pData);
			processFileManagementResp.setSignedData(null);
			processFileManagementResp.setPreTrustedHubTransId(null);
			return processFileManagementResp;
			
		} else if (agreementStatus == 5) {
			
			String pData = ExtFunc.genResponseMessage(Defines.CODE_AGREEMENTEXPIRED,
					Defines.ERROR_AGREEMENTEXPIRED, channelName, user, billCode);
			
			ProcessFileManagementResp processFileManagementResp = new ProcessFileManagementResp();
			processFileManagementResp.setResponseCode(Defines.CODE_AGREEMENTEXPIRED);
			processFileManagementResp.setXmlData(pData);
			processFileManagementResp.setSignedData(null);
			processFileManagementResp.setPreTrustedHubTransId(null);
			return processFileManagementResp;
		}
		
		ProcessFileManagementResp resp = null;

		if (action.equals(Defines.FILE_MANAGEMENT_GET)) {
			resp = getSingleFile(transInfo, trustedHubTransId, billCode);
			return resp;
		} else if (action.equals(Defines.FILE_MANAGEMENT_SUBMIT)) {
			resp = submitSingleFile(transInfo, trustedHubTransId, billCode);
			return resp;
		} else {
			// Invalid action
			String pData = ExtFunc.genResponseMessage(
					Defines.CODE_INVALIDACTION,
					Defines.ERROR_INVALIDACTION, channelName, user, billCode);
			
			ProcessFileManagementResp processFileManagementResp = new ProcessFileManagementResp();
			processFileManagementResp.setResponseCode(Defines.CODE_INVALIDACTION);
			processFileManagementResp.setXmlData(pData);
			processFileManagementResp.setSignedData(null);
			processFileManagementResp.setPreTrustedHubTransId(null);
			return processFileManagementResp;
		}
	}

	private ProcessFileManagementResp getSingleFile(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
		String workerIdOrName = "";
		String functionName = "";
		
		String sslSubDn = "";
		String sslIseDn = "";
		String sslSnb = "";
		String unsignedData = "";
		String signedData = "";

		String xmlData = transInfo.getXmlData();
		CAGCredential cagCredential = transInfo.getCredentialData();

		String username = cagCredential.getUsername();
		String channelName = ExtFunc.getContent(Defines._CHANNEL, xmlData);
		String user = ExtFunc.getContent(Defines._USER, xmlData);
		String idTag = ExtFunc.getContent(Defines._ID, xmlData);
		String metaData = ExtFunc.getContent(Defines._METADATA, xmlData);
		String action = ExtFunc.getContent(Defines._ACTION, xmlData);
		String signatureMethod = ExtFunc.getContent(Defines._SIGNATUREMETHOD, xmlData);

		functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
		String fileId = ExtFunc.getContent(Defines._FILEID, xmlData);
		
		workerIdOrName = functionName;

		List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();
		if (!metaData.equals("")) {
			requestMetadata = getMetaData(metaData);
		}
		
		org.signserver.clientws.Metadata metaMethod = new org.signserver.clientws.Metadata(Defines._METHOD, action);
		org.signserver.clientws.Metadata metaUser = new org.signserver.clientws.Metadata(Defines._USER, user);
		org.signserver.clientws.Metadata metaChannel = new org.signserver.clientws.Metadata(Defines._CHANNEL, channelName);
		org.signserver.clientws.Metadata metaTrustedHubTransId = new org.signserver.clientws.Metadata(Defines._TRUSTEDHUBTRANSID, String.valueOf(trustedHubTransId));

		requestMetadata.add(metaMethod);
		requestMetadata.add(metaUser);
		requestMetadata.add(metaChannel);
		requestMetadata.add(metaTrustedHubTransId);

		final int requestId = random.nextInt();
		final int workerId = getWorkerId(workerIdOrName);
		
		byte[] byteData = null;
		
		if (workerId < 1) {
			String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
					Defines.ERROR_NOWORKER, channelName, user, billCode);
			
			ProcessFileManagementResp processFileManagementResp = new ProcessFileManagementResp();
			processFileManagementResp.setResponseCode(Defines.CODE_NOWORKER);
			processFileManagementResp.setXmlData(pData);
			processFileManagementResp.setSignedData(signedData);
			processFileManagementResp.setPreTrustedHubTransId(null);
			return processFileManagementResp;
		}

		final RequestContext requestContext = handleRequestContext(
				requestMetadata, workerId);

		final ProcessRequest req = new GenericSignRequest(requestId, byteData);
		ProcessResponse resp = null;
		try {
			resp = getWorkerSession().process(workerId, req, requestContext);
		} catch (Exception e) {
			LOG.error("Something wrong: " + e.getMessage());
			e.printStackTrace();
			String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
					Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);
			
			ProcessFileManagementResp processFileManagementResp = new ProcessFileManagementResp();
			processFileManagementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
			processFileManagementResp.setXmlData(pData);
			processFileManagementResp.setSignedData(signedData);
			processFileManagementResp.setPreTrustedHubTransId(null);
			return processFileManagementResp;
		}

		if (!(resp instanceof GenericSignResponse)) {
			LOG.error("resp is not a instance of GenericSignResponse");
			String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
					Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);
			
			ProcessFileManagementResp processFileManagementResp = new ProcessFileManagementResp();
			processFileManagementResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
			processFileManagementResp.setXmlData(pData);
			processFileManagementResp.setSignedData(signedData);
			processFileManagementResp.setPreTrustedHubTransId(null);
			return processFileManagementResp;
		} else {
			final GenericSignResponse signResponse = (GenericSignResponse) resp;
			if (signResponse.getRequestID() != requestId) {
				LOG.error("Response ID " + signResponse.getRequestID()
						+ " not matching request ID " + requestId);
				
				String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
						Defines.ERROR_NOTMATCHID, channelName, user, billCode);
				
				ProcessFileManagementResp processFileManagementResp = new ProcessFileManagementResp();
				processFileManagementResp.setResponseCode(Defines.CODE_NOTMATCHID);
				processFileManagementResp.setXmlData(pData);
				processFileManagementResp.setSignedData(signedData);
				processFileManagementResp.setPreTrustedHubTransId(null);
				return processFileManagementResp;
			}

			int responseCode = signResponse.getResponseCode();
			String responseMessage = signResponse.getResponseMessage();

			if (responseCode == Defines.CODE_SUCCESS) {
				if (!License.getInstance().getLicenseType().equals("Unlimited")) {
					DBConnector.getInstances().increaseSuccessTransaction();
				}
				byte[] signedFile = signResponse.getProcessedData();
				
				Properties properties = signResponse.getPropertiesData();
				
				String fileName = StringEscapeUtils.unescapeHtml(properties.getProperty(Defines._FILENAME));
				String mimeType = properties.getProperty(Defines._MIMETYPE);
				
				String pData = ExtFunc.genResponseMessageForFileProcessor(responseCode,
						responseMessage, channelName, user, fileName, mimeType, fileId, billCode);
				
				ProcessFileManagementResp processFileManagementResp = new ProcessFileManagementResp();
				processFileManagementResp.setResponseCode(responseCode);
				processFileManagementResp.setXmlData(pData);
				processFileManagementResp.setSignedData(signedData);
				processFileManagementResp.setFileData(signedFile); // SUCCESS
				processFileManagementResp.setPreTrustedHubTransId(null);
				return processFileManagementResp;
			} else {
				LOG.error("Failed to get file from File Server");
				String pData = ExtFunc.genResponseMessage(responseCode,
						responseMessage, channelName, user, billCode);
				
				ProcessFileManagementResp processFileManagementResp = new ProcessFileManagementResp();
				processFileManagementResp.setResponseCode(responseCode);
				processFileManagementResp.setXmlData(pData);
				processFileManagementResp.setSignedData(null);
				processFileManagementResp.setPreTrustedHubTransId(null);
				return processFileManagementResp;
			}
		}
	}

	private ProcessFileManagementResp submitSingleFile(TransactionInfo transInfo, int trustedHubTransId, String billCode) {
		String workerIdOrName = "";
		String functionName = "";
		
		String sslSubDn = "";
		String sslIseDn = "";
		String sslSnb = "";
		String unsignedData = "";
		String signedData = "";

		String xmlData = transInfo.getXmlData();
		CAGCredential cagCredential = transInfo.getCredentialData();

		String username = cagCredential.getUsername();
		String channelName = ExtFunc.getContent(Defines._CHANNEL, xmlData);
		String user = ExtFunc.getContent(Defines._USER, xmlData);
		String idTag = ExtFunc.getContent(Defines._ID, xmlData);
		String metaData = ExtFunc.getContent(Defines._METADATA, xmlData);
		String action = ExtFunc.getContent(Defines._ACTION, xmlData);
		String signatureMethod = ExtFunc.getContent(Defines._SIGNATUREMETHOD, xmlData);

		functionName = ExtFunc.getContent(Defines._WORKERNAME, xmlData);
		
		workerIdOrName = functionName;
		
		byte[] byteData = transInfo.getFileData();
		
		if(transInfo.getBase64FileData() != null) {
			byteData = DatatypeConverter.parseBase64Binary(transInfo.getBase64FileData());
		}
		
		if(byteData == null) {
			String pData = ExtFunc.genResponseMessage(Defines.CODE_NOBASE64FILE,
					Defines.ERROR_NOBASE64FILE, channelName, user, billCode);
			
			ProcessFileManagementResp processFileManagementResp = new ProcessFileManagementResp();
			processFileManagementResp.setResponseCode(Defines.CODE_NOBASE64FILE);
			processFileManagementResp.setXmlData(pData);
			processFileManagementResp.setSignedData(signedData);
			processFileManagementResp.setPreTrustedHubTransId(null);
			return processFileManagementResp;
		}

		List<org.signserver.clientws.Metadata> requestMetadata = new ArrayList<Metadata>();
		if (!metaData.equals("")) {
			requestMetadata = getMetaData(metaData);
		}
		
		org.signserver.clientws.Metadata metaMethod = new org.signserver.clientws.Metadata(Defines._METHOD, action);
		org.signserver.clientws.Metadata metaUser = new org.signserver.clientws.Metadata(Defines._USER, user);
		org.signserver.clientws.Metadata metaChannel = new org.signserver.clientws.Metadata(Defines._CHANNEL, channelName);
		org.signserver.clientws.Metadata metaTrustedHubTransId = new org.signserver.clientws.Metadata(Defines._TRUSTEDHUBTRANSID, String.valueOf(trustedHubTransId));

		requestMetadata.add(metaMethod);
		requestMetadata.add(metaUser);
		requestMetadata.add(metaChannel);
		requestMetadata.add(metaTrustedHubTransId);

		final int requestId = random.nextInt();
		final int workerId = getWorkerId(workerIdOrName);
		
		if (workerId < 1) {
			String pData = ExtFunc.genResponseMessage(Defines.CODE_NOWORKER,
					Defines.ERROR_NOWORKER, channelName, user, billCode);
			
			ProcessFileManagementResp processFileManagementResp = new ProcessFileManagementResp();
			processFileManagementResp.setResponseCode(Defines.CODE_NOWORKER);
			processFileManagementResp.setXmlData(pData);
			processFileManagementResp.setSignedData(signedData);
			processFileManagementResp.setPreTrustedHubTransId(null);
			return processFileManagementResp;
		}

		final RequestContext requestContext = handleRequestContext(
				requestMetadata, workerId);

		final ProcessRequest req = new GenericSignRequest(requestId, byteData);
		ProcessResponse resp = null;
		try {
			resp = getWorkerSession().process(workerId, req, requestContext);
		} catch (Exception e) {
			LOG.error("Something wrong: " + e.getMessage());
			e.printStackTrace();
			String pData = ExtFunc.genResponseMessage(Defines.CODE_INTERNALSYSTEM,
					Defines.ERROR_INTERNALSYSTEM, channelName, user, billCode);
			
			ProcessFileManagementResp processFileManagementResp = new ProcessFileManagementResp();
			processFileManagementResp.setResponseCode(Defines.CODE_INTERNALSYSTEM);
			processFileManagementResp.setXmlData(pData);
			processFileManagementResp.setSignedData(signedData);
			processFileManagementResp.setPreTrustedHubTransId(null);
			return processFileManagementResp;
		}

		if (!(resp instanceof GenericSignResponse)) {
			LOG.error("resp is not a instance of GenericSignResponse");
			String pData = ExtFunc.genResponseMessage(Defines.CODE_UNEXPECTEDRETURNTYPE,
					Defines.ERROR_UNEXPECTEDRETURNTYPE, channelName, user, billCode);
			
			ProcessFileManagementResp processFileManagementResp = new ProcessFileManagementResp();
			processFileManagementResp.setResponseCode(Defines.CODE_UNEXPECTEDRETURNTYPE);
			processFileManagementResp.setXmlData(pData);
			processFileManagementResp.setSignedData(signedData);
			processFileManagementResp.setPreTrustedHubTransId(null);
			return processFileManagementResp;
		} else {
			final GenericSignResponse signResponse = (GenericSignResponse) resp;
			if (signResponse.getRequestID() != requestId) {
				LOG.error("Response ID " + signResponse.getRequestID()
						+ " not matching request ID " + requestId);
				
				String pData = ExtFunc.genResponseMessage(Defines.CODE_NOTMATCHID,
						Defines.ERROR_NOTMATCHID, channelName, user, billCode);
				
				ProcessFileManagementResp processFileManagementResp = new ProcessFileManagementResp();
				processFileManagementResp.setResponseCode(Defines.CODE_NOTMATCHID);
				processFileManagementResp.setXmlData(pData);
				processFileManagementResp.setSignedData(signedData);
				processFileManagementResp.setPreTrustedHubTransId(null);
				return processFileManagementResp;
			}

			int responseCode = signResponse.getResponseCode();
			String responseMessage = signResponse.getResponseMessage();

			if (responseCode == Defines.CODE_SUCCESS) {
				if (!License.getInstance().getLicenseType().equals("Unlimited")) {
					DBConnector.getInstances().increaseSuccessTransaction();
				}
				
				String newFileId = signResponse.getFileId();
				
				String pData = ExtFunc.genResponseMessage(
						responseCode,
						responseMessage, 
						channelName, 
						user,
						null, // --> fileType
						newFileId,
						null,// --> certificate
						billCode);
				
				ProcessFileManagementResp processFileManagementResp = new ProcessFileManagementResp();
				processFileManagementResp.setResponseCode(responseCode);
				processFileManagementResp.setXmlData(pData);
				processFileManagementResp.setSignedData(null);
				processFileManagementResp.setFileData(null);
				processFileManagementResp.setPreTrustedHubTransId(null);
				return processFileManagementResp;
			} else {
				LOG.error("Failed to submit file from File Server");
				String pData = ExtFunc.genResponseMessage(responseCode,
						responseMessage, channelName, user, billCode);
				
				ProcessFileManagementResp processFileManagementResp = new ProcessFileManagementResp();
				processFileManagementResp.setResponseCode(responseCode);
				processFileManagementResp.setXmlData(pData);
				processFileManagementResp.setSignedData(null);
				processFileManagementResp.setPreTrustedHubTransId(null);
				return processFileManagementResp;
			}
		}
	}

	private int getWorkerId(String workerIdOrName) {
		final int retval;

		if (workerIdOrName.substring(0, 1).matches("\\d")) {
			retval = Integer.parseInt(workerIdOrName);
		} else {
			retval = getWorkerSession().getWorkerId(workerIdOrName);
		}
		return retval;
	}

	private IWorkerSession.ILocal getWorkerSession() {
		if (workersession == null) {
			try {
				workersession = ServiceLocator.getInstance().lookupLocal(
						IWorkerSession.ILocal.class);
			} catch (NamingException e) {
				LOG.error(e);
			}
		}
		return workersession;
	}

	private RequestContext handleRequestContext(
			final List<Metadata> requestMetadata, final int workerId) {
		final HttpServletRequest servletRequest = (HttpServletRequest) wsContext
				.getMessageContext().get(MessageContext.SERVLET_REQUEST);
		String requestIP = ExtFunc.getRequestIP(wsContext);
		X509Certificate clientCertificate = getClientCertificate();
		final RequestContext requestContext = new RequestContext(
				clientCertificate, requestIP);

		IClientCredential credential;

		if (clientCertificate instanceof X509Certificate) {
			final X509Certificate cert = (X509Certificate) clientCertificate;
			//LOG.info("Authentication: certificate");
			credential = new CertificateClientCredential(cert.getSerialNumber()
					.toString(16), cert.getIssuerDN().getName());
		} else {
			// Check is client supplied basic-credentials
			final String authorization = servletRequest
					.getHeader(HTTP_AUTH_BASIC_AUTHORIZATION);
			if (authorization != null) {
				//LOG.info("Authentication: password");

				final String decoded[] = new String(Base64.decode(authorization
						.split("\\s")[1])).split(":", 2);

				credential = new UsernamePasswordClientCredential(decoded[0],
						decoded[1]);
			} else {
				//LOG.info("Authentication: none");
				credential = null;
			}
		}
		requestContext.put(RequestContext.CLIENT_CREDENTIAL, credential);

		final LogMap logMap = LogMap.getInstance(requestContext);

		// Add HTTP specific log entries
		logMap.put(
				IWorkerLogger.LOG_REQUEST_FULLURL,
				servletRequest.getRequestURL().append("?")
						.append(servletRequest.getQueryString()).toString());
		logMap.put(IWorkerLogger.LOG_REQUEST_LENGTH,
				servletRequest.getHeader("Content-Length"));
		logMap.put(IWorkerLogger.LOG_XFORWARDEDFOR,
				servletRequest.getHeader("X-Forwarded-For"));

		logMap.put(IWorkerLogger.LOG_WORKER_NAME,
				getWorkerSession().getCurrentWorkerConfig(workerId)
						.getProperty(ProcessableConfig.NAME));

		if (requestMetadata == null) {
			requestContext.remove(RequestContext.REQUEST_METADATA);
		} else {
			final RequestMetadata metadata = RequestMetadata
					.getInstance(requestContext);
			for (Metadata rmd : requestMetadata) {
				metadata.put(rmd.getName(), rmd.getValue());
			}

			// Special handling of FILENAME
			String fileName = metadata.get(RequestContext.FILENAME);
			if (fileName != null) {
				requestContext.put(RequestContext.FILENAME, fileName);
				logMap.put(IWorkerLogger.LOG_FILENAME, fileName);
			}
		}

		return requestContext;
	}

	private String getIssuerName(String DN) {
		String issuer = DN;
		String issuerName = "";
		String[] pairs = issuer.split(",");
		for (String pair : pairs) {
			String[] paramvalue = pair.split("=");
			if (paramvalue[0].compareTo("CN") == 0
					|| paramvalue[0].compareTo(" CN") == 0) {
				issuerName = paramvalue[1];
				break;
			}
		}

		return issuerName;
	}

	private X509Certificate getClientCertificate() {
		MessageContext msgContext = wsContext.getMessageContext();
		HttpServletRequest request = (HttpServletRequest) msgContext
				.get(MessageContext.SERVLET_REQUEST);
		X509Certificate[] certificates = (X509Certificate[]) request
				.getAttribute("javax.servlet.request.X509Certificate");

		if (certificates != null) {
			return certificates[0];
		}
		return null;
	}
	
	private List<Metadata> getMetaData(String metaData) {
		List<org.signserver.clientws.Metadata> listMD = new ArrayList<org.signserver.clientws.Metadata>();
		try {
			String xmlData = "<MetaData>" + metaData + "</MetaData>";

			DocumentBuilderFactory factory = DocumentBuilderFactory
					.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();
			Document document = builder.parse(new InputSource(new StringReader(
					xmlData)));
			Element rootElement = document.getDocumentElement();

			NodeList list = document.getElementsByTagName("*");
			for (int i = 0; i < list.getLength(); i++) {
				Element element = (Element) list.item(i);
				if (!element.getNodeName().equals("MetaData")) {
					String nodeName = element.getNodeName();
					String nodeContent = element.getTextContent();
					
					if(nodeName.compareTo(Defines._FILENAME) == 0) {
						nodeContent = StringEscapeUtils.escapeHtml(nodeContent);
						LOG.info("Escape unicode fileName");
					}
					
					org.signserver.clientws.Metadata tmp = new org.signserver.clientws.Metadata(
							nodeName, nodeContent);
					listMD.add(tmp);
				}
			}

		} catch (Exception e) {
			listMD = null;
		}
		return listMD;
	}
}