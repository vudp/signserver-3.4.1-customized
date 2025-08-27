package org.signserver.socket;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.MessageToMessageDecoder;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.util.concurrent.GlobalEventExecutor;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;

import org.signserver.common.*;
import org.signserver.common.util.*;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.*;

import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebService;
import javax.naming.NamingException;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;
import javax.jws.HandlerChain;

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

import org.signserver.common.*;
import org.signserver.common.util.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import ft.otp.core.api.OTPCore;
import ft.otp.core.api.OTPCoreFactory;
import ft.otp.core.api.Version;
import ft.otp.core.entity.UserInfo;
import ft.otp.core.exception.OTPCoreException;

import org.apache.commons.io.IOUtils;

import javax.xml.ws.handler.soap.SOAPMessageContext;

import com.tomicalab.cag360.cagconnector.ws.*;

/**
 *
 * @author PHUONGVU
 */
public class CAGSocketGateWay extends HttpServlet {
	private static final Logger LOG = Logger.getLogger(CAGSocketGateWay.class);

	private static OTPCore otpcore = null;
	private static boolean isUseContraints = true;
	private static String localWorkerName;
	private static final String HTTP_AUTH_BASIC_AUTHORIZATION = "Authorization";
	private static Properties config = null;
	// @Resource
	// private WebServiceContext wsContext;

	@EJB
	private static IWorkerSession.ILocal workersession;

	private static final Random random = new Random();

	private static final int PORT = Integer.parseInt(System.getProperty("port",
			"14003"));
	private static byte[] NULL = { 0x00 };

	static {
		// LOG.info("New Instance...\n\n\n");
		// Thread start socket server listening
		new Thread(new Runnable() {
			@Override
			public void run() {
				try {
					LOG.info("Clear TPM Request");
					DBConnector.getInstances().Socket_ClearTPMRequest();
					LOG.info("Try to active a signer...");
					if (config == null) {
						config = DBConnector.getInstances()
								.getPropertiesConfig();
					}
					String workerId = config
							.getProperty("tomica_autoactive_signerid");
					if (workerId != null) {
						if(workerId.compareTo("") != 0) {
							String[] Ids = workerId.split(",");
							try {
								for (int i = 0; i < Ids.length; i++) {
									int Id = Integer.valueOf(Ids[i]);
									WorkerConfig signerConfig = getWorkerSession()
											.getCurrentWorkerConfig(
													Integer.valueOf(Id));
									getWorkerSession().activateSigner(
											Integer.valueOf(Id),
											signerConfig.getProperty("PIN"));
								}
							} catch (Exception e) {
								e.printStackTrace();
							}
						}
					}
					LOG.info("Socket deploying and listening on port 14003...");
					EventLoopGroup bossGroup = new NioEventLoopGroup(1);
					EventLoopGroup workerGroup = new NioEventLoopGroup();
					try {
						ServerBootstrap b = new ServerBootstrap();
						b.group(bossGroup, workerGroup)
								.channel(NioServerSocketChannel.class)
								.handler(new LoggingHandler(LogLevel.INFO))
								.childHandler(new SecureChatServerInitializer());

						b.bind(PORT).sync().channel().closeFuture().sync();
					} finally {
						bossGroup.shutdownGracefully();
						workerGroup.shutdownGracefully();
					}

				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}).start();
		// Thread do signing
		new Thread(new Runnable() {
			@Override
			public void run() {
				SocketRequestObject requestObject = null;
				while (true) {
					try {
						requestObject = DBConnector.getInstances()
								.Socket_GetRequest();
						if (requestObject != null) {
							// Co request
							String functionName = "processData";
							String ipClient = Utils.getIPAdress(requestObject
									.getIp());
							String sslSubDn = "TCP Socket";
							String sslIseDn = "TCP Socket";
							String sslSnb = "TCP Socket";
							String xmlData = "";
							String username = "";
							String password = "";
							String timestamp = "";
							String signature = "";
							String pkcs1Signature = "";
							String unsignedData = "";
							String signedData = "";
							byte[] byteData = null;

							byte[] request = requestObject.getRequestData();
							// tpm free
							byte[] raw_xmlData = Utils.getBytesValue(request,
									Utils.S_XMLDATA, Utils.E_XMLDATA);
							byte[] raw_byteData = Utils.getBytesValue(request,
									Utils.S_FILEDATA, Utils.E_FILEDATA);
							byte[] raw_userName = Utils.getBytesValue(request,
									Utils.S_USERNAME, Utils.E_USERNAME);
							byte[] raw_passWord = Utils.getBytesValue(request,
									Utils.S_PASSWORD, Utils.E_PASSWORD);
							byte[] raw_signature = Utils.getBytesValue(request,
									Utils.S_SIGNATURE, Utils.E_SIGNATURE);
							byte[] raw_timestamp = Utils.getBytesValue(request,
									Utils.S_TIMESTAMP, Utils.E_TIMESTAMP);
							byte[] raw_pkcs1Sig = Utils.getBytesValue(request,
									Utils.S_PKCS1SIGNATURE,
									Utils.E_PKCS1SIGNATURE);

							if (raw_xmlData == null
									|| Arrays.equals(raw_xmlData, NULL)) {
								// Invalid parameter
								String billCode = ExtFunc.getBillCode();
								String pData = ExtFunc.genResponseMessage(
										Defines.CODE_INVALIDPARAMETER,
										Defines.ERROR_INVALIDPARAMETER, "", "",
										billCode);
								DBConnector.getInstances()
										.writeLogToDataBaseOutside(
												functionName, "", ipClient, "",
												Defines.ERROR_INVALIDPARAMETER,
												Defines.CODE_INVALIDPARAMETER,
												sslSubDn, sslIseDn, sslSnb, "",
												"", xmlData, pData, billCode,
												unsignedData, signedData);
								ResponseData(requestObject,
										(new TransactionInfo(pData)).toBytes());
								continue;

							} else {
								xmlData = new String(raw_xmlData, "UTF-8");
								byteData = raw_byteData;
								String channelName = ExtFunc.getContent(
										Defines._CHANNEL, xmlData);
								String user = ExtFunc.getContent(Defines._USER,
										xmlData);
								String idTag = ExtFunc.getContent(Defines._ID,
										xmlData);

								String method = "";
								String transactionData = "";
								String subject = "";
								String _billCode = "";
								String _otp = "";

								if (raw_userName == null
										|| Arrays.equals(raw_userName, NULL)
										|| raw_passWord == null
										|| Arrays.equals(raw_passWord, NULL)
										|| raw_signature == null
										|| Arrays.equals(raw_signature, NULL)
										|| raw_timestamp == null
										|| Arrays.equals(raw_timestamp, NULL)
										|| raw_pkcs1Sig == null
										|| Arrays.equals(raw_pkcs1Sig, NULL)) {
									String billCode = ExtFunc.getBillCode();
									String pData = ExtFunc.genResponseMessage(
											Defines.CODE_INVALIDCREDENTIAL,
											Defines.ERROR_INVALIDCREDENTIAL,
											billCode);
									DBConnector
											.getInstances()
											.writeLogToDataBaseOutside(
													functionName,
													username,
													ipClient,
													user,
													Defines.ERROR_INVALIDCREDENTIAL,
													Defines.CODE_INVALIDCREDENTIAL,
													sslSubDn, sslIseDn, sslSnb,
													idTag, channelName,
													xmlData, pData, billCode,
													unsignedData, signedData);
									ResponseData(requestObject,
											(new TransactionInfo(pData))
													.toBytes());
									continue;
								} else {
									username = new String(raw_userName);
									password = new String(raw_passWord);
									timestamp = new String(raw_timestamp);
									signature = new String(raw_signature);
									pkcs1Signature = new String(raw_pkcs1Sig);

									if (channelName.compareTo("") == 0) {
										String billCode = ExtFunc.getBillCode();
										String pData = ExtFunc
												.genResponseMessage(
														Defines.CODE_INVALIDCHANNEL,
														Defines.ERROR_INVALIDCHANNEL,
														billCode);
										DBConnector
												.getInstances()
												.writeLogToDataBaseOutside(
														functionName,
														username,
														ipClient,
														user,
														Defines.ERROR_INVALIDCHANNEL,
														Defines.CODE_INVALIDCHANNEL,
														sslSubDn, sslIseDn,
														sslSnb, idTag,
														channelName, xmlData,
														pData, billCode,
														unsignedData,
														signedData);
										ResponseData(requestObject,
												(new TransactionInfo(pData))
														.toBytes());
										continue;
									}

									if (ExtFunc.getContent(Defines._WORKERNAME,
											xmlData).compareTo(
											Defines.WORKER_AGREEMENT) == 0
											&& ExtFunc
													.getContent(
															Defines._ACTION,
															xmlData)
													.compareTo(
															Defines.AGREEMENT_ACTION_VALIDA) == 0) {
										// do nothing
									} else {
										if (user.compareTo("") == 0) {
											String billCode = ExtFunc
													.getBillCode();
											String pData = ExtFunc
													.genResponseMessage(
															Defines.CODE_INVALIDUSER,
															Defines.ERROR_INVALIDUSER,
															billCode);
											DBConnector
													.getInstances()
													.writeLogToDataBaseOutside(
															functionName,
															username,
															ipClient,
															user,
															Defines.ERROR_INVALIDUSER,
															Defines.CODE_INVALIDUSER,
															sslSubDn, sslIseDn,
															sslSnb, idTag,
															channelName,
															xmlData, pData,
															billCode,
															unsignedData,
															signedData);
											ResponseData(
													requestObject,
													(new TransactionInfo(pData))
															.toBytes());
											continue;
										}
									}

									String result = "";
									String fileType = "";

									boolean isValidChannel = DBConnector
											.getInstances().checkChannelCode(
													channelName);

									if (isValidChannel) {
										result = DBConnector.getInstances()
												.readDataBase(channelName,
														ipClient, username,
														password, signature,
														timestamp,
														pkcs1Signature);

										if (result
												.compareTo(Defines.ERROR_INVALIDIP) == 0) {
											String billCode = ExtFunc
													.getBillCode();
											String pData = ExtFunc
													.genResponseMessage(
															Defines.CODE_INVALIDIP,
															Defines.ERROR_INVALIDIP,
															channelName, user,
															billCode);
											DBConnector
													.getInstances()
													.writeLogToDataBaseOutside(
															functionName,
															username,
															ipClient,
															user,
															Defines.ERROR_INVALIDIP,
															Defines.CODE_INVALIDIP,
															sslSubDn, sslIseDn,
															sslSnb, idTag,
															channelName,
															xmlData, pData,
															billCode,
															unsignedData,
															signedData);
											ResponseData(
													requestObject,
													(new TransactionInfo(pData))
															.toBytes());
											continue;
										} else if (result
												.compareTo(Defines.ERROR_INVALIDLOGININFO) == 0) {
											String billCode = ExtFunc
													.getBillCode();
											String pData = ExtFunc
													.genResponseMessage(
															Defines.CODE_INVALIDLOGININFO,
															Defines.ERROR_INVALIDLOGININFO,
															channelName, user,
															billCode);
											DBConnector
													.getInstances()
													.writeLogToDataBaseOutside(
															functionName,
															username,
															ipClient,
															user,
															Defines.ERROR_INVALIDLOGININFO,
															Defines.CODE_INVALIDLOGININFO,
															sslSubDn, sslIseDn,
															sslSnb, idTag,
															channelName,
															xmlData, pData,
															billCode,
															unsignedData,
															signedData);
											ResponseData(
													requestObject,
													(new TransactionInfo(pData))
															.toBytes());
											continue;
										} else if (result
												.compareTo(Defines.ERROR_INVALIDSIGNATURE) == 0) {
											String billCode = ExtFunc
													.getBillCode();
											String pData = ExtFunc
													.genResponseMessage(
															Defines.CODE_INVALIDSIGNATURE,
															Defines.ERROR_INVALIDSIGNATURE,
															channelName, user,
															billCode);
											DBConnector
													.getInstances()
													.writeLogToDataBaseOutside(
															functionName,
															username,
															ipClient,
															user,
															Defines.ERROR_INVALIDSIGNATURE,
															Defines.CODE_INVALIDSIGNATURE,
															sslSubDn, sslIseDn,
															sslSnb, idTag,
															channelName,
															xmlData, pData,
															billCode,
															unsignedData,
															signedData);
											ResponseData(
													requestObject,
													(new TransactionInfo(pData))
															.toBytes());
											continue;
										} else {
											// do operation
											String workerIdOrName = ExtFunc
													.getContent(
															Defines._WORKERNAME,
															xmlData);
											localWorkerName = workerIdOrName;
											if (workerIdOrName.compareTo("") == 0) {
												String billCode = ExtFunc
														.getBillCode();
												String pData = ExtFunc
														.genResponseMessage(
																Defines.CODE_INVALIDWORKERNAME,
																Defines.ERROR_INVALIDWORKERNAME,
																channelName,
																user, billCode);
												DBConnector
														.getInstances()
														.writeLogToDataBaseOutside(
																functionName,
																username,
																ipClient,
																user,
																Defines.ERROR_INVALIDWORKERNAME,
																Defines.CODE_INVALIDWORKERNAME,
																sslSubDn,
																sslIseDn,
																sslSnb, idTag,
																channelName,
																xmlData, pData,
																billCode,
																unsignedData,
																signedData);
												ResponseData(requestObject,
														(new TransactionInfo(
																pData))
																.toBytes());
												continue;
											}
											functionName = workerIdOrName;
											final int workerId = getWorkerId(workerIdOrName);
											if (!(workerIdOrName
													.compareTo(Defines.WORKER_AGREEMENT) == 0)) {
												if (workerId < 1) {
													String billCode = ExtFunc
															.getBillCode();
													String pData = ExtFunc
															.genResponseMessage(
																	Defines.CODE_NOWORKER,
																	Defines.ERROR_NOWORKER,
																	channelName,
																	user,
																	billCode);
													DBConnector
															.getInstances()
															.writeLogToDataBaseOutside(
																	functionName,
																	username,
																	ipClient,
																	user,
																	Defines.ERROR_NOWORKER,
																	Defines.CODE_NOWORKER,
																	sslSubDn,
																	sslIseDn,
																	sslSnb,
																	idTag,
																	channelName,
																	xmlData,
																	pData,
																	billCode,
																	unsignedData,
																	signedData);
													ResponseData(
															requestObject,
															(new TransactionInfo(
																	pData))
																	.toBytes());
													continue;
												}
											}
											// Check WorkerName and ChannelName
											// for permission
											boolean isAllow = DBConnector
													.getInstances()
													.authCheckRelation(
															channelName,
															workerIdOrName);
											if (!isAllow) {
												String billCode = ExtFunc
														.getBillCode();
												String pData = ExtFunc
														.genResponseMessage(
																Defines.CODE_INVALIDFUNCTION,
																Defines.ERROR_INVALIDFUNCTION,
																channelName,
																user, billCode);
												DBConnector
														.getInstances()
														.writeLogToDataBaseOutside(
																functionName,
																username,
																ipClient,
																user,
																Defines.ERROR_INVALIDFUNCTION,
																Defines.CODE_INVALIDFUNCTION,
																sslSubDn,
																sslIseDn,
																sslSnb, idTag,
																channelName,
																xmlData, pData,
																billCode,
																unsignedData,
																signedData);
												ResponseData(requestObject,
														(new TransactionInfo(
																pData))
																.toBytes());
												continue;
											}

											// Process SIMCA
											if (workerIdOrName
													.compareTo(Defines.WORKER_SIMCA) == 0) {
												String action = ExtFunc
														.getContent(
																Defines._ACTION,
																xmlData);

												if (action
														.compareTo(Defines.AGREEMENT_ACTION_REG) == 0) {
													String branchId = ExtFunc.getContent(Defines._BranchID, xmlData);
													// check user in
													// simagreement
													if (DBConnector
															.getInstances()
															.simca_CheckUser(
																	user,
																	channelName)) {
														// User exit
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_INVALIDUSERAGREEMENT,
																		Defines.ERROR_INVALIDUSERAGREEMENT,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_INVALIDUSERAGREEMENT,
																		Defines.CODE_INVALIDUSERAGREEMENT,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}

													String expiration = ExtFunc
															.getContent(
																	Defines._EXPIRATION,
																	xmlData);
													// check expiration format
													if (expiration.equals("")) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_INVALIDPARAMETER,
																		Defines.ERROR_INVALIDPARAMETER,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_INVALIDPARAMETER,
																		Defines.CODE_INVALIDPARAMETER,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}

													int expire = 0;
													try {
														expire = Integer
																.parseInt(expiration);
													} catch (NumberFormatException e) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_INVALIDPARAMETER,
																		Defines.ERROR_INVALIDPARAMETER,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_INVALIDPARAMETER,
																		Defines.CODE_INVALIDPARAMETER,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}
													if (expire <= 0) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_INVALIDPARAMETER,
																		Defines.ERROR_INVALIDPARAMETER,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_INVALIDPARAMETER,
																		Defines.CODE_INVALIDPARAMETER,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}
													// end check expiration
													// format

													// Check Provider: VIETTEL
													// or MOBIFONE...
													String provider = ExtFunc
															.getContent(
																	Defines._SIMPROVIDER,
																	xmlData);
													int isValidProvider = DBConnector
															.getInstances()
															.simca_CheckSimProvider(
																	provider);
													if (isValidProvider == 0) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_SIMCA_INVALIDPROVIDER,
																		Defines.ERROR_SIMCA_INVALIDPROVIDER,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_SIMCA_INVALIDPROVIDER,
																		Defines.CODE_SIMCA_INVALIDPROVIDER,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}

													final String content = "<Function>"
															+ Defines.CONNECTOR_FUNC_SIMCA_CERTIFICATEQUERY
															+ "</Function>"
															+ "<PhoneNo>"
															+ user
															+ "</PhoneNo>"
															+ "<Provider>"
															+ provider
															+ "</Provider>";
													CAGConnector wsConnector = CAGConnectorSrv
															.getInstance()
															.getWS();
													String sim_response = wsConnector
															.call(content);
													int responseCode = Integer
															.valueOf(ExtFunc.getContent(
																	"ResponseCode",
																	sim_response));
													String responseMess = ExtFunc.getContent(
															"ResponseMessage",
															sim_response);
													if (responseCode != 0) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_SIMCA_ERRORRESPONSE,
																		provider
																				+ ": "
																				+ responseMess,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		provider
																				+ ": "
																				+ responseMess,
																		Defines.CODE_SIMCA_ERRORRESPONSE,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}

													String certificate = ExtFunc.getContent(
															"Data",
															sim_response);
													// Check certificate valid
													if (!isCertificateValid(certificate)) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_INVALIDCERTIFICATE,
																		Defines.ERROR_INVALIDCERTIFICATE,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_INVALIDCERTIFICATE,
																		Defines.CODE_INVALIDCERTIFICATE,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}

													// insert sim agreement
													String[] certComponets = ExtFunc
															.getCertificateComponents(certificate);
													int rv = DBConnector
															.getInstances()
															.simca_InsertAgreement(
																	idTag,
																	channelName,
																	user,
																	certificate,
																	certComponets[0],
																	certComponets[3],
																	certComponets[4],
																	Defines.AGREEMENT_STATUS_ACTI,
																	expire, branchId);
													if (rv == -1) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_SIMCA_INSERTAGREEMENT,
																		Defines.ERROR_SIMCA_INSERTAGREEMENT,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_SIMCA_INSERTAGREEMENT,
																		Defines.CODE_SIMCA_INSERTAGREEMENT,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}
													String billCode = ExtFunc
															.getBillCode();
													String pData = ExtFunc
															.genResponseMessage(
																	Defines.CODE_SUCCESS,
																	Defines.SUCCESS,
																	channelName,
																	user,
																	Defines.AGREEMENT_STATUS_ACTI,
																	billCode);
													DBConnector
															.getInstances()
															.writeLogToDataBaseOutside(
																	functionName,
																	username,
																	ipClient,
																	user,
																	Defines.SUCCESS,
																	Defines.CODE_SUCCESS,
																	sslSubDn,
																	sslIseDn,
																	sslSnb,
																	idTag,
																	channelName,
																	xmlData,
																	pData,
																	billCode,
																	unsignedData,
																	signedData);
													ResponseData(requestObject,
															(new TransactionInfo(
																	pData))
																	.toBytes());
													continue;

												} else if (action
														.compareTo(Defines.AGREEMENT_ACTION_CHAINF) == 0) {

													// get agreement id
													int agreementId = DBConnector
															.getInstances()
															.simca_GetAgreementID(
																	user,
																	channelName);
													if (agreementId <= 0) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_AGREEMENTNOTEXITS,
																		Defines.ERROR_AGREEMENTNOTEXITS,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_AGREEMENTNOTEXITS,
																		Defines.CODE_AGREEMENTNOTEXITS,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}

													String expiration = ExtFunc
															.getContent(
																	Defines._EXPIRATION,
																	xmlData);
													// check expiration format
													if (expiration.equals("")) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_INVALIDPARAMETER,
																		Defines.ERROR_INVALIDPARAMETER,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_INVALIDPARAMETER,
																		Defines.CODE_INVALIDPARAMETER,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}

													int expire = 0;
													try {
														expire = Integer
																.parseInt(expiration);
													} catch (NumberFormatException e) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_INVALIDPARAMETER,
																		Defines.ERROR_INVALIDPARAMETER,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_INVALIDPARAMETER,
																		Defines.CODE_INVALIDPARAMETER,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}
													if (expire <= 0) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_INVALIDPARAMETER,
																		Defines.ERROR_INVALIDPARAMETER,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_INVALIDPARAMETER,
																		Defines.CODE_INVALIDPARAMETER,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}
													// end check expiration
													// format

													// update expiration day
													int rv = DBConnector
															.getInstances()
															.simca_UpdateAgreement(
																	agreementId,
																	expire);

													if (rv == -1) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_SIMCA_UPDATEAGREEMENT,
																		Defines.ERROR_SIMCA_UPDATEAGREEMENT,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_SIMCA_UPDATEAGREEMENT,
																		Defines.CODE_SIMCA_UPDATEAGREEMENT,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}
													String billCode = ExtFunc
															.getBillCode();
													String pData = ExtFunc
															.genResponseMessage(
																	Defines.CODE_SUCCESS,
																	Defines.SUCCESS,
																	channelName,
																	user,
																	billCode);
													DBConnector
															.getInstances()
															.writeLogToDataBaseOutside(
																	functionName,
																	username,
																	ipClient,
																	user,
																	Defines.SUCCESS,
																	Defines.CODE_SUCCESS,
																	sslSubDn,
																	sslIseDn,
																	sslSnb,
																	idTag,
																	channelName,
																	xmlData,
																	pData,
																	billCode,
																	unsignedData,
																	signedData);
													ResponseData(requestObject,
															(new TransactionInfo(
																	pData))
																	.toBytes());
													continue;

												} else if (action
														.compareTo(Defines.AGREEMENT_ACTION_UNREG) == 0) {

													// get agreement id
													int agreementId = DBConnector
															.getInstances()
															.simca_GetAgreementID(
																	user,
																	channelName);
													if (agreementId <= 0) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_AGREEMENTNOTEXITS,
																		Defines.ERROR_AGREEMENTNOTEXITS,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_AGREEMENTNOTEXITS,
																		Defines.CODE_AGREEMENTNOTEXITS,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}

													int rv = DBConnector
															.getInstances()
															.simca_CancelAgreement(
																	agreementId);
													if (rv == -1) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_SIMCA_CANCELAGREEMENT,
																		Defines.ERROR_SIMCA_CANCELAGREEMENT,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_SIMCA_CANCELAGREEMENT,
																		Defines.CODE_SIMCA_CANCELAGREEMENT,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}

													String billCode = ExtFunc
															.getBillCode();
													String pData = ExtFunc
															.genResponseMessage(
																	Defines.CODE_SUCCESS,
																	Defines.SUCCESS,
																	channelName,
																	user,
																	billCode);
													DBConnector
															.getInstances()
															.writeLogToDataBaseOutside(
																	functionName,
																	username,
																	ipClient,
																	user,
																	Defines.SUCCESS,
																	Defines.CODE_SUCCESS,
																	sslSubDn,
																	sslIseDn,
																	sslSnb,
																	idTag,
																	channelName,
																	xmlData,
																	pData,
																	billCode,
																	unsignedData,
																	signedData);
													ResponseData(requestObject,
															(new TransactionInfo(
																	pData))
																	.toBytes());
													continue;

												} else if (action
														.compareTo(Defines.ACTION_SIMCA_SIGNTRAN) == 0) {
													// Check agreement status
													int rv = DBConnector
															.getInstances()
															.simca_CheckAgreementStatus(
																	user,
																	channelName);
													if (rv == 1) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_AGREEMENTNOTEXITS,
																		Defines.ERROR_AGREEMENTNOTEXITS,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_AGREEMENTNOTEXITS,
																		Defines.CODE_AGREEMENTNOTEXITS,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}

													if (rv == 2) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_AGREEMENTEXPIRED,
																		Defines.ERROR_AGREEMENTEXPIRED,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_AGREEMENTEXPIRED,
																		Defines.CODE_AGREEMENTEXPIRED,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}

													if (rv == 3) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_CONTRACTSTATUS,
																		Defines.ERROR_CONTRACTSTATUS,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_CONTRACTSTATUS,
																		Defines.CODE_CONTRACTSTATUS,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}

													if (rv == -1) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_UNKNOWN,
																		Defines.ERROR_UNKNOWN,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_UNKNOWN,
																		Defines.CODE_UNKNOWN,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}
													// rv = 0
													// Check Provider: VIETTEL
													// or MOBIFONE...
													String provider = ExtFunc
															.getContent(
																	Defines._SIMPROVIDER,
																	xmlData);
													int isValidProvider = DBConnector
															.getInstances()
															.simca_CheckSimProvider(
																	provider);
													if (isValidProvider == 0) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_SIMCA_INVALIDPROVIDER,
																		Defines.ERROR_SIMCA_INVALIDPROVIDER,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_SIMCA_INVALIDPROVIDER,
																		Defines.CODE_SIMCA_INVALIDPROVIDER,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}

													String dataToSign = ExtFunc
															.getContent(
																	Defines._DATATOSIGN,
																	xmlData);
													if (dataToSign.equals("")) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_INVALIDDATATOSIGN,
																		Defines.ERROR_INVALIDDATATOSIGN,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_INVALIDDATATOSIGN,
																		Defines.CODE_INVALIDDATATOSIGN,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}

													dataToSign = ExtFunc
															.removeAccent(dataToSign);
													if (dataToSign.length() > 107) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_SIMCA_INVALIDLENGTH,
																		Defines.ERROR_SIMCA_INVALIDLENGTH,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_SIMCA_INVALIDLENGTH,
																		Defines.CODE_SIMCA_INVALIDLENGTH,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}
													String signingcert = DBConnector
															.getInstances()
															.simca_GetCertificate(
																	user,
																	channelName);
													final String content = "<Function>"
															+ Defines.CONNECTOR_FUNC_SIMCA_SIGNTRANSACTION
															+ "</Function>"
															+ "<Content>"
															+ dataToSign
															+ "</Content>"
															+ "<PhoneNo>"
															+ user
															+ "</PhoneNo>"
															+ "<Provider>"
															+ provider
															+ "</Provider>"
															+ "<Certificate>"
															+ signingcert
															+ "</Certificate>";
													CAGConnector wsConnector = CAGConnectorSrv
															.getInstance()
															.getWS();
													String connectorResponse = wsConnector
															.call(content);

													int responseCode = Integer
															.valueOf(ExtFunc.getContent(
																	"ResponseCode",
																	connectorResponse));
													String responseMess = ExtFunc.getContent(
															"ResponseMessage",
															connectorResponse);
													if (responseCode != 0) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_SIMCA_ERRORRESPONSE,
																		provider
																				+ ": "
																				+ responseMess,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		provider
																				+ ": "
																				+ responseMess,
																		Defines.CODE_SIMCA_ERRORRESPONSE,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}
													String response_signature = ExtFunc.getContent(
															"Data",
															connectorResponse);

													String billCode = ExtFunc
															.getBillCode();
													String pData = ExtFunc
															.genResponseMessage(
																	responseCode,
																	Defines.SUCCESS,
																	channelName,
																	user,
																	fileType,
																	signingcert,
																	billCode);
													DBConnector
															.getInstances()
															.writeLogToDataBaseOutside(
																	functionName,
																	username,
																	ipClient,
																	user,
																	responseMess,
																	responseCode,
																	sslSubDn,
																	sslIseDn,
																	sslSnb,
																	idTag,
																	channelName,
																	xmlData,
																	pData,
																	billCode,
																	unsignedData,
																	signedData);
													ResponseData(requestObject,
															(new TransactionInfo(
																	pData,
																	DatatypeConverter
																			.parseBase64Binary(response_signature)).toBytes()));
													continue;

												} else {
													String billCode = ExtFunc
															.getBillCode();
													String pData = ExtFunc
															.genResponseMessage(
																	Defines.CODE_INVALIDACTION,
																	Defines.ERROR_INVALIDACTION,
																	channelName,
																	user,
																	billCode);
													DBConnector
															.getInstances()
															.writeLogToDataBaseOutside(
																	functionName,
																	username,
																	ipClient,
																	user,
																	Defines.ERROR_INVALIDACTION,
																	Defines.CODE_INVALIDACTION,
																	sslSubDn,
																	sslIseDn,
																	sslSnb,
																	idTag,
																	channelName,
																	xmlData,
																	pData,
																	billCode,
																	unsignedData,
																	signedData);
													ResponseData(requestObject,
															(new TransactionInfo(
																	pData))
																	.toBytes());
													continue;
												}
											}
											// End Process SIMCA

											if (!(workerIdOrName
													.compareTo(Defines.WORKER_AGREEMENT) == 0)) {
												// Check agreement status
												method = ExtFunc.getContent(
														Defines._METHOD,
														xmlData);
												int agreementStatus = DBConnector
														.getInstances()
														.getAgreementStatusUser(
																user,
																channelName,
																getWorkerType(
																		workerIdOrName,
																		method));
												if (agreementStatus == 1) {
													String billCode = ExtFunc
															.getBillCode();
													String pData = ExtFunc
															.genResponseMessage(
																	Defines.CODE_AGREEMENTNOTEXITS,
																	Defines.ERROR_AGREEMENTNOTEXITS,
																	channelName,
																	user,
																	billCode);
													DBConnector
															.getInstances()
															.writeLogToDataBaseOutside(
																	functionName,
																	username,
																	ipClient,
																	user,
																	Defines.ERROR_AGREEMENTNOTEXITS,
																	Defines.CODE_AGREEMENTNOTEXITS,
																	sslSubDn,
																	sslIseDn,
																	sslSnb,
																	idTag,
																	channelName,
																	xmlData,
																	pData,
																	billCode,
																	unsignedData,
																	signedData);
													ResponseData(
															requestObject,
															(new TransactionInfo(
																	pData))
																	.toBytes());
													continue;
												} else if (agreementStatus == 4
														|| agreementStatus == 2
														|| agreementStatus == 3
														|| agreementStatus == 6
														|| agreementStatus == 7) {
													String billCode = ExtFunc
															.getBillCode();
													String pData = ExtFunc
															.genResponseMessage(
																	Defines.CODE_CONTRACTSTATUS,
																	Defines.ERROR_CONTRACTSTATUS,
																	channelName,
																	user,
																	billCode);
													DBConnector
															.getInstances()
															.writeLogToDataBaseOutside(
																	functionName,
																	username,
																	ipClient,
																	user,
																	Defines.ERROR_CONTRACTSTATUS,
																	Defines.CODE_CONTRACTSTATUS,
																	sslSubDn,
																	sslIseDn,
																	sslSnb,
																	idTag,
																	channelName,
																	xmlData,
																	pData,
																	billCode,
																	unsignedData,
																	signedData);
													ResponseData(
															requestObject,
															(new TransactionInfo(
																	pData))
																	.toBytes());
													continue;
												} else if (agreementStatus == 5) {
													String billCode = ExtFunc
															.getBillCode();
													String pData = ExtFunc
															.genResponseMessage(
																	Defines.CODE_AGREEMENTEXPIRED,
																	Defines.ERROR_AGREEMENTEXPIRED,
																	channelName,
																	user,
																	billCode);
													DBConnector
															.getInstances()
															.writeLogToDataBaseOutside(
																	functionName,
																	username,
																	ipClient,
																	user,
																	Defines.ERROR_AGREEMENTEXPIRED,
																	Defines.CODE_AGREEMENTEXPIRED,
																	sslSubDn,
																	sslIseDn,
																	sslSnb,
																	idTag,
																	channelName,
																	xmlData,
																	pData,
																	billCode,
																	unsignedData,
																	signedData);
													ResponseData(
															requestObject,
															(new TransactionInfo(
																	pData))
																	.toBytes());
													continue;
												}
												// Check PKI Validation block
												if (getWorkerType(
														workerIdOrName, method) == 2) {
													if (workerIdOrName
															.indexOf("Validator") != -1) {
														int pkiCheck = DBConnector
																.getInstances()
																.checkHWPKI(
																		channelName,
																		user);
														if (pkiCheck == 1
																|| pkiCheck == 2) {
															String billCode = ExtFunc
																	.getBillCode();
															String pData = ExtFunc
																	.genResponseMessage(
																			Defines.CODE_PKILOCKED,
																			Defines.ERROR_PKILOCKED,
																			channelName,
																			user,
																			billCode);
															DBConnector
																	.getInstances()
																	.writeLogToDataBaseOutside(
																			functionName,
																			username,
																			ipClient,
																			user,
																			Defines.ERROR_PKILOCKED,
																			Defines.CODE_PKILOCKED,
																			sslSubDn,
																			sslIseDn,
																			sslSnb,
																			idTag,
																			channelName,
																			xmlData,
																			pData,
																			billCode,
																			unsignedData,
																			signedData);
															ResponseData(
																	requestObject,
																	(new TransactionInfo(
																			pData))
																			.toBytes());
															continue;
														} else if (pkiCheck == -1) {
															String billCode = ExtFunc
																	.getBillCode();
															String pData = ExtFunc
																	.genResponseMessage(
																			Defines.CODE_UNKNOWN,
																			Defines.ERROR_UNKNOWN,
																			channelName,
																			user,
																			billCode);
															DBConnector
																	.getInstances()
																	.writeLogToDataBaseOutside(
																			functionName,
																			username,
																			ipClient,
																			user,
																			Defines.ERROR_UNKNOWN,
																			Defines.CODE_UNKNOWN,
																			sslSubDn,
																			sslIseDn,
																			sslSnb,
																			idTag,
																			channelName,
																			xmlData,
																			pData,
																			billCode,
																			unsignedData,
																			signedData);
															ResponseData(
																	requestObject,
																	(new TransactionInfo(
																			pData))
																			.toBytes());
															continue;
														}
													}

													if (workerIdOrName
															.indexOf("Signer") != -1) {
														int maxSignerCheck = DBConnector
																.getInstances()
																.checkMaxSigner(
																		channelName,
																		user);
														if (maxSignerCheck == 1) {
															String billCode = ExtFunc
																	.getBillCode();
															String pData = ExtFunc
																	.genResponseMessage(
																			Defines.CODE_OVERSIGNERTIME,
																			Defines.ERROR_OVERSIGNERTIME,
																			channelName,
																			user,
																			billCode);
															DBConnector
																	.getInstances()
																	.writeLogToDataBaseOutside(
																			functionName,
																			username,
																			ipClient,
																			user,
																			Defines.ERROR_OVERSIGNERTIME,
																			Defines.CODE_OVERSIGNERTIME,
																			sslSubDn,
																			sslIseDn,
																			sslSnb,
																			idTag,
																			channelName,
																			xmlData,
																			pData,
																			billCode,
																			unsignedData,
																			signedData);
															ResponseData(
																	requestObject,
																	(new TransactionInfo(
																			pData))
																			.toBytes());
															continue;
														} else if (maxSignerCheck == -1) {
															String billCode = ExtFunc
																	.getBillCode();
															String pData = ExtFunc
																	.genResponseMessage(
																			Defines.CODE_UNKNOWN,
																			Defines.ERROR_UNKNOWN,
																			channelName,
																			user,
																			billCode);
															DBConnector
																	.getInstances()
																	.writeLogToDataBaseOutside(
																			functionName,
																			username,
																			ipClient,
																			user,
																			Defines.ERROR_UNKNOWN,
																			Defines.CODE_UNKNOWN,
																			sslSubDn,
																			sslIseDn,
																			sslSnb,
																			idTag,
																			channelName,
																			xmlData,
																			pData,
																			billCode,
																			unsignedData,
																			signedData);
															ResponseData(
																	requestObject,
																	(new TransactionInfo(
																			pData))
																			.toBytes());
															continue;
														}
													}
												}

												// Get SerialNumber of User
												String serialNumber = "";
												if (getWorkerType(
														workerIdOrName, method) == 2
														&& workerIdOrName
																.indexOf("Validator") != -1) {
													serialNumber = DBConnector
															.getInstances()
															.getSerialNumberFromCa(
																	channelName,
																	user);
													if (serialNumber
															.compareTo("") == 0
															|| serialNumber
																	.compareTo(Defines.NULL) == 0) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_NOCERTSERIAL,
																		Defines.ERROR_NOCERTSERIAL,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_NOCERTSERIAL,
																		Defines.CODE_NOCERTSERIAL,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(
																requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}
												}

												// MetaData
												List<Metadata> requestMetadata = new ArrayList<Metadata>();
												String metaData = ExtFunc
														.getContent(
																Defines._METADATA,
																xmlData);
												if (!(metaData.compareTo("") == 0)) {
													requestMetadata = getMetaData(metaData);
													Metadata certserial = new Metadata(
															"certSerialNumber",
															serialNumber);
													requestMetadata
															.add(certserial);
												} else {
													Metadata certserial = new Metadata(
															"certSerialNumber",
															serialNumber);
													requestMetadata
															.add(certserial);
												}

												final int requestId = random
														.nextInt();
												// final int workerId =
												// getWorkerId(workerIdOrName);
												try {

													// Base64File
													byte[] data = null;
													if (workerIdOrName
															.indexOf("OATH") != -1) {
														// store check OTP co bi
														// lock hay ko
														int otpCheck = DBConnector
																.getInstances()
																.checkHWOTP(
																		channelName,
																		user);
														if (otpCheck == 1
																|| otpCheck == 2) {
															String billCode = ExtFunc
																	.getBillCode();
															String pData = ExtFunc
																	.genResponseMessage(
																			Defines.CODE_OTPLOCKED,
																			Defines.ERROR_OTPLOCKED,
																			channelName,
																			user,
																			billCode);
															DBConnector
																	.getInstances()
																	.writeLogToDataBaseOutside(
																			functionName,
																			username,
																			ipClient,
																			user,
																			Defines.ERROR_OTPLOCKED,
																			Defines.CODE_OTPLOCKED,
																			sslSubDn,
																			sslIseDn,
																			sslSnb,
																			idTag,
																			channelName,
																			xmlData,
																			pData,
																			billCode,
																			unsignedData,
																			signedData);
															ResponseData(
																	requestObject,
																	(new TransactionInfo(
																			pData))
																			.toBytes());
															continue;
														} else if (otpCheck == -1) {
															String billCode = ExtFunc
																	.getBillCode();
															String pData = ExtFunc
																	.genResponseMessage(
																			Defines.CODE_UNKNOWN,
																			Defines.ERROR_UNKNOWN,
																			channelName,
																			user,
																			billCode);
															DBConnector
																	.getInstances()
																	.writeLogToDataBaseOutside(
																			functionName,
																			username,
																			ipClient,
																			user,
																			Defines.ERROR_UNKNOWN,
																			Defines.CODE_UNKNOWN,
																			sslSubDn,
																			sslIseDn,
																			sslSnb,
																			idTag,
																			channelName,
																			xmlData,
																			pData,
																			billCode,
																			unsignedData,
																			signedData);
															ResponseData(
																	requestObject,
																	(new TransactionInfo(
																			pData))
																			.toBytes());
															continue;
														}
														// if oathrequest
														if (workerIdOrName
																.compareTo(Defines.WORKER_OATHREQUEST) == 0) {

															method = ExtFunc
																	.getContent(
																			Defines._METHOD,
																			xmlData);
															transactionData = ExtFunc
																	.getContent(
																			Defines._TRANSACTIONDATA,
																			xmlData);
															subject = ExtFunc
																	.getContent(
																			Defines._SUBJECT,
																			xmlData);
															if ((method
																	.compareTo("") == 0)
																	|| (transactionData
																			.compareTo("") == 0)) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_INVALIDPARAMETER,
																				Defines.ERROR_INVALIDPARAMETER,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_INVALIDPARAMETER,
																				Defines.CODE_INVALIDPARAMETER,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}

															if (!(method
																	.compareTo(Defines._OTPSMS) == 0)
																	&& !(method
																			.compareTo(Defines._OTPEMAIL) == 0)) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_INVALIDOTPMETHOD,
																				Defines.ERROR_INVALIDOTPMETHOD,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_INVALIDOTPMETHOD,
																				Defines.CODE_INVALIDOTPMETHOD,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}

															if (!DBConnector
																	.getInstances()
																	.authCheckOTPMethod(
																			channelName,
																			user,
																			method)) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_INVALIDOTPMETHOD,
																				Defines.ERROR_INVALIDOTPMETHOD,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_INVALIDOTPMETHOD,
																				Defines.CODE_INVALIDOTPMETHOD,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}
															/*
															if (!DBConnector
																	.getInstances()
																	.authCheckOTPPerformance(
																			channelName,
																			user,
																			method)) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_OTPPERFORMANCEXCEED,
																				Defines.ERROR_OTPPERFORMANCEXCEED,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_OTPPERFORMANCEXCEED,
																				Defines.CODE_OTPPERFORMANCEXCEED,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}
															*/
														}

														if (workerIdOrName
																.compareTo(Defines.WORKER_OATHRESPONSE) == 0) {
															_billCode = ExtFunc
																	.getContent(
																			Defines._BILLCODE,
																			xmlData);
															transactionData = ExtFunc
																	.getContent(
																			Defines._TRANSACTIONDATA,
																			xmlData);
															_otp = ExtFunc
																	.getContent(
																			Defines._OTP,
																			xmlData);
															if (_billCode
																	.compareTo("") == 0
																	|| transactionData
																			.compareTo("") == 0
																	|| _otp.compareTo("") == 0) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_INVALIDPARAMETER,
																				Defines.ERROR_INVALIDPARAMETER,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_INVALIDPARAMETER,
																				Defines.CODE_INVALIDPARAMETER,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}

															if (!(transactionData
																	.compareTo(DBConnector
																			.getInstances()
																			.authGetTransactionData(
																					channelName,
																					_billCode)) == 0)) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_INVALIDTRANSACSTATUS,
																				Defines.ERROR_INVALIDTRANSACSTATUS,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_INVALIDTRANSACSTATUS,
																				Defines.CODE_INVALIDTRANSACSTATUS,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}

															if (!DBConnector
																	.getInstances()
																	.authCheckOTPTransactionStatus(
																			channelName,
																			_billCode,
																			Defines.OTP_STATUS_WAIT)
																	&& !DBConnector
																			.getInstances()
																			.authCheckOTPTransactionStatus(
																					channelName,
																					_billCode,
																					Defines.OTP_STATUS_FAIL)
																	&& !DBConnector
																			.getInstances()
																			.authCheckOTPTransactionStatus(
																					channelName,
																					_billCode,
																					Defines.OTP_STATUS_TIME)
																	&& !DBConnector
																			.getInstances()
																			.authCheckOTPTransactionStatus(
																					channelName,
																					_billCode,
																					Defines.OTP_STATUS_EXPI)) {
																if (!DBConnector
																		.getInstances()
																		.authCheckOTPTransactionStatus(
																				channelName,
																				_billCode,
																				Defines.ERROR_OTPLOCKED)) {
																	String billCode = ExtFunc
																			.getBillCode();
																	String pData = ExtFunc
																			.genResponseMessage(
																					Defines.CODE_INVALIDTRANSACSTATUS,
																					Defines.ERROR_INVALIDTRANSACSTATUS,
																					channelName,
																					user,
																					billCode);
																	DBConnector
																			.getInstances()
																			.writeLogToDataBaseOutside(
																					functionName,
																					username,
																					ipClient,
																					user,
																					Defines.ERROR_INVALIDTRANSACSTATUS,
																					Defines.CODE_INVALIDTRANSACSTATUS,
																					sslSubDn,
																					sslIseDn,
																					sslSnb,
																					idTag,
																					channelName,
																					xmlData,
																					pData,
																					billCode,
																					unsignedData,
																					signedData);
																	ResponseData(
																			requestObject,
																			(new TransactionInfo(
																					pData))
																					.toBytes());
																	continue;
																} else {
																	String billCode = ExtFunc
																			.getBillCode();
																	String pData = ExtFunc
																			.genResponseMessage(
																					Defines.CODE_OTPLOCKED,
																					Defines.ERROR_OTPLOCKED,
																					channelName,
																					user,
																					billCode);
																	DBConnector
																			.getInstances()
																			.writeLogToDataBaseOutside(
																					functionName,
																					username,
																					ipClient,
																					user,
																					Defines.ERROR_OTPLOCKED,
																					Defines.CODE_OTPLOCKED,
																					sslSubDn,
																					sslIseDn,
																					sslSnb,
																					idTag,
																					channelName,
																					xmlData,
																					pData,
																					billCode,
																					unsignedData,
																					signedData);
																	ResponseData(
																			requestObject,
																			(new TransactionInfo(
																					pData))
																					.toBytes());
																	continue;
																}
															}

															Metadata billCodeOTP = new Metadata(
																	"BillCode",
																	_billCode);
															Metadata otpOTP = new Metadata(
																	"OTP", _otp);
															requestMetadata
																	.add(billCodeOTP);
															requestMetadata
																	.add(otpOTP);
														}

														Metadata channelNameOTP = new Metadata(
																Defines._CHANNEL,
																channelName);

														Metadata userOTP = new Metadata(
																Defines._USER, user);
														requestMetadata
																.add(channelNameOTP);
														requestMetadata
																.add(userOTP);
													} else if (workerIdOrName
															.compareTo("CapicomValidator") == 0) {
														String capicomSignature = ExtFunc
																.getContent(
																		Defines._CAPICOMSIGNATURE,
																		xmlData);
														unsignedData = capicomSignature;
														if (capicomSignature
																.compareTo("") == 0) {
															String billCode = ExtFunc
																	.getBillCode();
															String pData = ExtFunc
																	.genResponseMessage(
																			Defines.CODE_NOCAPICOMSIGNATURE,
																			Defines.ERROR_NOCAPICOMSIGNATURE,
																			channelName,
																			user,
																			billCode);
															DBConnector
																	.getInstances()
																	.writeLogToDataBaseOutside(
																			functionName,
																			username,
																			ipClient,
																			user,
																			Defines.ERROR_NOCAPICOMSIGNATURE,
																			Defines.CODE_NOCAPICOMSIGNATURE,
																			sslSubDn,
																			sslIseDn,
																			sslSnb,
																			idTag,
																			channelName,
																			xmlData,
																			pData,
																			billCode,
																			unsignedData,
																			signedData);
															ResponseData(
																	requestObject,
																	(new TransactionInfo(
																			pData))
																			.toBytes());
															continue;
														}

														data = Base64
																.decode(capicomSignature);
													} else { // Signer and
																// Validator
														// Check FileType if
														// Signer
														if (workerIdOrName
																.indexOf("Signer") != -1) {
															fileType = ExtFunc
																	.getContent(
																			Defines._FILETYPE,
																			xmlData);
															if (fileType
																	.compareTo("") == 0) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_INVALIDFILETYPE,
																				Defines.ERROR_INVALIDFILETYPE,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_INVALIDFILETYPE,
																				Defines.CODE_INVALIDFILETYPE,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}
														}

														if (workerIdOrName
																.compareTo("CMSSigner") == 0) {
															String dataToSign = ExtFunc
																	.getContent(
																			Defines._DATATOSIGN,
																			xmlData);
															if (dataToSign
																	.compareTo("") == 0) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_INVALIDDATATOSIGN,
																				Defines.ERROR_INVALIDDATATOSIGN,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_INVALIDDATATOSIGN,
																				Defines.CODE_INVALIDDATATOSIGN,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}
															try {
																data = dataToSign
																		.getBytes("UTF-16LE");
															} catch (UnsupportedEncodingException e) {
																e.printStackTrace();
															}

														} else {

															if (byteData == null
																	|| Arrays
																			.equals(byteData,
																					NULL)) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_NOBASE64FILE,
																				Defines.ERROR_NOBASE64FILE,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_NOBASE64FILE,
																				Defines.CODE_NOBASE64FILE,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}
															data = byteData;
														}
													}

													// save log for text file
													// input
													if (workerIdOrName
															.compareTo(Defines.WORKER_XMLVALIDATOR) == 0
															|| workerIdOrName
																	.compareTo(Defines.WORKER_XMLSIGNER) == 0) {
														unsignedData = new String(
																data);
													}

													final RequestContext requestContext = handleRequestContext(
															ipClient,
															requestMetadata,
															workerId);

													final ProcessRequest req = new GenericSignRequest(
															requestId, data);
													final ProcessResponse resp = getWorkerSession()
															.process(workerId,
																	req,
																	requestContext);

													if (resp instanceof GenericSignResponse) {
														final GenericSignResponse signResponse = (GenericSignResponse) resp;
														if (signResponse
																.getRequestID() != requestId) {
															LOG.error("Response ID "
																	+ signResponse
																			.getRequestID()
																	+ " not matching request ID "
																	+ requestId);
															String billCode = ExtFunc
																	.getBillCode();
															String pData = ExtFunc
																	.genResponseMessage(
																			Defines.CODE_NOTMATCHID,
																			Defines.ERROR_NOTMATCHID,
																			channelName,
																			user,
																			billCode);
															DBConnector
																	.getInstances()
																	.writeLogToDataBaseOutside(
																			functionName,
																			username,
																			ipClient,
																			user,
																			Defines.ERROR_NOTMATCHID,
																			Defines.CODE_NOTMATCHID,
																			sslSubDn,
																			sslIseDn,
																			sslSnb,
																			idTag,
																			channelName,
																			xmlData,
																			pData,
																			billCode,
																			unsignedData,
																			signedData);
															ResponseData(
																	requestObject,
																	(new TransactionInfo(
																			pData))
																			.toBytes());
															continue;

														}

														DataResponse response = new DataResponse(
																requestId,
																signResponse
																		.getProcessedData(),
																signResponse
																		.getArchiveId(),
																signResponse
																		.getSignerCertificate() == null ? signResponse
																		.getSignerCertificateChainBytes()
																		: signResponse
																				.getSignerCertificate()
																				.getEncoded(),
																getResponseMetadata(requestContext),
																signResponse
																		.getResponseCode(),
																signResponse
																		.getResponseMessage(),
																signResponse
																		.getSignerInfoResponse());
														int responseCode = signResponse
																.getResponseCode();
														String responseMessage = signResponse
																.getResponseMessage();

														if (workerIdOrName
																.indexOf("Validator") != -1
																&& workerIdOrName
																		.indexOf("OATH") == -1) {
															// Validator
															if (responseCode == Defines.CODE_SUCCESS) {
																DBConnector
																		.getInstances()
																		.resetErrorCounterHWPKI(
																				channelName,
																				user);
																List<SignerInfoResponse> signInfo = signResponse
																		.getSignerInfoResponse();
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				responseCode,
																				responseMessage,
																				channelName,
																				user,
																				signInfo,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				responseMessage,
																				responseCode,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															} else {
																int pkiCheck = DBConnector
																		.getInstances()
																		.leftRetryHWPKI(
																				channelName,
																				user);
																if (pkiCheck == -100) {
																	String billCode = ExtFunc
																			.getBillCode();
																	String pData = ExtFunc
																			.genResponseMessage(
																					Defines.CODE_PKILOCKED,
																					Defines.ERROR_PKILOCKED,
																					channelName,
																					user,
																					billCode);
																	DBConnector
																			.getInstances()
																			.writeLogToDataBaseOutside(
																					functionName,
																					username,
																					ipClient,
																					user,
																					responseMessage,
																					responseCode,
																					sslSubDn,
																					sslIseDn,
																					sslSnb,
																					idTag,
																					channelName,
																					xmlData,
																					pData,
																					billCode,
																					unsignedData,
																					signedData);
																	ResponseData(
																			requestObject,
																			(new TransactionInfo(
																					pData))
																					.toBytes());
																	continue;
																}
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				responseCode,
																				responseMessage,
																				channelName,
																				user,
																				pkiCheck,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				responseMessage,
																				responseCode,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}

														} else if (workerIdOrName
																.indexOf("Signer") != -1) {
															// Signer
															if (responseCode == Defines.CODE_SUCCESS) {

																byte[] signedFile = signResponse
																		.getProcessedData();
																String signingcert = signResponse
																		.getSignerCertificate() == null ? new String(
																		Base64.encode(signResponse
																				.getSignerCertificateChainBytes()))
																		: new String(
																				Base64.encode(signResponse
																						.getSignerCertificate()
																						.getEncoded()));

																// save log for
																// text file
																// output
																if (workerIdOrName
																		.compareTo(Defines.WORKER_XMLSIGNER) == 0) {
																	signedData = new String(
																			signedFile);
																}

																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				responseCode,
																				responseMessage,
																				channelName,
																				user,
																				fileType,
																				signingcert,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				responseMessage,
																				responseCode,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);

																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData,
																				signedFile))
																				.toBytes());
																continue;
															}
														} else {
															// OATHRequest
															if (workerIdOrName
																	.compareTo(Defines.WORKER_OATHREQUEST) == 0) {

																String otpInformation = "";
																String otp = new String(
																		signResponse
																				.getProcessedData());
																int otpInformationID = DBConnector
																		.getInstances()
																		.authGetOTPInformationID(
																				channelName,
																				user);
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseOATHMessage(
																				Defines.CODE_OTP_STATUS_WAIT,
																				Defines.OTP_STATUS_WAIT,
																				channelName,
																				user,
																				billCode);
																int logID = DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.OTP_STATUS_WAIT,
																				Defines.CODE_OTP_STATUS_WAIT,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);

																boolean res = DBConnector
																		.getInstances()
																		.authInsertOTPTransaction(
																				logID,
																				otp,
																				transactionData,
																				otpInformationID,
																				method);
																if (method
																		.compareTo(Defines._OTPEMAIL) == 0) {
																	String email = DBConnector
																			.getInstances()
																			.authGetEmailOTP(
																					channelName,
																					user);
																	otpInformation = DBConnector
																			.getInstances()
																			.OTPInformationGeneration(
																					transactionData,
																					otp);
																	// Email
																	// Connector
																	final String content = "<Function>SENDEMAIL</Function><Email>"
																			+ email
																			+ "</Email><Content>"
																			+ otpInformation
																			+ "</Content>"
																			+ "<Subject>"
																			+ subject
																			+ "</Subject>";
																	CAGConnector wsConnector = CAGConnectorSrv
																			.getInstance()
																			.getWS();
																	String otp_response = wsConnector
																			.call(content);

																	DBConnector
																			.getInstances()
																			.authInsertEmail(
																					channelName,
																					ExtFunc.getContent(
																							"ServiceID",
																							otp_response),
																					email,
																					otpInformation,
																					(ExtFunc.getContent(
																							"Status",
																							otp_response)
																							.compareTo(
																									"true") == 0),
																					ExtFunc.getContent(
																							"ResponseMessage",
																							otp_response),
																					logID);
																} else {
																	String phoneNo = DBConnector
																			.getInstances()
																			.authGetPhoneNoOTP(
																					channelName,
																					user);
																	otpInformation = DBConnector
																			.getInstances()
																			.OTPInformationGeneration(
																					ExtFunc.removeAccent(transactionData),
																					otp);
																	// SMS
																	// Gateway
																	final String content = "<Function>SENDSMS</Function><PhoneNo>"
																			+ phoneNo
																			+ "</PhoneNo><Content>"
																			+ otpInformation
																			+ "</Content>";
																	CAGConnector wsConnector = CAGConnectorSrv
																			.getInstance()
																			.getWS();
																	String otp_response = wsConnector
																			.call(content);
																	DBConnector
																			.getInstances()
																			.authInsertSMS(
																					channelName,
																					ExtFunc.getContent(
																							"ServiceID",
																							otp_response),
																					phoneNo,
																					otpInformation,
																					(ExtFunc.getContent(
																							"Status",
																							otp_response)
																							.compareTo(
																									"true") == 0),
																					ExtFunc.getContent(
																							"ResponseMessage",
																							otp_response),
																					logID);
																}
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															} else if (workerIdOrName
																	.compareTo(Defines.WORKER_OATHRESPONSE) == 0) {
																if (responseCode != Defines.CODE_SUCCESS) {
																	int otpCheck = DBConnector
																			.getInstances()
																			.leftRetryHWOTP(
																					channelName,
																					user);
																	if (otpCheck == -100) {
																		String[] otpTransaction = DBConnector
																				.getInstances()
																				.authGetOTPTransaction(
																						channelName,
																						_billCode);
																		DBConnector
																				.getInstances()
																				.authSetOTPTransactionStatus(
																						Integer.parseInt(otpTransaction[0]),
																						Defines.OTP_STATUS_EXPI);

																		String pData = ExtFunc
																				.genResponseOATHMessage(
																						Defines.CODE_OTPLOCKED,
																						Defines.ERROR_OTPLOCKED,
																						channelName,
																						user,
																						_billCode);
																		String billCode = ExtFunc
																				.getBillCode();
																		DBConnector
																				.getInstances()
																				.writeLogToDataBaseOutside(
																						functionName,
																						username,
																						ipClient,
																						user,
																						Defines.ERROR_OTPLOCKED,
																						Defines.CODE_OTPLOCKED,
																						sslSubDn,
																						sslIseDn,
																						sslSnb,
																						idTag,
																						channelName,
																						xmlData,
																						pData,
																						billCode,
																						unsignedData,
																						signedData);
																		ResponseData(
																				requestObject,
																				(new TransactionInfo(
																						pData))
																						.toBytes());
																		continue;
																	}

																	String pData = ExtFunc
																			.genResponseOATHMessage(
																					responseCode,
																					responseMessage,
																					channelName,
																					user,
																					_billCode,
																					otpCheck);
																	String billCode = ExtFunc
																			.getBillCode();
																	DBConnector
																			.getInstances()
																			.writeLogToDataBaseOutside(
																					functionName,
																					username,
																					ipClient,
																					user,
																					responseMessage,
																					responseCode,
																					sslSubDn,
																					sslIseDn,
																					sslSnb,
																					idTag,
																					channelName,
																					xmlData,
																					pData,
																					billCode,
																					unsignedData,
																					signedData);
																	ResponseData(
																			requestObject,
																			(new TransactionInfo(
																					pData))
																					.toBytes());
																	continue;
																}
																// SUCCESS
																DBConnector
																		.getInstances()
																		.resetErrorCounterHWOTP(
																				channelName,
																				user);
																String pData = ExtFunc
																		.genResponseOATHMessage(
																				responseCode,
																				responseMessage,
																				channelName,
																				user,
																				_billCode);
																String billCode = ExtFunc
																		.getBillCode();
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				responseMessage,
																				responseCode,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;

															} else {
																// OATHValidator
																// and OATHSync
																if (responseCode != Defines.CODE_SUCCESS) {
																	// Su dung
																	// lai store
																	// checkOTP
																	// de tra ve
																	// so lan
																	// con lai
																	int otpCheck = DBConnector
																			.getInstances()
																			.leftRetryHWOTP(
																					channelName,
																					user);
																	LOG.info("Real OTP left retry: "
																			+ new String(
																					signResponse
																							.getProcessedData()));
																	if (otpCheck == -100) {
																		String billCode = ExtFunc
																				.getBillCode();
																		String pData = ExtFunc
																				.genResponseMessage(
																						Defines.CODE_OTPLOCKED,
																						Defines.ERROR_OTPLOCKED,
																						channelName,
																						user,
																						billCode);
																		DBConnector
																				.getInstances()
																				.writeLogToDataBaseOutside(
																						functionName,
																						username,
																						ipClient,
																						user,
																						Defines.ERROR_OTPLOCKED,
																						Defines.CODE_OTPLOCKED,
																						sslSubDn,
																						sslIseDn,
																						sslSnb,
																						idTag,
																						channelName,
																						xmlData,
																						pData,
																						billCode,
																						unsignedData,
																						signedData);
																		ResponseData(
																				requestObject,
																				(new TransactionInfo(
																						pData))
																						.toBytes());
																		continue;
																	}
																	String billCode = ExtFunc
																			.getBillCode();
																	String pData = ExtFunc
																			.genResponseMessage(
																					responseCode,
																					responseMessage,
																					channelName,
																					user,
																					otpCheck,
																					billCode);
																	DBConnector
																			.getInstances()
																			.writeLogToDataBaseOutside(
																					functionName,
																					username,
																					ipClient,
																					user,
																					responseMessage,
																					responseCode,
																					sslSubDn,
																					sslIseDn,
																					sslSnb,
																					idTag,
																					channelName,
																					xmlData,
																					pData,
																					billCode,
																					unsignedData,
																					signedData);
																	ResponseData(
																			requestObject,
																			(new TransactionInfo(
																					pData))
																					.toBytes());
																	continue;
																} else if (responseCode == Defines.CODE_SUCCESS) {
																	DBConnector
																			.getInstances()
																			.resetErrorCounterHWOTP(
																					channelName,
																					user);
																}
															}
														}
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		responseCode,
																		responseMessage,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		responseMessage,
																		responseCode,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(
																requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;

													} else {

														LOG.error("Unexpected return type: "
																+ resp.getClass()
																		.getName());
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_UNEXPECTEDRETURNTYPE,
																		Defines.ERROR_UNEXPECTEDRETURNTYPE,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_UNEXPECTEDRETURNTYPE,
																		Defines.CODE_UNEXPECTEDRETURNTYPE,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(
																requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}
												} catch (CertificateEncodingException ex) {
													LOG.error(
															"Signer certificate could not be encoded",
															ex);
													String billCode = ExtFunc
															.getBillCode();
													String pData = ExtFunc
															.genResponseMessage(
																	Defines.CODE_SIGNERCERTENCODE,
																	Defines.ERROR_SIGNERCERTENCODE,
																	channelName,
																	user,
																	billCode);
													DBConnector
															.getInstances()
															.writeLogToDataBaseOutside(
																	functionName,
																	username,
																	ipClient,
																	user,
																	Defines.ERROR_SIGNERCERTENCODE,
																	Defines.CODE_SIGNERCERTENCODE,
																	sslSubDn,
																	sslIseDn,
																	sslSnb,
																	idTag,
																	channelName,
																	xmlData,
																	pData,
																	billCode,
																	unsignedData,
																	signedData);
													ResponseData(
															requestObject,
															(new TransactionInfo(
																	pData))
																	.toBytes());
													continue;
												} catch (IllegalRequestException ex) {
													LOG.info("Request failed: "
															+ ex.getMessage());
													String billCode = ExtFunc
															.getBillCode();
													String pData = ExtFunc
															.genResponseMessage(
																	Defines.CODE_INTERNALSYSTEM,
																	Defines.ERROR_INTERNALSYSTEM,
																	channelName,
																	user,
																	billCode);
													DBConnector
															.getInstances()
															.writeLogToDataBaseOutside(
																	functionName,
																	username,
																	ipClient,
																	user,
																	Defines.ERROR_INTERNALSYSTEM,
																	Defines.CODE_INTERNALSYSTEM,
																	sslSubDn,
																	sslIseDn,
																	sslSnb,
																	idTag,
																	channelName,
																	xmlData,
																	pData,
																	billCode,
																	unsignedData,
																	signedData);
													ResponseData(
															requestObject,
															(new TransactionInfo(
																	pData))
																	.toBytes());
													continue;
												} catch (CryptoTokenOfflineException ex) {
													LOG.info("Token offline: "
															+ ex.getMessage());
													String billCode = ExtFunc
															.getBillCode();
													String pData = ExtFunc
															.genResponseMessage(
																	Defines.CODE_WORKEROFFLINE,
																	Defines.ERROR_WORKEROFFLINE,
																	channelName,
																	user,
																	billCode);
													DBConnector
															.getInstances()
															.writeLogToDataBaseOutside(
																	functionName,
																	username,
																	ipClient,
																	user,
																	Defines.ERROR_WORKEROFFLINE,
																	Defines.CODE_WORKEROFFLINE,
																	sslSubDn,
																	sslIseDn,
																	sslSnb,
																	idTag,
																	channelName,
																	xmlData,
																	pData,
																	billCode,
																	unsignedData,
																	signedData);
													ResponseData(
															requestObject,
															(new TransactionInfo(
																	pData))
																	.toBytes());
													continue;
												} catch (AuthorizationRequiredException ex) {
													LOG.info("Request failed: "
															+ ex.getMessage());
													String billCode = ExtFunc
															.getBillCode();
													String pData = ExtFunc
															.genResponseMessage(
																	Defines.CODE_INTERNALSYSTEM,
																	Defines.ERROR_INTERNALSYSTEM,
																	channelName,
																	user,
																	billCode);
													DBConnector
															.getInstances()
															.writeLogToDataBaseOutside(
																	functionName,
																	username,
																	ipClient,
																	user,
																	Defines.ERROR_INTERNALSYSTEM,
																	Defines.CODE_INTERNALSYSTEM,
																	sslSubDn,
																	sslIseDn,
																	sslSnb,
																	idTag,
																	channelName,
																	xmlData,
																	pData,
																	billCode,
																	unsignedData,
																	signedData);
													ResponseData(
															requestObject,
															(new TransactionInfo(
																	pData))
																	.toBytes());
													continue;
												} catch (AccessDeniedException ex) {
													LOG.info("Request failed: "
															+ ex.getMessage());
													String billCode = ExtFunc
															.getBillCode();
													String pData = ExtFunc
															.genResponseMessage(
																	Defines.CODE_INTERNALSYSTEM,
																	Defines.ERROR_INTERNALSYSTEM,
																	channelName,
																	user,
																	billCode);
													DBConnector
															.getInstances()
															.writeLogToDataBaseOutside(
																	functionName,
																	username,
																	ipClient,
																	user,
																	Defines.ERROR_INTERNALSYSTEM,
																	Defines.CODE_INTERNALSYSTEM,
																	sslSubDn,
																	sslIseDn,
																	sslSnb,
																	idTag,
																	channelName,
																	xmlData,
																	pData,
																	billCode,
																	unsignedData,
																	signedData);
													ResponseData(
															requestObject,
															(new TransactionInfo(
																	pData))
																	.toBytes());
													continue;
												} catch (SignServerException ex) {
													String billCode = ExtFunc
															.getBillCode();
													String pData = ExtFunc
															.genResponseMessage(
																	Defines.CODE_INTERNALSYSTEM,
																	Defines.ERROR_INTERNALSYSTEM,
																	channelName,
																	user,
																	billCode);
													DBConnector
															.getInstances()
															.writeLogToDataBaseOutside(
																	functionName,
																	username,
																	ipClient,
																	user,
																	Defines.ERROR_INTERNALSYSTEM,
																	Defines.CODE_INTERNALSYSTEM,
																	sslSubDn,
																	sslIseDn,
																	sslSnb,
																	idTag,
																	channelName,
																	xmlData,
																	pData,
																	billCode,
																	unsignedData,
																	signedData);
													ResponseData(
															requestObject,
															(new TransactionInfo(
																	pData))
																	.toBytes());
													continue;
												}
											} else {
												// Agreement
												String action = ExtFunc
														.getContent(
																Defines._ACTION,
																xmlData);
												if (action
														.compareTo(Defines.AGREEMENT_ACTION_REG) == 0) {

													// do operation
													String isOtpSms = ExtFunc
															.getContent(
																	Defines._ISOTPSMS,
																	xmlData);
													String otpSms = ExtFunc
															.getContent(
																	Defines._OTPSMS,
																	xmlData);

													String isOtpEmail = ExtFunc
															.getContent(
																	Defines._ISOTPEMAIL,
																	xmlData);
													String otpEmail = ExtFunc
															.getContent(
																	Defines._OTPEMAIL,
																	xmlData);

													String isOtpHardware = ExtFunc
															.getContent(
																	Defines._ISOTPHARDWARE,
																	xmlData);
													String otpHardware = ExtFunc
															.getContent(
																	Defines._OTPHARDWARE,
																	xmlData);

													String isPKI = ExtFunc
															.getContent(
																	Defines._ISPKI,
																	xmlData);
													String pkiCertificate = ExtFunc
															.getContent(
																	Defines._CERTIFICATE,
																	xmlData);

													String isOtpSoftware = ExtFunc
															.getContent(
																	Defines._ISOTPSOFTWARE,
																	xmlData);

													String expiration = ExtFunc
															.getContent(
																	Defines._EXPIRATION,
																	xmlData);
													
													String branchId = ExtFunc.getContent(
															Defines._BranchID, xmlData);

													if (isOtpSms.compareTo("") == 0
															|| isOtpEmail
																	.compareTo("") == 0
															|| isOtpHardware
																	.compareTo("") == 0
															|| isPKI.compareTo("") == 0
															|| isOtpSoftware
																	.compareTo("") == 0) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_INVALIDPARAMETER,
																		Defines.ERROR_INVALIDPARAMETER,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_INVALIDPARAMETER,
																		Defines.CODE_INVALIDPARAMETER,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(
																requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}

													if (!(isOtpEmail
															.compareTo(Defines.TRUE) == 0)) {
														isOtpEmail = Defines.FALSE;
														otpEmail = Defines.NULL;
													}
													if (!(isOtpHardware
															.compareTo(Defines.TRUE) == 0)) {
														isOtpHardware = Defines.FALSE;
														otpHardware = Defines.NULL;
													}
													if (!(isOtpSms
															.compareTo(Defines.TRUE) == 0)) {
														isOtpSms = Defines.FALSE;
														otpSms = Defines.NULL;
													}
													if (!(isOtpSoftware
															.compareTo(Defines.TRUE) == 0)) {
														isOtpSoftware = Defines.FALSE;
													}
													if (!(isPKI
															.compareTo(Defines.TRUE) == 0)) {
														isPKI = Defines.FALSE;
														pkiCertificate = Defines.NULL;
													}
													if (isOtpEmail
															.compareTo(Defines.TRUE) == 0) {
														if (!(otpEmail
																.compareTo("") == 0)) {
															if (!ExtFunc
																	.isValidEmail(otpEmail)) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_INVALIDPARAMETER,
																				Defines.ERROR_INVALIDPARAMETER,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_INVALIDPARAMETER,
																				Defines.CODE_INVALIDPARAMETER,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}

															if (DBConnector
																	.getInstances()
																	.authCheckOTPEmail(user,
																			otpEmail)) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_USEREMAILEXIT,
																				Defines.ERROR_USEREMAILEXIT,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_USEREMAILEXIT,
																				Defines.CODE_USEREMAILEXIT,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}
														} else {
															String billCode = ExtFunc
																	.getBillCode();
															String pData = ExtFunc
																	.genResponseMessage(
																			Defines.CODE_INVALIDPARAMETER,
																			Defines.ERROR_INVALIDPARAMETER,
																			channelName,
																			user,
																			billCode);
															DBConnector
																	.getInstances()
																	.writeLogToDataBaseOutside(
																			functionName,
																			username,
																			ipClient,
																			user,
																			Defines.ERROR_INVALIDPARAMETER,
																			Defines.CODE_INVALIDPARAMETER,
																			sslSubDn,
																			sslIseDn,
																			sslSnb,
																			idTag,
																			channelName,
																			xmlData,
																			pData,
																			billCode,
																			unsignedData,
																			signedData);
															ResponseData(
																	requestObject,
																	(new TransactionInfo(
																			pData))
																			.toBytes());
															continue;
														}
													}

													if (isOtpSms
															.compareTo(Defines.TRUE) == 0) {
														if (!(otpSms
																.compareTo("") == 0)) {
															if (!ExtFunc
																	.isValidPhoneNumber(otpSms)) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_INVALIDPARAMETER,
																				Defines.ERROR_INVALIDPARAMETER,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_INVALIDPARAMETER,
																				Defines.CODE_INVALIDPARAMETER,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}

															if (DBConnector
																	.getInstances()
																	.authCheckOTPSMS(user,
																			otpSms)) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_USERPHONEEXIT,
																				Defines.ERROR_USERPHONEEXIT,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_USERPHONEEXIT,
																				Defines.CODE_USERPHONEEXIT,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}
														} else {
															String billCode = ExtFunc
																	.getBillCode();
															String pData = ExtFunc
																	.genResponseMessage(
																			Defines.CODE_INVALIDPARAMETER,
																			Defines.ERROR_INVALIDPARAMETER,
																			channelName,
																			user,
																			billCode);
															DBConnector
																	.getInstances()
																	.writeLogToDataBaseOutside(
																			functionName,
																			username,
																			ipClient,
																			user,
																			Defines.ERROR_INVALIDPARAMETER,
																			Defines.CODE_INVALIDPARAMETER,
																			sslSubDn,
																			sslIseDn,
																			sslSnb,
																			idTag,
																			channelName,
																			xmlData,
																			pData,
																			billCode,
																			unsignedData,
																			signedData);
															ResponseData(
																	requestObject,
																	(new TransactionInfo(
																			pData))
																			.toBytes());
															continue;
														}
													}

													// Check expireation

													if (expiration
															.compareTo("") == 0) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_INVALIDPARAMETER,
																		Defines.ERROR_INVALIDPARAMETER,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_INVALIDPARAMETER,
																		Defines.CODE_INVALIDPARAMETER,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(
																requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}

													int expire = 0;
													try {
														expire = Integer
																.parseInt(expiration);
													} catch (NumberFormatException e) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_INVALIDPARAMETER,
																		Defines.ERROR_INVALIDPARAMETER,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_INVALIDPARAMETER,
																		Defines.CODE_INVALIDPARAMETER,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(
																requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}
													if (expire <= 0) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_INVALIDPARAMETER,
																		Defines.ERROR_INVALIDPARAMETER,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_INVALIDPARAMETER,
																		Defines.CODE_INVALIDPARAMETER,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(
																requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}

													// check user
													if (DBConnector
															.getInstances()
															.checkUser(user,
																	channelName)) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_INVALIDUSERAGREEMENT,
																		Defines.ERROR_INVALIDUSERAGREEMENT,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_INVALIDUSERAGREEMENT,
																		Defines.CODE_INVALIDUSERAGREEMENT,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(
																requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}// end check user

													// Check certificate PKI
													if (isPKI
															.compareTo(Defines.TRUE) == 0) {
														if (!isCertificateValid(pkiCertificate)) {
															String billCode = ExtFunc
																	.getBillCode();
															String pData = ExtFunc
																	.genResponseMessage(
																			Defines.CODE_INVALIDCERTIFICATE,
																			Defines.ERROR_INVALIDCERTIFICATE,
																			channelName,
																			user,
																			billCode);
															DBConnector
																	.getInstances()
																	.writeLogToDataBaseOutside(
																			functionName,
																			username,
																			ipClient,
																			user,
																			Defines.ERROR_INVALIDCERTIFICATE,
																			Defines.CODE_INVALIDCERTIFICATE,
																			sslSubDn,
																			sslIseDn,
																			sslSnb,
																			idTag,
																			channelName,
																			xmlData,
																			pData,
																			billCode,
																			unsignedData,
																			signedData);
															ResponseData(
																	requestObject,
																	(new TransactionInfo(
																			pData))
																			.toBytes());
															continue;
														}

														String[] certs = ExtFunc
																.getCertificateComponents(pkiCertificate);
														if (DBConnector
																.getInstances()
																.checkPKICertificate(
																		certs[0],
																		channelName)) {
															String billCode = ExtFunc
																	.getBillCode();
															String pData = ExtFunc
																	.genResponseMessage(
																			Defines.CODE_CERTIFICATEEXITED,
																			Defines.ERROR_CERTIFICATEEXITED,
																			channelName,
																			user,
																			billCode);
															DBConnector
																	.getInstances()
																	.writeLogToDataBaseOutside(
																			functionName,
																			username,
																			ipClient,
																			user,
																			Defines.ERROR_CERTIFICATEEXITED,
																			Defines.CODE_CERTIFICATEEXITED,
																			sslSubDn,
																			sslIseDn,
																			sslSnb,
																			idTag,
																			channelName,
																			xmlData,
																			pData,
																			billCode,
																			unsignedData,
																			signedData);
															ResponseData(
																	requestObject,
																	(new TransactionInfo(
																			pData))
																			.toBytes());
															continue;
														}

													} // end check certificate
														// pki

													// OTP
													if (isOtpHardware
															.compareTo(Defines.TRUE) == 0) {

														// Check if serialNumber
														// of OTP token is null
														if (otpHardware
																.compareTo("") == 0) {
															String billCode = ExtFunc
																	.getBillCode();
															String pData = ExtFunc
																	.genResponseMessage(
																			Defines.CODE_INVALIDPARAMETER,
																			Defines.ERROR_INVALIDPARAMETER,
																			channelName,
																			user,
																			billCode);
															DBConnector
																	.getInstances()
																	.writeLogToDataBaseOutside(
																			functionName,
																			username,
																			ipClient,
																			user,
																			Defines.ERROR_INVALIDPARAMETER,
																			Defines.CODE_INVALIDPARAMETER,
																			sslSubDn,
																			sslIseDn,
																			sslSnb,
																			idTag,
																			channelName,
																			xmlData,
																			pData,
																			billCode,
																			unsignedData,
																			signedData);
															ResponseData(
																	requestObject,
																	(new TransactionInfo(
																			pData))
																			.toBytes());
															continue;
														}

														if (DBConnector
																.getInstances()
																.authCheckOTPHardware(
																		otpHardware)) {
															String billCode = ExtFunc
																	.getBillCode();
															String pData = ExtFunc
																	.genResponseMessage(
																			Defines.CODE_OTPHARDWAREEXIT,
																			Defines.ERROR_OTPHARDWAREEXIT,
																			channelName,
																			user,
																			billCode);
															DBConnector
																	.getInstances()
																	.writeLogToDataBaseOutside(
																			functionName,
																			username,
																			ipClient,
																			user,
																			Defines.ERROR_OTPHARDWAREEXIT,
																			Defines.CODE_OTPHARDWAREEXIT,
																			sslSubDn,
																			sslIseDn,
																			sslSnb,
																			idTag,
																			channelName,
																			xmlData,
																			pData,
																			billCode,
																			unsignedData,
																			signedData);
															ResponseData(
																	requestObject,
																	(new TransactionInfo(
																			pData))
																			.toBytes());
															continue;
														}

														otpcore = getOTPCore();
														if (otpcore == null) {
															String billCode = ExtFunc
																	.getBillCode();
															String pData = ExtFunc
																	.genResponseMessage(
																			Defines.CODE_OTPEXCEPTION,
																			Defines.ERROR_OTPEXCEPTION,
																			channelName,
																			user,
																			billCode);
															DBConnector
																	.getInstances()
																	.writeLogToDataBaseOutside(
																			functionName,
																			username,
																			ipClient,
																			user,
																			Defines.ERROR_OTPEXCEPTION,
																			Defines.CODE_OTPEXCEPTION,
																			sslSubDn,
																			sslIseDn,
																			sslSnb,
																			idTag,
																			channelName,
																			xmlData,
																			pData,
																			billCode,
																			unsignedData,
																			signedData);
															ResponseData(
																	requestObject,
																	(new TransactionInfo(
																			pData))
																			.toBytes());
															continue;
														}

														// Check connection
														try {
															if (!otpcore
																	.connectTest(
																			otpcore.getConfig(),
																			false)) {
																LOG.info("OTP Connect test failed!");
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_OTPCONNECTION,
																				Defines.ERROR_OTPCONNECTION,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_OTPCONNECTION,
																				Defines.CODE_OTPCONNECTION,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}

															// Add user to
															// database
															UserInfo userInfo = new UserInfo();
															userInfo.setUserName(user);

															otpcore.addUser(userInfo);
															LOG.info("Add user succeed!");

															// Bind user and
															// token
															otpcore.bind(
																	user,
																	otpHardware,
																	1);
															LOG.info("Bind user and token succeed!");

														} catch (OTPCoreException e) {
															e.printStackTrace();
															String billCode = ExtFunc
																	.getBillCode();
															String pData = ExtFunc
																	.genResponseMessage(
																			Defines.CODE_OTPEXCEPTION,
																			Defines.ERROR_OTPEXCEPTION
																					+ ": "
																					+ e.getMessage(),
																			channelName,
																			user,
																			billCode);
															DBConnector
																	.getInstances()
																	.writeLogToDataBaseOutside(
																			functionName,
																			username,
																			ipClient,
																			user,
																			Defines.ERROR_OTPEXCEPTION
																					+ ": "
																					+ e.getMessage(),
																			Defines.CODE_OTPEXCEPTION,
																			sslSubDn,
																			sslIseDn,
																			sslSnb,
																			idTag,
																			channelName,
																			xmlData,
																			pData,
																			billCode,
																			unsignedData,
																			signedData);
															ResponseData(
																	requestObject,
																	(new TransactionInfo(
																			pData))
																			.toBytes());
															continue;
														}
													}

													// insert agreement
													int agreementID = DBConnector
															.getInstances()
															.insertAgreement(
																	channelName,
																	user,
																	Defines.AGREEMENT_STATUS_ACTI,
																	expire,
																	idTag, branchId);

													if (agreementID == -1) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_CREATEAGREEMENT,
																		Defines.ERROR_CREATEAGREEMENT,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_CREATEAGREEMENT,
																		Defines.CODE_CREATEAGREEMENT,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(
																requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}

													int res;

													res = DBConnector
															.getInstances()
															.insertOTPInformation(
																	agreementID,
																	otpSms,
																	otpEmail,
																	otpHardware,
																	(isOtpEmail
																			.compareTo(Defines.TRUE) == 0),
																	(isOtpSms
																			.compareTo(Defines.TRUE) == 0),
																	(isOtpHardware
																			.compareTo(Defines.TRUE) == 0),
																	(isOtpSoftware
																			.compareTo(Defines.TRUE) == 0));

													if (res == -1) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_INSERTOTPINFORMATION,
																		Defines.ERROR_INSERTOTPINFORMATION,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_INSERTOTPINFORMATION,
																		Defines.CODE_INSERTOTPINFORMATION,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(
																requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}

													if (isPKI
															.compareTo(Defines.TRUE) == 0) {
														String[] certs = ExtFunc
																.getCertificateComponents(pkiCertificate);
														res = DBConnector
																.getInstances()
																.insertPKIInformation(
																		agreementID,
																		certs[0],
																		certs[0].substring(
																				2,
																				4),
																		certs[3],
																		certs[4],
																		getIssuerName(certs[2]),
																		pkiCertificate,
																		(isPKI.compareTo(Defines.TRUE) == 0));
													} else {
														res = DBConnector
																.getInstances()
																.insertPKIInformation(
																		agreementID,
																		Defines.NULL,
																		Defines.NULL,
																		Defines.NULL,
																		Defines.NULL,
																		Defines.NULL,
																		Defines.NULL,
																		(isPKI.compareTo(Defines.TRUE) == 0));
													}

													if (res == -1) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_INSERTPKIINFORMATION,
																		Defines.ERROR_INSERTPKIINFORMATION,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_INSERTPKIINFORMATION,
																		Defines.CODE_INSERTPKIINFORMATION,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(
																requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}
													String billCode = ExtFunc
															.getBillCode();
													String pData = ExtFunc
															.genResponseMessage(
																	Defines.CODE_SUCCESS,
																	Defines.SUCCESS,
																	channelName,
																	user,
																	Defines.AGREEMENT_STATUS_ACTI,
																	billCode);
													DBConnector
															.getInstances()
															.writeLogToDataBaseOutside(
																	functionName,
																	username,
																	ipClient,
																	user,
																	Defines.SUCCESS,
																	Defines.CODE_SUCCESS,
																	sslSubDn,
																	sslIseDn,
																	sslSnb,
																	idTag,
																	channelName,
																	xmlData,
																	pData,
																	billCode,
																	unsignedData,
																	signedData);
													ResponseData(
															requestObject,
															(new TransactionInfo(
																	pData))
																	.toBytes());
													continue;

												} else if (action
														.compareTo(Defines.AGREEMENT_ACTION_CHAINF) == 0) {

													int agreementID = DBConnector
															.getInstances()
															.authGetArrangementID(
																	channelName,
																	user);
													if (agreementID == 0) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_AGREEMENTNOTEXITS,
																		Defines.ERROR_AGREEMENTNOTEXITS,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_AGREEMENTNOTEXITS,
																		Defines.CODE_AGREEMENTNOTEXITS,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(
																requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}

													String isOtpSms = ExtFunc
															.getContent(
																	Defines._ISOTPSMS,
																	xmlData);
													String otpSms = ExtFunc
															.getContent(
																	Defines._OTPSMS,
																	xmlData);

													String isOtpEmail = ExtFunc
															.getContent(
																	Defines._ISOTPEMAIL,
																	xmlData);
													String otpEmail = ExtFunc
															.getContent(
																	Defines._OTPEMAIL,
																	xmlData);

													String isOtpHardware = ExtFunc
															.getContent(
																	Defines._ISOTPHARDWARE,
																	xmlData);
													String otpHardware = ExtFunc
															.getContent(
																	Defines._OTPHARDWARE,
																	xmlData);

													String isPKI = ExtFunc
															.getContent(
																	Defines._ISPKI,
																	xmlData);
													String pkiCertificate = ExtFunc
															.getContent(
																	Defines._CERTIFICATE,
																	xmlData);

													String isOtpSoftware = ExtFunc
															.getContent(
																	Defines._ISOTPSOFTWARE,
																	xmlData);

													String isUnblockOTP = ExtFunc
															.getContent(
																	Defines._ISUNBLOCKOTP,
																	xmlData);

													String expiration = ExtFunc
															.getContent(
																	Defines._EXPIRATION,
																	xmlData);

													String isExtend = ExtFunc
															.getContent(
																	Defines._ISEXTEND,
																	xmlData);

													boolean isEffective = false;

													// OTP SMS
													if (!(isOtpSms
															.compareTo("") == 0)) {
														if (!(isOtpSms
																.compareTo(Defines.TRUE) == 0))
															isOtpSms = Defines.FALSE;
														// Check OTP Method
														if (isOtpSms
																.compareTo(Defines.FALSE) == 0) {
															if (DBConnector
																	.getInstances()
																	.authCheckOTPMethod(
																			channelName,
																			user,
																			Defines._OTPSMS)) {
																LOG.info("Invalid OTP SMS Method");
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_INVALIDOTPMETHOD,
																				Defines.ERROR_INVALIDOTPMETHOD,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_INVALIDOTPMETHOD,
																				Defines.CODE_INVALIDOTPMETHOD,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}
														}

														if (!(otpSms
																.compareTo("") == 0)
																&& (isOtpSms
																		.compareTo(Defines.TRUE) == 0)) {

															if (!ExtFunc
																	.isValidPhoneNumber(otpSms)) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_INVALIDPARAMETER,
																				Defines.ERROR_INVALIDPARAMETER,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_INVALIDPARAMETER,
																				Defines.CODE_INVALIDPARAMETER,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}

															if (DBConnector
																	.getInstances()
																	.authCheckOTPSMS(user,
																			otpSms)) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_USERPHONEEXIT,
																				Defines.ERROR_USERPHONEEXIT,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_USERPHONEEXIT,
																				Defines.CODE_USERPHONEEXIT,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}

															boolean res = DBConnector
																	.getInstances()
																	.authSetIsOTPSMSArrangement(
																			agreementID,
																			(isOtpSms
																					.compareTo(Defines.TRUE) == 0));
															if (!res) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_UPDATEOTPSMS,
																				Defines.ERROR_UPDATEOTPSMS,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_UPDATEOTPSMS,
																				Defines.CODE_UPDATEOTPSMS,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}

															if (!DBConnector
																	.getInstances()
																	.authCheckOTPMethod(
																			channelName,
																			user,
																			Defines._OTPSMS)) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_INVALIDOTPMETHOD,
																				Defines.ERROR_INVALIDOTPMETHOD,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_INVALIDOTPMETHOD,
																				Defines.CODE_INVALIDOTPMETHOD,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															} else {
																res = DBConnector
																		.getInstances()
																		.authSetOTPSMSArrangement(
																				agreementID,
																				otpSms);
																isEffective = true;
																if (!res) {
																	String billCode = ExtFunc
																			.getBillCode();
																	String pData = ExtFunc
																			.genResponseMessage(
																					Defines.CODE_UPDATEOTPSMS,
																					Defines.ERROR_UPDATEOTPSMS,
																					channelName,
																					user,
																					billCode);
																	DBConnector
																			.getInstances()
																			.writeLogToDataBaseOutside(
																					functionName,
																					username,
																					ipClient,
																					user,
																					Defines.ERROR_UPDATEOTPSMS,
																					Defines.CODE_UPDATEOTPSMS,
																					sslSubDn,
																					sslIseDn,
																					sslSnb,
																					idTag,
																					channelName,
																					xmlData,
																					pData,
																					billCode,
																					unsignedData,
																					signedData);
																	ResponseData(
																			requestObject,
																			(new TransactionInfo(
																					pData))
																					.toBytes());
																	continue;
																}
															}
														} else if ((otpSms
																.compareTo("") == 0)
																&& (isOtpSms
																		.compareTo(Defines.TRUE) == 0)) {
															String billCode = ExtFunc
																	.getBillCode();
															String pData = ExtFunc
																	.genResponseMessage(
																			Defines.CODE_INVALIDPARAMETER,
																			Defines.ERROR_INVALIDPARAMETER,
																			channelName,
																			user,
																			billCode);
															DBConnector
																	.getInstances()
																	.writeLogToDataBaseOutside(
																			functionName,
																			username,
																			ipClient,
																			user,
																			Defines.ERROR_INVALIDPARAMETER,
																			Defines.CODE_INVALIDPARAMETER,
																			sslSubDn,
																			sslIseDn,
																			sslSnb,
																			idTag,
																			channelName,
																			xmlData,
																			pData,
																			billCode,
																			unsignedData,
																			signedData);
															ResponseData(
																	requestObject,
																	(new TransactionInfo(
																			pData))
																			.toBytes());
															continue;
														}
													} // end otp sms

													// OTPEmail
													if (!(isOtpEmail
															.compareTo("") == 0)) {
														if (!(isOtpEmail
																.compareTo(Defines.TRUE) == 0))
															isOtpEmail = Defines.FALSE;
														// Check OTP Method
														if (isOtpEmail
																.compareTo(Defines.FALSE) == 0) {
															if (DBConnector
																	.getInstances()
																	.authCheckOTPMethod(
																			channelName,
																			user,
																			Defines._OTPEMAIL)) {
																LOG.info("Invalid OTP Email Method");
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_INVALIDOTPMETHOD,
																				Defines.ERROR_INVALIDOTPMETHOD,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_INVALIDOTPMETHOD,
																				Defines.CODE_INVALIDOTPMETHOD,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}
														}

														if (!(otpEmail
																.compareTo("") == 0)
																&& (isOtpEmail
																		.compareTo(Defines.TRUE) == 0)) {

															if (!ExtFunc
																	.isValidEmail(otpEmail)) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_INVALIDPARAMETER,
																				Defines.ERROR_INVALIDPARAMETER,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_INVALIDPARAMETER,
																				Defines.CODE_INVALIDPARAMETER,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}

															if (DBConnector
																	.getInstances()
																	.authCheckOTPEmail(user,
																			otpEmail)) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_USEREMAILEXIT,
																				Defines.ERROR_USEREMAILEXIT,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_USEREMAILEXIT,
																				Defines.CODE_USEREMAILEXIT,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}

															boolean res = DBConnector
																	.getInstances()
																	.authSetIsOTPEmailArrangement(
																			agreementID,
																			(isOtpEmail
																					.compareTo(Defines.TRUE) == 0));
															if (!res) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_UPDATEOTPEMAIL,
																				Defines.ERROR_UPDATEOTPEMAIL,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_UPDATEOTPEMAIL,
																				Defines.CODE_UPDATEOTPEMAIL,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}

															if (!DBConnector
																	.getInstances()
																	.authCheckOTPMethod(
																			channelName,
																			user,
																			Defines._OTPEMAIL)) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_INVALIDOTPMETHOD,
																				Defines.ERROR_INVALIDOTPMETHOD,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_INVALIDOTPMETHOD,
																				Defines.CODE_INVALIDOTPMETHOD,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															} else {
																res = DBConnector
																		.getInstances()
																		.authSetOTPEmailArrangement(
																				agreementID,
																				otpEmail);
																isEffective = true;
																if (!res) {
																	String billCode = ExtFunc
																			.getBillCode();
																	String pData = ExtFunc
																			.genResponseMessage(
																					Defines.CODE_UPDATEOTPEMAIL,
																					Defines.ERROR_UPDATEOTPEMAIL,
																					channelName,
																					user,
																					billCode);
																	DBConnector
																			.getInstances()
																			.writeLogToDataBaseOutside(
																					functionName,
																					username,
																					ipClient,
																					user,
																					Defines.ERROR_UPDATEOTPEMAIL,
																					Defines.CODE_UPDATEOTPEMAIL,
																					sslSubDn,
																					sslIseDn,
																					sslSnb,
																					idTag,
																					channelName,
																					xmlData,
																					pData,
																					billCode,
																					unsignedData,
																					signedData);
																	ResponseData(
																			requestObject,
																			(new TransactionInfo(
																					pData))
																					.toBytes());
																	continue;
																}
															}
														} else if ((otpEmail
																.compareTo("") == 0)
																&& (isOtpEmail
																		.compareTo(Defines.TRUE) == 0)) {
															String billCode = ExtFunc
																	.getBillCode();
															String pData = ExtFunc
																	.genResponseMessage(
																			Defines.CODE_INVALIDPARAMETER,
																			Defines.ERROR_INVALIDPARAMETER,
																			channelName,
																			user,
																			billCode);
															DBConnector
																	.getInstances()
																	.writeLogToDataBaseOutside(
																			functionName,
																			username,
																			ipClient,
																			user,
																			Defines.ERROR_INVALIDPARAMETER,
																			Defines.CODE_INVALIDPARAMETER,
																			sslSubDn,
																			sslIseDn,
																			sslSnb,
																			idTag,
																			channelName,
																			xmlData,
																			pData,
																			billCode,
																			unsignedData,
																			signedData);
															ResponseData(
																	requestObject,
																	(new TransactionInfo(
																			pData))
																			.toBytes());
															continue;
														}
													} // end OTP email

													// OTP hardware
													if (!(isOtpHardware
															.compareTo("") == 0)) {
														if (!(isOtpHardware
																.compareTo(Defines.TRUE) == 0))
															isOtpHardware = Defines.FALSE;
														// Check OTP Method
														if (isOtpHardware
																.compareTo(Defines.FALSE) == 0) {
															if (DBConnector
																	.getInstances()
																	.authCheckOTPMethod(
																			channelName,
																			user,
																			Defines._OTPHARDWARE)) {
																LOG.info("Invalid OTP Hardware Method");
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_INVALIDOTPMETHOD,
																				Defines.ERROR_INVALIDOTPMETHOD,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_INVALIDOTPMETHOD,
																				Defines.CODE_INVALIDOTPMETHOD,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}
														}

														if (!(otpHardware
																.compareTo("") == 0)
																&& (isOtpHardware
																		.compareTo(Defines.TRUE) == 0)) {
															boolean res = DBConnector
																	.getInstances()
																	.authSetIsOTPHardwareArrangement(
																			agreementID,
																			(isOtpHardware
																					.compareTo(Defines.TRUE) == 0));
															if (!res) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_UPDATEOTPHARDWARE,
																				Defines.ERROR_UPDATEOTPHARDWARE,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_UPDATEOTPHARDWARE,
																				Defines.CODE_UPDATEOTPHARDWARE,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}
															if (!DBConnector
																	.getInstances()
																	.authCheckOTPMethod(
																			channelName,
																			user,
																			Defines._OTPHARDWARE)) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_INVALIDOTPMETHOD,
																				Defines.ERROR_INVALIDOTPMETHOD,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_INVALIDOTPMETHOD,
																				Defines.CODE_INVALIDOTPMETHOD,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}

															if (DBConnector
																	.getInstances()
																	.authCheckOTPHardware(
																			otpHardware)) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_OTPHARDWAREEXIT,
																				Defines.ERROR_OTPHARDWAREEXIT,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_OTPHARDWAREEXIT,
																				Defines.CODE_OTPHARDWAREEXIT,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}

															String olderOtpHardware = DBConnector
																	.getInstances()
																	.authGetOTPHardware(
																			channelName,
																			user);
															if (olderOtpHardware
																	.compareTo("") == 0) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_ERRORGETOLDOTP,
																				Defines.ERROR_ERRORGETOLDOTP,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_ERRORGETOLDOTP,
																				Defines.CODE_ERRORGETOLDOTP,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}

															otpcore = getOTPCore();
															if (otpcore == null) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_OTPEXCEPTION,
																				Defines.ERROR_OTPEXCEPTION,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_OTPEXCEPTION,
																				Defines.CODE_OTPEXCEPTION,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}

															try {
																List<UserInfo> users = otpcore
																		.getUserInfo(user);
																if (users
																		.size() == 0) {
																	UserInfo userInfo = new UserInfo();
																	userInfo.setUserName(user);
																	otpcore.addUser(userInfo);
																	otpcore.bind(
																			user,
																			otpHardware,
																			1);
																} else {
																	otpcore.unbind(
																			user,
																			olderOtpHardware);
																	otpcore.bind(
																			user,
																			otpHardware,
																			1);
																}

															} catch (OTPCoreException e) {
																e.printStackTrace();
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_OTPEXCEPTION,
																				Defines.ERROR_OTPEXCEPTION
																						+ ": "
																						+ e.getMessage(),
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_OTPEXCEPTION
																						+ ": "
																						+ e.getMessage(),
																				Defines.CODE_OTPEXCEPTION,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}

															boolean resHOTP = DBConnector
																	.getInstances()
																	.authSetOTPHardwareArrangement(
																			agreementID,
																			otpHardware);
															isEffective = true;
															if (!resHOTP) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_UPDATEOTPHARDWARE,
																				Defines.ERROR_UPDATEOTPHARDWARE,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_UPDATEOTPHARDWARE,
																				Defines.CODE_UPDATEOTPHARDWARE,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}
														} else if ((otpHardware
																.compareTo("") == 0)
																&& (isOtpHardware
																		.compareTo(Defines.TRUE) == 0)) {
															String billCode = ExtFunc
																	.getBillCode();
															String pData = ExtFunc
																	.genResponseMessage(
																			Defines.CODE_INVALIDPARAMETER,
																			Defines.ERROR_INVALIDPARAMETER,
																			channelName,
																			user,
																			billCode);
															DBConnector
																	.getInstances()
																	.writeLogToDataBaseOutside(
																			functionName,
																			username,
																			ipClient,
																			user,
																			Defines.ERROR_INVALIDPARAMETER,
																			Defines.CODE_INVALIDPARAMETER,
																			sslSubDn,
																			sslIseDn,
																			sslSnb,
																			idTag,
																			channelName,
																			xmlData,
																			pData,
																			billCode,
																			unsignedData,
																			signedData);
															ResponseData(
																	requestObject,
																	(new TransactionInfo(
																			pData))
																			.toBytes());
															continue;
														}
													} // End OTP Hardware

													// OTP Software
													if (!(isOtpSoftware
															.compareTo("") == 0)) {
														if (!(isOtpSoftware
																.compareTo(Defines.TRUE) == 0))
															isOtpSoftware = Defines.FALSE;
														boolean res = DBConnector
																.getInstances()
																.authSetIsOTPSoftwareArrangement(
																		agreementID,
																		(isOtpSoftware
																				.compareTo(Defines.TRUE) == 0));
														if (!res) {
															String billCode = ExtFunc
																	.getBillCode();
															String pData = ExtFunc
																	.genResponseMessage(
																			Defines.CODE_UPDATEOTPSOFTWARE,
																			Defines.ERROR_UPDATEOTPSOFTWARE,
																			channelName,
																			user,
																			billCode);
															DBConnector
																	.getInstances()
																	.writeLogToDataBaseOutside(
																			functionName,
																			username,
																			ipClient,
																			user,
																			Defines.ERROR_UPDATEOTPSOFTWARE,
																			Defines.CODE_UPDATEOTPSOFTWARE,
																			sslSubDn,
																			sslIseDn,
																			sslSnb,
																			idTag,
																			channelName,
																			xmlData,
																			pData,
																			billCode,
																			unsignedData,
																			signedData);
															ResponseData(
																	requestObject,
																	(new TransactionInfo(
																			pData))
																			.toBytes());
															continue;
														}
														isEffective = true;
													} // End otp software

													// PKI
													if (!(isPKI.compareTo("") == 0)) {
														if (!(isPKI
																.compareTo(Defines.TRUE) == 0))
															isPKI = Defines.FALSE;
														// Check PKI method
														if (isPKI
																.compareTo(Defines.FALSE) == 0) {
															if (DBConnector
																	.getInstances()
																	.authCheckPKIArrangement(
																			agreementID)) {
																LOG.info("Invalid PKI Method");
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_INVALIDPKIMETHOD,
																				Defines.ERROR_INVALIDPKIMETHOD,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_INVALIDPKIMETHOD,
																				Defines.CODE_INVALIDPKIMETHOD,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}
														}

														if (!(pkiCertificate
																.compareTo("") == 0)
																&& (isPKI
																		.compareTo(Defines.TRUE) == 0)) {
															boolean res = DBConnector
																	.getInstances()
																	.authSetIsPKIArrangement(
																			agreementID,
																			(isPKI.compareTo(Defines.TRUE) == 0));
															if (!res) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_UPDATEPKI,
																				Defines.ERROR_UPDATEPKI,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_UPDATEPKI,
																				Defines.CODE_UPDATEPKI,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}

															res = DBConnector
																	.getInstances()
																	.authCheckPKIArrangement(
																			agreementID);
															if (!res) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_NOPKIAGREEMENT,
																				Defines.ERROR_NOPKIAGREEMENT,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_NOPKIAGREEMENT,
																				Defines.CODE_NOPKIAGREEMENT,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															} else {
																if (!isCertificateValid(pkiCertificate)) {
																	String billCode = ExtFunc
																			.getBillCode();
																	String pData = ExtFunc
																			.genResponseMessage(
																					Defines.CODE_INVALIDCERTIFICATE,
																					Defines.ERROR_INVALIDCERTIFICATE,
																					channelName,
																					user,
																					billCode);
																	DBConnector
																			.getInstances()
																			.writeLogToDataBaseOutside(
																					functionName,
																					username,
																					ipClient,
																					user,
																					Defines.ERROR_INVALIDCERTIFICATE,
																					Defines.CODE_INVALIDCERTIFICATE,
																					sslSubDn,
																					sslIseDn,
																					sslSnb,
																					idTag,
																					channelName,
																					xmlData,
																					pData,
																					billCode,
																					unsignedData,
																					signedData);
																	ResponseData(
																			requestObject,
																			(new TransactionInfo(
																					pData))
																					.toBytes());
																	continue;
																} else {
																	String[] certs = ExtFunc
																			.getCertificateComponents(pkiCertificate);

																	if (DBConnector
																			.getInstances()
																			.checkPKICertificate(
																					certs[0],
																					channelName)) {
																		String billCode = ExtFunc
																				.getBillCode();
																		String pData = ExtFunc
																				.genResponseMessage(
																						Defines.CODE_CERTIFICATEEXITED,
																						Defines.ERROR_CERTIFICATEEXITED,
																						channelName,
																						user,
																						billCode);
																		DBConnector
																				.getInstances()
																				.writeLogToDataBaseOutside(
																						functionName,
																						username,
																						ipClient,
																						user,
																						Defines.ERROR_CERTIFICATEEXITED,
																						Defines.CODE_CERTIFICATEEXITED,
																						sslSubDn,
																						sslIseDn,
																						sslSnb,
																						idTag,
																						channelName,
																						xmlData,
																						pData,
																						billCode,
																						unsignedData,
																						signedData);
																		ResponseData(
																				requestObject,
																				(new TransactionInfo(
																						pData))
																						.toBytes());
																		continue;
																	}

																	res = DBConnector
																			.getInstances()
																			.authSetCertificateArrangement(
																					agreementID,
																					certs[0],
																					certs[0].substring(
																							2,
																							4),
																					certs[3],
																					certs[4],
																					getIssuerName(certs[2]),
																					pkiCertificate);
																	isEffective = true;
																	if (!res) {
																		String billCode = ExtFunc
																				.getBillCode();
																		String pData = ExtFunc
																				.genResponseMessage(
																						Defines.CODE_UPDATEPKI,
																						Defines.ERROR_UPDATEPKI,
																						channelName,
																						user,
																						billCode);
																		DBConnector
																				.getInstances()
																				.writeLogToDataBaseOutside(
																						functionName,
																						username,
																						ipClient,
																						user,
																						Defines.ERROR_UPDATEPKI,
																						Defines.CODE_UPDATEPKI,
																						sslSubDn,
																						sslIseDn,
																						sslSnb,
																						idTag,
																						channelName,
																						xmlData,
																						pData,
																						billCode,
																						unsignedData,
																						signedData);
																		ResponseData(
																				requestObject,
																				(new TransactionInfo(
																						pData))
																						.toBytes());
																		continue;
																	}

																}
															}
														} else if ((pkiCertificate
																.compareTo("") == 0)
																&& (isPKI
																		.compareTo(Defines.TRUE) == 0)) {
															String billCode = ExtFunc
																	.getBillCode();
															String pData = ExtFunc
																	.genResponseMessage(
																			Defines.CODE_INVALIDPARAMETER,
																			Defines.ERROR_INVALIDPARAMETER,
																			channelName,
																			user,
																			billCode);
															DBConnector
																	.getInstances()
																	.writeLogToDataBaseOutside(
																			functionName,
																			username,
																			ipClient,
																			user,
																			Defines.ERROR_INVALIDPARAMETER,
																			Defines.CODE_INVALIDPARAMETER,
																			sslSubDn,
																			sslIseDn,
																			sslSnb,
																			idTag,
																			channelName,
																			xmlData,
																			pData,
																			billCode,
																			unsignedData,
																			signedData);
															ResponseData(
																	requestObject,
																	(new TransactionInfo(
																			pData))
																			.toBytes());
															continue;
														}
													} // End PKI updated

													// Unblock OTP
													if (!(isUnblockOTP
															.compareTo("") == 0)) {
														if (isUnblockOTP
																.compareTo(Defines.TRUE) == 0) {
															boolean res = DBConnector
																	.getInstances()
																	.authCheckOTPArrangement(
																			agreementID);
															if (!res) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_NOOTPAGREEMENT,
																				Defines.ERROR_NOOTPAGREEMENT,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_NOOTPAGREEMENT,
																				Defines.CODE_NOOTPAGREEMENT,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}

															String _olderOtpHardware = DBConnector
																	.getInstances()
																	.authGetOTPHardware(
																			channelName,
																			user);
															if (_olderOtpHardware
																	.compareTo("") == 0) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_ERRORGETOLDOTP,
																				Defines.ERROR_ERRORGETOLDOTP,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_ERRORGETOLDOTP,
																				Defines.CODE_ERRORGETOLDOTP,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}

															otpcore = getOTPCore();
															if (otpcore == null) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_OTPEXCEPTION,
																				Defines.ERROR_OTPEXCEPTION,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_OTPEXCEPTION,
																				Defines.CODE_OTPEXCEPTION,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}

															try {
																otpcore.setTokenLocked(
																		_olderOtpHardware,
																		0);
																DBConnector
																		.getInstances()
																		.resetErrorCounterHWOTP(
																				channelName,
																				user);
																isEffective = true;
															} catch (OTPCoreException e) {
																e.printStackTrace();
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_OTPEXCEPTION,
																				Defines.ERROR_OTPEXCEPTION
																						+ ": "
																						+ e.getMessage(),
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_OTPEXCEPTION
																						+ ": "
																						+ e.getMessage(),
																				Defines.CODE_OTPEXCEPTION,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}

														}

													} // End IsUnblock OTP

													// Extend
													if (!(isExtend
															.compareTo("") == 0)) {
														if (isExtend
																.compareTo(Defines.TRUE) == 0) {
															int expire = 0;
															try {
																expire = Integer
																		.parseInt(expiration);
															} catch (NumberFormatException e) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_INVALIDPARAMETER,
																				Defines.ERROR_INVALIDPARAMETER,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_INVALIDPARAMETER,
																				Defines.CODE_INVALIDPARAMETER,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}
															if (expire <= 0) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_INVALIDPARAMETER,
																				Defines.ERROR_INVALIDPARAMETER,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_INVALIDPARAMETER,
																				Defines.CODE_INVALIDPARAMETER,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}
															boolean res = DBConnector
																	.getInstances()
																	.authSetExtendArrangement(
																			agreementID,
																			channelName,
																			expire);
															isEffective = true;
															if (!res) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_UPDATEEXTEND,
																				Defines.ERROR_UPDATEEXTEND,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_UPDATEEXTEND,
																				Defines.CODE_UPDATEEXTEND,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}
														}

													} // end extend

													if (isEffective) {
														// Done
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_SUCCESS,
																		Defines.SUCCESS,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.SUCCESS,
																		Defines.CODE_SUCCESS,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(
																requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}
													// Done
													String billCode = ExtFunc
															.getBillCode();
													String pData = ExtFunc
															.genResponseMessage(
																	Defines.CODE_UNCHANGEDAGREEMENT,
																	Defines.INFO_UNCHANGEAGREEMENT,
																	channelName,
																	user,
																	billCode);
													DBConnector
															.getInstances()
															.writeLogToDataBaseOutside(
																	functionName,
																	username,
																	ipClient,
																	user,
																	Defines.INFO_UNCHANGEAGREEMENT,
																	Defines.CODE_UNCHANGEDAGREEMENT,
																	sslSubDn,
																	sslIseDn,
																	sslSnb,
																	idTag,
																	channelName,
																	xmlData,
																	pData,
																	billCode,
																	unsignedData,
																	signedData);
													ResponseData(
															requestObject,
															(new TransactionInfo(
																	pData))
																	.toBytes());
													continue;

												} else if (action
														.compareTo(Defines.AGREEMENT_ACTION_UNREG) == 0) {
													int agreementID = DBConnector
															.getInstances()
															.authGetArrangementID(
																	channelName,
																	user);
													if (agreementID == 0) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_AGREEMENTNOTEXITS,
																		Defines.ERROR_AGREEMENTNOTEXITS,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_AGREEMENTNOTEXITS,
																		Defines.CODE_AGREEMENTNOTEXITS,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(
																requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}

													String agreementStatus = ExtFunc
															.getContent(
																	Defines._AGREEMENTSTATUS,
																	xmlData);
													if (agreementStatus
															.compareTo("") == 0) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_INVALIDPARAMETER,
																		Defines.ERROR_INVALIDPARAMETER,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_INVALIDPARAMETER,
																		Defines.CODE_INVALIDPARAMETER,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(
																requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}

													if (agreementStatus
															.compareTo(Defines.AGREEMENT_STATUS_CANC) == 0) {
														String olderOtpHardware = DBConnector
																.getInstances()
																.authGetOTPHardware(
																		channelName,
																		user);
														if (olderOtpHardware
																.compareTo("") == 0) {
															String billCode = ExtFunc
																	.getBillCode();
															String pData = ExtFunc
																	.genResponseMessage(
																			Defines.CODE_ERRORGETOLDOTP,
																			Defines.ERROR_ERRORGETOLDOTP,
																			channelName,
																			user,
																			billCode);
															DBConnector
																	.getInstances()
																	.writeLogToDataBaseOutside(
																			functionName,
																			username,
																			ipClient,
																			user,
																			Defines.ERROR_ERRORGETOLDOTP,
																			Defines.CODE_ERRORGETOLDOTP,
																			sslSubDn,
																			sslIseDn,
																			sslSnb,
																			idTag,
																			channelName,
																			xmlData,
																			pData,
																			billCode,
																			unsignedData,
																			signedData);
															ResponseData(
																	requestObject,
																	(new TransactionInfo(
																			pData))
																			.toBytes());
															continue;
														}
														if (!(olderOtpHardware
																.compareTo(Defines.NULL) == 0)) {
															otpcore = getOTPCore();
															if (otpcore == null) {
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_OTPEXCEPTION,
																				Defines.ERROR_OTPEXCEPTION,
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_OTPEXCEPTION,
																				Defines.CODE_OTPEXCEPTION,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}

															try {
																otpcore.unbind(
																		user,
																		olderOtpHardware);
																otpcore.delUser(user);
															} catch (OTPCoreException e) {
																e.printStackTrace();
																String billCode = ExtFunc
																		.getBillCode();
																String pData = ExtFunc
																		.genResponseMessage(
																				Defines.CODE_OTPEXCEPTION,
																				Defines.ERROR_OTPEXCEPTION
																						+ ": "
																						+ e.getMessage(),
																				channelName,
																				user,
																				billCode);
																DBConnector
																		.getInstances()
																		.writeLogToDataBaseOutside(
																				functionName,
																				username,
																				ipClient,
																				user,
																				Defines.ERROR_OTPEXCEPTION
																						+ ": "
																						+ e.getMessage(),
																				Defines.CODE_OTPEXCEPTION,
																				sslSubDn,
																				sslIseDn,
																				sslSnb,
																				idTag,
																				channelName,
																				xmlData,
																				pData,
																				billCode,
																				unsignedData,
																				signedData);
																ResponseData(
																		requestObject,
																		(new TransactionInfo(
																				pData))
																				.toBytes());
																continue;
															}
														}
													}

													int updateAgreement = DBConnector
															.getInstances()
															.authUpdateAgreement(
																	agreementID,
																	channelName,
																	agreementStatus);
													if (updateAgreement == 1) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_INVALIDAGREESTATUS,
																		Defines.ERROR_INVALIDAGREESTATUS,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_INVALIDAGREESTATUS,
																		Defines.CODE_INVALIDAGREESTATUS,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(
																requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}
													// Done unregistration
													String billCode = ExtFunc
															.getBillCode();
													String pData = ExtFunc
															.genResponseMessage(
																	Defines.CODE_SUCCESS,
																	Defines.SUCCESS,
																	channelName,
																	user,
																	billCode);
													DBConnector
															.getInstances()
															.writeLogToDataBaseOutside(
																	functionName,
																	username,
																	ipClient,
																	user,
																	Defines.SUCCESS,
																	Defines.CODE_SUCCESS,
																	sslSubDn,
																	sslIseDn,
																	sslSnb,
																	idTag,
																	channelName,
																	xmlData,
																	pData,
																	billCode,
																	unsignedData,
																	signedData);
													ResponseData(
															requestObject,
															(new TransactionInfo(
																	pData))
																	.toBytes());
													continue;

												} else if (action
														.compareTo(Defines.AGREEMENT_ACTION_VALIDA) == 0) {
													String certificate = ExtFunc
															.getContent(
																	Defines._CERTIFICATE,
																	xmlData);
													if (certificate
															.compareTo("") == 0) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_INVALIDPARAMETER,
																		Defines.ERROR_INVALIDPARAMETER,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_INVALIDPARAMETER,
																		Defines.CODE_INVALIDPARAMETER,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(
																requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}

													if (!isCertificateValid(certificate)) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_INVALIDCERTIFICATE,
																		Defines.ERROR_INVALIDCERTIFICATE,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_INVALIDCERTIFICATE,
																		Defines.CODE_INVALIDCERTIFICATE,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(
																requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}

													String certs[] = ExtFunc
															.getCertificateComponents(certificate);

													String res = DBConnector
															.getInstances()
															.authAgreementValidation(
																	certs[0],
																	getIssuerName(certs[2]));
													String pCode = res
															.split("#")[0];
													String pMess = res
															.split("#")[1];

													if ((pCode.compareTo("1") == 0)
															|| (pCode
																	.compareTo("3") == 0)) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_NOPKIAGREEMENT,
																		Defines.ERROR_NOPKIAGREEMENT,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_NOPKIAGREEMENT,
																		Defines.CODE_NOPKIAGREEMENT,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(
																requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}

													if ((pCode.compareTo("2") == 0)
															|| (pCode
																	.compareTo("4") == 0)
															|| (pCode
																	.compareTo("5") == 0)) {
														String billCode = ExtFunc
																.getBillCode();
														String pData = ExtFunc
																.genResponseMessage(
																		Defines.CODE_AGREEMENTNOTREADY,
																		Defines.ERROR_AGREEMENTNOTREADY,
																		channelName,
																		user,
																		billCode);
														DBConnector
																.getInstances()
																.writeLogToDataBaseOutside(
																		functionName,
																		username,
																		ipClient,
																		user,
																		Defines.ERROR_AGREEMENTNOTREADY,
																		Defines.CODE_AGREEMENTNOTREADY,
																		sslSubDn,
																		sslIseDn,
																		sslSnb,
																		idTag,
																		channelName,
																		xmlData,
																		pData,
																		billCode,
																		unsignedData,
																		signedData);
														ResponseData(
																requestObject,
																(new TransactionInfo(
																		pData))
																		.toBytes());
														continue;
													}
													String billCode = ExtFunc
															.getBillCode();
													String pData = ExtFunc
															.genResponseMessage(
																	Defines.CODE_SUCCESS,
																	Defines.SUCCESS,
																	channelName,
																	pMess,
																	billCode);
													DBConnector
															.getInstances()
															.writeLogToDataBaseOutside(
																	functionName,
																	username,
																	ipClient,
																	pMess,
																	Defines.SUCCESS,
																	Defines.CODE_SUCCESS,
																	sslSubDn,
																	sslIseDn,
																	sslSnb,
																	idTag,
																	channelName,
																	xmlData,
																	pData,
																	billCode,
																	unsignedData,
																	signedData);
													ResponseData(
															requestObject,
															(new TransactionInfo(
																	pData))
																	.toBytes());
													continue;

												} else {
													// Invalid action
													String billCode = ExtFunc
															.getBillCode();
													String pData = ExtFunc
															.genResponseMessage(
																	Defines.CODE_INVALIDACTION,
																	Defines.ERROR_INVALIDACTION,
																	channelName,
																	user,
																	billCode);
													DBConnector
															.getInstances()
															.writeLogToDataBaseOutside(
																	functionName,
																	username,
																	ipClient,
																	user,
																	Defines.ERROR_INVALIDACTION,
																	Defines.CODE_INVALIDACTION,
																	sslSubDn,
																	sslIseDn,
																	sslSnb,
																	idTag,
																	channelName,
																	xmlData,
																	pData,
																	billCode,
																	unsignedData,
																	signedData);
													ResponseData(
															requestObject,
															(new TransactionInfo(
																	pData))
																	.toBytes());
													continue;
												}
											}
										}
									} else {
										String billCode = ExtFunc.getBillCode();
										String pData = ExtFunc
												.genResponseMessage(
														Defines.CODE_INVALIDCHANNEL,
														Defines.ERROR_INVALIDCHANNEL,
														channelName, user,
														billCode);
										DBConnector
												.getInstances()
												.writeLogToDataBaseOutside(
														functionName,
														username,
														ipClient,
														user,
														Defines.ERROR_INVALIDCHANNEL,
														Defines.CODE_INVALIDCHANNEL,
														sslSubDn, sslIseDn,
														sslSnb, idTag,
														channelName, xmlData,
														pData, billCode,
														unsignedData,
														signedData);
										result = pData;
									}
									ResponseData(requestObject,
											(new TransactionInfo(result))
													.toBytes());
									continue;
								} // cagCredential not null
							} // xmlData and fileData not null
						}
						// Thread.sleep(500);
					} catch (Exception ex) {
						ex.printStackTrace();
						String billCode = ExtFunc.getBillCode();
						String pData = ExtFunc.genResponseMessage(
								Defines.CODE_UNKNOWN, Defines.ERROR_UNKNOWN
										+ ": " + ex.getMessage(), "", "",
								billCode);
						DBConnector.getInstances().writeLogToDataBaseOutside(
								"processData", "", "", "",
								Defines.ERROR_UNKNOWN + ": " + ex.getMessage(),
								Defines.CODE_UNKNOWN, "", "", "", "", "", "",
								pData, billCode, "", "");
						ResponseData(requestObject,
								(new TransactionInfo(pData)).toBytes());
						continue;
					}
				}

			}
		}).start();

	}

	private static IWorkerSession.ILocal getWorkerSession() {
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

	private static int getWorkerId(String workerIdOrName) {
		final int retval;

		if (workerIdOrName.substring(0, 1).matches("\\d")) {
			retval = Integer.parseInt(workerIdOrName);
		} else {
			retval = getWorkerSession().getWorkerId(workerIdOrName);
		}
		return retval;
	}

	private static void ResponseData(SocketRequestObject requestObject,
			byte[] byteData) {
		// LOG.info("ReponseData and close connection...");
		String timeSystem = requestObject.getTimeSystem();
		Session mSession = SessionManager.getInstance().getSession(timeSystem);
		if (mSession != null) {
			ChannelHandlerContext ctx = mSession.getContext();
			Channel c = ctx.channel();
			ByteBuf outBuf = c.alloc().buffer(4);
			outBuf.writeBytes(byteData);
			c.writeAndFlush(outBuf);
			ctx.close();
			SessionManager.getInstance().removeSession(timeSystem);
		}
		DBConnector.getInstances().SocketSetStatusRequest(timeSystem);
	}

	private static List<Metadata> getMetaData(String metaData) {
		List<Metadata> listMD = new ArrayList<Metadata>();
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
				if (!(element.getNodeName().compareTo("MetaData") == 0)) {
					// LOG.info("MetaData Name: "+ element.getNodeName());
					// LOG.info("MetaData Value: "+ element.getTextContent());
					Metadata tmp = new Metadata(element.getNodeName(),
							element.getTextContent());
					listMD.add(tmp);

				}
			}

		} catch (Exception e) {
			listMD = null;
		}
		return listMD;
	}

	private static int getWorkerType(String workerName, String otpMethod) {
		if (workerName.indexOf("Signer") != -1
				|| (workerName.indexOf("Validator") != -1 && workerName
						.indexOf("OATH") == -1))
			return 2; // PKI

		if (workerName.indexOf("OATH") != -1) {
			if ((workerName.compareTo(Defines.WORKER_OATHVALIDATOR) == 0)
					|| (workerName.compareTo(Defines.WORKER_OATHSYNC) == 0))
				return 1;// otp hardware information
			else {
				if (otpMethod.compareTo(Defines._OTPEMAIL) == 0)
					return 3; // otp email
				else
					return 4; // otp sms
			}
		}
		return 5; // agreement
	}

	private static RequestContext handleRequestContext(String ipAdress,
			final List<Metadata> requestMetadata, final int workerId) {
		/*
		 * final HttpServletRequest servletRequest = (HttpServletRequest)
		 * wsContext .getMessageContext().get(MessageContext.SERVLET_REQUEST);
		 * String requestIP = ipAdress; X509Certificate clientCertificate =
		 * getClientCertificate(); final RequestContext requestContext = new
		 * RequestContext( clientCertificate, requestIP);
		 * 
		 * IClientCredential credential;
		 * 
		 * if (clientCertificate instanceof X509Certificate) { final
		 * X509Certificate cert = (X509Certificate) clientCertificate;
		 * LOG.debug("Authentication: certificate"); credential = new
		 * CertificateClientCredential(cert.getSerialNumber() .toString(16),
		 * cert.getIssuerDN().getName()); } else { // Check is client supplied
		 * basic-credentials final String authorization = servletRequest
		 * .getHeader(HTTP_AUTH_BASIC_AUTHORIZATION); if (authorization != null)
		 * { LOG.debug("Authentication: password");
		 * 
		 * final String decoded[] = new String(Base64.decode(authorization
		 * .split("\\s")[1])).split(":", 2);
		 * 
		 * credential = new UsernamePasswordClientCredential(decoded[0],
		 * decoded[1]); } else { LOG.debug("Authentication: none"); credential =
		 * null; } } requestContext.put(RequestContext.CLIENT_CREDENTIAL,
		 * credential);
		 */
		final RequestContext requestContext = new RequestContext();
		/*
		 * final LogMap logMap = LogMap.getInstance(requestContext);
		 * 
		 * // Add HTTP specific log entries logMap.put(
		 * IWorkerLogger.LOG_REQUEST_FULLURL,
		 * servletRequest.getRequestURL().append("?")
		 * .append(servletRequest.getQueryString()).toString());
		 * logMap.put(IWorkerLogger.LOG_REQUEST_LENGTH,
		 * servletRequest.getHeader("Content-Length"));
		 * logMap.put(IWorkerLogger.LOG_XFORWARDEDFOR,
		 * servletRequest.getHeader("X-Forwarded-For"));
		 * 
		 * logMap.put(IWorkerLogger.LOG_WORKER_NAME,
		 * getWorkerSession().getCurrentWorkerConfig(workerId)
		 * .getProperty(ProcessableConfig.NAME));
		 */
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
				// logMap.put(IWorkerLogger.LOG_FILENAME, fileName);
			}
		}

		return requestContext;
	}

	/*
	 * private X509Certificate getClientCertificate() { MessageContext
	 * msgContext = wsContext.getMessageContext(); HttpServletRequest request =
	 * (HttpServletRequest) msgContext .get(MessageContext.SERVLET_REQUEST);
	 * X509Certificate[] certificates = (X509Certificate[]) request
	 * .getAttribute("javax.servlet.request.X509Certificate");
	 * 
	 * if (certificates != null) { return certificates[0]; } return null; }
	 */
	private static List<Metadata> getResponseMetadata(
			final RequestContext requestContext) {
		final LinkedList<Metadata> result = new LinkedList<Metadata>();
		return result;
	}

	/*
	 * private X509Certificate[] getClientCertificates() { SOAPMessageContext
	 * jaxwsContext = (SOAPMessageContext) wsContext .getMessageContext();
	 * HttpServletRequest request = (HttpServletRequest) jaxwsContext
	 * .get(SOAPMessageContext.SERVLET_REQUEST);
	 * 
	 * final X509Certificate[] certificates = (X509Certificate[]) request
	 * .getAttribute("javax.servlet.request.X509Certificate"); return
	 * certificates; }
	 */
	private static boolean isCertificateValid(String certificate) {
		try {

			CertificateFactory certFactory1 = CertificateFactory
					.getInstance("X.509");
			InputStream in1 = new ByteArrayInputStream(
					DatatypeConverter.parseBase64Binary(certificate));
			X509Certificate cert = (X509Certificate) certFactory1
					.generateCertificate(in1);

			String issuer = cert.getIssuerDN().toString();
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

			ArrayList<String[]> caProviders = new ArrayList<String[]>();
			try {
				caProviders = DBConnector.getInstances().getCAProviders();
			} catch (SQLException e) {
				e.printStackTrace();
				return false;
			}

			String caCertificate = "";
			String caCertificate2 = "";
			String ocspURL = "";
			String crlUrl = "";
			if (issuerName.compareTo("") != 0) {
				for (String[] ca : caProviders) {
					if (ca[0].compareTo(issuerName) == 0) {
						ocspURL = ca[1];
						caCertificate = ca[2];
						crlUrl = ca[3];
						caCertificate2 = ca[4];
						break;
					}
				}
			} else {
				return false;
			}
			// Check date validity

			if (!checkDataValidity(cert))
				return false;

			int methodValidateCert = DBConnector.getInstances()
					.getMethodValidateCert();
			switch (methodValidateCert) {
			case 0: // no check
				LOG.info("No checking certificate status");
				return true;
			case 1: // CRL
				LOG.info("CRL certificate status checking");
				if (crlUrl.compareTo("") != 0
						&& caCertificate.compareTo("") != 0) {
					X509Certificate subX509 = cert;

					CertificateFactory certFactory = CertificateFactory
							.getInstance("X.509");
					InputStream in = new ByteArrayInputStream(
							DatatypeConverter.parseBase64Binary(caCertificate));
					X509Certificate caX509 = (X509Certificate) certFactory
							.generateCertificate(in);

					if (!ExtFunc.checkCertificateRelation(caX509, subX509)) {
						if (caCertificate2.compareTo("") != 0) {
							in = new ByteArrayInputStream(
									DatatypeConverter
											.parseBase64Binary(caCertificate2));
							caX509 = (X509Certificate) certFactory
									.generateCertificate(in);
							if (!ExtFunc.checkCertificateRelation(caX509,
									subX509)) {

								return false;
							}
						} else {

							return false;
						}
					}

					CRLStatus CRLVarification = CertificateStatus.getInstance()
							.checkCRLCertificate(subX509, crlUrl);
					if (!CRLVarification.getIsValid()) {
						return true;
					} else {
						return false;
					}
				} else {
					return false;
				}
			case 2: // OCSP
				LOG.info("OCSP certificate status checking");
				if (ocspURL.compareTo("") != 0
						&& caCertificate.compareTo("") != 0) {
					X509Certificate subX509 = cert;

					CertificateFactory certFactory = CertificateFactory
							.getInstance("X.509");
					InputStream in = new ByteArrayInputStream(
							DatatypeConverter.parseBase64Binary(caCertificate));
					X509Certificate caX509 = (X509Certificate) certFactory
							.generateCertificate(in);

					if (!ExtFunc.checkCertificateRelation(caX509, subX509)) {
						if (caCertificate2.compareTo("") != 0) {
							in = new ByteArrayInputStream(
									DatatypeConverter
											.parseBase64Binary(caCertificate2));
							caX509 = (X509Certificate) certFactory
									.generateCertificate(in);
							if (!ExtFunc.checkCertificateRelation(caX509,
									subX509)) {

								return false;
							}
						} else {

							return false;
						}
					}

					boolean ocspStatus = false;
					int retryNumber = DBConnector.getInstances()
							.getNumberOCSPReTry();
					OcspStatus ocsp_status = CertificateStatus.getInstance()
							.checkRevocationStatus(ocspURL, subX509, caX509,
									retryNumber);
					ocspStatus = ocsp_status.getIsValid();
					if (ocspStatus) {
						return true;
					} else {
						return false;
					}
				} else {
					return false;
				}
			default:
				LOG.info("Signature validation and Certificate validation by OCSP (CRL if OCSP failure)");
				if (crlUrl.compareTo("") != 0 && ocspURL.compareTo("") != 0
						&& caCertificate.compareTo("") != 0) {
					X509Certificate subX509 = cert;

					CertificateFactory certFactory = CertificateFactory
							.getInstance("X.509");
					InputStream in = new ByteArrayInputStream(
							DatatypeConverter.parseBase64Binary(caCertificate));
					X509Certificate caX509 = (X509Certificate) certFactory
							.generateCertificate(in);

					if (!ExtFunc.checkCertificateRelation(caX509, subX509)) {
						if (caCertificate2.compareTo("") != 0) {
							in = new ByteArrayInputStream(
									DatatypeConverter
											.parseBase64Binary(caCertificate2));
							caX509 = (X509Certificate) certFactory
									.generateCertificate(in);
							if (!ExtFunc.checkCertificateRelation(caX509,
									subX509)) {

								return false;
							}
						} else {

							return false;
						}
					}

					boolean ocspStatus = false;
					boolean crlStatus = false;
					int retryNumber = DBConnector.getInstances()
							.getNumberOCSPReTry();
					OcspStatus ocsp_status = CertificateStatus.getInstance()
							.checkRevocationStatus(ocspURL, subX509, caX509,
									retryNumber);
					if (ocsp_status.getCertificateState().equals(
							OcspStatus.ERROR)) {
						CRLStatus CRLVarification = CertificateStatus
								.getInstance().checkCRLCertificate(subX509,
										crlUrl);
						crlStatus = !CRLVarification.getIsValid();
						if (crlStatus) {
							return true;
						} else {
							return false;
						}
					} else {
						ocspStatus = ocsp_status.getIsValid();
						if (ocspStatus) {
							return true;
						} else {
							return false;
						}
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	private static String getIssuerName(String DN) {
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

	private static boolean checkDataValidity(X509Certificate x509) {
		try {
			x509.checkValidity();
			return true;
		} catch (CertificateExpiredException e) {
			e.printStackTrace();

		} catch (CertificateNotYetValidException e) {
			e.printStackTrace();
		}
		return false;
	}

	private static OTPCore getOTPCore() {
		if (otpcore == null) {
			otpcore = OTPCoreFactory.getOTPCore();
			try {
				otpcore.initialize("otpcore.xml", 0);
			} catch (OTPCoreException e) {
				LOG.info(e.getMessage());
				try {
					otpcore.reloadConfig("otpcore.xml");
				} catch (OTPCoreException ex) {
					ex.printStackTrace();
				}
			}
		}
		return otpcore;
	}

	/**
	 * Processes requests for both HTTP <code>GET</code> and <code>POST</code>
	 * methods.
	 *
	 * @param request
	 *            servlet request
	 * @param response
	 *            servlet response
	 * @throws ServletException
	 *             if a servlet-specific error occurs
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	protected void processRequest(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html;charset=UTF-8");
		PrintWriter out = response.getWriter();
		try {
			/* TODO output your page here. You may use following sample code. */
			out.println("<!DOCTYPE html>");
			out.println("<html>");
			out.println("<head>");
			out.println("<title>Servlet CAGSocketGateWay</title>");
			out.println("</head>");
			out.println("<body>");
			out.println("<h1>Servlet CAGSocketGateWay at "
					+ request.getContextPath() + "</h1>");
			out.println("</body>");
			out.println("</html>");
		} finally {
			out.close();
		}
	}

	// <editor-fold defaultstate="collapsed"
	// desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
	/**
	 * Handles the HTTP <code>GET</code> method.
	 *
	 * @param request
	 *            servlet request
	 * @param response
	 *            servlet response
	 * @throws ServletException
	 *             if a servlet-specific error occurs
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		processRequest(request, response);
	}

	/**
	 * Handles the HTTP <code>POST</code> method.
	 *
	 * @param request
	 *            servlet request
	 * @param response
	 *            servlet response
	 * @throws ServletException
	 *             if a servlet-specific error occurs
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	@Override
	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		processRequest(request, response);
	}

	/**
	 * Returns a short description of the servlet.
	 *
	 * @return a String containing servlet description
	 */
	@Override
	public String getServletInfo() {
		return "Short description";
	}// </editor-fold>
}