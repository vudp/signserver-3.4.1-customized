package org.signserver.clientws;

import java.io.*;
import java.security.KeyStoreException;
import java.security.cert.*;
import java.util.*;
import java.util.Map.Entry;
import javax.naming.NamingException;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import org.apache.log4j.Logger;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.SecurityEventsAuditorSessionRemote;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.query.Criteria;
import org.cesecore.util.query.Elem;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.clauses.Order;
import org.cesecore.util.query.elems.RelationalOperator;
import org.cesecore.util.query.elems.Term;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ICertReqData;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.ProcessRequest;
import org.signserver.common.RequestAndResponseManager;
import org.signserver.common.RequestContext;
import org.signserver.common.ResyncException;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerStatus;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.common.*;
import org.signserver.common.util.*;
import org.signserver.common.dbdao.*;
import org.signserver.admin.cli.defaultimpl.SetProperties;
import org.signserver.admin.cli.defaultimpl.RemoveWorkerCommand;
import org.signserver.admin.cli.defaultimpl.ReloadCommand;

public class AdminLayer {
	private static final Logger LOG = Logger.getLogger(AdminLayer.class);
	
	private IWorkerSession.IRemote worker;
    private IGlobalConfigurationSession.IRemote global;
    private SecurityEventsAuditorSessionRemote auditor;
    
    private static AdminLayer instance;
    
    public static AdminLayer getInstance() {
    	if(instance == null) {
    		instance = new AdminLayer();
    	}
    	return instance;
    }
    
    private AdminLayer() {
    	try {
	        if (worker == null) {
	            worker = ServiceLocator.getInstance().lookupRemote(
	                    IWorkerSession.IRemote.class);
	        }
	        if (global == null) {
	            global = ServiceLocator.getInstance().lookupRemote(
	                    IGlobalConfigurationSession.IRemote.class);
	        }
	        if (auditor == null) {
	            auditor = ServiceLocator.getInstance().lookupRemote(
	                    SecurityEventsAuditorSessionRemote.class);
	        }
    	} catch(NamingException e) {
    		e.printStackTrace();
    	}
    }
    
    public void activateSigner(int signerId, String authenticationCode) {
        try {
            worker.activateSigner(signerId, authenticationCode);
        } catch (Exception e) {
        	LOG.error("Error while activating signer "+signerId);
            e.printStackTrace();
        }
    }
    
    public boolean deactivateSigner(int signerId) {
    	boolean result = false;
	    try {
	    	result = worker.deactivateSigner(signerId);
	    } catch (Exception e) {
	    	LOG.error("Error while deactivating signer "+signerId);
	        e.printStackTrace();
	    }
	    return result;
    }
    
    public void reloadConfiguration(int workerId) {
        worker.reloadConfiguration(workerId);
    }
    
	public String reloadWorker(final String workerID) {
		//String resp = WorkerCommandLine.getInstance().reloadWorker(workerID);
            String resp = "Worker "+workerID+" has been reloaded";
            LOG.info(resp);
            try {
                ReloadCommand reloadCommand = new ReloadCommand();
                reloadCommand.execute(new String[] {String.valueOf(workerID)});
                //reloadCommand.execute(new String[] {"all"});
            } catch(Exception e) {
                e.printStackTrace();
                resp = "";
            }
            
            if(ExtFunc.isNumeric(workerID)) {
                    reloadConfiguration(Integer.parseInt(workerID));
            }
            return resp;
	}
    
    public String getPKCS10CertificateRequestForKey(
            final int signerId,
            final String sigAlgorithm,
            final String subjectDn,
            final boolean explicitEccParameters,
            final boolean defaultKey) {
        String csr = null;;
        try {
            final ICertReqData data = worker.getCertificateRequest(signerId, 
                    new PKCS10CertReqInfo(sigAlgorithm, subjectDn, null), explicitEccParameters, defaultKey);
            if (!(data instanceof org.signserver.common.Base64SignerCertReqData)) {
                throw new RuntimeException("Unsupported cert req data: " + data);
            }

            csr = "-----BEGIN CERTIFICATE REQUEST-----\n"+
            new String(((org.signserver.common.Base64SignerCertReqData) data).getBase64CertReq())
            +"\n-----END CERTIFICATE REQUEST-----";
            

        } catch (Exception e) {
        	LOG.error("Error while generating csr for signer "+signerId);
	        e.printStackTrace();
        }
        return csr;
    }
    
    public int addWorker(String configFileName) {
    	//return WorkerCommandLine.getInstance().addWorkerFromPortal(workerConfig);
        String res = "";
        int workerId = -1;
        try {
                //res = WorkerCommandLine.getInstance().addWorker(configFileName);
                        InputStream in = new ByteArrayInputStream(configFileName.getBytes());
                        Properties properties = new Properties();
                        properties.load(in);
                        LOG.info("Adding worker by using SetProperties");
                        SetProperties processProperties = new SetProperties();
                        processProperties.process(properties);
                        workerId = processProperties.getWorkerId();
                        res = "This is result for worker "+workerId+".";
                        LOG.info(res);
            } catch (Exception ex) {
               ex.printStackTrace();
            }
        //return res;
        return workerId;
    }
    
    public String generateSignerKey(
            final int signerId,
            final String keyAlgorithm,
            final String keySpec,
            final String alias,
            final String authCode) {
    	String keyAlias = null;
        try {
        	keyAlias = worker.generateSignerKey(signerId, keyAlgorithm, keySpec, alias, authCode.toCharArray());
        } catch (Exception e) {
        	LOG.error("Error while generating key for signer "+signerId);
	        e.printStackTrace();
        }
        return keyAlias;
    }
    
	public String removeWorker(final int workerID) {
		//return WorkerCommandLine.getInstance().removeWorker(workerID);
            String res = "Worker has been removed";
                RemoveWorkerCommand removeWorkerCommand = new RemoveWorkerCommand();
                try {
                    //LOG.info("Removing worker by using RemoveWorkerCommand");
                    //removeWorkerCommand.execute(new String[] {String.valueOf(workerID)});
                    LOG.info("Removing worker by using Database procedure");
                    DBConnector.getInstances().removeWorker(workerID);
                } catch(Exception e) {
                    e.printStackTrace();
                    res = null;
                }
                return res;
	}
	
    public void uploadSignerCertificate(
            final int signerId,
            final byte[] signerCert) {
        try {
            worker.uploadSignerCertificate(signerId, signerCert, GlobalConfiguration.SCOPE_GLOBAL);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void uploadSignerCertificateChain(
            final int signerId,
            final List<byte[]> signerCerts) {
        try {
            worker.uploadSignerCertificateChain(signerId, signerCerts, GlobalConfiguration.SCOPE_GLOBAL);
         // 20180812
            try {
                reloadWorker(String.valueOf(signerId));
                //final WorkerStatus status = worker.getStatus(signerId);
                //if(status != null) {
                    //if(status.getFatalErrors().isEmpty()) {
                    	GeneralPolicy gp = DBConnector.getInstances().getGeneralPolicy();
                        if(gp.isFrontIsNotifySignServerCertificateByEmail()) {
                            //20180815
                            /*
                            String template = gp.getFrontEmailTemplateSignServer();

                            Properties p = new Properties();
                            Reader reader = new InputStreamReader(new ByteArrayInputStream(template.getBytes()), StandardCharsets.UTF_8);
                            p.load(reader);
                            String subject = p.getProperty("SUBJECT");
                            String content = p.getProperty("CONTENT");
                            */
                            String[] template = DBConnector.getInstances().getBackOfficeParamsDetailClient(Defines.PARAMS_BACKOFFICE_MAIL_ISSUEDCERT_SIGNSERVER, true);
                            String subject = template[0];
                            String content = template[1];

                            content = content.replace(Defines.PATTERN_BOLD_OPEN, "<b>");
                            content = content.replace(Defines.PATTERN_BOLD_CLOSE, "</b>");
                            content = content.replace(Defines.PATTERN_NEW_LINE, "<br>");

                            String[] result = DBConnector.getInstances().getSignServerByWorkerUUID(signerId);
                            if(result != null) {
                                //final Collection<Certificate> signerCertCollection = CertTools.getCertsFromPEM(new ByteArrayInputStream(signerCerts));
                                //List<Certificate> certificates = new ArrayList(signerCertCollection);
                                final X509Certificate signer = ExtFunc.convertToX509Cert(DatatypeConverter.printBase64Binary(signerCerts.get(0)));

                                String validFrom = ExtFunc.getRegularDateFormat(signer.getNotBefore());
                                String validTo = ExtFunc.getRegularDateFormat(signer.getNotAfter());
                                String subjectDN = signer.getSubjectDN().toString();
                                String issuerDN = signer.getIssuerDN().toString();
                                String serialNumber = signer.getSerialNumber().toString(16).toUpperCase();
                                content = content.replace(Defines.PATTERN_VALID_FROM, validFrom);
                                content = content.replace(Defines.PATTERN_VALID_TO, validTo);
                                content = content.replace(Defines.PATTERN_SUBJECT_DN, subjectDN);
                                content = content.replace(Defines.PATTERN_ISSUER_DN, issuerDN);
                                content = content.replace(Defines.PATTERN_SERIAL_NUMBER, serialNumber);
                                // 20180815
                                final byte[] attachment = signer.getEncoded();
                                final String threadChannel = result[2];
                                final String threadUser = result[1];
                                final String threadEmail = result[0];
                                final String threadSubject = subject;
                                final String threadContent = content;
                                new Thread(new Runnable() {
                                    @Override
                                    public void run() {
                                        String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(Defines.CONNECTION_PARAMS_SMTP);
                                        if(endpointParams != null) {
                                            EndpointServiceResp endpointServiceResp = EndpointService.getInstance().sendEmailNoLogging(
                                                            threadChannel,
                                                            threadUser, 
                                                            threadEmail, 
                                                            threadSubject,
                                                            threadContent,
                                                            attachment,
                                                            ExtFunc.getCertFileNameFromSubjectDn(signer.getSubjectDN().toString(), threadUser)+".cer",
                                                            endpointParams[1], 
                                                            Integer.parseInt(endpointParams[2]));
                                            if(endpointServiceResp.getResponseCode() == 0) {
                                                    LOG.info("Certificate has been sent to "+threadEmail);
                                            } else {
                                                    LOG.error("Failed to send certificate to "+threadEmail);
                                            }
                                        } else {
                                            LOG.error("No endpoint config to send email");
                                        }
                                    }
                                }).start();
                            }
                        }
                    //}
                //}
            } catch(Exception e) {
                e.printStackTrace();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public String getCertificate(
    		final String channelName,
    		final String userId,
			final String subjectDn,
			final String email,
			final String dayPattern,
			final String csr,
			final String caName,
			final int trustedhubTransId) {
    	String certificate = null;
    	try {
	    	Ca ca = DBConnector.getInstances().getCa(caName);
			if(ca == null) {
				LOG.error("Cannot found CA configuration: "+caName);
				return certificate;
			}
			
			if(ca.getEndPointParamsValue() == null) {
				LOG.error("Cannot found RA configuration of CA: "+caName);
				return certificate;
			}
			
			EndpointServiceResp endpointServiceResp = EndpointService.getInstance().getCertificate(channelName, userId, subjectDn, email, dayPattern, csr, ca.getEndPointParamsValue(), ca.getEndPointConfigID(), trustedhubTransId);
			if(endpointServiceResp.getResponseCode() == 0) {
				certificate = new String(endpointServiceResp.getResponseData());
			}
    	} catch(Exception e) {
    		e.printStackTrace();
    	}
		return certificate;
	}
}