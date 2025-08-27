package org.signserver.webbjob;

import java.util.*;
import java.io.*;
import java.text.*;
import java.net.*;
import org.apache.log4j.Logger;
import org.signserver.common.*;
import org.signserver.common.util.*;
import org.signserver.common.dbdao.*;
import java.nio.channels.FileChannel;


public class MonitoringTask extends TimerTask {
	
	private final static Logger log = Logger.getLogger(MonitoringTask.class);
	
	private static Boolean previousHAStatus = null;
	private static Boolean previousRLStatus = null;
	
	@Override
	public void run() {
		GeneralPolicy gp = DBConnector.getInstances().getGeneralPolicy();
		boolean resend = gp.isFrontIsHAReSent();
		
		
		// check HA Cluster
		String crmStatus = WorkerCommandLine.getInstance().executeCrmStatus();
		
		Boolean currentHAStatus;
		
		if(crmStatus.contains("OFFLINE") || crmStatus.contains("Offline") ||
				crmStatus.contains("offline")) {
			
			currentHAStatus = false;
			
			if(resend) {
				//GeneralPolicy gp = DBConnector.getInstances().getGeneralPolicy();
				boolean isSms = gp.isFrontIsHASMS();
				boolean isEmail = gp.isFrontIsHAEmail();
				
				List<ReceiverHAStatus> receiverHAStatuses = DBConnector.getInstances().authReceiverHAStatusList();
				
				if(isSms) {
					String content = getCrmStatusForSms(crmStatus);
					String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(Defines.CONNECTION_PARAMS_SMPP);
					
					String[] smsContentInfo = DBConnector.getInstances()
							.getBackOfficeParamsDetailClient(Defines.PARAMS_BACKOFFICE_MAIL_HA, true);
					
					content = "Message from "+ExtFunc.getHostName()+"\n"+content;
					
					if(endpointParams == null) {
						log.error("Cannot send HA alert through SMS because no smpp configuration found in system");
					} else {
						for(int i=0; i<receiverHAStatuses.size(); i++) {
							EndpointServiceResp endpointServiceResp = EndpointService.getInstance().sendSmsNoLogging(null, null, receiverHAStatuses.get(i).getPhoneNo()
									, content, endpointParams[1], Integer.parseInt(endpointParams[2]));
							if(endpointServiceResp.getResponseCode() == 0) {
								log.info("HA alert sms has been sent to "+receiverHAStatuses.get(i).getFullName());
							} else {
								log.error("HA alert sms couldn't send to "+receiverHAStatuses.get(i).getFullName());
							}
						}
					}
				}
				
				if(isEmail) {
					String content = getCrmStatusForSms(crmStatus);
					String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(Defines.CONNECTION_PARAMS_SMTP);
					
					String[] emailContentInfo = DBConnector.getInstances()
							.getBackOfficeParamsDetailClient(Defines.PARAMS_BACKOFFICE_MAIL_HA, true);
					
					content = emailContentInfo[1] + "\nMessage from "+ExtFunc.getHostName()+"\n" + content;
					
					if(endpointParams == null) {
						log.error("Cannot send HA alert through Email because no smtp configuration found in system");
					} else {
						for(int i=0; i<receiverHAStatuses.size(); i++) {
							EndpointServiceResp endpointServiceResp = EndpointService.getInstance().sendEmailNoLogging(null, null, receiverHAStatuses.get(i).getEmail()
									, emailContentInfo[0], content, endpointParams[1], Integer.parseInt(endpointParams[2]));
							if(endpointServiceResp.getResponseCode() == 0) {
								log.info("HA alert email has been sent to "+receiverHAStatuses.get(i).getFullName());
							} else {
								log.error("HA alert email couldn't send to "+receiverHAStatuses.get(i).getFullName());
							}
						}
					}
				}
				
				if(!isSms && !isEmail) {
					log.warn("HA has a problem but system doesn't send any alert to administrator");
				}
				
				previousHAStatus = false;
				
			} else {
				
				if(previousHAStatus != currentHAStatus) {
				
					//GeneralPolicy gp = DBConnector.getInstances().getGeneralPolicy();
					boolean isSms = gp.isFrontIsHASMS();
					boolean isEmail = gp.isFrontIsHAEmail();
					
					List<ReceiverHAStatus> receiverHAStatuses = DBConnector.getInstances().authReceiverHAStatusList();
					
					if(isSms) {
						String content = getCrmStatusForSms(crmStatus);
						String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(Defines.CONNECTION_PARAMS_SMPP);
						
						String[] smsContentInfo = DBConnector.getInstances()
								.getBackOfficeParamsDetailClient(Defines.PARAMS_BACKOFFICE_MAIL_HA, true);
						
						content = "Message from "+ExtFunc.getHostName()+"\n"+content;
						
						if(endpointParams == null) {
							log.error("Cannot send HA alert through SMS because no smpp configuration found in system");
						} else {
							for(int i=0; i<receiverHAStatuses.size(); i++) {
								EndpointServiceResp endpointServiceResp = EndpointService.getInstance().sendSmsNoLogging(null, null, receiverHAStatuses.get(i).getPhoneNo()
										, content, endpointParams[1], Integer.parseInt(endpointParams[2]));
								if(endpointServiceResp.getResponseCode() == 0) {
									log.info("HA alert sms has been sent to "+receiverHAStatuses.get(i).getFullName());
								} else {
									log.error("HA alert sms couldn't send to "+receiverHAStatuses.get(i).getFullName());
								}
							}
							
						}
					}
					
					if(isEmail) {
						String content = getCrmStatusForSms(crmStatus);
						String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(Defines.CONNECTION_PARAMS_SMTP);
						
						String[] emailContentInfo = DBConnector.getInstances()
								.getBackOfficeParamsDetailClient(Defines.PARAMS_BACKOFFICE_MAIL_HA, true);
						
						content = emailContentInfo[1] + "\nMessage from "+ExtFunc.getHostName()+"\n" + content;
						
						if(endpointParams == null) {
							log.error("Cannot send HA alert through Email because no smtp configuration found in system");
						} else {
							for(int i=0; i<receiverHAStatuses.size(); i++) {
								EndpointServiceResp endpointServiceResp = EndpointService.getInstance().sendEmailNoLogging(null, null, receiverHAStatuses.get(i).getEmail()
										, emailContentInfo[0], content, endpointParams[1], Integer.parseInt(endpointParams[2]));
								if(endpointServiceResp.getResponseCode() == 0) {
									log.info("HA alert email has been sent to "+receiverHAStatuses.get(i).getFullName());
								} else {
									log.error("HA alert email couldn't send to "+receiverHAStatuses.get(i).getFullName());
								}
							}
						}
					}
					
					if(!isSms && !isEmail) {
						log.warn("HA has a problem but system doesn't send any alert to administrator");
					}
					
					previousHAStatus = false;
					
				} else {
					log.info("Notification has already sent.");
				}
			}
		} else {
			// back to normal
			currentHAStatus = true;
			
			if(previousHAStatus != currentHAStatus) {
				
				if(previousHAStatus != null) {
					//GeneralPolicy gp = DBConnector.getInstances().getGeneralPolicy();
					boolean isSms = gp.isFrontIsHASMS();
					boolean isEmail = gp.isFrontIsHAEmail();
					
					List<ReceiverHAStatus> receiverHAStatuses = DBConnector.getInstances().authReceiverHAStatusList();
					
					if(isSms) {
						String content = getCrmStatusForSms(crmStatus);
						String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(Defines.CONNECTION_PARAMS_SMPP);
						
						String[] smsContentInfo = DBConnector.getInstances()
								.getBackOfficeParamsDetailClient(Defines.PARAMS_BACKOFFICE_MAIL_HA, true);
						
						content = "Message from "+ExtFunc.getHostName()+"\n"+content;
						
						if(endpointParams == null) {
							log.error("Cannot send HA alert through SMS because no smpp configuration found in system");
						} else {
							for(int i=0; i<receiverHAStatuses.size(); i++) {
								EndpointServiceResp endpointServiceResp = EndpointService.getInstance().sendSmsNoLogging(null, null, receiverHAStatuses.get(i).getPhoneNo()
										, content, endpointParams[1], Integer.parseInt(endpointParams[2]));
								if(endpointServiceResp.getResponseCode() == 0) {
									log.info("HA alert sms has been sent to "+receiverHAStatuses.get(i).getFullName());
								} else {
									log.error("HA alert sms couldn't send to "+receiverHAStatuses.get(i).getFullName());
								}
							}
							
						}
					}
					
					if(isEmail) {
						String content = getCrmStatusForSms(crmStatus);
						String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(Defines.CONNECTION_PARAMS_SMTP);
						
						String[] emailContentInfo = DBConnector.getInstances()
								.getBackOfficeParamsDetailClient(Defines.PARAMS_BACKOFFICE_MAIL_HA, true);
						
						content = emailContentInfo[1] + "\nMessage from "+ExtFunc.getHostName()+"\n" + content;
						
						if(endpointParams == null) {
							log.error("Cannot send HA alert through Email because no smtp configuration found in system");
						} else {
							for(int i=0; i<receiverHAStatuses.size(); i++) {
								EndpointServiceResp endpointServiceResp = EndpointService.getInstance().sendEmailNoLogging(null, null, receiverHAStatuses.get(i).getEmail()
										, emailContentInfo[0], content, endpointParams[1], Integer.parseInt(endpointParams[2]));
								if(endpointServiceResp.getResponseCode() == 0) {
									log.info("HA alert email has been sent to "+receiverHAStatuses.get(i).getFullName());
								} else {
									log.error("HA alert email couldn't send to "+receiverHAStatuses.get(i).getFullName());
								}
							}
						}
					}
					
					if(!isSms && !isEmail) {
						log.warn("HA has a problem but system doesn't send any alert to administrator");
					}
					
					previousHAStatus = true;
				}
			}
		}
		
		Boolean currentRLStatus;
		
		// check DB Replication
		Properties config = DBConnector.getInstances().getPropertiesConfig();
		String dbRepl = WorkerCommandLine.getInstance().executeDBReplication(ExtFunc.getMasterDBAdrr(config.getProperty("database.url")),
				config.getProperty("database.username"), config.getProperty("database.password"));
		if(dbRepl.contains("NO") || dbRepl.contains("No") || dbRepl.contains("no")
				|| dbRepl.contains("Connecting") || dbRepl.contains("connecting")) {
			
			currentRLStatus = false;
			
			if(resend) {
				
				//GeneralPolicy gp = DBConnector.getInstances().getGeneralPolicy();
				boolean isSms = gp.isFrontIsHASMS();
				boolean isEmail = gp.isFrontIsHAEmail();
				
				List<ReceiverHAStatus> receiverHAStatuses = DBConnector.getInstances().authReceiverHAStatusList();
				
				if(isSms) {
					String content = getDbReplSms(dbRepl);
					String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(Defines.CONNECTION_PARAMS_SMPP);
					
					String[] smsContentInfo = DBConnector.getInstances()
							.getBackOfficeParamsDetailClient(Defines.PARAMS_BACKOFFICE_MAIL_DB, true);
					
					content = "Message from "+ExtFunc.getHostName()+"\n"+content;
					
					if(endpointParams == null) {
						log.error("Cannot send database replication alert through SMS because no smpp configuration found in system");
					} else {
						for(int i=0; i<receiverHAStatuses.size(); i++) {
							EndpointServiceResp endpointServiceResp = EndpointService.getInstance().sendSmsNoLogging(null, null, receiverHAStatuses.get(i).getPhoneNo()
									, content, endpointParams[1], Integer.parseInt(endpointParams[2]));
							if(endpointServiceResp.getResponseCode() == 0) {
								log.info("database replication alert sms has been sent to "+receiverHAStatuses.get(i).getFullName());
							} else {
								log.error("database replication alert couldn't send to "+receiverHAStatuses.get(i).getFullName());
							}
						}
					}
				}
				
				if(isEmail) {
					String content = getDbReplEmail(dbRepl);
					String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(Defines.CONNECTION_PARAMS_SMTP);
					
					String[] emailContentInfo = DBConnector.getInstances()
							.getBackOfficeParamsDetailClient(Defines.PARAMS_BACKOFFICE_MAIL_DB, true);
					
					content = emailContentInfo[1] + "\nMessage from "+ExtFunc.getHostName()+"\n" + content;
					
					if(endpointParams == null) {
						log.error("Cannot send database replication alert through Email because no smtp configuration found in system");
					} else {
						for(int i=0; i<receiverHAStatuses.size(); i++) {
							EndpointServiceResp endpointServiceResp = EndpointService.getInstance().sendEmailNoLogging(null, null, receiverHAStatuses.get(i).getEmail()
									, emailContentInfo[0], content, endpointParams[1], Integer.parseInt(endpointParams[2]));
							if(endpointServiceResp.getResponseCode() == 0) {
								log.info("database replication alert email has been sent to "+receiverHAStatuses.get(i).getFullName());
							} else {
								log.error("database replication alert email couldn't send to "+receiverHAStatuses.get(i).getFullName());
							}
						}
						
					}
				}
				
				if(!isSms && !isEmail) {
					log.warn("database replication has a problem but system doesn't send any alert to administrator");
				}
				
				previousRLStatus = false;

			} else {
				
				if(previousRLStatus != currentRLStatus) {
				
					//GeneralPolicy gp = DBConnector.getInstances().getGeneralPolicy();
					boolean isSms = gp.isFrontIsHASMS();
					boolean isEmail = gp.isFrontIsHAEmail();
					
					List<ReceiverHAStatus> receiverHAStatuses = DBConnector.getInstances().authReceiverHAStatusList();
					
					if(isSms) {
						String content = getDbReplSms(dbRepl);
						String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(Defines.CONNECTION_PARAMS_SMPP);
						
						String[] smsContentInfo = DBConnector.getInstances()
								.getBackOfficeParamsDetailClient(Defines.PARAMS_BACKOFFICE_MAIL_DB, true);
						
						content = "Message from "+ExtFunc.getHostName()+"\n"+content;
						
						if(endpointParams == null) {
							log.error("Cannot send database replication alert through SMS because no smpp configuration found in system");
						} else {
							for(int i=0; i<receiverHAStatuses.size(); i++) {
								EndpointServiceResp endpointServiceResp = EndpointService.getInstance().sendSmsNoLogging(null, null, receiverHAStatuses.get(i).getPhoneNo()
										, content, endpointParams[1], Integer.parseInt(endpointParams[2]));
								if(endpointServiceResp.getResponseCode() == 0) {
									log.info("database replication alert sms has been sent to "+receiverHAStatuses.get(i).getFullName());
								} else {
									log.error("database replication alert couldn't send to "+receiverHAStatuses.get(i).getFullName());
								}
							}
						}
					}
					
					if(isEmail) {
						String content = getDbReplEmail(dbRepl);
						String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(Defines.CONNECTION_PARAMS_SMTP);
						
						String[] emailContentInfo = DBConnector.getInstances()
								.getBackOfficeParamsDetailClient(Defines.PARAMS_BACKOFFICE_MAIL_DB, true);
						
						content = emailContentInfo[1] + "\nMessage from "+ExtFunc.getHostName()+"\n" + content;
						
						if(endpointParams == null) {
							log.error("Cannot send database replication alert through Email because no smtp configuration found in system");
						} else {
							for(int i=0; i<receiverHAStatuses.size(); i++) {
								EndpointServiceResp endpointServiceResp = EndpointService.getInstance().sendEmailNoLogging(null, null, receiverHAStatuses.get(i).getEmail()
										, emailContentInfo[0], content, endpointParams[1], Integer.parseInt(endpointParams[2]));
								if(endpointServiceResp.getResponseCode() == 0) {
									log.info("database replication alert email has been sent to "+receiverHAStatuses.get(i).getFullName());
								} else {
									log.error("database replication alert email couldn't send to "+receiverHAStatuses.get(i).getFullName());
								}
							}
							
						}
					}
					
					if(!isSms && !isEmail) {
						log.warn("database replication has a problem but system doesn't send any alert to administrator");
					}
					
					previousRLStatus = false;
					
				} else {
					log.info("Notification has already sent.");
				}
			}
		} else {
			// back to normal
			
			currentRLStatus = true;
			
			if(previousRLStatus != currentRLStatus) {
				
				if(previousRLStatus != null) {
			
					//GeneralPolicy gp = DBConnector.getInstances().getGeneralPolicy();
					boolean isSms = gp.isFrontIsHASMS();
					boolean isEmail = gp.isFrontIsHAEmail();
					
					List<ReceiverHAStatus> receiverHAStatuses = DBConnector.getInstances().authReceiverHAStatusList();
					
					if(isSms) {
						String content = getDbReplSms(dbRepl);
						String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(Defines.CONNECTION_PARAMS_SMPP);
						
						String[] smsContentInfo = DBConnector.getInstances()
								.getBackOfficeParamsDetailClient(Defines.PARAMS_BACKOFFICE_MAIL_DB, true);
						
						content = "Message from "+ExtFunc.getHostName()+"\n"+content;
						
						if(endpointParams == null) {
							log.error("Cannot send database replication alert through SMS because no smpp configuration found in system");
						} else {
							for(int i=0; i<receiverHAStatuses.size(); i++) {
								EndpointServiceResp endpointServiceResp = EndpointService.getInstance().sendSmsNoLogging(null, null, receiverHAStatuses.get(i).getPhoneNo()
										, content, endpointParams[1], Integer.parseInt(endpointParams[2]));
								if(endpointServiceResp.getResponseCode() == 0) {
									log.info("database replication alert sms has been sent to "+receiverHAStatuses.get(i).getFullName());
								} else {
									log.error("database replication alert couldn't send to "+receiverHAStatuses.get(i).getFullName());
								}
							}
							
						}
					}
					
					if(isEmail) {
						String content = getDbReplEmail(dbRepl);
						String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(Defines.CONNECTION_PARAMS_SMTP);
						
						String[] emailContentInfo = DBConnector.getInstances()
								.getBackOfficeParamsDetailClient(Defines.PARAMS_BACKOFFICE_MAIL_DB, true);
						
						content = emailContentInfo[1] + "\nMessage from "+ExtFunc.getHostName()+"\n" + content;
						
						if(endpointParams == null) {
							log.error("Cannot send database replication alert through Email because no smtp configuration found in system");
						} else {
							for(int i=0; i<receiverHAStatuses.size(); i++) {
								EndpointServiceResp endpointServiceResp = EndpointService.getInstance().sendEmailNoLogging(null, null, receiverHAStatuses.get(i).getEmail()
										, emailContentInfo[0], content, endpointParams[1], Integer.parseInt(endpointParams[2]));
								if(endpointServiceResp.getResponseCode() == 0) {
									log.info("database replication alert email has been sent to "+receiverHAStatuses.get(i).getFullName());
								} else {
									log.error("database replication alert email couldn't send to "+receiverHAStatuses.get(i).getFullName());
								}
							}
							
						}
					}
					
					if(!isSms && !isEmail) {
						log.warn("database replication has a problem but system doesn't send any alert to administrator");
					}
					
					previousRLStatus = true;
				}
			}
		}
	}
	/*
	private static String getCrmStatusForSms(String crmStatus) {
		String filterResult = "";
		try {
			BufferedReader bufReader = new BufferedReader(new StringReader(crmStatus));
		    String line=null;
		    while((line=bufReader.readLine()) != null ) {
		    	if(line.contains("Current DC")) {
		    		filterResult += line+"\n";
		    	}
		    	if(line.contains("[") && line.contains("]")) {
		    		if(line.contains("OFFLINE") || line.contains("Offline") || line.contains("offline"))
			    		filterResult += line+"\n";
		    	}
		    }
		} catch(Exception e) {
			e.printStackTrace();
			filterResult = crmStatus;
		}
		return filterResult;
	}
	*/
	
	private static String getCrmStatusForSms(String crmStatus) {
		String filterResult = "";
		try {
			BufferedReader bufReader = new BufferedReader(new StringReader(crmStatus));
		    String line=null;
		    while((line=bufReader.readLine()) != null ) {
		    	if(line.contains("Online")) {
		    		filterResult += line +"\n";
		    	}
		    	
		    	if(line.contains("OFFLINE")) {
		    		filterResult += line +"\n";
		    	}
		    }
		} catch(Exception e) {
			e.printStackTrace();
			filterResult = crmStatus;
		}
		return filterResult;
	}
/*
	private static String getCrmStatusForEmail(String crmStatus) {
	    return crmStatus;
	}
*/	
	private static String getDbReplSms(String dbStatus) {
		String filterResult = "";
		try {
			BufferedReader bufReader = new BufferedReader(new StringReader(dbStatus));
		    String line=null;
		    while((line=bufReader.readLine()) != null ) {
		    	if(line.contains("Slave_IO_Running") || line.contains("Slave_SQL_Running")) {
		    		filterResult += line.trim()+"\n";
		    	}
		    }
		} catch(Exception e) {
			e.printStackTrace();
			filterResult = dbStatus;
		}
	    return filterResult;
	}
	
	private static String getDbReplEmail(String dbStatus) {
	    return getDbReplSms(dbStatus);
	}
}