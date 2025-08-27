package org.signserver.common;

import java.io.IOException;

import org.apache.log4j.Logger;

import java.io.*;
import java.util.*;

import org.signserver.common.*;
import org.signserver.common.util.*;


public class WorkerCommandLine {
	
	private static WorkerCommandLine instance;
	private static final org.apache.log4j.Logger log = Logger.getLogger(WorkerCommandLine.class);
	
	private static String SIGNSERVER_HOME;
	private static String APPSRV_HOME;
	
	private static String PROCESS_PATH = "/bin/signserver.sh";
	private static String TOKEN_FOLDER = "/usr/local/tokens";
	
	private static String COMMAND_EXPORT_APPSRVHOME;
	private static String COMMAND_EXPORT_SIMPLE_PATH;
	private static String COMMAND_RELOAD;
	private static String COMMAND_CONFIG;
	private static String COMMAND_REMOVE;
	private static String COMMAND_CREATE;
	private static String COMMAND_ADMINGUI;
	private static String COMMAND_KEY_SYNC;
	
	private static String WORKER_CONFIG_PATH;
	private static Properties config;
	private static boolean isWindows = false;
	
	public static String INTERFACE_PATH = "/etc/sysconfig/network-scripts/";
	public static String INTERFACE_NAME;
	public static String INTERFACE_RAW_NAME;
	public static String INTERFACE;
	
	public static String COMMAND_RESTART_NETWORK_EL6 = "sudo service network restart";
	public static String COMMAND_RESTART_NETWORK_EL7 = "sudo systemctl restart network";
	
	public static String COMMAND_CRM_IP_RESOURCE;
	public static String COMMAND_CRM_STATUS;
	
	
	static {
		if(config == null) {
			config = DBConnector.getInstances().getPropertiesConfig();
		}
		SIGNSERVER_HOME = System.getProperty("jboss.server.home.dir")+"/"+"../../../../../signserver-3.4.1";
		APPSRV_HOME = System.getProperty("jboss.server.home.dir")+"/"+"../../../jboss-as";
		
		if(SIGNSERVER_HOME.contains("C:")) {
			PROCESS_PATH = "/bin/signserver.cmd";
			isWindows = true;
		}
		
		COMMAND_EXPORT_APPSRVHOME = "export APPSRV_HOME="+APPSRV_HOME;
		COMMAND_EXPORT_SIMPLE_PATH = "export PATH=$PATH:/usr/java/latest/bin:/usr/lib64/qt-3.3/bin:/usr/local/bin:/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/sbin";
		COMMAND_RELOAD = SIGNSERVER_HOME+PROCESS_PATH+" "+"reload ";
		COMMAND_CONFIG = SIGNSERVER_HOME+PROCESS_PATH+" "+"getstatus brief ";
		COMMAND_REMOVE = SIGNSERVER_HOME+PROCESS_PATH+" "+"removeworker ";
		COMMAND_CREATE = SIGNSERVER_HOME+PROCESS_PATH+" "+"setproperties ";
		COMMAND_ADMINGUI= SIGNSERVER_HOME+ "/bin/admingui.sh";
		WORKER_CONFIG_PATH = SIGNSERVER_HOME+"/doc/worker-configs";
		
		INTERFACE = ExtFunc.getNetworkInterfaceName(executeIPLinkCommand());
		INTERFACE_NAME = "ifcfg-"+INTERFACE+":0";
		INTERFACE_RAW_NAME = "ifcfg-"+INTERFACE;
		
	}
	
	public static WorkerCommandLine getInstance()
	{
		if(instance == null)
			instance = new WorkerCommandLine();
		return instance;
	}
	
	public String reloadWorker(String workerID)
	{
		String out = "";
		try
		{
			String[] command=null;
			if(!isWindows) {
				command = new String[] {"/bin/sh", "-c", COMMAND_EXPORT_APPSRVHOME+" && "+COMMAND_RELOAD+workerID};
				log.info("Exec command: "+COMMAND_EXPORT_APPSRVHOME+" && "+COMMAND_RELOAD+workerID);
			} else {
				command = new String[] {SIGNSERVER_HOME+PROCESS_PATH, "reload", workerID};
			}
			
			Process child = Runtime.getRuntime().exec(command);
	        BufferedReader r = new BufferedReader(new InputStreamReader(child.getInputStream()));
	        String s;
	        while ((s = r.readLine()) != null) {
	        	out = out.concat(s).concat("\n");
	        }
	        r.close();
		} catch(IOException e)	{
			e.printStackTrace();
			return e.getMessage();
		}
		return out;
	}
	
	public String getWorkerStatus(int workerID)
	{
		String out = "";
		try{
			String[] command = null;
			if(!isWindows) {
				command = new String[] {"/bin/sh", "-c", COMMAND_EXPORT_APPSRVHOME+" && "+COMMAND_CONFIG+workerID};
				log.info("Exec command: "+COMMAND_EXPORT_APPSRVHOME+" && "+COMMAND_CONFIG+workerID);
			} else {
				command = new String[] {SIGNSERVER_HOME+PROCESS_PATH, "getstatus", "brief", String.valueOf(workerID)};
			}
			Process child = Runtime.getRuntime().exec(command);
	        BufferedReader r = new BufferedReader(new InputStreamReader(child.getInputStream()));
	        String s;
	        while ((s = r.readLine()) != null) {
	        	out = out.concat(s).concat("\n");
	        }
	        r.close();
	        
		}
	    catch (IOException ex) {
	        ex.printStackTrace();
	        return ex.getMessage();
	    }
		return out;
	}
	
	public String getAllWorkerStatus()
	{
		String out = "";
		try{
			String[] command = null;
			
			command = new String[] {SIGNSERVER_HOME+PROCESS_PATH, "getstatus", "brief", "all"};
			
			Process child = Runtime.getRuntime().exec(command);
	        BufferedReader r = new BufferedReader(new InputStreamReader(child.getInputStream()));
	        String s;
	        while ((s = r.readLine()) != null) {
	        	out = out.concat(s).concat("\n");
	        }
	        r.close();
	        
		}
	    catch (IOException ex) {
	        ex.printStackTrace();
	        return ex.getMessage();
	    }
		return out;
	}
	
	public String removeWorker(int workerID)
	{
		String out = "";
		try{
			String[] command = null;
			if(!isWindows) {
				command = new String[] {"/bin/sh", "-c", COMMAND_EXPORT_APPSRVHOME+" && "+COMMAND_REMOVE+workerID};
				log.info("Exec command: "+COMMAND_EXPORT_APPSRVHOME+" && "+COMMAND_REMOVE+workerID);
			} else {
				command = new String[] {SIGNSERVER_HOME+PROCESS_PATH, "removeworker", String.valueOf(workerID)};
			}
			Process child = Runtime.getRuntime().exec(command);
	        BufferedReader r = new BufferedReader(new InputStreamReader(child.getInputStream()));
	        String s;
	        while ((s = r.readLine()) != null) {
	        	out = out.concat(s).concat("\n");
	        }
	        r.close();
		}
	    catch (IOException ex) {
	        ex.printStackTrace();
	        return ex.getMessage();
	    }
	    return out;
	}
	
	public String addWorker(String configFileName)
	{
		String out = "";
		try{
			String[] command = null;
			if(!isWindows) {
				command = new String[] {"/bin/sh", "-c", COMMAND_EXPORT_APPSRVHOME+" && "+COMMAND_CREATE+WORKER_CONFIG_PATH+"/"+configFileName};
				log.info("Exec command: "+COMMAND_EXPORT_APPSRVHOME+" && "+COMMAND_CREATE+WORKER_CONFIG_PATH+"/"+configFileName);
			} else {
				command = new String[] {SIGNSERVER_HOME+PROCESS_PATH, "setproperties", WORKER_CONFIG_PATH+"/"+configFileName};
			}
			Process child = Runtime.getRuntime().exec(command);
	        BufferedReader r = new BufferedReader(new InputStreamReader(child.getInputStream()));
	        String s;
	        while ((s = r.readLine()) != null) {
	        	out = out.concat(s).concat("\n");
	        }
	        r.close();
	        
		}
	    catch (IOException ex) {
	        ex.printStackTrace();
	        return ex.getMessage();
	    }
	    return out;
	}
	
	public String addWorkerFromPortal(String config)
	{
		String out = "";
		try {
			InputStream in = new ByteArrayInputStream(config.getBytes());
			byte[] buffer = new byte[1024];
		    int read = -1;
		    File temp = File.createTempFile("WorkerName", ".properties", new File(Defines.TMP_DIR));
		    FileOutputStream fos = new FileOutputStream(temp);

		    while((read = in.read(buffer)) != -1) {
		        fos.write(buffer, 0, read);
		    }
		    fos.close();
		    in.close();

		    String filePath = temp.getAbsolutePath();
		    
		    String[] command = null;
			if(!isWindows) {
				command = new String[] {"/bin/sh", "-c", COMMAND_EXPORT_APPSRVHOME+" && "+COMMAND_CREATE+filePath};
				log.info("Exec command: "+COMMAND_EXPORT_APPSRVHOME+" && "+COMMAND_CREATE+filePath);
			} else {
				command = new String[] {SIGNSERVER_HOME+PROCESS_PATH, "setproperties", filePath};
				log.info("Exec command: "+COMMAND_EXPORT_APPSRVHOME+" && "+COMMAND_CREATE+filePath);
			}
			Process child = Runtime.getRuntime().exec(command);
	        BufferedReader r = new BufferedReader(new InputStreamReader(child.getInputStream()));
	        String s;
	        while ((s = r.readLine()) != null) {
	        	out = out.concat(s).concat("\n");
	        }
	        r.close();
		    
		} catch(Exception e) {
			e.printStackTrace();
			return e.getMessage();
		}
		return out;
	}
	
	public List<AvailableWorkers> getAvailableWorkers()
	{
		List<AvailableWorkers> list = new ArrayList<AvailableWorkers>();
		
        File directory1 = new File(WORKER_CONFIG_PATH);
        File[] fList1 = directory1.listFiles();
 
        for (File file : fList1){
            if (file.isFile()){
            	AvailableWorkers aws = new AvailableWorkers(getWorkerNameFromNameConfigFile(file.getName()),
            			file.getName());
            	list.add(aws);
            }
        }
        
        return list;
	}
	
    private String getWorkerNameFromNameConfigFile(String configfile)
    {
    	int index_start = configfile.indexOf("_")+1;
    	int index_end = configfile.lastIndexOf("_");
    	return configfile.substring(index_start, index_end);
    }
    
    public String getWorkerConfigFile(String configFileName)
    {
    	String theString = "";
		try {
			
			FileInputStream fin = new FileInputStream(new File(WORKER_CONFIG_PATH+"/"+configFileName));
	        java.util.Scanner scanner = new java.util.Scanner(fin,"UTF-8").useDelimiter("\\A");
	        theString = scanner.hasNext() ? scanner.next() : "";
	        scanner.close();
		} catch (Exception e1) {
			e1.printStackTrace();
			return e1.getMessage();
		}
		return theString;
    }
    
    public String setWorkerConfigFile(String configFileName, String content) {
		try {
			File file = new File(WORKER_CONFIG_PATH+"/"+configFileName);
			if (!file.exists()) {
				return "File not found";
			}
			FileWriter fw;
			fw = new FileWriter(file.getAbsoluteFile());
			BufferedWriter bw = new BufferedWriter(fw);
			bw.write(content);
			bw.close();

		} catch (IOException e1) {
			e1.printStackTrace();
			return e1.getMessage();
		}
		return "File has been updated";
    }
    
    public boolean syncKeyPairs() {
    	String out = "";
    	boolean rv = false;
		try{
			Runtime rt = Runtime.getRuntime();
	        String[] commands = {"/bin/sh", "-c", COMMAND_EXPORT_SIMPLE_PATH+" && "+COMMAND_KEY_SYNC};
	        log.info("Exec command: "+COMMAND_EXPORT_SIMPLE_PATH+" && "+COMMAND_KEY_SYNC);
	        Process proc = rt.exec(commands);

	        BufferedReader stdInput = new BufferedReader(new 
	             InputStreamReader(proc.getInputStream()));

	        BufferedReader stdError = new BufferedReader(new 
	             InputStreamReader(proc.getErrorStream()));

	        // read the output from the command
	        String s = null;
	        while ((s = stdInput.readLine()) != null) {
	            out += s;
	        }
	        // read any errors from the attempted command
	        while ((s = stdError.readLine()) != null) {
	            out += s;
	        }
	        if(out==null) {
	        	log.info("Keypair has been synchronized.");
	        	rv = true;
	        } else {
	        	log.error(out);
	        	log.error("Keypair could not be synchronized.");
	        	rv = false;
	        }
		} catch (IOException ex) {
	    	rv = false;
	    }
	    return rv;
    }
    
    public String executeTailCommand(int numOfLine, String fileName) {
    	String out = "";
    	boolean rv = false;
		try{
			Runtime rt = Runtime.getRuntime();
			
			String tailCmd = "tail -n "+numOfLine+" "+fileName;
			
	        String[] commands = {"/bin/sh", "-c", COMMAND_EXPORT_SIMPLE_PATH+" && "+tailCmd};
	        Process proc = rt.exec(commands);

	        BufferedReader stdInput = new BufferedReader(new 
	             InputStreamReader(proc.getInputStream()));

	        BufferedReader stdError = new BufferedReader(new 
	             InputStreamReader(proc.getErrorStream()));

	        // read the output from the command
	        String s = null;
	        while ((s = stdInput.readLine()) != null) {
	            out += s+"\n";
	        }
	        // read any errors from the attempted command
	        while ((s = stdError.readLine()) != null) {
	            out += s+"\n";
	        }
		} catch (IOException ex) {
			ex.printStackTrace();
	    }
	    return out;
    }
    
    
    public static String executeIPLinkCommand() {
    	String out = "";
    	boolean rv = false;
		try{
			Runtime rt = Runtime.getRuntime();
			
			String ipLink = "ip link";
			
	        String[] commands = {"/bin/sh", "-c", COMMAND_EXPORT_SIMPLE_PATH+" && "+ipLink};
	        Process proc = rt.exec(commands);

	        BufferedReader stdInput = new BufferedReader(new 
	             InputStreamReader(proc.getInputStream()));

	        BufferedReader stdError = new BufferedReader(new 
	             InputStreamReader(proc.getErrorStream()));

	        // read the output from the command
	        String s = null;
	        while ((s = stdInput.readLine()) != null) {
	            out += s+"\n";
	        }
	        // read any errors from the attempted command
	        while ((s = stdError.readLine()) != null) {
	            out += s+"\n";
	        }
		} catch (IOException ex) {
			ex.printStackTrace();
	    }
	    return out;
    }
    
    
    public String[] editInterface(String ipAddr, String netMask,
			String gateWay, String dns1, String dns2) {
		String[] result = new String[5];
		try {
			if (ipAddr == null || netMask == null || gateWay == null || dns1 == null || dns2 == null) {
				File aliasInterface = new File(INTERFACE_PATH + INTERFACE_NAME);
				if (aliasInterface.exists()) {
					CustomProperties p = new CustomProperties();
					p.load(new FileInputStream(aliasInterface));
					result[0] = p.getProperty("IPADDR").replace("\"", "");
					result[1] = p.getProperty("NETMASK").replace("\"", "");
					result[2] = p.getProperty("GATEWAY").replace("\"", "");
					if(p.getProperty("DNS1") != null) {
						result[3] = p.getProperty("DNS1").replace("\"", "");
					}
					
					if(p.getProperty("DNS2") != null) {
						result[4] = p.getProperty("DNS2").replace("\"", "");
					}
					return result;
				} else {
					CustomProperties p = new CustomProperties();
					p.load(new FileInputStream(INTERFACE_PATH
							+ INTERFACE_RAW_NAME));
					result[0] = p.getProperty("IPADDR").replace("\"", "");
					result[1] = p.getProperty("NETMASK").replace("\"", "");
					result[2] = p.getProperty("GATEWAY").replace("\"", "");
					if(p.getProperty("DNS1") != null) {
						result[3] = p.getProperty("DNS1").replace("\"", "");
					}
					
					if(p.getProperty("DNS2") != null) {
						result[4] = p.getProperty("DNS2").replace("\"", "");
					}
					return result;
				}
			} else {
				File aliasInterface = new File(INTERFACE_PATH + INTERFACE_NAME);
				if (aliasInterface.exists()) {
					CustomProperties p = new CustomProperties();
					p.load(new FileInputStream(aliasInterface));
					String interfaceName = p.getProperty("DEVICE");
					
					if(interfaceName == null)
						interfaceName = p.getProperty("NAME");
					
					if (interfaceName.contains("\"")) {
						String broadCast = p.getProperty("BROADCAST");
						if (broadCast != null)
							p.remove("BROADCAST");
						
						if(p.getProperty("NAME") != null)
							p.remove("NAME");
						
						p.setProperty("DEVICE", "\"" + INTERFACE+":0" + "\"");
						p.setProperty("IPADDR", "\"" + ipAddr + "\"");
						p.setProperty("NETMASK", "\"" + netMask + "\"");
						p.setProperty("GATEWAY", "\"" + gateWay + "\"");
						p.setProperty("DNS1", "\"" + dns1 + "\"");
						p.setProperty("DNS2", "\"" + dns2 + "\"");
					} else {
						String broadCast = p.getProperty("BROADCAST");
						if (broadCast != null)
							p.remove("BROADCAST");
						
						if(p.getProperty("NAME") != null)
							p.remove("NAME");
						
						p.setProperty("DEVICE", INTERFACE+":0");
						p.setProperty("IPADDR", ipAddr);
						p.setProperty("NETMASK", netMask);
						p.setProperty("GATEWAY", gateWay);
						p.setProperty("DNS1", dns1);
						p.setProperty("DNS2", dns2);
					}
					p.store(new FileOutputStream(aliasInterface), null);
				} else {
					CustomProperties eth0Properties = new CustomProperties();
					eth0Properties.load(new FileInputStream(INTERFACE_PATH
							+ INTERFACE_RAW_NAME));
					eth0Properties.store(new FileOutputStream(INTERFACE_PATH
							+ INTERFACE_NAME), null);

					CustomProperties ethAliasProperties = new CustomProperties();
					ethAliasProperties.load(new FileInputStream(INTERFACE_PATH
							+ INTERFACE_NAME));
					String interfaceName = ethAliasProperties
							.getProperty("DEVICE");
					
					if(interfaceName == null)
						interfaceName = ethAliasProperties.getProperty("NAME");
					
					if (interfaceName.contains("\"")) {
						String broadCast = ethAliasProperties
								.getProperty("BROADCAST");
						if (broadCast != null)
							ethAliasProperties.remove("BROADCAST");
						
						if(ethAliasProperties.getProperty("NAME") != null)
							ethAliasProperties.remove("NAME");
						
						ethAliasProperties.setProperty("DEVICE", "\""
								+ INTERFACE+":0" + "\"");
						ethAliasProperties.setProperty("IPADDR", "\"" + ipAddr
								+ "\"");
						ethAliasProperties.setProperty("NETMASK", "\""
								+ netMask + "\"");
						ethAliasProperties.setProperty("GATEWAY", "\""
								+ gateWay + "\"");
						ethAliasProperties.setProperty("DNS1", "\""
								+ dns1 + "\"");
						ethAliasProperties.setProperty("DNS2", "\""
								+ dns2 + "\"");
					} else {
						String broadCast = ethAliasProperties
								.getProperty("BROADCAST");
						if (broadCast != null)
							ethAliasProperties.remove("BROADCAST");
						
						if(ethAliasProperties
								.getProperty("NAME") != null)
							ethAliasProperties.remove("NAME");
						
						ethAliasProperties.setProperty("DEVICE", INTERFACE+":0");
						ethAliasProperties.setProperty("IPADDR", ipAddr);
						ethAliasProperties.setProperty("NETMASK", netMask);
						ethAliasProperties.setProperty("GATEWAY", gateWay);
						ethAliasProperties.setProperty("DNS1", dns1);
						ethAliasProperties.setProperty("DNS2", dns2);
					}
					ethAliasProperties.store(new FileOutputStream(
							INTERFACE_PATH + INTERFACE_NAME), null);
				}

				Runtime rt = Runtime.getRuntime();
				
				String[] commands = null;
				if(ExtFunc.getOSVersion().equals(ExtFunc.OS_VERSION_EL7)) {
					commands = new String[] {
							"/bin/sh",
							"-c",
							COMMAND_EXPORT_SIMPLE_PATH + " && "
									+ COMMAND_RESTART_NETWORK_EL7 };
					
					log.info("Exec command: "
							+ COMMAND_EXPORT_SIMPLE_PATH + " && "
							+ COMMAND_RESTART_NETWORK_EL7);
				} else {
					commands = new String[] {
							"/bin/sh",
							"-c",
							COMMAND_EXPORT_SIMPLE_PATH + " && "
									+ COMMAND_RESTART_NETWORK_EL6 };
					
					log.info("Exec command: "
							+ COMMAND_EXPORT_SIMPLE_PATH + " && "
							+ COMMAND_RESTART_NETWORK_EL6);
				}
				
				Process proc = rt.exec(commands);

				BufferedReader stdInput = new BufferedReader(
						new InputStreamReader(proc.getInputStream()));

				BufferedReader stdError = new BufferedReader(
						new InputStreamReader(proc.getErrorStream()));

				// read the output from the command
				String s = null;
				String out = "";
				while ((s = stdInput.readLine()) != null) {
					out += s;
				}
				// read any errors from the attempted command
				while ((s = stdError.readLine()) != null) {
					out += s;
				}
				if (out == null) {
					log.info(out);
				} else {
					log.error(out);
				}
				result[0] = "SUCCESS";
				result[1] = "SUCCESS";
				result[2] = "SUCCESS";
				result[3] = "SUCCESS";
				result[4] = "SUCCESS";
			}
		} catch (Exception e) {
			e.printStackTrace();
			result = null;
		}
		return result;
	}
    
	public class CustomProperties extends Properties {
		  private static final long serialVersionUID = 1L;
		  @Override
		  public void store(OutputStream out, String comments) throws IOException {
		      customStore0(new BufferedWriter(new OutputStreamWriter(out, "8859_1")),
		                   comments, true);
		  }
		  private void customStore0(BufferedWriter bw, String comments, boolean escUnicode)
		          throws IOException {
		      bw.write("#" + new Date().toString());
		      bw.newLine();
		      synchronized (this) {
		          for (Enumeration e = keys(); e.hasMoreElements();) {
		              String key = (String) e.nextElement();
		              String val = (String) get(key);
		              bw.write(key + "=" + val);
		              bw.newLine();
		          }
		      }
		      bw.flush();
		  }
		}
	
	public static String executeDBReplication(String hostname, String username, String password) {
		String out = "";
    	boolean rv = false;
		try{
			Runtime rt = Runtime.getRuntime();
			
			String dbRepl = "mysql --host="+hostname+" --user="+username+" --password="+password+"  -e \"show slave status \\G\"";
			
	        String[] commands = {"/bin/sh", "-c", COMMAND_EXPORT_SIMPLE_PATH+" && "+dbRepl};

	        Process proc = rt.exec(commands);

	        BufferedReader stdInput = new BufferedReader(new 
	             InputStreamReader(proc.getInputStream()));
	        /*
	        BufferedReader stdError = new BufferedReader(new 
	             InputStreamReader(proc.getErrorStream()));
 			*/
	        // read the output from the command
	        String s = null;
	        while ((s = stdInput.readLine()) != null) {
	            if(s.contains("Slave_IO_Running") 
	            		|| s.contains("Slave_SQL_Running")
	            		|| s.contains("Seconds_Behind_Master")
	            		|| s.contains("Last_SQL_Error")) {
	            	out += s+"\n";
	            }
	        }
	        /*
	        // read any errors from the attempted command
	        while ((s = stdError.readLine()) != null) {
	            out += s+"\n";
	        }
	        */
		} catch (IOException ex) {
			ex.printStackTrace();
	    }
	    return out;
	}
	
	
	public static String executeCrmStatus() {
		String out = "";
    	boolean rv = false;
		try{
			Runtime rt = Runtime.getRuntime();
			
			String osVersion = ExtFunc.getOSVersion();
			if(osVersion.compareTo(ExtFunc.OS_VERSION_EL6) == 0) {
				String key = ExtFunc.OS_VERSION_EL6+".monitoring.status";
				COMMAND_CRM_STATUS = config.getProperty(key);
			} else if(osVersion.compareTo(ExtFunc.OS_VERSION_EL7) == 0) {
				String key = ExtFunc.OS_VERSION_EL7+".monitoring.status";
				COMMAND_CRM_STATUS = config.getProperty(key);
			} else {
				COMMAND_CRM_STATUS = null;
			}
			
			if(COMMAND_CRM_STATUS != null && validCommand(COMMAND_CRM_STATUS)) {
				
		        String[] commands = {"/bin/sh", "-c", COMMAND_EXPORT_SIMPLE_PATH+" && "+COMMAND_CRM_STATUS};
	
		        Process proc = rt.exec(commands);
	
		        BufferedReader stdInput = new BufferedReader(new 
		             InputStreamReader(proc.getInputStream()));
	
		        BufferedReader stdError = new BufferedReader(new 
		             InputStreamReader(proc.getErrorStream()));
	
		        // read the output from the command
		        String s = null;
		        while ((s = stdInput.readLine()) != null) {
		            out += s+"\n";
		        }
		        
		        // read any errors from the attempted command
		        while ((s = stdError.readLine()) != null) {
		            out += s+"\n";
		        }
			} else {
				log.error("Invalid get HA status command: "+COMMAND_CRM_STATUS);
			}
		} catch (IOException ex) {
			ex.printStackTrace();
			out = "N/A";
	    }
	    return out;
	}
	
    public String executeCrmResourceStatusClusterIP() {
    	String out = "";
    	boolean rv = false;
		try{
			Runtime rt = Runtime.getRuntime();
			
			String osVersion = ExtFunc.getOSVersion();
			if(osVersion.compareTo(ExtFunc.OS_VERSION_EL6) == 0) {
				String key = ExtFunc.OS_VERSION_EL6+".monitoring.clusterip";
				COMMAND_CRM_IP_RESOURCE = config.getProperty(key);
			} else if(osVersion.compareTo(ExtFunc.OS_VERSION_EL7) == 0) {
				String key = ExtFunc.OS_VERSION_EL7+".monitoring.clusterip";
				COMMAND_CRM_IP_RESOURCE = config.getProperty(key);
			} else {
				COMMAND_CRM_IP_RESOURCE = null;
			}
			
			if(COMMAND_CRM_IP_RESOURCE != null && validCommand(COMMAND_CRM_IP_RESOURCE)) {
				
		        String[] commands = {"/bin/sh", "-c", COMMAND_EXPORT_SIMPLE_PATH+" && "+COMMAND_CRM_IP_RESOURCE};
	
		        Process proc = rt.exec(commands);
	
		        BufferedReader stdInput = new BufferedReader(new 
		             InputStreamReader(proc.getInputStream()));
	
		        BufferedReader stdError = new BufferedReader(new 
		             InputStreamReader(proc.getErrorStream()));
	
		        // read the output from the command
		        String s = null;
		        while ((s = stdInput.readLine()) != null) {
		            out += s+"\n";
		        }
		        
		        // read any errors from the attempted command
		        while ((s = stdError.readLine()) != null) {
		            out += s+"\n";
		        }
			} else {
				log.error("Invalid get HA clusterIP command: "+COMMAND_CRM_IP_RESOURCE);
			}
		} catch (IOException ex) {
			ex.printStackTrace();
			out = "N/A";
	    }
	    return out;
    }
    
    private static boolean validCommand(String command) {
    	String[] parts = command.split(" ");
    	for(int i=0; i<parts.length; i++) {
    		if(parts[i].equals("rm")
        			|| parts[i].equals("reboot")
        			|| parts[i].equals("shutdown")
        			|| parts[i].equals("ls")
        			|| parts[i].equals("ll")
        			|| parts[i].equals("cat")
        			|| parts[i].equals("shadow")
        			|| parts[i].equals("mv ")) {
        		return false;
        	}
    	}
    	return true;
    }
}