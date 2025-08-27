package org.signserver.socket;

import java.util.Properties;
import java.net.URL;

import javax.xml.namespace.QName;

import org.signserver.common.DBConnector;

import com.tomicalab.cag360.cagconnector.ws.*;

import java.io.*;

public class CAGConnectorSrv
{
	private static CAGConnectorSrv instance;
	private CAGConnector ws;
	private String SIGNSERVER_BUILD_CONFIG = "/opt/CAG360/signserver-3.4.1/conf/signserver_build.properties";
	public CAGConnectorSrv() {
		try {
			File f = new File(SIGNSERVER_BUILD_CONFIG);
			if(!f.exists()) {
				SIGNSERVER_BUILD_CONFIG = "C:/CAG360/signserver-3.4.1/conf/signserver_build.properties";
			}
			Properties prop = new Properties();
			InputStream inPropFile = new FileInputStream(SIGNSERVER_BUILD_CONFIG);
			prop.load(inPropFile);
			inPropFile.close();
			CAGConnectorImpService service = new CAGConnectorImpService(new URL(prop.getProperty("tomica_cagconnector_url"))
			, new  QName("http://cagconnector.cag360.tomicalab.com/", "CAGConnectorImpService"));
			ws = service.getCAGConnectorImpPort();
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	public static CAGConnectorSrv getInstance() {
		if(instance == null)
			instance = new CAGConnectorSrv();
		return instance;
	}
	
	public CAGConnector getWS() {
		return ws;
	}
}