package org.signserver.u2f.tomica.database.manager;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

import com.mysql.jdbc.*;

import java.util.*;
import java.io.*;

import org.signserver.common.DBConnector;


public class ConnectionManager {
	static Connection con;
	static String url;
	private static String SIGNSERVER_BUILD_CONFIG = "/opt/CAG360/signserver-3.4.1/conf/signserver_build.properties";
	private static Properties config = null;
	private static Properties proConfig = null;
	
	static {
		if(config == null)
		{
			config = getPropertiesConfig();
		}
	}

	public static Connection getConnection() {    
	    Connection conn = null;
	    Statement stmt = null;
	    try {
	        Class.forName("com.mysql.jdbc.Driver");
	        conn = DriverManager.getConnection(config.getProperty("database.url")+"?useUnicode=true&characterEncoding=UTF-8",config.getProperty("database.username")
					, config.getProperty("database.password"));
	    } catch (Exception e) {
	    	e.printStackTrace();
	    }
		return conn;
	}
	
	private static Properties getPropertiesConfig()
	{
		if(proConfig == null)
		{
			InputStream inPropFile;
			Properties tempProp = new Properties();

			try {
				File f = new File(SIGNSERVER_BUILD_CONFIG);
				if(!f.exists()) {
					SIGNSERVER_BUILD_CONFIG = "C:/CAG360/signserver-3.4.1/conf/signserver_build.properties";
				}
				inPropFile = new FileInputStream(SIGNSERVER_BUILD_CONFIG);
				tempProp.load(inPropFile);
				inPropFile.close();
			} catch (IOException ioe) {
				ioe.printStackTrace();
			}
			return tempProp;
		}
		return proConfig;
	}
}
