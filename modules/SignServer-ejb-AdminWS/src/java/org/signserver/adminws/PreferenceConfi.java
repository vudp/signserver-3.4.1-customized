package org.signserver.adminws;

import java.text.Format;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.prefs.Preferences;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * 
 * @author Tran
 */
public class PreferenceConfi {
	private static PreferenceConfi instance = null;
	// Preference key name

	private Properties mProps;
	private Properties mPropsIp;
	private Properties mPropSignin;
	
	private final String FILENAME_MANAGER_ACCOUNT = "confiadmin.properties";
	private final String FILENAME_MANAGER_IPCONNECT = "ipcoonect.properties";

	private final int TYPE_MANAGER_ACCOUNT = 1;
	private final int TYPE_MANAGER_IP = 2;

	private final String PREFER_VALUE_SUPERADMIN_USERNAME = "superadmin";
	private final String PREFER_VALUE_SUPERADMIN_PASSWORD = "tomicalab!@#098";
	private final String MASTER_KEY = "HCMtomica123)(*lab";
	private int numCurrent = 1;
	private final String PREFER_NAME_USER_USERNAME = "admin";
	private static final String DEFAULT_FAIL = "tomicalabfail";
	private static int SUPER_ADMIN_TYPE = 3;
	private static int ADMIN_TYPE = 2;
	private static int UNKNOWN_TYPE = 1;
	private static int FAIL_PASSWORD_TYPE = 0;
	private static int FAIL_BE_CONNECTING = -1;
	private static int FAIL_IP_DONT_GRANT = -2;
	private static String mIpSuperAdminIsCoonecting = "";

	private static String PREFER_KEY_AUTHORIZED = "authoriuzedcheck";

	public PreferenceConfi() {
		System.out.println("[TCCHTNN_AdminWS.java] constructor properties");
		mProps = new Properties();
		mPropsIp = new Properties();
		mPropSignin = new Properties();
		
		if (isExistProperties(FILENAME_MANAGER_ACCOUNT)) {
			loadPropertiesFile(TYPE_MANAGER_ACCOUNT);
		} else {
			initProperties(TYPE_MANAGER_ACCOUNT);
		}

		if (isExistProperties(FILENAME_MANAGER_IPCONNECT)) {
			loadPropertiesFile(TYPE_MANAGER_IP);
		} else {
			initProperties(TYPE_MANAGER_IP);
		}

	}

	public static PreferenceConfi getInstace() {
		if (instance == null) {
			instance = new PreferenceConfi();
		}
		return instance;
	}

	private boolean isExistProperties(String filename) {
		Properties prop = new Properties();
		try {
			// load a properties file
			prop.load(new FileInputStream(filename));

		} catch (IOException ex) {
			return false;
		}
		return true;
	}

	private void loadPropertiesFile(int type) {
		try {
			// load a properties file
			System.out.println("[TCCHTNN_AdminWS.java] loadPropertiesFile");
			switch (type) {
			case TYPE_MANAGER_ACCOUNT:
				mProps.load(new FileInputStream(FILENAME_MANAGER_ACCOUNT));
				break;
			case TYPE_MANAGER_IP:
				mPropsIp.load(new FileInputStream(FILENAME_MANAGER_IPCONNECT));
				break;
			default:
				break;
			}
		} catch (IOException ex) {
		}		
	}

	private void initProperties(int type) {

		System.out.println("[TCCHTNN_AdminWS.java] loadPropertiesFile");
		switch (type) {
		case TYPE_MANAGER_ACCOUNT:
			mProps.setProperty(PREFER_VALUE_SUPERADMIN_USERNAME,
					PREFER_VALUE_SUPERADMIN_PASSWORD);
			mProps.setProperty(PREFER_NAME_USER_USERNAME, "tomicalab");

			// save properties to project root folder
			commitChange(TYPE_MANAGER_ACCOUNT);
			break;
		case TYPE_MANAGER_IP:
			mPropsIp.setProperty("192.168.1.10",
					"tcchtnn");
			// save properties to project root folder
			commitChange(TYPE_MANAGER_IP);
			break;
		default:
			break;
		}
		
	}

	public void commitChange(int type) {
		
		try {
			switch (type) {
			case TYPE_MANAGER_ACCOUNT:
				mProps.store(new FileOutputStream(FILENAME_MANAGER_ACCOUNT), null);
				break;
			case TYPE_MANAGER_IP:
				mPropsIp.store(new FileOutputStream(FILENAME_MANAGER_IPCONNECT), null);
				break;
			default:
				break;
			}
			
		} catch (FileNotFoundException ex) {
			// Logger.getLogger(TestPropertiesFileInJava.class.getName()).log(Level.SEVERE,
			// null, ex);
		} catch (IOException ex) {
			// Logger.getLogger(TestPropertiesFileInJava.class.getName()).log(Level.SEVERE,
			// null, ex);
		}
	}

	/*
	 * public String getValueUrl() { return mPrefs.get(PREF_NAME, defaultValue);
	 * // "a string" }
	 * 
	 * public void setValueUrl(String newValue) { mPrefs.put(PREF_NAME,
	 * newValue); }
	 */

	public void addAdminUser(String passWord) {
		mProps.setProperty(PREFER_NAME_USER_USERNAME + numCurrent, passWord);
		commitChange(TYPE_MANAGER_ACCOUNT);
		numCurrent++;
	}
	
	public void removeAdminUser(String username) {
		mProps.remove(username);
		commitChange(TYPE_MANAGER_ACCOUNT);		
	}
	
	public void addIpGrantConnect(String ip) {
		Date today = Calendar.getInstance().getTime(); 
		Format formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		String s = formatter.format(today);
		mPropsIp.setProperty(ip, s);
		commitChange(TYPE_MANAGER_IP);
	}
	
	public void removeIPBeenGrantConnect(String ip) {
		mPropsIp.remove(ip);
		commitChange(TYPE_MANAGER_IP);
	}

	public int typeOfUsername(String username, String password, String ip) {
		// String pass = mPrefs.get(username, DEFAULT_FAIL);
		if (!mProps.containsKey(username)) {
			return UNKNOWN_TYPE;
		} else {
			// String pass = mProps.getProperty(username);
			if (PREFER_VALUE_SUPERADMIN_USERNAME.equals(username)) {
				if (isCorrectPassword(username, password)) {
					if (isConnecting(username, ip)) {
						return FAIL_BE_CONNECTING;
					}
					mPropSignin.setProperty(ip, username);
					return SUPER_ADMIN_TYPE;
				}
				return FAIL_PASSWORD_TYPE;
			}
			if (isCorrectPassword(username, password)) {
				if (isConnecting(username, ip)) {
					return FAIL_BE_CONNECTING;
				}
				if (!mPropsIp.containsKey(ip))
					return FAIL_IP_DONT_GRANT;
				mPropSignin.setProperty(ip, username);
				return ADMIN_TYPE;
			}
			return FAIL_PASSWORD_TYPE;
		}
	}
	
	private boolean isConnecting(String username, String ip) {
		System.out.println("[TCCHTNN_PreferenceConfi.java] check isConnecting.");
		if (mPropSignin.containsKey(ip)) {
			System.out.println("[TCCHTNN_PreferenceConfi.java] contain ip: "+ip);
			if (username.equals(mPropSignin.getProperty(ip))) {
				System.out.println("[TCCHTNN_PreferenceConfi.java] equal username: "+username);
				return false;
			}
			return true;
		}
		else {
			System.out.println("[TCCHTNN_PreferenceConfi.java] not contain ip: "+ip);
			if (mPropSignin.contains(username)) {
				return true;
			}
			return false;
		}
	}

	public boolean isCorrectPassword(String username, String password) {
		String pass = mProps.getProperty(username);
		if (pass.equals(password))
			return true;
		return false;
	}

	public boolean isAuthorized(String ip) {
		return mPropSignin.containsKey(ip);
	}

	public void setAuthorized(boolean authorized, String ip, String username) {
		if (authorized) {
			mPropSignin.setProperty(ip, username);
		} else
			mPropSignin.remove(ip);
	}

	public List<String> getAllIpConnect(){
		Set<Object> a = mPropsIp.keySet();
        List<String> bc = new ArrayList<String>();
        for (Iterator<Object> it = a.iterator(); it.hasNext();) {           
            bc.add((String) it.next());            
        }
        return bc;
	}
	
	public List<String> getAllUsernameConnect() {
		Set<Object> a= mProps.keySet();
		List<String> bc = new ArrayList<String>();
        for (Iterator<Object> it = a.iterator(); it.hasNext();) {           
            bc.add((String) it.next());            
        }
        return bc;
	}
	
	public boolean changePasswordAccountAdmin(String username, String oldPass, String password) {
		if (!oldPass.equals(mProps.getProperty(username)))
			return false;
		mProps.setProperty(username, password);
		return true;
	}
	
	public void resetPassword(String username) {
		mProps.setProperty(username, "tomicalab");
	}
	
	public boolean resetPasswordSuperadmin(String masterkey) {
		if (MASTER_KEY.equals(masterkey)) {
			mProps.setProperty(PREFER_VALUE_SUPERADMIN_USERNAME, PREFER_VALUE_SUPERADMIN_PASSWORD);
			return true;
		}
		return false;
	}
	
	boolean isSuperAdminConnect(String ip) {
		String username = mPropSignin.getProperty(ip, "null");
		return (PREFER_VALUE_SUPERADMIN_USERNAME.equals(username));
	}

}
