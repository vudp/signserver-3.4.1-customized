package org.signserver.common;

import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
import org.signserver.common.util.*;
import org.signserver.common.dbdao.*;
import oracle.jdbc.OracleTypes;
import org.apache.log4j.Logger;

public class OracleConnector {

    private static final Logger LOG = Logger.getLogger(OracleConnector.class);
    private static OracleConnector instance = null;
    private static GeneralPolicy gp = null;
    private static List<EndPointConfig> epc = null;
    private static ArrayList<Ca> cas = null;
    private static ArrayList<Ip> ipLists = null;
    private static ArrayList<Channel> channels = null;
    private static ArrayList<EndPointParams> endPointParams = null;
    private static Boolean isOptimized = null;
    private static Properties config = null;
    private static Properties proConfig = null;
    private static String SIGNSERVER_BUILD_CONFIG = System.getProperty("jboss.server.home.dir") + "/" + "../../../../../signserver-3.4.1/conf/signserver_build.properties";
    private String username;
    private String ipConnect;
    private static Connection dbConn;

    static {
        if (config == null) {
            LOG.info("JBOSS HOME: " + System.getProperty("jboss.server.home.dir"));
            LOG.info("SIGNSERVER CONFIG: " + SIGNSERVER_BUILD_CONFIG);
            config = getPropertiesConfig();
        }
    }

    public OracleConnector() {
        if (dbConn == null) {
            dbConn = getDBConnection();
        }
    }

    public static OracleConnector getInstances() {
        if (instance == null) {
            instance = new OracleConnector();
        }
        return instance;
    }

    public static Properties getPropertiesConfig() {
        if (proConfig == null) {
            InputStream inPropFile;
            Properties tempProp = new Properties();

            try {
                File f = new File(SIGNSERVER_BUILD_CONFIG);
                if (!f.exists()) {
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

    private Connection getDBConnection() {
        if (dbConn != null) {
            if (isDbConnected(dbConn)) {
                return dbConn;
            } else {
                dbConn = getDBConnection();
            }
        } else {
            dbConn = getDBConnection();
        }
        return dbConn;
    }

    private boolean isDbConnected(Connection conn) {
        final String CHECK_SQL_QUERY = "SELECT 1";
        boolean isConnected = false;
        try {
            if (conn.isClosed()) {
                isConnected = false;
            } else if (!conn.isValid(5)) {
                isConnected = false;
            } else {
                final PreparedStatement statement = conn.prepareStatement(CHECK_SQL_QUERY);
                isConnected = true;
            }
        } catch (Exception e) {
            // handle SQL error here!
            LOG.error("Something wrong with DB connection!!!");
        }
        return isConnected;
    }

    private Connection openConnect() {
        try {
            Class.forName("oracle.jdbc.driver.OracleDriver");
            return DriverManager.getConnection(
                    config.getProperty("database.url"),
                    config.getProperty("database.username"),
                    config.getProperty("database.password"));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] authGetLicenseInfo() {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        byte[] lic = null;
        try {
            String str = "{?=call FRONT_GETLICENSEINFO(?)}";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.registerOutParameter(2, OracleTypes.BLOB);
            rs = cals.executeQuery();
            lic = cals.getBytes(2);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return lic;
    }

    public boolean authSetLicenseInfo(byte[] licenseData) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        boolean rv = false;
        try {
            String str = "{ ?=call FRONT_GETLICENSEUPDATE(?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            InputStream in = new ByteArrayInputStream(licenseData);

            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setBlob(2, in);

            rs = cals.executeQuery();
            rv = true;
            in.close();

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return rv;
    }

    public int authGetSuccessTransaction() {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int num = 0;
        try {
            String str = "{?=call FRONT_GENERALLICENSELIST()}";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            rs = cals.executeQuery();
            num = cals.getInt("TotalTransactionSuccess");

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return num;
    }

    public boolean checkChannelCode(String channelCode) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{?=call FRONT_CHECKCHANNEL(?, ?)}";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelCode);
            cals.registerOutParameter(3, OracleTypes.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(3);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 1);
    }

    public Object[] loginChannel(String channelCode, String user, String password, String signature) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        Object[] loginStatus = new Object[2];
        try {
            String str = "{ ?=call FRONT_CHECKLOGINCHANNEL(?, ?, ?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelCode);
            cals.setString(3, user);
            cals.setString(4, password);
            cals.setString(5, signature);
            cals.registerOutParameter(6, java.sql.Types.INTEGER);
            cals.registerOutParameter(7, java.sql.Types.LONGVARCHAR);
            rs = cals.executeQuery();
            loginStatus[0] = cals.getInt(6);
            loginStatus[1] = cals.getString(7);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return loginStatus;
    }

    public String readDataBase(String channelCode, String ip, String username,
            String password, String signature, String timestamp,
            String digitalSign) {
        String result = Defines.ERROR_INVALIDLOGININFO;
        String ipList = "";
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {
            // check info login
            /**
             * *********************************************************
             */
            Object[] loginStatus = loginChannel(channelCode, username, password, signature);
            Integer statusCode = (Integer) loginStatus[0];
            String pem = (String) loginStatus[1];

            if (statusCode.intValue() == 1) {
                LOG.info("Invalid Channel information");
                return Defines.ERROR_INVALIDLOGININFO;
            }
            /**
             * *********************************************************
             */
            // check digital signature
            if (statusCode.intValue() == 2) {
                LOG.info("PKCS#1 Signature unmatched");
                return Defines.ERROR_INVALIDSIGNATURE;
            }

            PublicKey pubkey = null;
            String data = null;
            if (timestamp != null) {
                data = username + password + signature + timestamp;
            } else {
                data = username + password + signature;
            }
            try {
                pubkey = PKCS11Util.getPublicKeyFromString(pem);
            } catch (Exception ex) {
                ex.printStackTrace();
            }

            String encoding = "UTF-8";
            if (!PKCS11Util.VerifyPKCS1Sig(data, digitalSign, encoding, pubkey)) {
                LOG.info("PKCS#1 Signature Verification failed");
                return Defines.ERROR_INVALIDSIGNATURE;
            }
            // check IP
            /**
             * *********************************************************
             */
            ArrayList<Ip> ips = getIpList();
            for (int i = 0; i < ips.size(); i++) {
                if (ips.get(i).getChannelCode().compareTo(channelCode) == 0) {
                    ipList = ipList + ips.get(i).getIp().concat(";");
                }
            }

            boolean isIP = checkIpCondition(ipList, ip);
            if (!isIP) {
                return Defines.ERROR_INVALIDIP;
            }
            /**
             * *********************************************************
             */
            this.username = username;
            this.ipConnect = ip;
            result = Defines.SUCCESS;

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return result;
    }

    private String concatAllIP(ResultSet resultSet) throws SQLException {
        String result = "";
        while (resultSet.next()) {

            int isActive = resultSet.getInt(4);
            if (isActive == 1) {
                result = result + resultSet.getString(3) + ";";
            }
        }
        return result;
    }

    private boolean checkIpCondition(String ipTruth, String ip) {
        if (ip.compareTo("127.0.0.1") == 0) {
            return true;
        }

        if (ipTruth.indexOf("*") != -1) {
            return true;
        }

        boolean check = ipTruth.contains(ip);
        return check;
    }

    public String writeLogToDataBaseOutside(String workerName,
            String username,
            String ip,
            String userContract,
            int status,
            String idTag,
            String channelName,
            String requestData,
            String responseData,
            String unsignedText,
            String signedText,
            String functionName,
            int dataInId) {

        // re-process xmlData Request to hide sensitive data
        requestData = ExtFunc.replaceContentInXmlTag(requestData, Defines._PASSWORD, Defines._HIDDENPASSWORD);
        requestData = ExtFunc.replaceContentInXmlTag(requestData, Defines._CURRENTPW, Defines._HIDDENPASSWORD);
        requestData = ExtFunc.replaceContentInXmlTag(requestData, Defines._NEWPW, Defines._HIDDENPASSWORD);
        requestData = ExtFunc.replaceContentInXmlTag(requestData, Defines._OTP, Defines._HIDDENPASSWORD);
        requestData = ExtFunc.replaceContentInXmlTag(requestData, Defines._NEXTOTP, Defines._HIDDENPASSWORD);
        requestData = ExtFunc.replaceContentInXmlTag(requestData, Defines._SIGNATUREIMAGE, Defines._BASE64DATA);

        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        String billCode = null;
        try {
            conn = getDBConnection();
            String str = "{ ?=call FRONT_INSERTCLIENTLOG(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) }";
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, username);
            cals.setString(3, userContract);
            cals.setString(4, ip);
            cals.setString(5, workerName);
            cals.setInt(6, status);
            cals.setString(7, idTag);
            cals.setString(8, channelName);
            cals.setString(9, requestData);
            cals.setString(10, responseData);
            cals.registerOutParameter(11, java.sql.Types.INTEGER);
            cals.setString(12, unsignedText);
            cals.setString(13, signedText);
            cals.setString(14, functionName);
            cals.setInt(15, dataInId);
            cals.setObject(16, null);

            cals.execute();

            billCode = cals.getString(10);

        } catch (Exception e) {
            e.printStackTrace();
            billCode = channelName.concat("-").concat(userContract).concat("-").concat(ExtFunc.getDateFormat());
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return billCode;
    }

    public String writeLogForResponse(String workerName,
            String username,
            String ip,
            String userContract,
            int status,
            String idTag,
            String channelName,
            String requestData,
            String responseData,
            String unsignedText,
            String signedText,
            String functionName,
            int dataInId,
            int oathResponseId) {

        // re-process xmlData Request to hide sensitive data
        requestData = ExtFunc.replaceContentInXmlTag(requestData, Defines._PASSWORD, Defines._HIDDENPASSWORD);
        requestData = ExtFunc.replaceContentInXmlTag(requestData, Defines._SIGNATUREIMAGE, Defines._BASE64DATA);

        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        String billCode = null;
        try {
            conn = getDBConnection();
            String str = "{ ?=call FRONT_INSERTCLIENTLOG(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) }";
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, username);
            cals.setString(3, userContract);
            cals.setString(4, ip);
            cals.setString(5, workerName);
            cals.setInt(6, status);
            cals.setString(7, idTag);
            cals.setString(8, channelName);
            cals.setString(9, requestData);
            cals.setString(10, responseData);
            cals.registerOutParameter(11, java.sql.Types.INTEGER);
            cals.setString(12, unsignedText);
            cals.setString(13, signedText);
            cals.setString(14, functionName);
            cals.setInt(15, dataInId);
            cals.setObject(16, (oathResponseId == -1) ? null : oathResponseId);

            cals.execute();

            billCode = cals.getString(10);

        } catch (Exception e) {
            e.printStackTrace();
            billCode = channelName.concat("-").concat(userContract).concat("-").concat(ExtFunc.getDateFormat());
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return billCode;
    }

    public void updateClientLog(int transId, String responseData) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {
            conn = getDBConnection();
            String str = "{ ?=call FRONT_UPDATECLIENTLOG(?, ?) }";
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, transId);
            cals.setString(3, responseData);
            cals.execute();

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
    }

    public int insertDataIn(String request) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int Id = 0;
        try {
            conn = getDBConnection();
            String str = "{ ?=call FRONT_INFORMATIONININSERT(?, ?) }";
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, request);
            cals.registerOutParameter(3, OracleTypes.INTEGER);
            cals.execute();
            Id = cals.getInt(3);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return Id;
    }

    public void insertDataOut(String response, int dataInId) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {
            conn = getDBConnection();
            String str = "{ ?=call FRONT_INFORMATIONOUTINSERT(?, ?) }";
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, response);
            cals.setInt(3, dataInId);
            cals.execute();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
    }

    public String insertTrustedHubTransaction(
            String user,
            String ip,
            String workerName,
            String clientBillCode,
            String channelCode,
            String requestData,
            String unsignedData,
            String functionName,
            int dataInId,
            Integer trustedHubTransId,
            Integer agreementId,
            boolean isBackOffice) {
        // re-process xmlData Request to hide sensitive data
        requestData = ExtFunc.replaceContentInXmlTag(requestData, Defines._PASSWORD, Defines._HIDDENPASSWORD);
        requestData = ExtFunc.replaceContentInXmlTag(requestData, Defines._SIGNATUREIMAGE, Defines._BASE64DATA);
        requestData = ExtFunc.replaceContentInXmlTag(requestData, Defines._CURRENTPW, Defines._HIDDENPASSWORD);
        requestData = ExtFunc.replaceContentInXmlTag(requestData, Defines._NEWPW, Defines._HIDDENPASSWORD);
        requestData = ExtFunc.replaceContentInXmlTag(requestData, Defines._OTP, Defines._HIDDENPASSWORD);
        requestData = ExtFunc.replaceContentInXmlTag(requestData, Defines._NEXTOTP, Defines._HIDDENPASSWORD);

        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        String billCode = null;
        try {
            conn = getDBConnection();
            String str = "{ ?=call FRONT_INSERTTRUSTEDHUBTRANSACTION(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) }";
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, user);
            cals.setString(3, ip);
            cals.setString(4, workerName);
            cals.setString(5, clientBillCode);
            cals.setString(6, channelCode);
            cals.setString(7, requestData);
            cals.setString(8, unsignedData);
            cals.setString(9, functionName);
            cals.setInt(10, dataInId);
            cals.setObject(11, trustedHubTransId);
            cals.setBoolean(12, isBackOffice);
            cals.setObject(13, agreementId);
            cals.registerOutParameter(14, java.sql.Types.VARCHAR);
            cals.execute();
            billCode = cals.getString(14);
        } catch (Exception e) {
            e.printStackTrace();
            billCode = channelCode.concat("-").concat(user).concat("-").concat(ExtFunc.getDateFormat());
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return billCode;
    }

    public void updateTrustedHubTransaction(
            int trustedHubTransId,
            int responseCode,
            String responseData,
            String signedData,
            Integer preTrustedHubTransId,
            Integer agreementId) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {
            conn = getDBConnection();
            String str = "{ ?=call FRONT_UPDATETRUSTEDHUBTRANSACTION(?, ?, ?, ?, ?, ?) }";
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, trustedHubTransId);
            cals.setInt(3, responseCode);
            cals.setString(4, responseData);
            cals.setString(5, signedData);
            cals.setObject(6, preTrustedHubTransId);
            cals.setObject(7, agreementId);
            cals.execute();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
    }

    public boolean authInsertOTPTransaction(int otpTransactionID, String otp,
            String transactionData, int otpInformationId, String method, String otpStatus) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_INSERTASYNCTRANSACTION(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, otpTransactionID);
            cals.setString(3, otp);
            cals.setString(4, transactionData);
            cals.setInt(5, otpInformationId);
            cals.setString(6, method);
            cals.setString(7, otpStatus);
            cals.setObject(8, null);
            cals.setObject(9, null);
            cals.setObject(10, null);
            cals.setObject(11, null);
            cals.setObject(12, null);
            cals.setObject(13, null);
            cals.setObject(14, null);
            cals.setObject(15, null);

            cals.setObject(16, null);
            cals.setObject(17, null);
            cals.setObject(18, null);
            cals.setObject(19, null);
            cals.setObject(20, null);

            cals.registerOutParameter(21, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(21);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }

        return (getresult == 0);
    }

    public boolean getIsOptimized() {
        if (isOptimized == null) {
            gp = reloadGeneralPolicy();
            isOptimized = gp.isFrontIsOptimized();
        }
        return isOptimized;
    }

    public boolean reloadIsOptimized() {
        gp = reloadGeneralPolicy();
        isOptimized = gp.isFrontIsOptimized();
        return isOptimized;
    }

    public int getIsFunctionAccess() {
        GeneralPolicy gp = getGeneralPolicy();
        int result = gp.isFrontIsAccessFunction() ? 1 : 0;
        return result;
    }

    public boolean checkUser(String user, String channelCode) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_CHECKUSER(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, user);
            cals.setString(3, channelCode);
            cals.registerOutParameter(4, OracleTypes.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(4);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }

        return (getresult == 0);
    }

    public boolean authCheckOTPEmail(String user, String otpEmail, String channelCode) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_CHECKOTPEMAIL(?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, user);
            cals.setString(3, otpEmail);
            cals.setString(4, channelCode);
            cals.registerOutParameter(5, OracleTypes.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(5);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 1);
    }

    public boolean authCheckOTPSMS(String user, String otpSMS, String channelCode) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_CHECKOTPSMS(?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, user);
            cals.setString(3, otpSMS);
            cals.setString(4, channelCode);
            cals.registerOutParameter(5, OracleTypes.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(5);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 1);
    }

    public ArrayList<Ip> getIpList() {
        if (!getIsOptimized()) {
            return reloadIpList();
        } else {
            if (ipLists == null) {
                LOG.info("Load Ip list");
                ipLists = new ArrayList<Ip>();
                Connection conn = null;
                ResultSet rs = null;
                CallableStatement cals = null;
                try {
                    String strQuery = "{ ?=call FRONT_IPLISTALL() }";
                    conn = getDBConnection();
                    cals = conn.prepareCall(strQuery);
                    cals.registerOutParameter(1, OracleTypes.INTEGER);
                    rs = cals.executeQuery();
                    while (rs.next()) {
                        int ipListID = rs.getInt("IPListID");
                        int channelID = rs.getInt("channelID");
                        String channelCode = rs.getString("ChannelCode");
                        String ipDb = rs.getString("ip");
                        boolean activeFlag = rs.getBoolean("ActiveFlag");
                        String descriptions = rs.getString("IPListDesc");

                        if (activeFlag) {
                            Ip ip = new Ip();
                            ip.setIpListID(ipListID);
                            ip.setChannelID(channelID);
                            ip.setIp(ipDb);
                            ip.setActiveFlag(activeFlag);
                            ip.setDescriptions(descriptions);
                            ip.setChannelCode(channelCode);

                            ipLists.add(ip);
                        }

                    }

                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    /*
                     * begin try { if (conn != null) conn.close(); if (rs !=
                     * null) rs.close(); if (cals != null) cals.close(); }
                     * catch(SQLException e) { e.printStackTrace(); } end
                     */
                }
            }
            return ipLists;
        }
    }

    public ArrayList<Ip> reloadIpList() {
        ArrayList<Ip> _ipLists = new ArrayList<Ip>();
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {
            String strQuery = "{ ?=call FRONT_IPLISTALL() }";
            conn = getDBConnection();
            cals = conn.prepareCall(strQuery);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            rs = cals.executeQuery();
            while (rs.next()) {
                int ipListID = rs.getInt("IPListID");
                int channelID = rs.getInt("channelID");
                String channelCode = rs.getString("ChannelCode");
                String ipDb = rs.getString("ip");
                boolean activeFlag = rs.getBoolean("ActiveFlag");
                String descriptions = rs.getString("IPListDesc");

                if (activeFlag) {
                    Ip ip = new Ip();
                    ip.setIpListID(ipListID);
                    ip.setChannelID(channelID);
                    ip.setIp(ipDb);
                    ip.setActiveFlag(activeFlag);
                    ip.setDescriptions(descriptions);
                    ip.setChannelCode(channelCode);

                    _ipLists.add(ip);
                }

            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        ipLists = _ipLists;
        return _ipLists;
    }

    public ArrayList<Channel> getChannels() {
        if (!getIsOptimized()) {
            return reloadChannels();
        } else {
            if (channels == null) {
                LOG.info("Load Channels");
                channels = new ArrayList<Channel>();
                Connection conn = null;
                ResultSet rs = null;
                CallableStatement cals = null;
                try {
                    String strQuery = "{ ?=call FRONT_CHANNELLIST() }";
                    conn = getDBConnection();
                    cals = conn.prepareCall(strQuery);
                    cals.registerOutParameter(1, OracleTypes.INTEGER);
                    rs = cals.executeQuery();
                    while (rs.next()) {
                        if (rs.getBoolean("ActiveFlag")) {
                            Channel channel = new Channel();
                            channel.setChannelID(rs.getInt("channelID"));
                            channel.setChannelCode(rs.getString("channelCode"));
                            channel.setUser(rs.getString("user"));
                            channel.setPassword(rs.getString("password"));
                            channel.setSignature(rs.getString("signature"));
                            channel.setPem(rs.getString("pem"));
                            channel.setChannelDesc(rs.getString("channelDesc"));
                            channel.setActiveFlag(rs.getBoolean("ActiveFlag"));

                            channels.add(channel);
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    /*
                     * begin try { if (conn != null) conn.close(); if (rs !=
                     * null) rs.close(); if (cals != null) cals.close(); }
                     * catch(SQLException e) { e.printStackTrace(); } end
                     */
                }
            }
            return channels;
        }
    }

    public ArrayList<Channel> reloadChannels() {
        ArrayList<Channel> _channels = new ArrayList<Channel>();
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {
            String strQuery = "{ ?=call FRONT_CHANNELLIST() }";
            conn = getDBConnection();
            cals = conn.prepareCall(strQuery);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            rs = cals.executeQuery();
            while (rs.next()) {
                if (rs.getBoolean("ActiveFlag")) {
                    Channel channel = new Channel();
                    channel.setChannelID(rs.getInt("channelID"));
                    channel.setChannelCode(rs.getString("channelCode"));
                    channel.setUser(rs.getString("user"));
                    channel.setPassword(rs.getString("password"));
                    channel.setSignature(rs.getString("signature"));
                    channel.setPem(rs.getString("pem"));
                    channel.setChannelDesc(rs.getString("channelDesc"));
                    channel.setActiveFlag(rs.getBoolean("ActiveFlag"));

                    _channels.add(channel);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        channels = _channels;
        return _channels;
    }

    public ArrayList<Ca> getCAProviders() {
        if (!getIsOptimized()) {
            return reloadCAProviders();
        } else {
            if (cas == null) {
                LOG.info("Load CAs information");
                cas = new ArrayList<Ca>();
                Connection conn = null;
                ResultSet rs = null;
                CallableStatement cals = null;
                try {
                    String strQuery = "{ ?=call FRONT_GETCA() }";
                    conn = getDBConnection();
                    cals = conn.prepareCall(strQuery);
                    cals.registerOutParameter(1, OracleTypes.CURSOR);
                    cals.execute();
                    rs = (ResultSet) cals.getObject(1);
                    while (rs.next()) {
                        Ca ca = new Ca();
                        ca.setCaID(rs.getInt("CAID"));
                        ca.setCaCode(rs.getString("CACode"));
                        ca.setCaDesc(rs.getString("CADesc"));
                        ca.setOcspUrl(rs.getString("OCSPUrl"));
                        ca.setCrlUrl(rs.getString("CRLUrl"));
                        ca.setCrlPath(System.getProperty("jboss.server.home.dir") + "/" + "../../../../../file/crl/" + rs.getString("CRLPath"));
                        ca.setCert(rs.getString("Cert"));
                        ca.setIsDownloadableCRL(rs.getBoolean("IsDownloadableCRL"));
                        ca.setOcspUrl2(rs.getString("OCSPUrl2"));
                        ca.setCrlUrl2(rs.getString("CRLUrl2"));
                        ca.setCrlPath2(System.getProperty("jboss.server.home.dir") + "/" + "../../../../../file/crl/" + rs.getString("CRLPath2"));
                        ca.setCert2(rs.getString("Cert2"));
                        ca.setIsDownloadableCRL2(rs.getBoolean("IsDownloadableCRL2"));
                        ca.setIsCheckOCSP(rs.getBoolean("CheckOCSP"));
                        ca.setIsCheckCRL(rs.getBoolean("CheckCRL"));
                        ca.setOcspRetry(rs.getInt("CheckOCSPRetry"));
                        ca.setEndPointConfigID(rs.getInt("EndPointConfigID"));
                        ca.setEndPointParamsID(rs.getInt("EndPointParamsID"));
                        ca.setEndPointParamsValue(rs.getString("EndPointParamsValue"));

                        cas.add(ca);
                    }

                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    /*
                     * begin try { if (conn != null) conn.close(); if (rs !=
                     * null) rs.close(); if (cals != null) cals.close(); }
                     * catch(SQLException e) { e.printStackTrace(); } end
                     */
                }
            }
            return cas;
        }
    }

    public ArrayList<Ca> reloadCAProviders() {
        ArrayList<Ca> _cas = new ArrayList<Ca>();
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {
            String strQuery = "{ ?=call FRONT_GETCA() }";
            conn = getDBConnection();
            cals = conn.prepareCall(strQuery);
            cals.registerOutParameter(1, OracleTypes.CURSOR);
            cals.execute();
            rs = (ResultSet) cals.getObject(1);
            while (rs.next()) {
                Ca ca = new Ca();
                ca.setCaID(rs.getInt("CAID"));
                ca.setCaCode(rs.getString("CACode"));
                ca.setCaDesc(rs.getString("CADesc"));
                ca.setOcspUrl(rs.getString("OCSPUrl"));
                ca.setCrlUrl(rs.getString("CRLUrl"));
                ca.setCrlPath(System.getProperty("jboss.server.home.dir") + "/" + "../../../../../file/crl/" + rs.getString("CRLPath"));
                ca.setCert(rs.getString("Cert"));
                ca.setIsDownloadableCRL(rs.getBoolean("IsDownloadableCRL"));
                ca.setOcspUrl2(rs.getString("OCSPUrl2"));
                ca.setCrlUrl2(rs.getString("CRLUrl2"));
                ca.setCrlPath2(System.getProperty("jboss.server.home.dir") + "/" + "../../../../../file/crl/" + rs.getString("CRLPath2"));
                ca.setCert2(rs.getString("Cert2"));
                ca.setIsDownloadableCRL2(rs.getBoolean("IsDownloadableCRL2"));
                ca.setIsCheckOCSP(rs.getBoolean("CheckOCSP"));
                ca.setIsCheckCRL(rs.getBoolean("CheckCRL"));
                ca.setOcspRetry(rs.getInt("CheckOCSPRetry"));
                ca.setEndPointConfigID(rs.getInt("EndPointConfigID"));
                ca.setEndPointParamsID(rs.getInt("EndPointParamsID"));
                ca.setEndPointParamsValue(rs.getString("EndPointParamsValue"));

                _cas.add(ca);
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        cas = _cas;
        return _cas;
    }

    public int getMethodValidateCert(String caCode) {
        int ocsp = 1;
        int crl = 1;
        int result = 1;

        ArrayList<Ca> cas = getCAProviders();
        for (int i = 0; i < cas.size(); i++) {
            if (cas.get(i).getCaDesc().compareTo(caCode) == 0) {
                LOG.info("Get method certificate validation for " + caCode);
                if (!cas.get(i).isIsCheckOCSP()) {
                    ocsp = 0;
                }
                if (!cas.get(i).isIsCheckCRL()) {
                    crl = 0;
                }
                result = (int) (Math.scalb(ocsp, 1) + Math.scalb(crl, 0));
                // 4
                // states:
                // 0 -->
                // 3
            }
        }
        return result;
    }

    public void authInsertRepudiation(String billCode, String signedData,
            String signature, Date signedTime, Date ctsValidFrom,
            Date ctsValidTo, String serialNumber, String issuerName,
            String user, String channelCode) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_REPUDIATIONINSERT(?, ?, ?, ?, ?, ?, ?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.CURSOR);
            cals.setString(2, billCode);
            cals.setString(3, signedData);
            cals.setString(4, signature);
            cals.setTimestamp(5, new java.sql.Timestamp(signedTime.getTime()));
            cals.setTimestamp(6, new java.sql.Timestamp(ctsValidFrom.getTime()));
            cals.setTimestamp(7, new java.sql.Timestamp(ctsValidTo.getTime()));
            cals.setString(8, serialNumber);
            cals.setString(9, issuerName);
            cals.setString(10, user);
            cals.setString(11, channelCode);
            rs = cals.executeQuery();

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
    }

    public void CertificateStatusLogInsert(String type, String serialNumber,
            String result, String caSerialNumber) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {
            conn = getDBConnection();
            String str = "{ ?=call FRONT_CERTIFICATESTATUSLOGINSERT(?, ?, ?, ?) }";
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, type);
            cals.setString(3, serialNumber);
            cals.setString(4, result);
            cals.setString(5, caSerialNumber);
            cals.execute();

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
    }

    public boolean checkTPKICertificate(String thumbprint, String channelCode, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_CHECKTPKICERT(?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, thumbprint);
            cals.setString(3, channelCode);
            cals.setString(4, user);
            cals.registerOutParameter(5, OracleTypes.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(5);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }

        return (getresult == 1);
    }

    public boolean checkLCDPKICertificate(String thumbprint, String channelCode, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_CHECKLCDPKICERTIFICATE(?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, thumbprint);
            cals.setString(3, channelCode);
            cals.setString(4, user);
            cals.registerOutParameter(5, OracleTypes.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(5);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }

        return (getresult == 1);
    }

    public int authCheckOTPHardware(String user, String otpHardware, String channelCode) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = 2;
        try {
            String str = "{ ?=call FRONT_CHECKOTPHARDWARE(?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, user);
            cals.setString(3, otpHardware);
            cals.setString(4, channelCode);
            cals.registerOutParameter(5, OracleTypes.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(5);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return getresult;
    }

    public int insertAgreement(String channelName, String user,
            String agreementStatus, int expiration, String remark, String branchId,
            /*
             * otpinformation
             */
            String otpSMS,
            String otpEmail,
            String otpHardware,
            boolean isOtpEmail,
            boolean isOtpSMS,
            boolean isOtpHardware,
            boolean isOtpSoftware,
            /*
             * single agreement details
             */
            String workerName,
            String keyName,
            String keyType,
            String spkiEmail,
            String spkiSMS,
            String propertiesConfig,
            String signserverSpkiSlotId,
            String signserverSpkiModule,
            String signserverSpkiPin,
            String signserverSpkiLevel,
            int p11InfoId,
            boolean isSignserver,
            String signserverPassword,
            /*
             * pkiinformation
             */
            String tpkiCertificate,
            String tpkiThumbprint,
            boolean isTPKI,
            String lpkiCertificate,
            String lpkiThumbprint,
            boolean isLPKI,
            String wpkiCertificate,
            String wpkiThumbprint,
            boolean isWPKI,
            String msisdn,
            String vendor,
            /*
             * u2finformation
             */
            boolean isU2F,
            String appId) {

        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int agreementId = 1;
        try {
            String str = "{ ?=call FRONT_INSERTAGREEMENT(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            //agreement
            cals.setString(2, channelName);
            cals.setString(3, user);
            cals.setString(4, agreementStatus);
            cals.setInt(5, expiration);
            cals.setString(6, remark);
            //otpinformation
            cals.setString(7, otpSMS);
            cals.setString(8, otpEmail);
            cals.setString(9, otpHardware);
            cals.setInt(10, isOtpEmail == true ? 1 : 0);
            cals.setInt(11, isOtpSMS == true ? 1 : 0);
            cals.setInt(12, isOtpHardware == true ? 1 : 0);
            cals.setInt(13, isOtpSoftware == true ? 1 : 0);
            // single agreement details
            if (!propertiesConfig.equals(Defines.NULL)
                    && !propertiesConfig.equals("")) {
                Properties p = new Properties();
                p.load(new ByteArrayInputStream(propertiesConfig.getBytes()));
                p.setProperty("WORKERGENID1.NAME", workerName);
                p.setProperty("WORKERGENID1.defaultKey", keyName);
                p.setProperty("WORKERGENID1.slot", signserverSpkiSlotId);
                p.setProperty("WORKERGENID1.sharedLibrary", signserverSpkiModule);

                if (signserverSpkiLevel.compareTo(Defines.P11_LEVEL_BASIC) == 0) {
                    p.setProperty("WORKERGENID1.pin", signserverSpkiPin);
                } else {
                    // avanced, so remove pin property
                    p.remove("WORKERGENID1.pin");
                }

                ByteArrayOutputStream os = new ByteArrayOutputStream();
                p.store(os, null);
                propertiesConfig = new String(os.toByteArray());
                os.close();
            }

            if (propertiesConfig.equals("")) {
                propertiesConfig = Defines.NULL;
            }

            cals.setString(14, workerName);
            cals.setString(15, keyName);
            cals.setString(16, propertiesConfig);
            cals.setInt(17, p11InfoId);
            cals.setBoolean(18, isSignserver);
            cals.setString(19, signserverPassword);
            // pkiinformation
            cals.setString(20, tpkiCertificate);
            cals.setString(21, tpkiThumbprint);
            cals.setBoolean(22, isTPKI);

            cals.setString(23, lpkiCertificate);
            cals.setString(24, lpkiThumbprint);
            cals.setBoolean(25, isLPKI);

            cals.setString(26, wpkiCertificate);
            cals.setString(27, wpkiThumbprint);
            cals.setBoolean(28, isWPKI);
            cals.setString(29, msisdn);
            cals.setString(30, vendor.equals(Defines.NULL) ? null : vendor);
            // addition
            cals.setString(31, spkiEmail);
            cals.setString(32, spkiSMS);
            cals.setString(33, keyType);

            cals.registerOutParameter(34, java.sql.Types.INTEGER);
            cals.setString(35, appId);
            cals.setBoolean(36, isU2F);
            rs = cals.executeQuery();
            agreementId = cals.getInt(34);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return agreementId;
    }

    public int authGetArrangementID(String channleCode, String User) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_GETAGREEMENTID(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channleCode);
            cals.setString(3, User);
            cals.registerOutParameter(4, OracleTypes.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(4);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return getresult;
    }

    public int authUpdateAgreement(int agreementID, String agreementStatus) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_UPDATEAGREEMENT(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementID);
            cals.setString(3, agreementStatus);
            cals.registerOutParameter(4, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(4);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return getresult;
    }

    public int authMultiUnregisteration(String idTag) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_MULTIUNREGISTERATION(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, idTag);
            cals.registerOutParameter(3, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(3);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return getresult;
    }

    public boolean authSetExtendArrangement(int agreementID,
            String channelCode, int expiration) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_SETEXTENDAGREEMENT(?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementID);
            cals.setString(3, channelCode);
            cals.setInt(4, expiration);
            cals.registerOutParameter(5, OracleTypes.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(5);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public String authAgreementValidation(String serialNumber, String issuerName) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        String strResult = "";
        try {
            String str = "{ ?=call FRONT_AGREEMENTVALIDATE(?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, serialNumber);
            cals.setString(3, issuerName);
            cals.registerOutParameter(4, java.sql.Types.INTEGER);
            cals.registerOutParameter(5, java.sql.Types.VARCHAR);
            rs = cals.executeQuery();
            getresult = cals.getInt(4);
            strResult = cals.getString(5);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return getresult + "#" + strResult;
    }

    public boolean authSetIsOTPSMSArrangement(int agreementID, boolean isOtpSms) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_SETISOTPSMSAGREEMENT(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementID);
            cals.setInt(3, (isOtpSms == true ? 1 : 0));
            cals.registerOutParameter(4, OracleTypes.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(4);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public boolean authSetOTPSMSArrangement(int agreementID, String otpSms) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_SETOTPSMSAGREEMENT(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementID);
            cals.setString(3, otpSms);
            cals.registerOutParameter(4, OracleTypes.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(4);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public boolean authSetIsOTPEmailArrangement(int agreementID,
            boolean isOtpEmail) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_SETISOTPEMAILAGREEMENT(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementID);
            cals.setInt(3, (isOtpEmail == true ? 1 : 0));
            cals.registerOutParameter(4, OracleTypes.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(4);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public boolean authSetOTPEmailArrangement(int agreementID, String otpEmail) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_SETOTPEMAILAGREEMENT(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementID);
            cals.setString(3, otpEmail);
            cals.registerOutParameter(4, OracleTypes.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(4);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public boolean authSetIsOTPHardwareArrangement(int agreementID,
            boolean isOtpHardware) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_SETISOTPHARDWAREAGREEMENT(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementID);
            cals.setInt(3, (isOtpHardware == true ? 1 : 0));
            cals.registerOutParameter(4, OracleTypes.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(4);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public boolean authSetOTPHardwareArrangement(int agreementID,
            String otpHardware) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_SETOTPHARDWAREAGREEMENT(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementID);
            cals.setString(3, otpHardware);
            cals.registerOutParameter(4, OracleTypes.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(4);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public boolean authSetIsOTPSoftwareArrangement(int agreementID,
            boolean isOtpSoftware) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_SETISOTPSOFTWAREAGREEMENT(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementID);
            cals.setInt(3, (isOtpSoftware == true ? 1 : 0));
            cals.registerOutParameter(4, OracleTypes.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(4);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public boolean authSetIsPKIArrangement(int agreementID, boolean isPKI) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_SETISTPKIAGREEMENT(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementID);
            cals.setInt(3, (isPKI == true ? 1 : 0));
            cals.registerOutParameter(4, OracleTypes.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(4);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public boolean authSetCertificateArrangement(int agreementID,
            String thumbprint, String certificate) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;

        try {
            String str = "{ ?=call FRONT_SETTPKICERTAGREEMENT(?, ?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementID);
            cals.setString(3, thumbprint);
            cals.setString(4, certificate);

            cals.registerOutParameter(5, OracleTypes.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(5);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);

    }

    public boolean authSetIsLCDPKIArrangement(int agreementID, boolean isPKI) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_SETISLPKIAGREEMENT(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementID);
            cals.setInt(3, (isPKI == true ? 1 : 0));
            cals.registerOutParameter(4, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(4);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public boolean authSetLCDCertificateArrangement(int agreementID,
            String thumbprint, String certificate) {

        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_SETLPKICERTAGREEMENT(?, ?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementID);
            cals.setString(3, thumbprint);
            cals.setString(4, certificate);
            cals.registerOutParameter(5, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(5);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);

    }

    public GeneralPolicy getGeneralPolicy() {
        if (!getIsOptimized()) {
            return reloadGeneralPolicy();
        } else {
            if (gp == null) {
                LOG.info("Load GeneralPolicy information");
                Connection conn = null;
                ResultSet rs = null;
                CallableStatement cals = null;
                gp = new GeneralPolicy();
                try {
                    String sql = "{ ?=call FRONT_GENERALPOLICYLIST() }";
                    conn = getDBConnection();
                    cals = conn.prepareCall(sql);
                    cals.registerOutParameter(1, OracleTypes.INTEGER);
                    rs = cals.executeQuery();
                    while (rs.next()) {
                        gp.setGeneralPolicyID(rs.getInt("GeneralPolicyID"));
                        gp.setFrontExpirationNotificationDay(rs.getInt("Front_ExpirationNotificationDay"));
                        gp.setFrontMaxRetry(rs.getInt("Front_MaxRetry"));
                        gp.setFrontFreezeTime(rs.getInt("Front_FreezeTime"));
                        gp.setFrontOTPMaxEvent(rs.getInt("Front_OTPMaxEvent"));
                        gp.setFrontOTPMaxInterval(rs.getInt("Front_OTPMaxInterval"));
                        gp.setFrontOTPNumDigits(rs.getInt("Front_OTPNumDigits"));
                        gp.setFrontOTPTimeOut(rs.getInt("Front_OTPTimeOut"));
                        gp.setFrontHAIntervalCheck(rs.getInt("Front_HAIntervalCheck"));

                        gp.setFrontIsForgotEmailSignserver(rs.getBoolean("Front_IsForgotEmailSignserver"));
                        gp.setFrontIsHAEmail(rs.getBoolean("Front_IsHAEmail"));
                        gp.setFrontIsHASMS(rs.getBoolean("Front_IsHASMS"));
                        gp.setFrontIsHAReSent(rs.getBoolean("Front_IsHAReSent"));
                        gp.setFrontIsAccessFunction(rs.getBoolean("Front_IsAccessFunction"));
                        gp.setFrontIsOptimized(rs.getBoolean("Front_IsOptimized"));

                        gp.setFrontDefaultPassSignserver(rs.getString("Front_DefaultPassSignserver"));
                        gp.setFrontAgreementCreationAutoLink(rs.getBoolean("Front_AgreementCreationAutoLink"));
                        gp.setFrontAgreementActivationAutoLink(rs.getBoolean("Front_AgreementActivationAutoLink"));
                        gp.setFrontIsRandomSignServerPassword(rs.getBoolean("Front_IsRandomSignServerPassword"));
                        gp.setFrontIsNotifySignServerCertificateByEmail(rs.getBoolean("Front_IsNotifySignServerCertificateByEmail"));
                        gp.setFrontIsNotifySignServerPasswordByEmail(rs.getBoolean("Front_IsNotifySignServerPasswordByEmail"));
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    /*
                     * begin try { if (conn != null) conn.close(); if (rs !=
                     * null) rs.close(); } catch(SQLException e) {
                     * e.printStackTrace(); } end
                     */
                }
            }
            return gp;
        }
    }

    public GeneralPolicy reloadGeneralPolicy() {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        GeneralPolicy _gp = new GeneralPolicy();
        try {
            String sql = "{ ?=call FRONT_GENERALPOLICYLIST() }";
            conn = getDBConnection();
            cals = conn.prepareCall(sql);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            rs = cals.executeQuery();
            while (rs.next()) {
                _gp.setGeneralPolicyID(rs.getInt("GeneralPolicyID"));
                _gp.setFrontExpirationNotificationDay(rs.getInt("Front_ExpirationNotificationDay"));
                _gp.setFrontMaxRetry(rs.getInt("Front_MaxRetry"));
                _gp.setFrontFreezeTime(rs.getInt("Front_FreezeTime"));
                _gp.setFrontOTPMaxEvent(rs.getInt("Front_OTPMaxEvent"));
                _gp.setFrontOTPMaxInterval(rs.getInt("Front_OTPMaxInterval"));
                _gp.setFrontOTPNumDigits(rs.getInt("Front_OTPNumDigits"));
                _gp.setFrontOTPTimeOut(rs.getInt("Front_OTPTimeOut"));
                _gp.setFrontHAIntervalCheck(rs.getInt("Front_HAIntervalCheck"));

                _gp.setFrontIsForgotEmailSignserver(rs.getBoolean("Front_IsForgotEmailSignserver"));
                _gp.setFrontIsHAEmail(rs.getBoolean("Front_IsHAEmail"));
                _gp.setFrontIsHASMS(rs.getBoolean("Front_IsHASMS"));
                _gp.setFrontIsHAReSent(rs.getBoolean("Front_IsHAReSent"));
                _gp.setFrontIsAccessFunction(rs.getBoolean("Front_IsAccessFunction"));
                _gp.setFrontIsOptimized(rs.getBoolean("Front_IsOptimized"));

                _gp.setFrontDefaultPassSignserver(rs.getString("Front_DefaultPassSignserver"));
                _gp.setFrontAgreementCreationAutoLink(rs.getBoolean("Front_AgreementCreationAutoLink"));
                _gp.setFrontAgreementActivationAutoLink(rs.getBoolean("Front_AgreementActivationAutoLink"));
                _gp.setFrontIsRandomSignServerPassword(rs.getBoolean("Front_IsRandomSignServerPassword"));
                _gp.setFrontIsNotifySignServerCertificateByEmail(rs.getBoolean("Front_IsNotifySignServerCertificateByEmail"));
                _gp.setFrontIsNotifySignServerPasswordByEmail(rs.getBoolean("Front_IsNotifySignServerPasswordByEmail"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); } catch(SQLException e) { e.printStackTrace(); } end
             */
        }
        gp = _gp;
        return _gp;
    }

    public List<EndPointConfig> getEndPointConfig() {
        if (!getIsOptimized()) {
            return reloadEndPointConfig();
        } else {
            if (epc == null) {
                LOG.info("Load EndPointConfig information");
                Connection conn = null;
                ResultSet rs = null;
                CallableStatement cals = null;
                epc = new ArrayList<EndPointConfig>();
                try {
                    String sql = "{ ?=call FRONT_ENDPOINTCONFIGLIST() }";
                    conn = getDBConnection();
                    cals = conn.prepareCall(sql);
                    cals.registerOutParameter(1, OracleTypes.INTEGER);
                    rs = cals.executeQuery();
                    while (rs.next()) {
                        EndPointConfig endPointConfig = new EndPointConfig();
                        endPointConfig.setEndPointConfigID(rs.getInt("EndPointConfigID"));
                        endPointConfig.setUrl(rs.getString("URL"));
                        endPointConfig.setAppID(rs.getString("AppID"));
                        endPointConfig.setKeyID(rs.getInt("KeyID"));
                        endPointConfig.setKeyValue(rs.getString("KeyValue"));
                        endPointConfig.setHostname(rs.getString("Hostname"));
                        epc.add(endPointConfig);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    /*
                     * begin try { if (conn != null) conn.close(); if (rs !=
                     * null) rs.close(); } catch(SQLException e) {
                     * e.printStackTrace(); } end
                     */
                }
            }
            return epc;
        }
    }

    public List<EndPointConfig> reloadEndPointConfig() {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        List<EndPointConfig> _epc = new ArrayList<EndPointConfig>();
        try {
            String sql = "{ ?=call FRONT_ENDPOINTCONFIGLIST() }";
            conn = getDBConnection();
            cals = conn.prepareCall(sql);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            rs = cals.executeQuery();
            while (rs.next()) {
                EndPointConfig endPointConfig = new EndPointConfig();
                endPointConfig.setEndPointConfigID(rs.getInt("EndPointConfigID"));
                endPointConfig.setUrl(rs.getString("URL"));
                endPointConfig.setAppID(rs.getString("AppID"));
                endPointConfig.setKeyID(rs.getInt("KeyID"));
                endPointConfig.setKeyValue(rs.getString("KeyValue"));
                endPointConfig.setHostname(rs.getString("Hostname"));
                _epc.add(endPointConfig);
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); } catch(SQLException e) { e.printStackTrace(); } end
             */
        }
        epc = _epc;
        return _epc;
    }

    public int AdminWSLogin(int ClientID, String UserName, String Password) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        String uname = null;
        String pass = null;
        String type = null;
        try {
            String sql = "{ ?=call FRONT_ADMINWS_GETTMSUSER(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(sql);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, UserName);
            cals.setString(3, Password);
            rs = cals.executeQuery();
            while (rs.next()) {
                uname = rs.getString(2);
                pass = rs.getString(3);
                type = rs.getString(5);
                if (uname == null || uname.equals("")) {
                    return -1; // user not exist
                } else {
                    // login ok
                    if (type.equals("ADMI")) {
                        return 1; // super admin
                    } else {
                        return 2; // normal user
                    }
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); } catch(SQLException e) { e.printStackTrace(); } end
             */
        }
        return -2;
    }

    public List<String> getAllIPFilter() {
        List<String> list = new ArrayList<String>();
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        String ip = null;
        try {
            String sql = "{ ?=call FRONT_ADMINWS_GETIPLIST(?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(sql);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, "TRUSTEDHUB");
            rs = cals.executeQuery();
            while (rs.next()) {
                ip = rs.getString(1);
                if (!ip.equals("") && ip != null) {
                    list.add(ip);
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); } catch(SQLException e) { e.printStackTrace(); } end
             */
        }
        return list;
    }

    public void addIPFilter(String Ip, String desr, int activeFlag,
            String channel) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {
            conn = getDBConnection();
            String str = "{ ?=call FRONT_IPLISTINSERT(?, ?, ?, ?) }";
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, Ip);
            cals.setString(3, desr);
            cals.setInt(4, activeFlag);
            cals.setString(5, channel);
            cals.execute();

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
    }

    public void removeIPFilter(String Ip, String channelID) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {
            conn = getDBConnection();
            String str = "{ ?=call FRONT_IPLISTDELETE(?, ?) }";
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, Ip);
            cals.setString(3, channelID);
            cals.execute();

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
    }

    public int[] getAgreementStatusUser(String username, String channelName,
            int workerType) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int[] info = new int[2];
        try {
            String sql = "{ ?=call FRONT_GETAGREEMENTSTATUSUSER(?, ?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(sql);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, username);
            cals.setString(3, channelName);
            cals.setInt(4, workerType);
            cals.registerOutParameter(5, java.sql.Types.INTEGER);
            cals.registerOutParameter(6, java.sql.Types.INTEGER);
            cals.execute();
            info[0] = cals.getInt(5);
            info[1] = cals.getInt(6);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return info;
    }

    public int checkHWOTP(String channelName, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int status = -1;
        try {
            String sql = "{ ?=call FRONT_CHECKHWOTP(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(sql);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, user);
            cals.setString(3, channelName);
            cals.registerOutParameter(4, java.sql.Types.INTEGER);
            cals.execute();
            status = cals.getInt(4);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return status;
    }

    public int leftRetryHWOTP(String channelName, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int status = -1;
        int leftRetry = -1;
        try {
            String sql = "{ ?=call FRONT_LEFTRETRYHWOTP(?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(sql);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, user);
            cals.setString(3, channelName);
            cals.registerOutParameter(4, java.sql.Types.INTEGER);
            cals.registerOutParameter(5, java.sql.Types.INTEGER);
            cals.execute();
            status = cals.getInt(4);
            leftRetry = cals.getInt(5);

            if (status != 0) {
                leftRetry = -100;
            }

            if (leftRetry == 0) {
                leftRetry = -100;
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return leftRetry;
    }

    public int checkHWLCDPKI(String channelName, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int status = -1;
        try {
            String sql = "{ ?=call FRONT_CHECKHWLCDPKI(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(sql);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, user);
            cals.setString(3, channelName);
            cals.registerOutParameter(4, java.sql.Types.INTEGER);
            cals.execute();
            status = cals.getInt(4);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return status;
    }

    public int leftRetryHWLCDPKI(String channelName, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int status = -1;
        int leftRetry = -1;
        try {
            String sql = "{ ?=call FRONT_LEFTRETRYHWLCDPKI(?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(sql);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, user);
            cals.setString(3, channelName);
            cals.registerOutParameter(4, java.sql.Types.INTEGER);
            cals.registerOutParameter(5, java.sql.Types.INTEGER);
            cals.execute();
            status = cals.getInt(4);
            leftRetry = cals.getInt(5);
            if (status != 0) {
                leftRetry = -100;
            }

            if (leftRetry == 0) {
                leftRetry = -100;
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return leftRetry;
    }

    public void resetErrorCounterHWLCDPKI(String channelCode, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {
            String sql = "{ ?=call FRONT_RESETHWLCDPKI(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(sql);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelCode);
            cals.setString(3, user);
            cals.execute();

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
    }

    public int checkHWPKI(String channelName, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int status = -1;
        try {
            String sql = "{ ?=call FRONT_CHECKHWPKI(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(sql);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, user);
            cals.setString(3, channelName);
            cals.registerOutParameter(4, java.sql.Types.INTEGER);
            cals.execute();
            status = cals.getInt(4);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return status;
    }

    public int leftRetryHWPKI(String channelName, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int status = -1;
        int leftRetry = -1;
        try {
            String sql = "{ ?=call FRONT_LEFTRETRYHWPKI(?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(sql);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, user);
            cals.setString(3, channelName);
            cals.registerOutParameter(4, java.sql.Types.INTEGER);
            cals.registerOutParameter(5, java.sql.Types.INTEGER);
            cals.execute();
            status = cals.getInt(3);
            leftRetry = cals.getInt(5);
            if (status != 0) {
                leftRetry = -100;
            }

            if (leftRetry == 0) {
                leftRetry = -100;
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return leftRetry;
    }

    public String authGetOTPHardware(String channelCode, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        String otpHardware = "";
        try {
            String str = "{ ?=call FRONT_AUTHGETOTPHARDWARE(?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelCode);
            cals.setString(3, user);
            cals.registerOutParameter(4, java.sql.Types.INTEGER);
            cals.registerOutParameter(5, java.sql.Types.VARCHAR);
            rs = cals.executeQuery();
            getresult = cals.getInt(4);
            otpHardware = cals.getString(5);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return otpHardware;
    }

    public int authGetOTPDigits(String channelCode, String user) {
        int getresult = 8;

        GeneralPolicy gp = getGeneralPolicy();
        getresult = gp.getFrontOTPNumDigits();

        return getresult;
    }

    public int authGetOTPInformationID(String channelName, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_GETOTPINFORMATIONID(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelName);
            cals.setString(3, user);
            cals.registerOutParameter(4, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(4);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return getresult;
    }

    public void resetErrorCounterHWOTP(String channelCode, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {
            String sql = "{ ?=call FRONT_RESETHWOTP(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(sql);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelCode);
            cals.setString(3, user);
            cals.execute();

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
    }

    public void resetErrorCounterHWPKI(String channelCode, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {
            String sql = "{ ?=call FRONT_RESETHWPKI(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(sql);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelCode);
            cals.setString(3, user);
            cals.execute();

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
    }

    public String getSerialNumberFromCa(String channelName, String username) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        String certSerial = "";
        try {
            String sql = "{ ?=call FRONT_GETSERIALNUMBERCONTRACT(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(sql);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelName);
            cals.setString(3, username);
            rs = cals.executeQuery();
            while (rs.next()) {
                certSerial = rs.getString(1);
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); } catch(SQLException e) { e.printStackTrace(); } end
             */
        }
        return certSerial;
    }

    public boolean authCheckOTPMethod(String channelCode, String user,
            String method) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_CHECKOTPMETHOD(?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelCode);
            cals.setString(3, user);
            cals.setString(4, method);
            cals.registerOutParameter(5, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(5);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public boolean authCheckOTPMethodLinked(String channelCode, String user,
            String method) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_CHECKOTPMETHODLINKED(?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelCode);
            cals.setString(3, user);
            cals.setString(4, method);
            cals.registerOutParameter(5, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(5);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public boolean authCheckOTPPerformance(String channelName, String user,
            String method) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_CHECKOTPPERFORMANCE(?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelName);
            cals.setString(3, user);
            cals.setString(4, method);
            cals.registerOutParameter(5, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(5);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public int countKeyStore() {
        Connection conn = null;
        CallableStatement cals = null;
        int count = 0;
        try {
            String str = "{ ?=call FRONT_COUNTKEYSTORE(?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.registerOutParameter(2, java.sql.Types.INTEGER);
            cals.executeQuery();
            count = cals.getInt(2);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (cals != null)
             * cals.close(); } catch (SQLException e) { e.printStackTrace(); }
             * end
             */
        }
        return count;
    }

    public int insertEndpointLog(String channelCode, String cif, String functionName, String fileId, String phoneNo, String pkisim, String email, String request, String response, Integer clientLogId) {
        Connection conn = null;
        CallableStatement cals = null;
        int endpointId = -1;
        try {
            String str = "{ ?=call FRONT_ENDPOINTLOGINSERT(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelCode);
            cals.setString(3, cif);
            cals.setString(4, functionName);
            cals.setString(5, fileId);
            cals.setString(6, phoneNo);
            cals.setString(7, email);
            cals.setString(8, request);
            cals.setString(9, response);
            cals.setString(10, pkisim);
            cals.setObject(11, clientLogId);
            cals.registerOutParameter(12, java.sql.Types.INTEGER);
            cals.executeQuery();
            endpointId = cals.getInt(12);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (cals != null)
             * cals.close(); } catch (SQLException e) { e.printStackTrace(); }
             * end
             */
        }
        return endpointId;
    }

    public boolean authCheckRelation(String channelCode, String functionName) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int status = -1;
        try {
            String sql = "{ ?=call FRONT_CHECKRELATION(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(sql);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelCode);
            cals.setString(3, functionName);
            cals.registerOutParameter(4, java.sql.Types.INTEGER);
            cals.execute();
            status = cals.getInt(4);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (status == 0);
    }

    public String[] authGetAsyncTransaction(int otpTransactionId) {
        String[] tmp = new String[21];
        CallableStatement cals = null;
        Connection conn = null;
        ResultSet rs = null;
        boolean isNotNull = false;
        try {
            conn = getDBConnection();
            cals = conn.prepareCall("{ ?=call FRONT_GETASYNCTRANSACTION(?) }");
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, otpTransactionId);
            rs = cals.executeQuery();
            while (rs.next()) {
                String verifiedDate = rs.getString("VerifiedDate");
                String otp = rs.getString("OTP");
                String SysDateTime = rs.getString("SystemDateTime");
                String OTPStatus = rs.getString("AsyncTransactionStatus");
                String billCode = rs.getString("BillCode");
                String streamPath = rs.getString("StreamPath");
                String fileType = rs.getString("FileType");
                String dcStreamDataPath = rs.getString("DcDataPath");
                String dcStreamSignPath = rs.getString("DcSignPath");
                String msspTransId = rs.getString("AETransactionID");
                String transCode = rs.getString("TransactionCode");
                String externalStorageResponse = rs.getString("ExternalStorageResponse");
                int externalStorageResponseStatus = rs.getInt("ExternalStorageResponseStatusCode");
                String transactionData = rs.getString("TransactionData");
                String userContract = rs.getString("User");

                String fileId = rs.getString("FileID");
                String mineType = rs.getString("MineType");
                String fileName = rs.getString("FileName");
                String dataToSign = rs.getString("DataToSign");
                String fileDisplay = rs.getString("FileDisplay");

                tmp[0] = String.valueOf(otpTransactionId);
                tmp[1] = verifiedDate;
                tmp[2] = otp;
                tmp[3] = SysDateTime;
                tmp[4] = OTPStatus;
                tmp[5] = billCode;
                tmp[6] = streamPath;
                tmp[7] = fileType;
                tmp[8] = dcStreamDataPath;
                tmp[9] = dcStreamSignPath;
                tmp[10] = msspTransId;
                tmp[11] = transCode;
                tmp[12] = externalStorageResponse;
                tmp[13] = String.valueOf(externalStorageResponseStatus);
                tmp[14] = transactionData;
                tmp[15] = userContract;

                tmp[16] = fileId;
                tmp[17] = mineType;
                tmp[18] = fileName;
                tmp[19] = dataToSign;
                tmp[20] = fileDisplay;

                isNotNull = true;
            }
            if (!isNotNull) {
                tmp = null;
            }

        } catch (Exception e) {
            e.printStackTrace();
            tmp = null;
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return tmp;
    }

    public void authSetOTPTransactionStatus(int transactionID,
            String transactionstatus) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {
            String str = "{ ?=call FRONT_SETASYNCTRANSACTIONSTATUS(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, transactionID);
            cals.setString(3, transactionstatus);

            rs = cals.executeQuery();

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
    }

    public boolean authInsertPKITransaction(int otpTransactionID, String otp,
            String transactionData, int otpInformationId, String method,
            String otpStatus, String streamPath, String fileType, String fileId, String fileName, String mineType, String displayValue) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_INSERTASYNCTRANSACTION(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, otpTransactionID);
            cals.setString(3, otp);
            cals.setString(4, transactionData);
            cals.setInt(5, otpInformationId);
            cals.setString(6, method);
            cals.setString(7, otpStatus);
            cals.setString(8, streamPath);
            cals.setString(9, fileType);
            cals.setObject(10, null);
            cals.setObject(11, null);
            cals.setObject(12, null);
            cals.setObject(13, null);
            cals.setObject(14, null);
            cals.setObject(15, null);

            cals.setObject(16, fileId);
            cals.setObject(17, mineType);
            cals.setObject(18, fileName);
            cals.setObject(19, null);
            cals.setObject(20, displayValue);

            cals.registerOutParameter(21, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(21);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }

        return (getresult == 0);
    }

    public boolean authInsertDcWPKITransaction(int otpTransactionID, String dcDataPath,
            String dcSignPath, String transactionId, String fileType, String requestId, String fileName,
            String fileId, String mimeType, String displayValue) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_INSERTASYNCTRANSACTION(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            /*
             * cals.registerOutParameter(1, OracleTypes.INTEGER); cals.setInt(2,
             * otpTransactionID); cals.setObject(3, displayValue);
             * cals.setObject(4, dtbs); cals.setObject(5,
             * Defines.SIGNATURE_METHOD_WPKI); cals.setObject(6, null);
             * cals.setObject(7, null); cals.setObject(8, displayData);
             * cals.setObject(9, fileType); cals.setObject(10, dcDataPath);
             * cals.setObject(11, dcSignPath); cals.setObject(12, aeTransId);
             * cals.setObject(13, transCode); cals.setObject(14,
             * externalStorageResp); cals.setObject(15, null);
             *
             * cals.setObject(16, null); cals.setObject(17, null);
             * cals.setObject(18, null); cals.setObject(19, null);
             * cals.setObject(20, null);
             *
             * cals.registerOutParameter(21, java.sql.Types.INTEGER);
             */
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, otpTransactionID);
            cals.setObject(3, null);
            cals.setObject(4, null);
            cals.setObject(5, null);
            cals.setObject(6, Defines.SIGNATURE_METHOD_WPKI);
            cals.setObject(7, null);
            cals.setObject(8, null);
            cals.setObject(9, fileType);
            cals.setObject(10, dcDataPath);
            cals.setObject(11, dcSignPath);
            cals.setObject(12, transactionId);
            cals.setObject(13, requestId);
            cals.setObject(14, null);
            cals.setObject(15, null);

            cals.setObject(16, fileId); // file Id
            cals.setObject(17, mimeType); // mineType
            cals.setObject(18, fileName); // fileName
            cals.setObject(19, null);
            cals.setObject(20, displayValue);
            cals.registerOutParameter(21, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(21);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }

        return (getresult == 0);
    }

    public boolean authInsertDcTPKITransaction(int otpTransactionID,
            String dcDataPath,
            String dcSignPath,
            String fileId,
            String fileType,
            String mineType,
            String fileName,
            String dtbs,
            String displayData) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_INSERTASYNCTRANSACTION(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, otpTransactionID);
            cals.setObject(3, null);
            cals.setObject(4, null);
            cals.setObject(5, null);
            cals.setObject(6, Defines.SIGNATURE_METHOD_WPKI);
            cals.setObject(7, null);
            cals.setObject(8, displayData);
            cals.setObject(9, fileType);
            cals.setObject(10, dcDataPath);
            cals.setObject(11, dcSignPath);
            cals.setObject(12, null);
            cals.setObject(13, null);
            cals.setObject(14, null);
            cals.setObject(15, null);

            cals.setObject(16, fileId);
            cals.setObject(17, mineType);
            cals.setObject(18, fileName);
            cals.setObject(19, dtbs);
            cals.setObject(20, displayData);

            cals.registerOutParameter(21, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(21);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public boolean authCheckSimPKI(String user, String PhoneNo,
            String channelCode) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_CHECKSIMPKI(?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, user);
            cals.setString(3, PhoneNo);
            cals.setString(4, channelCode);
            cals.registerOutParameter(5, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(5);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 1);
    }

    public boolean checkPKIMethodLinked(String channelCode, String user, String method) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = 1;
        try {
            String str = "{ call FRONT_CHECKPKIMETHODLINKED(?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.setString(1, channelCode);
            cals.setString(2, user);
            cals.setString(3, method);
            cals.registerOutParameter(4, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(4);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public String[] authCheckSimPKIVendor(String vendor) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        String[] result = new String[3];
        boolean isNull = true;
        try {
            String str = "{ ?=call FRONT_CHECKWPKIVENDOR(?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, vendor);
            rs = cals.executeQuery();

            while (rs.next()) {
                result[0] = rs.getString("WPKIVendorCode");
                result[1] = String.valueOf(rs.getInt("EndPointConfigID"));
                result[2] = rs.getString("EndPointParamsValue");
                isNull = false;
            }

            if (isNull) {
                result = null;
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return result;
    }

    public boolean checkSimKICertificate(String thumbprint,
            String channelCode, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_CHECKSIMPKICERTIFICATE(?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, thumbprint);
            cals.setString(3, channelCode);
            cals.setString(4, user);
            cals.registerOutParameter(5, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(5);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 1);
    }

    public boolean authSetIsSimPKIArrangement(int agreementID, boolean isSimPKI) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_SETISWPKIAGREEMENT(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementID);
            cals.setInt(3, (isSimPKI == true ? 1 : 0));
            cals.registerOutParameter(4, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(4);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public boolean authSetSimCertificateArrangement(int agreementID,
            String thumbprint, String certificate, String phoneNo, String vendor) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_SETWPKICERTAGREEMENT(?, ?, ?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementID);
            cals.setString(3, thumbprint);
            cals.setString(4, certificate);
            cals.setString(5, phoneNo);
            cals.setObject(6, vendor.equals(Defines.NULL) ? null : vendor);
            cals.registerOutParameter(7, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(7);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public String[] authGetPhoneNoSimPKI(String channelCode, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        String[] getresult = new String[6];
        boolean hasValue = false;
        try {
            String str = "{ ?=call FRONT_GETPHONENOWPKI(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelCode);
            cals.setString(3, user);
            rs = cals.executeQuery();
            while (rs.next()) {
                getresult[0] = rs.getString("PhoneNo");
                getresult[1] = rs.getString("WPKICert");
                getresult[2] = rs.getString("WPKIThumbPrint");
                getresult[3] = rs.getString("WPKIVendorCode");
                getresult[4] = rs.getString("EndPointParamsValue");
                getresult[5] = String.valueOf(rs.getInt("EndPointConfigID"));
                hasValue = true;
            }
            if (!hasValue) {
                getresult = null;
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return getresult;
    }

    public boolean authSetIsSignServerArrangement(
            int agreementId,
            boolean isSignserver,
            String signserverPassword,
            int p11InfoId,
            String workerName,
            String keyName,
            String keyType,
            String spkiEmail,
            String spkiSMS,
            String workerConfig,
            String signserverSpkiSlotId,
            String signserverSpkiModule,
            String signserverSpkiPin,
            String signserverSpkiLevel) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_SETISSIGNSERVERAGREEMENT(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementId);
            cals.setBoolean(3, isSignserver);
            cals.setString(4, signserverPassword);
            cals.setInt(5, p11InfoId);
            cals.setString(6, workerName);
            cals.setString(7, keyName);

            // single agreement details
            if (!workerConfig.equals(Defines.NULL)
                    && !workerConfig.equals("")) {
                Properties p = new Properties();
                p.load(new ByteArrayInputStream(workerConfig.getBytes()));
                p.setProperty("WORKERGENID1.NAME", workerName);
                p.setProperty("WORKERGENID1.defaultKey", keyName);
                p.setProperty("WORKERGENID1.slot", signserverSpkiSlotId);
                p.setProperty("WORKERGENID1.sharedLibrary", signserverSpkiModule);

                if (signserverSpkiLevel.compareTo(Defines.P11_LEVEL_BASIC) == 0) {
                    p.setProperty("WORKERGENID1.pin", signserverSpkiPin);
                } else {
                    // avanced, so remove pin property
                    p.remove("WORKERGENID1.pin");
                }

                ByteArrayOutputStream os = new ByteArrayOutputStream();
                p.store(os, null);
                workerConfig = new String(os.toByteArray());
                os.close();
            }

            if (workerConfig.equals("")) {
                workerConfig = Defines.NULL;
            }

            cals.setString(8, workerConfig);
            cals.setString(9, spkiEmail);
            cals.setString(10, spkiSMS);
            cals.setString(11, keyType);
            cals.registerOutParameter(12, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(12);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public String authGetWorkerConfig(String workerName) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        workerName = workerName.toLowerCase();
        String wConfig = "";
        try {
            String str = "{ ?=call FRONT_WORKERCONFIGLIST(?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setObject(2, null);
            rs = cals.executeQuery();
            while (rs.next()) {
                String wName = rs.getString("WorkerConfigCode").toLowerCase();
                if (workerName.contains(wName)) {
                    wConfig = rs.getString("Properties");
                    break;
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return wConfig;
    }

    public void authSANewUpdateCANC(int agreementId) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {

            String str = "{ ?=call FRONT_CANCELCERTSIGNSERVER(?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementId);
            rs = cals.executeQuery();

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
    }

    public boolean authInsertSignExternalStorageTransaction(int otpTransactionID, int transactionStatus) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_INSERTASYNCTRANSACTION(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, otpTransactionID);
            cals.setObject(3, null);
            cals.setObject(4, null);
            cals.setObject(5, null);
            cals.setObject(6, null);
            cals.setObject(7, null);
            cals.setObject(8, null);
            cals.setObject(9, null);
            cals.setObject(10, null);
            cals.setObject(11, null);
            cals.setObject(12, null);
            cals.setObject(13, null);
            cals.setObject(14, null);
            cals.setInt(15, transactionStatus);

            cals.setObject(16, null);
            cals.setObject(17, null);
            cals.setObject(18, null);
            cals.setObject(19, null);
            cals.setObject(20, null);

            cals.registerOutParameter(21, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(21);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }

        return (getresult == 0);
    }

    public void authUpdateSignExternalStorageTransaction(int otpTransactionID, String externalStorageResponse, int externalStorageResponseStatus) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {
            String str = "{ ?=call FRONT_UPDATEASYNCTRANSACTION(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, otpTransactionID);
            cals.setString(3, externalStorageResponse);
            cals.setInt(4, externalStorageResponseStatus);

            rs = cals.executeQuery();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
    }

    public void updateEndpointLog(int clientLogId, Integer endpointId) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {
            String str = "{ ?=call FRONT_ENDPOINTLOGUPDATE(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setObject(2, endpointId);
            cals.setObject(3, clientLogId);
            rs = cals.executeQuery();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
    }

    public String[] authGetCertificateTPKI(String channelCode, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        String[] getresult = new String[2];
        boolean hasValue = false;
        try {
            String str = "{ ?=call FRONT_GETCERTTPKI(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelCode);
            cals.setString(3, user);
            rs = cals.executeQuery();
            while (rs.next()) {
                getresult[0] = rs.getString("TPKICert");
                getresult[1] = rs.getString("TPKIThumbPrint");
                hasValue = true;
            }
            if (!hasValue) {
                getresult = null;
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return getresult;
    }

    public String[] authGetCertificateLPKI(String channelCode, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        String[] getresult = new String[2];
        boolean hasValue = false;
        try {
            String str = "{ ?=call FRONT_GETCERTLPKI(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelCode);
            cals.setString(3, user);
            rs = cals.executeQuery();
            while (rs.next()) {
                getresult[0] = rs.getString("LPKICert");
                getresult[1] = rs.getString("LPKIThumbPrint");
                hasValue = true;
            }
            if (!hasValue) {
                getresult = null;
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return getresult;
    }

    public String[] authCertificateSPKI(String channelCode, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        String[] getresult = new String[11];
        boolean hasValue = false;
        try {
            String str = "{ ?=call FRONT_GETSIGNSERVER(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelCode);
            cals.setString(3, user);
            cals.registerOutParameter(4, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            int response = cals.getInt(4);
            if (response == 0) {
                while (rs.next()) {
                    getresult[0] = rs.getString("Cert");
                    getresult[1] = rs.getString("P11InfoLevelCode");
                    getresult[2] = String.valueOf(rs.getInt("SlotID"));
                    getresult[3] = rs.getString("Module");
                    getresult[4] = ExtFunc.decrypt(rs.getString("Pin"));
                    getresult[5] = ExtFunc.decrypt(rs.getString("Sopin"));
                    getresult[6] = rs.getString("WorkerUUID") != null ? String.valueOf(rs.getString("WorkerUUID")) : null;
                    getresult[7] = rs.getString("CSR");
                    getresult[8] = rs.getString("DN");
                    getresult[9] = rs.getString("CADesc");
                    getresult[10] = String.valueOf(rs.getInt("ValueDay"));
                    hasValue = true;
                }
                if (!hasValue) {
                    getresult = null;
                }
            } else {
                getresult = null;
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return getresult;
    }

    public String[] authEndPointParamsGet(String paramName) {
        String[] getresult = new String[3];
        List<EndPointParams> epParamsList = getEndPointParams();
        boolean isNotNull = false;
        for (int i = 0; i < epParamsList.size(); i++) {
            if (epParamsList.get(i).getEndPointParamsCode().compareTo(paramName) == 0) {
                getresult[0] = epParamsList.get(i).getEndPointParamsCode();
                getresult[1] = epParamsList.get(i).getEndPointParamsValue();
                getresult[2] = String.valueOf(epParamsList.get(i).getEndPointConfigID());
                isNotNull = true;
            }
        }
        if (!isNotNull) {
            getresult = null;
        }

        return getresult;
    }

    public List<EndPointParams> getEndPointParams() {
        if (!getIsOptimized()) {
            return reloadEndPointParams();
        } else {
            if (endPointParams == null) {
                LOG.info("Load EndPointParams information");
                endPointParams = new ArrayList<EndPointParams>();
                Connection conn = null;
                ResultSet rs = null;
                CallableStatement cals = null;
                try {
                    String strQuery = "{ ?=call FRONT_ENDPOINTPARAMSGET(?) }";
                    conn = getDBConnection();
                    cals = conn.prepareCall(strQuery);
                    cals.registerOutParameter(1, OracleTypes.INTEGER);
                    cals.setObject(2, null);
                    rs = cals.executeQuery();
                    while (rs.next()) {
                        EndPointParams epParams = new EndPointParams();
                        epParams.setEndPointParamsCode(rs.getString("EndPointParamsCode"));
                        epParams.setEndPointParamsValue(rs.getString("EndPointParamsValue"));
                        epParams.setEndPointConfigID(rs.getInt("EndPointConfigID"));
                        endPointParams.add(epParams);
                    }

                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    /*
                     * begin try { if (conn != null) conn.close(); if (rs !=
                     * null) rs.close(); if (cals != null) cals.close(); }
                     * catch(SQLException e) { e.printStackTrace(); } end
                     */
                }
            }
            return endPointParams;
        }
    }

    public ArrayList<EndPointParams> reloadEndPointParams() {
        ArrayList<EndPointParams> _endPointParams = new ArrayList<EndPointParams>();

        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {
            String strQuery = "{ ?=call FRONT_ENDPOINTPARAMSGET(?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(strQuery);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setObject(2, null);
            rs = cals.executeQuery();
            while (rs.next()) {
                EndPointParams epParams = new EndPointParams();
                epParams.setEndPointParamsCode(rs.getString("EndPointParamsCode"));
                epParams.setEndPointParamsValue(rs.getString("EndPointParamsValue"));
                epParams.setEndPointConfigID(rs.getInt("EndPointConfigID"));
                _endPointParams.add(epParams);
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        endPointParams = _endPointParams;
        return _endPointParams;
    }

    public List<AgreementObject> authGetAgreementInfo(String channelCode, String user, String id, String agreementStatus) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        List<AgreementObject> result = new ArrayList<AgreementObject>();
        try {
            String str = "{ ?=call FRONT_GETAGREEMENTINFO(?, ?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, user);
            cals.setString(3, channelCode);
            cals.setString(4, id);
            cals.setString(5, agreementStatus);

            rs = cals.executeQuery();
            while (rs.next()) {
                AgreementObject agreement = new AgreementObject();
                agreement.setUser(rs.getString("User"));
                agreement.setRemark(rs.getString("Remark"));
                agreement.setChannel(rs.getString("channelCode"));
                agreement.setAgreementStatus(rs.getString("AgreementStatusCode"));

                agreement.setIsOtpSms(rs.getBoolean("IsOTPSMS"));
                agreement.setOtpSms(rs.getString("OTPSms"));
                agreement.setIsOtpSmsLinked(rs.getBoolean("IsOTPSMSLinked"));

                agreement.setIsOtpEmail(rs.getBoolean("IsOTPEmail"));
                agreement.setOtpEmail(rs.getString("OTPEmail"));
                agreement.setIsOtpEmailLinked(rs.getBoolean("IsOTPEmailLinked"));

                agreement.setIsOtpHardware(rs.getBoolean("IsOTPHardware"));
                agreement.setOtpHardware(rs.getString("OTPHardware"));
                agreement.setIsOtpHardwareLinked(rs.getBoolean("IsOTPHardwareLinked"));

                agreement.setIsOtpSoftware(rs.getBoolean("IsOTPSoftware"));
                agreement.setIsOtpSoftwareLinked(rs.getBoolean("IsOtpSoftwareLinked"));

                agreement.setIsPki(rs.getBoolean("IsTPKI"));
                agreement.setCertificate(rs.getString("TPKICert"));
                agreement.setTpkiThumbPrint(rs.getString("TPKIThumbPrint"));
                agreement.setIsTPKILinked(rs.getBoolean("IsTPKILinked"));

                agreement.setIsLcdPki(rs.getBoolean("IsLPKI"));
                agreement.setLcdCertificate(rs.getString("LPKICert"));
                agreement.setLpkiThumbPrint(rs.getString("LPKIThumbPrint"));
                agreement.setIsLPKILinked(rs.getBoolean("IsLPKILinked"));


                agreement.setIsSimPKI(rs.getBoolean("IsWPKI"));
                agreement.setSimCertificate(rs.getString("WPKICert"));
                agreement.setWpkiThumbPrint(rs.getString("WPKIThumbPrint"));
                agreement.setPkiSim(rs.getString("PhoneNo"));
                agreement.setIsWPKILinked(rs.getBoolean("IsWPKILinked"));


                agreement.setIsSignserver(rs.getBoolean("IsSignserver"));
                agreement.setsCertificate(rs.getString("Cert"));
                agreement.setSpkiThumbPrint(rs.getString("ThumbPrint"));
                agreement.setIsSPKILinked(rs.getBoolean("IsLinked"));

                agreement.setCreatedDate(rs.getDate("CreateDate"));
                agreement.setEffectiveDate(rs.getDate("EffectiveDate"));
                agreement.setExpiredDate(rs.getDate("EndDate"));

                result.add(agreement);
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return result;
    }

    public void authResetOTPTransaction(int otpTransactionID) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {
            String str = "{ ?=call FRONT_RESETASYNCTRANSACTION(?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, otpTransactionID);
            rs = cals.executeQuery();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
    }

    public int[] authCheckPassSignServer(String user, String channelName,
            String password) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int[] response = new int[2];
        try {
            String str = "{ ?=call FRONT_CHECKPASSSIGNSERVER(?, ?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, user);
            cals.setString(3, channelName);
            cals.setString(4, password);
            cals.registerOutParameter(5, java.sql.Types.INTEGER);
            cals.registerOutParameter(6, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            response[0] = cals.getInt(5);
            response[1] = cals.getInt(6);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return response;
    }

    public Object[] authChangePassSignServer(int agreementId, String currentPassword,
            String newPassword) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        Object status = null;
        Object retry = null;
        Object[] authResp = new Object[2];
        try {
            String str = "{ ?=call FRONT_CHANGEPASSSIGNSERVER(?, ?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementId);
            cals.setString(3, currentPassword);
            cals.setString(4, newPassword);
            cals.registerOutParameter(5, java.sql.Types.INTEGER);
            cals.registerOutParameter(6, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            status = cals.getObject(5);
            retry = cals.getObject(6);
            authResp[0] = status;
            authResp[1] = retry;

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return authResp;
    }

    public String[] getBackOfficeParamsDetailClient(String nameParams, boolean isEmail) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        String[] result = null;
        try {
            String str = "{ ?=call FRONT_BACKOFFICEPARAMSDETAILCLIENT(?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, nameParams);
            rs = cals.executeQuery();

            if (isEmail) {
                result = new String[2];
                while (rs.next()) {
                    String valueParams = rs.getString("ValueParams");
                    result[0] = valueParams.substring(valueParams.indexOf("sendMailSubject=") + "sendMailSubject=".length(), valueParams.indexOf("sendMailContent="));
                    result[1] = valueParams.substring(valueParams.indexOf("sendMailContent=") + "sendMailContent=".length());
                }
            } else {
                result = new String[1];
                while (rs.next()) {
                    String valueParams = rs.getString("ValueParams");
                    result[0] = valueParams.substring(valueParams.indexOf("sendSMSContent=") + "sendSMSContent=".length());
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return result;
    }

    public String authGetEmailSignServer(String channelCode, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        String result = null;
        try {
            String str = "{ ?=call FRONT_GETEMAILSIGNSERVER(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelCode);
            cals.setString(3, user);
            rs = cals.executeQuery();

            while (rs.next()) {
                result = rs.getString("Email");
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return result;
    }

    public String authGetPhoneSignServer(String channelCode, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        String result = null;
        try {
            String str = "{ ?=call FRONT_GETPHONESIGNSERVER(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelCode);
            cals.setString(3, user);
            rs = cals.executeQuery();

            while (rs.next()) {
                result = rs.getString("PhoneNo");
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return result;
    }

    public void authResetPassSignserver(int agreementId, String password) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {
            String str = "{ ?=call FRONT_RESETPASSSIGNSERVER(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementId);
            cals.setString(3, password);
            rs = cals.executeQuery();

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
    }

    public void authSAUpdateIsRegistered(int agreementId, boolean isRegistered) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {
            String str = "{ ?=call FRONT_SETISSIGNSERVERLINKED(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementId);
            cals.setBoolean(3, isRegistered);
            rs = cals.executeQuery();

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
    }

    public boolean authSAGetIsRegistered(String channelName, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        boolean result = false;
        try {
            String str = "{ ?=call FRONT_GETISSIGNSERVERLINKED(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelName);
            cals.setString(3, user);
            cals.registerOutParameter(4, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            result = cals.getBoolean(4);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return result;
    }

    public int authCheckSignServerStatus(String channelName, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int result = -1;
        try {
            String str = "{ ?=call FRONT_CHECKSIGNSERVERSTATUS(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, user);
            cals.setString(3, channelName);
            cals.registerOutParameter(4, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            result = cals.getInt(4);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return result;
    }

    public List<ReceiverHAStatus> authReceiverHAStatusList() {
        List<ReceiverHAStatus> receiverHAStatuses = new ArrayList<ReceiverHAStatus>();
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {
            String strQuery = "{ ?=call FRONT_RECEIVERHASTATUSLIST() }";
            conn = getDBConnection();
            cals = conn.prepareCall(strQuery);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            rs = cals.executeQuery();
            while (rs.next()) {
                ReceiverHAStatus receiverHAStatus = new ReceiverHAStatus();
                receiverHAStatus.setReceiverHAStatusID(rs.getInt("ReceiverHAStatusID"));
                receiverHAStatus.setFullName(rs.getString("FullName"));
                receiverHAStatus.setEmail(rs.getString("Email"));
                receiverHAStatus.setPhoneNo(rs.getString("PhoneNo"));

                receiverHAStatuses.add(receiverHAStatus);
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }

        return receiverHAStatuses;
    }

    public void increaseSuccessTransaction() {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {
            String sql = "{ ?=call FRONT_UPDATETOTALTRANSACTIONSUCCESS() }";
            conn = getDBConnection();
            cals = conn.prepareCall(sql);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.execute();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
    }

    public Ca getCa(String caName) {
        Ca ca = null;
        if (cas == null) {
            cas = getCAProviders();
        }
        for (int i = 0; i < cas.size(); i++) {
            if (cas.get(i).getCaDesc().compareTo(caName) == 0) {
                ca = cas.get(i);
            }
        }
        return ca;
    }

    public boolean authSetIsOTPSMSActive(int agreementID, boolean isActive) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_SETISOTPSMSLINKED(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementID);
            cals.setInt(3, (isActive == true ? 1 : 0));
            rs = cals.executeQuery();
            getresult = 0;
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public boolean authSetIsOTPEmailActive(int agreementID, boolean isActive) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_SETISOTPEMAILLINKED(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementID);
            cals.setInt(3, (isActive == true ? 1 : 0));
            rs = cals.executeQuery();
            getresult = 0;
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public boolean authSetIsOTPHardwareActive(int agreementID, boolean isActive) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_SETISOTPHARDWARELINKED(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementID);
            cals.setInt(3, (isActive == true ? 1 : 0));
            rs = cals.executeQuery();
            getresult = 0;
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public boolean authSetIsSimPKIActive(int agreementID, boolean isActive) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_SETISWPKILINKED(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementID);
            cals.setInt(3, (isActive == true ? 1 : 0));
            rs = cals.executeQuery();
            getresult = 0;
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public boolean authSetIsTPKIActive(int agreementID, boolean isActive) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_SETISTPKILINKED(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementID);
            cals.setInt(3, (isActive == true ? 1 : 0));
            rs = cals.executeQuery();
            getresult = 0;
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public boolean authSetIsLPKIActive(int agreementID, boolean isActive) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_SETISLPKILINKED(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementID);
            cals.setInt(3, (isActive == true ? 1 : 0));
            rs = cals.executeQuery();
            getresult = 0;
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public List<OwnerInfo> authGetAgreementValidation(String serialNumber, Date signingTime) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        List<OwnerInfo> ownerInfos = null;
        boolean hasData = false;
        try {

            if (signingTime == null) {
                signingTime = new Date();
            }

            String str = "{ ?=call FRONT_GETAGREEMENTVALIDATION(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);

            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, serialNumber);
            cals.setTimestamp(3, new java.sql.Timestamp(signingTime.getTime()));
            rs = cals.executeQuery();
            ownerInfos = new ArrayList<OwnerInfo>();
            while (rs.next()) {
                OwnerInfo ownerInfo = new OwnerInfo();
                ownerInfo.setChannelName(rs.getString("channelCode"));
                ownerInfo.setCif(rs.getString("User"));
                ownerInfo.setAgreementType(rs.getString("AgreementType"));
                ownerInfos.add(ownerInfo);
                hasData = true;
            }

            if (!hasData) {
                ownerInfos = null;
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return ownerInfos;
    }

    public String OTPInformationGeneration(String transactionData, String otp) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        String getresult = "";
        try {
            String str = "{ ?=call FRONT_GETPARAMETER(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, Defines.PARAMETER_OTP);
            cals.registerOutParameter(3, java.sql.Types.LONGNVARCHAR);
            rs = cals.executeQuery();
            getresult = cals.getString(3);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }

        String data = transactionData.replace(getresult, otp);
        return data;
    }

    public String getWPKITransactionGeneration(String transactionData, String defaultVCSymbol) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        String getresult = "";
        try {
            String str = "{ ?=call FRONT_GETPARAMETER(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, Defines.PARAMETER_TRANSCODE);
            cals.registerOutParameter(3, java.sql.Types.LONGNVARCHAR);
            rs = cals.executeQuery();
            getresult = cals.getString(3);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        String data = null;
        if (transactionData.contains(getresult)) {
            data = transactionData.replace(getresult, defaultVCSymbol);
        } else {
            data = transactionData;
        }
        return data;
    }

    public String getParameter(String paramName) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        String getresult = "";
        try {
            String str = "{ ?=call FRONT_GETPARAMETER(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, paramName);
            cals.registerOutParameter(3, java.sql.Types.LONGNVARCHAR);
            rs = cals.executeQuery();
            getresult = cals.getString(3);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return getresult;
    }

    public String authGetEmailOTP(String channelCode, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        String getresult = "";
        try {
            String str = "{ ?=call FRONT_GETEMAILOTP(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelCode);
            cals.setString(3, user);
            cals.registerOutParameter(4, java.sql.Types.VARCHAR);
            rs = cals.executeQuery();
            getresult = cals.getString(4);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return getresult;
    }

    public String authGetPhoneNoOTP(String channelCode, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        String getresult = "";
        try {
            String str = "{ ?=call FRONT_GETPHONENOOTP(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelCode);
            cals.setString(3, user);
            cals.registerOutParameter(4, java.sql.Types.VARCHAR);
            rs = cals.executeQuery();
            getresult = cals.getString(4);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return getresult;
    }

    public boolean CAUpdateDownloadableCRL(String caName, Boolean isDownloadable1, Boolean isDownloadable2) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        boolean rv = false;
        try {
            String str = "{ ?=call FRONT_CAUPDATEDOWNLOADABLECRL(?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);

            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, caName);
            cals.setObject(3, isDownloadable1);
            cals.setObject(4, isDownloadable2);
            cals.registerOutParameter(5, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            rv = (cals.getInt(5) == 0) ? true : false;

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }

        return rv;
    }

    public int getNumberOCSPReTry(String caName) {
        Ca ca = getCa(caName);
        return ca.getOcspRetry();
    }

    public Tsa getTSA(String tsaDesc) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        Tsa tsa = null;
        boolean hasData = false;
        try {
            String str = "{ ?=call FRONT_GETTSA(?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, tsaDesc);
            rs = cals.executeQuery();
            while (rs.next()) {
                tsa = new Tsa();
                tsa.setTsaUrl(rs.getString("TSAUrl"));
                tsa.setUser(rs.getString("User"));
                tsa.setPassword(rs.getString("Password"));
                tsa.setEndpointConfigId(rs.getInt("EndPointConfigID"));

                tsa.setOcspUrl(rs.getString("OCSPUrl"));
                tsa.setCrlUrl(rs.getString("CRLUrl"));
                tsa.setCrlPath(System.getProperty("jboss.server.home.dir") + "/" + "../../../../../file/crl/" + rs.getString("CRLPath"));
                tsa.setThumbprint(rs.getString("ThumbPrint"));
                tsa.setTsaCACert(rs.getString("TSACACert"));
                tsa.setCheckOcsp(rs.getBoolean("CheckOCSP"));
                tsa.setCheckCrl(rs.getBoolean("CheckCRL"));
                tsa.setCheckOcspRetry(rs.getInt("CheckOCSPRetry"));

                hasData = true;
            }

            if (!hasData) {
                tsa = null;
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }

        return tsa;
    }

    public boolean updateDownloadableCrlTsa(String tsaName, boolean isDownloadable) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        boolean rv = false;
        try {
            String str = "{ ?=call FRONT_TSAUPDATEDOWNLOADABLECRL(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, tsaName);
            cals.setObject(3, isDownloadable);
            cals.registerOutParameter(4, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            rv = (cals.getInt(4) == 0) ? true : false;

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }

        return rv;
    }

    public P11Info getP11Info(String p11Name) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        P11Info p11Info = null;
        boolean hasData = false;
        try {
            String str = "{ ?=call FRONT_GETP11INFO(?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, p11Name);

            rs = cals.executeQuery();
            while (rs.next()) {
                p11Info = new P11Info();
                p11Info.setP11InfoId(rs.getInt("P11InfoID"));
                p11Info.setSlotId(rs.getInt("SlotID"));
                p11Info.setModule(rs.getString("Module"));
                p11Info.setPin(ExtFunc.decrypt(rs.getString("Pin")));
                p11Info.setSopin(ExtFunc.decrypt(rs.getString("Sopin")));
                p11Info.setLevel(rs.getString("P11InfoLevelCode"));
                hasData = true;
            }

            if (!hasData) {
                p11Info = null;
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }

        return p11Info;
    }

    public int checkErrorCountSignServer(String channelName, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int rv = 1;

        try {
            String str = "{ ?=call FRONT_CHECKERRORCOUNTSIGNSERVER(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, user);
            cals.setString(3, channelName);
            cals.registerOutParameter(4, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            rv = cals.getInt(4);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return rv;
    }

    public void resetErrorCountSignServer(String channelName, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;

        try {
            String str = "{ ?=call FRONT_RESETERRORCOUNTSIGNSERVER(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, user);
            cals.setString(3, channelName);
            rs = cals.executeQuery();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
    }

    public void updateSignerServerAgreement(
            int agreementId,
            Integer signserverStatusId,
            String workerName,
            String keyName,
            String keyNameNext,
            String csr,
            String cert,
            String config,
            Integer workerUUID,
            String dn,
            String commonName,
            Date validFrom,
            Date validTo,
            Integer certStatusId,
            Integer caId,
            Integer shareKeyTypeId,
            Integer certProfileId,
            String phoneNo,
            String thumbprint,
            Integer certTypeId) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;

        try {
            String str = "{ ?=call FRONT_SIGNSERVERUPDATE(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementId);
            cals.setObject(3, signserverStatusId);
            cals.setString(4, workerName);
            cals.setString(5, keyName);
            cals.setString(6, keyNameNext);
            cals.setString(7, csr);
            cals.setString(8, cert);
            cals.setString(9, config);
            cals.setObject(10, workerUUID);
            cals.setString(11, dn);
            cals.setString(12, commonName);
            if (validFrom != null) {
                cals.setTimestamp(13, new java.sql.Timestamp(validFrom.getTime()));
            } else {
                cals.setObject(13, validFrom);
            }
            if (validTo != null) {
                cals.setTimestamp(14, new java.sql.Timestamp(validTo.getTime()));
            } else {
                cals.setObject(14, validTo);
            }
            cals.setObject(15, certStatusId);
            cals.setObject(16, caId);
            cals.setObject(17, shareKeyTypeId);
            cals.setObject(18, certProfileId);
            cals.setString(19, phoneNo);
            cals.setString(20, thumbprint);
            cals.setObject(21, certTypeId);
            rs = cals.executeQuery();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
    }

    public String[] getCertTypeKeyInfo(String certTypeCode) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        String[] result = new String[4];
        boolean hasData = false;
        try {
            String str = "{ ?=call FRONT_CERTTYPEGETALGORITHM(?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, certTypeCode);
            rs = cals.executeQuery();
            while (rs.next()) {
                result[0] = rs.getString("AlgorithmSignWithSHACode");
                result[1] = rs.getString("AlgorithmKeyCode");
                result[2] = rs.getString("KeySizeCode");
                result[3] = String.valueOf(rs.getInt("CertTypeID"));
                hasData = true;
            }

            if (!hasData) {
                result = null;
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return result;
    }

    public int getCertProfileId(int valueDay) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int certProfileId = 1;
        boolean hasData = false;
        try {
            String str = "{ ?=call FRONT_VALUEDAYGETCERTPROFILEID(?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, valueDay);
            rs = cals.executeQuery();
            while (rs.next()) {
                certProfileId = rs.getInt("CertProfileID");
                hasData = true;
            }

            if (!hasData) {
                certProfileId = 1;
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return certProfileId;
    }

    public List<CertTemplate> getCertTemplate(int certTypeId) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        List<CertTemplate> list = new ArrayList<CertTemplate>();
        try {
            String str = "{ ?=call FRONT_GETCERTTEMPLATE(?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, certTypeId);
            rs = cals.executeQuery();
            while (rs.next()) {
                CertTemplate certTemplate = new CertTemplate();
                certTemplate.setAttrCode(rs.getString("SubjectDNAttrCode"));
                certTemplate.setPrefix(rs.getString("SubjectDNAttrPreFix"));
                list.add(certTemplate);
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return list;
    }

    public AgreementObject getAgreementByTPKIThumbPrint(String channelName, String thumbprint) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        AgreementObject agreement = null;
        try {
            String str = "{ ?=call FRONT_GETAGREEMENTBYTPKITHUMBPRINT(?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelName);
            cals.setString(3, thumbprint);
            rs = cals.executeQuery();
            while (rs.next()) {
                agreement = new AgreementObject();
                agreement.setChannel(rs.getString("channelCode"));
                agreement.setUser(rs.getString("User"));
                agreement.setCreatedDate(rs.getDate("CreateDate"));
                agreement.setAgreementStatus(rs.getString("AgreementStatusCode"));
                agreement.setEffectiveDate(rs.getDate("EffectiveDate"));
                agreement.setExpiredDate(rs.getDate("EndDate"));
                agreement.setCertificate(rs.getString("TPKICert"));
                agreement.setTpkiThumbPrint(rs.getString("TPKIThumbPrint"));
                agreement.setIsTPKILinked(rs.getBoolean("IsTPKILinked"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return agreement;
    }

    public boolean setIsU2F(int agreementID, boolean isU2F) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_SETISU2F(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementID);
            cals.setInt(3, (isU2F == true ? 1 : 0));
            cals.registerOutParameter(4, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(4);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public boolean setU2FAgreement(int agreementID, String appId) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = -1;
        try {
            String str = "{ ?=call FRONT_SETU2F(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementID);
            cals.setString(3, appId);
            cals.registerOutParameter(4, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(4);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (getresult == 0);
    }

    public String getU2F(String channelCode, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        String getresult = "";
        try {
            String str = "{ ?=call FRONT_GETU2F(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelCode);
            cals.setString(3, user);
            cals.registerOutParameter(4, java.sql.Types.VARCHAR);
            rs = cals.executeQuery();
            getresult = cals.getString(4);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch(SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return getresult;
    }

    public String checkU2FLinked(String channelCode, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int getresult = 1;
        String appId = null;
        try {
            String str = "{ call FRONT_CHECKU2FLINKED(?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelCode);
            cals.setString(3, user);
            cals.registerOutParameter(4, java.sql.Types.VARCHAR);
            cals.registerOutParameter(5, java.sql.Types.INTEGER);
            rs = cals.executeQuery();
            getresult = cals.getInt(5);
            if (getresult == 0) {
                appId = cals.getString(4);
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return appId;
    }

    public void setU2FLinked(int agreementId, boolean isLinked) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {
            String str = "{ ?=call FRONT_SETISU2FLINKED(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setInt(2, agreementId);
            cals.setBoolean(3, isLinked);
            cals.executeQuery();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
    }

    public boolean checkU2FLock(String channelName, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int resultCode = 1;
        try {
            String str = "{ ?=call FRONT_CHECKU2FLOCK(?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, user);
            cals.setString(3, channelName);
            cals.registerOutParameter(4, java.sql.Types.INTEGER);
            cals.executeQuery();
            resultCode = cals.getInt(4);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return (resultCode == 0);
    }

    public int getLeftU2FRetry(String channelCode, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int resultCode = 1;
        int leftRetry = 0;
        try {
            String str = "{ ?=call FRONT_LEFTRETRYU2F(?, ?, ?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(str);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, user);
            cals.setString(3, channelCode);
            cals.registerOutParameter(4, java.sql.Types.INTEGER);
            cals.registerOutParameter(5, java.sql.Types.INTEGER);
            cals.executeQuery();
            resultCode = cals.getInt(4);
            leftRetry = cals.getInt(5);

            if (resultCode != 0) {
                leftRetry = -100;
            }

            if (leftRetry == 0) {
                leftRetry = -100;
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return leftRetry;
    }

    public void resetErrorCounterU2F(String channelCode, String user) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {
            String sql = "{ ?=call FRONT_RESETU2FCOUNTER(?, ?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(sql);
            cals.registerOutParameter(1, OracleTypes.INTEGER);
            cals.setString(2, channelCode);
            cals.setString(3, user);
            cals.execute();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
    }

    public int getWorkerUUID() {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        int workerUUID = -1;
        try {
            String sql = "{ ? = call NEXTVAL(?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(sql);
            cals.registerOutParameter(1, java.sql.Types.INTEGER);
            cals.setInt(2, 6);

            cals.execute();

            workerUUID = cals.getInt(1);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            /*
             * begin try { if (conn != null) conn.close(); if (rs != null)
             * rs.close(); if (cals != null) cals.close(); } catch (SQLException
             * e) { e.printStackTrace(); } end
             */
        }
        return workerUUID;
    }

    public String[] getSignServerByWorkerUUID(int workerUUID) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        String[] result = null;
        try {
            String sql = "{ ? = call FRONT_SIGNSERVERGETBYWORKERUUID(?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(sql);
            cals.registerOutParameter(1, java.sql.Types.INTEGER);
            cals.setInt(2, workerUUID);
            rs = cals.executeQuery();
            while (rs.next()) {
                result = new String[3];
                result[0] = rs.getString("Email");
                result[1] = rs.getString("User");
                result[2] = rs.getString("channelCode");
                break;
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (conn != null) {
                    conn.close();
                }
                if (rs != null) {
                    rs.close();
                }
                if (cals != null) {
                    cals.close();
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        return result;
    }
    
    public void removeWorker(int workerID) {
        Connection conn = null;
        ResultSet rs = null;
        CallableStatement cals = null;
        try {
            String sql = "{ ?=call FRONT_WORKERDELETE(?) }";
            conn = getDBConnection();
            cals = conn.prepareCall(sql);
            cals.registerOutParameter(1, java.sql.Types.INTEGER);
            cals.setInt(2, workerID);
            cals.execute();
            LOG.info("Removing worker ID "+workerID+" in database");
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (conn != null) {
                    conn.close();
                }
                if (rs != null) {
                    rs.close();
                }
                if (cals != null) {
                    cals.close();
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }
}