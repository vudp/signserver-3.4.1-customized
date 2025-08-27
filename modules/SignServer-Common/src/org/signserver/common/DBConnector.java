package org.signserver.common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.signserver.common.util.*;
import org.signserver.common.dbdao.*;

public class DBConnector {

    private static Connection connect;
    private static Statement statement;
    private static ResultSet resultSet;
    private static String SIGNSERVER_BUILD_CONFIG = System.getProperty("jboss.server.home.dir")
            + "/"
            + "../../../../../signserver-3.4.1/conf/signserver_build.properties";
    private static Properties proConfig = null;
    private PreparedStatement preparedStatement = null;
    private static String DB_TYPE_MYSQL = "mysql";
    private static String DB_TYPE_ORACLE = "oracle";
    private int id;
    private String ipList;
    private String username;
    private String password;
    private String signature;
    private String publickeyString;
    private String ipConnect;
    private static String dbType;
    private boolean ssl = false;
    private static DBConnector instance = null;
    private static Properties config = null;

    static {
        if (config == null) {
            config = getPropertiesConfig();
            dbType = config.getProperty("database.name");
        }
    }

    public DBConnector() {
    }

    public static DBConnector getInstances() {
        if (instance == null) {
            instance = new DBConnector();
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

    public ArrayList<Ca> getCAProviders() {
        ArrayList<Ca> caProviders = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            caProviders = MySQLConnector.getInstances().getCAProviders();
        } else {
            caProviders = OracleConnector.getInstances().getCAProviders();
        }
        return caProviders;
    }

    private void close() {
        try {
            if (resultSet != null) {
                resultSet.close();
            }

            if (statement != null) {
                statement.close();
            }

            if (connect != null) {
                connect.close();
            }
        } catch (Exception e) {
        }
    }

    private ResultSet getDataQuery(String str, Connection conn)
            throws SQLException {
        CallableStatement csa = null;
        ResultSet rs = null;
        try {
            csa = conn.prepareCall(str);
            rs = csa.executeQuery();
        } catch (Exception ex) {
            ex.printStackTrace();
        } finally {
        }
        return rs;
    }

    private Connection openConnect() {
        // This will load the MySQL driver, each DB has its own driver
        try {
            Class.forName("com.mysql.jdbc.Driver");
            return DriverManager.getConnection(
                    config.getProperty("database.url")
                    + "?useUnicode=true&characterEncoding=UTF-8",
                    config.getProperty("database.username"),
                    config.getProperty("database.password"));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
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

        int num = 1;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().insertAgreement(channelName, user,
                    agreementStatus, expiration, remark, branchId,
                    /*
                     * otpinformation
                     */
                    otpSMS,
                    otpEmail,
                    otpHardware,
                    isOtpEmail,
                    isOtpSMS,
                    isOtpHardware,
                    isOtpSoftware,
                    /*
                     * single agreement details
                     */
                    workerName,
                    keyName,
                    keyType,
                    spkiEmail,
                    spkiSMS,
                    propertiesConfig,
                    signserverSpkiSlotId,
                    signserverSpkiModule,
                    signserverSpkiPin,
                    signserverSpkiLevel,
                    p11InfoId,
                    isSignserver,
                    signserverPassword,
                    /*
                     * pkiinformation
                     */
                    tpkiCertificate,
                    tpkiThumbprint,
                    isTPKI,
                    lpkiCertificate,
                    lpkiThumbprint,
                    isLPKI,
                    wpkiCertificate,
                    wpkiThumbprint,
                    isWPKI,
                    msisdn,
                    vendor,
                    /*
                     * u2finformation
                     */
                    isU2F,
                    appId);
        } else {
            num = OracleConnector.getInstances().insertAgreement(channelName, user,
                    agreementStatus, expiration, remark, branchId,
                    /*
                     * otpinformation
                     */
                    otpSMS,
                    otpEmail,
                    otpHardware,
                    isOtpEmail,
                    isOtpSMS,
                    isOtpHardware,
                    isOtpSoftware,
                    /*
                     * single agreement details
                     */
                    workerName,
                    keyName,
                    keyType,
                    spkiEmail,
                    spkiSMS,
                    propertiesConfig,
                    signserverSpkiSlotId,
                    signserverSpkiModule,
                    signserverSpkiPin,
                    signserverSpkiLevel,
                    p11InfoId,
                    isSignserver,
                    signserverPassword,
                    /*
                     * pkiinformation
                     */
                    tpkiCertificate,
                    tpkiThumbprint,
                    isTPKI,
                    lpkiCertificate,
                    lpkiThumbprint,
                    isLPKI,
                    wpkiCertificate,
                    wpkiThumbprint,
                    isWPKI,
                    msisdn,
                    vendor,
                    /*
                     * u2finformation
                     */
                    isU2F,
                    appId);
        }
        return num;
    }

    public List<EndPointConfig> getEndPointConfig() {
        List<EndPointConfig> epc = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            epc = MySQLConnector.getInstances().getEndPointConfig();
        } else {
            epc = OracleConnector.getInstances().getEndPointConfig();
        }
        return epc;
    }

    public int authGetArrangementID(String channleCode, String User) {
        int num = 0;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authGetArrangementID(
                    channleCode, User);
        } else {
            num = OracleConnector.getInstances().authGetArrangementID(
                    channleCode, User);
        }
        return num;
    }

    public int authUpdateAgreement(int agreementID, String agreementStatus) {
        int num = 0;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authUpdateAgreement(agreementID, agreementStatus);
        } else {
            num = OracleConnector.getInstances().authUpdateAgreement(agreementID, agreementStatus);
        }
        return num;
    }

    public int authMultiUnregisteration(String idTag) {
        int num = 0;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authMultiUnregisteration(idTag);
        } else {
            num = OracleConnector.getInstances().authMultiUnregisteration(idTag);
        }
        return num;
    }

    public int authCheckOTPHardware(String user, String otpHardware,
            String channelCode) {
        int num = 2;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authCheckOTPHardware(user,
                    otpHardware, channelCode);
        } else {
            num = OracleConnector.getInstances().authCheckOTPHardware(user,
                    otpHardware, channelCode);
        }
        return num;
    }

    public boolean authCheckOTPEmail(String user, String otpEmail,
            String channelCode) {
        boolean num = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authCheckOTPEmail(user,
                    otpEmail, channelCode);
        } else {
            num = OracleConnector.getInstances().authCheckOTPEmail(user,
                    otpEmail, channelCode);
        }
        return num;
    }

    public boolean authCheckOTPSMS(String user, String otpSMS,
            String channelCode) {
        boolean num = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authCheckOTPSMS(user, otpSMS,
                    channelCode);
        } else {
            num = OracleConnector.getInstances().authCheckOTPSMS(user, otpSMS,
                    channelCode);
        }
        return num;
    }

    public boolean authCheckOTPMethod(String channelCode, String user,
            String method) {
        boolean num = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authCheckOTPMethod(channelCode,
                    user, method);
        } else {
            num = OracleConnector.getInstances().authCheckOTPMethod(
                    channelCode, user, method);
        }
        return num;
    }

    public boolean authCheckOTPMethodLinked(String channelCode, String user,
            String method) {
        boolean num = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authCheckOTPMethodLinked(channelCode,
                    user, method);
        } else {
            num = OracleConnector.getInstances().authCheckOTPMethodLinked(
                    channelCode, user, method);
        }
        return num;
    }

    public boolean authCheckOTPPerformance(String channelName, String user,
            String method) {
        boolean num = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authCheckOTPPerformance(
                    channelName, user, method);
        } else {
            num = OracleConnector.getInstances().authCheckOTPPerformance(
                    channelName, user, method);
        }
        return num;
    }

    public boolean authSetIsOTPSMSArrangement(int agreementID, boolean isOtpSms) {
        boolean num = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authSetIsOTPSMSArrangement(
                    agreementID, isOtpSms);
        } else {
            num = OracleConnector.getInstances().authSetIsOTPSMSArrangement(
                    agreementID, isOtpSms);
        }
        return num;
    }

    public boolean authSetOTPSMSArrangement(int agreementID, String otpSms) {
        boolean num = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authSetOTPSMSArrangement(
                    agreementID, otpSms);
        } else {
            num = OracleConnector.getInstances().authSetOTPSMSArrangement(
                    agreementID, otpSms);
        }
        return num;
    }

    public boolean authSetIsOTPEmailArrangement(int agreementID,
            boolean isOtpEmail) {
        boolean num = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authSetIsOTPEmailArrangement(
                    agreementID, isOtpEmail);
        } else {
            num = OracleConnector.getInstances().authSetIsOTPEmailArrangement(
                    agreementID, isOtpEmail);
        }
        return num;
    }

    public boolean authSetOTPEmailArrangement(int agreementID, String otpEmail) {
        boolean num = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authSetOTPEmailArrangement(
                    agreementID, otpEmail);
        } else {
            num = OracleConnector.getInstances().authSetOTPEmailArrangement(
                    agreementID, otpEmail);
        }
        return num;
    }

    public boolean authSetIsOTPHardwareArrangement(int agreementID,
            boolean isOtpHardware) {
        boolean num = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authSetIsOTPHardwareArrangement(agreementID, isOtpHardware);
        } else {
            num = OracleConnector.getInstances().authSetIsOTPHardwareArrangement(agreementID, isOtpHardware);
        }
        return num;
    }

    public boolean authSetOTPHardwareArrangement(int agreementID,
            String otpHardware) {
        boolean num = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authSetOTPHardwareArrangement(
                    agreementID, otpHardware);
        } else {
            num = OracleConnector.getInstances().authSetOTPHardwareArrangement(
                    agreementID, otpHardware);
        }
        return num;
    }

    public boolean authSetIsOTPSoftwareArrangement(int agreementID,
            boolean isOtpSoftware) {
        boolean num = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authSetIsOTPSoftwareArrangement(agreementID, isOtpSoftware);
        } else {
            num = OracleConnector.getInstances().authSetIsOTPSoftwareArrangement(agreementID, isOtpSoftware);
        }
        return num;
    }

    public boolean authSetIsPKIArrangement(int agreementID, boolean isPKI) {
        boolean num = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authSetIsPKIArrangement(
                    agreementID, isPKI);
        } else {
            num = OracleConnector.getInstances().authSetIsPKIArrangement(
                    agreementID, isPKI);
        }
        return num;
    }

    public boolean authSetCertificateArrangement(int agreementID,
            String thumbprint, String certificate) {
        boolean num = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authSetCertificateArrangement(agreementID,
                    thumbprint, certificate);
        } else {
            num = OracleConnector.getInstances().authSetCertificateArrangement(agreementID,
                    thumbprint, certificate);
        }
        return num;
    }

    public boolean authSetIsLCDPKIArrangement(int agreementID, boolean isPKI) {
        boolean num = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authSetIsLCDPKIArrangement(
                    agreementID, isPKI);
        } else {
            num = OracleConnector.getInstances().authSetIsLCDPKIArrangement(
                    agreementID, isPKI);
        }
        return num;
    }

    public boolean authSetLCDCertificateArrangement(int agreementID,
            String thumbprint, String certificate) {
        boolean num = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authSetLCDCertificateArrangement(agreementID,
                    thumbprint, certificate);
        } else {
            num = OracleConnector.getInstances().authSetLCDCertificateArrangement(agreementID,
                    thumbprint, certificate);
        }
        return num;
    }

    public boolean authSetIsSimPKIArrangement(int agreementID, boolean isSimPKI) {
        boolean rv = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authSetIsSimPKIArrangement(agreementID, isSimPKI);
        } else {
            rv = OracleConnector.getInstances().authSetIsSimPKIArrangement(agreementID, isSimPKI);
        }
        return rv;
    }

    public boolean authSetSimCertificateArrangement(int agreementID,
            String thumbprint, String certificate,
            String phoneNo, String vendor) {
        boolean rv = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authSetSimCertificateArrangement(agreementID,
                    thumbprint, certificate,
                    phoneNo, vendor);
        } else {
            rv = OracleConnector.getInstances().authSetSimCertificateArrangement(agreementID,
                    thumbprint, certificate,
                    phoneNo, vendor);
        }
        return rv;
    }

    public boolean authSetExtendArrangement(int agreementID,
            String channelCode, int expiration) {
        boolean num = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authSetExtendArrangement(
                    agreementID, channelCode, expiration);
        } else {
            num = OracleConnector.getInstances().authSetExtendArrangement(
                    agreementID, channelCode, expiration);
        }
        return num;
    }

    public String authAgreementValidation(String serialNumber, String issuerName) {
        String result = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            result = MySQLConnector.getInstances().authAgreementValidation(serialNumber, issuerName);
        } else {
            result = OracleConnector.getInstances().authAgreementValidation(serialNumber, issuerName);
        }
        return result;
    }

    public String authGetOTPHardware(String channelCode, String user) {
        String num = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authGetOTPHardware(channelCode,
                    user);
        } else {
            num = OracleConnector.getInstances().authGetOTPHardware(
                    channelCode, user);
        }
        return num;
    }

    public int authGetOTPDigits(String channelCode, String user) {
        int num = 8;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authGetOTPDigits(channelCode, user);
        } else {
            num = OracleConnector.getInstances().authGetOTPDigits(channelCode, user);
        }
        return num;
    }

    public int authGetOTPInformationID(String channelName, String user) {
        int num;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authGetOTPInformationID(channelName, user);
        } else {
            num = OracleConnector.getInstances().authGetOTPInformationID(channelName, user);
        }
        return num;
    }

    public boolean authInsertOTPTransaction(int otpTransactionID, String otp,
            String transactionData, int otpInformationId, String method, String otpStatus) {
        boolean num = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authInsertOTPTransaction(otpTransactionID, otp,
                    transactionData, otpInformationId, method, otpStatus);
        } else {
            num = OracleConnector.getInstances().authInsertOTPTransaction(otpTransactionID, otp,
                    transactionData, otpInformationId, method, otpStatus);
        }
        return num;
    }

    public void authInsertRepudiation(String billCode, String signedData,
            String signature, Date signedTime, Date ctsValidFrom,
            Date ctsValidTo, String serialNumber, String issuerName,
            String user, String channelCode) {
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().authInsertRepudiation(billCode,
                    signedData, signature, signedTime, ctsValidFrom,
                    ctsValidTo, serialNumber, issuerName, user, channelCode);
        } else {
            OracleConnector.getInstances().authInsertRepudiation(billCode,
                    signedData, signature, signedTime, ctsValidFrom,
                    ctsValidTo, serialNumber, issuerName, user, channelCode);
        }
    }

    public String OTPInformationGeneration(String transactionData, String otp) {
        String rv = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().OTPInformationGeneration(transactionData, otp);
        } else {
            rv = OracleConnector.getInstances().OTPInformationGeneration(transactionData, otp);
        }
        return rv;
    }

    public String getWPKITransactionGeneration(String transactionData, String transactionCode) {
        String rv = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().getWPKITransactionGeneration(transactionData, transactionCode);
        } else {
            rv = OracleConnector.getInstances().getWPKITransactionGeneration(transactionData, transactionCode);
        }
        return rv;
    }

    public String getParameter(String paramName) {
        String rv = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().getParameter(paramName);
        } else {
            rv = OracleConnector.getInstances().getParameter(paramName);
        }
        return rv;
    }

    public String authGetEmailOTP(String channelCode, String user) {
        String rv = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authGetEmailOTP(channelCode, user);
        } else {
            rv = OracleConnector.getInstances().authGetEmailOTP(channelCode, user);
        }
        return rv;
    }

    public String authGetPhoneNoOTP(String channelCode, String user) {
        String rv = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authGetPhoneNoOTP(channelCode, user);
        } else {
            rv = OracleConnector.getInstances().authGetPhoneNoOTP(channelCode, user);
        }
        return rv;
    }

    public String[] authGetPhoneNoSimPKI(String channelCode, String user) {
        String[] rv = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authGetPhoneNoSimPKI(channelCode, user);
        } else {
            rv = OracleConnector.getInstances().authGetPhoneNoSimPKI(channelCode, user);
        }
        return rv;
    }

    public String[] authGetAsyncTransaction(int otpTransactionId) {
        String[] parts = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            parts = MySQLConnector.getInstances().authGetAsyncTransaction(otpTransactionId);
        } else {
            parts = OracleConnector.getInstances().authGetAsyncTransaction(otpTransactionId);
        }
        return parts;
    }

    public byte[] authGetLicenseInfo() {
        byte[] lic = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            lic = MySQLConnector.getInstances().authGetLicenseInfo();
        } else {
            lic = OracleConnector.getInstances().authGetLicenseInfo();
        }
        return lic;
    }

    public boolean authSetLicenseInfo(byte[] licenseData) {
        boolean num = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authSetLicenseInfo(licenseData);
        } else {
            num = OracleConnector.getInstances().authSetLicenseInfo(licenseData);
        }
        return num;
    }

    public int authGetSuccessTransaction() {
        int num = 0;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authGetSuccessTransaction();
        } else {
            num = OracleConnector.getInstances().authGetSuccessTransaction();
        }
        return num;
    }

    public List<AgreementObject> authGetAgreementInfo(String channelName, String user, String id, String agreementStatus) {
        List<AgreementObject> rv = new ArrayList<AgreementObject>();
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authGetAgreementInfo(channelName, user, id, agreementStatus);
        } else {
            rv = OracleConnector.getInstances().authGetAgreementInfo(channelName, user, id, agreementStatus);
        }
        return rv;
    }

    public String authGetWorkerConfig(String workerName) {
        String rv = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authGetWorkerConfig(workerName);
        } else {
            rv = OracleConnector.getInstances().authGetWorkerConfig(workerName);
        }
        return rv;
    }

    public void authSetOTPTransactionStatus(int transactionID,
            String transactionstatus) {

        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().authSetOTPTransactionStatus(transactionID, transactionstatus);
        } else {
            OracleConnector.getInstances().authSetOTPTransactionStatus(transactionID, transactionstatus);
        }

    }

    public boolean checkUser(String user, String channelCode) {
        boolean rv = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().checkUser(user, channelCode);
        } else {
            rv = OracleConnector.getInstances().checkUser(user, channelCode);
        }
        return rv;
    }

    public boolean checkTPKICertificate(String thumbprint, String channelCode,
            String user) {
        boolean num = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().checkTPKICertificate(
                    thumbprint, channelCode, user);
        } else {
            num = OracleConnector.getInstances().checkTPKICertificate(
                    thumbprint, channelCode, user);
        }
        return num;
    }

    public boolean checkLCDPKICertificate(String thumbprint,
            String channelCode, String user) {
        boolean num = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().checkLCDPKICertificate(
                    thumbprint, channelCode, user);
        } else {
            num = OracleConnector.getInstances().checkLCDPKICertificate(
                    thumbprint, channelCode, user);
        }
        return num;
    }

    public boolean checkSimKICertificate(String serialNumber,
            String channelCode, String user) {
        boolean rv = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().checkSimKICertificate(serialNumber,
                    channelCode, user);
        } else {
            rv = OracleConnector.getInstances().checkSimKICertificate(serialNumber,
                    channelCode, user);
        }
        return rv;
    }

    public void reloadIpList() {
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().reloadIpList();
        } else {
            OracleConnector.getInstances().reloadIpList();
        }
    }

    public void reloadChannels() {
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().reloadChannels();
        } else {
            OracleConnector.getInstances().reloadChannels();
        }
    }

    public void reloadCAProviders() {
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().reloadCAProviders();
        } else {
            OracleConnector.getInstances().reloadCAProviders();
        }
    }

    public void reloadGeneralPolicy() {
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().reloadGeneralPolicy();
        } else {
            OracleConnector.getInstances().reloadGeneralPolicy();
        }
    }

    public void reloadEndPointConfig() {
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().reloadEndPointConfig();
        } else {
            OracleConnector.getInstances().reloadEndPointConfig();
        }
    }

    public boolean checkChannelCode(String channelCode) {
        boolean rv = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().checkChannelCode(channelCode);
        } else {
            rv = OracleConnector.getInstances().checkChannelCode(channelCode);
        }
        return rv;
    }

    public Object[] loginChannel(String channelCode, String user, String password, String signature) {
        Object[] rv = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().loginChannel(channelCode, user, password, signature);
        } else {
            rv = OracleConnector.getInstances().loginChannel(channelCode, user, password, signature);
        }
        return rv;
    }

    public String readDataBase(String channelCode, String ip, String username,
            String password, String signature, String timestamp,
            String digitalSign) {
        String rv = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().readDataBase(channelCode, ip,
                    username, password, signature, timestamp, digitalSign);
        } else {
            rv = OracleConnector.getInstances().readDataBase(channelCode, ip,
                    username, password, signature, timestamp, digitalSign);
        }
        return rv;
    }

    private String concatAllIP(ResultSet resultSet) throws SQLException {
        String result = "";
        while (resultSet.next()) {

            int isActive = resultSet.getInt(4);
            if (isActive == 1) {
                result = result + resultSet.getString(3) + ";";
            }
        }
        // System.out.println("[DBConnector-concatAllIP] listIP = " + result);
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

    private boolean writeResultSet(ResultSet resultSet) throws SQLException {

        boolean result = false;
        this.id = -1;
        while (resultSet.next()) {
            this.id = resultSet.getInt(1);
            this.username = resultSet.getString(3);
            this.password = resultSet.getString(4);
            this.signature = resultSet.getString(5);
            this.publickeyString = resultSet.getString(6);

            result = true;
        }

        return result;
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

        String billCode;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            billCode = MySQLConnector.getInstances().writeLogToDataBaseOutside(workerName,
                    username,
                    ip,
                    userContract,
                    status,
                    idTag,
                    channelName,
                    requestData,
                    responseData,
                    unsignedText,
                    signedText,
                    functionName,
                    dataInId);
        } else {
            billCode = OracleConnector.getInstances().writeLogToDataBaseOutside(workerName,
                    username,
                    ip,
                    userContract,
                    status,
                    idTag,
                    channelName,
                    requestData,
                    responseData,
                    unsignedText,
                    signedText,
                    functionName,
                    dataInId);
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

        String billCode;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            billCode = MySQLConnector.getInstances().writeLogForResponse(workerName,
                    username,
                    ip,
                    userContract,
                    status,
                    idTag,
                    channelName,
                    requestData,
                    responseData,
                    unsignedText,
                    signedText,
                    functionName,
                    dataInId,
                    oathResponseId);
        } else {
            billCode = OracleConnector.getInstances().writeLogForResponse(workerName,
                    username,
                    ip,
                    userContract,
                    status,
                    idTag,
                    channelName,
                    requestData,
                    responseData,
                    unsignedText,
                    signedText,
                    functionName,
                    dataInId,
                    oathResponseId);
        }
        return billCode;
    }
    /*
     * public String writeLogToDataBaseOutside(String workerName, String
     * username, String ip, String userContract, String exception, int status,
     * String idTag, String channelName, String requestData, String
     * unsignedText, String signedText, String functionName, int dataInId) {
     *
     * String billCode = ""; return billCode; }
     */

    public void updateClientLog(int transId, String responseData) {
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().updateClientLog(transId, responseData);
        } else {
            OracleConnector.getInstances().updateClientLog(transId, responseData);
        }
    }

    public int insertDataIn(String request) {
        int num = 0;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().insertDataIn(request);
        } else {
            num = OracleConnector.getInstances().insertDataIn(request);
        }
        return num;
    }

    public void insertDataOut(String response, int dataInId) {
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().insertDataOut(response, dataInId);
        } else {
            OracleConnector.getInstances().insertDataOut(response, dataInId);
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
        String result = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            result = MySQLConnector.getInstances().insertTrustedHubTransaction(
                    user,
                    ip,
                    workerName,
                    clientBillCode,
                    channelCode,
                    requestData,
                    unsignedData,
                    functionName,
                    dataInId,
                    trustedHubTransId,
                    agreementId,
                    isBackOffice);
        } else {
            result = OracleConnector.getInstances().insertTrustedHubTransaction(
                    user,
                    ip,
                    workerName,
                    clientBillCode,
                    channelCode,
                    requestData,
                    unsignedData,
                    functionName,
                    dataInId,
                    trustedHubTransId,
                    agreementId,
                    isBackOffice);
        }
        return result;
    }

    public void updateTrustedHubTransaction(
            int trustedHubTransId,
            int responseCode,
            String responseData,
            String signedData,
            Integer preTrustedHubTransId,
            Integer agreementId) {
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().updateTrustedHubTransaction(
                    trustedHubTransId,
                    responseCode,
                    responseData,
                    signedData,
                    preTrustedHubTransId,
                    agreementId);
        } else {
            OracleConnector.getInstances().updateTrustedHubTransaction(
                    trustedHubTransId,
                    responseCode,
                    responseData,
                    signedData,
                    preTrustedHubTransId,
                    agreementId);
        }
    }

    public int checkHWOTP(String channelName, String user) {
        int num = 0;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().checkHWOTP(channelName, user);
        } else {
            num = OracleConnector.getInstances().checkHWOTP(channelName, user);
        }
        return num;
    }

    public int leftRetryHWOTP(String channelName, String user) {
        int num = 0;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().leftRetryHWOTP(channelName, user);
        } else {
            num = OracleConnector.getInstances().leftRetryHWOTP(channelName, user);
        }
        return num;
    }

    public int checkHWLCDPKI(String channelName, String user) {
        int num = 0;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().checkHWLCDPKI(channelName, user);
        } else {
            num = OracleConnector.getInstances().checkHWLCDPKI(channelName, user);
        }
        return num;
    }

    public int leftRetryHWLCDPKI(String channelName, String user) {
        int num = 0;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().leftRetryHWLCDPKI(channelName, user);
        } else {
            num = OracleConnector.getInstances().leftRetryHWLCDPKI(channelName, user);
        }
        return num;
    }

    public void resetErrorCounterHWLCDPKI(String channelCode, String user) {
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().resetErrorCounterHWLCDPKI(channelCode, user);
        } else {
            OracleConnector.getInstances().resetErrorCounterHWLCDPKI(channelCode, user);
        }
    }

    public int checkHWPKI(String channelName, String user) {
        int num = 0;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().checkHWPKI(channelName, user);
        } else {
            num = OracleConnector.getInstances().checkHWPKI(channelName, user);
        }
        return num;
    }

    public int leftRetryHWPKI(String channelName, String user) {
        int num = 0;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().leftRetryHWPKI(channelName, user);
        } else {
            num = OracleConnector.getInstances().leftRetryHWPKI(channelName, user);
        }
        return num;
    }

    public void resetErrorCounterHWOTP(String channelCode, String user) {
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().resetErrorCounterHWOTP(channelCode,
                    user);
        } else {
            OracleConnector.getInstances().resetErrorCounterHWOTP(channelCode,
                    user);
        }
    }

    public void resetErrorCounterHWPKI(String channelCode, String user) {
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().resetErrorCounterHWPKI(channelCode, user);
        } else {
            OracleConnector.getInstances().resetErrorCounterHWPKI(channelCode, user);
        }
    }

    public boolean authCheckSimPKI(String user, String PhoneNo, String channelCode) {
        boolean rv = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authCheckSimPKI(user, PhoneNo, channelCode);
        } else {
            rv = OracleConnector.getInstances().authCheckSimPKI(user, PhoneNo, channelCode);
        }
        return rv;
    }

    public boolean checkPKIMethodLinked(String channelCode, String user, String method) {
        boolean rv = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().checkPKIMethodLinked(channelCode, user, method);
        } else {
            rv = OracleConnector.getInstances().checkPKIMethodLinked(channelCode, user, method);
        }
        return rv;
    }

    public String[] authCheckSimPKIVendor(String vendor) {
        String[] rv = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authCheckSimPKIVendor(vendor);
        } else {
            rv = OracleConnector.getInstances().authCheckSimPKIVendor(vendor);
        }
        return rv;
    }

    public String getSerialNumberFromCa(String channelName, String username) {
        String rv = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().getSerialNumberFromCa(channelName, username);
        } else {
            rv = OracleConnector.getInstances().getSerialNumberFromCa(channelName, username);
        }
        return rv;
    }

    public boolean authCheckRelation(String channelCode, String functionName) {
        boolean num = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().authCheckRelation(channelCode, functionName);
        } else {
            num = OracleConnector.getInstances().authCheckRelation(channelCode, functionName);
        }
        return num;
    }

    public int[] getAgreementStatusUser(String username, String channelName,
            int workerType) {
        int[] num;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().getAgreementStatusUser(
                    username, channelName, workerType);
        } else {
            num = OracleConnector.getInstances().getAgreementStatusUser(
                    username, channelName, workerType);
        }
        return num;
    }

    public int getMethodValidateCert(String caCode) {
        int num = 0;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().getMethodValidateCert(caCode);
        } else {
            num = OracleConnector.getInstances().getMethodValidateCert(caCode);
        }
        return num;
    }

    public void increaseSuccessTransaction() {
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().increaseSuccessTransaction();
        } else {
            OracleConnector.getInstances().increaseSuccessTransaction();
        }
    }

    public int getNumberOCSPReTry(String caName) {
        int num = 2;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().getNumberOCSPReTry(caName);
        } else {
            num = OracleConnector.getInstances().getNumberOCSPReTry(caName);
        }
        return num;
    }

    /*
     * AdminWS
     */
    public int AdminWSLogin(int ClientID, String UserName, String Password) {
        int num = 0;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().AdminWSLogin(ClientID, UserName, Password);
        } else {
            num = OracleConnector.getInstances().AdminWSLogin(ClientID, UserName, Password);
        }
        return num;
    }

    public boolean AdminWSIPFiler(String ipAddr) {
        return true;
    }

    public List<String> getAllIPFilter() {
        List<String> list = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            list = MySQLConnector.getInstances().getAllIPFilter();
        } else {
            list = OracleConnector.getInstances().getAllIPFilter();
        }
        return list;
    }

    public void addIPFilter(String Ip, String desr, int activeFlag,
            String channel) {
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().addIPFilter(Ip, desr, activeFlag,
                    channel);
        } else {
            OracleConnector.getInstances().addIPFilter(Ip, desr, activeFlag,
                    channel);
        }
    }

    public void removeIPFilter(String Ip, String channelID) {
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().removeIPFilter(Ip, channelID);
        } else {
            OracleConnector.getInstances().removeIPFilter(Ip, channelID);
        }
    }

    public boolean getIsOptimized() {
        boolean num = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().getIsOptimized();
        } else {
            num = OracleConnector.getInstances().getIsOptimized();
        }
        return num;
    }

    public boolean reloadIsOptimized() {
        boolean num = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().reloadIsOptimized();
        } else {
            num = OracleConnector.getInstances().reloadIsOptimized();
        }
        return num;
    }

    public int getIsFunctionAccess() {
        int num = 0;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().getIsFunctionAccess();
        } else {
            num = OracleConnector.getInstances().getIsFunctionAccess();
        }
        return num;
    }

    public int insertEndpointLog(String channelCode, String cif,
            String functionName, String fileId, String phoneNo, String pkisim, String email,
            String request, String response, Integer clientLogId) {
        int rv = -1;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().insertEndpointLog(channelCode, cif,
                    functionName, fileId, phoneNo, pkisim, email, request, response, clientLogId);
        } else {
            rv = OracleConnector.getInstances().insertEndpointLog(channelCode, cif,
                    functionName, fileId, phoneNo, pkisim, email, request, response, clientLogId);
        }
        return rv;
    }

    public boolean authInsertPKITransaction(int otpTransactionID, String otp,
            String transactionData, int otpInformationId, String method,
            String otpStatus, String streamPath, String fileType, String fileId, String fileName, String mineType, String displayValue) {
        boolean rv = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authInsertPKITransaction(otpTransactionID, otp,
                    transactionData, otpInformationId, method,
                    otpStatus, streamPath, fileType, fileId, fileName, mineType, displayValue);
        } else {
            rv = OracleConnector.getInstances().authInsertPKITransaction(otpTransactionID, otp,
                    transactionData, otpInformationId, method,
                    otpStatus, streamPath, fileType, fileId, fileName, mineType, displayValue);
        }
        return rv;
    }

    public boolean authInsertDcWPKITransaction(int otpTransactionID, String dcDataPath,
            String dcSignPath, String aeTransId, String fileType, String transCode, String externalStorageResp, String dtbs, String displayData, String displayValue) {
        boolean rv = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authInsertDcWPKITransaction(otpTransactionID, dcDataPath,
                    dcSignPath, aeTransId, fileType, transCode, externalStorageResp, dtbs, displayData, displayValue);
        } else {
            rv = OracleConnector.getInstances().authInsertDcWPKITransaction(otpTransactionID, dcDataPath,
                    dcSignPath, aeTransId, fileType, transCode, externalStorageResp, dtbs, displayData, displayValue);
        }
        return rv;
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
        boolean rv = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authInsertDcTPKITransaction(otpTransactionID,
                    dcDataPath,
                    dcSignPath,
                    fileId,
                    fileType,
                    mineType,
                    fileName,
                    dtbs,
                    displayData);
        } else {
            rv = OracleConnector.getInstances().authInsertDcTPKITransaction(otpTransactionID,
                    dcDataPath,
                    dcSignPath,
                    fileId,
                    fileType,
                    mineType,
                    fileName,
                    dtbs,
                    displayData);
        }
        return rv;
    }

    private byte[] getBytesFromInputStream(InputStream is) throws IOException {

        int len;
        int size = 1024;
        byte[] buf;

        if (is instanceof ByteArrayInputStream) {
            size = is.available();
            buf = new byte[size];
            len = is.read(buf, 0, size);
        } else {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            buf = new byte[size];
            while ((len = is.read(buf, 0, size)) != -1) {
                bos.write(buf, 0, len);
            }
            buf = bos.toByteArray();
        }
        return buf;
    }

    public String decodeTDES(String encSOPIN) {
        String SO = "";
        if (encSOPIN.compareTo("") == 0) {
            return null;
        }
        byte[] rawSO = DatatypeConverter.parseBase64Binary(encSOPIN);
        if ((rawSO.length % 8) != 0) {
            return null;
        }
        int length = rawSO.length;
        int numBlock = length / 8;

        byte[] block[] = new byte[numBlock][8];
        byte[] bt[] = new byte[numBlock][8];

        for (int i = 0; i < numBlock; i++) {
            System.arraycopy(rawSO, i * 8, block[i], 0, 8);
        }

        for (int i = 0; i < numBlock; i++) {
            try {
                bt[i] = decryptBlock(block[i]);
            } catch (InvalidKeyException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (InvalidKeySpecException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (BadPaddingException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (UnsupportedEncodingException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }

        byte[] decRawSO = new byte[length];
        Arrays.fill(decRawSO, (byte) 0);

        for (int i = 0; i < numBlock; i++) {
            System.arraycopy(bt[i], 0, decRawSO, i * 8, 8);
        }
        int last_byte = decRawSO[length - 1];
        byte[] temp = new byte[length - last_byte];
        System.arraycopy(decRawSO, 0, temp, 0, length - last_byte);

        try {
            SO = new String(temp, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return SO;
    }

    public String encodeTDES(String SoPin) {
        if (SoPin.compareTo("") == 0) {
            return null;
        }
        byte[] rawSo = null;
        try {
            rawSo = SoPin.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        int x, length, numBlock;
        String SOPIN = "";

        x = rawSo.length % 8;
        length = rawSo.length + 8 - x;
        numBlock = length / 8;

        byte[] dataSO = new byte[length];
        Arrays.fill(dataSO, (byte) (length - SoPin.length()));
        System.arraycopy(rawSo, 0, dataSO, 0, rawSo.length);

        byte[] block[] = new byte[numBlock][8];
        for (int i = 0; i < numBlock; i++) {
            System.arraycopy(dataSO, i * 8, block[i], 0, 8);
        }
        byte[] bt[] = new byte[numBlock][8];

        for (int i = 0; i < numBlock; i++) {
            try {
                bt[i] = encryptBlock(block[i]);
            } catch (InvalidKeyException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (InvalidKeySpecException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (BadPaddingException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (UnsupportedEncodingException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }

        byte[] encSOPIN = new byte[length];

        for (int i = 0; i < numBlock; i++) {
            System.arraycopy(bt[i], 0, encSOPIN, i * 8, 8);
        }

        SOPIN = DatatypeConverter.printBase64Binary(encSOPIN);

        return SOPIN;
    }

    public byte[] encryptBlock(byte[] block) throws InvalidKeyException,
            InvalidKeySpecException, NoSuchAlgorithmException,
            NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException, UnsupportedEncodingException {
        if (block.length != 8) {
            return null;
        }

        String key1 = "12345678";
        DESKeySpec KEY1 = new DESKeySpec(key1.getBytes("UTF-8"));
        SecretKeyFactory keyFactory1 = SecretKeyFactory.getInstance("DES");
        SecretKey myDesKey1 = keyFactory1.generateSecret(KEY1);

        String key2 = "90abcdef";
        DESKeySpec KEY2 = new DESKeySpec(key2.getBytes("UTF-8"));
        SecretKeyFactory keyFactory2 = SecretKeyFactory.getInstance("DES");
        SecretKey myDesKey2 = keyFactory2.generateSecret(KEY2);

        Cipher desCipher1;
        desCipher1 = Cipher.getInstance("DES/ECB/NoPadding");

        desCipher1.init(Cipher.ENCRYPT_MODE, myDesKey1);

        Cipher desCipher2;
        desCipher2 = Cipher.getInstance("DES/ECB/NoPadding");

        desCipher2.init(Cipher.DECRYPT_MODE, myDesKey2);

        byte[] d3 = desCipher1.doFinal(block);

        byte[] d2 = desCipher2.doFinal(d3);

        byte[] d1 = desCipher1.doFinal(d2);

        return d1;
    }

    public byte[] decryptBlock(byte[] block) throws InvalidKeyException,
            InvalidKeySpecException, NoSuchAlgorithmException,
            NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException, UnsupportedEncodingException {
        if (block.length != 8) {
            return null;
        }

        String key1 = "12345678";
        DESKeySpec KEY1 = new DESKeySpec(key1.getBytes("UTF-8"));
        SecretKeyFactory keyFactory1 = SecretKeyFactory.getInstance("DES");
        SecretKey myDesKey1 = keyFactory1.generateSecret(KEY1);

        String key2 = "90abcdef";
        DESKeySpec KEY2 = new DESKeySpec(key2.getBytes("UTF-8"));
        SecretKeyFactory keyFactory2 = SecretKeyFactory.getInstance("DES");
        SecretKey myDesKey2 = keyFactory2.generateSecret(KEY2);

        Cipher desCipher1;
        desCipher1 = Cipher.getInstance("DES/ECB/NoPadding");

        desCipher1.init(Cipher.DECRYPT_MODE, myDesKey1);

        Cipher desCipher2;
        desCipher2 = Cipher.getInstance("DES/ECB/NoPadding");

        desCipher2.init(Cipher.ENCRYPT_MODE, myDesKey2);

        byte[] d3 = desCipher1.doFinal(block);

        byte[] d2 = desCipher2.doFinal(d3);

        byte[] d1 = desCipher1.doFinal(d2);

        return d1;
    }

    public int countKeyStore() {
        int num = 0;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            num = MySQLConnector.getInstances().countKeyStore();
        } else {
            num = OracleConnector.getInstances().countKeyStore();
        }
        return num;
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
        boolean rv = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authSetIsSignServerArrangement(
                    agreementId,
                    isSignserver,
                    signserverPassword,
                    p11InfoId,
                    workerName,
                    keyName,
                    keyType,
                    spkiEmail,
                    spkiSMS,
                    workerConfig,
                    signserverSpkiSlotId,
                    signserverSpkiModule,
                    signserverSpkiPin,
                    signserverSpkiLevel);
        } else {
            rv = OracleConnector.getInstances().authSetIsSignServerArrangement(
                    agreementId,
                    isSignserver,
                    signserverPassword,
                    p11InfoId,
                    workerName,
                    keyName,
                    keyType,
                    spkiEmail,
                    spkiSMS,
                    workerConfig,
                    signserverSpkiSlotId,
                    signserverSpkiModule,
                    signserverSpkiPin,
                    signserverSpkiLevel);
        }
        return rv;
    }

    public void authSANewUpdateCANC(int agreementId) {
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().authSANewUpdateCANC(agreementId);
        } else {
            OracleConnector.getInstances().authSANewUpdateCANC(agreementId);
        }
    }

    public boolean authInsertSignExternalStorageTransaction(int otpTransactionID, int transactionStatus) {
        boolean rv = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authInsertSignExternalStorageTransaction(otpTransactionID, transactionStatus);
        } else {
            rv = OracleConnector.getInstances().authInsertSignExternalStorageTransaction(otpTransactionID, transactionStatus);
        }
        return rv;
    }

    public void authUpdateSignExternalStorageTransaction(int otpTransactionID, String externalStorageResponse, int externalStorageResponseStatus) {

        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().authUpdateSignExternalStorageTransaction(otpTransactionID, externalStorageResponse, externalStorageResponseStatus);
        } else {
            OracleConnector.getInstances().authUpdateSignExternalStorageTransaction(otpTransactionID, externalStorageResponse, externalStorageResponseStatus);
        }
    }

    public void updateEndpointLog(int clientLogId, Integer endpointId) {
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().updateEndpointLog(clientLogId, endpointId);
        } else {
            OracleConnector.getInstances().updateEndpointLog(clientLogId, endpointId);
        }
    }

    public String[] authGetCertificateTPKI(String channelCode, String user) {
        String[] rv = new String[2];
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authGetCertificateTPKI(channelCode, user);
        } else {
            rv = OracleConnector.getInstances().authGetCertificateTPKI(channelCode, user);
        }
        return rv;
    }

    public String[] authGetCertificateLPKI(String channelCode, String user) {
        String[] rv = new String[2];
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authGetCertificateLPKI(channelCode, user);
        } else {
            rv = OracleConnector.getInstances().authGetCertificateLPKI(channelCode, user);
        }
        return rv;
    }

    public String[] authCertificateSPKI(String channelCode, String user) {
        String[] rv = new String[1];
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authCertificateSPKI(channelCode, user);
        } else {
            rv = OracleConnector.getInstances().authCertificateSPKI(channelCode, user);
        }
        return rv;
    }

    public String[] authEndPointParamsGet(String paramName) {
        String[] rv = new String[2];
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authEndPointParamsGet(paramName);
        } else {
            rv = OracleConnector.getInstances().authEndPointParamsGet(paramName);
        }
        return rv;
    }

    public void reloadEndPointParams() {
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().reloadEndPointParams();
        } else {
            OracleConnector.getInstances().reloadEndPointParams();
        }
    }

    public void authResetOTPTransaction(int otpTransactionID) {
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().authResetOTPTransaction(otpTransactionID);
        } else {
            OracleConnector.getInstances().authResetOTPTransaction(otpTransactionID);
        }
    }

    public int[] authCheckPassSignServer(String user, String channelName,
            String password) {
        int[] response;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            response = MySQLConnector.getInstances().authCheckPassSignServer(user, channelName,
                    password);
        } else {
            response = OracleConnector.getInstances().authCheckPassSignServer(user, channelName,
                    password);
        }
        return response;
    }

    public Object[] authChangePassSignServer(int agreementId, String currentPassword,
            String newPassword) {
        Object[] rv = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authChangePassSignServer(agreementId, currentPassword,
                    newPassword);
        } else {
            rv = OracleConnector.getInstances().authChangePassSignServer(agreementId, currentPassword,
                    newPassword);
        }
        return rv;
    }

    public String[] getBackOfficeParamsDetailClient(String nameParams, boolean isEmail) {
        String[] rv;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().getBackOfficeParamsDetailClient(nameParams, isEmail);
        } else {
            rv = OracleConnector.getInstances().getBackOfficeParamsDetailClient(nameParams, isEmail);
        }
        return rv;
    }

    public String authGetEmailSignServer(String channelCode, String user) {
        String rv;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authGetEmailSignServer(channelCode, user);
        } else {
            rv = OracleConnector.getInstances().authGetEmailSignServer(channelCode, user);
        }
        return rv;
    }

    public String authGetPhoneSignServer(String channelCode, String user) {
        String rv;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authGetPhoneSignServer(channelCode, user);
        } else {
            rv = OracleConnector.getInstances().authGetPhoneSignServer(channelCode, user);
        }
        return rv;
    }

    public void authResetPassSignserver(int agreementId, String password) {
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().authResetPassSignserver(agreementId, password);
        } else {
            OracleConnector.getInstances().authResetPassSignserver(agreementId, password);
        }
    }

    public void authSAUpdateIsRegistered(int agreementId, boolean isRegistered) {
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().authSAUpdateIsRegistered(agreementId, isRegistered);
        } else {
            OracleConnector.getInstances().authSAUpdateIsRegistered(agreementId, isRegistered);
        }
    }

    public boolean authSAGetIsRegistered(String channelName, String user) {
        boolean rv;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authSAGetIsRegistered(channelName, user);
        } else {
            rv = OracleConnector.getInstances().authSAGetIsRegistered(channelName, user);
        }
        return rv;
    }

    public int authCheckSignServerStatus(String channelName, String user) {
        int rv;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authCheckSignServerStatus(channelName, user);
        } else {
            rv = OracleConnector.getInstances().authCheckSignServerStatus(channelName, user);
        }
        return rv;
    }

    public GeneralPolicy getGeneralPolicy() {
        GeneralPolicy rv;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().getGeneralPolicy();
        } else {
            rv = OracleConnector.getInstances().getGeneralPolicy();
        }
        return rv;
    }

    public List<ReceiverHAStatus> authReceiverHAStatusList() {
        List<ReceiverHAStatus> receiverHAStatuses = new ArrayList<ReceiverHAStatus>();
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            receiverHAStatuses = MySQLConnector.getInstances().authReceiverHAStatusList();
        } else {
            receiverHAStatuses = OracleConnector.getInstances().authReceiverHAStatusList();
        }
        return receiverHAStatuses;
    }

    public Ca getCa(String caName) {
        Ca ca = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            ca = MySQLConnector.getInstances().getCa(caName);
        } else {
            ca = OracleConnector.getInstances().getCa(caName);
        }
        return ca;
    }

    public boolean authSetIsOTPSMSActive(int agreementID, boolean isActive) {
        boolean rv = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authSetIsOTPSMSActive(agreementID, isActive);
        } else {
            rv = OracleConnector.getInstances().authSetIsOTPSMSActive(agreementID, isActive);
        }
        return rv;
    }

    public boolean authSetIsOTPEmailActive(int agreementID, boolean isActive) {
        boolean rv = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authSetIsOTPEmailActive(agreementID, isActive);
        } else {
            rv = OracleConnector.getInstances().authSetIsOTPEmailActive(agreementID, isActive);
        }
        return rv;
    }

    public boolean authSetIsOTPHardwareActive(int agreementID, boolean isActive) {
        boolean rv = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authSetIsOTPHardwareActive(agreementID, isActive);
        } else {
            rv = OracleConnector.getInstances().authSetIsOTPHardwareActive(agreementID, isActive);
        }
        return rv;
    }

    public boolean authSetIsSimPKIActive(int agreementID, boolean isActive) {
        boolean rv = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authSetIsSimPKIActive(agreementID, isActive);
        } else {
            rv = OracleConnector.getInstances().authSetIsSimPKIActive(agreementID, isActive);
        }
        return rv;
    }

    public boolean authSetIsTPKIActive(int agreementID, boolean isActive) {
        boolean rv = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authSetIsTPKIActive(agreementID, isActive);
        } else {
            rv = OracleConnector.getInstances().authSetIsTPKIActive(agreementID, isActive);
        }
        return rv;
    }

    public boolean authSetIsLPKIActive(int agreementID, boolean isActive) {
        boolean rv = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authSetIsLPKIActive(agreementID, isActive);
        } else {
            rv = OracleConnector.getInstances().authSetIsLPKIActive(agreementID, isActive);
        }
        return rv;
    }

    public List<OwnerInfo> authGetAgreementValidation(String serialNumber, Date signingTime) {
        List<OwnerInfo> rv = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().authGetAgreementValidation(serialNumber, signingTime);
        } else {
            rv = OracleConnector.getInstances().authGetAgreementValidation(serialNumber, signingTime);
        }
        return rv;
    }

    public boolean CAUpdateDownloadableCRL(String caName, Boolean isDownloadable1, Boolean isDownloadable2) {
        boolean rv = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().CAUpdateDownloadableCRL(caName, isDownloadable1, isDownloadable2);
        } else {
            rv = OracleConnector.getInstances().CAUpdateDownloadableCRL(caName, isDownloadable1, isDownloadable2);
        }
        return rv;
    }

    public Tsa getTSA(String tsaDesc) {
        Tsa tsa = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            tsa = MySQLConnector.getInstances().getTSA(tsaDesc);
        } else {
            tsa = OracleConnector.getInstances().getTSA(tsaDesc);
        }
        return tsa;
    }

    public boolean updateDownloadableCrlTsa(String tsaName, boolean isDownloadable) {
        boolean rv = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().updateDownloadableCrlTsa(tsaName, isDownloadable);
        } else {
            rv = OracleConnector.getInstances().updateDownloadableCrlTsa(tsaName, isDownloadable);
        }
        return rv;
    }

    public P11Info getP11Info(String p11Name) {
        P11Info p11Info = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            p11Info = MySQLConnector.getInstances().getP11Info(p11Name);
        } else {
            p11Info = OracleConnector.getInstances().getP11Info(p11Name);
        }
        return p11Info;
    }

    public int checkErrorCountSignServer(String channelName, String user) {
        int rv = 1;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().checkErrorCountSignServer(channelName, user);
        } else {
            rv = OracleConnector.getInstances().checkErrorCountSignServer(channelName, user);
        }
        return rv;
    }

    public void resetErrorCountSignServer(String channelName, String user) {
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().resetErrorCountSignServer(channelName, user);
        } else {
            OracleConnector.getInstances().resetErrorCountSignServer(channelName, user);
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
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().updateSignerServerAgreement(
                    agreementId,
                    signserverStatusId,
                    workerName,
                    keyName,
                    keyNameNext,
                    csr,
                    cert,
                    config,
                    workerUUID,
                    dn,
                    commonName,
                    validFrom,
                    validTo,
                    certStatusId,
                    caId,
                    shareKeyTypeId,
                    certProfileId,
                    phoneNo,
                    thumbprint,
                    certTypeId);
        } else {
            OracleConnector.getInstances().updateSignerServerAgreement(
                    agreementId,
                    signserverStatusId,
                    workerName,
                    keyName,
                    keyNameNext,
                    csr,
                    cert,
                    config,
                    workerUUID,
                    dn,
                    commonName,
                    validFrom,
                    validTo,
                    certStatusId,
                    caId,
                    shareKeyTypeId,
                    certProfileId,
                    phoneNo,
                    thumbprint,
                    certTypeId);
        }
    }

    public String[] getCertTypeKeyInfo(String certTypeCode) {
        String[] rv = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().getCertTypeKeyInfo(certTypeCode);
        } else {
            rv = OracleConnector.getInstances().getCertTypeKeyInfo(certTypeCode);
        }
        return rv;
    }

    public int getCertProfileId(int valueDay) {
        int rv = 1;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().getCertProfileId(valueDay);
        } else {
            rv = OracleConnector.getInstances().getCertProfileId(valueDay);
        }
        return rv;
    }

    public List<CertTemplate> getCertTemplate(int certTypeId) {
        List<CertTemplate> rv = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().getCertTemplate(certTypeId);
        } else {
            rv = OracleConnector.getInstances().getCertTemplate(certTypeId);
        }
        return rv;
    }

    public AgreementObject getAgreementByTPKIThumbPrint(String channelName, String thumbprint) {
        AgreementObject rv = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().getAgreementByTPKIThumbPrint(channelName, thumbprint);
        } else {
            rv = OracleConnector.getInstances().getAgreementByTPKIThumbPrint(channelName, thumbprint);
        }
        return rv;
    }

    public boolean setIsU2F(int agreementID, boolean isU2F) {
        boolean rv = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().setIsU2F(agreementID, isU2F);
        } else {
            rv = OracleConnector.getInstances().setIsU2F(agreementID, isU2F);
        }
        return rv;
    }

    public boolean setU2FAgreement(int agreementID, String appId) {
        boolean rv = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().setU2FAgreement(agreementID, appId);
        } else {
            rv = OracleConnector.getInstances().setU2FAgreement(agreementID, appId);
        }
        return rv;
    }

    public String getU2F(String channelCode, String user) {
        String rv = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().getU2F(channelCode, user);
        } else {
            rv = OracleConnector.getInstances().getU2F(channelCode, user);
        }
        return rv;
    }

    public String checkU2FLinked(String channelCode, String user) {
        String rv = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().checkU2FLinked(channelCode, user);
        } else {
            rv = OracleConnector.getInstances().checkU2FLinked(channelCode, user);
        }
        return rv;
    }

    public void setU2FLinked(int agreementId, boolean isLinked) {
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().setU2FLinked(agreementId, isLinked);
        } else {
            OracleConnector.getInstances().setU2FLinked(agreementId, isLinked);
        }
    }

    public boolean checkU2FLock(String channelName, String user) {
        boolean rv = false;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().checkU2FLock(channelName, user);
        } else {
            rv = OracleConnector.getInstances().checkU2FLock(channelName, user);
        }
        return rv;
    }

    public int getLeftU2FRetry(String channelCode, String user) {
        int rv = -100;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().getLeftU2FRetry(channelCode, user);
        } else {
            rv = OracleConnector.getInstances().getLeftU2FRetry(channelCode, user);
        }
        return rv;
    }

    public void resetErrorCounterU2F(String channelCode, String user) {
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().resetErrorCounterU2F(channelCode, user);
        } else {
            OracleConnector.getInstances().resetErrorCounterU2F(channelCode, user);
        }
    }

    public int getWorkerUUID() {
        int workerUUID = -1;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            workerUUID = MySQLConnector.getInstances().getWorkerUUID();
        } else {
            workerUUID = OracleConnector.getInstances().getWorkerUUID();
        }
        return workerUUID;
    }

    public String[] getSignServerByWorkerUUID(int workerUUID) {
        String[] rv = null;
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            rv = MySQLConnector.getInstances().getSignServerByWorkerUUID(workerUUID);
        } else {
            rv = OracleConnector.getInstances().getSignServerByWorkerUUID(workerUUID);
        }
        return rv;
    }

    public void removeWorker(int workerID) {
        if (dbType.compareTo(DB_TYPE_MYSQL) == 0) {
            MySQLConnector.getInstances().removeWorker(workerID);
        } else {
            OracleConnector.getInstances().removeWorker(workerID);
        }
    }
}
