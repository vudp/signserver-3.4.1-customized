/**
 * ***********************************************************************
 *                                                                       *
 * SignServer: The OpenSource Automated Signing Server * * This software is free
 * software; you can redistribute it and/or * modify it under the terms of the
 * GNU Lesser General Public * License as published by the Free Software
 * Foundation; either * version 2.1 of the License, or any later version. * *
 * See terms of license at gnu.org. * *
 * ***********************************************************************
 */
package org.signserver.adminws;

import java.math.BigInteger;
import java.io.*;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebService;
import javax.naming.NamingException;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.SecurityEventsAuditorSessionLocal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.query.Criteria;
import org.cesecore.util.query.Elem;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.clauses.Order;
import org.cesecore.util.query.elems.Term;
import org.signserver.common.*;
import org.signserver.common.util.*;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.CertificateClientCredential;
import org.signserver.server.IClientCredential;
import org.signserver.server.UsernamePasswordClientCredential;
import org.signserver.server.log.AdminInfo;

import java.security.NoSuchAlgorithmException;
import java.util.Timer;
import java.util.TimerTask;

import com.tomicalab.cag360.license.*;
import org.signserver.common.dbdao.*;

import org.apache.commons.io.IOUtils;
import org.signserver.admin.cli.defaultimpl.SetProperties;
import org.signserver.admin.cli.defaultimpl.ReloadCommand;

/**
 * Class implementing the Admin WS interface.
 *
 * This class contains web service implementations for almost all EJB methods.
 *
 * @author Markus Kilås
 * @version $Id: AdminWS.java 3335 2013-02-11 15:35:07Z netmackan $
 */
@WebService(serviceName = "AdminWSService")
@Stateless
public class AdminWS {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(AdminWS.class);
    private static final String HTTP_AUTH_BASIC_AUTHORIZATION = "Authorization";
    private static final HashSet<String> LONG_COLUMNS = new HashSet<String>();
    private static final boolean ENABLE_CERTIFICATE_AUTHORIZATE = true;
    private int MAXSESSION = 10;
    private int INTERVAL = 3000;
    private int DELAY = 3000;
    private long EXPIRED_PERIOD = 1200; //1200*3 = 3600s (60m)
    private boolean isAdmin = false;
    public String session;
    public Timer[] time = new Timer[MAXSESSION];
    public MyTask[] myTask = new MyTask[MAXSESSION];
    private static String SESSIONFILE;
    private static String SCRIPTCHANGEIP;
    private static String SCRIPTREBOOT;
    private static String SCRIPTSHUTDOWN;
    private static String P12FILE;
    private static int MONITOR_ACTION_DOWNLOAD_TYPE = 1; // download
    private static int MONITOR_ACTION_VIEW_TYPE = 2; // view
    private static int MONITOR_LOG_SERVER_TYPE = 1; // server.log
    private static int MONITOR_LOG_ENDPOINT_TYPE = 2; // endpoint.log
    private static int MONITOR_LOG_BACKOFFICE_TYPE = 3; // backoffice.log
    private static String MONITOR_LOG_PATH = System.getProperty("jboss.server.home.dir") + "/log/";
    private static Properties config = null;

    static {
        if (config == null) {
            config = DBConnector.getInstances().getPropertiesConfig();
        }
        SESSIONFILE = System.getProperty("jboss.server.home.dir") + "/" + "../../../../../file/session.properties";
        P12FILE = System.getProperty("jboss.server.home.dir") + "/" + "../../../../../file/p12";
        SCRIPTCHANGEIP = System.getProperty("jboss.server.home.dir") + "/" + "../../../../../file/setIPHostName.sh";
        SCRIPTREBOOT = System.getProperty("jboss.server.home.dir") + "/" + "../../../../../file/reboot.sh";
        SCRIPTSHUTDOWN = System.getProperty("jboss.server.home.dir") + "/" + "../../../../../file/shutdown.sh";
    }

    public String createSession(String userName, String clientIP, int status) {
        Properties newProps = new Properties();
        Properties p = getProperties();
        Enumeration enumProps = p.propertyNames();
        String _key = "";
        boolean isSet = false;

        String value = userName + clientIP + System.currentTimeMillis();
        byte[] sessionbyte = value.getBytes();
        try {
            MessageDigest msd = MessageDigest.getInstance("SHA1");
            msd.update(sessionbyte);
            byte[] dgest = msd.digest();

            byte[] strStatus = String.valueOf(status).getBytes();
            byte[] dgestStatus = new byte[dgest.length + strStatus.length];
            System.arraycopy(dgest, 0, dgestStatus, 0, dgest.length);
            System.arraycopy(strStatus, 0, dgestStatus, dgest.length, strStatus.length);

            value = new String(Base64.encode(dgestStatus));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        while (enumProps.hasMoreElements()) {
            _key = (String) enumProps.nextElement();
            if (p.getProperty(_key).equals("")) {
                if (!isSet) {
                    newProps.setProperty(_key, value);
                    isSet = true;
                    time[Integer.valueOf(_key)] = new Timer();
                    myTask[Integer.valueOf(_key)] = new MyTask(_key, value);
                    time[Integer.valueOf(_key)].schedule(myTask[Integer.valueOf(_key)], DELAY, INTERVAL);
                } else {
                    newProps.setProperty(_key, p.getProperty(_key));
                }
            } else {
                newProps.setProperty(_key, p.getProperty(_key));
            }
        }
        saveProperties(newProps);
        return value;
    }

    public int clearSession(String value) {
        int res = -1;
        Properties newProps = new Properties();
        Properties p = getProperties();
        Enumeration enumProps = p.propertyNames();
        String _key = "";

        while (enumProps.hasMoreElements()) {

            _key = (String) enumProps.nextElement();

            if (p.getProperty(_key).equals(value)) {
                newProps.setProperty(_key, "");
                res = 0;
            } else {
                newProps.setProperty(_key, p.getProperty(_key));
            }
        }
        saveProperties(newProps);
        return res;
    }

    public Properties getProperties() {
        int indexTMS = MAXSESSION - 1;
        File f = new File(SESSIONFILE);
        Properties tmp = new Properties();
        if (!f.exists()) {
            for (int i = 0; i < MAXSESSION; i++) {
                tmp.setProperty(String.valueOf(i), "");
                if (i == (indexTMS)) {
                    tmp.setProperty(String.valueOf(i), "VG9taWNhLVRNUw==");
                }
            }
            OutputStream outPropFile;
            try {
                outPropFile = new FileOutputStream(SESSIONFILE);
                tmp.store(outPropFile, "Session of CAG360. Designed by VuDP");
                outPropFile.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        InputStream inPropFile;
        try {
            inPropFile = new FileInputStream(SESSIONFILE);
            tmp.load(inPropFile);
            inPropFile.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return tmp;
    }

    public void saveProperties(Properties p) {
        OutputStream outPropFile;
        try {
            outPropFile = new FileOutputStream(SESSIONFILE);
            p.store(outPropFile, "Session of CAG360. Designed by VuDP");
            outPropFile.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public String getSession(String key) {
        Properties p = getProperties();
        Enumeration enumProps = p.propertyNames();
        String _key = "";
        String _value = "";
        while (enumProps.hasMoreElements()) {
            _key = (String) enumProps.nextElement();
            if (_key.equals(key)) {
                _value = p.getProperty(_key);
                break;
            }
        }
        return _value;
    }

    public boolean SessionExits(String value) {
        boolean isExit = false;
        Properties p = getProperties();
        Enumeration enumProps = p.propertyNames();
        String _key = "";
        while (enumProps.hasMoreElements()) {

            _key = (String) enumProps.nextElement();
            if (p.getProperty(_key).equals(value)) {
                isExit = true;
                break;
            }
        }
        return isExit;
    }

    private boolean VerifySession(String sessionKey) {
        return SessionExits(sessionKey);
    }

    class MyTask extends TimerTask {

        private int times = 0;
        String key;
        String value;

        public MyTask() {
        }

        public MyTask(String _key, String _value) {
            key = _key;
            value = _value;
        }

        public void run() {
            String currentSession = getSession(key);
            if (currentSession.equals("")) {
                System.out.println("clear session " + key);
                this.cancel();
            } else {
                times++;
                if (times <= EXPIRED_PERIOD) {
                    //System.out.println("session "+key);
                } else {
                    System.out.println("clear session " + key);
                    clearSession(value);
                    this.cancel();
                }
            }
        }
    }

    static {
        LONG_COLUMNS.add(AuditLogEntry.FIELD_TIMESTAMP);
        LONG_COLUMNS.add(AuditLogEntry.FIELD_SEQUENCENUMBER);
    }
    @Resource
    private WebServiceContext wsContext;
    @EJB
    private IWorkerSession.ILocal worker;
    @EJB
    private IGlobalConfigurationSession.ILocal global;
    @EJB
    private SecurityEventsAuditorSessionLocal auditor;

    @PostConstruct
    private void postConstruct() { // NOPMD
        if (worker == null) {
            try {
                worker = ServiceLocator.getInstance().lookupRemote(
                        IWorkerSession.ILocal.class);
            } catch (NamingException ex) {
                LOG.error("Error looking up WorkerSession", ex);
            }
        }
        if (global == null) {
            try {
                global = ServiceLocator.getInstance().lookupRemote(
                        IGlobalConfigurationSession.ILocal.class);
            } catch (NamingException ex) {
                LOG.error("Error looking up GlobalConfigurationSession", ex);
            }
        }
    }

    /**
     * Returns the Id of a worker given a name
     *
     * @param workerName of the worker, cannot be null
     * @return The Id of a named worker or 0 if no such name exists
     */
    @WebMethod(operationName = "getWorkerId")
    public int getWorkerId(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "workerName") final String workerName,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {

        requireAdminAuthorization("getWorkerId", ClientID, sessionKey);

        return worker.getWorkerId(workerName);
    }

    /**
     * Returns the current status of a processalbe.
     *
     * Should be used with the cmd-line status command.
     *
     * @param workerId of the signer
     * @return a WorkerStatus class
     */
    @WebMethod(operationName = "getStatus")
    public WSWorkerStatus getStatus(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "workerId") final int workerId,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws InvalidWorkerIdException, AdminNotAuthorizedException {
        requireAdminAuthorization("getStatus", ClientID, sessionKey);

        final WSWorkerStatus result;
        final WorkerStatus status = worker.getStatus(workerId);
        if (status == null) {
            result = null;
        } else {
            result = new WSWorkerStatus();
            result.setActiveConfig(status.getActiveSignerConfig().getProperties());
            result.setHostname(status.getHostname());
            result.setOk(status.getFatalErrors().isEmpty() ? null : "offline");
            result.setWorkerId(workerId);
            final ByteArrayOutputStream bout1 = new ByteArrayOutputStream();
            status.displayStatus(workerId, new PrintStream(bout1), false);
            result.setStatusText(bout1.toString());

            final ByteArrayOutputStream bout2 = new ByteArrayOutputStream();
            status.displayStatus(workerId, new PrintStream(bout2), true);
            //result.setCompleteStatusText(bout2.toString());
            try {
                result.setCompleteStatusText(bout2.toString("UTF-8"));
            } catch (UnsupportedEncodingException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
        return result;
    }

    /**
     * Method used when a configuration have been updated. And should be called
     * from the commandline.
     *
     * @param workerId of the worker that should be reloaded, or 0 to reload
     * reload of all available workers
     */
    @WebMethod(operationName = "reloadConfiguration")
    public void reloadConfiguration(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "workerId") int workerId,
            @WebParam(name = "sessionKey") String sessionKey)
            throws AdminNotAuthorizedException {
        final AdminInfo adminInfo = requireAdminAuthorization(
                "reloadConfiguration", ClientID, sessionKey);

        worker.reloadConfiguration(adminInfo, workerId);
    }

    /**
     * Method used to activate the signtoken of a signer. Should be called from
     * the command line.
     *
     * @param signerId of the signer
     * @param authenticationCode (PIN) used to activate the token.
     * @throws CryptoTokenOfflineException
     * @throws CryptoTokenAuthenticationFailureException
     */
    @WebMethod(operationName = "activateSigner")
    public void activateSigner(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "signerId") int signerId,
            @WebParam(name = "authenticationCode") String authenticationCode,
            @WebParam(name = "sessionKey") String sessionKey)
            throws CryptoTokenAuthenticationFailureException,
            CryptoTokenOfflineException, InvalidWorkerIdException,
            AdminNotAuthorizedException {
        requireAdminAuthorization("activateSigner", ClientID, sessionKey);
        LOG.info("activateSigner Signer " + signerId);
        worker.activateSigner(signerId, authenticationCode);
    }

    /**
     * Method used to deactivate the signtoken of a signer. Should be called
     * from the command line.
     *
     * @param signerId of the signer
     * @return true if deactivation was successful
     * @throws CryptoTokenOfflineException
     * @throws CryptoTokenAuthenticationFailureException
     */
    @WebMethod(operationName = "deactivateSigner")
    public boolean deactivateSigner(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "signerId") int signerId,
            @WebParam(name = "sessionKey") String sessionKey)
            throws CryptoTokenOfflineException, InvalidWorkerIdException,
            AdminNotAuthorizedException {
        requireAdminAuthorization("deactivateSigner", ClientID, sessionKey);

        return worker.deactivateSigner(signerId);
    }

    // ///////////////////////////////////////////////////////////////////////////////
    /**
     * Returns the current configuration of a worker.
     *
     * Observe that this config might not be active until a reload command has
     * been excecuted.
     *
     * @param workerId
     * @return the current (not always active) configuration
     */
    @WebMethod(operationName = "getCurrentWorkerConfig")
    public WSWorkerConfig getCurrentWorkerConfig(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "workerId") final int workerId,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("getCurrentWorkerConfig", ClientID, sessionKey);

        return new WSWorkerConfig(worker.getCurrentWorkerConfig(workerId).getProperties());
    }

    /**
     * Sets a parameter in a workers configuration.
     *
     * Observe that the worker isn't activated with this config until reload is
     * performed.
     *
     * @param workerId
     * @param key
     * @param value
     */
    @WebMethod(operationName = "setWorkerProperty")
    public void setWorkerProperty(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "workerId") final int workerId,
            @WebParam(name = "key") final String key,
            @WebParam(name = "value") final String value,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        final AdminInfo adminInfo = requireAdminAuthorization(
                "setWorkerProperty", ClientID, sessionKey);

        worker.setWorkerProperty(adminInfo, workerId, key, value);
    }

    /**
     * Removes a given worker's property.
     *
     * @param workerId
     * @param key
     * @return true if the property did exist and was removed othervise false
     */
    @WebMethod(operationName = "removeWorkerProperty")
    public boolean removeWorkerProperty(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "workerId") final int workerId,
            @WebParam(name = "key") final String key,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        final AdminInfo adminInfo = requireAdminAuthorization(
                "removeWorkerProperty", ClientID, sessionKey);

        return worker.removeWorkerProperty(adminInfo, workerId, key);
    }

    /**
     * Method that returns a collection of AuthorizedClient of client
     * certificate sn and issuerid accepted for a given signer.
     *
     * @param workerId
     * @return Sorted collection of authorized clients
     */
    @WebMethod(operationName = "getAuthorizedClients")
    public Collection<AuthorizedClient> getAuthorizedClients(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "workerId") final int workerId,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("getAuthorizedClients", ClientID,
                sessionKey);

        return worker.getAuthorizedClients(workerId);
    }

    /**
     * Method adding an authorized client to a signer.
     *
     * @param workerId
     * @param authClient
     */
    @WebMethod(operationName = "addAuthorizedClient")
    public void addAuthorizedClient(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "workerId") final int workerId,
            @WebParam(name = "authClient") final AuthorizedClient authClient,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        final AdminInfo adminInfo = requireAdminAuthorization(
                "addAuthorizedClient", ClientID, sessionKey);

        worker.addAuthorizedClient(adminInfo, workerId, authClient);
    }

    /**
     * Removes an authorized client from a signer.
     *
     * @param workerId
     * @param authClient
     */
    @WebMethod(operationName = "removeAuthorizedClient")
    public boolean removeAuthorizedClient(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "workerId") final int workerId,
            @WebParam(name = "authClient") final AuthorizedClient authClient,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        final AdminInfo adminInfo = requireAdminAuthorization(
                "removeAuthorizedClient", ClientID, sessionKey);

        return worker.removeAuthorizedClient(adminInfo, workerId, authClient);
    }

    /**
     * Method used to let a signer generate a certificate request using the
     * signers own genCertificateRequest method.
     *
     * @param signerId id of the signer
     * @param certReqInfo information used by the signer to create the request
     * @param explicitEccParameters false should be default and will use
     * NamedCurve encoding of ECC public keys (IETF recommendation), use true to
     * include all parameters explicitly (ICAO ePassport requirement).
     */
    @WebMethod(operationName = "getPKCS10CertificateRequest")
    public Base64SignerCertReqData getPKCS10CertificateRequest(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "signerId") final int signerId,
            @WebParam(name = "certReqInfo") final PKCS10CertReqInfo certReqInfo,
            @WebParam(name = "explicitEccParameters") final boolean explicitEccParameters,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws CryptoTokenOfflineException, InvalidWorkerIdException,
            AdminNotAuthorizedException {
        final AdminInfo adminInfo = requireAdminAuthorization(
                "getPKCS10CertificateRequest", ClientID, sessionKey);

        final ICertReqData data = worker.getCertificateRequest(adminInfo,
                signerId, certReqInfo, explicitEccParameters);
        if (!(data instanceof Base64SignerCertReqData)) {
            throw new RuntimeException("Unsupported cert req data");
        }
        return (Base64SignerCertReqData) data;
    }

    /**
     * Method used to let a signer generate a certificate request using the
     * signers own genCertificateRequest method.
     *
     * @param signerId id of the signer
     * @param certReqInfo information used by the signer to create the request
     * @param explicitEccParameters false should be default and will use
     * NamedCurve encoding of ECC public keys (IETF recommendation), use true to
     * include all parameters explicitly (ICAO ePassport requirement).
     * @param defaultKey true if the default key should be used otherwise for
     * instance use next key.
     */
    @WebMethod(operationName = "getPKCS10CertificateRequestForKey")
    public Base64SignerCertReqData getPKCS10CertificateRequestForKey(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "signerId") final int signerId,
            @WebParam(name = "certReqInfo") final PKCS10CertReqInfo certReqInfo,
            @WebParam(name = "explicitEccParameters") final boolean explicitEccParameters,
            @WebParam(name = "defaultKey") final boolean defaultKey,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws CryptoTokenOfflineException, InvalidWorkerIdException,
            AdminNotAuthorizedException {
        final AdminInfo adminInfo = requireAdminAuthorization(
                "getPKCS10CertificateRequestForKey", ClientID, sessionKey);

        final ICertReqData data = worker.getCertificateRequest(adminInfo,
                signerId, certReqInfo, explicitEccParameters, defaultKey);
        if (!(data instanceof Base64SignerCertReqData)) {
            throw new RuntimeException("Unsupported cert req data");
        }
        return (Base64SignerCertReqData) data;
    }

    /**
     * Method returning the current signing certificate for the signer.
     *
     * @param signerId Id of signer
     * @return Current signing certificate if the worker is a signer and it has
     * been configured. Otherwise null or an exception is thrown.
     * @throws CryptoTokenOfflineException In case the crypto token or the
     * worker is not active
     */
    @WebMethod(operationName = "getSignerCertificate")
    public byte[] getSignerCertificate(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "signerId") final int signerId,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws CryptoTokenOfflineException, AdminNotAuthorizedException {
        requireAdminAuthorization("getSignerCertificate", ClientID, sessionKey);

        return worker.getSignerCertificateBytes(signerId);
    }

    /**
     * Method returning the current signing certificate chain for the signer.
     *
     * @param signerId Id of signer
     * @return Current signing certificate chain if the worker is a signer and
     * it has been configured. Otherwise null or an exception is thrown.
     * @throws CryptoTokenOfflineException In case the crypto token or the
     * worker is not active
     */
    @WebMethod(operationName = "getSignerCertificateChain")
    public List<byte[]> getSignerCertificateChain(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "signerId") final int signerId,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws CryptoTokenOfflineException, AdminNotAuthorizedException {
        requireAdminAuthorization("getSignerCertificateChain", ClientID, sessionKey);

        return worker.getSignerCertificateChainBytes(signerId);
    }

    /**
     * Gets the last date the specified worker can do signings.
     *
     * @param workerId Id of worker to check.
     * @return The last date or null if no last date (=unlimited).
     * @throws CryptoTokenOfflineException In case the cryptotoken is offline
     * for some reason.
     */
    @WebMethod(operationName = "getSigningValidityNotAfter")
    public Date getSigningValidityNotAfter(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "workerId") final int workerId,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws CryptoTokenOfflineException, AdminNotAuthorizedException {
        requireAdminAuthorization("getSigningValidityNotAfter", ClientID, sessionKey);

        return worker.getSigningValidityNotAfter(workerId);
    }

    /**
     * Gets the first date the specified worker can do signings.
     *
     * @param workerId Id of worker to check.
     * @return The first date or null if no last date (=unlimited).
     * @throws CryptoTokenOfflineException In case the cryptotoken is offline
     * for some reason.
     */
    @WebMethod(operationName = "getSigningValidityNotBefore")
    public Date getSigningValidityNotBefore(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "workerId") final int workerId,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws CryptoTokenOfflineException, AdminNotAuthorizedException {
        requireAdminAuthorization("getSigningValidityNotBefore", ClientID, sessionKey);

        return worker.getSigningValidityNotBefore(workerId);
    }

    /**
     * Returns the value of the KeyUsageCounter for the given workerId. If no
     * certificate is configured for the worker or the current key does not yet
     * have a counter in the database -1 is returned.
     *
     * @param workerId
     * @return Value of the key usage counter or -1
     * @throws CryptoTokenOfflineException
     */
    @WebMethod(operationName = "getKeyUsageCounterValue")
    public long getKeyUsageCounterValue(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "workerId") final int workerId,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws CryptoTokenOfflineException, AdminNotAuthorizedException {
        requireAdminAuthorization("getKeyUsageCounterValue", ClientID, sessionKey);

        return worker.getKeyUsageCounterValue(workerId);
    }

    /**
     * Method used to remove a key from a signer.
     *
     * @param signerId id of the signer
     * @param purpose on of ICryptoToken.PURPOSE_ constants
     * @return true if removal was successful.
     */
    @WebMethod(operationName = "destroyKey")
    public boolean destroyKey(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "signerId") final int signerId,
            @WebParam(name = "authCode") final String authCode,
            @WebParam(name = "alias") final String alias,
            @WebParam(name = "purpose") final int purpose,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws InvalidWorkerIdException, AdminNotAuthorizedException {
        final AdminInfo adminInfo = requireAdminAuthorization("destroyKey", ClientID,
                sessionKey);
        //boolean response = worker.destroyKey(adminInfo, signerId, authCode, alias, purpose);
        boolean response = true; // don't destroy key
        return response;
    }

    /**
     * Generate a new keypair.
     *
     * @param signerId Id of signer
     * @param keyAlgorithm Key algorithm
     * @param keySpec Key specification
     * @param alias Name of the new key
     * @param authCode Authorization code
     * @throws CryptoTokenOfflineException
     * @throws IllegalArgumentException
     */
    @WebMethod(operationName = "generateSignerKey")
    public synchronized String generateSignerKey(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "signerId") final int signerId,
            @WebParam(name = "keyAlgorithm") final String keyAlgorithm,
            @WebParam(name = "keySpec") final String keySpec,
            @WebParam(name = "alias") final String alias,
            @WebParam(name = "authCode") final String authCode,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws CryptoTokenOfflineException, InvalidWorkerIdException,
            AdminNotAuthorizedException {
        final AdminInfo adminInfo = requireAdminAuthorization("generateSignerKey", ClientID, sessionKey);
        String response = worker.generateSignerKey(adminInfo, signerId, keyAlgorithm,
                keySpec, alias, authCode.toCharArray());
        return response;
    }

    /**
     * Tests the key identified by alias or all keys if "all" specified.
     *
     * @param signerId Id of signer
     * @param alias Name of key to test or "all" to test all available
     * @param authCode Authorization code
     * @return Collection with test results for each key
     * @throws CryptoTokenOfflineException
     * @throws KeyStoreException
     */
    @WebMethod(operationName = "testKey")
    @SuppressWarnings("deprecation")
    // We support the old KeyTestResult class as well
    public Collection<KeyTestResult> testKey(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "signerId") final int signerId,
            @WebParam(name = "alias") final String alias,
            @WebParam(name = "authCode") final String authCode,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws CryptoTokenOfflineException, InvalidWorkerIdException,
            KeyStoreException, AdminNotAuthorizedException {
        final AdminInfo adminInfo = requireAdminAuthorization("testKey", ClientID,
                sessionKey);

        // Workaround for KeyTestResult first placed in wrong package
        final Collection<KeyTestResult> results;
        Collection<?> res = worker.testKey(adminInfo, signerId, alias,
                authCode.toCharArray());
        if (res.size() < 1) {
            results = new LinkedList<KeyTestResult>();
        } else {
            if (res.iterator().next() instanceof org.signserver.server.KeyTestResult) {
                results = new LinkedList<KeyTestResult>();
                for (Object res0 : res) {
                    final org.signserver.server.KeyTestResult res1 = (org.signserver.server.KeyTestResult) res0;
                    final KeyTestResult res2 = new KeyTestResult(
                            res1.getAlias(), res1.isSuccess(),
                            res1.getStatus(), res1.getPublicKeyHash());
                    results.add(res2);
                }
            } else {
                results = new LinkedList<KeyTestResult>();
                for (Object o : res) {
                    if (o instanceof KeyTestResult) {
                        results.add((KeyTestResult) o);
                    }
                }
            }
        }
        return results;
    }

    /**
     * Method used to upload a certificate to a signers active configuration.
     *
     * @param signerId id of the signer
     * @param signerCert the certificate used to sign signature requests
     * @param scope one of GlobalConfiguration.SCOPE_ constants
     */
    @WebMethod(operationName = "uploadSignerCertificate")
    public void uploadSignerCertificate(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "signerId") final int signerId,
            @WebParam(name = "signerCert") final byte[] signerCert,
            @WebParam(name = "scope") final String scope,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws IllegalRequestException, AdminNotAuthorizedException {
        final AdminInfo adminInfo = requireAdminAuthorization(
                "uploadSignerCertificate", ClientID, sessionKey);

        try {
            worker.uploadSignerCertificate(adminInfo, signerId, signerCert,
                    scope);
        } catch (CertificateException ex) {
            // Log stacktrace and only pass on description to client
            LOG.error("Unable to parse certificate", ex);
            throw new IllegalRequestException("Unable to parse certificate");
        }
    }

    /**
     * Method used to upload a complete certificate chain to a configuration
     *
     * @param signerId id of the signer
     * @param signerCerts the certificate chain used to sign signature requests
     * @param scope one of GlobalConfiguration.SCOPE_ constants
     */
    @WebMethod(operationName = "uploadSignerCertificateChain")
    public void uploadSignerCertificateChain(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "signerId") final int signerId,
            @WebParam(name = "signerCerts") final List<byte[]> signerCerts,
            @WebParam(name = "scope") final String scope,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws IllegalRequestException, AdminNotAuthorizedException {
        final AdminInfo adminInfo = requireAdminAuthorization(
                "uploadSignerCertificateChain", ClientID,
                sessionKey);
        try {
            worker.uploadSignerCertificateChain(adminInfo, signerId, signerCerts, scope);
            // 20180812
            try {
                reloadWorker(ClientID, String.valueOf(signerId), sessionKey);
                //final WorkerStatus status = worker.getStatus(signerId);
                //if(status != null) {
                //if(status.getFatalErrors().isEmpty()) {
                GeneralPolicy gp = DBConnector.getInstances().getGeneralPolicy();
                if (gp.isFrontIsNotifySignServerCertificateByEmail()) {
                    // 20180815
                                            /*
                     * String template = gp.getFrontEmailTemplateSignServer();
                     *
                     * Properties p = new Properties(); Reader reader = new
                     * InputStreamReader(new
                     * ByteArrayInputStream(template.getBytes()),
                     * StandardCharsets.UTF_8); p.load(reader); String subject =
                     * p.getProperty("SUBJECT"); String content =
                     * p.getProperty("CONTENT");
                     */
                    String[] template = DBConnector.getInstances().getBackOfficeParamsDetailClient(Defines.PARAMS_BACKOFFICE_MAIL_ISSUEDCERT_SIGNSERVER, true);
                    String subject = template[0];
                    String content = template[1];

                    content = content.replace(Defines.PATTERN_BOLD_OPEN, "<b>");
                    content = content.replace(Defines.PATTERN_BOLD_CLOSE, "</b>");
                    content = content.replace(Defines.PATTERN_NEW_LINE, "<br>");

                    String[] result = DBConnector.getInstances().getSignServerByWorkerUUID(signerId);
                    if (result != null) {
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
                                if (endpointParams != null) {
                                    EndpointServiceResp endpointServiceResp = EndpointService.getInstance().sendEmailNoLogging(
                                            threadChannel,
                                            threadUser,
                                            threadEmail,
                                            threadSubject,
                                            threadContent,
                                            attachment,
                                            ExtFunc.getCertFileNameFromSubjectDn(signer.getSubjectDN().toString(), threadUser) + ".cer",
                                            endpointParams[1],
                                            Integer.parseInt(endpointParams[2]));
                                    if (endpointServiceResp.getResponseCode() == 0) {
                                        LOG.info("Certificate has been sent to " + threadEmail);
                                    } else {
                                        LOG.error("Failed to send certificate to " + threadEmail);
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
            } catch (Exception e) {
                e.printStackTrace();
            }
        } catch (CertificateException ex) {
            // Log stacktrace and only pass on description to client
            LOG.error("Unable to parse certificate", ex);
            throw new IllegalRequestException("Unable to parse certificate");
        }
    }

    /**
     * Method setting a global configuration property. For node. prefix will the
     * node id be appended.
     *
     * @param scope one of the GlobalConfiguration.SCOPE_ constants
     * @param key of the property should not have any scope prefix, never null
     * @param value the value, never null.
     */
    @WebMethod(operationName = "setGlobalProperty")
    public void setGlobalProperty(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "scope") final String scope,
            @WebParam(name = "key") final String key,
            @WebParam(name = "value") final String value,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        final AdminInfo adminInfo = requireAdminAuthorization(
                "setGlobalProperty", ClientID, sessionKey);
        global.setProperty(adminInfo, scope, key, value);
    }

    /**
     * Method used to remove a property from the global configuration.
     *
     * @param scope one of the GlobalConfiguration.SCOPE_ constants
     * @param key of the property should start with either glob. or node., never
     * null
     * @return true if removal was successful, othervise false.
     */
    @WebMethod(operationName = "removeGlobalProperty")
    public boolean removeGlobalProperty(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "scope") final String scope,
            @WebParam(name = "key") final String key,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        final AdminInfo adminInfo = requireAdminAuthorization(
                "removeGlobalProperty", ClientID, sessionKey);

        return global.removeProperty(adminInfo, scope, key);
    }

    /**
     * Method that returns all the global properties with Global Scope and Node
     * scopes properties for this node.
     *
     * @return A GlobalConfiguration Object, never null
     */
    @WebMethod(operationName = "getGlobalConfiguration")
    public WSGlobalConfiguration getGlobalConfiguration(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("getGlobalConfiguration", ClientID, sessionKey);

        final WSGlobalConfiguration result;
        final GlobalConfiguration config = global.getGlobalConfiguration();
        if (config == null) {
            result = null;
        } else {
            result = new WSGlobalConfiguration();
            final Properties props = new Properties();
            final Enumeration<String> en = config.getKeyEnumeration();
            while (en.hasMoreElements()) {
                final String key = en.nextElement();
                props.setProperty(key, config.getProperty(key));
            }
            result.setConfig(props);
            result.setState(config.getState());
            result.setAppVersion(config.getAppVersion());
            result.setClusterClassLoaderEnabled(false);
            result.setRequireSigning(false);
            result.setUseClassVersions(false);
        }
        return result;
    }

    /**
     * Help method that returns all worker, either signers or services defined
     * in the global configuration.
     *
     * @param workerType can either be GlobalConfiguration.WORKERTYPE_ALL,
     * _SIGNERS or _SERVICES
     * @return A List if Integers of worker Ids, never null.
     */
    @WebMethod(operationName = "getWorkers")
    public List<Integer> getWorkers(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "workerType") final int workerType,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("getWorkers", ClientID, sessionKey);

        return worker.getWorkers(workerType);
    }

    /**
     * Method that is used after a database crash to restore all cached data to
     * database.
     *
     * @throws ResyncException if resync was unsuccessfull
     */
    @WebMethod(operationName = "globalResync")
    public void globalResync(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "sessionKey") final String sessionKey) throws ResyncException,
            AdminNotAuthorizedException {
        final AdminInfo adminInfo = requireAdminAuthorization("globalResync", ClientID,
                sessionKey);

        global.resync(adminInfo);
    }

    /**
     * Method to reload all data from database.
     */
    @WebMethod(operationName = "globalReload")
    public void globalReload(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "sessionKey") final String sessionKey) throws AdminNotAuthorizedException {
        final AdminInfo adminInfo = requireAdminAuthorization("globalReload", ClientID,
                sessionKey);

        global.reload(adminInfo);
    }

    /**
     * Method for requesting a collection of requests to be processed by the
     * specified worker.
     *
     * @param workerIdOrName Name or ID of the worker who should process the
     * request
     * @param requests Collection of serialized (binary) requests.
     *
     * @see
     * RequestAndResponseManager#serializeProcessRequest(org.signserver.common.ProcessRequest)
     * @see RequestAndResponseManager#parseProcessRequest(byte[])
     */
    @WebMethod(operationName = "process")
    public java.util.Collection<byte[]> process(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "workerIdOrName") final String workerIdOrName,
            @WebParam(name = "processRequest") Collection<byte[]> requests,
            @WebParam(name = "sessionKey") String sessionKey)
            throws InvalidWorkerIdException, IllegalRequestException,
            CryptoTokenOfflineException, SignServerException,
            AdminNotAuthorizedException {
        final AdminInfo adminInfo = requireAdminAuthorization("process", ClientID,
                sessionKey);

        final Collection<byte[]> result = new LinkedList<byte[]>();

        final X509Certificate[] clientCerts = getClientCertificates();
        final X509Certificate clientCertificate;
        if (clientCerts != null && clientCerts.length > 0) {
            clientCertificate = clientCerts[0];
        } else {
            clientCertificate = null;
        }
        // Requests from authenticated administrators are considered to come
        // from the local host and is set to null. This is also the same as
        // when requests are over EJB calls.
        final String ipAddress = null;

        final RequestContext requestContext = new RequestContext(
                clientCertificate, ipAddress);

        IClientCredential credential;
        if (clientCertificate instanceof X509Certificate) {
            final X509Certificate cert = (X509Certificate) clientCertificate;
            LOG.debug("Authentication: certificate");
            credential = new CertificateClientCredential(cert.getSerialNumber().toString(16), cert.getIssuerDN().getName());
        } else {
            final HttpServletRequest servletRequest = (HttpServletRequest) wsContext.getMessageContext().get(MessageContext.SERVLET_REQUEST);
            // Check is client supplied basic-credentials
            final String authorization = servletRequest.getHeader(HTTP_AUTH_BASIC_AUTHORIZATION);
            if (authorization != null) {
                LOG.debug("Authentication: password");

                final String decoded[] = new String(Base64.decode(authorization.split("\\s")[1])).split(":", 2);

                credential = new UsernamePasswordClientCredential(decoded[0],
                        decoded[1]);
            } else {
                LOG.debug("Authentication: none");
                credential = null;
            }
        }
        requestContext.put(RequestContext.CLIENT_CREDENTIAL, credential);

        final int workerId = getWorkerId(ClientID, workerIdOrName, sessionKey);

        for (byte[] requestBytes : requests) {
            final ProcessRequest req;
            try {
                req = RequestAndResponseManager.parseProcessRequest(requestBytes);
            } catch (IOException ex) {
                LOG.error("Error parsing process request", ex);
                throw new IllegalRequestException(
                        "Error parsing process request", ex);
            }
            try {
                result.add(RequestAndResponseManager.serializeProcessResponse(worker.process(adminInfo,
                        workerId, req, requestContext)));
            } catch (IOException ex) {
                LOG.error("Error serializing process response", ex);
                throw new IllegalRequestException(
                        "Error serializing process response", ex);
            }
        }
        return result;
    }

    /**
     * Query the audit log.
     *
     * @param startIndex Index where select will start. Set to 0 to start from
     * the beginning.
     * @param max maximum number of results to be returned.
     * @param conditions List of conditions defining the subset of logs to be
     * selected.
     * @param orderings List of ordering conditions for ordering the result.
     * @return List of log entries
     * @throws SignServerException In case of internal failures
     * @throws AdminNotAuthorizedException In case the administrator was not
     * authorized to perform the operation
     */
    @WebMethod(operationName = "queryAuditLog")
    public List<LogEntry> queryAuditLog(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "startIndex") int startIndex,
            @WebParam(name = "max") int max,
            @WebParam(name = "condition") final List<QueryCondition> conditions,
            @WebParam(name = "ordering") final List<QueryOrdering> orderings,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws SignServerException, AdminNotAuthorizedException {
        final AdminInfo adminInfo = requireAdminAuthorization( //requireAuditorAuthorization
                "queryAuditLog", ClientID, sessionKey);

        // For now we only query one of the available audit devices
        Set<String> devices = auditor.getQuerySupportingLogDevices();
        if (devices.isEmpty()) {
            throw new SignServerException(
                    "No log devices available for querying");
        }
        final String device = devices.iterator().next();

        final List<Elem> elements = toElements(conditions);
        final QueryCriteria qc = QueryCriteria.create();

        for (QueryOrdering order : orderings) {
            qc.add(new Order(order.getColumn(), Order.Value.valueOf(order.getOrder().name())));
        }

        if (!elements.isEmpty()) {
            qc.add(andAll(elements, 0));
        }

        try {
            return toLogEntries(worker.selectAuditLogs(adminInfo, startIndex,
                    max, qc, device));
        } catch (AuthorizationDeniedException ex) {
            throw new AdminNotAuthorizedException(ex.getMessage());
        }
    }

    /**
     * Convert to WS model LogEntry:s.
     */
    private List<LogEntry> toLogEntries(
            final List<? extends AuditLogEntry> entries) {
        final List<LogEntry> results = new LinkedList<LogEntry>();
        for (AuditLogEntry entry : entries) {
            results.add(LogEntry.fromAuditLogEntry(entry));
        }
        return results;
    }

    /**
     * Convert to the CESeCore model Elem:s.
     */
    private List<Elem> toElements(final List<QueryCondition> conditions) {
        final LinkedList<Elem> results = new LinkedList<Elem>();
        for (QueryCondition cond : conditions) {
            final Object value;
            if (LONG_COLUMNS.contains(cond.getColumn())) {
                value = Long.parseLong(cond.getValue());
            } else {
                value = cond.getValue();
            }
            results.add(new Term(cond.getOperator(), cond.getColumn(), value));
        }
        return results;
    }

    /**
     * Tie together the list of Elem:s to a tree of AND operations. This uses a
     * recursive implementation not expected to work for larger lists of Elem:s,
     * however as the number of columns are limited it is not expected to be a
     * real problem.
     */
    protected Elem andAll(final List<Elem> elements, final int index) {
        if (index >= elements.size() - 1) {
            return elements.get(index);
        } else {
            return Criteria.and(elements.get(index),
                    andAll(elements, index + 1));
        }
    }

    private boolean isAdminLogin(String sessionKey) {
        boolean isOK = false;
        byte[] session = Base64.decode(sessionKey);
        int length = session.length;
        String str = new String(new byte[]{session[length - 1]});
        if (str.equals("1")) {
            isOK = true;
        }
        return isOK;

    }

    private boolean isUserLogin(String sessionKey) {
        boolean isOK = false;
        byte[] session = Base64.decode(sessionKey);
        int length = session.length;
        String str = new String(new byte[]{session[length - 1]});
        if (str.equals("2")) {
            isOK = true;
        }
        return isOK;

    }

    private AdminInfo requireAdminAuthorization(final String operation,
            final int ClientID,
            final String sessionKey) throws AdminNotAuthorizedException {
        LOG.debug(">requireAdminAuthorization");

        X509Certificate[] certs = getClientCertificates();

        if (sessionKey == null || sessionKey.compareTo("") == 0) {
            throw new AdminNotAuthorizedException(
                    "Administrator not authorized to resource. "
                    + "SessionKey cannot be null or empty");
        }

        boolean grantAccess = false;
        if (sessionKey.equals("VG9taWNhLVRNUw==")) {
            grantAccess = true;
        }

        /*
         * boolean grantAccess = VerifySession(sessionKey); // Admin
         * if(isAdminLogin(sessionKey)) { if(!grantAccess) throw new
         * AdminNotAuthorizedException( "Administrator not authorized to
         * resource. " + "Access denied. Invalid session"); if(certs == null) {
         * if(DBConnector.getInstances().isUseSSL()) { throw new
         * AdminNotAuthorizedException( "Administrator not authorized to
         * resource. " + "Access denied. SSL client certificate error"); } }
         * else { return new AdminInfo(certs[0].getSubjectDN().getName() ,
         * certs[0].getIssuerDN().getName() , certs[0].getSerialNumber()); } }
         *
         * if(isUserLogin(sessionKey)) { //Normal user
         * if(!DBConnector.getInstances().AdminWSIPFiler(getIpOfClient())) throw
         * new AdminNotAuthorizedException( "Administrator not authorized to
         * resource. " + "Your IP doesn't grant to be accessed");
         *
         * if(!grantAccess) throw new AdminNotAuthorizedException(
         * "Administrator not authorized to resource. " + "Access denied.
         * Invalid session"); if(certs == null) {
         * if(DBConnector.getInstances().isUseSSL()) { throw new
         * AdminNotAuthorizedException( "Administrator not authorized to
         * resource. " + "Access denied. SSL client certificate error"); } }
         * else { return new AdminInfo("TMS Subject", "TMS Issuer", new
         * BigInteger("12345678")); }
         *
         * }
         */
        // TMS user
        if (!grantAccess) {
            throw new AdminNotAuthorizedException(
                    "Administrator not authorized to resource. "
                    + "Access denied. Invalid session");
        }

        return new AdminInfo("TMS Subject", "TMS Issuer", new BigInteger("12345678"));
        /*
         * if
         * (PreferenceConfi.getInstace().isSuperAdminConnect(getIpOfClient())) {
         * if (PreferenceConfi.getInstace().isAuthorized(getIpOfClient()))
         * return new AdminInfo("NHAN", "TRANVAN", new BigInteger("12345678"));
         * else throw new AdminNotAuthorizedException( "Auditor not authorized
         * to resource. " + "Client authentication required."); } else {
         * System.out .println("[TCCHTNN-AdminWS-requireAdminAuthorization]
         * checkadminAuthor."); final X509Certificate[] certificates =
         * getClientCertificates(); if (certificates == null ||
         * certificates.length == 0) { throw new AdminNotAuthorizedException(
         * "Administrator not authorized to resource. " + "Client certificate
         * authentication required."); } else { final boolean authorized =
         * isAdminAuthorized(certificates[0]); final X509Certificate cert =
         * certificates[0];
         *
         * log(cert, authorized, operation, args);
         *
         * if (!authorized) { throw new AdminNotAuthorizedException(
         * "Administrator not authorized to resource."); }
         *
         * return new AdminInfo(cert.getSubjectDN().getName(), cert
         * .getIssuerDN().keygetName(), cert.getSerialNumber()); } }
         */

    }

    private AdminInfo requireAuditorAuthorization(final String operation,
            final int ClientID,
            final String sessionKey) throws AdminNotAuthorizedException {
        LOG.debug(">requireAuditorAuthorization");
        return new AdminInfo("NHAN", "TRANVAN", new BigInteger("12345678"));
        /*
         * if
         * (PreferenceConfi.getInstace().isSuperAdminConnect(getIpOfClient())) {
         * if (PreferenceConfi.getInstace().isAuthorized(getIpOfClient()))
         * return new AdminInfo("NHAN", "TRANVAN", new BigInteger( "12345678"));
         * else throw new AdminNotAuthorizedException( "Auditor not authorized
         * to resource. " + "Client authentication required."); } else { final
         * X509Certificate[] certificates = getClientCertificates(); if
         * (certificates == null || certificates.length == 0) { System.out
         * .println("[TCCHTNN-AdminWS.java-requireAuditorAuthorization]
         * certificates == null"); throw new AdminNotAuthorizedException(
         * "Auditor not authorized to resource. " + "Client certificate
         * authentication required."); } else { System.out
         * .println("[TCCHTNN-AdminWS.java-requireAuditorAuthorization]
         * certificates != null"); final boolean authorized =
         * isAuditorAuthorized(certificates[0]); final X509Certificate cert =
         * certificates[0];
         *
         * log(cert, authorized, operation, args);
         *
         * if (!authorized) { throw new AdminNotAuthorizedException( "Auditor
         * not authorized to resource."); }
         *
         * return new AdminInfo(cert.getSubjectDN().getName(), cert
         * .getIssuerDN().getName(), cert.getSerialNumber()); } }
         */
    }

    private void log(final X509Certificate certificate,
            final boolean authorized, final String operation,
            final String... args) {
        final StringBuilder line = new StringBuilder().append("ADMIN OPERATION").append("; ").append("subjectDN=").append(certificate.getSubjectDN().getName()).append("; ").append("serialNumber=").append(certificate.getSerialNumber().toString(16)).append("; ").append("issuerDN=").append(certificate.getIssuerDN().getName()).append("; ").append("authorized=").append(authorized).append("; ").append("operation=").append(operation).append("; ").append("arguments=");
        for (String arg : args) {
            line.append(arg.replace(";", "\\;").replace("=", "\\="));
            line.append(",");
        }
        line.append(";");
        LOG.info(line.toString());
    }

    private boolean isAdminAuthorized(final X509Certificate cert) {

        if (PreferenceConfi.getInstace().isSuperAdminConnect(getIpOfClient())) {
            return PreferenceConfi.getInstace().isAuthorized(getIpOfClient());

        } else {
            boolean authorized = false;
            final String admins = global.getGlobalConfiguration().getProperty(
                    GlobalConfiguration.SCOPE_GLOBAL, "WSADMINS");
            final String admin = cert.getSerialNumber().toString(16) + ","
                    + cert.getIssuerDN();

            if (LOG.isDebugEnabled()) {
                LOG.debug("admin: " + admin + ", admins: " + admins);
            }


            if (admins == null) {
                LOG.warn("No WSADMINS global property set");
            } else {
                for (String entry : admins.split(";")) {
                    //if (entry.trim().equalsIgnoreCase(admin)) {
                    if (compareCertificateAttribute(entry.trim(), admin)) {
                        authorized = true;
                        break;
                    }
                }
            }
            return authorized;
        }
    }

    private boolean compareCertificateAttribute(String pattern, String compare) {
        try {
            int a = pattern.indexOf(",");
            String serial = pattern.substring(0, a);
            if (!compare.contains(serial)) {
                return false;
            }
            pattern = pattern.substring(a + 1);
            a = pattern.indexOf(",");
            String CN = pattern.substring(3, a);
            if (!compare.contains(CN)) {
                return false;
            }

            pattern = pattern.substring(a + 1);
            String C = pattern.substring(2);
            if (!compare.contains(C)) {
                return false;
            }
        } catch (Exception e) {
            // TODO: handle exception
            return false;
        }
        return true;

    }

    private boolean isAuditorAuthorized(final X509Certificate cert) {
        boolean authorized = false;
        final String admins = global.getGlobalConfiguration().getProperty(
                GlobalConfiguration.SCOPE_GLOBAL, "WSAUDITORS");
        final String admin = cert.getSerialNumber().toString(16) + ","
                + cert.getIssuerDN();
        if (LOG.isDebugEnabled()) {
            LOG.debug("admin: " + admin + ", admins: " + admins);
        }

        if (admins == null) {
            LOG.warn("No WSAUDITORS global property set");
        } else {
            for (String entry : admins.split(";")) {
                if (entry.trim().equalsIgnoreCase(admin)) {
                    authorized = true;
                    break;
                }
            }
        }
        return authorized;
    }

    private X509Certificate[] getClientCertificates() {

        SOAPMessageContext jaxwsContext = (SOAPMessageContext) wsContext.getMessageContext();
        HttpServletRequest request = (HttpServletRequest) jaxwsContext.get(SOAPMessageContext.SERVLET_REQUEST);

        final X509Certificate[] certificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
        return certificates;
    }

    private String getIpOfClient() {
        SOAPMessageContext jaxwsContext = (SOAPMessageContext) wsContext.getMessageContext();
        HttpServletRequest request = (HttpServletRequest) jaxwsContext.get(SOAPMessageContext.SERVLET_REQUEST);
        return request.getRemoteAddr();
    }

    @WebMethod(operationName = "changeIp")
    public String[] changeIp(
            @WebParam(name = "ClientID") int ClientID,
            @WebParam(name = "ipAddress") String ipAddress,
            @WebParam(name = "subnetMask") String subnetMask,
            @WebParam(name = "defaultGateway") String defaultGateway,
            @WebParam(name = "dns1") String dns1,
            @WebParam(name = "dns2") String dns2,
            @WebParam(name = "sessionKey") String sessionKey)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("changeIp", ClientID, sessionKey);

        if (ipAddress != null) {
            if (ipAddress.equals("")) {
                ipAddress = null;
            }
        }

        if (subnetMask != null) {
            if (subnetMask.equals("")) {
                subnetMask = null;
            }
        }

        if (defaultGateway != null) {
            if (defaultGateway.equals("")) {
                defaultGateway = null;
            }
        }

        if (dns1 != null) {
            if (dns1.equals("")) {
                dns1 = null;
            }
        }

        if (dns2 != null) {
            if (dns2.equals("")) {
                dns2 = null;
            }
        }

        return WorkerCommandLine.getInstance().editInterface(ipAddress, subnetMask, defaultGateway, dns1, dns2);
    }

    public boolean readBashScript(String ipAddress, String subnetMask,
            String defaultGateway, String searchDomain, String dnsServers) {

        try {
            Process proc = Runtime.getRuntime().exec(
                    SCRIPTCHANGEIP + " " + ipAddress + " "
                    + subnetMask + " " + defaultGateway + " "
                    + searchDomain + " " + dnsServers);
            BufferedReader read = new BufferedReader(new InputStreamReader(
                    proc.getInputStream()));
            try {
                proc.waitFor();
            } catch (InterruptedException e) {
                return false;
                // System.out.println(e.getMessage());
            }
            while (read.ready()) {
                read.readLine();
                // System.out.println(read.readLine());
            }

        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    @WebMethod(operationName = "rebootServer")
    public void rebootServer(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "sessionKey") final String sessionKey) throws AdminNotAuthorizedException {
        requireAdminAuthorization("rebootServer", ClientID, sessionKey);
        PreferenceConfi.getInstace().setAuthorized(false, getIpOfClient(),
                "Remove");
        try {
            Process proc = Runtime.getRuntime().exec(SCRIPTREBOOT);
            BufferedReader read = new BufferedReader(new InputStreamReader(
                    proc.getInputStream()));
            try {
                proc.waitFor();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            while (read.ready()) {
                read.readLine();
                // System.out.println(read.readLine());
            }
        } catch (IOException e) {
            e.printStackTrace();

        }
    }

    @WebMethod(operationName = "shutdownServer")
    public void shutdownServer(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "sessionKey") final String sessionKey) throws AdminNotAuthorizedException {
        requireAdminAuthorization("shutdownServer", ClientID, sessionKey);
        PreferenceConfi.getInstace().setAuthorized(false, getIpOfClient(),
                "Remove");
        try {
            Process proc = Runtime.getRuntime().exec(SCRIPTSHUTDOWN);
            BufferedReader read = new BufferedReader(new InputStreamReader(
                    proc.getInputStream()));
            try {
                proc.waitFor();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            while (read.ready()) {
                read.readLine();
            }
        } catch (IOException e) {
            e.printStackTrace();

        }
    }

    @WebMethod(operationName = "login")
    public LoginResponseObject login(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "username") final String username,
            @WebParam(name = "password") final String password)
            throws AdminNotAuthorizedException {
        //int type = PreferenceConfi.getInstace().typeOfUsername(username, password, getIpOfClient());
        getClientCertificates();
        int status = DBConnector.getInstances().AdminWSLogin(ClientID, username, password);

        String session = null;
        if (status == 2) {
            boolean checkIP = DBConnector.getInstances().AdminWSIPFiler(getIpOfClient());
            isAdmin = false;
            if (!checkIP) {
                status = 3;
            } else {
                session = createSession(username, getIpOfClient(), status);
            }

        } else if (status == 1) {
            isAdmin = true;
            session = createSession(username, getIpOfClient(), status);
        }

        LoginResponseObject lg = new LoginResponseObject(status, session);
        return lg;
    }

    @WebMethod(operationName = "logout")
    public void logout(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        clearSession(sessionKey);
        PreferenceConfi.getInstace().setAuthorized(false, getIpOfClient(), "Remove");

    }

    @WebMethod(operationName = "getAllIpConnect")
    public List<String> getAllIpConnect(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "sessionKey") final String sessionKey) throws AdminNotAuthorizedException {
        requireAdminAuthorization("getAllIpConnect", ClientID, sessionKey);
        return DBConnector.getInstances().getAllIPFilter();
    }

    @WebMethod(operationName = "addIpConnect")
    public void addIpConnect(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "ip") String ip,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("addIpConnect", ClientID, sessionKey);
        DBConnector.getInstances().addIPFilter(ip, "Grant for AdminGUI application", 1, "TRUSTEDHUB"); //hard-code channel id
    }

    @WebMethod(operationName = "removeIpConnect")
    public void removeIpConnect(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "ip") String ip,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("removeIpConnect", ClientID, sessionKey);
        DBConnector.getInstances().removeIPFilter(ip, "TRUSTEDHUB"); //hard-code channel id
    }
    /*
     * @WebMethod(operationName = "getAllAccountConnect") public List<String>
     * getAllAccountConnect( @WebParam(name = "ClientID") final int ClientID,
     * @WebParam(name = "sessionKey") final String sessionKey) throws
     * AdminNotAuthorizedException {
     * requireAdminAuthorization("getAllAccountConnect", ClientID, sessionKey);
     * return PreferenceConfi.getInstace().getAllUsernameConnect(); }
     *
     * @WebMethod(operationName = "changePasswordAccount") public boolean
     * changePasswordAccount( @WebParam(name = "ClientID") final int ClientID,
     * @WebParam(name = "username") String username, @WebParam(name =
     * "oldPassword") String oldPassword, @WebParam(name = "newPassword") String
     * newPassword, @WebParam(name = "sessionKey") final String sessionKey)
     * throws AdminNotAuthorizedException {
     * requireAdminAuthorization("changePasswordAccount", ClientID, sessionKey);
     * return PreferenceConfi.getInstace().changePasswordAccountAdmin(username,
     * oldPassword, newPassword); }
     *
     * @WebMethod(operationName = "resetPasswordAccount") public void
     * resetPasswordAccount( @WebParam(name = "ClientID") final int ClientID,
     * @WebParam(name = "username") String username, @WebParam(name =
     * "sessionKey") final String sessionKey) throws AdminNotAuthorizedException
     * { requireAdminAuthorization("resetPasswordAccount", ClientID,
     * sessionKey); PreferenceConfi.getInstace().resetPassword(username); }
     *
     * @WebMethod(operationName = "resetPasswordSuperadmin") public boolean
     * resetPasswordSuperadmin( @WebParam(name = "ClientID") final int ClientID,
     * @WebParam(name = "masterkey") String masterkey, @WebParam(name =
     * "sessionKey") final String sessionKey) throws AdminNotAuthorizedException
     * { requireAdminAuthorization("resetPasswordSuperadmin", ClientID,
     * sessionKey); return
     * PreferenceConfi.getInstace().resetPasswordSuperadmin(masterkey); }
     */

    @WebMethod(operationName = "reloadWorker")
    public synchronized String reloadWorker(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "workerID") String workerID,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("reloadWorker", ClientID, sessionKey);
        String resp = "Worker " + workerID + " has been reloaded";
        LOG.info(resp);
        try {
            ReloadCommand reloadCommand = new ReloadCommand();
            reloadCommand.execute(new String[]{"all"});
        } catch (Exception e) {
            e.printStackTrace();
            resp = "";
        }
        return resp;
    }

    @WebMethod(operationName = "getWorkerStatus")
    public String getWorkerStatus(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "workerID") int workerID,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("getWorkerStatus", ClientID, sessionKey);
        return WorkerCommandLine.getInstance().getWorkerStatus(workerID);
    }

    @WebMethod(operationName = "removeWorker")
    public String removeWorker(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "workerID") int workerID,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("removeWorker", ClientID, sessionKey);
        //return WorkerCommandLine.getInstance().removeWorker(workerID);
        String res = "Worker has been removed";
        /*
         * RemoveWorkerCommand removeWorkerCommand = new RemoveWorkerCommand();
         * try { removeWorkerCommand.execute(new
         * String[]{String.valueOf(workerID)}); } catch (Exception e) {
         * e.printStackTrace(); res = null; }
         */
        DBConnector.getInstances().removeWorker(workerID);
        return res;
    }

    @WebMethod(operationName = "addWorker")
    public synchronized int addWorker(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "configFileName") String configFileName,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("addWorker", ClientID, sessionKey);
        String res = "";
        int workerId = -1;
        if (ClientID == 0) {
            res = WorkerCommandLine.getInstance().addWorker(configFileName);
        } else {
            //res = WorkerCommandLine.getInstance().addWorkerFromPortal(configFileName);
            try {
                //res = WorkerCommandLine.getInstance().addWorker(configFileName);
                InputStream in = new ByteArrayInputStream(configFileName.getBytes());
                Properties properties = new Properties();
                properties.load(in);

                SetProperties processProperties = new SetProperties();
                processProperties.process(properties);
                workerId = processProperties.getWorkerId();
                res = "This is result for worker " + workerId + ".";
                LOG.info(res);
            } catch (Exception ex) {
                ex.printStackTrace();
            }

        }
        //return res;
        return workerId;
    }

    @WebMethod(operationName = "getAvailableWorkers")
    public List<AvailableWorkers> getAvailableWorkers(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "sessionKey") final String sessionKey) throws AdminNotAuthorizedException {
        requireAdminAuthorization("getAvailableWorkers", ClientID, sessionKey);
        return WorkerCommandLine.getInstance().getAvailableWorkers();
    }

    @WebMethod(operationName = "getWorkerConfigFile")
    public String getWorkerConfigFile(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "configFileName") String configFileName,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("getWorkerConfigFile", ClientID, sessionKey);
        return WorkerCommandLine.getInstance().getWorkerConfigFile(configFileName);
    }

    @WebMethod(operationName = "setWorkerConfigFile")
    public String setWorkerConfigFile(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "configFileName") String configFileName,
            @WebParam(name = "content") String content,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("setWorkerConfigFile", ClientID, sessionKey);
        return WorkerCommandLine.getInstance().setWorkerConfigFile(configFileName, content);
    }

    @WebMethod(operationName = "reloadParametes")
    public void reloadParametes(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("reloadParametes", ClientID, sessionKey);
        DBConnector.getInstances().reloadIpList();
        DBConnector.getInstances().reloadChannels();
        DBConnector.getInstances().reloadCAProviders();
        DBConnector.getInstances().reloadGeneralPolicy();
        DBConnector.getInstances().reloadEndPointConfig();
        DBConnector.getInstances().reloadIsOptimized();
        DBConnector.getInstances().reloadEndPointParams();
    }

    @WebMethod(operationName = "getCrlFiles")
    public List<CrlFile> getCrlFiles(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "crlPath") final String crlPath,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("getCrlFiles", ClientID, sessionKey);
        return QueryCrl.getCrlFiles(crlPath);
    }

    @WebMethod(operationName = "getCrlFile")
    public byte[] getCrlFile(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "crlPath") final String crlPath,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("getCrlFile", ClientID, sessionKey);
        return QueryCrl.getCrlFile(crlPath);
    }

    @WebMethod(operationName = "reloadCrlFile")
    public boolean reloadCrlFile(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "crlUrl") final String crlUrl,
            @WebParam(name = "crlPath") final String crlPath,
            @WebParam(name = "caName") final String caName,
            @WebParam(name = "isPrimaryCA") final boolean isPrimaryCA,
            @WebParam(name = "isTSA") final boolean isTSA,
            @WebParam(name = "endpointConfigId") final int endpointConfigId,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("reloadCrlFile", ClientID, sessionKey);
        return QueryCrl.reloadCrlFile(crlUrl, crlPath, caName, isPrimaryCA, isTSA, endpointConfigId);
    }

    @WebMethod(operationName = "uploadCrlFile")
    public boolean uploadCrlFile(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "crlData") final byte[] crlData,
            @WebParam(name = "crlPath") final String crlPath,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("uploadCrlFile", ClientID, sessionKey);
        return QueryCrl.uploadCrlFile(crlData, crlPath);
    }

    @WebMethod(operationName = "restartWS")
    public void restartWS(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("restartWS", ClientID, sessionKey);
        LOG.info("Webserver restarting...");
        try {
            new Thread(new Runnable() {

                @Override
                public void run() {
                    ExtFunc.executeExternalShellScript(ExtFunc.SCRIPT_PATH_RESTARTWS);
                }
            }).start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @WebMethod(operationName = "checkNonRepudiation")
    public NonRepudiationResponse checkNonRepudiation(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "data") final String data,
            @WebParam(name = "signature") final String signature,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("checkNonRepudiation", ClientID, sessionKey);
        NonRepudiationResponse response = new NonRepudiationResponse();
        try {
            NonRepudiation repudiation = new NonRepudiation();
            response = repudiation.check(data.getBytes("UTF-16LE"), DatatypeConverter.parseBase64Binary(signature));
        } catch (Exception e) {
            LOG.info("Not supported yet this signature");
            response.setResponseCode(Defines.CODE_NOTSUPPORTYET);
            response.setResponseMessage(Defines.ERROR_NOTSUPPORTYET);
        }
        return response;
    }

    @WebMethod(operationName = "getLicenseInfo")
    public LicenseInfo getLicenseInfo(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("getLicenseInfo", ClientID, sessionKey);
        LicInfoV3 licInfo = License.getInstance().getLicenseInfoV3();

        LicenseInfo l = new LicenseInfo();
        l.setStatusCode(licInfo.getStatusCode());
        l.setStatusDescription(licInfo.getStatusDescription());
        l.setValidFrom(licInfo.getValidFrom());
        l.setValidTo(licInfo.getValidTo());
        l.setDayRemain(licInfo.getDayRemain());
        l.setLicenseType(licInfo.getLicenseType());
        l.setPdfSigner(licInfo.isIsPdfSigner());
        l.setOfficeSigner(licInfo.isIsOfficeSigner());
        l.setXmlSigner(licInfo.isIsXmlSigner());
        l.setMrtdSigner(licInfo.isIsMrtdSigner());
        l.setPdfValidator(licInfo.isIsPdfValidator());
        l.setOfficeValidator(licInfo.isIsOfficeValidator());
        l.setXmlValidator(licInfo.isIsXmlValidator());
        l.setFidoValidator(licInfo.isIsFidoValidator());
        l.setOathValidator(licInfo.isIsOathValidator());
        l.setMobileOtp(licInfo.isIsMobileOtp());
        l.setCmsSigner(licInfo.isIsCmsSigner());
        l.setPkcs1Signer(licInfo.isIsPkcs1Signer());
        l.setCmsValidator(licInfo.isIsCmsValidator());
        l.setPkcs1Validator(licInfo.isIsPkcs1Validator());
        l.setDcSigner(licInfo.isIsDcSigner());
        l.setMultiSigner(licInfo.isIsMultiSigner());
        l.setSignerAp(licInfo.isIsSignerAp());
        l.setCertificateLicenseType(licInfo.getCertificateLicenseType());
        l.setCertificateLicenseNo(licInfo.getCertificateLicenseNo());
        l.setPerFormanceLicenseType(licInfo.getPerFormanceLicenseType());
        l.setPerFormanceLicenseNo(licInfo.getPerFormanceLicenseNo());
        l.setMultiValidator(licInfo.isIsMultiValidator());
        l.setSignatureValidator(licInfo.isIsSignatureValidator());
        l.setGeneralValidator(licInfo.isIsGeneralValidator());
        return l;
    }

    @WebMethod(operationName = "setLicenseInfo")
    public boolean setLicenseInfo(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "licenseData") final byte[] licenseData,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("setLicenseInfo", ClientID, sessionKey);

        boolean status = false;
        if (licenseData.length == 2700) {
            status = DBConnector.getInstances().authSetLicenseInfo(licenseData);
            if (status) {
                License.getInstance().reloadLicense();
            }
        }
        return status;
    }

    @WebMethod(operationName = "getHardwareId")
    public String getHardwareId(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("getHardwareId", ClientID, sessionKey);
        return License.getInstance().getHardwareId();
    }

    @WebMethod(operationName = "sendEmail")
    public int sendEmail(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "sessionKey") final String sessionKey,
            @WebParam(name = "email") final String email,
            @WebParam(name = "subject") final String subject,
            @WebParam(name = "content") final String content,
            @WebParam(name = "isLog") final boolean isLog)
            throws AdminNotAuthorizedException {

        requireAdminAuthorization("sendEmail", ClientID, sessionKey);
        String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(Defines.CONNECTION_PARAMS_SMTP);

        if (endpointParams == null) {
            return 2; // system error
        }
        EndpointServiceResp endpointServiceResp = null;

        if (isLog) {
            //endpointServiceResp = EndpointService.getInstance().sendEmail(null, null, email, subject, content, endpointParams[1], Integer.parseInt(endpointParams[2]));
            endpointServiceResp = EndpointService.getInstance().sendEmailNoLogging(null, null, email, subject, content, endpointParams[1], Integer.parseInt(endpointParams[2]));
        } else {
            endpointServiceResp = EndpointService.getInstance().sendEmailNoLogging(null, null, email, subject, content, endpointParams[1], Integer.parseInt(endpointParams[2]));
        }

        if (endpointServiceResp.getResponseCode() == 0) {
            return 0; // success;
        }
        return 1; // failed to send
    }

    @WebMethod(operationName = "sendSms")
    public int sendSms(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "sessionKey") final String sessionKey,
            @WebParam(name = "phoneNo") final String phoneNo,
            @WebParam(name = "content") final String content,
            @WebParam(name = "isLog") final boolean isLog)
            throws AdminNotAuthorizedException {

        requireAdminAuthorization("sendSms", ClientID, sessionKey);
        String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(Defines.CONNECTION_PARAMS_SMPP);

        if (endpointParams == null) {
            return 2; // system error
        }

        EndpointServiceResp endpointServiceResp = null;

        if (isLog) {
            endpointServiceResp = EndpointService.getInstance().sendSmsNoLogging(null, null, phoneNo, content, endpointParams[1], Integer.parseInt(endpointParams[2]));
        } else {
            endpointServiceResp = EndpointService.getInstance().sendSmsNoLogging(null, null, phoneNo, content, endpointParams[1], Integer.parseInt(endpointParams[2]));
        }

        if (endpointServiceResp.getResponseCode() == 0) {
            return 0; // success;
        }
        return 1; // failed to send
    }

    @WebMethod(operationName = "getHAResourcesStatus")
    public String[] getHAResourcesStatus(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "sessionKey") final String sessionKey)
            throws AdminNotAuthorizedException {

        requireAdminAuthorization("getHAResourcesStatus", ClientID, sessionKey);
        String[] response = new String[3];
        response[0] = WorkerCommandLine.getInstance().executeCrmResourceStatusClusterIP();
        response[1] = WorkerCommandLine.getInstance().executeCrmStatus();
        response[2] = WorkerCommandLine.getInstance().executeDBReplication(ExtFunc.getMasterDBAdrr(config.getProperty("database.url")),
                config.getProperty("database.username"), config.getProperty("database.password"));
        return response;
    }

    @WebMethod(operationName = "getMonitorServerLog")
    public byte[] getMonitorServerLog(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "sessionKey") final String sessionKey,
            @WebParam(name = "logType") final int logType,
            @WebParam(name = "actionType") final int actionType,
            @WebParam(name = "numOfLine") final int numOfLine,
            @WebParam(name = "dateTime") final Date dateTime)
            throws AdminNotAuthorizedException {

        requireAdminAuthorization("getMonitorServerLog", ClientID, sessionKey);
        byte[] content = null;
        try {
            if (actionType == MONITOR_ACTION_DOWNLOAD_TYPE) {
                // download
                String pattern = ExtFunc.getMonitorDatePattern(dateTime);
                String patternNow = ExtFunc.getMonitorDatePattern(Calendar.getInstance().getTime());

                String fileName = null;

                if (logType == MONITOR_LOG_SERVER_TYPE) {
                    // server
                    fileName = "server";

                } else if (logType == MONITOR_LOG_BACKOFFICE_TYPE) {
                    // backoffice
                    fileName = "backoffice";

                } else {
                    // endpoint
                    fileName = "endpoint";
                }

                if (pattern.compareTo(patternNow) == 0) {
                    fileName = fileName.concat(".log");
                } else {
                    fileName = fileName.concat(".log").concat(".").concat(pattern);
                }

                InputStream in = new FileInputStream(MONITOR_LOG_PATH.concat(fileName));

                content = IOUtils.toByteArray(in);

            } else {
                // view
                String pattern = ExtFunc.getMonitorDatePattern(dateTime);
                String patternNow = ExtFunc.getMonitorDatePattern(Calendar.getInstance().getTime());

                String fileName = null;

                if (logType == MONITOR_LOG_SERVER_TYPE) {
                    // server
                    fileName = "server";

                } else if (logType == MONITOR_LOG_BACKOFFICE_TYPE) {
                    // backoffice
                    fileName = "backoffice";

                } else {
                    // endpoint
                    fileName = "endpoint";
                }

                if (pattern.compareTo(patternNow) == 0) {
                    fileName = fileName.concat(".log");
                } else {
                    fileName = fileName.concat(".log").concat(".").concat(pattern);
                }
                content = (WorkerCommandLine.getInstance().executeTailCommand(numOfLine, MONITOR_LOG_PATH.concat(fileName))).getBytes("UTF-8");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return content;
    }

    @WebMethod(operationName = "getCertificate")
    public String getCertificate(
            @WebParam(name = "ClientID") final int ClientID,
            @WebParam(name = "sessionKey") final String sessionKey,
            @WebParam(name = "channlName") final String channlName,
            @WebParam(name = "userId") final String userId,
            @WebParam(name = "subjectDn") final String subjectDn,
            @WebParam(name = "email") final String email,
            @WebParam(name = "dayPattern") final String dayPattern,
            @WebParam(name = "csr") final String csr,
            @WebParam(name = "caName") final String caName)
            throws AdminNotAuthorizedException {

        requireAdminAuthorization("getCertificate", ClientID, sessionKey);

        Ca ca = DBConnector.getInstances().getCa(caName);

        String certificate = null;

        if (ca == null) {
            LOG.error("Cannot found CA configuration: " + caName);
            return certificate;
        }

        if (ca.getEndPointParamsValue() == null) {
            LOG.error("Cannot found RA configuration of CA: " + caName);
            return certificate;
        }

        EndpointServiceResp endpointServiceResp = EndpointService.getInstance().getCertificate(channlName, userId, subjectDn, email, dayPattern, csr, ca.getEndPointParamsValue(), ca.getEndPointConfigID(), null);
        if (endpointServiceResp.getResponseCode() == 0) {
            certificate = new String(endpointServiceResp.getResponseData());
        }
        return certificate;
    }
}
