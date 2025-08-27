package org.signserver.common.util;

public class Defines {

    public static final String PATTERN_BOLD_OPEN = "{B}";
    public static final String PATTERN_BOLD_CLOSE = "{/B}";
    public static final String PATTERN_NEW_LINE = "{BR}";
    public static final String PATTERN_SUBJECT_DN = "{SUBJECT_DN}";
    public static final String PATTERN_ISSUER_DN = "{ISSUER_DN}";
    public static final String PATTERN_VALID_FROM = "{VALID_FROM}";
    public static final String PATTERN_VALID_TO = "{VALID_TO}";
    public static final String PATTERN_USERNAME = "{USERNAME}";
    public static final String PATTERN_PASSWORD = "{PIN_CODE}";
    public static final String PATTERN_SERIAL_NUMBER = "{SERIAL_NUMBER}";
    public static String MSSP_SYMBOL_VC = "%%VC%%";
    public static String REQUEST_TYPE_FORCE_ACTI = "ForceActivation";
    public static String USER_SYSTEM = "SYSTEM";
    public static String _CHANNEL = "Channel";
    public static String _USER = "User";
    public static String _ID = "ExternalBillCode";
    public static String _TRUSTEDHUBTRANSID = "TrustedHubTransactionId";
    public static String _EXPIRATION = "Expiration";
    public static String _ISOTPSMS = "IsOTPSMS";
    public static String _OTPSMS = "OTPSMS";
    public static String _ISOTPEMAIL = "IsOTPEmail";
    public static String _OTPEMAIL = "OTPEmail";
    public static String _ISOTPSOFTWARE = "IsOTPSoftware";
    public static String _ISOTPHARDWARE = "IsOTPHardware";
    public static String _OTPHARDWARE = "OTPHardware";
    public static String _ISPKI = "IsTPKI";
    public static String _CERTIFICATE = "TCertificate";
    public static String _TTHUMBPRINT = "TPKIThumbPrint";
    public static String _ISLCDPKI = "IsLPKI";
    public static String _LCDCERTIFICATE = "LCertificate";
    public static String _ISPKISIM = "IsWPKI";
    public static String _WCERTIFICATE = "WCertificate";
    public static String _PKISIM = "PKISim";
    public static String _DISPLAYMESSAGE = "DisplayMessage";
    public static String _PKISIMVENDOR = "PKISimVendor";
    public static String _ALGORITHM = "HashAlgorithm";
    public static String _MESSAGEMODE = "MessageMode";
    public static String _ISHASHED = "IsHashed";
    public static String _SIGNATUREFORMAT = "SignatureFormat";
    public static String _REQUESTID = "RequestID";
    public static String _TRANSACTIONID = "TransactionID";
    public static String _THUMBPRINT = "Thumbprint";
    public static String _STREAMDATAPATH = "StreamDataPath";
    public static String _STREAMSIGNPATH = "StreamSignPath";
    public static String _TRANSACTIONCODE = "TransactionCode";
    public static String _SIGNATUREMETHOD = "SignatureMethod";
    public static String _PDFPASSWORD = "PdfPassword";
    public static String _pDFPASSWORD = "pdfPassword";
    public static String _XPATHNAMESPACE = "XpathNamespace";
    public static String _SIGNINGTIMEIDENTIFIER = "SigningTimeIdentifier";
    public static String _SIGNINGTIMEPATTERN = "SigningTimePattern";
    public static String _SIGNERINFOPREFIX = "SignerInfoPrefix";
    public static String _DATETIMEPREFIX = "DateTimePrefix";
    public static String _SIGNREASONPREFIX = "SignReasonPrefix";
    public static String _LOCATIONPREFIX = "LocationPrefix";
    public static String _SHOWSIGNERINFOONLY = "ShowSignerInfoOnly";
    public static String _SHOWDATETIMEONLY = "ShowDateTimeOnly";
    public static String _IMAGEANDTEXT = "ImageAndText";
    public static String _TEXTCOLOR = "TextColor";
    public static String _TEXTSTATUSPOSITION = "TextStatusPosition";
    public static String _LOCATION = "Location";
    
    public static String _SHOWTITLE = "ShowTitle"; 
    public static String _TITLEPREFIX = "TitlePrefix";
    public static String _TITLE = "Title";
    public static String _SHOWORGANIZATION = "ShowOrganization";
    public static String _ORGANIZATIONPREFIX = "OrganizationPrefix";
    public static String _ORGANIZATION = "Organization";
    public static String _SHOWORGANIZATIONUNIT = "ShowOrganizationUnit";
    public static String _ORGANIZATIONUNITPREFIX = "OrganizationUnitPrefix";
    public static String _ORGANIZATIONUNIT = "OrganizationUnit";
    public static String _SHOWSIGNINGID = "ShowSigningID";
    public static String _SIGNINGIDPREFIX = "SigningIDPrefix";
    public static String _SIGNINGID = "SigningID";
    public static String _FONTNAME = "FontName";
    
    public static String _SIGNINGTIMEID = "SigningTimeID";
    public static String _SIGNINGTIMEOBJECTID = "SigningTimeObjectID";
    public static String _SIGNATUREPROPERTIESOBJECTID = "SignaturePropertiesObjectID";
    public static String _SIGNINGTIMEXMLNS = "SigningTimeXMLNS";
    public static String _SIGNATUREPROPERTIESXMLNS = "SignaturePropertiesXMLNS";
    public static String _INCLUDEKEYINFO = "IncludeKeyInfo";
    public static String _TAGSIGNINGTIME = "TagSigningTime";
    public static String _INCLUDESIGNINGTIME = "IncludeSigningTime";
    public static String _TEXTDIRECTION = "TextDirection";
    public static String _LOCKAFTERSIGNING = "LockAfterSigning";
    public static String _DATETIMEFORMAT = "DatetimeFormat";
    public static String _TIMESTAMPFORMAT = "TimestampFormat";
    public static String _SHOWSIGNERINFO = "ShowSignerInfo";
    public static String _SHOWDATETIME = "ShowDateTime";
    public static String _SHOWREASON = "ShowReason";
    public static String _SHOWLOCATION = "ShowLocation";
    public static String _SIGNINGTIME = "SigningTime";
    public static String _TSA_PROVIDER = "TSAProvider";
    public static String _ISPKISIGN = "IsSPKI";
    public static String _WORKERNAMESIGNING = "WorkerNameSigning";
    public static String _SPKIEMAIL = "SPKIEmail";
    public static String _SPKISMS = "SPKISMS";
    public static String _SKEYNAME = "SKeyName";
    public static String _SKEYTYPE = "SKeyType";
    public static String _P11INFO = "P11Info";
    public static String _P11INFOLEVEL = "P11InfoLevel";
    public static String _ISWS = "IsWS";
    public static String _SPKICERTTYPE = "SPKICertType";
    public static String _SPKICERTPROVIDER = "SPKICertProvider";
    public static String _SPKIDN = "SPKIDN";
    public static String _SPKICERTPROFILE = "SPKICertProfile";
    public static String _SPKICERT = "SCertificate";
    public static String _ISINSTALLCERT = "IsInstallSCertificate";
    public static String _CURRENTPW = "CurrentPassword";
    public static String _NEWPW = "NewPassword";
    public static String _PASSWORD = "Password";
    public static String _SETRECOVERY = "SetRecovery";
    public static String _ISREGISTRED = "IsRegistered";
    public static String _SIGNDATAID = "SignDataID";
    public static String _ATTRIBUTENAME = "AttributeName";
    public static String _XMLPROFILE = "XmlProfile";
    public static String _SIGNATUREID = "SignatureID";
    public static String _XPATHEXPRESSION = "XPathExpression";
    public static String _CANONICALIZATIONMETHOD = "CanonicalizationMethod";
    public static String _SIGNATURELOCATION = "SignatureLocation";
    public static String _OMITXMLDECLARATION = "OmitXmlDeclaration";
    public static String _HIDDENPASSWORD = "********";
    public static String _BASE64DATA = "Base64Data";
    public static String _SERIALNUMBER = "SerialNumber";
    public static String _BranchID = "BranchID";
    public static String _WORKERNAME = "WorkerName";
    public static String _METADATA = "MetaData";
    public static String _BASE64FILE = "Base64File";
    public static String _SIGNEDDATA = "SignedData";
    public static String _ENCODING = "Encoding";
    public static String _CAPICOMSIGNATURE = "CapicomSignature";
    public static String _SIGNATURE = "Signature";
    public static String _FILETYPE = "FileType";
    public static String _ENDPOINTVALUE = "EndpointValue";
    public static String _ENDPOINTCONFIGID = "EndpointConfigId";
    public static String _DATATOSIGN = "DataToSign";
    public static String _ACTION = "Action";
    public static String _AGREEMENTSTATUS = "AgreementStatus";
    public static String _ISUNBLOCKOTP = "IsUnblockOTP";
    public static String _ISEXTEND = "IsExtend";
    public static String _METHOD = "Method";
    public static String _REQUESTTYPE = "RequestType";
    public static String _OTPMETHOD = "OTPMethod";
    public static String _SUBJECT = "Subject";
    public static String _TRANSACTIONDATA = "TransactionData";
    public static String _BILLCODE = "BillCode";
    public static String _OTP = "OTP";
    public static String _NEXTOTP = "NextOTP";
    public static String _FILEID = "FileId";
    public static String _FILENAME = "FileName";
    public static String _MIMETYPE = "MimeType";
    public static String _DISPLAYVALUE = "DisplayValue";
    public static String _EXTERNALSTORAGE = "ExternalStorage";
    public static String _URI = "URI";
    public static String _URINODE = "URINode";
    public static String _SIGNATUREPREFIX = "SignaturePrefix";
    public static String _SIGNREASON = "SignReason";
    public static String _COORDINATE = "Coordinate";
    public static String _PAGENO = "PageNo";
    public static String _VISIBLESIGNATURE = "VisibleSignature";
    public static String _VISUALSTATUS = "VisualStatus";
    public static String _SIGNATUREIMAGE = "SignatureImage";
    public static String _CITIZENID = "CitizenID";
    public static String _APPLICATIONID = "ApplicationID";
    public static String _USERHANDLE = "UserHandle";
    public static String _ISU2F = "IsU2F";
    public static String _APPID = "AppId";
    public static String _REGISTRATIONDATA = "RegistrationData";
    public static String _CLIENTDATA = "ClientData";
    public static String _SESSIONID = "SessionId";
    public static String _CHALLENGE = "Challenge";
    public static String _SIGNATUREDATA = "SignatureData";
    public static String _AUTHENCODE = "AuthenticationCode";
    public static String DCREQUEST = "DCRequest";
    public static String DCRESPONE = "DCResponse";
    public static String PKCS1SIGREQUEST = "SignatureRequest";
    public static String PKCS1CERREQUEST = "CertificateRequest";
    public static String SIGNERAP_SIGREG = "SignatureRequest";
    public static String SIGNERAP_STAREG = "SignatureResponse";
    public static String SIGNERAP_STRREG = "TransactionCodeRequest";
    public static String SIGNERAP_CERTREG = "CertificateRequest";
    public static String SIGNERAP_FILESIGREG = "SignFileRequest";
    public static String SIGNERAP_FILESTAREG = "SignFileResponse";
    public static String SIGNERAP_AUTH_REQ = "AUTHRequest";
    public static String SIGNERAP_AUTH_RESP = "AUTHResponse";
    public static String SIGNERAP_CERTQUERY = "CertificateQuery";
    public static String U2F_REG_REQUEST = "REGRequest";
    public static String U2F_REG_RESPONSE = "REGResponse";
    public static String U2F_AUTH_REQUEST = "AUTHRequest";
    public static String U2F_AUTH_RESPONSE = "AUTHResponse";
    public static String EXTERNAL_STORAGE_FILENETHOSE = "FILENET_HOSE";
    public static String EXTERNAL_STORAGE_FILENETTCB = "DMS";
    public static String EXTERNAL_STORAGE_LOCAL = "P2P";
    public static String CONNECTION_PARAMS_SMTP = "SMTP";
    public static String CONNECTION_PARAMS_SMPP = "SMPP";
    public static String CONNECTION_PARAMS_TSA = "TSA";
    public static String CONNECTION_PARAMS_U2F = "U2F";
    public static String ENCODING_UTF8 = "UTF-8";
    public static String ENCODING_UTF16 = "UTF-16LE";
    public static String FILE_MANAGEMENT_GET = "GET";
    public static String FILE_MANAGEMENT_SUBMIT = "SUBMIT";
    public static int DEFAULT_AGREEMENT_ID = 1;
    public static String PARAMS_BACKOFFICE_MAIL_SIGNSERVER = "SendMailSignserver";
    public static String PARAMS_BACKOFFICE_SMS_SIGNSERVER = "SendSMSSignserver";
    public static String PARAMS_BACKOFFICE_MAIL_HA = "SendMailHaMonitoring";
    public static String PARAMS_BACKOFFICE_MAIL_DB = "SendMailDBMonitoring";
    public static String PARAMS_BACKOFFICE_MAIL_NEWACCOUNT_SIGNSERVER = "SendMailRegisteredSignServerAccount";
    public static String PARAMS_BACKOFFICE_MAIL_ISSUEDCERT_SIGNSERVER = "SendMailIssuedSignServerCertificate";
    public static String SPKI_KEYTYPE_PRIVATE = "PRIVATE";
    public static String SPKI_KEYTYPE_USHARE = "USHARE";
    public static String SPKI_KEYTYPE_CSHARE = "CSHARE";
    public static String SIGNERAP_ASYNC = "Async";
    public static String SIGNERAP_SYNC = "Sync";
    public static String SIGNERAP_ASYNC_REQ_RESP = "AsyncReqResp";
    public static String PARAMETER_OTP = "OTP";
    public static String PARAMETER_TRANSCODE = "TRANSCODE";
    //public static String PARAMETER_PW		= "PASSWORD";
    //public static String PARAMETER_BR		= "BR";
    public static String SIGNERAP_SIGNFORMAT_P7 = "PKCS#7";
    public static String SIGNERAP_SIGNFORMAT_P1 = "PKCS#1";
    public static String P11_LEVEL_BASIC = "BASIC";
    public static String P11_LEVEL_AVANC = "ADVANCED";
    public static int CERT_STATUS_NEW = 2;
    public static int CERT_STATUS_RENEW = 3;
    public static int CERT_STATUS_CANCEL = 4;
    public static String SUCCESS = "SUCCESS";
    public static String TRUE = "True";
    public static String FALSE = "False";
    public static String NULL = "NULL";
    public static String EMPTY = "";
    public static String HASH_SHA1 = "SHA-1";
    public static String HASH_SHA1_ = "SHA1";
    public static String HASH_SHA256 = "SHA-256";
    public static String HASH_SHA256_ = "SHA256";
    public static String HASH_SHA384 = "SHA-384";
    public static String HASH_SHA384_ = "SHA384";
    public static String HASH_SHA512 = "SHA-512";
    public static String HASH_SHA512_ = "SHA512";
    public static String SIGNATURE_METHOD_TPKI = "TPKI";
    public static String SIGNATURE_METHOD_WPKI = "WPKI";
    public static String SIGNATURE_METHOD_LPKI = "LPKI";
    public static String SIGNATURE_METHOD_SPKI = "SPKI";
    /*
     * CAGConnector
     *
     *
     *
     */
    public static String CONNECTOR_FUNC_SMSOTP = "SENDSMS";
    public static String CONNECTOR_FUNC_SMSEMAIL = "SENDEMAIL";
    public static String CONNECTOR_FUNC_SIMCA_CERTIFICATEQUERY = "SIMCA_CERTIFICATEQUERY";
    public static String CONNECTOR_FUNC_SIMCA_SIGNTRANSACTION = "SIMCA_SIGNTRANSACTION";
    public static String CONNECTOR_FUNC_SIMCA_SIGNPDF = "SIMCA_SIGNPDF";
    public static String CONNECTOR_FUNC_SIMCA_SIGNOFFICE = "SIMCA_SIGNOFFICE";
    public static String CONNECTOR_FUNC_SIMCA_SIGNXML = "SIMCA_SIGNXML";
    public static String CONNECTOR_FUNC_SIMCA_SIGNCAPICOM = "SIMCA_SIGNCAPICOM";
    /*
     * WorkerName
     *
     *
     */
    public static String WORKER_PDFSIGNER = "PDFSigner";// workerType=5
    public static String WORKER_XMLSIGNER = "XMLSigner";// workerType=5
    public static String WORKER_ODFSIGNER = "ODFSigner";// workerType=5
    public static String WORKER_OOXMLSIGNER = "OOXMLSigner";// workerType=5
    public static String WORKER_OFFICESIGNER = "OfficeSigner";// workerType=5
    public static String WORKER_CMSSIGNER = "CMSSigner";// workerType=5
    public static String WORKER_PKCS1SIGNER = "PKCS1Signer";// workerType=5
    public static String WORKER_MULTISIGNER = "MultiSigner";// workerType=5
    public static String WORKER_DCSIGNER = "DCSigner";// workerType=5
    public static String WORKER_MRTDSIGNER = "MRTDSigner";// workerType=5
    public static String WORKER_SIGNERAP = "SignerAP";// workerType=8
    public static String WORKER_PDFVALIDATOR = "PDFValidator"; // depends on SignatureMethod, default workerType=2
    public static String WORKER_OFFICEVALIDATOR = "OfficeValidator";// depends on SignatureMethod, default workerType=2
    public static String WORKER_XMLVALIDATOR = "XMLValidator";// depends on SignatureMethod, default workerType=2
    public static String WORKER_ODFVALIDATOR = "ODFValidator";// depends on SignatureMethod, default workerType=2
    public static String WORKER_OOXMLVALIDATOR = "OOXMLValidator";// depends on SignatureMethod, default workerType=2
    public static String WORKER_FIDOVALIDATOR = "FidoValidator";// depends on SignatureMethod, default workerType=2
    public static String WORKER_CAPICOMVALIDATOR = "CapicomValidator";// depends on SignatureMethod, default workerType=2
    public static String WORKER_MULTIVALIDATOR = "MultiValidator"; // depends on SignatureMethod, default workerType=2
    public static String WORKER_SIGNATUREVALIDATOR = "SignatureValidator"; // depends on SignatureMethod, default workerType=2
    public static String WORKER_GENERALVALIDATOR = "GeneralValidator"; // no check agreement
    public static String WORKER_U2FVALIDATOR = "U2FValidator"; // workerType=12
    public static String WORKER_PKCS1VALIDATOR = "PKCS1Validator";// workerType=7
    public static String WORKER_OATHVALIDATOR = "OATHValidator";// workerType=1
    public static String WORKER_OATHSYNC = "OATHSync";// workerType=1
    public static String WORKER_OATHUNLOCK = "OATHUnlock";// workerType=1
    public static String WORKER_MOBILEOTPVALIDATOR = "MobileOTPValidator";
    public static String WORKER_OATHREQUEST = "OATHRequest"; // workerType=3 or 4
    public static String WORKER_OATHRESPONSE = "OATHResponse";// workerType=3 or 4
    public static String WORKER_AGREEMENT = "AgreementHandler";// workerType=6
    public static String WORKER_FILEPROCESSER = "FileProcessor"; // workerType=14
    public static String METHOD_SYNCHRONOUSSIGN = "SynchronousSign";
    public static String METHOD_SIGNREQUEST = "SignRequest";
    public static String METHOD_SIGNRESPONSE = "SignResponse";
    public static int SIGN_EXTERNAL_ASYNC_ERROR = 2;
    public static int SIGN_EXTERNAL_ASYNC_PROCESSING = 1;
    public static int SIGN_EXTERNAL_ASYNC_COMPLETED = 0;
    //public static String TMP_DIR = System.getProperty("jboss.server.home.dir") + "/tmp";
    public static String TMP_DIR = "/opt/CAG360/file" + "/tmp";
    /*
     * SIMCA
	 *
     */
    public static String WORKER_SIMCA = "SIMCA";
    public static String _SIMPROVIDER = "Provider";
    /*
     * SPKI status
     *
     *
     */
    public static int SPKI_STATUS_NEW = 2;
    public static int SPKI_STATUS_WORKER = 3;
    public static int SPKI_STATUS_KEY = 4;
    public static int SPKI_STATUS_CSR = 5;
    public static int SPKI_STATUS_FINISH = 6;
    /*
     * AgreementStatus
	 *
     */
    public static String AGREEMENT_ACTION_REG = "REGISTRATION";
    public static String AGREEMENT_ACTION_UNREG = "UNREGISTRATION";
    public static String AGREEMENT_ACTION_CHAINF = "CHANGEINFO";
    public static String AGREEMENT_ACTION_VALIDA = "VALIDATION";
    public static String AGREEMENT_ACTION_MULTI_UNREG = "MULTIUNREGISTRATION";
    public static String AGREEMENT_ACTION_MULTI_UNREG_DES = "Number of agreement is unregistered: %d";
    public static String AGREEMENT_ACTION_GETAGR = "GETAGREEMENT";
    public static String AGREEMENT_ACTION_ACTIVATION = "ACTIVATION";
    public static String AGREEMENT_ACTION_DEACTIVATION = "DEACTIVATION";
    public static String AGREEMENT_STATUS_ACTI = "ACTIVATED";
    public static String AGREEMENT_STATUS_WAIT = "WAIT";
    public static String AGREEMENT_STATUS_CANC = "CANC";
    public static String AGREEMENT_STATUS_BLOC = "BLOC";
    public static String AGREEMENT_STATUS_EXTE = "EXTE";
    public static String AGREEMENT_STATUS_EXPR = "EXPR";
    public static String OTP_STATUS_SUCC = "OTP authentication success";
    public static String OTP_STATUS_WAIT = "OTP wait for authentication";
    public static String OTP_STATUS_FAIL = "OTP authentication failed";
    public static String OTP_STATUS_TIME = "OTP authentication timeout";
    public static String OTP_STATUS_EXPI = "OTP authentication expired";
    public static String OTP_STATUS_DISA = "OTP token is disabled";
    public static String OTP_STATUS_LOST = "OTP token is lost";
    public static String ERROR_INVALIDCHANNEL = "Access denied. Invalid channelCode";
    public static String ERROR_INVALIDIP = "IP address is invalid";
    public static String ERROR_INVALIDLOGININFO = "Your login information is incorrect";
    public static String ERROR_INVALIDSIGNATURE = "Invalid Signature";
    public static String ERROR_INVALIDCREDENTIAL = "Your credential information is incorrect";
    public static String ERROR_INVALIDACTION = "Invalid action";
    public static String ERROR_INVALIDFUNCTION = "Channel isn't granted for this function";
    public static String ERROR_INVALID_SIM_VENDOR = "Invalid SIM vendor";
    public static String ERROR_UPDATE_SIGNSERVER = "Error while updating signserver information";
    /*
     * agreementMethod
     *
     *
     */
    public static String ERROR_INVALIDPARAMETER = "Invalid parameters in your request";
    public static String ERROR_INVALIDCERTIFICATE = "Invalid certificate";
    public static String ERROR_INVALIDUSERAGREEMENT = "User exits in system";
    public static String ERROR_CREATEAGREEMENT = "Agreement registration error";
    public static String ERROR_INSERTOTPINFORMATION = "Insert OTP information error";
    public static String ERROR_INSERTPKIINFORMATION = "Insert PKI information error";
    public static String INFO_AGREEMENTCREATED = "A new agreement has been created";
    public static String ERROR_AGREEMENTNOTEXITS = "Agreement not found";
    public static String ERROR_INVALIDAGREESTATUS = "Invalid agreement status";
    public static String INFO_AGREEMENTUPDATED = "Agreement status has been changed";
    public static String ERROR_CERTIFICATEEXITED = "Certificate exits in system";
    public static String ERROR_INVALIDOTPMETHOD = "Invalid OTP method";
    public static String ERROR_INVALIDPKIMETHOD = "Invalid PKI method";
    public static String ERROR_UPDATEOTPSMS = "Error update OTP SMS information";
    public static String ERROR_UPDATEOTPEMAIL = "Error update OTP Email information";
    public static String ERROR_UPDATEOTPHARDWARE = "Error update OTP Hardware information";
    public static String ERROR_ERRORGETOLDOTP = "Error get current OTP Hardware information";
    public static String ERROR_UPDATEOTPSOFTWARE = "Error udpate OTP Software information";
    public static String ERROR_UPDATEPKI = "Error update PKI information";
    public static String ERROR_NOPKIAGREEMENT = "No PKI agreement";
    public static String ERROR_NOOTPAGREEMENT = "No OTP agreement";
    public static String ERROR_UPDATEEXTEND = "Error update extend agreement";
    public static String INFO_AGREEMENTCHANGEINFO = "Agreement info has been changed";
    public static String ERROR_AGREEMENTNOTREADY = "Agreement is not ready for this operation";
    public static String ERROR_OTPHARDWAREEXIT = "OTP Hardware exits in system";
    public static String ERROR_AGREEMENTEXPIRED = "Agreement is expired";
    public static String INFO_AGREEMENTVALIDATEOK = "Certificate validation success";
    public static String ERROR_UPDATELCDPKI = "Error update LCD PKI information";
    public static String ERROR_UPDATESIMPKI = "Error update SIM PKI information";
    /*
     * pValidDate OTP
     *
     *
     */
    public static String ERROR_OTPEXCEPTION = "OTP exception";
    public static String ERROR_OTPCONNECTION = "OTP connection failed";
    /*
     * processData
     *
     *
     */
    public static String ERROR_INVALIDWORKERNAME = "Invalid WorkerName in your request";
    public static String ERROR_INVALIDUSER = "User is null in your request";
    public static String ERROR_NOWORKER = "No Worker could be found in system";
    public static String ERROR_NOTMATCHID = "Response ID doesn't match request ID";
    public static String ERROR_UNEXPECTEDRETURNTYPE = "Unexpected return type";
    public static String ERROR_SIGNERCERTENCODE = "Signer certificate could not be encoded";
    public static String ERROR_INTERNALSYSTEM = "Internal System error";
    public static String ERROR_WORKEROFFLINE = "Worker offline";
    public static String ERROR_NOBASE64FILE = "Invalid file data in your request";
    public static String ERROR_CONTRACTSTATUS = "Your agreement is not ready for this operation";
    public static String ERROR_NOCERTSERIAL = "Certificate serial number hasn't been registered";
    public static String ERROR_NOCAPICOMSIGNATURE = "No signature in your request";
    public static String ERROR_INVALIDISSUERCERT = "Invalid certificate issuer name";
    public static String ERROR_INVALIDCAINFO = "System error. CA information is unavailable";
    public static String ERROR_INVALIDCERTSERIAL = "Your agreement is not registered with this signing certificate";
    public static String ERROR_SIGNEDDOC = "Document has not been signed";
    public static String ERROR_NOSIGNELEMENT = "No signature element found";
    public static String ERROR_NOX509ELEMENT = "No X509Certificate found";
    public static String ERROR_UNKNOWN = "Unknown exception";
    public static String ERROR_NOCERTCHAIN = "Null certificate chain. This signer needs a certificate";
    public static String ERROR_INVALIDFILETYPE = "Invalid file type in your request";
    public static String ERROR_INVALIDDATATOSIGN = "Invalid data to sign in your request";
    //CMS
    public static String ERROR_INITSIGNER = "Error initializing signer";
    public static String ERROR_CERTSTORE = "Error constructing cert store";
    public static String ERROR_CONSTRUCTCMS = "Error constructing CMS";
    /*
     * //ODF public static String ERROR_ODFFORMAT	= "Data received is not in
     * valid odf package format"; public static String ERROR_ODFSIGNERROR	=
     * "Problem signing odf document"; public static String ERROR_ODFSAVESTREAM
     * = "Error saving document to output stream";
     *
     * //OOXML public static String ERROR_OOXMLFORMAT	= "Data received is not in
     * valid openxml package format"; public static String ERROR_OOXMLOPENFILE	=
     * "Error opening received data"; public static String
     * ERROR_OOXMLSIGNPROBLEM	= "Problem signing ooxml document";
     */
    //Make change for officeSigner
    //OFFICE
    public static String ERROR_OFFICESIGNEREXP = "OfficeSigner exception";
    public static String ERROR_OFFICESIGNERNOKEY = "No key for signing file";
    public static String ERROR_OFFICESIGNERISSIGN = "Document has been signed";
    public static String ERROR_OFFICESIGNERISENCRYPT = "Document has been encrypted";
    public static String ERROR_OFFICESIGNERCANSIGN = "Document could not be signed";
    public static String ERROR_OFFICESIGNERFAILDSIGN = "Failed to sign document";
    // PDF
    public static String ERROR_PDFCANNOTSIGN = "Could not sign document";
    public static String ERROR_PDFPASS = "A valid password is required to sign the document";
    public static String ERROR_PDFPASSENCODING = "The supplied password could not be read";
    public static String ERROR_PDFSIGN = "Could not sign document";
    public static String ERROR_PDFCERT = "Error estimating signature size contribution for certificate";
    public static String ERROR_PDFCRL = "Error estimating signature size contribution for CRL";
    public static String ERROR_PDFCALSIGN = "Error calculating signature";
    public static String ERROR_PDFCERTNULL = "Null certificate chain. This signer needs a certificate";
    public static String ERROR_PDFNOTCERTIFIED = "Will not certify an already certified document";
    public static String ERROR_PDFSIGNALLOW = "Will not sign a certified document where signing is not allowed";
    public static String ERROR_PDFPERMISSION = "Document contains permissions not allowed by this signer";
    public static String ERROR_PDFGETOCSPURL = "Error getting OCSP URL from certificate";
    public static String ERROR_PDFPKCS7 = "Error constructing PKCS7 package";
    public static String ERROR_PDFHASHALG = "Error creating SHA1 digest";
    public static String ERROR_PDFCALSIGNSIZE = "Failed to calculate signature size";
    public static String ERROR_PDFGETCDP = "Error obtaining CDP from signing certificate";
    // XML
    public static String ERROR_XMLEXP = "XMLSigner got an exception";
    public static String ERROR_EXPIREDCERT = "Certificate has been expired";
    public static String ERROR_NOTVALIDCERT = "Certificate is not valid yet";
    // PKCS#1
    public static String ERROR_PKCS1EXP = "PKCS1Signer got an exception";
    public static String ERROR_PKCS1MAKECHAIN = "Make certchain exception";
    // OTP
    public static String ERROR_OTPLOCKED = "OTP authentication blocked";
    public static String ERROR_USEREMAILEXIT = "Email is used by another user";
    public static String ERROR_USERPHONEEXIT = "Phone number is used by another user";
    public static String INFO_CERTIFICATE_REVOKED = "Certificate has been revoked";
    public static String INFO_CERTIFICATE_UNKNOWN = "Unknown certificate";
    public static String INFO_CERTIFICATE_ERROR = "Error occured while checking certificate status";
    public static String INFO_UNCHANGEAGREEMENT = "Agreement Unchanged";
    public static String ERROR_PKILOCKED = "PKI validation transaction is locked";
    public static String ERROR_CERTIFICATEEXPIRED = "Signing certificate expired";
    public static String ERROR_OVERSIGNERTIME = "Signing times has exceeded";
    public static String ERROR_OTPPERFORMANCEXCEED = "OTP verification times has exceeded";
    public static String ERROR_INVALIDTRANSACDATA = "Invalid transaction data";
    public static String ERROR_INVALIDTRANSACSTATUS = "No billcode found to complete the transaction";
    public static String ERROR_BILLCODENOTFOUND = "Billcode not found";
    public static String ERROR_OTPNEEDSYNC = "OTP token need to be synchronized";
    public static String ERROR_SSLCLIENTREQUEST = "SSL client certificate required";
    public static String ERROR_SIMCA_INVALIDPROVIDER = "Invalid SIM provider";
    public static String ERROR_SIMCA_INSERTAGREEMENT = "Failed to insert sim agreement";
    public static String ERROR_SIMCA_UPDATEAGREEMENT = "Failed to update sim agreement";
    public static String ERROR_SIMCA_CANCELAGREEMENT = "Failed to cancel sim agreement";
    public static String ERROR_SIMCA_INVALIDLENGTH = "Data length should be less than 107";
    public static String ERROR_INFO_LICENSE = "License violation";
    public static String ERROR_DCSIGNEREXP = "DCSigner exception";
    public static String ERROR_INVALID_ALGORITHM = "Invalid algorithm";
    public static String ERROR_INFO_LICENSE_NOTSUPPORT = "License isn't supported this function";
    public static String ERROR_INFO_LICENSE_PERFORMANCE = "Transaction number has been exceeded for this license";
    public static String ERROR_EXTERNAL_FILE_GET = "Can't get file data from external server";
    public static String ERROR_EXTERNAL_FILE_SET = "Can't set file data to external server";
    public static String ERROR_SIGNPKICONSTRAINT = "Signing PKI constraint for user. Worker isn't granted for user";
    public static String ERROR_ENDPOINTEXP = "Failed to send a request to endpoint service";
    public static String ERROR_NOTSUPPORTYET = "Not supported yet";
    public static String ERROR_ILLEGAL_CHARACTERS = "Illegal characters in request";
    public static String ERROR_SIGN_ASYNC_PROCESSING = "Sign request is being processed";
    public static String ERROR_SIGN_ASYNC_ERROR = "Error while processing asynchronous sign";
    public static String ERROR_INVALID_EXT_CONN_VENDOR = "Invalid external connection vendor";
    public static String ERROR_INVALID_PASSWORD_LENGTH = "Password length must be greater than (or equal to) 8 characters";
    public static String ERROR_INVALID_PASSWORD = "Invalid signer password";
    public static String ERROR_SIGNSERVER_PKI_LOCKED = "SignServer PKI blocked";
    public static String MSSP_REQUEST_ACCEPTED = "Request accepted";
    public static String MSSP_TRANSACTION_EXPIRED = "Transaction expired";
    public static String MSSP_NO_TRANSACTION_FOUND = "No transaction found";
    public static String MSSP_OUT_TRANSACTION = "Transaction is waiting for user";
    public static String MSSP_NOCERTIFICATE = "Certificate hasn't been registered";
    public static String MSSP_TRANSCANCELED = "Transaction has been canceled";
    public static String MSSP_ERROR = "Failed to process transaction";
    public static String MSSP_AUTH_FAILED = "Authentication failed. Transaction is not finished";
    public static String MSSP_TRANSACTION_CANCELED = "Transaction is canceled by user";
    public static String ACTION_SIMCA_SIGNTRAN = "SIGNTRANSACTION";
    public static String ACTION_SIMCA_SIGNPDF = "SIGNPDF";
    public static String ACTION_SIMCA_SIGNOFFICE = "SIGNOFFICE";
    public static String ACTION_SIMCA_SIGNXML = "SIGNXML";
    public static String ACTION_SIMCA_SIGNCAPICOM = "SIGNCAPICOM";
    public static String ERROR_INVALID_TYPE_REQUEST = "Invalid type of request";
    public static String ERROR_INVALID_TIMESTAMP = "Invalid timestamp signature";
    public static String ERROR_INVALID_OTPHARDWARE = "OTP token doesn't exit in system";
    public static String ERROR_INVALID_SUBJECTDN = "SubjectDN doesn't fulfill as expected";
    public static String ERROR_INVALID_P11INFO = "HSM slot has been used or not available in system";
    public static String ERROR_FAILED_TO_PROCESS_U2F = "Failed to process U2F request";
    public static String ERROR_U2F_BLOCKED = "U2F method is blocked";
    public static int CODE_SUCCESS = 0;
    public static int CODE_INVALIDWORKERNAME = 1;
    public static int CODE_INVALIDUSER = 2;
    public static int CODE_NOWORKER = 3;
    public static int CODE_NOTMATCHID = 4;
    public static int CODE_UNEXPECTEDRETURNTYPE = 5;
    public static int CODE_SIGNERCERTENCODE = 6;
    public static int CODE_INTERNALSYSTEM = 7;
    public static int CODE_WORKEROFFLINE = 8;
    public static int CODE_NOBASE64FILE = 9;
    public static int CODE_CONTRACTSTATUS = 10;
    public static int CODE_NOCERTSERIAL = 11;
    public static int CODE_NOCAPICOMSIGNATURE = 12;
    public static int CODE_INVALIDISSUERCERT = 13;
    public static int CODE_INVALIDCAINFO = 14;
    public static int CODE_INVALIDCERTSERIAL = 15;
    public static int CODE_SIGNEDDOC = 16;
    public static int CODE_NOSIGNELEMENT = 17;
    public static int CODE_NOX509ELEMENT = 18;
    public static int CODE_UNKNOWN = 19;
    public static int CODE_NOCERTCHAIN = 20;
    public static int CODE_INITSIGNER = 21;
    public static int CODE_CERTSTORE = 22;
    public static int CODE_CONSTRUCTCMS = 23;
    public static int CODE_OFFICESIGNEREXP = 24;
    public static int CODE_OFFICESIGNERNOKEY = 25;
    public static int CODE_OFFICESIGNERISSIGN = 26;
    public static int CODE_OFFICESIGNERISENCRYPT = 27;
    public static int CODE_OFFICESIGNERCANSIGN = 28;
    public static int CODE_OFFICESIGNERFAILDSIGN = 29;
    public static int CODE_PDFCANNOTSIGN = 30;
    public static int CODE_PDFPASS = 31;
    public static int CODE_PDFPASSENCODING = 32;
    public static int CODE_PDFSIGN = 33;
    public static int CODE_PDFCERT = 34;
    public static int CODE_PDFCRL = 35;
    public static int CODE_PDFCALSIGN = 36;
    public static int CODE_PDFCERTNULL = 37;
    public static int CODE_PDFNOTCERTIFIED = 38;
    public static int CODE_PDFSIGNALLOW = 39;
    public static int CODE_PDFPERMISSION = 40;
    public static int CODE_PDFGETOCSPURL = 41;
    public static int CODE_PDFPKCS7 = 42;
    public static int CODE_PDFHASHALG = 43;
    public static int CODE_PDFCALSIGNSIZE = 44;
    public static int CODE_PDFGETCDP = 45;
    public static int CODE_XMLEXP = 46;
    public static int CODE_PKCS1EXP = 47;
    public static int CODE_PKCS1MAKECHAIN = 48;
    public static int CODE_INVALIDFILETYPE = 49;
    public static int CODE_INVALIDDATATOSIGN = 50;
    public static int CODE_INVALIDPARAMETER = 51;
    public static int CODE_INVALIDCERTIFICATE = 52;
    public static int CODE_INVALIDUSERAGREEMENT = 53;
    public static int CODE_OTPEXCEPTION = 54;
    public static int CODE_OTPCONNECTION = 55;
    public static int CODE_CREATEAGREEMENT = 56;
    public static int CODE_INSERTOTPINFORMATION = 57;
    public static int CODE_INSERTPKIINFORMATION = 58;
    public static int CODE_INVALIDACTION = 59;
    public static int CODE_OTPLOCKED = 60;
    public static int CODE_AGREEMENTNOTEXITS = 61;
    public static int CODE_INVALIDAGREESTATUS = 62;
    public static int CODE_CERTIFICATEEXITED = 63;
    public static int CODE_INVALIDOTPMETHOD = 64;
    public static int CODE_INVALIDPKIMETHOD = 65;
    public static int CODE_UPDATEOTPSMS = 66;
    public static int CODE_UPDATEOTPEMAIL = 67;
    public static int CODE_UPDATEOTPHARDWARE = 68;
    public static int CODE_ERRORGETOLDOTP = 69;
    public static int CODE_UPDATEOTPSOFTWARE = 70;
    public static int CODE_UPDATEPKI = 71;
    public static int CODE_NOPKIAGREEMENT = 72;
    public static int CODE_NOOTPAGREEMENT = 73;
    public static int CODE_UPDATEEXTEND = 74;
    public static int CODE_AGREEMENTNOTREADY = 75;
    public static int CODE_OTPHARDWAREEXIT = 76;
    public static int CODE_AGREEMENTEXPIRED = 77;
    public static int CODE_INVALIDFUNCTION = 78;
    public static int CODE_INVALIDCHANNEL = 79;
    public static int CODE_INVALIDIP = 80;
    public static int CODE_INVALIDLOGININFO = 81;
    public static int CODE_INVALIDCREDENTIAL = 82;
    public static int CODE_INVALIDSIGNATURE = 83;
    public static int CODE_PKILOCKED = 84;
    public static int CODE_CERTIFICATEEXPIRED = 85;
    public static int CODE_OVERSIGNERTIME = 86;
    public static int CODE_UNCHANGEDAGREEMENT = 87;
    public static int CODE_OTPPERFORMANCEXCEED = 88;
    public static int CODE_BILLCODENOTFOUND = 89;
    public static int CODE_OTP_STATUS_WAIT = 90;
    public static int CODE_OTP_STATUS_FAIL = 91;
    public static int CODE_OTP_STATUS_TIME = 92;
    public static int CODE_INVALIDTRANSACDATA = 93;
    public static int CODE_INVALIDTRANSACSTATUS = 94;
    public static int CODE_OTPNEEDSYNC = 95;
    public static int CODE_SSLCLIENTREQUEST = 96;
    public static int CODE_USEREMAILEXIT = 97;
    public static int CODE_USERPHONEEXIT = 98;
    public static int CODE_SIMCA_INVALIDPROVIDER = 99;
    //public static int CODE_SIMCA_ERRORRESPONSE		= 100;
    public static int CODE_INVALID_PASSWORD_LENGTH = 100;
    public static int CODE_SIMCA_INSERTAGREEMENT = 101;
    public static int CODE_SIMCA_UPDATEAGREEMENT = 102;
    public static int CODE_SIMCA_CANCELAGREEMENT = 103;
    public static int CODE_SIMCA_INVALIDLENGTH = 104;
    public static int CODE_INFO_CERTIFICATE_REVOKED = 105;
    public static int CODE_INFO_CERTIFICATE_UNKNOWN = 106;
    public static int CODE_INFO_CERTIFICATE_ERROR = 107;
    public static int CODE_INFO_LICENSE = 108;
    public static int CODE_DCSIGNEREXP = 109;
    public static int CODE_INVALID_ALGORITHM = 110;
    public static int CODE_INFO_LICENSE_NOTSUPPORT = 111;
    public static int CODE_INFO_LICENSE_PERFORMANCE = 112;
    public static int CODE_MSSP_REQUEST_ACCEPTED = 113;
    public static int CODE_MSSP_TRANSACTION_EXPIRED = 114;
    public static int CODE_MSSP_NO_TRANSACTION_FOUND = 115;
    public static int CODE_MSSP_OUT_TRANSACTION = 116;
    public static int CODE_MSSP_NOCERTIFICATE = 117;
    public static int CODE_MSSP_TRANSCANCELED = 118;
    public static int CODE_OTP_STATUS_DISABLE = 119;
    public static int CODE_OTP_STATUS_LOST = 120;
    public static int CODE_EXTERNAL_FILE_GET = 121;
    public static int CODE_EXTERNAL_FILE_SET = 122;
    public static int CODE_UPDATELCDPKI = 123;
    public static int CODE_MSSP_ERROR = 124;
    public static int CODE_UPDATESIMPKI = 125;
    public static int CODE_SIGNPKICONSTRAINT = 126;
    public static int CODE_ENDPOINTEXP = 127;
    public static int CODE_NOTSUPPORTYET = 128;
    public static int CODE_ILLEGAL_CHARACTERS = 129;
    public static int CODE_OTP_STATUS_EXPI = 130;
    public static int CODE_INVALID_SIM_VENDOR = 131;
    public static int CODE_UPDATE_SIGNSERVER = 132;
    public static int CODE_SIGN_ASYNC_PROCESSING = 133;
    public static int CODE_SIGN_ASYNC_ERROR = 134;
    public static int CODE_INVALID_EXT_CONN_VENDOR = 135;
    public static int CODE_INVALID_PASSWORD = 136;
    public static int CODE_SIGNSERVER_PKI_LOCKED = 137;
    public static int CODE_INVALID_TYPE_REQUEST = 138;
    public static int CODE_INVALID_TIMESTAMP = 139;
    public static int CODE_INVALID_OTPHARDWARE = 140;
    public static int CODE_INVALID_SUBJECTDN = 141;
    public static int CODE_INVALID_P11INFO = 142;
    public static int CODE_FAILED_TO_PROCESS_U2F = 143;
    public static int CODE_U2F_BLOCKED = 144;
    public static int CODE_MSSP_AUTH_FAILED = 145;
    public static int CODE_MSSP_CANCELED = 146;
}