package org.signserver.module.multisigner.oath;

public final class OTPAgentReturnCode {
	/*
	 * public static final int OTPR_COMMON_SUIT = 0x00000000; public static
	 * final int OTPR_OK = (OTPR_COMMON_SUIT + 0); public static final int
	 * OTPR_ERR = (OTPR_COMMON_SUIT + 1); public static final int
	 * OTPR_PARAM_INVALID = (OTPR_COMMON_SUIT + 2); public static final int
	 * OTPR_MEM_ALLOC = (OTPR_COMMON_SUIT + 3); public static final int
	 * OTPR_SERV_INVALID = (OTPR_COMMON_SUIT + 4); public static final int
	 * OTPR_REQ_INVALID = (OTPR_COMMON_SUIT + 5); public static final int
	 * OTPR_PACKET_INVALID = (OTPR_COMMON_SUIT + 6); public static final int
	 * OTPR_SOCKET_INIT = (OTPR_COMMON_SUIT + 7); public static final int
	 * OTPR_REQ_SEND = (OTPR_COMMON_SUIT + 8); public static final int
	 * OTPR_RECV_ACK = (OTPR_COMMON_SUIT + 9); public static final int
	 * OTPR_UID_INVALID = (OTPR_COMMON_SUIT + 10); public static final int
	 * OTPR_REQ_MANY = (OTPR_COMMON_SUIT + 11); public static final int
	 * OTPR_SECRET_INVALID = (OTPR_COMMON_SUIT + 12); public static final int
	 * OTPR_NEED_SYNC = (OTPR_COMMON_SUIT + 13); public static final int
	 * OTPR_PIN_INVALID = (OTPR_COMMON_SUIT + 14); public static final int
	 * OTPR_AUTHNUM_SET = (OTPR_COMMON_SUIT + 15); public static final int
	 * OTPR_KEY_INVALID = (OTPR_COMMON_SUIT + 16); public static final int
	 * OTPR_PIN_SET = (OTPR_COMMON_SUIT + 17); public static final int
	 * OTPR_ACK_INVALID = (OTPR_COMMON_SUIT + 18); public static final int
	 * OTPR_CSINFO_INVALID = (OTPR_COMMON_SUIT + 19); public static final int
	 * OTPR_TOKEN_LOCKED = (OTPR_COMMON_SUIT + 20); public static final int
	 * OTPR_PROT_INVALID = (OTPR_COMMON_SUIT + 21); public static final int
	 * OTPR_OTP_INVALID = (OTPR_COMMON_SUIT + 22); public static final int
	 * OTPR_LOGIN_LOCKED = (OTPR_COMMON_SUIT + 23); public static final int
	 * OTPR_TOKEN_INVALID = (OTPR_COMMON_SUIT + 24); public static final int
	 * OTPR_TOKEN_BINDED = (OTPR_COMMON_SUIT + 25); public static final int
	 * OTPR_USERTOKEN_SET = (OTPR_COMMON_SUIT + 26); public static final int
	 * OTPR_UID_NOTEXIST = (OTPR_COMMON_SUIT + 27); public static final int
	 * OTPR_GET_USERTOKEN = (OTPR_COMMON_SUIT + 28); public static final int
	 * OTPR_BAD_REQINFO = (OTPR_COMMON_SUIT + 29); public static final int
	 * OTPR_PIN_EMPTY = (OTPR_COMMON_SUIT + 30); public static final int
	 * OTPR_PIN_NEEDVERIFY = (OTPR_COMMON_SUIT + 31); public static final int
	 * OTPR_OTP_EXCEED = (OTPR_COMMON_SUIT + 32); public static final int
	 * OTPR_PIN_NOTINIT = (OTPR_COMMON_SUIT + 33); public static final int
	 * OTPR_DBCORE_ERR = (OTPR_COMMON_SUIT + 34); public static final int
	 * OTPR_TKSN_INVALID = (OTPR_COMMON_SUIT + 35); public static final int
	 * OTPR_USER_INACTIVE = (OTPR_COMMON_SUIT + 36);
	 */
	/******************************************************************************
	 * 2009-11-10
	 *****************************************************************************/
	/*
	 * public static final int OTPR_HANDLE_INVALID = (OTPR_COMMON_SUIT + 37);
	 * public static final int OTPR_SESSID_INVALID = (OTPR_COMMON_SUIT + 38);
	 * public static final int OTPR_SESS_ESTED = (OTPR_COMMON_SUIT + 39); public
	 * static final int OTPR_SESS_NOTESTED = (OTPR_COMMON_SUIT + 40); public
	 * static final int OTPR_SESS_NOTEXIST = (OTPR_COMMON_SUIT + 41); public
	 * static final int OTPR_UIDTKSN_UNSET = (OTPR_COMMON_SUIT + 42); public
	 * static final int OTPR_CHLGE_INVLID = (OTPR_COMMON_SUIT + 43); public
	 * static final int OTPR_SESS_NOTNXTOTP = (OTPR_COMMON_SUIT + 44); public
	 * static final int OTPR_SESS_NOTNDPIN = (OTPR_COMMON_SUIT + 45);
	 * 
	 * 
	 * public static final int OTPR_TOKEN_LOGOUT = (OTPR_COMMON_SUIT + 55);
	 * public static final int OTPR_TOKEN_TIMEOUT = (OTPR_COMMON_SUIT + 56);
	 * public static final int OTPR_AUTH_METHOD_INVALID = (OTPR_COMMON_SUIT +
	 * 57); public static final int OTPR_SUITE_INVALID = (OTPR_COMMON_SUIT +
	 * 58); public static final int OTPR_CHALLENGE_INVALID = (OTPR_COMMON_SUIT +
	 * 59);
	 * 
	 * 
	 * public static final int OTPR_ERR_UNKNOWN = (OTPR_COMMON_SUIT + 63);
	 * 
	 * // ��֤��ط����� public static final int OTPR_AUTH_SUIT = 0x00000040;
	 * public static final int OTPR_AUTH_OK = (OTPR_AUTH_SUIT + 0); public
	 * static final int OTPR_AUTH_SYNC = OTPR_NEED_SYNC; public static final int
	 * OTPR_AUTH_PIN_INIT = OTPR_PIN_NOTINIT; public static final int
	 * OTPR_AUTH_PIN_INVALID = (OTPR_AUTH_SUIT + 3);
	 * 
	 * // �״ε�½�ж���ط����� public static final int OTPR_FIRST_SUIT = 0x00000080;
	 * public static final int OTPR_IS_FIRST = (OTPR_FIRST_SUIT + 0); public
	 * static final int OTPR_NOT_FIRST = (OTPR_FIRST_SUIT + 1);
	 * 
	 * // ����PIN����ط����� public static final int OTPR_PIN_SUIT = 0x000000C0;
	 * public static final int OTPR_PIN_OK = (OTPR_PIN_SUIT + 0);
	 * 
	 * // ����ͬ����ط����� public static final int OTPR_SYNC_SUIT = 0x00000100;
	 * public static final int OTPR_SYNC_OK = (OTPR_SYNC_SUIT + 0);
	 * 
	 * // ��ѯ��֤ʧ��״̬��ط����� public static final int OTPR_ERRSTAT_SUIT =
	 * 0x00000140; public static final int OTPR_ERRSTAT_SUCC =
	 * (OTPR_ERRSTAT_SUIT + 0);
	 * 
	 * // ���û�������ط����� public static final int OTPR_TKBIND_SUIT =
	 * 0x00000150; public static final int OTPR_TKBIND_SUCC = (OTPR_TKBIND_SUIT
	 * + 0); public static final int OTPR_TKBIND_EXCEED = (OTPR_TKBIND_SUIT +
	 * 1);
	 * 
	 * // ��ȡ������֤������Ϣ public static final int OTPR_OFFLINE_SUIT =
	 * 0x00000160; public static final int OTPR_OFFLINE_SUCC =
	 * (OTPR_OFFLINE_SUIT + 0); public static final int OTPR_OLCOUNT_INVALID =
	 * (OTPR_OFFLINE_SUIT + 1);
	 * 
	 * // ��ѯ����״̬��ط����� public static final int OTPR_TKQUERY_SUIT =
	 * 0x00000170; public static final int OTPR_TKQUERY_SUCC =
	 * (OTPR_TKQUERY_SUIT + 0);
	 * 
	 * // �����û�������ط����� public static final int OTPR_TKUNBIND_SUIT =
	 * 0x00000180; public static final int OTPR_TKUNBIND_SUCC =
	 * (OTPR_TKUNBIND_SUIT + 0);
	 * 
	 * // ���ƹ�ʧ��ط����� public static final int OTPR_TKLOCK_SUIT = 0x00000190;
	 * public static final int OTPR_TKLOCK_SUCC = (OTPR_TKLOCK_SUIT + 0);
	 * 
	 * // ���ƽ���ʧ������ public static final int OTPR_TKUNLOCK_SUIT =
	 * 0x00000200; public static final int OTPR_TKUNLOCK_SUCC =
	 * (OTPR_TKUNLOCK_SUIT + 0);
	 * 
	 * // ���ƽ�����½������ public static final int OTPR_LGUNLOCK_SUIT =
	 * 0x00000210; public static final int OTPR_LGUNLOCK_SUCC =
	 * (OTPR_LGUNLOCK_SUIT + 0);
	 * 
	 * // ��ѯ�û�״̬��ط����� public static final int OTPR_USERQUERY_SUIT =
	 * 0x00000220; public static final int OTPR_USERQUERY_SUCC =
	 * (OTPR_USERQUERY_SUIT + 0);
	 * 
	 * // �����û���ط����� public static final int OTPR_USERACTIVE_SUIT =
	 * 0x00000230; public static final int OTPR_USERACTIVE_SUCC =
	 * (OTPR_USERACTIVE_SUIT + 0);
	 * 
	 * // ��ͣ�û���ط����� public static final int OTPR_USERINACTV_SUIT =
	 * 0x00000240; public static final int OTPR_USERINACTV_SUCC =
	 * (OTPR_USERINACTV_SUIT + 0);
	 * 
	 * // OCRA������ط����� public static final int OA_INVALID_HANDLE =
	 * 0x00000250 ; public static final int OA_NEXT_CODE_REQUIRED = 0x00000251;
	 * public static final int OA_PIN_REQUIRED = (OTPR_PIN_NEEDVERIFY);
	 * 
	 * public static String getReturnCodeInfo(String strReturnCode) { int nCode
	 * = Integer.parseInt(strReturnCode);
	 * 
	 * switch(nCode) { case 0:// 0x0 // success return "OTPR_OK"; //return
	 * "success"; case 1:// 0x1 // fail return "OTPR_ERR"; //return "fail"; case
	 * 2:// 0x2 // bad parameter return "OTPR_PARAM_INVALID"; //return
	 * "bad parameter"; case 3:// 0x3 // memory allocation failed return
	 * "OTPR_MEM_ALLOC"; //return "memory allocation failed"; case 4:// 0x4 //
	 * invalid server information in .acf return "OTPR_SERV_INVALID"; //return
	 * "invalid server information in .acf"; case 5:// 0x5 // bad request return
	 * "OTPR_REQ_INVALID"; //return "bad request"; case 6:// 0x6 // bad packet
	 * return "OTPR_PACKET_INVALID"; //return "bad packet"; case 7:// 0x7 //
	 * init SOCKET failed return "OTPR_SOCKET_INIT"; //return
	 * "init SOCKET failed"; case 8:// 0x8 // send packet failed return
	 * "OTPR_REQ_SEND"; //return "send packet failed"; case 9:// 0x9 // receive
	 * packet failed return "OTPR_RECV_ACK"; //return "receive packet failed";
	 * case 10:// 0xA // invalid user return "OTPR_UID_INVALID"; //return
	 * "invalid user"; case 11:// 0xB // too many concurrent request return
	 * "OTPR_REQ_MANY"; //return "too many concurrent request"; case 12:// 0xC
	 * // invalid share key of server and agent return "OTPR_SECRET_INVALID";
	 * //return "invalid share key of server and agent"; case 13:// 0xD // OTP
	 * synchronization required return "OTPR_NEED_SYNC"; //return
	 * "OTP synchronization required"; case 14:// 0xE // invalid PIN return
	 * "OTPR_PIN_INVALID"; //return "invalid PIN"; case 15:// 0xF // set the
	 * base authentication number failed return "OTPR_AUTHNUM_SET"; //return
	 * "set the base authentication number failed"; case 16:// 0x10 // invalid
	 * token key return "OTPR_KEY_INVALID"; //return "invalid token key"; case
	 * 17:// 0x11 // set the new PIN failed on server side return
	 * "OTPR_PIN_SET"; //return "set the new PIN failed on server side"; case
	 * 18:// 0x12 // invalid ACK return "OTPR_ACK_INVALID"; //return
	 * "invalid ACK"; case 19:// 0x13 // invalid agent configure file return
	 * "OTPR_CSINFO_INVALID"; //return "invalid agent configure file"; case
	 * 20:// 0x14 // Token has been lost. return "OTPR_TOKEN_LOCKED"; //return
	 * "Token has been lost."; case 21:// 0x15 // invalid protected type of OTP
	 * return "OTPR_PROT_INVALID"; //return "invalid protected type of OTP";
	 * case 22:// 0x16 // invalid OTP return "OTPR_OTP_INVALID"; //return
	 * "invalid OTP"; case 23:// 0x17 // token has LOGIN-Locked return
	 * "OTPR_LOGIN_LOCKED"; //return "token has LOGIN-Locked"; case 24:// 0x18
	 * // invalid token information return "OTPR_TOKEN_INVALID"; //return
	 * "invalid token information"; case 25:// 0x19 // token has binded before
	 * return "OTPR_TOKEN_BINDED"; //return "token has binded before"; case
	 * 26:// 0x1A // failed to bind user with the token return
	 * "OTPR_USERTOKEN_SET"; //return "failed to bind user with the token"; case
	 * 27:// 0x1B // user name doesn't exist return "OTPR_UID_NOTEXIST";
	 * //return "user name doesn't exist"; case 28:// 0x1C // get the token
	 * information failed return "OTPR_GET_USERTOKEN"; //return
	 * "get the token information failed"; case 29:// 0x1D // invalid user
	 * information return "OTPR_BAD_REQINFO"; //return
	 * "invalid user information"; case 30:// 0x1F // verify PIN required return
	 * "OTPR_PIN_EMPTY"; //return "the user PIN empty"; case 31:// 0x20 // OTP
	 * length exceed 6 digits return "OTPR_PIN_NEEDVERIFY"; //return
	 * "verify PIN required"; case 32:// 0x21 // PIN-flag has set, but PIN is
	 * empty return "OTPR_OTP_EXCEED"; //return "OTP length exceed 6 digits";
	 * case 33:// 0x22 // DB error return "OTPR_PIN_NOTINIT"; //return
	 * "PIN-flag has set, but PIN is empty"; case 34:// 0x3F // db error return
	 * "OTPR_DBCORE_ERR"; //return "DB error"; case 35: return
	 * "OTPR_TKSN_INVALID"; //return "invalid token sn"; case 36: return
	 * "OTPR_USER_INACTIVE"; //return "user inactive"; //add by 2009-11-10 case
	 * 37: return "OTPR_HANDLE_INVALID"; case 38: return "OTPR_SESSID_INVALID";
	 * case 39: return "OTPR_SESS_ESTED"; case 40: return "OTPR_SESS_NOTESTED";
	 * case 41: return "OTPR_SESS_NOTEXIST"; case 42: return
	 * "OTPR_UIDTKSN_UNSET"; case 43: return "OTPR_CHLGE_INVLID"; case 44:
	 * return "OTPR_SESS_NOTNXTOTP"; case 45: return "OTPR_SESS_NOTNDPIN";
	 * 
	 * 
	 * case 55: return "OTPR_TOKEN_LOGOUT";
	 * 
	 * case 56: return "OTPR_TOKEN_TIMEOUT"; case 57: return
	 * "OTPR_AUTH_METHOD_INVALID"; case 58: return "OTPR_SUITE_INVALID"; case
	 * 59: return "OTPR_CHALLENGE_INVALID";
	 * 
	 * 
	 * case 63:// 0x3F // unknown error return "OTPR_ERR_UNKNOWN"; //return
	 * "unknown error";
	 * 
	 * default: return "OTPR_ERR_UNKNOWN"; //return "unknown error"; } }
	 * 
	 * public static String ConvertReturnCode(int nReturnCode) {
	 * switch(nReturnCode) { case OTPR_AUTH_OK: case OTPR_PIN_OK: case
	 * OTPR_SYNC_OK: case OTPR_ERRSTAT_SUCC: case OTPR_OFFLINE_SUCC: case
	 * OTPR_TKBIND_SUCC: case OTPR_TKQUERY_SUCC: case OTPR_TKUNBIND_SUCC: case
	 * OTPR_TKLOCK_SUCC: case OTPR_TKUNLOCK_SUCC: case OTPR_LGUNLOCK_SUCC: case
	 * OTPR_OK:// 0x0 // success return "0000"; case OTPR_ERR:// 0x1 // fail
	 * return "1"; case OTPR_PARAM_INVALID:// 0x2 // bad parameter return "2";
	 * case OTPR_MEM_ALLOC:// 0x3 // memory allocation failed return "3"; case
	 * OTPR_SERV_INVALID:// 0x4 // invalid server information in .acf return
	 * "4"; case OTPR_REQ_INVALID:// 0x5 // bad request return "5"; case
	 * OTPR_PACKET_INVALID:// 0x6 // bad packet return "6"; case
	 * OTPR_SOCKET_INIT:// 0x7 // init SOCKET failed return "7"; case
	 * OTPR_REQ_SEND:// 0x8 // send packet failed return "8"; case
	 * OTPR_RECV_ACK:// 0x9 // receive packet failed return "9"; case
	 * OTPR_UID_INVALID:// 0xA // invalid user return "10"; case
	 * OTPR_REQ_MANY:// 0xB // too many concurrent request return "11"; case
	 * OTPR_SECRET_INVALID:// 0xC // invalid share key of server and agent
	 * return "12"; case OTPR_NEED_SYNC:// 0xD // OTP synchronization required
	 * return "13"; case OTPR_PIN_INVALID:// 0xE // invalid PIN return "14";
	 * case OTPR_AUTHNUM_SET:// 0xF // set the base authentication number failed
	 * return "15"; case OTPR_KEY_INVALID:// 0x10 // invalid token key return
	 * "16"; case OTPR_PIN_SET:// 0x11 // set the new PIN failed on server side
	 * return "17"; case OTPR_ACK_INVALID:// 0x12 // invalid ACK return "18";
	 * case OTPR_CSINFO_INVALID:// 0x13 // invalid agent configure file return
	 * "19"; case OTPR_TOKEN_LOCKED:// 0x14 // Token has been lost. return "20";
	 * case OTPR_PROT_INVALID:// 0x15 // invalid protected type of OTP return
	 * "21"; case OTPR_OTP_INVALID:// 0x16 // invalid OTP return "22"; case
	 * OTPR_LOGIN_LOCKED:// 0x17 // token has LOGIN-Locked return "23"; case
	 * OTPR_TOKEN_INVALID:// 0x18 // invalid token information return "24"; case
	 * OTPR_TOKEN_BINDED:// 0x19 // token has binded before return "25"; case
	 * OTPR_USERTOKEN_SET:// 0x1A // failed to bind user with the token return
	 * "26"; case OTPR_UID_NOTEXIST:// 0x1B // user name doesn't exist return
	 * "27"; case OTPR_GET_USERTOKEN:// 0x1C // get the token information failed
	 * return "28"; case OTPR_BAD_REQINFO:// 0x1D // invalid user information
	 * return "29"; case OTPR_PIN_EMPTY:// 0x1E // verify PIN required return
	 * "30"; case OTPR_PIN_NEEDVERIFY:// 0x1F // OTP length exceed 6 digits
	 * return "31"; case OTPR_OTP_EXCEED:// 0x20 // PIN-flag has set, but PIN is
	 * empty return "32"; case OTPR_PIN_NOTINIT:// 0x21 // DB error return "33";
	 * case OTPR_DBCORE_ERR:// 0x3F // db error return "34"; case
	 * OTPR_TKSN_INVALID: return "35"; case OTPR_USER_INACTIVE: return "36";
	 * 
	 * //add by 2009-11-10 case OTPR_HANDLE_INVALID: return "37"; case
	 * OTPR_SESSID_INVALID: return "38"; case OTPR_SESS_ESTED: return "39"; case
	 * OTPR_SESS_NOTESTED: return "40"; case OTPR_SESS_NOTEXIST: return "41";
	 * case OTPR_UIDTKSN_UNSET: return "42"; case OTPR_CHLGE_INVLID: return
	 * "43"; case OTPR_SESS_NOTNXTOTP: return "44"; case OTPR_SESS_NOTNDPIN:
	 * return "45";
	 * 
	 * 
	 * case OTPR_TOKEN_LOGOUT: return "55";
	 * 
	 * case OTPR_TOKEN_TIMEOUT: return "56"; case OTPR_AUTH_METHOD_INVALID:
	 * return "57"; case OTPR_SUITE_INVALID: return "58"; case
	 * OTPR_CHALLENGE_INVALID: return "59";
	 * 
	 * case OTPR_ERR_UNKNOWN: return "63"; default: return "63"; } }
	 */
	public static int OTPR_OK = 0;
	public static int OTPR_ERR = 1;
	public static int OTPR_PARAM_INVALID = 2;
	public static int OTPR_REQ_INVALID = 5;
	public static int OTPR_RECV_ACK = 9;
	public static int OTPR_SECRET_INVALID = 12;
	public static int OTPR_INVALID_PACKET = 13;
	public static int OTPR_PIN_INVALID = 14;
	public static int OTPR_KEY_INVALID = 16;
	public static int OTPR_PIN_SET = 17;
	public static int OTPR_ACK_INVALID = 18;
	public static int OTPR_CSINFO_INVALID = 19;
	public static int OTPR_TOKEN_LOCKED = 20;
	public static int OTPR_OTP_INVALID = 22;
	public static int OTPR_LOGIN_LOCKED = 23;
	public static int OTPR_TOKEN_INVALID = 24;
	public static int OTPR_TOKEN_BINDED = 25;
	public static int OTPR_USERTOKEN_SET = 26;
	public static int OTPR_UID_NOTEXIST = 27;
	public static int OTPR_GET_USERTOKEN = 28;
	public static int OTPR_PIN_NEEDVERIFY = 31;
	public static int OTPR_PIN_NOTINIT = 33;
	public static int OTPR_USER_INACTIVE = 36;
	public static int OTPR_TOKEN_DISABLE = 37;
	public static int OTPR_TOKEN_LOGOUT = 38;
	public static int OTPR_HANDLE_INVALID = 39;
	public static int OTPR_SESSID_INVALID = 40;
	public static int OTPR_SESS_NOTESTED = 42;
	public static int OTPR_SESS_PENDING = 43;
	public static int OTPR_SESS_NOTEXIST = 44;
	public static int OTPR_UIDTKSN_UNSET = 45;
	public static int OTPR_CHLGE_INVLID = 46;
	public static int OTPR_AUMTHD_INVALID = 50;
	public static int OTPR_SUITE_INVALID = 51;
	public static int OTPR_TOKEN_EXPIRED = 52;
	public static int OTPR_USER_TEMP_LOCKED = 54;
	public static int OTPR_USER_LONG_LOCKED = 55;
	public static int OTPR_TOKEN_STATE_EXCEPTION = 56;
	public static int OTPR_PIN_DEATH = 57;
	public static int OTPR_OTP_LENNOTEQUAL_EMPIN = 58;
	public static int OTPR_ADD_USER = 59;
	public static int OTPR_TOKEN_REPEAT_BIND = 61;
	public static int OTPR_USER_TOKEN_NOTDOMAIN = 62;
	public static int OTPR_USER_OLD_PIN = 63;
	public static int OTPR_USER_OLDPIN_EQ_NEWPIN = 64;
	public static int OTPR_USER_TOKEN_NOTORG = 65;
	public static int OTPR_REPLACE_TOKEN_FAILED = 66;
	public static int OTPR_GEN_CHALLENGE_FAILED = 67;
	public static int OTPR_NOT_AGENTCONF = 68;
	public static int OTPR_EMPIN_DEATH = 69;
	public static int OTPR_EMPIN_INVALID = 70;
	public static int OTPR_SYNC_FAILED = 71;
	public static int OTPR_TOKEN_TEMP_LOCKED = 72;
	public static int OTPR_TOKEN_LONG_LOCKED = 73;
	public static int OTPR_PWD_LEN_ERR = 74;
	public static int OTPR_ERR_UNKOWN = 79;
	public static int OTPR_USER_TOKEN_NOBIND = 80;
	public static int OTPR_NOFIND_THIRD_AUTH_CONF = 81;
	public static int OTPR_LDPA_THIRD_AUTH = 82;
	public static int OTPR_GEN_AC_INVALID = 83;
	public static int OTPR_GEN_AC_ENABLED = 84;
	public static int OTPR_GEN_AC_EXPIRE = 85;
	public static int OTPR_GEN_AC_UDID_ERR = 86;
	public static int OTPR_GEN_AC_LOCKED = 87;
	public static int OTPR_PUK1MODE_NONSUPPORT = 88;
	public static int OTPR_PUK2MODE_NONSUPPORT = 89;
	public static int OTPR_TOKENEXT_NULL = 90;
	public static int OTPR_USER_BIND_MORE_TOKEN = 91;
	public static int OTPR_ACPWD_INVLID = 92;
	public static int OTPR_MBID_INVLID = 93;
	public static int OTPR_HA_INIT = 94;
	public static int OTPR_GEN_OTP_FAILED = 95;
	public static int OTPR_NOFIND_SMS_TOKEN = 96;
	public static int OTPR_NULL_PHONE = 97;
	public static int OTPR_SMS_SEND_FAILED = 98;
	public static int OTPR_SERVER_CODE_ERR = 99;
	public static int OTPR_ACTIVE_CODE_ERR = 100;
	public static int OTPR_CHALLENGE_LEN_ERR = 101;
	public static int OTPR_OPER_FAILED = 102;
	public static int OTPR_THIRD_AUTH_FILTER_ERR = 103;
	public static int OTPR_GEN_CHLG_FAIL = 104;
	public static int OTPR_TKBIND_EXCEED = 105;
	public static int OTPR_USERBIND_EXCEDD = 106;
	public static int OTPR_SMS_BIND_NOTTOKEN = 107;
}
