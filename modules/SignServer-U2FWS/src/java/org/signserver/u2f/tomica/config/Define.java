package org.signserver.u2f.tomica.config;

public class Define {
	public static final String			SEPERATE			= "		";
	
	public static final int				CODE_SUCCESS			= 0;
	public static final int 			CODE_BADREQUEST 		= 1;
	public static final int 			CODE_U2FEXP		 		= 2;
	public static final int 			CODE_USERNOTREGISTER	= 3;
	
	public static final String			MESS_SUCCESS			= "SUCCESS";
	public static final String			MESS_BADREQUEST			= "BAD REQUEST";
	public static final String			MESS_U2FEXP				= "U2F EXCEPTION";
	public static final String			MESS_USERNOTREGISTER	= "USER NOT REGISTERED";
}
