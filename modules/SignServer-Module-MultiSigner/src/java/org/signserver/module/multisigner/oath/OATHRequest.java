package org.signserver.module.multisigner.oath;

import org.signserver.common.*;
import org.signserver.module.multisigner.*;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.WorkerContext;
import org.signserver.server.signers.BaseSigner;

import javax.persistence.EntityManager;

import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;

import java.io.*;
import java.util.*;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;

import javax.xml.bind.DatatypeConverter;

import java.util.LinkedList;
import java.util.List;

import org.apache.log4j.Logger;
import org.signserver.server.BaseProcessable;
import org.signserver.validationservice.common.ValidateRequest;
import org.signserver.validationservice.common.ValidationServiceConstants;

import java.text.SimpleDateFormat;

import org.signserver.common.util.*;

public class OATHRequest {
	
	private static OATHRequest instance;
	public static OATHRequest getInstance() {
		if(instance == null) {
			instance = new OATHRequest();
		}
		return instance;
	} 

	private static final Logger LOG = Logger.getLogger(OATHRequest.class);
    
	private static final String CONTENT_TYPE = "text/xml";
	private static String WORKERNAME = "OATHRequest";
	private int ResponseCode = Defines.CODE_INTERNALSYSTEM;
	private String ResponseMessage = Defines.ERROR_INTERNALSYSTEM;

	public MultiSignerResponse processData(String channelName, String user) {
		// TODO Auto-generated method stub
		MultiSignerResponse signResponse;

		String str_secert = channelName+"#"+user;
		byte[] secretBytes = str_secert.getBytes();
		
		String timeStamp = new SimpleDateFormat("yyyyMMddHHmmssS").format(Calendar.getInstance().getTime());
		Long l = Long.valueOf(timeStamp);
		
		int digits = DBConnector.getInstances().authGetOTPDigits(channelName, user);
		String s = "";
		try {
			s = RFC4226.generateOTP(secretBytes, l, digits, false, -1);
		} catch(NoSuchAlgorithmException e) {
			e.printStackTrace();
			LOG.error("NoSuchAlgorithmException. Details: "+e.getMessage());
			return new MultiSignerResponse(Defines.CODE_INTERNALSYSTEM, Defines.ERROR_INTERNALSYSTEM);
		} catch(InvalidKeyException e) {
			e.printStackTrace();
			LOG.error("NoSuchAlgorithmException. Details: "+e.getMessage());
			return new MultiSignerResponse(Defines.CODE_INTERNALSYSTEM, Defines.ERROR_INTERNALSYSTEM);
		}
		LOG.info("User: "+user+" OTP: "+s);
		ResponseCode = Defines.CODE_SUCCESS;
		ResponseMessage = Defines.SUCCESS;
		
		signResponse = new MultiSignerResponse(s.getBytes(), ResponseCode, ResponseMessage);
        return signResponse;
	}
}
