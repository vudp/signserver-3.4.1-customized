package xades4j.providers.impl;

import com.google.inject.Inject;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.providers.TimeStampTokenGenerationException;
import xades4j.utils.Base64;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import javax.xml.bind.DatatypeConverter;

import org.signserver.common.*;
import org.signserver.common.util.*;
import org.signserver.common.dbdao.*;

/**
 * Implementation of {@code AbstractTimeStampTokenProvider} that gets time-stamp tokens
 * from a HTTP TSA. Requests are issued with {@code certReq} set to
 * {@code true}. If username and password are set supplied, HTTP basic
 * authenticated will be used.
 *
 * @author PHUONGVU
 */
public class EndpointTSAProvider extends AbstractTimeStampTokenProvider {
	
	private String tsaProvider;
	private int trustedhubTransId;
	private String channelName;
	private String user;

    @Inject
    public EndpointTSAProvider(MessageDigestEngineProvider messageDigestProvider, String tsaProvider, String channelName, String user, int trustedhubTransId) {
        super(messageDigestProvider);
        this.tsaProvider = tsaProvider;
        this.trustedhubTransId = trustedhubTransId;
        this.channelName = channelName;
        this.user = user;
    }
    
    @Override
    protected byte[] getResponse(byte[] encodedRequest) throws TimeStampTokenGenerationException {
        try {
        	/*
        	String[] endpointParams = DBConnector.getInstances().authEndPointParamsGet(Defines.CONNECTION_PARAMS_TSA);
        	EndpointServiceResp endpointServiceResp = EndpointService.getInstance().getTSAResponse(null, null
        			, encodedRequest, endpointParams[1], Integer.parseInt(endpointParams[2]));
        	
        	if(endpointServiceResp.getResponseCode() == 0) {
        		return endpointServiceResp.getResponseData();
        	} else {
        		throw new TimeStampTokenGenerationException("Error while requesting TSA server. Details: "+endpointServiceResp.getResponseCode());
        	}
        	*/
        	Tsa tsa =  DBConnector.getInstances().getTSA(this.tsaProvider);
        	
        	String tsaUrl = tsa.getTsaUrl();
        	String user = tsa.getUser();
        	String password = tsa.getPassword();
        	
        	String tsaConfig = null;
        	if(user != null && password != null) {
    	    	tsaConfig = "TSA_URL="+tsaUrl+"\n"+
    	    						"TSA_USERNAME="+user+"\n"+
    	    						"TSA_PASSWORD="+password;
        	} else {
        		tsaConfig = "TSA_URL="+tsaUrl;
        	}
        	
        	if(tsa == null) {
        		throw new TimeStampTokenGenerationException("Error while requesting TSA server. Details: No TSA provider found in system");
        	}
        	
        	EndpointServiceResp endpointServiceResp = EndpointService.getInstance().getTSAResponse(this.channelName, this.user
        			, encodedRequest, tsaConfig, tsa.getEndpointConfigId(), this.trustedhubTransId);
        	
        	if(endpointServiceResp.getResponseCode() == 0) {
        		return endpointServiceResp.getResponseData();
        	} else {
        		throw new TimeStampTokenGenerationException("Error while requesting TSA server. Details: "+endpointServiceResp.getResponseCode());
        	}
        } catch(Exception e) {
        	throw new TimeStampTokenGenerationException(e.toString());
        }
    }
}