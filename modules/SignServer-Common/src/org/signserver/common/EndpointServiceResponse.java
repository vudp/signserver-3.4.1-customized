package org.signserver.common;

import vn.mobile_id.endpoint.service.datatype.*;
import vn.mobile_id.endpoint.service.datatype.params.*;
import vn.mobile_id.endpoint.client.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.signserver.common.dbdao.*;
import org.signserver.common.util.*;
import org.apache.log4j.Logger;
import java.util.*;

public class EndpointServiceResponse {
	
	private int endpointId;
	private Response response;
	
	public EndpointServiceResponse(int endpointId, Response response) {
		this.endpointId = endpointId;
		this.response = response;
	}
	
	public int getEndpointId() {
		return endpointId;
	}
	public void setEndpointId(int endpointId) {
		this.endpointId = endpointId;
	}
	public Response getResponse() {
		return response;
	}
	public void setResponse(Response response) {
		this.response = response;
	}
	
}