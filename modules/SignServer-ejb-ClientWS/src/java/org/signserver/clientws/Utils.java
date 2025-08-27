package org.signserver.clientws;

import com.google.gson.Gson;
import org.signserver.common.util.*;

public class Utils {
	
	private static Gson gson = new Gson();
	
	public static String processTransactionInfo(TransactionInfo transInfo) {
		if(transInfo != null) {
			TransactionInfo clone = new TransactionInfo();
			clone = clone(transInfo);
			if(clone.getFileData() != null) {
				clone.setFileData(new byte[4]);
			}
			String json = gson.toJson(clone);
			return json;
		}
		return Defines.NULL;
	}
	
	private static TransactionInfo clone(TransactionInfo transInfo) {
		TransactionInfo clone = new TransactionInfo();
		clone.setCredentialData(transInfo.getCredentialData());
		
		String requestData = transInfo.getXmlData();
		// re-process xmlData Request to hide sensitive data
		requestData = ExtFunc.replaceContentInXmlTag(requestData, Defines._PASSWORD, Defines._HIDDENPASSWORD);
		requestData = ExtFunc.replaceContentInXmlTag(requestData, Defines._SIGNATUREIMAGE, Defines._BASE64DATA);
		
		clone.setXmlData(requestData);
		clone.setFileData(transInfo.getFileData());
		clone.setBase64FileData("BASE64FILEDATA");
		return clone;
	}
}