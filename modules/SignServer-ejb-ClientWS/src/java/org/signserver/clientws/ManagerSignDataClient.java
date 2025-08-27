package org.signserver.clientws;

import org.signserver.clientws.SignProcessObject;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


public class ManagerSignDataClient {
	private Map<String,SignProcessObject> mapData ;
	private static ManagerSignDataClient instance = null;
	
	
	public ManagerSignDataClient() {
		mapData = new ConcurrentHashMap<String, SignProcessObject>();
	}
	
	public static ManagerSignDataClient getInstance() {
		if (instance == null) {
			instance = new ManagerSignDataClient();
		}
		return instance;
	}
	
	public void insertNewObject(String key, SignProcessObject obj) {		
		mapData.put(key,obj);		
	}
	
	public SignProcessObject getObjectWithKey(String key) {
		SignProcessObject obj = mapData.get(key);
		return obj;
	}
	
	public void removeObjectWithKey(String key) {
		mapData.remove(key);
	}
}