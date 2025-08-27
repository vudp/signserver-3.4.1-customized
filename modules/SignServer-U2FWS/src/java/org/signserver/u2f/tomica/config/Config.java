package org.signserver.u2f.tomica.config;

import java.util.HashMap;
import java.util.Map;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import org.signserver.u2f.yubico.u2f.U2F;
import org.signserver.u2f.json.JSONObject;

public class Config {
	public static final String APP_ID = "https://192.168.1.138";
	public static final U2F u2f = new U2F(false);
	public static final Map<String, String> requestStorage = new HashMap<String, String>();
	public static final LoadingCache<String, Map<String, String>> userStorage = CacheBuilder.newBuilder().build(new CacheLoader<String, Map<String, String>>() {
        @Override
        public Map<String, String> load(String key) throws Exception {
            return new HashMap<String, String>();
        }
    });
	
	public static final String TYPE_REGISTER = "REGISTER";
	public static final String TYPE_AUTHENTICATION = "AUTHENTICATE";
	public static final String KEY_DATA ="DATA";
	public static final String KEY_REGISTRATION = "registration";
	
	
	public static String createResponse(int responseCode, String responseMessage, String currentJson) {
		if(currentJson == null)
			currentJson = "{}";
		JSONObject json = new JSONObject(currentJson);
		json.put("responseCode", String.valueOf(responseCode));
		json.put("responseMessage", responseMessage);
		return json.toString();
	}
}
