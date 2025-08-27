package org.signserver.socket;

import java.util.HashMap;

public class SessionManager {
	private static HashMap<String, Session> sessions = new HashMap<String, Session>();
	private static SessionManager instance = null;
	
	public static SessionManager getInstance() {
		if(instance == null) {
			instance = new SessionManager();
		}
		return instance;
	}
	
	public Session getSession(String timestamp) {
		return sessions.get(timestamp);
	}
	
	public void setSession(String timestamp, Session session) {
		sessions.put(timestamp, session);
	}
	
	public void removeSession(String timestamp) {
		System.out.println("Remove session: "+timestamp);
		sessions.remove(timestamp);
	}
	
	public HashMap<String, Session> getSessions() {
		return sessions;
	}
}