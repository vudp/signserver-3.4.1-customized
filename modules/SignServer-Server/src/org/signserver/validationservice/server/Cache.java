package org.signserver.validationservice.server;

import java.util.HashMap;
import java.util.Map;

public class Cache {

    private static final Cache singleton = new Cache();
    private Map<String, DCStream> cache = new HashMap<String, DCStream>();

    private Cache() {}

    public static Cache getInstance() {
        return singleton;
    }

    public void put(String id, DCStream data) {
        cache.put(id, data);
    }

    public DCStream get(String id) {
        return cache.get(id);
    }
}