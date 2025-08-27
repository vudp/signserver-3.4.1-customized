package org.signserver.webbjob;

import java.util.*;
import org.apache.log4j.Logger;
import org.signserver.common.*;
import org.signserver.common.dbdao.*;

public class TrustedHubTask extends TimerTask {

    private final Logger log = Logger.getLogger(TrustedHubTask.class);

    @Override
    public void run() {
        log.info("Crl Job has been started");
        Date date = new Date();   // given date
        Calendar calendar = GregorianCalendar.getInstance(); // creates a new calendar instance
        calendar.setTime(date);   // assigns calendar to given date 
        int hour = calendar.get(Calendar.HOUR_OF_DAY); // gets hour in 24h format
        if (hour == 1) {
            ArrayList<Ca> cas = DBConnector.getInstances().getCAProviders();
            for (int i = 0; i < cas.size(); i++) {
                QueryCrl.reloadCrlFile(cas.get(i).getCrlUrl(), cas.get(i).getCrlPath(), cas.get(i).getCaDesc(), true, false, cas.get(i).getEndPointConfigID());
            }
        }
    }
}