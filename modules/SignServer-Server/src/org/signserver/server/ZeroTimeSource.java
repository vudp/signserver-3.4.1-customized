package org.signserver.server;

import java.util.Date;
import java.util.Properties;

/**
 * Simple class implementing the ITimeSource interface
 * always returns time 0.
 * This is mainly intended to use for testing to get a
 * predictable non-null time value.
 * 
 * @author Marcus Lundblad
 * @version $Id: ZeroTimeSource.java 2878 2012-10-23 14:25:08Z malu9369 $
 *
 */
public class ZeroTimeSource implements ITimeSource {

	@Override
	public void init(Properties props) {
		// no properties defined
	}

	@Override
	public Date getGenTime() {
		return new Date(0);
	}

}
