package org.signserver.webbjob;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.*;

import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebService;
import javax.naming.NamingException;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;
import javax.jws.HandlerChain;

import org.apache.log4j.Logger;
import java.io.*;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.apache.commons.io.IOUtils;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.signserver.common.*;
import org.signserver.common.util.*;
import org.signserver.common.dbdao.*;

/**
 *
 * @author PHUONGVU
 */
public class WebBJOB extends HttpServlet {
	private static final Logger LOG = Logger.getLogger(WebBJOB.class);
	private static final String OPERATION_MODE_STANDALONE = "standalone";
	private static final String OPERATION_MODE_HA = "ha";
	private static final String INTERVAL = "1800000";
	
	static {
		final Properties properties = DBConnector.getInstances().getPropertiesConfig();
		
		if(Boolean.parseBoolean(properties.getProperty("appserver.crl.enable", "false"))) {
			final int crlInterval = Integer.parseInt(properties.getProperty("appserver.crl.interval", "30")) * 60 * 1000;
			new Thread(new Runnable() {
				@Override
				public void run() {
					try {
						LOG.info("Initializing Trusted Hub Job!");
						TimerTask task = new TrustedHubTask();
		                Timer timer = new Timer();
		                timer.schedule(task, 5000, crlInterval); // start after 5 seconds and repeat in every 50 minutes
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			}).start();
		}
		
		final GeneralPolicy gp = DBConnector.getInstances().getGeneralPolicy();
		if(properties.getProperty("appserver.operationmode", OPERATION_MODE_HA)
				.compareTo(OPERATION_MODE_HA) == 0) {
			new Thread(new Runnable() {
				@Override
				public void run() {
					try {
						LOG.info("Initializing Monitoring Job!");
						TimerTask task = new MonitoringTask();
		                Timer timer = new Timer();
		                //String ha_interval = properties.getProperty("appserver.ha.intervalcheck", INTERVAL);
		                //timer.schedule(task, 120000, Integer.valueOf(ha_interval).intValue());
		                int ha_interval = gp.getFrontHAIntervalCheck();
		                timer.schedule(task, 120000, (ha_interval * 60 * 1000));
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			}).start();
		}
	}

	/**
	 * Processes requests for both HTTP <code>GET</code> and <code>POST</code>
	 * methods.
	 *
	 * @param request
	 *            servlet request
	 * @param response
	 *            servlet response
	 * @throws ServletException
	 *             if a servlet-specific error occurs
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	protected void processRequest(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html;charset=UTF-8");
		PrintWriter out = response.getWriter();
		try {
			/* TODO output your page here. You may use following sample code. */
			out.println("<!DOCTYPE html>");
			out.println("<html>");
			out.println("<head>");
			out.println("<title>Servlet CAGSocketGateWay</title>");
			out.println("</head>");
			out.println("<body>");
			out.println("<h1>Servlet CAGSocketGateWay at "
					+ request.getContextPath() + "</h1>");
			out.println("</body>");
			out.println("</html>");
		} finally {
			out.close();
		}
	}

	// <editor-fold defaultstate="collapsed"
	// desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
	/**
	 * Handles the HTTP <code>GET</code> method.
	 *
	 * @param request
	 *            servlet request
	 * @param response
	 *            servlet response
	 * @throws ServletException
	 *             if a servlet-specific error occurs
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		processRequest(request, response);
	}

	/**
	 * Handles the HTTP <code>POST</code> method.
	 *
	 * @param request
	 *            servlet request
	 * @param response
	 *            servlet response
	 * @throws ServletException
	 *             if a servlet-specific error occurs
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	@Override
	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		processRequest(request, response);
	}

	/**
	 * Returns a short description of the servlet.
	 *
	 * @return a String containing servlet description
	 */
	@Override
	public String getServletInfo() {
		return "Short description";
	}// </editor-fold>
}