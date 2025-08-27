package org.signserver.webactivesigner;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;

import org.signserver.common.*;
import org.signserver.common.util.*;

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
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.*;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.CertificateClientCredential;
import org.signserver.server.IClientCredential;
import org.signserver.server.UsernamePasswordClientCredential;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;

import java.io.*;

import org.signserver.common.*;
import org.signserver.common.util.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import org.apache.commons.io.IOUtils;

import javax.xml.ws.handler.soap.SOAPMessageContext;
import org.signserver.adminws.*;
/**
 *
 * @author PHUONGVU
 */
public class WebActiveSigner extends HttpServlet {
	private static final Logger LOG = Logger.getLogger(WebActiveSigner.class);
	private static String localWorkerName;
	private static final String HTTP_AUTH_BASIC_AUTHORIZATION = "Authorization";
	private static Properties config = null;
	// @Resource
	// private WebServiceContext wsContext;

	@EJB
	private static IWorkerSession.ILocal workersession;

	private static final Random random = new Random();

	static {
                final Properties properties = DBConnector.getInstances().getPropertiesConfig();
                if(Boolean.parseBoolean(properties.getProperty("appserver.signer.activate.enable", "false"))) {
                    new Thread(new Runnable() {
                            @Override
                            public void run() {
                                    try {
                                            LOG.info("Active worker by getting their brief status");
                                            WorkerCommandLine.getInstance().getAllWorkerStatus();
                                    } catch (Exception e) {
                                            e.printStackTrace();
                                    }
                            }
                    }).start();
                }
	}

	private static IWorkerSession.ILocal getWorkerSession() {
		if (workersession == null) {
			try {
				workersession = ServiceLocator.getInstance().lookupLocal(
						IWorkerSession.ILocal.class);
			} catch (NamingException e) {
				LOG.error(e);
			}
		}
		return workersession;
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