/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.u2f.tomica.servlet;

import org.signserver.u2f.tomica.config.*;
import org.signserver.u2f.yubico.u2f.data.DeviceRegistration;
import org.signserver.u2f.yubico.u2f.data.messages.RegisterRequestData;
import org.signserver.u2f.yubico.u2f.data.messages.RegisterResponse;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.cert.CertificateException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.signserver.common.DBConnector;
import org.apache.log4j.Logger;

/**
 *
 * @author TOMICA
 */
public class FinishRegister extends HttpServlet {
	private static final Logger log = Logger.getLogger(FinishRegister.class);
    /**
     * Processes requests for both HTTP <code>GET</code> and <code>POST</code>
     * methods.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        String tokenResponse = request.getParameter("TokenResponse");
        String username = request.getParameter("Username"); 
        log.info("Username: "+username);
        log.info("TokenResponse: "+tokenResponse);
        String responseData = "";
        if(tokenResponse != null && username != null &&
        		tokenResponse.compareTo("") != 0 && username.compareTo("") != 0) {
        	try {
	            RegisterResponse registerResponse = RegisterResponse.fromJson(tokenResponse);
	            RegisterRequestData registerRequestData = RegisterRequestData
	                            .fromJson(DBConnector.getInstances().fido_DeleteRequest(registerResponse
	                            .getRequestId()));
	            DeviceRegistration registration = Config.u2f.finishRegistration(
	                            registerRequestData, registerResponse);
	            addRegistration(username, registration);
	
	            responseData = Config.createResponse(Define.CODE_SUCCESS
	        			, Define.MESS_SUCCESS, registration.toJson());
	            log.info("Response FinishRegister servlet: "+responseData);
        	} catch(Exception e) {
        		log.error(e.getMessage());
        		responseData = Config.createResponse(Define.CODE_U2FEXP
            			, Define.MESS_U2FEXP+Define.SEPERATE+e.getMessage(), null);
        	}
        } else {
        	responseData = Config.createResponse(Define.CODE_BADREQUEST
        			, Define.MESS_BADREQUEST, null);
        }
        
        PrintWriter out = response.getWriter();
        try {
            out.println(responseData);
        } finally {
            out.close();
        }
    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
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
 
    private void addRegistration(String username,
                    DeviceRegistration registration) {
            try {
            	DBConnector.getInstances().fido_InsertUserRegister(username, registration.getKeyHandle(),
                    registration.toJson(), registration.getAttestationCert(), registration.getAttestationCertificate().toString());
            } catch (CertificateException e) {
            	e.printStackTrace();
            } catch (NoSuchFieldException e) {
            	e.printStackTrace();
            }
            log.info("FinishRegister - addRegistration-" + username + "-"
                            + registration.getKeyHandle() + "-" + registration.toJson());
    }
}
