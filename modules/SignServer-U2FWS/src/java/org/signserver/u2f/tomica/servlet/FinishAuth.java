/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.u2f.tomica.servlet;

import org.apache.log4j.Logger;
import org.signserver.u2f.tomica.config.*;
import org.signserver.u2f.yubico.u2f.data.DeviceRegistration;
import org.signserver.u2f.yubico.u2f.data.messages.AuthenticateRequestData;
import org.signserver.u2f.yubico.u2f.data.messages.AuthenticateResponse;
import org.signserver.u2f.yubico.u2f.exceptions.DeviceCompromisedException;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;

import org.signserver.common.DBConnector;
import org.apache.log4j.Logger;
/**
 *
 * @author TOMICA
 */
public class FinishAuth extends HttpServlet {
	private static final Logger log = Logger.getLogger(FinishAuth.class);
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
        String TokenResponse = request.getParameter("TokenResponse");
        String Username = request.getParameter("Username");
        log.info("Username: "+Username);
        log.info("TokenResponse: "+TokenResponse);
        String responseData = "";
        if(TokenResponse != null && Username != null &&
        		TokenResponse.compareTo("") != 0 && Username.compareTo("") != 0) {
        	DeviceRegistration registration = null;
        	try {
	            AuthenticateResponse authenticateResponse = AuthenticateResponse
	                            .fromJson(TokenResponse);
	
	            AuthenticateRequestData authenticateRequest = AuthenticateRequestData
	                            .fromJson(DBConnector.getInstances().fido_DeleteRequest(authenticateResponse
	                                            .getRequestId()));
        
                registration = Config.u2f.finishAuthentication(authenticateRequest,
                                authenticateResponse, getRegistrations(Username));
                
                responseData = Config.createResponse(Define.CODE_SUCCESS
            			, Define.MESS_SUCCESS, null);
                log.info("Response FinishAuth servlet: "+responseData);
            } catch (DeviceCompromisedException e) {
                    responseData = "Device possibly compromised and therefore blocked: "
                                    + e.getMessage();
                    responseData = Config.createResponse(Define.CODE_U2FEXP
                			, Define.MESS_U2FEXP+Define.SEPERATE+responseData, null);
            } catch (Exception e) {
            	log.error(e.getMessage());
        		responseData = Config.createResponse(Define.CODE_U2FEXP
            			, Define.MESS_U2FEXP+Define.SEPERATE+e.getMessage(), null);
			} finally {
                    Config.userStorage.getUnchecked(Username).put(
                                    registration.getKeyHandle(), registration.toJson());
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
 
    private Iterable<DeviceRegistration> getRegistrations(String username) {
            List<DeviceRegistration> registrations = new ArrayList<DeviceRegistration>();
            for (String serialized : DBConnector.getInstances().fido_getUserRegisterValue(username)) {

                    registrations.add(DeviceRegistration.fromJson(serialized));
            }
            return registrations;
    }
}
