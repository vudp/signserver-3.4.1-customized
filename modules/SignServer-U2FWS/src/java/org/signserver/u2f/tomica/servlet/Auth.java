/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.u2f.tomica.servlet;

import org.signserver.u2f.tomica.config.*;
import org.signserver.u2f.tomica.model.TokenInfo;
import org.signserver.u2f.yubico.u2f.data.DeviceRegistration;
import org.signserver.u2f.yubico.u2f.data.messages.AuthenticateRequestData;
import org.signserver.u2f.yubico.u2f.exceptions.NoEligableDevicesException;
import org.signserver.u2f.yubico.u2f.exceptions.U2fBadInputException;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

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
public class Auth extends HttpServlet {
	private static final Logger log = Logger.getLogger(Auth.class);
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
        String responseData= "";
        String Username = request.getParameter("Username");
        if(Username != null && Username.compareTo("") != 0) {
            AuthenticateRequestData authenticateRequestData = null;
            TokenInfo tk = new TokenInfo();
            tk.setUsername(Username);
            tk.setSuccess(true);
            try {
                    authenticateRequestData = Config.u2f
                                    .startAuthentication(Config.APP_ID, getRegistrations(Username));
                    putToRequestStorage(Username, authenticateRequestData.getRequestId(), authenticateRequestData.toJson(), Config.TYPE_AUTHENTICATION);
                    tk.setTokenResponse(authenticateRequestData.toJson());
                    responseData = Config.createResponse(Define.CODE_SUCCESS
                			, Define.MESS_SUCCESS, tk.toJson());
                    log.info("Response Auth servlet: "+responseData);
            } catch (U2fBadInputException e) {			
                    tk.setSuccess(false);
                    responseData = Config.createResponse(Define.CODE_U2FEXP
                			, Define.MESS_U2FEXP+Define.SEPERATE+e.getMessage(), tk.toJson());
            } catch (NoEligableDevicesException e) {			
                    tk.setSuccess(false);
                    tk.setError(Define.MESS_USERNOTREGISTER);
                    responseData = Config.createResponse(Define.CODE_USERNOTREGISTER
                			, Define.MESS_USERNOTREGISTER, tk.toJson());
            } catch (Exception e) {
            	log.error(e.getMessage());
        		responseData = Config.createResponse(Define.CODE_U2FEXP
            			, Define.MESS_U2FEXP+Define.SEPERATE+e.getMessage(), null);
			}
        } else {
        	responseData = Config.createResponse(Define.CODE_BADREQUEST
        			, Define.MESS_BADREQUEST, null);
        }
        
        
        // response
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
    
    private void putToRequestStorage(String username, String requestID,
                    String data, String type) {
    	DBConnector.getInstances().fido_InsertRequest(username, requestID, data, type);
    }
}
