/*
 *  Copyright 2018-2021 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.webapps.fwp;

import java.io.IOException;

import java.util.GregorianCalendar;

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.fwp.IssuerRequest;
import org.webpki.fwp.PSPRequest;

import org.webpki.json.JSONParser;

/**
 * PSP step.
 *
 */
public class PSPServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(PSPServlet.class.getName());

    private static final long serialVersionUID = 1L;
    
    public static final String PSP_REQUEST = "pspRequest";
    
    // DIV elements to turn on and turn off.
    private static final String WAITING_ID     = "wait";
    private static final String ACTIVATE_ID    = "activate";
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        request.setCharacterEncoding("utf-8");
        String pspRequest = request.getParameter(PSP_REQUEST);
        if (pspRequest == null) {
            FWPWalletCore.failed("Missing PSP request");
            return;
        }
        IssuerRequest issuerRequest = 
                new IssuerRequest(new PSPRequest(JSONParser.parse(pspRequest)),
                                  // This is wrong, merchant hosts are stored in a PSP database
                                  request.getServerName(),
                                  new GregorianCalendar());
        StringBuilder html = new StringBuilder(
            "<form name='shoot' method='POST' action='issuerreq'>" +
            "<input type='hidden' name='" + IssuerServlet.ISSUER_REQUEST +
            "' value='")
        .append(HTML.encode(issuerRequest.serialize(), false))
        .append(
            "'/>" +
            "</form>" +

            "<div class='header'>PSP Action</div>" +

            "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
              "<div class='comment'>" +
              "This part is still to be written..." +
              "<div style='margin-top:0.4em'>Thanx for testing anyway!</div>" +
              "</div>" +
            "</div>" +
              
            "<div style='display:flex;justify-content:center'>" +
              "<img id='" + WAITING_ID + "' src='images/waiting.gif' " +
                 "style='padding-top:2em;display:none' alt='waiting'/>" +
            "</div>" +  
              
            "<div style='display:flex;justify-content:center'>" +
              "<div id='" + ACTIVATE_ID + "' class='stdbtn' onclick=\"doReturn()\">" +
                  "Send Request to Issuer" +
              "</div>" +
            "</div>" +
        
            "<div class='staticbox'>")
        .append(HTML.encode(issuerRequest.toString(), true))
        .append(
            "</div>");
        String js = new StringBuilder(
        
        FWPWalletCore.GO_HOME_JAVASCRIPT +
  
        "function doReturn() {\n" +
        "  document.getElementById('" + ACTIVATE_ID + "').style.display = 'none';\n" +
        "  document.getElementById('" + WAITING_ID + "').style.display = 'block';\n" +
        "  setTimeout(function() {\n" +
        "    document.forms.shoot.submit();\n" +
        "  }, 1000);\n" +
        "}\n").toString();
        
        HTML.standardPage(response, js, html);
    }
}
