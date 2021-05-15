/*
 *  Copyright 2018-2020 WebPKI.org (http://webpki.org).
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

import java.sql.Connection;

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class WalletAdminServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(WalletAdminServlet.class.getName());

    private static final long serialVersionUID = 1L;
    
    static final String WALLET_ADMIN_BUTTON =
            "<tr><td><div class='multibtn' onclick=\"document.location.href='walletadmin'\">" +
                "Wallet Administration..." +
            "</div></td></tr>" +
            "</table>";

    
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            StringBuilder html = new StringBuilder(
                "<div class='header'>Wallet Administration</div>" +
    
                "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
                  "<div class='comment'>" +
                    "The &quot;Wallet&quot; is a central part of FWP since it holds all " +
                    "related payment cards" +
                  "</div>" +
                "</div>");
    
            html.append(EnrollServlet.hasPaymentCards(request) ?
    
                "<form name='shoot' method='POST' action='walletadmin'></form>" +
                "<div style='display:flex;justify-content:center'>" +
                  "<div class='stdbtn' onclick=\"document.forms.shoot.submit()\">" +
                    "Delete Cards!" +
                  "</div>" +
                "</div>"
                                              :
                "<div class='important'>" +
                  "You currently have no payment cards" +
                "</div>");
    
            HTML.standardPage(response, null, html);
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            // The user ID is stored in a persistent cookie.
            String userId = EnrollServlet.getWalletCookie(request);
            
            // This is the only database call needed for deleting payment cards (all of them...).
            try (Connection connection = FWPService.jdbcDataSource.getConnection();) {
                DataBaseOperations.deletePaymentCards(userId, connection);
            }
            
            // Tell the user that it worked...
            StringBuilder html = new StringBuilder(
                    "<form name='shoot' method='POST' action='hash'>" +
                    "<div class='header'>Payment Cards Deleted</div>" +
                    "<div style='display:flex;justify-content:center;margin-top:15pt'>")
                .append("Thank you testing.  We hope that you liked it!")
                .append(
                    "</div>" +
                    "</form>");
            HTML.standardPage(response, null, html);

            logger.info("Deleted payment cards for user: " + userId);
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
}
