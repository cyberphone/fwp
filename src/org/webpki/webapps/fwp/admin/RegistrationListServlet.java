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
package org.webpki.webapps.fwp.admin;

import java.io.IOException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.webapps.fwp.Actors;
import org.webpki.webapps.fwp.HTML;
import org.webpki.webapps.fwp.ApplicationService;
/**
 * For listing site activity...
 *
 */
public class RegistrationListServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(RegistrationListServlet.class.getName());

    private static final long serialVersionUID = 1L;
    
    String convertToOptionalString(int value) {
        return "</td><td style='text-align:center'>" + (value == 0 ? "-" : String.valueOf(value));
    }
    
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        request.setCharacterEncoding("utf-8");
        try {
            StringBuilder html = new StringBuilder(
                "<div class='header'>Successful Registrations</div>" +
            
                "<div style='display:flex;justify-content:center;margin-top:1.5em'>" +
                "<table class='tftable'><tr>" +
                "<th style='text-align:center'>User ID</th>" +
                "<th style='text-align:center'>Created</th>" +
                "<th style='text-align:center'>IP Address</th>" +
                "<th style='text-align:center'>Host Name</th>" +
                "<th style='text-align:center'>WebAuthn</th>" +
                "<th style='text-align:center'>Basic Buy</th>" +
                "<th style='text-align:center'>FWP Steps</th><tr>");

            try (Connection connection = ApplicationService.jdbcDataSource.getConnection();) {
                try (PreparedStatement stmt = connection.prepareStatement(
                        "SELECT UserId, Created, ClientIpAddress, " +
                          "ClientHost, WebAuthn, BasicBuy, FWPSteps from USERS " +
                        "WHERE PublicKey IS NOT NULL " +
                        "ORDER BY Created DESC LIMIT 100;");) {
                    try (ResultSet rs = stmt.executeQuery();) {
                        while (rs.next()) {
                            String host = rs.getString(4);
                            html.append("<tr><td>")
                                .append(rs.getString(1))
                                .append("</td><td>")
                                .append(rs.getString(2))
                                .append("</td><td>")
                                .append(rs.getString(3))
                                .append("</td><td>")
                                .append(host == null ? "<div style='text-align:center'>-</div>" : host)
                                .append(convertToOptionalString(rs.getInt(5)))
                                .append(convertToOptionalString(rs.getInt(6)))
                                .append(convertToOptionalString(rs.getInt(7)))
                                .append("</td></tr>");
                        }
                    }
                }
            }
            
            html.append("</table>" +
                        "</div>");
            
            HTML.standardPage(response, Actors.ADMIN, null, html);
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
}
