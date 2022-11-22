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

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 
 * Provides filled-in card images to the WalletUIServlet
 *
 */
public class CardServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    
    static final String ACCOUNT = "p1";
    static final String USER = "p2";
    
    String getParameter(String name, HttpServletRequest request) {
        String value = request.getParameter(name);
        if (value == null) {
            return "Undefined";
        }
        return value;
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        
        String user = getParameter(USER, request);
        String account = getParameter(ACCOUNT, request);
        boolean iban = account.startsWith("FR");
        String svg = new StringBuilder(
            "<?xml version='1.0' encoding='utf-8'?>" +
            "<svg width='300' height='160' xmlns='http://www.w3.org/2000/svg'>" +
            "<defs>" +
            "<filter id='dropShaddow'>" +
            "<feGaussianBlur stdDeviation='1.5'/>" +
            "</filter>" +
            "<linearGradient id='background' x1='0' x2='1' y1='0' y2='1'>")
        .append(
                iban ? 
            "<stop offset='0.04167' stop-color='#c3f7f7'/>" +
            "<stop offset='0.65105' stop-color='#e8f9fc'/>" +
            "<stop offset='1' stop-color='#c3f7f7'/>" 
                     :
            "<stop offset='0.04167' stop-color='#fff9c9'/>" +
            "<stop offset='0.65105' stop-color='#fffde8'/>" +
            "<stop offset='1' stop-color='#f9f6b1'/>"
                )
        .append(
            "</linearGradient>" +
            "</defs>" +
            "<rect x='2' y='2' width='296' height='156' rx='10' fill='black' opacity='0.3' filter='url(#dropShaddow)'/>" +
            "<rect x='0.5' y='0.5' width='295' height='155' stroke='black' stroke-width='1' rx='10' fill='url(#background)'/>" +
            "<text x='150' y='100' font-size='20' font-family='Roboto,sans-serif' text-anchor='middle'>" +
            USER + 
            "</text>" +
            "<text x='150' y='140' font-size='15' font-family='Roboto,sans-serif' text-anchor='middle'>" +
            ACCOUNT +
            "</text>" +
            "<text x='30' y='50' font-size='30' font-family='Roboto,sans-serif'>")
        .append(iban ? "BankNet2" : "Supercard")
        .append(
            "</text>" +
            "</svg>").toString().replace(USER, user).replace(ACCOUNT, account);
        
        WalletCore.returnSVG(response, svg);
    }
}
