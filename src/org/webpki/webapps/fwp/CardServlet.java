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
    
    private static final String SVG = 
        "<?xml version='1.0' encoding='utf-8'?>" +
        "<svg width='300' height='100' xmlns='http://www.w3.org/2000/svg'>" +
        "<rect x='1' y='1' width='297' height='98' stroke='grey' stroke-width='2' fill='none'/>" +
        "<text font-size='30' font-family='Roboto,sans-serif' text-anchor='middle'>" +
        "<tspan x='78' y='43'>Payment</tspan>" +
        "<tspan x='78' y='79'>Card</tspan>" +
        "</text>" +
        "</svg>";

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        
        WalletCore.returnSVG(response, SVG);
    }
}
