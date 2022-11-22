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
package org.webpki.fwp;

import java.io.IOException;

import java.util.GregorianCalendar;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;

import org.webpki.util.ISODateTime;

/**
 * Sample Issuer request matching the FWP documentation. 
 */
public class IssuerRequest {

    public static final String PSP_REQUEST     = "pspRequest";
    public static final String PAYEE_HOST      = "payeeHost";
    public static final String TIME_STAMP      = "timeStamp";
    
    PSPRequest pspRequest;
    public PSPRequest getPspRequest() {
        return pspRequest;
    }
    
    String payeeHost;
    public String getPayeeHost() {
        return payeeHost;
    }
 
    GregorianCalendar timeStamp;
    public GregorianCalendar getTimeStamp() {
        return timeStamp;
    }   
    
    public IssuerRequest(JSONObjectReader reader) throws IOException {
        pspRequest = new PSPRequest(reader.getObject(PSP_REQUEST));
        payeeHost = reader.getString(PAYEE_HOST);
        timeStamp = reader.getDateTime(TIME_STAMP, ISODateTime.COMPLETE);
    }
    
    public IssuerRequest(PSPRequest pspRequest,
                         String payeeHost,
                         GregorianCalendar timeStamp) {
        this.pspRequest = pspRequest;
        this.payeeHost = payeeHost;
        this.timeStamp = timeStamp;
    }
    
    public String serialize() throws IOException {
        return getWriter().serializeToString(JSONOutputFormats.NORMALIZED);
    }
    
    public JSONObjectWriter getWriter() throws IOException {
        return new JSONObjectWriter()
                .setObject(PSP_REQUEST, pspRequest.getWriter())
                .setString(PAYEE_HOST, payeeHost)
                .setDateTime(TIME_STAMP, timeStamp, ISODateTime.UTC_NO_SUBSECONDS);
    }
    
    @Override
    public String toString() {
        try {
            return getWriter().toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
