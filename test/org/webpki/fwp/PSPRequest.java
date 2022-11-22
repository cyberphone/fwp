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
 * Sample PSP request matching the FWP documentation. 
 */
public class PSPRequest {

    public static final String PAYMENT_REQUEST   = "paymentRequest";
    public static final String FWP_ASSERTION     = "fwpAssertion";
    public static final String RECEIVE_ACCOUNT   = "receiveAccount";
    public static final String CLIENT_IP_ADDRESS = "clientIpAddress";
    public static final String TIME_STAMP        = "timeStamp";

    
    FWPPaymentRequest paymentRequest;
    public FWPPaymentRequest getPaymentRequest() {
        return paymentRequest;
    }
    
    FWPJsonAssertion fwpAssertion;
    public FWPJsonAssertion getFwpAssertion() {
        return fwpAssertion;
    }

    String receiveAccount;
    public String getReceiveAccount() {
        return receiveAccount;
    }

    String clientIpAddress;
    public String getClientIpAddress() {
        return clientIpAddress;
    }    

    GregorianCalendar timeStamp;
    public GregorianCalendar getTimeStamp() {
        return timeStamp;
    }    

    JSONObjectReader reader;
    
    public PSPRequest(JSONObjectReader reader) throws IOException {
        this.reader = reader;
        paymentRequest = new FWPPaymentRequest(reader.getObject(PAYMENT_REQUEST));
        fwpAssertion = new FWPJsonAssertion(reader.getObject(FWP_ASSERTION));
        receiveAccount = reader.getString(RECEIVE_ACCOUNT);
        clientIpAddress = reader.getString(CLIENT_IP_ADDRESS);
        timeStamp = reader.getDateTime(TIME_STAMP, ISODateTime.COMPLETE);
    }
    
    public PSPRequest(FWPPaymentRequest paymentRequest,
                      FWPJsonAssertion fwpAssertion,
                      String receiveAccount,
                      String clientIpAddress,
                      GregorianCalendar timeStamp) {
        this.paymentRequest = paymentRequest;
        this.fwpAssertion = fwpAssertion;
        this.receiveAccount = receiveAccount;
        this.clientIpAddress = clientIpAddress;
        this.timeStamp = timeStamp;
    }
    
    public String serialize() throws IOException {
        return getWriter().serializeToString(JSONOutputFormats.NORMALIZED);
    }
    
    public JSONObjectWriter getWriter() throws IOException {
        return new JSONObjectWriter()
                .setObject(PAYMENT_REQUEST, paymentRequest.getWriter())
                .setObject(FWP_ASSERTION, fwpAssertion.getWriter())
                .setString(RECEIVE_ACCOUNT, receiveAccount)
                .setString(CLIENT_IP_ADDRESS, clientIpAddress)
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
