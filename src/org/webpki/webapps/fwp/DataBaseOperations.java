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

import java.security.GeneralSecurityException;

import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import java.util.ArrayList;

import java.util.logging.Logger;

import org.webpki.webutil.DNSReverseLookup;

import org.webpki.crypto.HashAlgorithms;

public class DataBaseOperations {

    static Logger logger = Logger.getLogger(DataBaseOperations.class.getName());
    
    static void testConnection() throws SQLException {
        try (Connection connection = ApplicationService.jdbcDataSource.getConnection();) { }
    }
    
    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Create (or recreate) user and give it some payment credentials as well                     //
    ////////////////////////////////////////////////////////////////////////////////////////////////
    static void initiateUserAccount(String userId,
                                    String cardHolder,
                                    byte[] credentialId,
                                    String rpId,
                                    byte[] rawCosePublicKey,
                                    String clientIpAddress,
                                    Connection connection)
            throws SQLException, IOException, GeneralSecurityException {
/*
        CREATE PROCEDURE InitiateUserAccountSP (IN p_UserId CHAR(36),
                                                IN p_CardHolder VARCHAR(50),
                                                IN p_CredentialId VARBINARY(1024),
                                                IN p_RpId VARCHAR(255),
                                                IN p_PublicKey VARBINARY(300),
                                                IN p_S256KeyHash BINARY(32),
                                                IN p_ClientIpAddress VARCHAR(50))
*/
        try (CallableStatement stmt = 
                connection.prepareCall("{call InitiateUserAccountSP(?,?,?,?,?,?,?)}");) {
            stmt.setString(1, userId);
            stmt.setString(2, cardHolder);
            stmt.setBytes(3, credentialId);
            stmt.setString(4, rpId);
            stmt.setBytes(5, rawCosePublicKey);
            stmt.setBytes(6, HashAlgorithms.SHA256.digest(rawCosePublicKey));
            stmt.setString(7, clientIpAddress);
            stmt.execute();
        }

        // Potentially very slow operation, perform it in the background!
        new Thread(new Runnable() {

            @Override
            public void run() {
                try {
                    String host = DNSReverseLookup.getHostName(clientIpAddress);
                    if (host.equals(clientIpAddress)) {
                        return;
                    }
                    try (PreparedStatement stmt = 
                            ApplicationService.jdbcDataSource.getConnection().prepareStatement(
                                "UPDATE USERS SET ClientHost = ? WHERE UserID = ?;");) {
                        stmt.setString(1, host);
                        stmt.setString(2, userId);
                        stmt.executeUpdate();
                    }
                } catch (SQLException | IOException | InterruptedException e) {
                    throw new RuntimeException(e);
                }
            }
           
        }).start();
    }
    
    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Delete user                                                                                //
    ////////////////////////////////////////////////////////////////////////////////////////////////
    static void deletePaymentCards(String userId,
                                   Connection connection) throws SQLException {
/*
        CREATE PROCEDURE DeletePaymentCardsSP (IN p_UserId CHAR(36))
*/
        try (CallableStatement stmt = connection.prepareCall("{call DeletePaymentCardsSP(?)}");) {
            stmt.setString(1, userId);
            stmt.execute();
        }
    }

    static class CoreClientData {
        byte[] credentialId;
        String rpId;
        byte[] cosePublicKey;
        String cardHolder;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // WebAuthn on Android as well as FWP presume that the key handle (CredentialId) is known.    //
    ////////////////////////////////////////////////////////////////////////////////////////////////
    static CoreClientData getCoreClientData(String userId, Connection connection)
            throws IOException, SQLException, GeneralSecurityException {
/*
        CREATE PROCEDURE GetCoreClientDataSP (OUT p_CredentialId VARCHAR(100),
                                              OUT p_RpId VARCHAR(255),
                                              OUT p_PublicKey VARBINARY(300),
                                              OUT p_CardHolder VARCHAR(50),
                                              IN p_UserId CHAR(36))
*/
        try (CallableStatement stmt = 
                connection.prepareCall("{call GetCoreClientDataSP(?,?,?,?,?)}");) {
            stmt.registerOutParameter(1, java.sql.Types.VARBINARY);
            stmt.registerOutParameter(2, java.sql.Types.VARCHAR);
            stmt.registerOutParameter(3, java.sql.Types.VARBINARY);
            stmt.registerOutParameter(4, java.sql.Types.VARCHAR);
            stmt.setString(5, userId);
            stmt.execute();
            byte[] credentialId = stmt.getBytes(1);
            if (credentialId == null) {
                return null;
            }
            CoreClientData coreClientData = new CoreClientData();
            coreClientData.credentialId = credentialId;
            coreClientData.rpId = stmt.getString(2);
            coreClientData.cosePublicKey = stmt.getBytes(3);
            coreClientData.cardHolder = stmt.getString(4);
            return coreClientData;
        }
    }
    
    static class VirtualCard {
        byte[] credentialId;
        byte[] publicKey;
        String cardHolder;
        String serialNumber;
        String accountId;
        String paymentNetworkId;
        
        VirtualCard(byte[] credentialId, 
                    byte[] cosePublicKey, 
                    String cardHolder,
                    String serialNumber, 
                    String accountId,
                    String paymentNetworkId) {
            this.credentialId = credentialId;
            this.publicKey = cosePublicKey;
            this.cardHolder = cardHolder;
            this.serialNumber = serialNumber;
            this.accountId = accountId;
            this.paymentNetworkId = paymentNetworkId;
        }
    }
    
    ////////////////////////////////////////////////////////////////////////////////////////////////
    // FIDO Web Pay: Get our enrolled virtual cards if there are any                              //
    ////////////////////////////////////////////////////////////////////////////////////////////////
    static ArrayList<VirtualCard> getVirtualCards(String userId, Connection connection)
            throws IOException, SQLException, GeneralSecurityException {
        ArrayList<VirtualCard> virtualCards = new  ArrayList<>();
        try (PreparedStatement stmt = connection.prepareStatement(
                "SELECT USERS.CredentialId, USERS.PublicKey, USERS.CardHolder, " +
                "PAYMENT_CARDS.SerialNumber, PAYMENT_CARDS.AccountId, " +
                "PAYMENT_CARDS.PaymentNetworkId FROM " +
                "USERS INNER JOIN PAYMENT_CARDS ON " +
                "USERS.UserId = PAYMENT_CARDS.UserId WHERE USERS.UserId = ?;");) {
            stmt.setString(1, userId);
            try (ResultSet rs = stmt.executeQuery();) {
                while (rs.next()) {
                    virtualCards.add(new VirtualCard(rs.getBytes(1),
                                                     rs.getBytes(2),
                                                     rs.getString(3),
                                                     String.valueOf(rs.getInt(4)),
                                                     rs.getString(5),
                                                     rs.getString(6)));
                }
            }
        }
        return virtualCards;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // FIDO login: Verify that the key hash of the public key matches the user Id                 //
    ////////////////////////////////////////////////////////////////////////////////////////////////
    static void authenticate(String userId, byte[] rawPublicKey, Connection connection)
            throws IOException, SQLException, GeneralSecurityException {
/*
        CREATE PROCEDURE AuthenticateSP (OUT p_Status INT,
                                         IN p_UserId CHAR(36),
                                         IN p_S256KeyHash BINARY(32))
*/
        try (CallableStatement stmt = 
                connection.prepareCall("{call AuthenticateSP(?,?,?)}");) {
            stmt.registerOutParameter(1, java.sql.Types.INTEGER);
            stmt.setString(2, userId);
            stmt.setBytes(3, HashAlgorithms.SHA256.digest(rawPublicKey));
            stmt.execute();
            switch (stmt.getInt(1)) {
                case 0:
                    return;
                case 1:
                    throw new GeneralSecurityException("No such user: " + userId);
                default:
                    throw new GeneralSecurityException("Non-matching key hash");
            }
        }
    }
    
    static class AuthorizedInfo {
        String userId;
        String cardHolder;
        
        AuthorizedInfo(String userId, String cardHolder) {
            this.userId = userId;
            this.cardHolder = cardHolder;
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // FIDO Web Pay: Verify that the account related data matches                                 //
    ////////////////////////////////////////////////////////////////////////////////////////////////
    static AuthorizedInfo authorize(String serialNumber,
                                    String accountId,
                                    byte[] rawPublicKey,
                                    Connection connection)
            throws IOException, SQLException, GeneralSecurityException {
/*
        CREATE PROCEDURE AuthorizeSP (OUT p_Status INT,
                                      OUT p_UserId CHAR(36),
                                      OUT p_CardHolder VARCHAR(50),
                                      IN p_SerialNumber INT,
                                      IN p_AccountId VARCHAR(30),
                                      IN p_S256KeyHash BINARY(32))
*/
        try (CallableStatement stmt = 
                connection.prepareCall("{call AuthorizeSP(?,?,?,?,?,?)}");) {
            stmt.registerOutParameter(1, java.sql.Types.INTEGER);
            stmt.registerOutParameter(2, java.sql.Types.CHAR);
            stmt.registerOutParameter(3, java.sql.Types.VARCHAR);
            stmt.setInt(4, Integer.valueOf(serialNumber));
            stmt.setString(5, accountId);
            stmt.setBytes(6, HashAlgorithms.SHA256.digest(rawPublicKey));
            stmt.execute();
            switch (stmt.getInt(1)) {
                case 0:
                    return new AuthorizedInfo(stmt.getString(2), stmt.getString(3));
                case 1:
                    throw new GeneralSecurityException("No such card: " + serialNumber);
                case 2:
                    throw new GeneralSecurityException("No such account: " + accountId);
                default:
                    throw new GeneralSecurityException("Non-matching key hash");
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Update user activity data                                                                  //
    ////////////////////////////////////////////////////////////////////////////////////////////////
    public static void updateUserStatistics(String userId, boolean login, Connection connection) 
            throws SQLException {
        String element = login ? "WebAuthn" : "BasicBuy";
        try (PreparedStatement stmt = 
                ApplicationService.jdbcDataSource.getConnection().prepareStatement(
                    "UPDATE USERS SET " + element + " = " + element + " + 1 WHERE UserID = ?;");) {
            stmt.setString(1, userId);
            stmt.executeUpdate();
        }
    }
}
