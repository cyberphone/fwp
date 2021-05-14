/*
 *  Copyright 2015-2020 WebPKI.org (http://webpki.org).
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

import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.SQLException;

import java.util.logging.Logger;

public class DataBaseOperations {

    static Logger logger = Logger.getLogger(DataBaseOperations.class.getCanonicalName());
    
    static void testConnection() throws SQLException {
        try (Connection connection = FWPService.jdbcDataSource.getConnection();) { }
    }
    
    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Create user                                                                                //
    ////////////////////////////////////////////////////////////////////////////////////////////////
    static void createUser(String userId,
                           String commonName,
                           Connection connection) throws SQLException, IOException {
/*
        CREATE PROCEDURE CreateUserSP (IN p_UserID CHAR(36),
                                       IN p_CommonName VARCHAR(50))
*/
        try (CallableStatement stmt = 
                connection.prepareCall("{call CreateUserSP(?,?)}");) {
            stmt.setString(1, userId);
            stmt.setString(2, commonName);
            stmt.execute();
        }
    }

    
    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Delete user                                                                                //
    ////////////////////////////////////////////////////////////////////////////////////////////////
    static void deleteUser(String userId,
                           Connection connection) throws SQLException, IOException {
/*
        CREATE PROCEDURE DeleteUserSP (IN p_UserID CHAR(36))
*/
        try (CallableStatement stmt = 
                connection.prepareCall("{call DeleteUserSP(?)}");) {
            stmt.setString(1, userId);
            stmt.execute();
        }
    }
}
