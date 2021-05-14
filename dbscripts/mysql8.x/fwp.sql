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
 
 -- SQL Script for MySQL 8.x
--
-- root privileges are required!!!
--
-- Clear and create DB to begin with
--
DROP DATABASE IF EXISTS FWP;
CREATE DATABASE FWP CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE FWP;
--
-- Create our single user
--
DROP USER IF EXISTS fwp@localhost;
CREATE USER fwp@localhost IDENTIFIED BY 'foo123';
--
-- Give this user access
--
GRANT ALL ON FWP.* TO fwp@localhost;
CREATE DEFINER = root@localhost SQL SECURITY DEFINER
  VIEW v_routines AS SELECT * FROM information_schema.routines;
GRANT SELECT ON v_routines TO fwp@localhost;
--
-- Create tables and stored procedures
--
-- ###############################################################
-- # This is the Payer side of a PoC database for "Direct Mode"  #
-- # Open Banking APIs.  The database holds information about    #
-- # Credentials and OAuth2 tokens                               #
-- ###############################################################

/*=============================================*/
/*                   USERS                     *
/*=============================================*/
CREATE TABLE USERS (
    UserID          CHAR(36)    NOT NULL UNIQUE,                        -- Unique User ID &
                                                                        -- cookie for FWP Wallet
                                                                        -- Uses UUID

    CommonName      VARCHAR(50) NOT NULL,                               -- Name on cards
    
    Created         TIMESTAMP   NOT NULL  DEFAULT CURRENT_TIMESTAMP,    -- Administrator data
                                                                        
    PRIMARY KEY (UserID)
);


/*=============================================*/
/*                CREDENTIALS                  */
/*=============================================*/

CREATE TABLE CREDENTIALS (

-- Note: a Credential holds an external representation of an Account ID
-- like an IBAN or Card Number + and an Authorization key

    CredentialId    INT         NOT NULL  AUTO_INCREMENT,               -- Unique ID/Serial number

    AccountId       VARCHAR(30) NOT NULL,                               -- Account Reference
    
    PaymentMethodUrl VARCHAR(50) NOT NULL,                              -- Payment method URL

    AccessCount     INT         NOT NULL  DEFAULT 0,                    -- "Statistics"
    
    IpAddress       VARCHAR(50) NOT NULL,                               -- "Statistics"

    LastAccess      TIMESTAMP   NULL,                                   -- "Statistics"
    
    UserID          CHAR(36)    NOT NULL,                               -- Owner

    Created         TIMESTAMP   NOT NULL  DEFAULT CURRENT_TIMESTAMP,    -- Administrator data

-- Authentication of user authorization signatures is performed
-- by verifying that both SHA256 of the public key (in X.509 DER
-- format) and claimed CredentialId match.

    S256AuthKey     BINARY(32)  NOT NULL,                               -- Payment request key hash 

    S256BalKey      BINARY(32)  NOT NULL,                               -- Balance key hash 

    PRIMARY KEY (CredentialId),
    FOREIGN KEY (UserID) REFERENCES USERS(UserID) ON DELETE CASCADE
) AUTO_INCREMENT=200500123;                                             -- Brag about "users" :-)


DELIMITER //

-- Test code only called by this script
CREATE PROCEDURE ASSERT_TRUE (IN p_DidIt BOOLEAN,
                              IN p_Message VARCHAR(100))
  BEGIN
    IF p_DidIt = FALSE THEN
      SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = p_Message, MYSQL_ERRNO = 1001;
    END IF;
  END
//


CREATE PROCEDURE CreateUserSP (IN p_UserID CHAR(36),
                               IN p_CommonName VARCHAR(50))
  BEGIN
    INSERT INTO USERS(UserID, 
                      CommonName) 
        VALUES(p_UserId,
               p_CommonName);
  END
//


CREATE PROCEDURE DeleteUserSP (IN p_UserID CHAR(36))
  BEGIN
  /* production only...
    CALL ASSERT_TRUE (EXISTS (SELECT * FROM USERS WHERE UserID=p_UserID),
                      "Missing UserID!");
   */
    DELETE FROM USERS WHERE UserID=p_UserID;
  END
//

DELIMITER ;

-- Run a few tests

SET @UserID = "2fb3f4f1-0d7d-43b9-b9f7-39d5dc5544fd";
SET @CommonName = "Luke Skywalker";

CALL CreateUserSP(@UserID, @CommonName);

-- Remove all test data

CALL DeleteUserSP(@UserID);

SET @Result = 'SUCCESSFUL';
SELECT @Result;
