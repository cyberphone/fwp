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
-- #################################################
-- # This is a database for the FIDO Web Pay PoC   #
-- #################################################

/*=============================================*/
/*                   USERS                     *
/*=============================================*/
CREATE TABLE USERS (
    UserId          CHAR(36)    NOT NULL UNIQUE,                        -- Unique User ID &
                                                                        -- cookie for FWP Wallet
                                                                        -- Uses UUID

    CommonName      VARCHAR(50) NOT NULL,                               -- Name on cards
    
    Created         TIMESTAMP   NOT NULL  DEFAULT CURRENT_TIMESTAMP,    -- Administrator data
                                                                        
    PRIMARY KEY (UserId)
);


/*=============================================*/
/*                CREDENTIALS                  */
/*=============================================*/

CREATE TABLE CREDENTIALS (

-- Note: a Credential holds an external representation of an Account ID
-- like an IBAN or Card Number + and an Authorization key

    CredentialId    INT         NOT NULL  AUTO_INCREMENT,               -- Unique ID/Serial number

/*
    AccountId       VARCHAR(30) NOT NULL,                               -- Account Reference
    
    PaymentMethodUrl VARCHAR(50) NOT NULL,                              -- Payment method URL

    AccessCount     INT         NOT NULL  DEFAULT 0,                    -- "Statistics"
    
    IpAddress       VARCHAR(50) NOT NULL,                               -- "Statistics"

    LastAccess      TIMESTAMP   NULL,                                   -- "Statistics"
 */   
    UserId          CHAR(36)    NOT NULL,                               -- Owner

    Created         TIMESTAMP   NOT NULL  DEFAULT CURRENT_TIMESTAMP,    -- Administrator data

-- Authentication of user authorization signatures is performed
-- by verifying that both SHA256 of the public key (in X.509 DER
-- format) and claimed CredentialId match.
/*
    S256AuthKey     BINARY(32)  NOT NULL,                               -- Payment request key hash 
*/
    PRIMARY KEY (CredentialId),
    FOREIGN KEY (UserId) REFERENCES USERS(UserId) ON DELETE CASCADE
);


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


CREATE PROCEDURE InitiateUserAccountSP (IN p_UserId CHAR(36),
                                        IN p_CommonName VARCHAR(50))
  BEGIN
    -- To make it simple, clear previous entry...
    DELETE FROM USERS WHERE UserId = p_UserId;
    
    -- Create an entry with the same UserId
    INSERT INTO USERS(UserId, 
                      CommonName) 
        VALUES(p_UserId,
               p_CommonName);
               
    -- Add the needed credentials
    INSERT INTO CREDENTIALS(UserId) 
        VALUES(p_UserId);
  END
//


CREATE PROCEDURE DeletePaymentCardsSP (IN p_UserId CHAR(36))
  BEGIN
    DELETE Target FROM CREDENTIALS As Target
        INNER JOIN USERS ON USERS.UserId = Target.UserId
        WHERE USERS.UserId = p_UserId;
  END
//

CREATE PROCEDURE HasPaymentCardsSP (OUT p_Found BOOLEAN, IN p_UserId CHAR(36))
  BEGIN
    SET p_Found = EXISTS (SELECT * FROM USERS
        INNER JOIN CREDENTIALS ON USERS.UserId = CREDENTIALS.UserId
        WHERE USERS.UserId = p_UserId);
  END
//

DELIMITER ;

-- Run a few tests

SET @UserId = "2fb3f4f1-0d7d-43b9-b9f7-39d5dc5544fd";
SET @CommonName = "Luke Skywalker";

CALL InitiateUserAccountSP(@UserId, @CommonName);

CALL HasPaymentCardsSP(@found, @UserId);

CALL ASSERT_TRUE(@found = TRUE, "Must have");

CALL DeletePaymentCardsSP(@UserId);

CALL HasPaymentCardsSP(@found, @UserId);

CALL ASSERT_TRUE(@found = FALSE, "Must NOT have");


-- Remove all test data

DELETE FROM USERS;

SET @Result = 'SUCCESSFUL';
SELECT @Result;
