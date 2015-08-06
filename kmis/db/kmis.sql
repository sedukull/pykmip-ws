/*
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
*/

/*
__Author__: Santhosh
__Version__:1.0
__Desc__: DB Code for KMIS Solution
*/


DROP DATABASE IF EXISTS `kmis`;
DROP TABLE IF EXISTS `kmis`.`app_users`;
DROP TABLE IF EXISTS `kmis`.`app_certs`;
DROP TABLE IF EXISTS `kmis`.`app_keys`;

CREATE DATABASE `kmis`;

/* Individual application information with keys, pass phrases and other related information */
CREATE TABLE `kmis`.`app_users`
(
   `app_user_id` INT NOT NULL AUTO_INCREMENT,
   `app_key` varchar(255) NOT NULL,
   `app_pass_phrase` varchar(255) NOT NULL,
   `app_name` varchar(255) NOT NULL,
   `app_desc` VARCHAR(512) NOT NULL,
   `app_ip` varchar(128) NOT NULL DEFAULT '',
   `app_fqdn` varchar(256) NOT NULL DEFAULT '',
   `active` TINYINT default 0,
   `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
   `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
   PRIMARY KEY ( app_user_id, app_key ),
   UNIQUE (app_key) 
)ENGINE = INNODB;

/* Policy information related to application, as what certs it can access */
CREATE TABLE `kmis`.`app_certs`
(
   `app_key` varchar(255) NOT NULL,
   `private_key_name` varchar(255) NOT NULL,
   `ca_cert_name` varchar(255) NOT NULL,
   `ssl_cert_name` varchar(255) NOT NULL,
   `format` varchar(32) NOT NULL,
   `active` TINYINT default 0
)ENGINE = INNODB;

/* Policy information related to application, as what keys it can access */
CREATE TABLE `kmis`.`app_keys`
(
   `app_key` varchar(255) NOT NULL,
   `key_name` varchar(255) NOT NULL,
   `format` varchar(32) NOT NULL,
   `active` TINYINT default 0
)ENGINE = INNODB;

/* Policy information related to application, whether it can create the key and keypair */
CREATE TABLE `kmis`.`app_policies`
(
   `app_key` varchar(255) NOT NULL,
   `create_key` TINYINT default 0,
   `create_key_pair` TINYINT default 0
)ENGINE = INNODB;

/* Policy information related to Key algorithms and their lengths */
CREATE TABLE `kmis`.`key_algorithm_policies`
(
   `algorithm` varchar(255) NOT NULL,
   `key_length` INT NOT NULL,
   `active` TINYINT default 0
)ENGINE = INNODB;

GRANT ALL PRIVILEGES ON kmis.* TO 'kmis_db_user'@'localhost' IDENTIFIED BY 'UnDetect@ble123!';

FLUSH PRIVILEGES;