/*
__Author__: Santhosh
__Version__:1.0
__Desc__: DB Code for KMIS Solution
 */

DROP DATABASE IF EXISTS `kmis`;
DROP TABLE IF EXISTS `kmis`.`app_users`;

CREATE DATABASE `kmis`;

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
   PRIMARY KEY ( app_user_id,app_key ),
   UNIQUE (app_key) 
)ENGINE = MYISAM;

DROP USER 'kmis_db_user'@'localhost';

CREATE USER 'kmis_db_user'@'localhost' IDENTIFIED BY 'UnDetect@ble123!';

GRANT ALL PRIVILEGES ON kmis.* TO 'kmis_db_user'@'localhost';

FLUSH PRIVILEGES;
