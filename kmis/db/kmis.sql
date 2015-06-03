
DROP DATABASE IF EXISTS `kmis`;
DROP TABLE IF EXISTS `kmis`.`app_users`;

CREATE DATABASE `kmis`;

CREATE TABLE `kmis`.`app_users`
(
   `app_user_id` INT NOT NULL AUTO_INCREMENT,
   `app_key` varchar(128) NOT NULL,
   `app_pass_phrase` varchar(32) NOT NULL,
   `app_name` varchar(256) NOT NULL,
   `app_desc` VARCHAR(512) NOT NULL,
   `app_ip` varchar(128) NOT NULL,
   `app_fqdn` varchar(256) NOT NULL,
   `created_at` DATETIME NOT NULL,
   `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
   PRIMARY KEY ( app_user_id,app_key )
);

CREATE USER 'kmis_db_user'@'localhost' IDENTIFIED BY 'UnDetect@ble123!';

GRANT ALL PRIVILEGES ON 'kmis' . * TO 'kmis_db_user'@'UnDetect@ble123!';

FLUSH PRIVILEGES;
