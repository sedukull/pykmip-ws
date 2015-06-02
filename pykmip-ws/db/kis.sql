
DROP DATABASE IF EXISTS `kis`;
DROP TABLE IF EXISTS `kis`.`app_users`;

CREATE DATABASE `kis`;

CREATE TABLE `kis`.`app_users`
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
