-- Arogya Healthcare System - Simple Database Setup
-- Single file import for phpMyAdmin/XAMPP
-- Creates database and essential tables only

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Create database
--
CREATE DATABASE IF NOT EXISTS `web_app_db` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE `web_app_db`;

--
-- Table structure for table `users`
--
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `nic` varchar(20) NOT NULL,
  `full_name` varchar(255) NOT NULL,
  `dob` date NOT NULL,
  `gender` enum('MA','FE') NOT NULL,
  `email` varchar(255) NOT NULL,
  `phone` varchar(20) NOT NULL,
  `address` text NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `secret_key` varchar(255) NOT NULL,
  `email_verified` tinyint(1) DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`nic`),
  UNIQUE KEY `email` (`email`),
  UNIQUE KEY `phone` (`phone`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Table structure for table `signup_email_verification`
--
DROP TABLE IF EXISTS `signup_email_verification`;
CREATE TABLE `signup_email_verification` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `email` varchar(255) NOT NULL,
  `verification_code` varchar(6) NOT NULL,
  `user_data` text NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `expires_at` timestamp NOT NULL,
  `used` tinyint(1) DEFAULT 0,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Table structure for table `user_devices`
--
DROP TABLE IF EXISTS `user_devices`;
CREATE TABLE `user_devices` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nic` varchar(20) NOT NULL,
  `device_fingerprint` varchar(255) NOT NULL,
  `device_name` varchar(255) DEFAULT NULL,
  `trusted` tinyint(1) DEFAULT 0,
  `last_used` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_device_per_user` (`nic`, `device_fingerprint`),
  FOREIGN KEY (`nic`) REFERENCES `users`(`nic`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Table structure for table `login_history`
--
DROP TABLE IF EXISTS `login_history`;
CREATE TABLE `login_history` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nic` varchar(20) NOT NULL,
  `device_fingerprint` varchar(255) DEFAULT NULL,
  `device_name` varchar(255) DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `location` varchar(255) DEFAULT NULL,
  `suspicious` tinyint(1) DEFAULT 0,
  `login_time` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  FOREIGN KEY (`nic`) REFERENCES `users`(`nic`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Table structure for table `email_verification_codes`
--
DROP TABLE IF EXISTS `email_verification_codes`;
CREATE TABLE `email_verification_codes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nic` varchar(20) NOT NULL,
  `verification_code` varchar(6) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `expires_at` timestamp NOT NULL,
  `used` tinyint(1) DEFAULT 0,
  PRIMARY KEY (`id`),
  FOREIGN KEY (`nic`) REFERENCES `users`(`nic`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
