CREATE DATABASE IF NOT EXISTS `file-sharing` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `file-sharing`;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  full_name VARCHAR(255) NOT NULL,
  username VARCHAR(150) NOT NULL UNIQUE,
  password_hash VARBINARY(255) NOT NULL,
  created_at DATETIME NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS files (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  original_filename VARCHAR(255) NOT NULL,
  stored_filename VARCHAR(512) NOT NULL,
  upload_timestamp DATETIME NOT NULL,
  sha256_hash CHAR(64) NOT NULL,
  plaintext_sha256 CHAR(64) NOT NULL,
  iv CHAR(32) NOT NULL,
  password_salt CHAR(32) NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS file_shares (
  id INT AUTO_INCREMENT PRIMARY KEY,
  file_id INT NOT NULL,
  user_id INT NOT NULL,
  shared_at DATETIME NOT NULL,
  UNIQUE KEY (file_id, user_id),
  FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
