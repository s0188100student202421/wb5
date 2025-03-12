CREATE DATABASE form_db;

USE form_db;

CREATE TABLE users(
	id INT AUTO_INCREMENT PRIMARY KEY,
	full_name VARCHAR(150) NOT NULL,
	gender ENUM('Male', 'Female') NOT NULL
);

CREATE TABLE programming_languages(
	id INT AUTO_INCREMENT PRIMARY KEY,
	user_id INT, 
	language VARCHAR(50) NOT NULL,
	FOREIGN KEY (user_id) REFERENCES user(id)
);

CREATE TABLE users(
	id INT AUTO_INCREMENT PRIMARY KEY,
	user_id INT, 
	login INT NOT NULL,
	hashed_password INT NOT NULL 
);
