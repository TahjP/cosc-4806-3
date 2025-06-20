<?php

require_once('app/database.php');

class User {

    public $username;
    public $password;
    public $auth = false;

    public function __construct() {
        
    }

    public function test () {
      $db = db_connect();
      $log = $db->prepare("INSERT INTO log (username, attempt) VALUES (:username, :attempt);");
      $statement = $db->prepare("select * from users;");
      $statement->execute();
      $rows = $statement->fetch(PDO::FETCH_ASSOC);
      return $rows;
    }

    public function authenticate($username, $password) {
        /*
         * if username and password good then
         * $this->auth = true;
         */
		$username = strtolower($username);
		$db = db_connect();
        $statement = $db->prepare("select * from users WHERE username = :name;");
        $statement->bindValue(':name', $username);
        $statement->execute();
        $rows = $statement->fetch(PDO::FETCH_ASSOC);
		
		if (password_verify($password, $rows['password'])) {
      $log->execute(['username' => $username, 'attempt' => 'good']);
			$_SESSION['auth'] = 1;
			$_SESSION['username'] = ucwords($username);
			unset($_SESSION['failedAuth']);
			header('Location: /home');
			die;
		} else {
      $log->execute(['username' => $username, 'attempt' => 'bad']);
      $_SESSION['failedAuth'] = ($_SESSION['failedAuth'] ?? 0) + 1;

			header('Location: /login');
			die;
		}
    }
    public function register($username, $password) {
        $db = db_connect();

        if (strlen($password) < 10) {
            return "Password must be at least 10 characters long.";
        }

        $check = $db->prepare("SELECT * FROM users WHERE username = :username;");
        $check->execute(['username' => $username]);

        if ($check->fetch()) {
            return "Error: Username already exists.";
        }

        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $db->prepare("INSERT INTO users (username, password) VALUES (:username, :password);");
        $stmt->execute([
            'username' => $username,
            'password' => $hashedPassword
        ]);

        $_SESSION['auth'] = 1;
        $_SESSION['username'] = ucwords($username);
        header('Location: /home');
        exit;
    }

}
