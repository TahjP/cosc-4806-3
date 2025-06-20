<?php

require_once('app/database.php');

class User {

    public $username;
    public $password;
    public $auth = false;

    public function __construct() {}

    public function test() {
        $db = db_connect();
        $statement = $db->prepare("SELECT * FROM users;");
        $statement->execute();
        return $statement->fetch(PDO::FETCH_ASSOC);
    }

    public function authenticate($username, $password) {

        /*
         * if username and password good then
         * $this->auth = true;
         */
        $username = strtolower($username);
        $db = db_connect();

        // check for lockout
        if (isset($_SESSION['failedAuth']) && $_SESSION['failedAuth'] >= 3) {
            $elapsed = time() - ($_SESSION['lastFailed'] ?? 0);
            if ($elapsed < 60) {
                echo "Too many failed attempts. Try again in " . (60 - $elapsed) . " seconds.";
                exit;
            }
        }

        // Attempt login
        $statement = $db->prepare("SELECT * FROM users WHERE username = :name;");
        $statement->bindValue(':name', $username);
        $statement->execute();
        $rows = $statement->fetch(PDO::FETCH_ASSOC);

        if ($rows && password_verify($password, $rows['password'])) {
            // tpLog good attempt and reset session
            $log = $db->prepare("INSERT INTO log (username, attempt) VALUES (:username, 'good');");
            $log->execute(['username' => $username]);

            $_SESSION['auth'] = 1;
            $_SESSION['username'] = ucwords($username);
            unset($_SESSION['failedAuth'], $_SESSION['lastFailed']);

            header('Location: /home');
            exit;
        } else {
            // log bad attempt and track failure
            $log = $db->prepare("INSERT INTO log (username, attempt) VALUES (:username, 'bad');");
            $log->execute(['username' => $username]);

            $_SESSION['failedAuth'] = ($_SESSION['failedAuth'] ?? 0) + 1;
            $_SESSION['lastFailed'] = time();

            header('Location: /login');
            exit;
        }
    }

    public function register($username, $password) {
        $db = db_connect();

        // validate password length
        if (strlen($password) < 10) {
            return "Password must be at least 10 characters long.";
        }

        //  check for duplicate usernames
        $check = $db->prepare("SELECT * FROM users WHERE username = :username;");
        $check->execute(['username' => $username]);

        if ($check->fetch()) {
            return "Error: Username already exists.";
        }

        // insert new user
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $db->prepare("INSERT INTO users (username, password) VALUES (:username, :password);");
        $stmt->execute([
            'username' => $username,
            'password' => $hashedPassword
        ]);

        //  autologin after registration
        $_SESSION['auth'] = 1;
        $_SESSION['username'] = ucwords($username);
        header('Location: /home');
        exit;
    }
}
