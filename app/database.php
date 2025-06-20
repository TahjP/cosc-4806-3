<?php

/* database connection stuff here
 * 
 */
require_once ('app/core/config.php');

function db_connect() {
    try { 
        $dbh = new PDO('mysql:host=' . DB_HOST . ';port='. DB_PORT . ';dbname=' . DB_DATABASE, DB_USER, DB_PASS);
        return $dbh;
    } catch (PDOException $e) {
        //We should set a global variable here so we know the DB is down
        $GLOBALS['DB_DOWN'] = true;
        echo "Database connection failed: " . $e->getMessage();
        exit;
    }
}