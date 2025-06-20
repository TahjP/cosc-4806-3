<?php

class Login extends Controller {

    public function index() {		
	    $this->view('login/index');
    }
    
    public function verify(){
			$username = $_REQUEST['username'];
			$password = $_REQUEST['password'];

			$user = $this->model('User');
			$user->authenticate($username, $password); 
    }

			public function create() {
					$this->view('login/create');
			}
	
			public function store() {
					$username = strtolower(trim($_REQUEST['username']));
					$password = $_REQUEST['password'];

					$user = $this->model('User');
					$message = $user->register($username, $password);

					if ($message === null) {
							exit; // user has been redirected from model
					}

					$this->view('login/create', ['message' => $message]);
			}
}
