<?php

class Create extends Controller {

    public function index() {		
	    $this->view('create/index');
    }
  public function store() {
      $username = strtolower(trim($_REQUEST['username']));
      $password = $_REQUEST['password'];

      $user = $this->model('User');
      $message = $user->register($username, $password);

      $this->view('create/index', ['message' => $message]);
  }
}
