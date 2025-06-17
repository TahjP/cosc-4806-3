<?php require_once 'app/views/templates/headerPublic.php'?>
<main role="main" class="container">
    <div class="page-header" id="banner">
        <div class="row">
            <div class="col-lg-12">
                <h1>Create an Account</h1>
            </div>
        </div>
    </div>

    <?php if (isset($data) && !empty($data['message'])): ?>
        <div class="alert alert-info">
            <?= $data['message']; ?>
        </div>
    <?php endif; ?>

<div class="row">
    <div class="col-sm-auto">
        <form action="/create/store" method="post">
        <fieldset>
            <div class="form-group">
                <label for="username">Username</label>
                <input required type="text" class="form-control" name="username">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input required type="password" class="form-control" name="password">
            </div>
            <br>
            <button type="submit" class="btn btn-primary">Register</button>
            <a href="/login/index" class="btn btn-secondary mt-2">Back to Login</a>
        </fieldset>
        </form>
    </div>
</div>
<?php require_once 'app/views/templates/footer.php' ?>
