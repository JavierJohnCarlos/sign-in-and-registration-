<?php
require_once 'includes/functions.php';
if (isset($_SESSION['user_id'])) { redirect('index.php'); }

$error = '';
$login = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $login = trim($_POST['login'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($login === '' || $password === '') {
        $error = 'Please enter your username/email and password.';
    } else {
        $stmt = $conn->prepare('SELECT * FROM users WHERE username = ? OR email = ?');
        $stmt->bind_param('ss', $login, $login);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();

        if ($user && password_verify($password, $user['password'])) {
            session_regenerate_id(true);
            $_SESSION['user_id']   = $user['id'];
            $_SESSION['full_name'] = $user['full_name'];
            $_SESSION['role']      = $user['role'];
            redirect($user['role'] === 'admin' ? 'admin_dashboard.php' : 'dashboard.php');
        } else {
            $error = 'Incorrect username/email or password.';
        }
    }
}

$page_title = 'Login';
include 'includes/header.php';
?>
<div class="form-box">
    <h2>Login</h2>
    <?php if ($error): ?>
        <div class="alert alert-error"><?php echo e($error); ?></div>
    <?php endif; ?>
    <form method="post" action="login.php">
        <label for="login">Username or Email</label>
        <input type="text" id="login" name="login" value="<?php echo e($login); ?>" required>

        <label for="password">Password</label>
        <input type="password" id="password" name="password" required>

        <button type="submit" class="btn btn-full">Login</button>
    </form>
    <p class="form-note">No account yet? <a href="register.php">Register here</a></p>
</div>
<?php include 'includes/footer.php'; ?>
