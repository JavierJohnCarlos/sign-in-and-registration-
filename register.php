<?php
require_once 'includes/functions.php';
if (isset($_SESSION['user_id'])) { redirect('index.php'); }

$errors = [];
$f = ['full_name' => '', 'username' => '', 'email' => '', 'contact' => '', 'address' => ''];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    foreach ($f as $key => $v) {
        $f[$key] = trim($_POST[$key] ?? '');
    }
    $password = $_POST['password'] ?? '';
    $confirm  = $_POST['confirm'] ?? '';

    if ($f['full_name'] === '' || $f['username'] === '' || $f['email'] === '' || $f['contact'] === '' || $f['address'] === '') {
        $errors[] = 'Please fill in all fields.';
    }
    if (!filter_var($f['email'], FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Please enter a valid email address.';
    }
    if (!preg_match('/^[A-Za-z0-9_]{4,20}$/', $f['username'])) {
        $errors[] = 'Username must be 4 to 20 letters, numbers or underscores.';
    }
    if (!preg_match('/^[0-9+ -]{7,15}$/', $f['contact'])) {
        $errors[] = 'Please enter a valid contact number.';
    }
    if (strlen($password) < 6) {
        $errors[] = 'Password must be at least 6 characters.';
    }
    if ($password !== $confirm) {
        $errors[] = 'Passwords do not match.';
    }

    if (!$errors) {
        $stmt = $conn->prepare('SELECT id FROM users WHERE username = ? OR email = ?');
        $stmt->bind_param('ss', $f['username'], $f['email']);
        $stmt->execute();
        if ($stmt->get_result()->num_rows > 0) {
            $errors[] = 'Username or email is already registered.';
        }
    }

    if (!$errors) {
        $hash = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $conn->prepare('INSERT INTO users (full_name, username, email, contact, address, password) VALUES (?, ?, ?, ?, ?, ?)');
        $stmt->bind_param('ssssss', $f['full_name'], $f['username'], $f['email'], $f['contact'], $f['address'], $hash);
        $stmt->execute();
        set_flash('success', 'Registration successful. You can now log in.');
        redirect('login.php');
    }
}

$page_title = 'Register';
include 'includes/header.php';
?>
<div class="form-box">
    <h2>Create an Account</h2>
    <?php foreach ($errors as $err): ?>
        <div class="alert alert-error"><?php echo e($err); ?></div>
    <?php endforeach; ?>
    <form method="post" action="register.php">
        <label for="full_name">Full Name</label>
        <input type="text" id="full_name" name="full_name" value="<?php echo e($f['full_name']); ?>" required>

        <label for="username">Username</label>
        <input type="text" id="username" name="username" value="<?php echo e($f['username']); ?>" required>

        <label for="email">Email</label>
        <input type="email" id="email" name="email" value="<?php echo e($f['email']); ?>" required>

        <label for="contact">Contact Number</label>
        <input type="text" id="contact" name="contact" value="<?php echo e($f['contact']); ?>" required>

        <label for="address">Home Address</label>
        <input type="text" id="address" name="address" value="<?php echo e($f['address']); ?>" required>

        <label for="password">Password</label>
        <input type="password" id="password" name="password" required>

        <label for="confirm">Confirm Password</label>
        <input type="password" id="confirm" name="confirm" required>

        <button type="submit" class="btn btn-full">Register</button>
    </form>
    <p class="form-note">Already have an account? <a href="login.php">Login here</a></p>
</div>
<?php include 'includes/footer.php'; ?>
