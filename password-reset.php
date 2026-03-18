<?php
/**
 * password-reset.php
 *
 * Handles password reset requests with token validation and optional
 * recovery key verification for accounts with encryption enabled.
 *
 * ResearchChatAI
 * Author: Marc Becker, David de Jong
 * License: MIT
 */

// Error reporting for development (disable in production)
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(E_ALL);

require 'Backend/MySQL/medoo-Credentials.php';

use Medoo\Medoo;

// =============================================================================
// SECURITY HEADERS
// =============================================================================

// Prevent clickjacking attacks
header("X-Frame-Options: DENY");

// Prevent MIME-type sniffing
header("X-Content-Type-Options: nosniff");

// Enable XSS protection in older browsers
header("X-XSS-Protection: 1; mode=block");

// Control referrer information leakage
header("Referrer-Policy: strict-origin-when-cross-origin");

// Restrict browser features and APIs
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");

// Content Security Policy - prevent XSS and injection attacks
// Note: Adjusted to allow inline scripts for form validation
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://code.jquery.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");

// Force HTTPS in production (uncomment when using HTTPS)
// header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");

// =============================================================================
// CONSTANTS
// =============================================================================

define('PASSWORD_RESET_SUCCESS_PAGE', 'password-reset-response.html');

// =============================================================================
// INITIALIZATION
// =============================================================================

$errorMessage = "";
$successMessage = "";
$requiresRecoveryKey = false;
$tokenValid = false;
$user = null;

// Initialize CSRF token
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrfToken = $_SESSION['csrf_token'];

// =============================================================================
// TOKEN VALIDATION
// =============================================================================

if (!isset($_GET['token']) || empty($_GET['token'])) {
    $errorMessage = "No reset token provided.";
} else {
    $token = $_GET['token'];
    
    // Validate token format (basic sanity check)
    if (!preg_match('/^[a-f0-9]{64}$/i', $token)) {
        $errorMessage = "Invalid token format.";
    } else {
        // Check if token is valid and not expired
        $user = $database->get("users", "*", [
            "reset_token" => $token,
            "token_expiry[>]" => date('Y-m-d H:i:s')
        ]);

        if ($user) {
            $tokenValid = true;
            $requiresRecoveryKey = !empty($user['recoveryKeyEnc']) && !empty($user['keySalt']);
        } else {
            $errorMessage = "Invalid or expired token.";
        }
    }
}

// =============================================================================
// PASSWORD RESET PROCESSING
// =============================================================================

if ($tokenValid && $_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF token validation
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $errorMessage = "Invalid request. Please try again.";
        error_log("CSRF token validation failed in password reset");
    } else {
        // Get and validate form inputs
        $newPassword = isset($_POST['password']) ? $_POST['password'] : '';
        $repeatPassword = isset($_POST['repeatPassword']) ? $_POST['repeatPassword'] : '';
        $recoveryKey = isset($_POST['recoveryKey']) ? trim($_POST['recoveryKey']) : '';

        // Validate password inputs
        if (empty($newPassword) || empty($repeatPassword)) {
            $errorMessage = "Please enter and confirm your new password.";
        } elseif ($newPassword !== $repeatPassword) {
            $errorMessage = "Passwords do not match.";
        } elseif (strlen($newPassword) < 8) {
            $errorMessage = "Password must be at least 8 characters long.";
        } else {
            // Process password reset based on account type
            if ($requiresRecoveryKey) {
                $resetResult = resetPasswordWithRecovery($database, $user, $newPassword, $recoveryKey);
            } else {
                $resetResult = resetPasswordLegacy($database, $user, $newPassword);
            }

            if ($resetResult['success']) {
                // Regenerate session to prevent session fixation
                session_regenerate_id(true);
                
                header('Location: ' . PASSWORD_RESET_SUCCESS_PAGE);
                exit;
            } else {
                $errorMessage = $resetResult['error'];
            }
        }
    }
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Reset password for modern accounts with encryption keys
 *
 * Validates recovery key, decrypts private key, and re-encrypts with new password.
 *
 * @param Medoo $database Database connection
 * @param array $user User record from database
 * @param string $newPassword New password to set
 * @param string $recoveryKey Recovery key provided by user
 * @return array Result with 'success' boolean and 'error' message if failed
 */
function resetPasswordWithRecovery($database, $user, $newPassword, $recoveryKey)
{
    $result = ['success' => false, 'error' => ''];

    // Validate recovery key was provided
    if (empty($recoveryKey)) {
        $result['error'] = "Please provide your recovery key.";
        return $result;
    }

    // Decode and validate key salt
    $keySalt = base64_decode($user['keySalt'], true);
    $recoveryKeyEnc = $user['recoveryKeyEnc'];

    if ($keySalt === false || strlen($keySalt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
        error_log("Invalid key salt for user during password reset");
        $result['error'] = "Unable to process recovery data for this account.";
        return $result;
    }

    if (empty($recoveryKeyEnc)) {
        error_log("Missing recovery key encryption data");
        $result['error'] = "Unable to process recovery data for this account.";
        return $result;
    }

    // Derive key from recovery key
    $recoveryDerivedKey = sodium_crypto_pwhash(
        SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
        $recoveryKey,
        $keySalt,
        SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
        SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
    );

    // Decode encrypted recovery data
    $encryptedData = base64_decode($recoveryKeyEnc, true);
    if ($encryptedData === false || strlen($encryptedData) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
        error_log("Invalid recovery key encryption data");
        sodium_memzero($recoveryDerivedKey);
        $result['error'] = "Unable to process recovery data for this account.";
        return $result;
    }

    // Extract nonce and ciphertext
    $nonce = substr($encryptedData, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $ciphertext = substr($encryptedData, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

    // Decrypt private key using recovery key
    $privateKey = sodium_crypto_secretbox_open($ciphertext, $nonce, $recoveryDerivedKey);
    sodium_memzero($recoveryDerivedKey);

    if ($privateKey === false) {
        error_log("Failed to decrypt private key with provided recovery key");
        $result['error'] = "Invalid recovery key.";
        return $result;
    }

    // Re-encrypt private key with new password
    $newPasswordDerivedKey = sodium_crypto_pwhash(
        SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
        $newPassword,
        $keySalt,
        SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
        SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
    );

    $newNonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $newEncryptedPrivateKey = sodium_crypto_secretbox($privateKey, $newNonce, $newPasswordDerivedKey);
    $newPrivateKeyEnc = base64_encode($newNonce . $newEncryptedPrivateKey);

    // Clear sensitive data from memory
    sodium_memzero($privateKey);
    sodium_memzero($newPasswordDerivedKey);

    // Hash new password
    $hashedPassword = password_hash($newPassword, PASSWORD_ARGON2ID);

    // Update database
    $updateResult = $database->update("users", [
        "userPassword" => $hashedPassword,
        "privateKeyEnc" => $newPrivateKeyEnc,
        "reset_token" => null,
        "token_expiry" => null
    ], ["userID" => $user['userID']]);

    if ($updateResult === false) {
        error_log("Database update failed during password reset");
        $result['error'] = "Failed to update password. Please try again.";
        return $result;
    }

    $result['success'] = true;
    return $result;
}

/**
 * Reset password for legacy accounts without encryption keys
 *
 * @param Medoo $database Database connection
 * @param array $user User record from database
 * @param string $newPassword New password to set
 * @return array Result with 'success' boolean and 'error' message if failed
 */
function resetPasswordLegacy($database, $user, $newPassword)
{
    $result = ['success' => false, 'error' => ''];

    // Hash new password
    $hashedPassword = password_hash($newPassword, PASSWORD_ARGON2ID);

    // Update database
    $updateResult = $database->update("users", [
        "userPassword" => $hashedPassword,
        "reset_token" => null,
        "token_expiry" => null
    ], ["userID" => $user['userID']]);

    if ($updateResult === false) {
        error_log("Database update failed during legacy password reset");
        $result['error'] = "Failed to update password. Please try again.";
        return $result;
    }

    $result['success'] = true;
    return $result;
}

?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password - ResearchChatAI</title>
    
    <!-- Stylesheets -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@0.9.4/css/bulma.min.css">
    <link rel="stylesheet" href="src/CSS/login.css">
    
    <!-- FontAwesome -->
    <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/solid.min.css">
    <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/light.min.css">
    <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/regular.min.css">
    <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/brands.min.css">
    <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/fontawesome.min.css">
</head>

<body>
    <section class="section">
        <div class="container">
            <!-- Password Reset Card -->
            <div id="loginCard" class="card">
                <header class="card-header has-background-dark">
                    <p class="card-header-title has-text-white">Reset Password</p>
                </header>
                
                <div class="card-content">
                    <div class="content">
                        <?php if ($tokenValid): ?>
                            <form method="POST" action="" id="resetForm">
                                <!-- CSRF Protection -->
                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">
                                
                                <!-- New Password Field -->
                                <div class="field">
                                    <label class="label">New Password</label>
                                    <p class="control has-icons-left">
                                        <input 
                                            class="input" 
                                            type="password" 
                                            name="password" 
                                            id="password"
                                            placeholder="New password"
                                            autocomplete="new-password"
                                            minlength="8"
                                            required
                                        >
                                        <span class="icon is-small is-left">
                                            <i class="fas fa-lock"></i>
                                        </span>
                                    </p>
                                    <p class="help">Must be at least 8 characters long</p>
                                </div>
                                
                                <!-- Confirm Password Field -->
                                <div class="field">
                                    <label class="label">Confirm Password</label>
                                    <p class="control has-icons-left">
                                        <input 
                                            class="input" 
                                            type="password" 
                                            name="repeatPassword" 
                                            id="repeatPassword"
                                            placeholder="Repeat new password"
                                            autocomplete="new-password"
                                            minlength="8"
                                            required
                                        >
                                        <span class="icon is-small is-left">
                                            <i class="fas fa-lock"></i>
                                        </span>
                                    </p>
                                </div>
                                
                                <!-- Recovery Key Field (conditional) -->
                                <?php if ($requiresRecoveryKey): ?>
                                    <div class="field">
                                        <label class="label">Recovery Key</label>
                                        <p class="control has-icons-left">
                                            <input 
                                                class="input" 
                                                type="text" 
                                                name="recoveryKey" 
                                                id="recoveryKey"
                                                placeholder="Recovery key"
                                                autocomplete="off"
                                                required
                                            >
                                            <span class="icon is-small is-left">
                                                <i class="fas fa-key"></i>
                                            </span>
                                        </p>
                                        <p class="help">Your recovery key is required to decrypt your encrypted data</p>
                                    </div>
                                <?php else: ?>
                                    <!-- Hidden field for legacy accounts -->
                                    <input type="hidden" name="recoveryKey" value="">
                                <?php endif; ?>
                                
                                <!-- Submit Button -->
                                <button type="submit" class="button is-primary is-fullwidth">
                                    Reset Password
                                </button>
                            </form>
                        <?php else: ?>
                            <p class="has-text-centered">
                                Unable to process password reset request.
                            </p>
                        <?php endif; ?>
                        
                        <!-- Error Message -->
                        <?php if (!empty($errorMessage)): ?>
                            <div class="notification is-danger mt-4">
                                <p><?php echo htmlspecialchars($errorMessage, ENT_QUOTES, 'UTF-8'); ?></p>
                            </div>
                        <?php endif; ?>
                        
                        <!-- Success Message -->
                        <?php if (!empty($successMessage)): ?>
                            <div class="notification is-success mt-4">
                                <p><?php echo htmlspecialchars($successMessage, ENT_QUOTES, 'UTF-8'); ?></p>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
                
                <!-- Footer Link -->
                <footer class="card-footer">
                    <a href="login.php" class="card-footer-item has-text-dark">Back to Login</a>
                </footer>
            </div>
        </div>
    </section>

    <!-- Scripts -->
    <script src="https://code.jquery.com/jquery-3.6.3.min.js"
        integrity="sha256-pvPw+upLPUjgMXY0G+8O0xUf+/Im1MZjXxxgOcBQBXU=" 
        crossorigin="anonymous"></script>
    <script type="text/javascript">
        /**
         * Client-side password validation
         * Ensures passwords match before form submission
         */
        document.getElementById('resetForm')?.addEventListener('submit', function(event) {
            var password = document.getElementById('password').value;
            var repeatPassword = document.getElementById('repeatPassword').value;

            if (password !== repeatPassword) {
                alert('Passwords do not match. Please try again.');
                event.preventDefault();
                return false;
            }

            if (password.length < 8) {
                alert('Password must be at least 8 characters long.');
                event.preventDefault();
                return false;
            }
        });
    </script>
</body>

</html>