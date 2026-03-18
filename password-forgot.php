<?php
/**
 * password-forgot.php
 *
 * Handles password reset requests by sending a time-limited reset
 * token to the user's email address.
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
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");

// Force HTTPS in production (uncomment when using HTTPS)
// header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");

// =============================================================================
// CONSTANTS
// =============================================================================

define('RESET_TOKEN_LENGTH', 32); // 32 bytes = 64 hex characters
define('TOKEN_EXPIRY_HOURS', 1);
define('GENERIC_SUCCESS_MESSAGE', 'If an account with this email exists, you will receive a reset link shortly. This can take up to 5 minutes.');

// =============================================================================
// INITIALIZATION
// =============================================================================

$message = "";
$messageType = ""; // 'success' or 'error'

// Initialize CSRF token
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrfToken = $_SESSION['csrf_token'];

// =============================================================================
// PASSWORD RESET REQUEST PROCESSING
// =============================================================================

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF token validation
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $message = "Invalid request. Please try again.";
        $messageType = "error";
        error_log("CSRF token validation failed in password-forgot");
    } else {
        // Get and validate email
        $email = isset($_POST['email']) ? trim(strtolower($_POST['email'])) : '';

        if (empty($email)) {
            $message = "Please enter a valid email address.";
            $messageType = "error";
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $message = "Please enter a valid email address.";
            $messageType = "error";
        } else {
            // Process password reset request
            // Note: Always show generic message to prevent user enumeration
            processPasswordResetRequest($database, $email);
            
            // Redirect to prevent form resubmission
            header("Location: password-forgot.php?status=success");
            exit;
        }
    }
}

// Check for success status from redirect
if (isset($_GET['status']) && $_GET['status'] === 'success') {
    $message = GENERIC_SUCCESS_MESSAGE;
    $messageType = "success";
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Process password reset request
 *
 * Generates reset token, stores it in database, and sends email.
 * Uses generic responses to prevent user enumeration.
 *
 * @param Medoo $database Database connection
 * @param string $email User's email address
 * @return void
 */
function processPasswordResetRequest($database, $email)
{
    // Check if user exists
    // NOTE: Production systems should implement rate limiting here to prevent abuse
    // Consider: max 3 requests per email per hour, max 10 requests per IP per hour
    $userExists = $database->has("users", ["userEmail" => $email]);

    if ($userExists) {
        // Generate cryptographically secure reset token
        $token = bin2hex(random_bytes(RESET_TOKEN_LENGTH));
        
        // Calculate token expiry time
        $expiryTime = date('Y-m-d H:i:s', strtotime('+' . TOKEN_EXPIRY_HOURS . ' hour'));

        // Store token in database
        $updateResult = $database->update("users", [
            "reset_token" => $token,
            "token_expiry" => $expiryTime
        ], ["userEmail" => $email]);

        if ($updateResult === false) {
            error_log("Failed to update reset token for email: " . $email);
            return;
        }

        // Build reset link
        $resetLink = buildResetLink($token);

        // Send email with reset link
        try {
            require_once 'Backend/Util/email.php';
            sendResetEmail($email, $resetLink);
        } catch (Exception $e) {
            error_log("Failed to send password reset email to {$email}: " . $e->getMessage());
            // Note: We don't inform the user of email failures to prevent user enumeration
        }
    } else {
        // User doesn't exist, but we don't tell them that
        // This prevents attackers from enumerating valid email addresses
        error_log("Password reset requested for non-existent email: " . $email);
    }
}

/**
 * Build password reset link URL
 *
 * @param string $token Reset token
 * @return string Complete reset URL
 */
function buildResetLink($token)
{
    // Load environment variables
    $env = loadEnv(__DIR__ . '/../.env');
    $baseUrl = rtrim($env['BASE_URL'] ?? '', '/');
    
    // Fallback to current host if BASE_URL not set
    if (empty($baseUrl)) {
        $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'];
        $baseUrl = $protocol . '://' . $host;
    }
    
    return $baseUrl . '/password-reset.php?token=' . urlencode($token);
}

?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forgot Password - ResearchChatAI</title>
    
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
            <h1 class="title has-text-centered" style="margin-top:100px;">ResearchChatAI</h1>
            
            <!-- Password Reset Request Card -->
            <div id="loginCard" class="card">
                <header class="card-header has-background-dark">
                    <a href="login.php" class="card-header-icon" aria-label="Back to login">
                        <span class="icon">
                            <i class="fas fa-arrow-left has-text-white" aria-hidden="true"></i>
                        </span>
                    </a>
                    <p class="card-header-title has-text-white">Forgot Password</p>
                </header>
                
                <div class="card-content">
                    <div class="content">
                        <?php if ($messageType === "success"): ?>
                            <!-- Success Message -->
                            <div class="notification is-success">
                                <p><strong>Success!</strong><br><br>Please check your email (including your spam folder) for further instructions.</p>
                            </div>
                        <?php else: ?>
                            <!-- Password Reset Form -->
                            <form method="POST" action="password-forgot.php" id="forgotPasswordForm">
                                <!-- CSRF Protection -->
                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">
                                
                                <!-- Email Field -->
                                <div class="field">
                                    <label class="label">Email Address</label>
                                    <p class="control has-icons-left">
                                        <input 
                                            class="input" 
                                            type="email" 
                                            name="email" 
                                            id="email"
                                            placeholder="your.email@example.com"
                                            autocomplete="email"
                                            required
                                        >
                                        <span class="icon is-small is-left">
                                            <i class="fas fa-envelope"></i>
                                        </span>
                                    </p>
                                    <p class="help">
                                        Enter the email address associated with your account. 
                                        If an account exists, you will receive password reset instructions.
                                    </p>
                                </div>
                                
                                <!-- Submit Button -->
                                <button type="submit" id="submitBtn" class="button is-primary is-fullwidth">
                                    <span class="icon">
                                        <i class="fas fa-paper-plane"></i>
                                    </span>
                                    <span>Send Reset Link</span>
                                </button>
                            </form>

                            <script>
                                (function () {
                                    var submitted = false;

                                    document.getElementById('forgotPasswordForm').addEventListener('submit', function () {
                                        if (submitted) return false;
                                        submitted = true;

                                        var btn = document.getElementById('submitBtn');
                                        // Bulma's is-loading hides the button content and shows a CSS spinner natively
                                        btn.classList.add('is-loading');
                                        btn.style.pointerEvents = 'none'; // block clicks without using disabled
                                    });
                                })();
                            </script>
                            
                            <!-- Error Message -->
                            <?php if ($messageType === "error" && !empty($message)): ?>
                                <div class="notification is-danger mt-4">
                                    <p><?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?></p>
                                </div>
                            <?php endif; ?>
                            
                            <!-- Information Box -->
                            <div class="box mt-5 has-background-light">
                                <p class="has-text-grey-dark">
                                    <span class="icon-text">
                                        <span class="icon has-text-info">
                                            <i class="fas fa-info-circle"></i>
                                        </span>
                                        <span><strong>What happens next?</strong></span>
                                    </span>
                                </p>
                                <ul class="has-text-grey-dark mt-3" style="margin-left: 1.5rem;">
                                    <li>If your email is registered, you'll receive a reset link</li>
                                    <li>The link is valid for <?php echo TOKEN_EXPIRY_HOURS; ?> hour</li>
                                    <li>Check your spam folder if you don't see the email</li>
                                    <li>You can request a new link if the current one expires</li>
                                </ul>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
                
                <!-- Footer Link -->
                <footer class="card-footer">
                    <a href="login.php" class="card-footer-item has-text-dark">
                        <span class="icon">
                            <i class="fas fa-arrow-left"></i>
                        </span>
                        <span>Back to Login</span>
                    </a>
                </footer>
            </div>
        </div>
    </section>
</body>

</html>