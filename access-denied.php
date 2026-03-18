<?php
/**
 * access-denied.php
 *
 * Displays an access denied message when unauthenticated users
 * attempt to access protected resources.
 *
 * ResearchChatAI
 * Author: Marc Becker, David de Jong
 * License: MIT
 */

// Error reporting for development (disable in production)
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(E_ALL);

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
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");

// Prevent caching of access denied page
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");
header("Expires: 0");

// Force HTTPS in production (uncomment when using HTTPS)
// header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");

// Set appropriate HTTP status code
http_response_code(403);

?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Access Denied - ResearchChatAI</title>

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
            
            <!-- Access Denied Card -->
            <div id="loginCard" class="card">
                <header class="card-header has-background-danger">
                    <p class="card-header-title has-text-white">
                        <span class="icon">
                            <i class="fas fa-exclamation-triangle"></i>
                        </span>
                        <span>Access Denied</span>
                    </p>
                </header>
                
                <div class="card-content">
                    <div class="content has-text-centered">
                        <p class="mb-5">
                            You do not have permission to access this page.
                        </p>
                        <p class="mb-5">
                            Please log in to continue.
                        </p>
                        
                        <!-- Action Buttons -->
                        <div class="buttons is-centered">
                            <a href="login.php" class="button is-primary">
                                <span class="icon">
                                    <i class="fas fa-sign-in-alt"></i>
                                </span>
                                <span>Go to Login</span>
                            </a>
                            <a href="index.php" class="button is-light">
                                <span class="icon">
                                    <i class="fas fa-arrow-left"></i>
                                </span>
                                <span>Go Back</span>
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>
</body>

</html>