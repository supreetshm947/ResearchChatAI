<?php
/**
 * user-delete.php
 *
 * Permanently deletes a user account and all associated data including
 * studies, messages, submissions, and uploaded files.
 *
 * ResearchChatAI
 * Author: Marc Becker, David de Jong
 * License: MIT
 */

// Error reporting for development (disable in production)
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

session_start();

// =============================================================================
// SECURITY HEADERS
// =============================================================================

// Prevent MIME-type sniffing
header("X-Content-Type-Options: nosniff");

// Set JSON content type
header('Content-Type: application/json');

// Prevent caching of sensitive operations
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

// =============================================================================
// CONSTANTS
// =============================================================================

define('BASE_FILE_PATH', realpath(__DIR__ . '/../../'));
define('MAX_FILE_DELETE_ATTEMPTS', 3);

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Send JSON response and exit
 *
 * @param string $status Status code ('good' or 'bad')
 * @param string $message Optional message
 * @param int $httpCode HTTP status code
 */
function sendResponse(string $status, string $message = '', int $httpCode = 200): void
{
    http_response_code($httpCode);
    echo json_encode([
        'status' => $status,
        'message' => $message
    ]);
    exit;
}

/**
 * Safely delete file with path traversal protection
 *
 * @param string $filePath File path relative to base directory
 * @return bool True if deleted or doesn't exist, false on error
 */
function safeDeleteFile(string $filePath): bool
{
    // Construct absolute path
    $absolutePath = realpath(BASE_FILE_PATH . '/' . $filePath);
    
    // Security check: ensure path is within allowed directory
    if ($absolutePath === false || strpos($absolutePath, BASE_FILE_PATH) !== 0) {
        error_log("Path traversal attempt detected: " . $filePath);
        return false;
    }
    
    // Check if file exists
    if (!file_exists($absolutePath)) {
        return true; // Already deleted
    }
    
    // Verify it's a file (not a directory)
    if (!is_file($absolutePath)) {
        error_log("Attempted to delete non-file: " . $absolutePath);
        return false;
    }
    
    // Attempt deletion with retry logic
    for ($i = 0; $i < MAX_FILE_DELETE_ATTEMPTS; $i++) {
        if (@unlink($absolutePath)) {
            return true;
        }
        usleep(100000); // Wait 100ms before retry
    }
    
    error_log("Failed to delete file after " . MAX_FILE_DELETE_ATTEMPTS . " attempts: " . $absolutePath);
    return false;
}

/**
 * Delete user account and all associated data
 *
 * @param object $database Medoo database instance
 * @param int $userID User ID to delete
 * @return array Result with 'success' boolean and 'message' string
 */
function deleteUserAccount($database, int $userID): array
{
    $result = ['success' => false, 'message' => ''];
    
    try {
        // Fetch all study IDs owned by this user
        $studyIDs = $database->select('studies', 'studyID', [
            'studyOwner' => $userID
        ]);
        
        if ($studyIDs === false) {
            throw new Exception("Failed to fetch user studies");
        }
        
        if (!empty($studyIDs)) {
            // Delete messages related to these studies
            $messagesDeleted = $database->delete('messages', [
                'studyID' => $studyIDs
            ]);
            
            if ($messagesDeleted === false) {
                error_log("Warning: Failed to delete messages for user " . $userID);
            }
            
            // Delete submissions related to these studies
            $submissionsDeleted = $database->delete('submissions', [
                'studyID' => $studyIDs
            ]);
            
            if ($submissionsDeleted === false) {
                error_log("Warning: Failed to delete submissions for user " . $userID);
            }
            
            // Remove files from disk and database
            $files = $database->select('files', ['filePath', 'fileID'], [
                'studyID' => $studyIDs,
                'deleted' => 0
            ]);
            
            if ($files === false) {
                error_log("Warning: Failed to fetch files for user " . $userID);
            } elseif (!empty($files)) {
                $deletedFileCount = 0;
                $failedFileCount = 0;
                
                foreach ($files as $file) {
                    if (isset($file['filePath'])) {
                        if (safeDeleteFile($file['filePath'])) {
                            $deletedFileCount++;
                        } else {
                            $failedFileCount++;
                        }
                    }
                }
                
                error_log("Deleted " . $deletedFileCount . " files for user " . $userID . 
                         ($failedFileCount > 0 ? " (" . $failedFileCount . " failed)" : ""));
            }
            
            // Delete file records from database
            $fileRecordsDeleted = $database->delete('files', [
                'studyID' => $studyIDs
            ]);
            
            if ($fileRecordsDeleted === false) {
                error_log("Warning: Failed to delete file records for user " . $userID);
            }
            
            // Delete studies themselves
            $studiesDeleted = $database->delete('studies', [
                'studyID' => $studyIDs
            ]);
            
            if ($studiesDeleted === false) {
                throw new Exception("Failed to delete studies");
            }
        }
        
        // Delete user record
        $userDeleted = $database->delete('users', [
            'userID' => $userID
        ]);
        
        if ($userDeleted === false) {
            throw new Exception("Failed to delete user record");
        }
        
        $result['success'] = true;
        $result['message'] = 'Account deleted successfully';
        
        error_log("User account deleted successfully: userID " . $userID);
        
        return $result;
        
    } catch (Exception $e) {
        error_log("Error deleting user account (userID " . $userID . "): " . $e->getMessage());
        $result['message'] = 'An error occurred during account deletion';
        return $result;
    }
}

// =============================================================================
// MAIN LOGIC
// =============================================================================

// Authentication check
if (!isset($_SESSION['pm_loggedin']) || $_SESSION['pm_loggedin'] !== true) {
    sendResponse('bad', 'Unauthorized', 401);
}

// Verify user ID exists in session
if (!isset($_SESSION['userID'])) {
    sendResponse('bad', 'Invalid session', 400);
}

// CSRF token validation
if (!isset($_POST['csrf_token']) || !isset($_SESSION['csrf_token'])) {
    error_log("CSRF token missing in user-delete request");
    sendResponse('bad', 'Invalid request', 403);
}

if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    error_log("CSRF token validation failed in user-delete request");
    sendResponse('bad', 'Invalid request', 403);
}

// Verify this is a POST request
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendResponse('bad', 'Invalid request method', 405);
}

// Load database
require '../MySQL/medoo.php';
require '../MySQL/medoo-Credentials.php';

// Get user ID and sanitize
$userID = (int)$_SESSION['userID'];

if ($userID <= 0) {
    sendResponse('bad', 'Invalid user ID', 400);
}

// Perform account deletion
$deleteResult = deleteUserAccount($database, $userID);

if ($deleteResult['success']) {
    // Destroy session after successful deletion
    $_SESSION = [];
    
    // Destroy session cookie
    if (isset($_COOKIE[session_name()])) {
        setcookie(
            session_name(), 
            '', 
            [
                'expires' => time() - 3600,
                'path' => '/',
                'httponly' => true,
                'secure' => false, // Set to true when using HTTPS
                'samesite' => 'Strict'
            ]
        );
    }
    
    session_destroy();
    
    sendResponse('good', 'Account deleted successfully', 200);
} else {
    sendResponse('bad', $deleteResult['message'], 500);
}