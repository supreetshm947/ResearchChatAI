<?php
/**
 * files-delete-all.php
 *
 * Deletes all uploaded files for a study after verifying user ownership.
 * Marks files as deleted in database and removes files from filesystem.
 *
 * ResearchChatAI
 * Authors: Marc Becker, David de Jong
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

header("X-Content-Type-Options: nosniff");
header('Content-Type: application/json');
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

// =============================================================================
// CONSTANTS
// =============================================================================

// Base directory for uploaded files - must be set correctly
define('BASE_FILE_PATH', realpath(__DIR__));
define('MAX_FILE_DELETE_ATTEMPTS', 3);
define('FILE_DELETE_RETRY_DELAY_MS', 100);

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Send JSON response and exit
 *
 * @param string $status Status code ('good' or 'bad')
 * @param string $message Optional message
 * @param int|null $studyID Optional study ID
 * @param int $httpCode HTTP status code
 */
function sendResponse(string $status, string $message = '', ?int $studyID = null, int $httpCode = 200): void
{
    http_response_code($httpCode);
    
    $response = ['status' => $status];
    
    if ($message !== '') {
        $response['message'] = $message;
    }
    
    if ($studyID !== null) {
        $response['studyID'] = $studyID;
    }
    
    echo json_encode($response);
    exit;
}

/**
 * Verify study ownership via study code
 *
 * @param object $database Medoo database instance
 * @param string $studyCode Study code
 * @param int $userID User ID to verify
 * @return array|false Study data or false if not found/unauthorized
 */
function verifyStudyOwnership($database, string $studyCode, int $userID)
{
    try {
        // Get study ID and owner from study code
        $study = $database->get("studies", [
            "studyID",
            "studyOwner"
        ], [
            "studyCode" => $studyCode
        ]);
        
        if (!$study) {
            return false;
        }
        
        // Type-cast and verify ownership
        $studyID = (int)$study['studyID'];
        $studyOwnerID = (int)$study['studyOwner'];
        
        if ($studyOwnerID !== $userID) {
            error_log("Authorization violation: User $userID attempted to delete files for study $studyID owned by user $studyOwnerID");
            return false;
        }
        
        return [
            'studyID' => $studyID,
            'studyOwner' => $studyOwnerID
        ];
        
    } catch (Exception $e) {
        error_log("Error verifying study ownership: " . $e->getMessage());
        return false;
    }
}

/**
 * Safely delete a file with path traversal protection
 *
 * @param string $filePath Relative file path from database
 * @return bool True if file was deleted successfully or doesn't exist
 */
function safeDeleteFile(string $filePath): bool
{
    try {
        // Construct full path
        $fullPath = realpath(BASE_FILE_PATH . '/' . $filePath);
        
        // CRITICAL: Verify path is within allowed directory
        if ($fullPath === false || strpos($fullPath, BASE_FILE_PATH) !== 0) {
            error_log("Path traversal attempt detected: $filePath");
            return false;
        }
        
        // Check if file exists
        if (!file_exists($fullPath)) {
            return true; // Already deleted or never existed
        }
        
        // Verify it's a file (not a directory)
        if (!is_file($fullPath)) {
            error_log("Attempted to delete non-file: $fullPath");
            return false;
        }
        
        // Attempt deletion with retry logic
        for ($attempt = 1; $attempt <= MAX_FILE_DELETE_ATTEMPTS; $attempt++) {
            if (@unlink($fullPath)) {
                return true;
            }
            
            // If not last attempt, wait before retrying
            if ($attempt < MAX_FILE_DELETE_ATTEMPTS) {
                usleep(FILE_DELETE_RETRY_DELAY_MS * 1000);
            }
        }
        
        error_log("Failed to delete file after " . MAX_FILE_DELETE_ATTEMPTS . " attempts: $fullPath");
        return false;
        
    } catch (Exception $e) {
        error_log("Error deleting file '$filePath': " . $e->getMessage());
        return false;
    }
}

/**
 * Delete all files for a study
 *
 * @param object $database Medoo database instance
 * @param int $studyID Study ID
 * @return array Result with 'success' boolean, 'deletedCount' int, 'failedCount' int, and 'message' string
 */
function deleteAllStudyFiles($database, int $studyID): array
{
    $result = [
        'success' => false,
        'deletedCount' => 0,
        'failedCount' => 0,
        'message' => ''
    ];
    
    try {
        // Get all non-deleted file paths for this study
        $files = $database->select('files', [
            'fileID',
            'filePath'
        ], [
            'studyID' => $studyID,
            'deleted' => 0
        ]);
        
        if (empty($files)) {
            $result['success'] = true;
            $result['message'] = 'No files to delete';
            return $result;
        }
        
        $deletedCount = 0;
        $failedCount = 0;
        $fileIDs = [];
        
        // Delete each file
        foreach ($files as $file) {
            $fileIDs[] = $file['fileID'];
            
            if (safeDeleteFile($file['filePath'])) {
                $deletedCount++;
            } else {
                $failedCount++;
                error_log("Failed to delete file: {$file['filePath']} (fileID: {$file['fileID']})");
            }
        }
        
        // Mark all files as deleted in database (even if physical deletion failed)
        // This prevents orphaned database records
        if (!empty($fileIDs)) {
            $database->update('files', [
                'deleted' => 1
            ], [
                'fileID' => $fileIDs
            ]);
        }
        
        $result['success'] = true;
        $result['deletedCount'] = $deletedCount;
        $result['failedCount'] = $failedCount;
        
        if ($failedCount > 0) {
            $result['message'] = "Deleted $deletedCount files, $failedCount failed";
            error_log("Study $studyID: Deleted $deletedCount files, $failedCount failed");
        } else {
            $result['message'] = "All $deletedCount files deleted successfully";
            error_log("Study $studyID: All $deletedCount files deleted successfully");
        }
        
        return $result;
        
    } catch (Exception $e) {
        error_log("Error deleting files for study $studyID: " . $e->getMessage());
        $result['message'] = 'An error occurred while deleting files';
        return $result;
    }
}

// =============================================================================
// MAIN LOGIC
// =============================================================================

// Authentication check
if (!isset($_SESSION['pm_loggedin']) || $_SESSION['pm_loggedin'] !== true) {
    sendResponse('bad', 'Unauthorized', null, 401);
}

// Verify user ID exists in session
if (!isset($_SESSION['userID'])) {
    sendResponse('bad', 'Invalid session', null, 400);
}

// CSRF token validation
if (!isset($_POST['csrf_token']) || !isset($_SESSION['csrf_token'])) {
    error_log("CSRF token missing in file deletion request");
    sendResponse('bad', 'Invalid request', null, 403);
}

if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    error_log("CSRF token validation failed in file deletion request");
    sendResponse('bad', 'Invalid request', null, 403);
}

// Verify this is a POST request
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendResponse('bad', 'Invalid request method', null, 405);
}

// Get session user ID
$sessionUserID = (int)$_SESSION['userID'];

if ($sessionUserID <= 0) {
    sendResponse('bad', 'Invalid session user ID', null, 400);
}

// Validate study code
if (!isset($_POST['studyCode'])) {
    sendResponse('bad', 'Missing studyCode parameter', null, 400);
}

$studyCode = trim($_POST['studyCode']);

if ($studyCode === '') {
    sendResponse('bad', 'Invalid studyCode parameter', null, 400);
}

// Load database
require '../MySQL/medoo.php';
require '../MySQL/medoo-Credentials.php';

// Verify study ownership
$study = verifyStudyOwnership($database, $studyCode, $sessionUserID);

if (!$study) {
    sendResponse('bad', 'Invalid studyCode or you do not have permission to access this study', null, 403);
}

$studyID = $study['studyID'];

// Delete all files for the study
$deleteResult = deleteAllStudyFiles($database, $studyID);

if ($deleteResult['success']) {
    sendResponse('good', $deleteResult['message'], $studyID, 200);
} else {
    sendResponse('bad', $deleteResult['message'], null, 500);
}
?>