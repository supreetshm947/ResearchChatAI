<?php
/**
 * messages-delete-all.php
 *
 * Deletes all messages for a study after verifying user ownership.
 * Provides statistics on deletion operation.
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
// HELPER FUNCTIONS
// =============================================================================

/**
 * Send JSON response and exit
 *
 * @param string $status Status code ('good' or 'bad')
 * @param string $message Optional message
 * @param int|null $studyID Optional study ID
 * @param int|null $deletedCount Optional count of deleted messages
 * @param int $httpCode HTTP status code
 */
function sendResponse(string $status, string $message = '', ?int $studyID = null, ?int $deletedCount = null, int $httpCode = 200): void
{
    http_response_code($httpCode);
    
    $response = ['status' => $status];
    
    if ($message !== '') {
        $response['message'] = $message;
    }
    
    if ($studyID !== null) {
        $response['studyID'] = $studyID;
    }
    
    if ($deletedCount !== null) {
        $response['deletedCount'] = $deletedCount;
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
            error_log("Authorization violation: User $userID attempted to delete messages for study $studyID owned by user $studyOwnerID");
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
 * Delete all messages for a study
 *
 * @param object $database Medoo database instance
 * @param int $studyID Study ID
 * @return array Result with 'success' boolean, 'deletedCount' int, and 'message' string
 */
function deleteAllMessages($database, int $studyID): array
{
    $result = ['success' => false, 'deletedCount' => 0, 'message' => ''];
    
    try {
        // Count messages before deletion
        $messageCount = $database->count("messages", [
            "studyID" => $studyID
        ]);
        
        if ($messageCount === 0) {
            $result['success'] = true;
            $result['message'] = 'No messages to delete';
            return $result;
        }
        
        // Delete all messages for the study
        $deleteResult = $database->delete("messages", [
            "studyID" => $studyID
        ]);
        
        if ($deleteResult === false) {
            error_log("Failed to delete messages for study $studyID");
            $result['message'] = 'Failed to delete messages';
            return $result;
        }
        
        // PDOStatement::rowCount() returns the number of affected rows
        $deletedCount = is_object($deleteResult) ? $deleteResult->rowCount() : $messageCount;
        
        $result['success'] = true;
        $result['deletedCount'] = $deletedCount;
        $result['message'] = "Successfully deleted $deletedCount messages";
        
        error_log("Study $studyID: Deleted $deletedCount messages");
        
        return $result;
        
    } catch (Exception $e) {
        error_log("Error deleting messages for study $studyID: " . $e->getMessage());
        $result['message'] = 'An error occurred while deleting messages';
        return $result;
    }
}

// =============================================================================
// MAIN LOGIC
// =============================================================================

// Authentication check
if (!isset($_SESSION['pm_loggedin']) || $_SESSION['pm_loggedin'] !== true) {
    sendResponse('bad', 'Unauthorized', null, null, 401);
}

// Verify user ID exists in session
if (!isset($_SESSION['userID'])) {
    sendResponse('bad', 'Invalid session', null, null, 400);
}

// CSRF token validation
// TODO: Make this required once frontend is updated
if (isset($_POST['csrf_token']) && isset($_SESSION['csrf_token'])) {
    if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        error_log("CSRF token validation failed in message deletion request");
        sendResponse('bad', 'Invalid request', null, null, 403);
    }
} else {
    // Log warning but allow request (backward compatibility)
    error_log("WARNING: Message deletion request without CSRF token - update frontend to include token");
}

// Verify this is a POST request
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendResponse('bad', 'Invalid request method', null, null, 405);
}

// Get session user ID
$sessionUserID = (int)$_SESSION['userID'];

if ($sessionUserID <= 0) {
    sendResponse('bad', 'Invalid session user ID', null, null, 400);
}

// Validate study code
if (!isset($_POST['studyCode'])) {
    sendResponse('bad', 'Missing studyCode parameter', null, null, 400);
}

$studyCode = trim($_POST['studyCode']);

if ($studyCode === '') {
    sendResponse('bad', 'Invalid studyCode parameter', null, null, 400);
}

// Load database
require '../MySQL/medoo.php';
require '../MySQL/medoo-Credentials.php';

// Verify study ownership
$study = verifyStudyOwnership($database, $studyCode, $sessionUserID);

if (!$study) {
    sendResponse('bad', 'Invalid studyCode or you do not have permission to access this study', null, null, 403);
}

$studyID = $study['studyID'];

// Delete all messages for the study
$deleteResult = deleteAllMessages($database, $studyID);

if ($deleteResult['success']) {
    sendResponse(
        'good',
        $deleteResult['message'],
        $studyID,
        $deleteResult['deletedCount'],
        200
    );
} else {
    sendResponse('bad', $deleteResult['message'], null, null, 500);
}