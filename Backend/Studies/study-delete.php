<?php
/**
 * study-delete.php
 *
 * Deletes a study after verifying user ownership.
 * Validates authorization and cascades deletion to related data.
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
 * Verify study ownership
 *
 * @param object $database Medoo database instance
 * @param int $studyID Study ID to check
 * @param int $userID User ID to verify
 * @return array Result with 'isOwner' boolean and 'message' string
 */
function verifyStudyOwnership($database, int $studyID, int $userID): array
{
    $result = ['isOwner' => false, 'message' => ''];
    
    try {
        // Get study owner from database
        $studyOwner = $database->get("studies", "studyOwner", [
            "studyID" => $studyID
        ]);
        
        if ($studyOwner === null || $studyOwner === false) {
            $result['message'] = 'Study not found';
            return $result;
        }
        
        // Type-cast and compare
        $studyOwnerID = (int)$studyOwner;
        
        if ($studyOwnerID !== $userID) {
            error_log("Authorization violation: User $userID attempted to delete study $studyID owned by user $studyOwnerID");
            $result['message'] = 'Unauthorized - you can only delete your own studies';
            return $result;
        }
        
        $result['isOwner'] = true;
        return $result;
        
    } catch (Exception $e) {
        error_log("Error verifying study ownership: " . $e->getMessage());
        $result['message'] = 'Error verifying study ownership';
        return $result;
    }
}

/**
 * Delete study and related data
 *
 * @param object $database Medoo database instance
 * @param int $studyID Study ID to delete
 * @return array Result with 'success' boolean and 'message' string
 */
function deleteStudy($database, int $studyID): array
{
    $result = ['success' => false, 'message' => ''];
    
    try {
        // Delete study from database
        // Note: Related data (messages, participants, etc.) should be handled
        // by database foreign key constraints with CASCADE DELETE
        $deleteResult = $database->delete("studies", [
            "studyID" => $studyID
        ]);
        
        if ($deleteResult === false) {
            error_log("Failed to delete study $studyID from database");
            $result['message'] = 'Failed to delete study';
            return $result;
        }
        
        $result['success'] = true;
        $result['message'] = 'Study deleted successfully';
        
        error_log("Study $studyID deleted successfully");
        
        return $result;
        
    } catch (Exception $e) {
        error_log("Error deleting study $studyID: " . $e->getMessage());
        $result['message'] = 'An error occurred while deleting the study';
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
    error_log("CSRF token missing in study deletion request");
    sendResponse('bad', 'Invalid request', null, 403);
}

if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    error_log("CSRF token validation failed in study deletion request");
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

// Get and validate study ID
$studyID = isset($_POST['studyID']) ? (int)$_POST['studyID'] : 0;

if ($studyID <= 0) {
    sendResponse('bad', 'Invalid study ID', null, 400);
}

// Load database
require '../MySQL/medoo.php';
require '../MySQL/medoo-Credentials.php';

// Verify study ownership
$ownershipCheck = verifyStudyOwnership($database, $studyID, $sessionUserID);

if (!$ownershipCheck['isOwner']) {
    $httpCode = ($ownershipCheck['message'] === 'Study not found') ? 404 : 403;
    sendResponse('bad', $ownershipCheck['message'], null, $httpCode);
}

// Delete study
$deleteResult = deleteStudy($database, $studyID);

if ($deleteResult['success']) {
    sendResponse('good', $deleteResult['message'], $studyID, 200);
} else {
    sendResponse('bad', $deleteResult['message'], null, 500);
}
?>