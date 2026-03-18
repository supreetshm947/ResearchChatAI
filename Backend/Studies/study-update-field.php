<?php
/**
 * study-update-field.php
 *
 * Updates a single field in a study after verifying user ownership.
 * Enforces field whitelisting and handles encryption for sensitive fields.
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

// CRITICAL: These fields CANNOT be updated via this endpoint (blocklist approach)
define('FORBIDDEN_FIELDS', [
    'studyID',      // Primary key - immutable
    'studyCode',    // Security identifier - changing enables unauthorized access
    'studyOwner',   // Ownership field - changing enables account takeover
    'isEncrypted',  // Encryption flag - changing would break encryption/decryption
    'lastEdited'    // Auto-updated timestamp - should not be manually set
]);

// All other fields in the studies table CAN be updated via this endpoint
// This blocklist approach allows new fields to be added without code changes

// Fields that should be encrypted if study has encryption enabled
define('ENCRYPTED_FIELDS', [
    'openaiApiKey',
    'openrouterApiKey',
    'experimentalConditions',
    'aiInstructions',
    'participantInstructions',
    'aiName',
    'aiStatusMessage',
    'aiDescription',
    'firstAiMessage',
    'aiTypingBubbleText',
    'customConnectorConfiguration'
]);

// Maximum field value length (prevent DoS)
define('MAX_FIELD_VALUE_LENGTH', 100000); // 100KB

// =============================================================================
// DEPENDENCIES
// =============================================================================

require '../MySQL/medoo.php';
require '../MySQL/medoo-Credentials.php';
require '../Util/crypto.php';

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
 * Validate field key is not in forbidden list
 *
 * @param string $fieldKey Field key to validate
 * @return array Result with 'valid' boolean and 'message' string
 */
function validateFieldKey(string $fieldKey): array
{
    $result = ['valid' => false, 'message' => ''];
    
    if ($fieldKey === '') {
        $result['message'] = 'Field key cannot be empty';
        return $result;
    }
    
    // CRITICAL: Block forbidden fields (blocklist approach)
    if (in_array($fieldKey, FORBIDDEN_FIELDS, true)) {
        $result['message'] = "Field '$fieldKey' is protected and cannot be updated";
        error_log("SECURITY: Attempt to update forbidden field '$fieldKey'");
        return $result;
    }
    
    // All other fields are allowed (scalable approach)
    $result['valid'] = true;
    return $result;
}

/**
 * Validate field value
 *
 * @param mixed $fieldValue Field value to validate
 * @param string $fieldKey Field key for context
 * @return array Result with 'valid' boolean, 'sanitized' value, and 'message' string
 */
function validateFieldValue($fieldValue, string $fieldKey): array
{
    $result = ['valid' => false, 'sanitized' => null, 'message' => ''];
    
    // Allow null/empty values (for clearing fields)
    if ($fieldValue === null || $fieldValue === '') {
        $result['valid'] = true;
        $result['sanitized'] = '';
        return $result;
    }
    
    // Convert to string
    $fieldValue = (string)$fieldValue;
    
    // Check length to prevent DoS
    if (strlen($fieldValue) > MAX_FIELD_VALUE_LENGTH) {
        $result['message'] = 'Field value exceeds maximum length';
        return $result;
    }
    
    // Check for null bytes
    if (strpos($fieldValue, "\0") !== false) {
        $result['message'] = 'Field value contains invalid characters';
        return $result;
    }
    
    $result['valid'] = true;
    $result['sanitized'] = $fieldValue;
    return $result;
}

/**
 * Verify study ownership
 *
 * @param object $database Medoo database instance
 * @param int $studyID Study ID
 * @param int $userID User ID to verify
 * @return array|false Study data or false if not found/unauthorized
 */
function verifyStudyOwnership($database, int $studyID, int $userID)
{
    try {
        // Get study with owner and encryption info
        $study = $database->get("studies", [
            "studyID",
            "studyOwner",
            "isEncrypted"
        ], [
            "studyID" => $studyID
        ]);
        
        if (!$study) {
            return false;
        }
        
        // CRITICAL: Verify user owns this study
        $studyOwnerID = (int)$study['studyOwner'];
        
        if ($studyOwnerID !== $userID) {
            error_log("Authorization violation: User $userID attempted to update study $studyID owned by user $studyOwnerID");
            return false;
        }
        
        return $study;
        
    } catch (Exception $e) {
        error_log("Error verifying study ownership: " . $e->getMessage());
        return false;
    }
}

/**
 * Update study field
 *
 * @param object $database Medoo database instance
 * @param int $studyID Study ID
 * @param string $fieldKey Field to update
 * @param string $fieldValue New value
 * @param bool $isEncrypted Whether study has encryption enabled
 * @return bool Success status
 */
function updateStudyField($database, int $studyID, string $fieldKey, string $fieldValue, bool $isEncrypted): bool
{
    try {
        // Encrypt value if needed
        $valueToStore = $fieldValue;
        
        if ($isEncrypted && in_array($fieldKey, ENCRYPTED_FIELDS, true)) {
            $encrypted = encryptString($fieldValue);
            
            if ($encrypted !== false && $encrypted !== '') {
                $valueToStore = $encrypted;
            } else {
                error_log("Failed to encrypt field '$fieldKey' for study $studyID");
                return false;
            }
        }
        
        // Update the field
        $updateResult = $database->update('studies', [
            $fieldKey => $valueToStore,
            'lastEdited' => date('Y-m-d H:i:s')
        ], [
            'studyID' => $studyID
        ]);
        
        if ($updateResult === false) {
            error_log("Failed to update field '$fieldKey' for study $studyID");
            return false;
        }
        
        error_log("Study $studyID: Updated field '$fieldKey'");
        
        return true;
        
    } catch (Exception $e) {
        error_log("Error updating study field: " . $e->getMessage());
        return false;
    }
}

/**
 * Update user's last active timestamp
 *
 * @param object $database Medoo database instance
 * @param int $userID User ID
 */
function updateUserActivity($database, int $userID): void
{
    try {
        $database->update('users', [
            'userLastActiveDate' => date('Y-m-d H:i:s')
        ], [
            'userID' => $userID
        ]);
    } catch (Exception $e) {
        error_log("Error updating user activity: " . $e->getMessage());
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
    error_log("CSRF token missing in study update request");
    sendResponse('bad', 'Invalid request', null, 403);
}
if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    error_log("CSRF token validation failed in study update request");
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

// Validate studyID parameter
if (!isset($_POST['studyID'])) {
    sendResponse('bad', 'Missing studyID parameter', null, 400);
}

$studyID = (int)$_POST['studyID'];

if ($studyID <= 0) {
    sendResponse('bad', 'Invalid studyID parameter', null, 400);
}

// Validate fieldKey parameter
if (!isset($_POST['fieldKey'])) {
    sendResponse('bad', 'Missing fieldKey parameter', null, 400);
}

$fieldKey = trim($_POST['fieldKey']);

$fieldKeyValidation = validateFieldKey($fieldKey);

if (!$fieldKeyValidation['valid']) {
    sendResponse('bad', $fieldKeyValidation['message'], null, 400);
}

// Validate fieldValue parameter
if (!isset($_POST['fieldValue'])) {
    sendResponse('bad', 'Missing fieldValue parameter', null, 400);
}

$fieldValue = $_POST['fieldValue'];

$fieldValueValidation = validateFieldValue($fieldValue, $fieldKey);

if (!$fieldValueValidation['valid']) {
    sendResponse('bad', $fieldValueValidation['message'], null, 400);
}

$sanitizedValue = $fieldValueValidation['sanitized'];

// Verify study ownership
$study = verifyStudyOwnership($database, $studyID, $sessionUserID);

if (!$study) {
    sendResponse('bad', 'Invalid studyID or you do not have permission to access this study', null, 403);
}

// Check if encryption is enabled
$isEncrypted = !empty($study['isEncrypted']);

// Update the field
if (!updateStudyField($database, $studyID, $fieldKey, $sanitizedValue, $isEncrypted)) {
    sendResponse('bad', 'Failed to update field', null, 500);
}

// Update user activity
updateUserActivity($database, $sessionUserID);

// Success response
sendResponse('good', 'Field updated successfully', $studyID, 200);
?>