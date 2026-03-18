<?php
/**
 * study-import.php
 *
 * Imports study configuration from JSON file.
 * Validates file, filters sensitive fields, and encrypts data.
 *
 * SECURITY NOTE: API keys are never imported for security reasons.
 * Users must configure API keys separately after import.
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

define('MAX_FILE_SIZE', 5 * 1024 * 1024); // 5MB
define('STUDY_CODE_LENGTH', 48);
define('MAX_STUDY_NAME_LENGTH', 200);

// Columns that should never be imported
define('EXCLUDED_IMPORT_COLUMNS', [
    'studyID',                      // Auto-generated
    'studyCode',                    // Auto-generated
    'studyOwner',                   // Set from session
    'lastEdited',                   // Auto-updated by database
    'openaiApiKey',                 // SECURITY: Never import API keys
    'openrouterApiKey',             // SECURITY: Never import API keys
    'customConnectorConfiguration'  // SECURITY: May contain credentials
]);

// Fields that require encryption before storage
define('ENCRYPT_FIELDS', [
    'experimentalConditions',
    'aiInstructions',
    'participantInstructions',
    'aiName',
    'aiStatusMessage',
    'aiDescription',
    'firstAiMessage',
    'aiTypingBubbleText'
]);

// Fields that may contain JSON arrays that need encoding
define('JSON_FIELDS', [
    'experimentalConditions',
    'participantInstructions',
    'aiInstructions'
]);

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Send JSON response and exit
 *
 * @param string $status Status code ('good' or 'bad')
 * @param string $message Optional message
 * @param int|null $studyID Optional study ID
 * @param array $missingColumns Optional list of missing columns
 * @param int $httpCode HTTP status code
 */
function sendResponse(string $status, string $message = '', ?int $studyID = null, array $missingColumns = [], int $httpCode = 200): void
{
    http_response_code($httpCode);
    
    $response = ['status' => $status];
    
    if ($message !== '') {
        $response['message'] = $message;
    }
    
    if ($studyID !== null) {
        $response['studyID'] = $studyID;
    }
    
    if (!empty($missingColumns)) {
        $response['missingColumns'] = $missingColumns;
    }
    
    echo json_encode($response);
    exit;
}

/**
 * Generate cryptographically secure random key
 *
 * @param int $length Length of the key to generate
 * @return string Random alphanumeric key
 */
function generateSecureRandomKey(int $length): string
{
    $randomBytes = random_bytes((int)ceil($length / 2));
    $hexString = bin2hex($randomBytes);
    return substr($hexString, 0, $length);
}

/**
 * Validate uploaded JSON file
 *
 * @param array $file $_FILES array for the uploaded file
 * @return array Result with 'valid' boolean, 'data' array, and 'message' string
 */
function validateJsonFile(array $file): array
{
    $result = ['valid' => false, 'data' => null, 'message' => ''];
    
    // Check if file was uploaded
    if (!isset($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
        $result['message'] = 'No file uploaded';
        return $result;
    }
    
    // Check file size
    if ($file['size'] > MAX_FILE_SIZE) {
        $result['message'] = 'File size exceeds ' . (MAX_FILE_SIZE / 1024 / 1024) . 'MB limit';
        return $result;
    }
    
    // Check file extension
    $filename = $file['name'];
    $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    
    if ($extension !== 'json') {
        $result['message'] = 'Invalid file type. Only JSON files are allowed';
        return $result;
    }
    
    // Read file contents
    $jsonContent = file_get_contents($file['tmp_name']);
    
    if ($jsonContent === false) {
        $result['message'] = 'Failed to read file';
        return $result;
    }
    
    // Parse JSON
    $data = json_decode($jsonContent, true);
    
    if (json_last_error() !== JSON_ERROR_NONE) {
        $result['message'] = 'Invalid JSON format: ' . json_last_error_msg();
        return $result;
    }
    
    // Validate that data is an array and not empty
    if (!is_array($data) || empty($data)) {
        $result['message'] = 'JSON file must contain study configuration data';
        return $result;
    }
    
    $result['valid'] = true;
    $result['data'] = $data;
    return $result;
}

/**
 * Validate study name
 *
 * @param string $name Study name to validate
 * @return array Result with 'valid' boolean, 'sanitized' string, and 'message' string
 */
function validateStudyName(string $name): array
{
    $result = ['valid' => false, 'sanitized' => '', 'message' => ''];
    
    $name = trim($name);
    
    if (empty($name)) {
        $result['message'] = 'Study name is required';
        return $result;
    }
    
    if (strlen($name) > MAX_STUDY_NAME_LENGTH) {
        $result['message'] = 'Study name must be ' . MAX_STUDY_NAME_LENGTH . ' characters or less';
        return $result;
    }
    
    // Check for control characters
    if (preg_match('/[\x00-\x1F\x7F]/', $name)) {
        $result['message'] = 'Study name contains invalid characters';
        return $result;
    }
    
    $result['valid'] = true;
    $result['sanitized'] = $name;
    return $result;
}

/**
 * Filter and prepare study data for import
 *
 * @param object $database Medoo database instance
 * @param array $importData Data from JSON file
 * @param int $userID User ID who owns the study
 * @param string $studyName Name for the imported study
 * @return array Result with 'success' boolean, 'data' array, 'missingColumns' array, and 'message' string
 */
function prepareStudyData($database, array $importData, int $userID, string $studyName): array
{
    $result = ['success' => false, 'data' => [], 'missingColumns' => [], 'message' => ''];
    
    try {
        // Get current table columns
        $currentColumns = $database->query("SHOW COLUMNS FROM studies")->fetchAll(PDO::FETCH_COLUMN);
        
        // Filter data to only include valid columns
        $filteredData = array_intersect_key($importData, array_flip($currentColumns));
        
        // Track columns that were in import but not in current schema
        $missingColumns = array_diff(array_keys($importData), array_keys($filteredData));
        
        // Remove excluded columns from import data
        foreach (EXCLUDED_IMPORT_COLUMNS as $excludedColumn) {
            if (isset($filteredData[$excludedColumn])) {
                unset($filteredData[$excludedColumn]);
                error_log("Excluded column '$excludedColumn' removed from import data");
            }
        }
        
        // Set required fields
        $filteredData['studyOwner'] = $userID;
        $filteredData['studyCode'] = generateSecureRandomKey(STUDY_CODE_LENGTH);
        $filteredData['studyName'] = $studyName;
        $filteredData['isEncrypted'] = isset($filteredData['isEncrypted']) ? (int)$filteredData['isEncrypted'] : 1;
        
        // Convert JSON arrays to strings
        foreach (JSON_FIELDS as $field) {
            if (isset($filteredData[$field]) && is_array($filteredData[$field])) {
                $filteredData[$field] = json_encode($filteredData[$field], JSON_UNESCAPED_UNICODE);
            }
        }
        
        $result['success'] = true;
        $result['data'] = $filteredData;
        $result['missingColumns'] = array_values($missingColumns);
        
        return $result;
        
    } catch (Exception $e) {
        error_log("Error preparing study data: " . $e->getMessage());
        $result['message'] = 'Failed to prepare study data';
        return $result;
    }
}

/**
 * Encrypt sensitive study fields
 *
 * @param array $data Study data to encrypt
 * @return array Study data with encrypted fields
 */
function encryptStudyFields(array $data): array
{
    // Only encrypt if encryption is enabled
    if (empty($data['isEncrypted'])) {
        return $data;
    }
    
    try {
        foreach (ENCRYPT_FIELDS as $field) {
            if (isset($data[$field]) && $data[$field] !== '' && $data[$field] !== null) {
                $encrypted = encryptString($data[$field]);
                
                if ($encrypted !== false) {
                    $data[$field] = $encrypted;
                } else {
                    error_log("Warning: Failed to encrypt field '$field'");
                }
            }
        }
        
    } catch (Exception $e) {
        error_log("Error encrypting study fields: " . $e->getMessage());
    }
    
    return $data;
}

/**
 * Import study into database
 *
 * @param object $database Medoo database instance
 * @param array $studyData Prepared and encrypted study data
 * @return array Result with 'success' boolean, 'studyID' int, and 'message' string
 */
function importStudy($database, array $studyData): array
{
    $result = ['success' => false, 'studyID' => null, 'message' => ''];
    
    try {
        // Insert study into database
        $database->insert("studies", $studyData);
        
        $insertedID = $database->id();
        
        if (!$insertedID) {
            error_log("Failed to import study - no ID returned");
            $result['message'] = 'Failed to import study';
            return $result;
        }
        
        $result['success'] = true;
        $result['studyID'] = (int)$insertedID;
        $result['message'] = 'Study imported successfully';
        
        error_log("Study imported successfully with ID: $insertedID");
        
        return $result;
        
    } catch (Exception $e) {
        error_log("Error importing study: " . $e->getMessage());
        $result['message'] = 'An error occurred while importing the study';
        return $result;
    }
}

// =============================================================================
// MAIN LOGIC
// =============================================================================

// Authentication check
if (!isset($_SESSION['pm_loggedin']) || $_SESSION['pm_loggedin'] !== true) {
    sendResponse('bad', 'Unauthorized', null, [], 401);
}

// Verify user ID exists in session
if (!isset($_SESSION['userID'])) {
    sendResponse('bad', 'Invalid session', null, [], 400);
}

// CSRF token validation
if (!isset($_POST['csrf_token']) || !isset($_SESSION['csrf_token'])) {
    error_log("CSRF token missing in study import request");
    sendResponse('bad', 'Invalid request', null, [], 403);
}

if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    error_log("CSRF token validation failed in study import request");
    sendResponse('bad', 'Invalid request', null, [], 403);
}

// Verify this is a POST request
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendResponse('bad', 'Invalid request method', null, [], 405);
}

// Get session user ID
$sessionUserID = (int)$_SESSION['userID'];

if ($sessionUserID <= 0) {
    sendResponse('bad', 'Invalid session user ID', null, [], 400);
}

// Get posted user ID and verify authorization
$postedUserID = isset($_POST['studyOwner']) ? (int)$_POST['studyOwner'] : 0;

// CRITICAL: User can only import studies for themselves
if ($sessionUserID !== $postedUserID) {
    error_log("Authorization violation: User $sessionUserID attempted to import study for user $postedUserID");
    sendResponse('bad', 'Unauthorized - you can only import studies for yourself', null, [], 403);
}

// Validate study name
if (!isset($_POST['studyName'])) {
    sendResponse('bad', 'Study name is required', null, [], 400);
}

$nameValidation = validateStudyName($_POST['studyName']);
if (!$nameValidation['valid']) {
    sendResponse('bad', $nameValidation['message'], null, [], 400);
}

// Validate file upload
if (!isset($_FILES['jsonFile'])) {
    sendResponse('bad', 'No file uploaded', null, [], 400);
}

$fileValidation = validateJsonFile($_FILES['jsonFile']);
if (!$fileValidation['valid']) {
    sendResponse('bad', $fileValidation['message'], null, [], 400);
}

// Load database and crypto utilities
require '../MySQL/medoo.php';
require '../MySQL/medoo-Credentials.php';
require '../Util/crypto.php';

// Prepare study data
$prepareResult = prepareStudyData(
    $database,
    $fileValidation['data'],
    $sessionUserID,
    $nameValidation['sanitized']
);

if (!$prepareResult['success']) {
    sendResponse('bad', $prepareResult['message'], null, [], 500);
}

// Encrypt sensitive fields
$encryptedData = encryptStudyFields($prepareResult['data']);

// Import study
$importResult = importStudy($database, $encryptedData);

if ($importResult['success']) {
    sendResponse(
        'good',
        $importResult['message'],
        $importResult['studyID'],
        $prepareResult['missingColumns'],
        200
    );
} else {
    sendResponse('bad', $importResult['message'], null, [], 500);
}
?>