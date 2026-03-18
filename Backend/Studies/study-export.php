<?php
/**
 * study-export.php
 *
 * Exports study configuration as JSON file after verifying user ownership.
 * Decrypts sensitive fields before export.
 *
 * SECURITY NOTE: API keys and credentials are NEVER exported for security.
 * Only study configuration (settings, messages, instructions) is exported.
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

// Note: Content-Type and Content-Disposition headers are set later for download

header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

// =============================================================================
// CONSTANTS
// =============================================================================

// Columns to exclude from export for security reasons
define('EXCLUDED_COLUMNS', [
    'studyID',                          // Internal database ID
    'studyCode',                        // Participant access code (security risk)
    'studyOwner',                       // User ID who owns the study
    'apiKey',                           // Legacy API key field
    'openaiApiKey',                     // OpenAI API key (CRITICAL - never export)
    'openrouterApiKey',                 // OpenRouter API key (CRITICAL - never export)
    'customConnectorConfiguration',     // May contain sensitive credentials
    'lastEdited'                        // Metadata timestamp
]);

// Fields that require decryption before export
// Note: API keys are excluded above and never decrypted for export
define('ENCRYPTED_FIELDS', [
    'experimentalConditions',
    'aiInstructions',
    'participantInstructions',
    'aiName',
    'aiStatusMessage',
    'aiDescription',
    'firstAiMessage',
    'aiTypingBubbleText'
]);

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Send error response and exit
 *
 * @param string $message Error message to display
 * @param int $httpCode HTTP status code
 */
function sendError(string $message, int $httpCode = 500): void
{
    http_response_code($httpCode);
    
    // For downloads, send JSON error response
    header('Content-Type: application/json');
    echo json_encode([
        'status' => 'error',
        'message' => $message
    ]);
    exit;
}

/**
 * Verify study ownership
 *
 * @param object $database Medoo database instance
 * @param int $studyID Study ID to check
 * @param int $userID User ID to verify
 * @return bool True if user owns the study, false otherwise
 */
function verifyStudyOwnership($database, int $studyID, int $userID): bool
{
    try {
        $studyOwner = $database->get("studies", "studyOwner", [
            "studyID" => $studyID
        ]);
        
        if ($studyOwner === null || $studyOwner === false) {
            return false;
        }
        
        $studyOwnerID = (int)$studyOwner;
        
        if ($studyOwnerID !== $userID) {
            error_log("Authorization violation: User $userID attempted to export study $studyID owned by user $studyOwnerID");
            return false;
        }
        
        return true;
        
    } catch (Exception $e) {
        error_log("Error verifying study ownership: " . $e->getMessage());
        return false;
    }
}

/**
 * Get filtered study columns
 *
 * @param object $database Medoo database instance
 * @return array Array of column names to export
 */
function getExportColumns($database): array
{
    try {
        // Get all columns from studies table
        $allColumns = $database->query("SHOW COLUMNS FROM studies")->fetchAll(PDO::FETCH_COLUMN);
        
        // Filter out excluded columns
        $filteredColumns = array_diff($allColumns, EXCLUDED_COLUMNS);
        
        return array_values($filteredColumns);
        
    } catch (Exception $e) {
        error_log("Error fetching study columns: " . $e->getMessage());
        return [];
    }
}

/**
 * Decrypt study fields
 *
 * Decrypts non-sensitive fields like instructions and messages.
 * Note: API keys are excluded from export entirely and never decrypted.
 *
 * @param array $data Study data
 * @return array Decrypted study data
 */
function decryptStudyFields(array $data): array
{
    // Check if study uses encryption
    if (empty($data['isEncrypted'])) {
        return $data;
    }
    
    try {
        // Decrypt each encrypted field (excludes API keys - they're not exported)
        foreach (ENCRYPTED_FIELDS as $field) {
            if (isset($data[$field]) && $data[$field] !== '' && $data[$field] !== null) {
                $decrypted = decryptString($data[$field]);
                
                // Only update if decryption succeeded
                if ($decrypted !== false && $decrypted !== $data[$field]) {
                    $data[$field] = $decrypted;
                } else {
                    error_log("Warning: Failed to decrypt field '$field' or field was not encrypted");
                }
            }
        }
        
    } catch (Exception $e) {
        error_log("Error decrypting study fields: " . $e->getMessage());
        // Continue with partially decrypted data rather than failing completely
    }
    
    return $data;
}

/**
 * Export study data as JSON
 *
 * @param object $database Medoo database instance
 * @param int $studyID Study ID to export
 * @return array Study data ready for export
 */
function exportStudy($database, int $studyID): array
{
    try {
        // Get filtered columns for export
        $columns = getExportColumns($database);
        
        if (empty($columns)) {
            throw new Exception("Failed to retrieve study columns");
        }
        
        // Fetch study data
        $data = $database->get("studies", $columns, [
            "studyID" => $studyID
        ]);
        
        if (!$data) {
            throw new Exception("Study not found");
        }
        
        // Decrypt encrypted fields
        $data = decryptStudyFields($data);
        
        return $data;
        
    } catch (Exception $e) {
        error_log("Error exporting study $studyID: " . $e->getMessage());
        throw $e;
    }
}

// =============================================================================
// MAIN LOGIC
// =============================================================================

// Authentication check
if (!isset($_SESSION['pm_loggedin']) || $_SESSION['pm_loggedin'] !== true) {
    sendError('Unauthorized - please log in', 401);
}

// Verify user ID exists in session
if (!isset($_SESSION['userID'])) {
    sendError('Invalid session', 400);
}

// Verify this is a GET request
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    sendError('Invalid request method', 405);
}

// Get session user ID
$sessionUserID = (int)$_SESSION['userID'];

if ($sessionUserID <= 0) {
    sendError('Invalid session user ID', 400);
}

// Validate study ID parameter
if (!isset($_GET['studyID'])) {
    sendError('Missing studyID parameter', 400);
}

$studyID = (int)$_GET['studyID'];

if ($studyID <= 0) {
    sendError('Invalid studyID parameter', 400);
}

// Load database and crypto utilities
require '../MySQL/medoo.php';
require '../MySQL/medoo-Credentials.php';
require '../Util/crypto.php';

// Verify study ownership
if (!verifyStudyOwnership($database, $studyID, $sessionUserID)) {
    sendError('You do not have permission to export this study', 403);
}

// Export study data
try {
    $studyData = exportStudy($database, $studyID);
    
    // Sanitize filename to prevent directory traversal
    $safeStudyID = preg_replace('/[^0-9]/', '', (string)$studyID);
    $filename = 'study_' . $safeStudyID . '.json';
    
    // Set headers for JSON download
    header('Content-Type: application/json; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    
    // Output JSON with pretty printing
    echo json_encode($studyData, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    
    // Log successful export
    error_log("Study $studyID exported successfully by user $sessionUserID");
    
} catch (Exception $e) {
    error_log("Failed to export study $studyID: " . $e->getMessage());
    sendError('Failed to export study: ' . $e->getMessage(), 500);
}
?>