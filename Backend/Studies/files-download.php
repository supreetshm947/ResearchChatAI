<?php
/**
 * files-download.php
 *
 * Downloads all uploaded files for a study as a ZIP archive.
 * Verifies user ownership and validates file paths for security.
 *
 * ResearchChatAI
 * Authors: Marc Becker, David de Jong
 * License: MIT
 */

// Error reporting for development (disable in production)
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

// =============================================================================
// SESSION INITIALIZATION
// =============================================================================

session_cache_limiter('nocache');
session_start();

// =============================================================================
// AUTHENTICATION CHECK
// =============================================================================

if (!isset($_SESSION['pm_loggedin']) || $_SESSION['pm_loggedin'] !== true) {
    http_response_code(401);
    exit('Unauthorized - please log in');
}

if (!isset($_SESSION['userID'])) {
    http_response_code(400);
    exit('Invalid session');
}

// =============================================================================
// SECURITY HEADERS
// =============================================================================

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

// Force OPcache to re-validate this script
if (function_exists('opcache_invalidate')) {
    opcache_invalidate(__FILE__, true);
}

// =============================================================================
// DEPENDENCIES
// =============================================================================

require_once __DIR__ . '/../MySQL/medoo.php';
require_once __DIR__ . '/../MySQL/medoo-Credentials.php';

use Medoo\Medoo;
/** @var Medoo $database */

// =============================================================================
// CONSTANTS
// =============================================================================

// IMPORTANT: Configure the correct base path for your uploaded files
define('BASE_FILE_PATH', realpath(__DIR__ . '/../..'));

// Option 4: Custom path (adjust as needed)
// define('BASE_FILE_PATH', '/full/path/to/your/uploads');

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Send error response and exit
 *
 * @param string $message Error message
 * @param int $httpCode HTTP status code
 */
function sendError(string $message, int $httpCode = 400): void
{
    http_response_code($httpCode);
    
    // Log error for debugging
    error_log("files-download.php error ($httpCode): $message");
    
    exit($message);
}

/**
 * Verify study ownership
 *
 * @param Medoo $database Database connection
 * @param string $studyCode Study code
 * @param int $userID User ID
 * @return array|false Study data or false if not found/unauthorized
 */
function verifyStudyAccess(Medoo $database, string $studyCode, int $userID)
{
    try {
        // Get study with owner information
        $study = $database->get('studies', [
            'studyID',
            'studyOwner',
            'studyName'
        ], [
            'studyCode' => $studyCode
        ]);
        
        if (!$study) {
            return false;
        }
        
        // CRITICAL: Verify user owns this study
        $studyOwnerID = (int)$study['studyOwner'];
        
        if ($studyOwnerID !== $userID) {
            error_log("Authorization violation: User $userID attempted to download files for study owned by $studyOwnerID");
            return false;
        }
        
        return $study;
        
    } catch (Exception $e) {
        error_log("Error verifying study access: " . $e->getMessage());
        return false;
    }
}

/**
 * Validate file path for security
 *
 * @param string $filePath Relative or absolute file path from database
 * @return string|false Validated absolute path or false if invalid
 */
function validateFilePath(string $filePath)
{
    // Try as absolute path first
    $fullPath = realpath($filePath);
    
    // If not absolute, try relative to BASE_FILE_PATH
    if ($fullPath === false) {
        $fullPath = realpath(BASE_FILE_PATH . '/' . $filePath);
    }
    
    // Still not found?
    if ($fullPath === false) {
        error_log("File not found: $filePath");
        return false;
    }
    
    // CRITICAL: Verify path is within allowed directory
    // This prevents path traversal attacks
    if (strpos($fullPath, BASE_FILE_PATH) !== 0) {
        error_log("Path traversal attempt detected: $filePath resolves to $fullPath");
        return false;
    }
    
    // Verify file exists
    if (!file_exists($fullPath)) {
        error_log("File does not exist: $fullPath");
        return false;
    }
    
    // Verify it's a file (not a directory)
    if (!is_file($fullPath)) {
        error_log("Path is not a file: $fullPath");
        return false;
    }
    
    return $fullPath;
}

/**
 * Generate safe filename for ZIP download
 *
 * @param string $studyCode Study code
 * @return string Safe filename
 */
function generateZipFilename(string $studyCode): string
{
    // Sanitize study code to prevent path traversal
    $safeStudyCode = preg_replace('/[^a-zA-Z0-9_-]/', '', $studyCode);
    
    // Generate timestamp
    $timestamp = date('Y-m-d_H-i-s');
    
    return sprintf('researchChatAI-files-%s-%s.zip', $safeStudyCode, $timestamp);
}

/**
 * Create ZIP archive with study files
 *
 * @param array $files Array of file records from database
 * @param string $zipPath Path to temporary ZIP file
 * @return array Result with 'success' boolean, 'addedCount' int, 'skippedCount' int
 */
function createZipArchive(array $files, string $zipPath): array
{
    $result = [
        'success' => false,
        'addedCount' => 0,
        'skippedCount' => 0,
        'message' => ''
    ];
    
    try {
        $zip = new ZipArchive();
        
        if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            $result['message'] = 'Could not create ZIP archive';
            error_log("Failed to create ZIP at: $zipPath");
            return $result;
        }
        
        $addedCount = 0;
        $skippedCount = 0;
        
        foreach ($files as $file) {
            // Validate file path for security
            $validatedPath = validateFilePath($file['filePath']);
            
            if ($validatedPath === false) {
                $skippedCount++;
                error_log("Skipped invalid file path: {$file['filePath']}");
                continue;
            }
            
            // Sanitize filename for ZIP entry
            $safeFileName = basename($file['fileName']);
            
            // Add file to ZIP
            if ($zip->addFile($validatedPath, $safeFileName)) {
                $addedCount++;
                error_log("Added to ZIP: {$file['fileName']} from $validatedPath");
            } else {
                $skippedCount++;
                error_log("Failed to add file to ZIP: {$file['fileName']} from $validatedPath");
            }
        }
        
        $zip->close();
        
        $result['success'] = true;
        $result['addedCount'] = $addedCount;
        $result['skippedCount'] = $skippedCount;
        
        if ($skippedCount > 0) {
            $result['message'] = "Added $addedCount files, skipped $skippedCount";
        } else {
            $result['message'] = "Added $addedCount files";
        }
        
        error_log("ZIP created: {$result['message']}");
        
        return $result;
        
    } catch (Exception $e) {
        error_log("Error creating ZIP archive: " . $e->getMessage());
        $result['message'] = 'Error creating ZIP archive: ' . $e->getMessage();
        return $result;
    }
}

// =============================================================================
// MAIN LOGIC
// =============================================================================

// Verify this is a GET request
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    sendError('Invalid request method', 405);
}

// Get and validate session user ID
$sessionUserID = (int)$_SESSION['userID'];

if ($sessionUserID <= 0) {
    sendError('Invalid session user ID', 400);
}

// Validate studyCode parameter
$studyCode = filter_input(INPUT_GET, 'studyCode', FILTER_SANITIZE_FULL_SPECIAL_CHARS);

if (!$studyCode || trim($studyCode) === '') {
    sendError('Missing or invalid studyCode parameter', 400);
}

$studyCode = trim($studyCode);

error_log("File download requested for study: $studyCode by user: $sessionUserID");

// Verify study exists and user has access
$study = verifyStudyAccess($database, $studyCode, $sessionUserID);

if (!$study) {
    sendError('Invalid studyCode or you do not have permission to access this study', 403);
}

$studyID = (int)$study['studyID'];

// Get all non-deleted files for this study
try {
    $files = $database->select('files', [
        'fileID',
        'filePath',
        'fileName'
    ], [
        'studyID' => $studyID,
        'deleted' => 0
    ]);
    
    error_log("Found " . count($files) . " files for study $studyID");
    
} catch (Exception $e) {
    error_log("Error fetching files for study $studyID: " . $e->getMessage());
    sendError('Error retrieving files', 500);
}

// Verify files exist
if (empty($files)) {
    sendError('No files available for this study', 404);
}

// Log file paths for debugging
foreach ($files as $file) {
    error_log("File in DB - ID: {$file['fileID']}, Name: {$file['fileName']}, Path: {$file['filePath']}");
}

// Create temporary ZIP file
$tmpZip = tempnam(sys_get_temp_dir(), 'files_');

if ($tmpZip === false) {
    sendError('Could not create temporary file', 500);
}

error_log("Created temporary ZIP file: $tmpZip");

// Ensure cleanup on script termination
register_shutdown_function(function() use ($tmpZip) {
    if (file_exists($tmpZip)) {
        @unlink($tmpZip);
        error_log("Cleaned up temporary ZIP: $tmpZip");
    }
});

// Create ZIP archive
$zipResult = createZipArchive($files, $tmpZip);

if (!$zipResult['success']) {
    @unlink($tmpZip);
    sendError($zipResult['message'], 500);
}

if ($zipResult['addedCount'] === 0) {
    @unlink($tmpZip);
    sendError('No valid files could be added to archive', 500);
}

// Generate safe filename
$zipFilename = generateZipFilename($studyCode);

// Set download headers
header('Content-Type: application/zip');
header("Content-Disposition: attachment; filename=\"$zipFilename\"");
header('Content-Length: ' . filesize($tmpZip));

// Stream ZIP file to user
if (!readfile($tmpZip)) {
    error_log("Failed to read ZIP file: $tmpZip");
    @unlink($tmpZip);
    sendError('Error streaming file', 500);
}

// Log successful download
error_log("Files downloaded for study $studyID by user $sessionUserID: {$zipResult['addedCount']} files");

// Cleanup (also handled by shutdown function)
@unlink($tmpZip);

exit;
?>