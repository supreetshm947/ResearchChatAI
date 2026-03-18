<?php

/**
 * message-image-upload.php
 *
 * Handles image uploads from the participant chat interface.
 * Files are stored in /Uploads/ with cryptographically random filenames
 * so they cannot be guessed or enumerated by outsiders.
 *
 * Security measures:
 *   - MIME type validated against an image-only whitelist
 *   - File extension enforced to match detected MIME type
 *   - getimagesize() used as secondary validation (rejects non-images)
 *   - Filename randomized with 32 hex chars (cryptographically random)
 *   - Upload directory created with 0750 permissions
 *   - File size capped at 1 MB
 *   - Upload errors checked before processing
 *
 * ResearchChatAI
 * Authors: Marc Becker, David de Jong
 * License: MIT
 */

ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(E_ALL);

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-cache, no-store');

require '../MySQL/medoo.php';
require '../MySQL/medoo-Credentials.php';

// =============================================================================
// CONFIGURATION
// =============================================================================

define('MAX_FILE_SIZE', 1 * 1024 * 1024); // 1 MB

/** Allowed MIME types mapped to their canonical file extension. */
const ALLOWED_TYPES = [
    'image/jpeg' => 'jpg',
    'image/png'  => 'png',
    'image/gif'  => 'gif',
    'image/webp' => 'webp',
];

$baseURL   = $env['BASE_URL'] ?? 'https://researchchatai.com/';
$uploadDir = '../../Uploads/';


// =============================================================================
// VALIDATION
// =============================================================================

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_FILES['image'])) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'No file uploaded']);
    exit;
}

$file = $_FILES['image'];

/* Check for PHP upload errors */
if ($file['error'] !== UPLOAD_ERR_OK) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Upload failed (error code ' . intval($file['error']) . ')']);
    exit;
}

/* File size */
if ($file['size'] > MAX_FILE_SIZE) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'File size exceeds 1 MB']);
    exit;
}

/* MIME type — check the actual file content, not the client-provided type */
$detectedType = mime_content_type($file['tmp_name']);
if (!$detectedType || !isset(ALLOWED_TYPES[$detectedType])) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Only JPEG, PNG, GIF, and WebP images are allowed']);
    exit;
}

/* Secondary validation: getimagesize rejects files that aren't real images */
if (getimagesize($file['tmp_name']) === false) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'File does not appear to be a valid image']);
    exit;
}


// =============================================================================
// STORE FILE
// =============================================================================

if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0750, true);
}

/* Cryptographically random filename — prevents URL guessing/enumeration */
$ext      = ALLOWED_TYPES[$detectedType];
$fileName = bin2hex(random_bytes(16)) . '.' . $ext;
$filePath = $uploadDir . $fileName;

if (!move_uploaded_file($file['tmp_name'], $filePath)) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Failed to save the file']);
    exit;
}

$fileUrl = rtrim($baseURL, '/') . '/Uploads/' . $fileName;

echo json_encode([
    'status'   => 'success',
    'url'      => $fileUrl,
    'filename' => $fileName,
]);