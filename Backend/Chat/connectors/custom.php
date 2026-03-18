<?php
declare(strict_types=1);

/* ------------------------------------------------------------------
 *  connectors/custom.php  –  ResearchChatAI
 *
 *  Loads a researcher-defined custom connector configuration.
 *
 *  Expects in scope (set by prepareChat.php before including):
 *    $study      – study row from DB
 *    $streamFlag – bool, whether streaming is requested
 *
 *  Sets:
 *    $connector  – fully configured connector array (from JSON)
 *
 *  The connector JSON is stored in the study's customConnectorConfiguration
 *  field and follows the same schema as OpenAI/OpenRouter connectors:
 *    { request: {url, method, auth, headers, ...},
 *      aiPayload: {...},
 *      history: {mode: "array"|"string"|"none", ...},
 *      response: {resultPath: "$.path.to.content", ...} }
 *
 *  Researchers configure this via the study settings UI. The custom
 *  connector enables any Chat Completions-compatible API (Anthropic,
 *  Azure, local LLMs, etc.) to be used as the AI backend.
 * 
 * ResearchChatAI
 * Authors: Marc Becker, David de Jong
 * License: MIT
 * ------------------------------------------------------------------ */

$connector = json_decode($study['customConnectorConfiguration'] ?? '', true);

if (!$connector || !is_array($connector)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid custom connector configuration']);
    exit;
}
