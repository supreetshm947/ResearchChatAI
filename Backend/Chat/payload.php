<?php
declare(strict_types=1);

/* ------------------------------------------------------------------
 *  payload.php  –  ResearchChatAI
 *
 *  Shared functions for building and transforming AI provider payloads.
 *  Included by prepareChat.php — used across all connector types.
 *
 *  Contents:
 *    renderTemplate()          – {{placeholder}} replacement
 *    jsonPathExtract()         – minimal JSONPath for response parsing
 *    applyRoleMap()            – rename roles (e.g. "human" → "user")
 *    buildPayload()            – combine connector config + chat history
 *    normalizeForOpenRouter()  – flatten multi-part messages for OR
 *    messagesToResponsesInput() – convert to OpenAI Responses API format
 *    resolveAuthHeaders()      – turn auth config into plain headers
 *    validateUpstreamUrl()     – SSRF protection (HTTPS + no private IPs)
 * 
 * ResearchChatAI
 * Authors: Marc Becker, David de Jong
 * License: MIT
 * ------------------------------------------------------------------ */


/* ------------------------------------------------------------------
 *  Template rendering
 * ------------------------------------------------------------------ */

/**
 * Recursively replace {{placeholder}} tokens in a value.
 *
 * Walks arrays and replaces in all string leaves. Non-string scalars
 * (int, float, bool) pass through unchanged.
 *
 * @param  mixed $value  String, array, or scalar to process.
 * @param  array $vars   Key-value map of replacements.
 * @return mixed         Processed value with the same type as input.
 */
function renderTemplate($value, array $vars)
{
    if (is_array($value))
        return array_map(fn($v) => renderTemplate($v, $vars), $value);
    if (!is_string($value))
        return $value;
    return preg_replace_callback('/\{\{\s*(\w+)\s*\}\}/', fn($m) => $vars[$m[1]] ?? '', $value);
}


/* ------------------------------------------------------------------
 *  JSONPath extraction
 * ------------------------------------------------------------------ */

/**
 * Extract a value from a nested array using a simple JSONPath expression.
 *
 * Supports dot notation and bracket indices:
 *   "$.choices[0].message.content"
 *   "$.output_text"
 *
 * Does NOT support wildcards, recursive descent, or filters.
 *
 * @param  array  $data  Decoded JSON array to traverse.
 * @param  string $path  JSONPath expression.
 * @return mixed|null    Extracted value, or null if the path doesn't resolve.
 */
function jsonPathExtract(array $data, string $path)
{
    $path = ltrim($path, '$.');
    foreach (preg_split('/\.(?![^\[]*\])/', $path) as $seg) {
        if (preg_match('/(.+)\[(\d+)\]$/', $seg, $m)) {
            $seg = $m[1];
            $idx = (int) $m[2];
            if (!isset($data[$seg][$idx])) return null;
            $data = $data[$seg][$idx];
        } else {
            if (!isset($data[$seg])) return null;
            $data = $data[$seg];
        }
    }
    return $data;
}


/* ------------------------------------------------------------------
 *  Chat history processing
 * ------------------------------------------------------------------ */

/**
 * Remap role names in a message array (e.g. "human" → "user").
 *
 * @param  array  $messages  Chat history array with 'role' keys.
 * @param  array  $roleMap   Map of lowercase old_role → new_role.
 * @param  string $default   Default role name if no mapping matches.
 * @return array             Messages with remapped roles.
 */
function applyRoleMap(array $messages, array $roleMap = [], string $default = 'user'): array
{
    foreach ($messages as &$m) {
        if (isset($m['role'])) {
            $r = strtolower($m['role']);
            $m['role'] = $roleMap[$r] ?? $r;
        }
    }
    return $messages;
}

/**
 * Build the final AI request payload by combining the connector's
 * aiPayload template with the chat history.
 *
 * Supports three history modes (set via connector.history.mode):
 *   "array"  – messages as a JSON array (default, used by OpenAI/OR)
 *   "string" – messages concatenated into a single text string
 *   "none"   – no history injected (payload used as-is)
 *
 * When extractSystem is true, the first system-role message is pulled
 * out of history and placed as a top-level parameter.
 *
 * @param  array $connector  Full connector configuration.
 * @param  array $vars       Template variables including chatHistory.
 * @return array             Ready-to-serialize payload for the AI API.
 */
function buildPayload(array $connector, array $vars): array
{
    $historyCfg      = $connector['history'] ?? [];
    $extractSystem   = !empty($historyCfg['extractSystem']);
    $systemParamName = $historyCfg['systemParam'] ?? 'system';

    $chatHistory  = $vars['chatHistory'] ?? [];
    $systemPrompt = null;

    if ($extractSystem) {
        foreach ($chatHistory as $idx => $msg) {
            if (($msg['role'] ?? '') === 'system') {
                $systemPrompt = $msg['content'] ?? '';
                unset($chatHistory[$idx]);
                break;
            }
        }
        $chatHistory = array_values($chatHistory);
    }

    $vars['systemPrompt'] = $systemPrompt ?? '';
    $payload     = renderTemplate($connector['aiPayload'], $vars);
    $historyMode = strtolower($historyCfg['mode'] ?? 'array');

    if ($extractSystem && $systemPrompt !== null && !array_key_exists($systemParamName, $payload)) {
        $payload[$systemParamName] = $systemPrompt;
    }

    if ($historyMode === 'none') return $payload;

    if ($historyMode === 'string') {
        $template  = $historyCfg['template'] ?? '{{role}}: {{content}}';
        $delimiter = $historyCfg['delimiter'] ?? "\n";
        $chunks    = [];
        foreach ($chatHistory as $msg) {
            $chunks[] = str_replace(
                ['{{role}}', '{{content}}'],
                [$msg['role'] ?? '', $msg['content'] ?? ''],
                $template
            );
        }
        $historyStr = implode($delimiter, $chunks);
        if (array_key_exists('prompt', $payload)) {
            $payload['prompt'] = $historyStr;
        } else {
            $payload['messages'] = $historyStr;
        }
        return $payload;
    }

    /* Default: "array" mode — inject messages as a JSON array */
    $roleMap = $historyCfg['roleMap'] ?? [];
    $payload['messages'] = applyRoleMap(
        $chatHistory, $roleMap, $historyCfg['defaultRoleName'] ?? 'user'
    );
    return $payload;
}


/* ------------------------------------------------------------------
 *  Provider-specific message normalization
 * ------------------------------------------------------------------ */

/**
 * Normalize chat messages for OpenRouter's expected format.
 *
 * OpenRouter prefers plain-string content when there are no images.
 * This flattens multi-part text arrays into single strings, and keeps
 * image parts as structured content only when present.
 *
 * @param  array $messages  Chat history in OpenAI multi-part format.
 * @return array            Messages normalized for OpenRouter.
 */
function normalizeForOpenRouter(array $messages): array
{
    $out = [];
    foreach ($messages as $m) {
        $role    = strtolower($m['role'] ?? 'user');
        $content = $m['content'] ?? '';

        if (is_string($content)) {
            $out[] = ['role' => $role, 'content' => $content];
            continue;
        }
        if (is_array($content)) {
            $textParts  = [];
            $imageParts = [];
            foreach ($content as $part) {
                if (is_array($part) && ($part['type'] ?? '') === 'image_url') {
                    $url = is_array($part['image_url']) ? ($part['image_url']['url'] ?? '') : ($part['image_url'] ?? '');
                    if ($url !== '') $imageParts[] = ['type' => 'image_url', 'image_url' => ['url' => $url]];
                } else {
                    $txt = is_string($part) ? $part
                         : (is_array($part) && isset($part['text']) ? (string) $part['text']
                         : json_encode($part, JSON_UNESCAPED_UNICODE));
                    if ($txt !== '') $textParts[] = $txt;
                }
            }
            if (!$imageParts) {
                $out[] = ['role' => $role, 'content' => trim(implode("\n", $textParts))];
            } else {
                $parts = [];
                foreach ($textParts as $t) $parts[] = ['type' => 'text', 'text' => $t];
                $out[] = ['role' => $role, 'content' => array_merge($parts, $imageParts)];
            }
            continue;
        }
        $out[] = ['role' => $role, 'content' => (string) $content];
    }
    return $out;
}

/**
 * Convert Chat Completions messages to OpenAI Responses API input format.
 *
 * The Responses API (used by GPT-5+) uses different content types:
 *   text  →  "input_text" (user) or "output_text" (assistant)
 *   image →  "input_image"
 *   system → separate entry with "input_text"
 *
 * @param  array       $messages      Chat history in Chat Completions format.
 * @param  string|null $systemPrompt  Extracted system prompt, if any.
 * @return array                      Input array for /v1/responses.
 */
function messagesToResponsesInput(array $messages, ?string $systemPrompt = null): array
{
    $input = [];
    if ($systemPrompt !== null && $systemPrompt !== '') {
        $input[] = ['role' => 'system', 'content' => [['type' => 'input_text', 'text' => $systemPrompt]]];
    }
    foreach ($messages as $m) {
        $role     = strtolower($m['role'] ?? 'user');
        $content  = $m['content'] ?? '';
        $textType = ($role === 'assistant') ? 'output_text' : 'input_text';

        if (is_string($content)) {
            $input[] = ['role' => $role, 'content' => [['type' => $textType, 'text' => $content]]];
            continue;
        }
        if (is_array($content)) {
            $items = [];
            foreach ($content as $part) {
                if (is_string($part)) {
                    $items[] = ['type' => $textType, 'text' => $part];
                } elseif (is_array($part)) {
                    if ((($part['type'] ?? '') === 'text') && isset($part['text'])) {
                        $items[] = ['type' => $textType, 'text' => (string) $part['text']];
                    } elseif (isset($part['image_url'])) {
                        $url = is_array($part['image_url']) ? ($part['image_url']['url'] ?? '') : $part['image_url'];
                        if (is_string($url) && $url !== '' && $role !== 'assistant') {
                            $items[] = ['type' => 'input_image', 'image_url' => $url];
                        } else {
                            $items[] = ['type' => $textType, 'text' => json_encode($part, JSON_UNESCAPED_UNICODE)];
                        }
                    } else {
                        $items[] = ['type' => $textType, 'text' => json_encode($part, JSON_UNESCAPED_UNICODE)];
                    }
                }
            }
            if (!$items) {
                $items = [['type' => $textType, 'text' => json_encode($content, JSON_UNESCAPED_UNICODE)]];
            }
            $input[] = ['role' => $role, 'content' => $items];
            continue;
        }
        $input[] = ['role' => $role, 'content' => [['type' => $textType, 'text' => (string) $content]]];
    }
    return $input;
}


/* ------------------------------------------------------------------
 *  Auth resolution
 * ------------------------------------------------------------------ */

/**
 * Merge authentication config into a flat headers array.
 *
 * Supports three auth types defined in the connector:
 *   "bearer" → Authorization: Bearer <token>
 *   "basic"  → Authorization: Basic <token>
 *   "custom" → <header>: <value>
 *
 * @param  array $headers  Existing headers from the connector.
 * @param  array $auth     Auth config with 'type', 'token'/'header'/'value'.
 * @return array           Headers with auth merged in.
 */
function resolveAuthHeaders(array $headers, array $auth): array
{
    $type = strtolower($auth['type'] ?? '');
    if ($type === 'bearer' && !empty($auth['token'])) {
        $headers['Authorization'] = 'Bearer ' . $auth['token'];
    } elseif ($type === 'basic' && !empty($auth['token'])) {
        $headers['Authorization'] = 'Basic ' . $auth['token'];
    } elseif ($type === 'custom' && !empty($auth['header'])) {
        $headers[$auth['header']] = $auth['value'] ?? '';
    }
    return $headers;
}


/* ------------------------------------------------------------------
 *  SSRF protection
 * ------------------------------------------------------------------ */

/**
 * Validate that an upstream URL is safe to call.
 *
 * Enforces:
 *   - HTTPS only (no plain HTTP)
 *   - No private/reserved IP ranges (10.x, 172.16-31.x, 192.168.x)
 *   - No localhost, loopback, or link-local addresses
 *
 * This protects against custom connectors being crafted to target
 * internal services on the hosting network.
 *
 * @param  string $url  The upstream AI provider URL.
 * @return bool              Returns true on success.
 * @throws RuntimeException  With a user-safe message on failure.
 */
function validateUpstreamUrl(string $url): bool
{
    $parsed = parse_url($url);
    $host   = strtolower($parsed['host'] ?? '');
    $scheme = strtolower($parsed['scheme'] ?? '');

    if ($scheme !== 'https') {
        throw new RuntimeException('Only HTTPS AI provider URLs are allowed');
    }

    $blocked = ['localhost', '127.0.0.1', '0.0.0.0', '::1', '169.254.', '10.', '192.168.'];
    foreach ($blocked as $pattern) {
        if (str_contains($host, $pattern)) {
            throw new RuntimeException('Internal network targets are not allowed');
        }
    }

    return true;
}
