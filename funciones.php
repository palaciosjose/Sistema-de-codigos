<?php
/**
 * Sistema de Consulta de Códigos por Email - Funciones Optimizadas
 * Versión: 2.1 - Integración de licencias corregida
 */

// Inicializar sesión de forma segura
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// ===== INTEGRACIÓN DEL SISTEMA DE LICENCIAS CORREGIDA =====
require_once __DIR__ . '/license_client.php';

// Verificar licencia automáticamente (excepto en instalador)
if (!defined('INSTALLER_MODE')) {
    try {
        $license_client = new ClientLicense();
        
        // Verificación simple de licencia válida
        if (!$license_client->isLicenseValid()) {
            showLicenseError();
            exit();
        }
    } catch (Exception $e) {
        // En caso de error con el sistema de licencias, log y continuar
        error_log("Error verificando licencia: " . $e->getMessage());
        // Para desarrollo, puedes comentar las siguientes líneas
        showLicenseError();
        exit();
    }
}

/**
 * Mostrar error de licencia
 */
function showLicenseError() {
    $license_client = new ClientLicense();
    $diagnostic_info = $license_client->getDiagnosticInfo();
    
    // Limpiar cualquier salida previa
    if (ob_get_level()) {
        ob_end_clean();
    }
    
    header('HTTP/1.1 403 Forbidden');
    header('Content-Type: text/html; charset=utf-8');
    
    echo '<!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Licencia Requerida</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            body { 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .license-error-container {
                background: white;
                border-radius: 15px;
                padding: 2rem;
                max-width: 600px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                text-align: center;
            }
            .license-icon {
                font-size: 4rem;
                color: #dc3545;
                margin-bottom: 1rem;
            }
            .diagnostic-info {
                background: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 8px;
                padding: 1rem;
                margin-top: 1.5rem;
                text-align: left;
                font-family: monospace;
                font-size: 0.9rem;
            }
        </style>
    </head>
    <body>
        <div class="license-error-container">
            <div class="license-icon">
                <i class="fas fa-shield-alt"></i>
            </div>
            <h1 class="h3 mb-3">Licencia Requerida</h1>
            <p class="text-muted mb-4">
                Este software requiere una licencia válida para funcionar correctamente.
            </p>
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <strong>Estado:</strong> Licencia no válida o no encontrada
            </div>
            
            <div class="diagnostic-info">
                <h6><i class="fas fa-wrench me-2"></i>Información de Diagnóstico:</h6>
                <ul class="list-unstyled mb-0">
                    <li><strong>Directorio existe:</strong> ' . ($diagnostic_info['directory_exists'] ? 'SÍ' : 'NO') . '</li>
                    <li><strong>Archivo existe:</strong> ' . ($diagnostic_info['file_exists'] ? 'SÍ' : 'NO') . '</li>
                    <li><strong>Archivo legible:</strong> ' . ($diagnostic_info['file_readable'] ? 'SÍ' : 'NO') . '</li>
                    <li><strong>Dominio actual:</strong> ' . htmlspecialchars($_SERVER['HTTP_HOST']) . '</li>
                </ul>
            </div>
            
            <div class="mt-4">
                <p class="text-muted small">
                    <i class="fas fa-info-circle me-1"></i>
                    Contacte al administrador del sistema para resolver este problema.
                </p>
                <a href="instalacion/instalador.php" class="btn btn-primary">
                    <i class="fas fa-cogs me-2"></i>Ir al Instalador
                </a>
            </div>
        </div>
    </body>
    </html>';
}

// Incluir dependencias
require_once 'config/config.php';
require_once 'decodificador.php';
require_once 'instalacion/basededatos.php';
require_once 'cache/cache_helper.php';

/**
 * Clase principal para manejo de emails
 */
class EmailSearchEngine {
    private $conn;
    private $settings;
    private $platforms_cache;
    
    public function __construct($db_connection) {
        $this->conn = $db_connection;
        $this->loadSettings();
        $this->loadPlatforms();
    }
    
    private function loadSettings() {
        $this->settings = SimpleCache::get_settings($this->conn);
    }
    
    private function loadPlatforms() {
        $this->platforms_cache = SimpleCache::get_platform_subjects($this->conn);
    }
    
    /**
     * Búsqueda principal de emails con fallback automático
     */
    public function searchEmails($email, $platform, $user_id = null) {
        $start_time = microtime(true);
        
        // Validaciones iniciales
        $validation_result = $this->validateSearchRequest($email, $platform);
        if ($validation_result !== true) {
            return $validation_result;
        }
        
        // Obtener asuntos para la plataforma
        $subjects = $this->getSubjectsForPlatform($platform);
        if (empty($subjects)) {
            return $this->createErrorResponse('No se encontraron asuntos para la plataforma seleccionada.');
        }
        
        // Obtener servidores habilitados
        $servers = SimpleCache::get_enabled_servers($this->conn);
        if (empty($servers)) {
            return $this->createErrorResponse('No hay servidores IMAP configurados.');
        }
        
        // Buscar en servidores
        $result = $this->searchInServers($email, $subjects, $servers);
        
        // Registrar en log
        $this->logSearch($user_id, $email, $platform, $result);
        
        $execution_time = microtime(true) - $start_time;
        $this->logPerformance("Búsqueda completa: " . round($execution_time, 3) . "s");
        
        return $result;
    }
    
    /**
     * Validación segura de la solicitud de búsqueda
     */
    private function validateSearchRequest($email, $platform) {
        // Validar formato de email
        if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return $this->createErrorResponse('Email inválido.');
        }
        
        if (strlen($email) > 50) {
            return $this->createErrorResponse('El email no debe superar los 50 caracteres.');
        }
        
        // Verificar autorización
        if (!$this->isAuthorizedEmail($email)) {
            return $this->createErrorResponse('No tiene permisos para consultar este email.');
        }
        
        return true;
    }
    
    /**
     * Verificación de email autorizado con restricciones por usuario
     */
    private function isAuthorizedEmail($email) {
        $auth_enabled = ($this->settings['EMAIL_AUTH_ENABLED'] ?? '0') === '1';
        $user_restrictions_enabled = ($this->settings['USER_EMAIL_RESTRICTIONS_ENABLED'] ?? '0') === '1';
        
        // Si no hay filtro de autorizacion, permitir todos
        if (!$auth_enabled) {
            return true;
        }
        
        // Verificar si el email está en la lista de autorizados
        $stmt = $this->conn->prepare("SELECT id FROM authorized_emails WHERE email = ? LIMIT 1");
        if (!$stmt) {
            error_log("Error preparando consulta de autorización: " . $this->conn->error);
            return false;
        }
        
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows == 0) {
            $stmt->close();
            return false; // Email no está en la lista de autorizados
        }
        
        $email_data = $result->fetch_assoc();
        $authorized_email_id = $email_data['id'];
        $stmt->close();
        
        // Si las restricciones por usuario están deshabilitadas, permitir
        if (!$user_restrictions_enabled) {
            return true;
        }
        
        // Verificar si el usuario actual tiene acceso a este email específico
        $user_id = $_SESSION['user_id'] ?? null;
        
        // Si no hay usuario logueado, denegar
        if (!$user_id) {
            return false;
        }
        
        // Si es admin, permitir acceso a todos los correos
        if (isset($_SESSION['user_role']) && $_SESSION['user_role'] === 'admin') {
            return true;
        }
        
        // Verificar si el usuario tiene asignado este email específico
        $stmt_user = $this->conn->prepare("
            SELECT 1 FROM user_authorized_emails 
            WHERE user_id = ? AND authorized_email_id = ? 
            LIMIT 1
        ");
        
        if (!$stmt_user) {
            error_log("Error preparando consulta de restricción por usuario: " . $this->conn->error);
            return false;
        }
        
        $stmt_user->bind_param("ii", $user_id, $authorized_email_id);
        $stmt_user->execute();
        $result_user = $stmt_user->get_result();
        $has_access = $result_user->num_rows > 0;
        $stmt_user->close();
        
        return $has_access;
    }

    /**
     * Nueva función para obtener emails asignados a un usuario específico
     */
    public function getUserAuthorizedEmails($user_id) {
        $user_restrictions_enabled = ($this->settings['USER_EMAIL_RESTRICTIONS_ENABLED'] ?? '0') === '1';
        
        // Si no hay restricciones por usuario, devolver todos los emails autorizados
        if (!$user_restrictions_enabled) {
            $stmt = $this->conn->prepare("SELECT email FROM authorized_emails ORDER BY email ASC");
            $stmt->execute();
            $result = $stmt->get_result();
            
            $emails = [];
            while ($row = $result->fetch_assoc()) {
                $emails[] = $row['email'];
            }
            $stmt->close();
            return $emails;
        }
        
        // Si hay restricciones, devolver solo los emails asignados al usuario
        $query = "
            SELECT ae.email 
            FROM user_authorized_emails uae 
            JOIN authorized_emails ae ON uae.authorized_email_id = ae.id 
            WHERE uae.user_id = ? 
            ORDER BY ae.email ASC
        ";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();
        
        $emails = [];
        while ($row = $result->fetch_assoc()) {
            $emails[] = $row['email'];
        }
        $stmt->close();
        
        return $emails;
    }
        
    /**
     * Obtener asuntos para una plataforma
     */
    private function getSubjectsForPlatform($platform) {
        return $this->platforms_cache[$platform] ?? [];
    }
    
    /**
     * Búsqueda en múltiples servidores con estrategia optimizada
     */
    private function searchInServers($email, $subjects, $servers) {
        $early_stop = ($this->settings['EARLY_SEARCH_STOP'] ?? '1') === '1';
        
        foreach ($servers as $server) {
            $result = $this->searchInSingleServer($email, $subjects, $server);
            
            if ($result['found']) {
                $this->logPerformance("Email encontrado en servidor: " . $server['server_name']);
                return $result;
            }
            
            if ($early_stop && $result['found']) {
                break;
            }
        }
        
        return $this->createNotFoundResponse();
    }
    
    /**
     * Búsqueda en un servidor individual
     */
    private function searchInSingleServer($email, $subjects, $server_config) {
        $inbox = $this->openImapConnection($server_config);
        
        if (!$inbox) {
            return ['found' => false, 'error' => 'Error de conexión'];
        }
        
        try {
            // Estrategia de búsqueda inteligente
            $email_ids = $this->executeSearch($inbox, $email, $subjects);
            
            if (!empty($email_ids)) {
                $latest_email_id = max($email_ids);
                $email_content = $this->processFoundEmail($inbox, $latest_email_id);
                
                if ($email_content) {
                    return [
                        'found' => true,
                        'content' => $email_content,
                        'server' => $server_config['server_name']
                    ];
                }
            }
            
            return ['found' => false];
            
        } catch (Exception $e) {
            error_log("Error en búsqueda: " . $e->getMessage());
            return ['found' => false, 'error' => $e->getMessage()];
        } finally {
            if ($inbox) {
                imap_close($inbox);
            }
        }
    }
    
    /**
     * Ejecución de búsqueda con múltiples estrategias
     */
    private function executeSearch($inbox, $email, $subjects) {
        // Estrategia 1: Búsqueda optimizada
        $emails = $this->searchOptimized($inbox, $email, $subjects);
        
        if (!empty($emails)) {
            return $emails;
        }
        
        // Estrategia 2: Búsqueda simple (fallback)
        return $this->searchSimple($inbox, $email, $subjects);
    }
    
/**
 * Búsqueda optimizada con IMAP - MEJORADA para zonas horarias
 */
private function searchOptimized($inbox, $email, $subjects) {
    try {
        // CAMBIO PRINCIPAL: Usar horas configurables para cubrir diferencias de zona horaria
        $search_hours = (int)($this->settings['TIMEZONE_DEBUG_HOURS'] ?? 48); // Configurable, 48h por defecto
        $search_date = date("d-M-Y", time() - ($search_hours * 3600));
        
        $this->logPerformance("Búsqueda ampliada: últimas 48h desde " . $search_date);
        
        // Construir criterio de búsqueda con rango amplio
        $criteria = 'TO "' . $email . '" SINCE "' . $search_date . '"';
        
        $all_emails = imap_search($inbox, $criteria);
        
        if (!$all_emails) {
            $this->logPerformance("No se encontraron emails en rango amplio para: " . $email);
            return [];
        }
        
        $this->logPerformance("Emails encontrados en rango amplio: " . count($all_emails));
        
        // NUEVO: Filtrar por tiempo preciso usando timestamps locales
        return $this->filterEmailsByTimeAndSubject($inbox, $all_emails, $subjects);
        
    } catch (Exception $e) {
        $this->logPerformance("Error en búsqueda optimizada: " . $e->getMessage());
        return [];
    }
}

/**
 * Filtrar emails por tiempo preciso y asunto
 * Este método resuelve problemas de zona horaria usando timestamps locales
 */
private function filterEmailsByTimeAndSubject($inbox, $email_ids, $subjects) {
    $found_emails = [];
    $max_check = (int)($this->settings['MAX_EMAILS_TO_CHECK'] ?? 50);
    
    // Obtener el límite de tiempo configurado (en minutos)
    $time_limit_minutes = (int)($this->settings['EMAIL_QUERY_TIME_LIMIT_MINUTES'] ?? 20);
    $cutoff_timestamp = time() - ($time_limit_minutes * 60);
    
    $this->logPerformance("Filtrando emails: límite " . $time_limit_minutes . " minutos, timestamp corte: " . date('Y-m-d H:i:s', $cutoff_timestamp));
    
    // Ordenar emails por más recientes primero
    rsort($email_ids);
    $emails_to_check = array_slice($email_ids, 0, $max_check);
    
    $checked_count = 0;
    $time_filtered_count = 0;
    $subject_matched_count = 0;
    
    foreach ($emails_to_check as $email_id) {
        try {
            $checked_count++;
            $header = imap_headerinfo($inbox, $email_id);
            
            if (!$header || !isset($header->date)) {
                continue;
            }
            
            // Convertir fecha del email a timestamp
            $email_timestamp = $this->parseEmailTimestamp($header->date);
            if ($email_timestamp === false) {
                $this->logPerformance("No se pudo parsear fecha: " . $header->date);
                continue;
            }
            
            // FILTRO DE TIEMPO: Verificar si está dentro del rango permitido
            if ($email_timestamp < $cutoff_timestamp) {
                // Este email es muy viejo, saltar
                continue;
            }
            
            $time_filtered_count++;
            $email_age_minutes = round((time() - $email_timestamp) / 60, 1);
            $this->logPerformance("Email válido por tiempo: " . date('Y-m-d H:i:s', $email_timestamp) . " (hace " . $email_age_minutes . " min)");
            
            // FILTRO DE ASUNTO: Verificar si coincide con algún asunto buscado
            if (!isset($header->subject)) {
                continue;
            }
            
            $decoded_subject = $this->decodeMimeSubject($header->subject);
            
            foreach ($subjects as $subject) {
                if ($this->subjectMatches($decoded_subject, $subject)) {
                    $found_emails[] = $email_id;
                    $subject_matched_count++;
                    
                    $this->logPerformance("¡MATCH! Asunto: '" . substr($decoded_subject, 0, 50) . "...' con patrón: '" . substr($subject, 0, 30) . "...'");
                    
                    // Early stop si está habilitado
                    if (($this->settings['EARLY_SEARCH_STOP'] ?? '1') === '1') {
                        $this->logPerformance("Early stop activado, deteniendo búsqueda");
                        return $found_emails;
                    }
                    break;
                }
            }
            
        } catch (Exception $e) {
            $this->logPerformance("Error procesando email ID " . $email_id . ": " . $e->getMessage());
            continue;
        }
    }
    
    $this->logPerformance("Resumen filtrado - Revisados: $checked_count, Válidos por tiempo: $time_filtered_count, Con asunto coincidente: $subject_matched_count");
    
    return $found_emails;
}

/**
 * Parsear timestamp de email de forma robusta
 * Maneja diferentes formatos de fecha que pueden venir en headers de email
 */
private function parseEmailTimestamp($email_date) {
    if (empty($email_date)) {
        return false;
    }
    
    try {
        // Intentar parseo directo con strtotime (funciona con la mayoría de formatos RFC)
        $timestamp = strtotime($email_date);
        
        if ($timestamp !== false && $timestamp > 0) {
            // Validar que el timestamp sea razonable (no muy viejo ni futuro)
            $now = time();
            $one_year_ago = $now - (365 * 24 * 3600);
            $one_day_future = $now + (24 * 3600);
            
            if ($timestamp >= $one_year_ago && $timestamp <= $one_day_future) {
                return $timestamp;
            } else {
                $this->logPerformance("Timestamp fuera de rango razonable: " . date('Y-m-d H:i:s', $timestamp) . " de fecha: " . $email_date);
            }
        }
        
        // Si el parseo directo falla, intentar con DateTime (más robusto)
        $datetime = new DateTime($email_date);
        $timestamp = $datetime->getTimestamp();
        
        // Validar nuevamente
        if ($timestamp >= $one_year_ago && $timestamp <= $one_day_future) {
            return $timestamp;
        }
        
        $this->logPerformance("DateTime timestamp fuera de rango: " . date('Y-m-d H:i:s', $timestamp) . " de fecha: " . $email_date);
        return false;
        
    } catch (Exception $e) {
        $this->logPerformance("Error parseando fecha '" . $email_date . "': " . $e->getMessage());
        
        // Último intento: extraer timestamp usando regex si es un formato conocido
        if (preg_match('/(\d{1,2})\s+(\w{3})\s+(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})/', $email_date, $matches)) {
            try {
                $day = $matches[1];
                $month = $matches[2];
                $year = $matches[3];
                $hour = $matches[4];
                $minute = $matches[5];
                $second = $matches[6];
                
                $formatted_date = "$day $month $year $hour:$minute:$second";
                $timestamp = strtotime($formatted_date);
                
                if ($timestamp !== false && $timestamp > 0) {
                    return $timestamp;
                }
            } catch (Exception $regex_error) {
                $this->logPerformance("Error en parseo regex: " . $regex_error->getMessage());
            }
        }
        
        return false;
    }
}
    
    /**
 * Búsqueda simple (fallback confiable) - MEJORADA para zonas horarias
 */
private function searchSimple($inbox, $email, $subjects) {
    try {
        $this->logPerformance("Iniciando búsqueda simple (fallback)");
        
        // Usar búsqueda amplia sin restricción de fecha como fallback
        $criteria = 'TO "' . $email . '"';
        $all_emails = imap_search($inbox, $criteria);
        
        if (!$all_emails) {
            $this->logPerformance("No se encontraron emails en búsqueda simple");
            return [];
        }
        
        $this->logPerformance("Búsqueda simple encontró: " . count($all_emails) . " emails totales");
        
        // Ordenar por más recientes y limitar para performance
        rsort($all_emails);
        $emails_to_check = array_slice($all_emails, 0, 30); // Limitar a 30 para búsqueda simple
        
        // Usar el mismo filtrado preciso por tiempo y asunto
        return $this->filterEmailsByTimeAndSubject($inbox, $emails_to_check, $subjects);
        
    } catch (Exception $e) {
        $this->logPerformance("Error en búsqueda simple: " . $e->getMessage());
        return [];
    }
}
    
    /**
     * Filtrar emails por asunto
     */
    private function filterEmailsBySubject($inbox, $email_ids, $subjects) {
        $found_emails = [];
        $max_check = (int)($this->settings['MAX_EMAILS_TO_CHECK'] ?? 50);
        
        foreach (array_slice($email_ids, 0, $max_check) as $email_id) {
            try {
                $header = imap_headerinfo($inbox, $email_id);
                if (!$header || !isset($header->subject)) {
                    continue;
                }
                
                $decoded_subject = $this->decodeMimeSubject($header->subject);
                
                foreach ($subjects as $subject) {
                    if ($this->subjectMatches($decoded_subject, $subject)) {
                        $found_emails[] = $email_id;
                        
                        // Early stop si está habilitado
                        if (($this->settings['EARLY_SEARCH_STOP'] ?? '1') === '1') {
                            return $found_emails;
                        }
                        break;
                    }
                }
                
            } catch (Exception $e) {
                continue;
            }
        }
        
        return $found_emails;
    }
    
    /**
     * Decodificación segura de asuntos MIME
     */
    private function decodeMimeSubject($subject) {
        if (empty($subject)) {
            return '';
        }
        
        try {
            $decoded = imap_mime_header_decode($subject);
            $result = '';
            
            foreach ($decoded as $part) {
                $charset = $part->charset ?? 'utf-8';
                if (strtolower($charset) === 'default') {
                    $result .= $part->text;
                } else {
                    $result .= mb_convert_encoding($part->text, 'UTF-8', $charset);
                }
            }
            
            return trim($result);
        } catch (Exception $e) {
            return $subject; // Retornar original si falla la decodificación
        }
    }
    
    /**
     * Verificación de coincidencia de asuntos
     */
    private function subjectMatches($decoded_subject, $pattern) {
        // Coincidencia directa (case insensitive)
        if (stripos($decoded_subject, trim($pattern)) !== false) {
            return true;
        }
        
        // Coincidencia flexible por palabras clave
        return $this->flexibleSubjectMatch($decoded_subject, $pattern);
    }
    
    /**
     * Coincidencia flexible de asuntos
     */
    private function flexibleSubjectMatch($subject, $pattern) {
        $subject_clean = strtolower(strip_tags($subject));
        $pattern_clean = strtolower(strip_tags($pattern));
        
        $subject_words = preg_split('/\s+/', $subject_clean);
        $pattern_words = preg_split('/\s+/', $pattern_clean);
        
        if (count($pattern_words) <= 1) {
            return false;
        }
        
        $matches = 0;
        foreach ($pattern_words as $word) {
            if (strlen($word) > 3) {
                foreach ($subject_words as $subject_word) {
                    if (stripos($subject_word, $word) !== false) {
                        $matches++;
                        break;
                    }
                }
            }
        }
        
        $match_ratio = $matches / count($pattern_words);
        return $match_ratio >= 0.7; // 70% de coincidencia
    }
    
    /**
     * Conexión IMAP optimizada
     */
    private function openImapConnection($server_config) {
        if (empty($server_config['imap_server']) || empty($server_config['imap_user'])) {
            return false;
        }
        
        $timeout = (int)($this->settings['IMAP_CONNECTION_TIMEOUT'] ?? 10);
        $old_timeout = ini_get('default_socket_timeout');
        ini_set('default_socket_timeout', $timeout);
        
        try {
            $mailbox = sprintf(
                '{%s:%d/imap/ssl/novalidate-cert}INBOX',
                $server_config['imap_server'],
                $server_config['imap_port']
            );
            
            $inbox = imap_open(
                $mailbox,
                $server_config['imap_user'],
                $server_config['imap_password'],
                OP_READONLY | CL_EXPUNGE,
                1
            );
            
            return $inbox ?: false;
            
        } catch (Exception $e) {
            error_log("Error conexión IMAP: " . $e->getMessage());
            return false;
        } finally {
            ini_set('default_socket_timeout', $old_timeout);
        }
    }
    
    /**
     * Procesar email encontrado
     */
    private function processFoundEmail($inbox, $email_id) {
        try {
            $header = imap_headerinfo($inbox, $email_id);
            $body = get_email_body($inbox, $email_id, $header);
            
            if (!empty($body)) {
                return process_email_body($body);
            }
            
            return null;
        } catch (Exception $e) {
            error_log("Error procesando email: " . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Crear respuesta de error
     */
    private function createErrorResponse($message) {
        return [
            'found' => false,
            'error' => true,
            'message' => $message
        ];
    }
    
    /**
     * Crear respuesta de no encontrado
     */
    private function createNotFoundResponse() {
        return [
            'found' => false,
            'message' => '0 mensajes encontrados.'
        ];
    }
    
    /**
     * Registrar búsqueda en log
     */
    private function logSearch($user_id, $email, $platform, $result) {
        try {
            $status = $result['found'] ? 'Éxito' : 'No Encontrado';
            $detail = $result['found'] ? '[Contenido Omitido]' : ($result['message'] ?? 'Sin detalles');
            
            $stmt = $this->conn->prepare(
                "INSERT INTO logs (user_id, email_consultado, plataforma, ip, resultado) VALUES (?, ?, ?, ?, ?)"
            );
            
            $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $log_entry = $status . ": " . substr(strip_tags($detail), 0, 200);
            
            $stmt->bind_param("issss", $user_id, $email, $platform, $ip, $log_entry);
            $stmt->execute();
            $stmt->close();
            
        } catch (Exception $e) {
            error_log("Error registrando log: " . $e->getMessage());
        }
    }
    
    /**
     * Log de performance (configurable)
     */
    private function logPerformance($message) {
        $logging_enabled = ($this->settings['PERFORMANCE_LOGGING'] ?? '0') === '1';
        
        if ($logging_enabled) {
            error_log("PERFORMANCE: " . $message);
        }
    }
}

// ================================================
// FUNCIONES DE UTILIDAD Y COMPATIBILIDAD
// ================================================

/**
 * Validación de email mejorada
 */
function validate_email($email) {
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return 'El correo electrónico proporcionado es inválido o está vacío.';
    }
    
    if (strlen($email) > 50) {
        return 'El correo electrónico no debe superar los 50 caracteres.';
    }
    
    return '';
}

/**
 * Escape seguro de strings
 */
function escape_string($string) {
    return htmlspecialchars($string, ENT_QUOTES, 'UTF-8');
}

/**
 * Verificar si el sistema está instalado
 */
function is_installed() {
    global $db_host, $db_user, $db_password, $db_name;
    
    if (empty($db_host) || empty($db_user) || empty($db_name)) {
        return false;
    }
    
    try {
        $conn = new mysqli($db_host, $db_user, $db_password, $db_name);
        $conn->set_charset("utf8mb4");
        
        if ($conn->connect_error) {
            return false;
        }
        
        $result = $conn->query("SELECT value FROM settings WHERE name = 'INSTALLED'");
        
        if (!$result || $result->num_rows === 0) {
            $conn->close();
            return false;
        }
        
        $row = $result->fetch_assoc();
        $installed = $row['value'] === '1';
        
        $conn->close();
        return $installed;
        
    } catch (Exception $e) {
        return false;
    }
}

/**
 * Obtener configuraciones (con cache)
 */
function get_all_settings($conn) {
    return SimpleCache::get_settings($conn);
}

/**
 * Verificar configuración habilitada
 */
function is_setting_enabled($setting_name, $conn, $default = false) {
    $settings = SimpleCache::get_settings($conn);
    $value = $settings[$setting_name] ?? ($default ? '1' : '0');
    return $value === '1';
}

/**
 * Obtener valor de configuración
 */
function get_setting_value($setting_name, $conn, $default = '') {
    $settings = SimpleCache::get_settings($conn);
    return $settings[$setting_name] ?? $default;
}

// ================================================
// PROCESAMIENTO DE FORMULARIO PRINCIPAL
// ================================================

if (isset($_POST['email']) && isset($_POST['plataforma'])) {
    try {
        // Conexión a BD
        $conn = new mysqli($db_host, $db_user, $db_password, $db_name);
        $conn->set_charset("utf8mb4");
        
        if ($conn->connect_error) {
            throw new Exception("Error de conexión a la base de datos");
        }
        
        // Inicializar motor de búsqueda
        $search_engine = new EmailSearchEngine($conn);
        
        // Procesar búsqueda
        $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
        $platform = $_POST['plataforma'];
        $user_id = isset($_POST['user_id']) ? (int)$_POST['user_id'] : null;
        
        $result = $search_engine->searchEmails($email, $platform, $user_id);
        
        // Establecer respuesta en sesión
        if ($result['found']) {
            $_SESSION['resultado'] = $result['content'];
            unset($_SESSION['error_message']);
        } else {
            if (isset($result['error']) && $result['error']) {
                $_SESSION['error_message'] = '<div class="alert alert-danger text-center" role="alert">' . 
                                            htmlspecialchars($result['message']) . '</div>';
            } else {
                $_SESSION['resultado'] = '<div class="alert alert-success alert-light text-center" 
                                         style="background-color: #d1e7dd; color: #0f5132;" role="alert">' . 
                                         htmlspecialchars($result['message']) . '</div>';
            }
        }
        
        $conn->close();
        
    } catch (Exception $e) {
        $_SESSION['error_message'] = '<div class="alert alert-danger text-center" role="alert">
            Error del sistema. Inténtalo de nuevo más tarde.
        </div>';
        error_log("Error en procesamiento principal: " . $e->getMessage());
    }
    
    header('Location: inicio.php');
    exit();
}

// ============================
// FUNCIONES DE COMPATIBILIDAD 
// ============================

// Funciones legacy para compatibilidad
function search_email($inbox, $email, $asunto) {
    // Usar nueva clase si está disponible
    return false; // Placeholder
}

function open_imap_connection($server_config) {
    // Usar nueva clase si está disponible
    return false; // Placeholder
}

function close_imap_connection() {
    // Mantenido por compatibilidad
}

?>