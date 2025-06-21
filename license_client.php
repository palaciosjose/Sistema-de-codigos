<?php
/**
 * Cliente de Licencias - VERSIÓN COMPLETA CON MONITOREO
 * Incluye sistema de logging y monitoreo de verificaciones
 * Versión: 3.0
 */

class ClientLicense {
    private $license_server;
    private $license_dir;
    private $license_file;
    
    public function __construct($license_server = null) {
        $this->license_server = $license_server ?: 'https://scode.warsup.shop/api.php';
        
        // ==========================================
        // SOLUCIÓN AL PROBLEMA DE RUTAS
        // ==========================================
        
        // Verificar si las constantes ya están definidas (desde el instalador)
        if (defined('LICENSE_DIR') && defined('LICENSE_FILE')) {
            // Usar las constantes definidas por el instalador
            $this->license_dir = LICENSE_DIR;
            $this->license_file = LICENSE_FILE;
        } else {
            // Definir rutas basadas en la raíz del proyecto
            $this->license_dir = $this->getProjectRoot() . '/license';
            $this->license_file = $this->license_dir . '/license.dat';
            
            // Definir constantes para uso futuro
            if (!defined('LICENSE_DIR')) {
                define('LICENSE_DIR', $this->license_dir);
            }
            if (!defined('LICENSE_FILE')) {
                define('LICENSE_FILE', $this->license_file);
            }
        }
        
        // Asegurar que el directorio existe
        $this->ensureLicenseDirectoryExists();
    }
    
    /**
     * Obtener la ruta raíz del proyecto independientemente de dónde se ejecute
     */
    private function getProjectRoot() {
        // Si está definida la constante PROJECT_ROOT, usarla
        if (defined('PROJECT_ROOT')) {
            return PROJECT_ROOT;
        }
        
        // Detectar la raíz del proyecto buscando archivos característicos
        $current_dir = __DIR__;
        $max_levels = 5; // Máximo 5 niveles hacia arriba
        $level = 0;
        
        while ($level < $max_levels) {
            // Buscar archivos que indiquen la raíz del proyecto
            $markers = [
                'index.php',
                'inicio.php', 
                'config/config.php',
                'instalacion/basededatos.php'
            ];
            
            foreach ($markers as $marker) {
                if (file_exists($current_dir . '/' . $marker)) {
                    return $current_dir;
                }
            }
            
            // Subir un nivel
            $parent_dir = dirname($current_dir);
            if ($parent_dir === $current_dir) {
                // Llegamos a la raíz del sistema, parar
                break;
            }
            $current_dir = $parent_dir;
            $level++;
        }
        
        // Si no se encuentra, usar el directorio actual como fallback
        return __DIR__;
    }
    
    /**
     * Asegurar que el directorio de licencias existe
     */
    private function ensureLicenseDirectoryExists() {
        if (!file_exists($this->license_dir)) {
            if (!mkdir($this->license_dir, 0755, true)) {
                error_log("Error: No se pudo crear el directorio de licencias: " . $this->license_dir);
                return false;
            }
            
            // Crear .htaccess para proteger el directorio
            $htaccess_content = "Deny from all\n<Files \"*.dat\">\nDeny from all\n</Files>";
            file_put_contents($this->license_dir . '/.htaccess', $htaccess_content);
        }
        
        return true;
    }
    
    /**
     * ==========================================
     * SISTEMA DE LOGGING MEJORADO
     * ==========================================
     */
    
    /**
     * Log mejorado para verificaciones de licencia
     */
    private function logLicenseActivity($message, $type = 'info') {
        $log_file = $this->license_dir . '/license_activity.log';
        $timestamp = date('Y-m-d H:i:s');
        $log_entry = "[$timestamp] [$type] $message" . PHP_EOL;
        
        // Escribir al log personalizado
        file_put_contents($log_file, $log_entry, FILE_APPEND | LOCK_EX);
        
        // También escribir al error_log del sistema si es error o warning
        if (in_array($type, ['error', 'warning'])) {
            error_log("License Monitor [$type]: $message");
        }
    }
    
    /**
     * Limpiar logs antiguos (mantener solo últimos 30 días)
     */
    public function cleanOldLogs() {
        $log_file = $this->license_dir . '/license_activity.log';
        
        if (!file_exists($log_file)) {
            return;
        }
        
        $content = file_get_contents($log_file);
        $lines = explode("\n", $content);
        $cutoff_date = date('Y-m-d', strtotime('-30 days'));
        $filtered_lines = [];
        
        foreach ($lines as $line) {
            if (preg_match('/\[(.+?)\]/', $line, $matches)) {
                $line_date = substr($matches[1], 0, 10);
                if ($line_date >= $cutoff_date) {
                    $filtered_lines[] = $line;
                }
            }
        }
        
        file_put_contents($log_file, implode("\n", $filtered_lines));
        $this->logLicenseActivity("Logs antiguos limpiados automáticamente", 'info');
    }
    
    /**
     * ==========================================
     * FUNCIONES PRINCIPALES DE LICENCIA
     * ==========================================
     */
    
    /**
     * Activar licencia
     */
    public function activateLicense($license_key) {
        $this->logLicenseActivity("Iniciando activación de licencia", 'info');
        
        try {
            $domain = $_SERVER['HTTP_HOST'];
            $ip = $_SERVER['SERVER_ADDR'] ?? $_SERVER['REMOTE_ADDR'] ?? '';
            
            $data = [
                'action' => 'activate',
                'license_key' => $license_key,
                'domain' => $domain,
                'ip' => $ip,
                'software' => 'Sistema de Códigos',
                'version' => '2.0'
            ];
            
            $this->logLicenseActivity("Enviando petición de activación para dominio: $domain", 'info');
            $response = $this->makeRequest($data);
            
            if ($response && $response['success']) {
                // Guardar la licencia en el archivo correcto
                $license_data = [
                    'license_key' => $license_key,
                    'domain' => $domain,
                    'activated_at' => date('Y-m-d H:i:s'),
                    'last_check' => time(),
                    'status' => 'active',
                    'server_response' => $response,
                    'activation_ip' => $ip
                ];
                
                if ($this->saveLicenseData($license_data)) {
                    $this->logLicenseActivity("Licencia activada y guardada exitosamente", 'success');
                    error_log("Licencia guardada exitosamente en: " . $this->license_file);
                    return ['success' => true, 'message' => 'Licencia activada correctamente'];
                } else {
                    $this->logLicenseActivity("Error guardando archivo de licencia", 'error');
                    error_log("Error guardando licencia en: " . $this->license_file);
                    return ['success' => false, 'message' => 'Error guardando la licencia'];
                }
            } else {
                $error_msg = $response['message'] ?? 'Error desconocido del servidor';
                $this->logLicenseActivity("Activación fallida: $error_msg", 'error');
                return ['success' => false, 'message' => $error_msg];
            }
            
        } catch (Exception $e) {
            $error_msg = $e->getMessage();
            $this->logLicenseActivity("Error en activación: $error_msg", 'error');
            error_log("Error activando licencia: " . $error_msg);
            return ['success' => false, 'message' => 'Error de conexión: ' . $error_msg];
        }
    }
    
    /**
     * Verificar si la licencia es válida (VERSIÓN MEJORADA)
     */
    public function isLicenseValid() {
        // Verificar en modo instalador
        if (defined('INSTALLER_MODE') && INSTALLER_MODE) {
            return $this->hasLicense();
        }
        
        if (!$this->hasLicense()) {
            $this->logLicenseActivity("No se encontró archivo de licencia", 'warning');
            return false;
        }
        
        $license_data = $this->getLicenseData();
        if (!$license_data) {
            $this->logLicenseActivity("No se pudieron leer los datos de licencia", 'error');
            return false;
        }
        
        // Verificar si necesita validación remota (cada 24 horas)
        $last_check = $license_data['last_check'] ?? 0;
        $time_since_check = time() - $last_check;
        
        if ($time_since_check > 86400) { // 24 horas
            $hours_since = round($time_since_check / 3600, 1);
            $this->logLicenseActivity("Necesaria verificación remota (última hace $hours_since horas)", 'info');
            return $this->validateWithServer($license_data);
        } else {
            $hours_remaining = round((86400 - $time_since_check) / 3600, 1);
            $this->logLicenseActivity("Usando licencia local válida (próxima verificación en $hours_remaining horas)", 'info');
        }
        
        return $license_data['status'] === 'active';
    }
    
    /**
     * Verificar si existe archivo de licencia
     */
    public function hasLicense() {
        return file_exists($this->license_file) && is_readable($this->license_file);
    }
    
    /**
     * Obtener información de la licencia
     */
    public function getLicenseInfo() {
        if (!$this->hasLicense()) {
            return null;
        }
        
        $license_data = $this->getLicenseData();
        if (!$license_data) {
            return null;
        }
        
        return [
            'domain' => $license_data['domain'] ?? '',
            'activated_at' => $license_data['activated_at'] ?? '',
            'status' => $license_data['status'] ?? 'unknown',
            'last_check' => date('Y-m-d H:i:s', $license_data['last_check'] ?? 0),
            'file_path' => $this->license_file,
            'activation_ip' => $license_data['activation_ip'] ?? '',
            'license_key_preview' => isset($license_data['license_key']) ? 
                substr($license_data['license_key'], 0, 8) . '...' . substr($license_data['license_key'], -4) : ''
        ];
    }
    
    /**
     * Guardar datos de licencia en archivo
     */
    private function saveLicenseData($data) {
        try {
            // Agregar timestamp de última actualización
            $data['last_updated'] = time();
            
            $encoded = base64_encode(serialize($data));
            $result = file_put_contents($this->license_file, $encoded, LOCK_EX);
            
            if ($result !== false) {
                chmod($this->license_file, 0644);
                return true;
            }
            
            return false;
        } catch (Exception $e) {
            $this->logLicenseActivity("Error guardando datos: " . $e->getMessage(), 'error');
            error_log("Error guardando licencia: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Leer datos de licencia desde archivo
     */
    private function getLicenseData() {
        try {
            if (!$this->hasLicense()) {
                return null;
            }
            
            $content = file_get_contents($this->license_file);
            if ($content === false) {
                return null;
            }
            
            $decoded = base64_decode($content);
            if ($decoded === false) {
                return null;
            }
            
            $data = unserialize($decoded);
            if ($data === false) {
                return null;
            }
            
            return $data;
        } catch (Exception $e) {
            $this->logLicenseActivity("Error leyendo datos: " . $e->getMessage(), 'error');
            error_log("Error leyendo licencia: " . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Validar licencia con el servidor remoto (VERSIÓN MEJORADA)
     */
    private function validateWithServer($license_data) {
        $this->logLicenseActivity("Iniciando verificación remota de licencia", 'info');
        
        try {
            $data = [
                'action' => 'validate',
                'license_key' => $license_data['license_key'] ?? '',
                'domain' => $_SERVER['HTTP_HOST'],
                'current_domain' => $license_data['domain'] ?? ''
            ];
            
            $this->logLicenseActivity("Enviando petición a: " . $this->license_server, 'info');
            $response = $this->makeRequest($data);
            
            if ($response && $response['success']) {
                // Actualizar datos de licencia
                $license_data['last_check'] = time();
                $license_data['status'] = 'active';
                $license_data['last_validation_response'] = $response;
                $license_data['validation_count'] = ($license_data['validation_count'] ?? 0) + 1;
                $this->saveLicenseData($license_data);
                
                $this->logLicenseActivity("Verificación exitosa - Licencia válida", 'success');
                return true;
            } else {
                // Marcar como inválida pero conservar archivo para debugging
                $license_data['last_check'] = time();
                $license_data['status'] = 'invalid';
                $license_data['last_error'] = $response['message'] ?? 'Error desconocido';
                $license_data['error_count'] = ($license_data['error_count'] ?? 0) + 1;
                $this->saveLicenseData($license_data);
                
                $error_msg = $response['message'] ?? 'Respuesta inválida del servidor';
                $this->logLicenseActivity("Verificación fallida: $error_msg", 'error');
                return false;
            }
        } catch (Exception $e) {
            $error_msg = $e->getMessage();
            $this->logLicenseActivity("Error en verificación: $error_msg", 'error');
            
            // En caso de error de red, mantener válida si no ha expirado hace mucho
            $grace_period = 7 * 24 * 3600; // 7 días
            $is_within_grace = (time() - ($license_data['last_check'] ?? 0)) < $grace_period;
            
            if ($is_within_grace) {
                $this->logLicenseActivity("Usando período de gracia - Licencia mantenida como válida", 'warning');
            } else {
                $this->logLicenseActivity("Período de gracia expirado - Licencia marcada como inválida", 'error');
            }
            
            return $is_within_grace;
        }
    }
    
    /**
     * Realizar petición HTTP al servidor de licencias
     */
    private function makeRequest($data, $timeout = 10) {
        if (!function_exists('curl_init')) {
            throw new Exception('cURL no está disponible');
        }
        
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $this->license_server,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($data),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_USERAGENT => 'License-Client/3.0'
        ]);
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        
        if ($response === false || !empty($error)) {
            throw new Exception("Error cURL: " . $error);
        }
        
        if ($http_code !== 200) {
            throw new Exception("HTTP Error: " . $http_code);
        }
        
        $decoded = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception("Error decodificando respuesta JSON");
        }
        
        return $decoded;
    }
    
    /**
     * ==========================================
     * FUNCIONES DE MONITOREO Y DIAGNÓSTICO
     * ==========================================
     */
    
    /**
     * Obtener información de diagnóstico
     */
    public function getDiagnosticInfo() {
        return [
            'license_dir' => $this->license_dir,
            'license_file' => $this->license_file,
            'directory_exists' => file_exists($this->license_dir),
            'directory_writable' => is_writable($this->license_dir),
            'file_exists' => file_exists($this->license_file),
            'file_readable' => is_readable($this->license_file),
            'file_writable' => is_writable($this->license_file),
            'project_root' => $this->getProjectRoot(),
            'current_dir' => getcwd(),
            'script_dir' => __DIR__,
            'server_url' => $this->license_server,
            'constants_defined' => [
                'LICENSE_DIR' => defined('LICENSE_DIR'),
                'LICENSE_FILE' => defined('LICENSE_FILE'),
                'PROJECT_ROOT' => defined('PROJECT_ROOT'),
                'INSTALLER_MODE' => defined('INSTALLER_MODE')
            ]
        ];
    }
    
    /**
     * Obtener actividad reciente de licencia
     */
    public function getLicenseActivity($lines = 50) {
        $log_file = $this->license_dir . '/license_activity.log';
        
        if (!file_exists($log_file)) {
            return [];
        }
        
        $content = file_get_contents($log_file);
        $lines_array = explode("\n", trim($content));
        
        // Obtener las últimas líneas
        $recent_lines = array_slice($lines_array, -$lines);
        $activity = [];
        
        foreach ($recent_lines as $line) {
            if (preg_match('/\[(.+?)\] \[(.+?)\] (.+)/', $line, $matches)) {
                $activity[] = [
                    'timestamp' => $matches[1],
                    'type' => $matches[2],
                    'message' => $matches[3]
                ];
            }
        }
        
        return array_reverse($activity); // Más recientes primero
    }
    
    /**
     * Forzar verificación inmediata (para testing)
     */
    public function forceValidation() {
        $this->logLicenseActivity("Verificación forzada por administrador", 'info');
        
        $license_data = $this->getLicenseData();
        if (!$license_data) {
            return ['success' => false, 'message' => 'No se encontraron datos de licencia'];
        }
        
        try {
            $result = $this->validateWithServer($license_data);
            return [
                'success' => $result,
                'message' => $result ? 'Verificación exitosa' : 'Verificación fallida'
            ];
        } catch (Exception $e) {
            return ['success' => false, 'message' => $e->getMessage()];
        }
    }
    
    /**
     * Obtener estadísticas de la licencia
     */
    public function getLicenseStats() {
        $license_data = $this->getLicenseData();
        if (!$license_data) {
            return null;
        }
        
        $last_check = $license_data['last_check'] ?? 0;
        $activated_at = strtotime($license_data['activated_at'] ?? '');
        $time_since_check = time() - $last_check;
        $time_since_activation = time() - $activated_at;
        
        return [
            'status' => $license_data['status'] ?? 'unknown',
            'validation_count' => $license_data['validation_count'] ?? 0,
            'error_count' => $license_data['error_count'] ?? 0,
            'days_since_activation' => round($time_since_activation / 86400),
            'hours_since_last_check' => round($time_since_check / 3600, 1),
            'hours_until_next_check' => round((86400 - $time_since_check) / 3600, 1),
            'grace_period_remaining' => round((7 * 86400 - $time_since_check) / 86400, 1),
            'last_error' => $license_data['last_error'] ?? null
        ];
    }
}

// ==========================================
// VERIFICACIÓN AUTOMÁTICA (SOLO SI NO ES INSTALADOR)
// ==========================================
if (!defined('INSTALLER_MODE') || !INSTALLER_MODE) {
    $license_client = new ClientLicense();
    
    // Verificar licencia en páginas públicas
    $exempt_files = ['index.php', 'inicio.php', 'license_monitor.php', 'debug_license_status.php'];
    $current_file = basename($_SERVER['SCRIPT_NAME']);
    
    if (!in_array($current_file, $exempt_files)) {
        if (!$license_client->isLicenseValid()) {
            // Redirigir a página de error de licencia o bloquear acceso
            header('HTTP/1.1 403 Forbidden');
            echo '<!DOCTYPE html>
            <html>
            <head>
                <title>Licencia Requerida</title>
                <style>
                    body { font-family: Arial, sans-serif; text-align: center; margin-top: 100px; background: #f8f9fa; }
                    .error-box { 
                        background: white; 
                        border: 1px solid #dc3545; 
                        padding: 30px; 
                        margin: 20px auto; 
                        width: 60%; 
                        border-radius: 8px; 
                        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                    }
                    .error-icon { font-size: 48px; color: #dc3545; margin-bottom: 20px; }
                    h1 { color: #dc3545; margin-bottom: 20px; }
                    .btn { 
                        background: #007bff; 
                        color: white; 
                        padding: 10px 20px; 
                        text-decoration: none; 
                        border-radius: 4px; 
                        display: inline-block; 
                        margin: 10px;
                    }
                </style>
            </head>
            <body>
                <div class="error-box">
                    <div class="error-icon">🛡️</div>
                    <h1>Licencia Requerida</h1>
                    <p>Este software requiere una licencia válida para funcionar.</p>
                    <p>Contacte al administrador del sistema.</p>
                    <hr>
                    <small>
                        <strong>Información técnica:</strong><br>
                        Archivo: ' . htmlspecialchars($current_file) . '<br>
                        Fecha: ' . date('Y-m-d H:i:s') . '
                    </small>
                </div>
            </body>
            </html>';
            exit;
        }
    }
}
?>