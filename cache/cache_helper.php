<?php
/**
 * Sistema de Cache Optimizado para mejorar performance
 * Versión 2.0 - Optimizada para menos consultas BD
 */

class SimpleCache {
    private static $cache_dir = 'cache/data/';
    private static $cache_time = 300; // 5 minutos en segundos
    private static $memory_cache = []; // Cache en memoria para la sesión actual
    
    /**
     * Inicializar el sistema de cache
     */
    public static function init() {
        if (!file_exists(self::$cache_dir)) {
            mkdir(self::$cache_dir, 0755, true);
        }
        
        // Crear archivo .htaccess para proteger la carpeta
        $htaccess_content = "# Proteger carpeta de cache\nDeny from all\n<Files \"*.json\">\nDeny from all\n</Files>";
        $htaccess_file = self::$cache_dir . '.htaccess';
        if (!file_exists($htaccess_file)) {
            file_put_contents($htaccess_file, $htaccess_content);
        }
    }
    
    /**
     * Obtener configuraciones desde cache (MULTI-NIVEL: Memoria -> Archivo -> BD)
     */
    public static function get_settings($conn) {
        $cache_key = 'settings';
        
        // NIVEL 1: Cache en memoria (más rápido)
        if (isset(self::$memory_cache[$cache_key])) {
            return self::$memory_cache[$cache_key];
        }
        
        // NIVEL 2: Cache en archivo
        $cache_file = self::$cache_dir . 'settings.json';
        if (file_exists($cache_file) && (time() - filemtime($cache_file)) < self::$cache_time) {
            $cached_data = file_get_contents($cache_file);
            $data = json_decode($cached_data, true);
            if ($data !== null) {
                // Guardar en memoria para próximas consultas en esta sesión
                self::$memory_cache[$cache_key] = $data;
                return $data;
            }
        }
        
        // NIVEL 3: Consultar BD (último recurso)
        $settings = [];
        $stmt = $conn->prepare("SELECT name, value FROM settings");
        if ($stmt) {
            $stmt->execute();
            $result = $stmt->get_result();
            
            while ($row = $result->fetch_assoc()) {
                $settings[$row['name']] = $row['value'];
            }
            $stmt->close();
            
            // Guardar en ambos caches
            file_put_contents($cache_file, json_encode($settings));
            self::$memory_cache[$cache_key] = $settings;
        } else {
            error_log("Error al preparar consulta de settings: " . $conn->error);
        }
        
        return $settings;
    }
    
    /**
     * Obtener plataformas y asuntos desde cache (MULTI-NIVEL: Memoria -> Archivo -> BD)
     */
    public static function get_platform_subjects($conn) {
        $cache_key = 'platforms';
        
        // NIVEL 1: Cache en memoria
        if (isset(self::$memory_cache[$cache_key])) {
            return self::$memory_cache[$cache_key];
        }
        
        // NIVEL 2: Cache en archivo
        $cache_file = self::$cache_dir . 'platforms.json';
        if (file_exists($cache_file) && (time() - filemtime($cache_file)) < self::$cache_time) {
            $cached_data = file_get_contents($cache_file);
            $data = json_decode($cached_data, true);
            if ($data !== null) {
                self::$memory_cache[$cache_key] = $data;
                return $data;
            }
        }
        
        // NIVEL 3: Consultar BD con query optimizada
        $platforms = [];
        
        // Una sola query que trae todo lo necesario
        $query = "
            SELECT p.name as platform_name, ps.subject 
            FROM platforms p 
            LEFT JOIN platform_subjects ps ON p.id = ps.platform_id 
            ORDER BY p.sort_order ASC, ps.subject ASC
        ";
        
        $result = $conn->query($query);
        if ($result) {
            while ($row = $result->fetch_assoc()) {
                $platform_name = $row['platform_name'];
                if (!isset($platforms[$platform_name])) {
                    $platforms[$platform_name] = [];
                }
                if (!empty($row['subject'])) {
                    $platforms[$platform_name][] = $row['subject'];
                }
            }
            
            // Guardar en ambos caches
            file_put_contents($cache_file, json_encode($platforms));
            self::$memory_cache[$cache_key] = $platforms;
        } else {
            error_log("Error al consultar plataformas: " . $conn->error);
        }
        
        return $platforms;
    }
    
    /**
     * NUEVA: Cache para servidores IMAP habilitados
     */
    public static function get_enabled_servers($conn) {
        $cache_key = 'enabled_servers';
        
        // Cache en memoria
        if (isset(self::$memory_cache[$cache_key])) {
            return self::$memory_cache[$cache_key];
        }
        
        // Cache en archivo (tiempo más corto para servidores)
        $cache_file = self::$cache_dir . 'servers.json';
        $server_cache_time = 60; // 1 minuto para servidores
        
        if (file_exists($cache_file) && (time() - filemtime($cache_file)) < $server_cache_time) {
            $cached_data = file_get_contents($cache_file);
            $data = json_decode($cached_data, true);
            if ($data !== null) {
                self::$memory_cache[$cache_key] = $data;
                return $data;
            }
        }
        
        // Consultar BD
        $servers = [];
        $query = "SELECT * FROM email_servers WHERE enabled = 1 ORDER BY id ASC";
        $result = $conn->query($query);
        
        if ($result) {
            while ($row = $result->fetch_assoc()) {
                $servers[] = $row;
            }
            
            file_put_contents($cache_file, json_encode($servers));
            self::$memory_cache[$cache_key] = $servers;
        }
        
        return $servers;
    }
    
    /**
     * Limpiar cache completo
     */
    public static function clear_cache() {
        // Limpiar cache en memoria
        self::$memory_cache = [];
        
        // Limpiar archivos de cache
        $files = glob(self::$cache_dir . '*.json');
        foreach ($files as $file) {
            if (file_exists($file)) {
                unlink($file);
            }
        }
    }
    
    /**
     * Limpiar solo cache de configuraciones
     */
    public static function clear_settings_cache() {
        unset(self::$memory_cache['settings']);
        
        $cache_file = self::$cache_dir . 'settings.json';
        if (file_exists($cache_file)) {
            unlink($cache_file);
        }
    }
    
    /**
     * Limpiar solo cache de plataformas
     */
    public static function clear_platforms_cache() {
        unset(self::$memory_cache['platforms']);
        
        $cache_file = self::$cache_dir . 'platforms.json';
        if (file_exists($cache_file)) {
            unlink($cache_file);
        }
    }
    
    /**
     * NUEVA: Limpiar cache de servidores
     */
    public static function clear_servers_cache() {
        unset(self::$memory_cache['enabled_servers']);
        
        $cache_file = self::$cache_dir . 'servers.json';
        if (file_exists($cache_file)) {
            unlink($cache_file);
        }
    }
    
    /**
     * NUEVA: Obtener estadísticas del cache
     */
    public static function get_cache_stats() {
        $stats = [
            'memory_cached_items' => count(self::$memory_cache),
            'file_cache_dir' => self::$cache_dir,
            'cache_time_seconds' => self::$cache_time
        ];
        
        // Contar archivos de cache
        $cache_files = glob(self::$cache_dir . '*.json');
        $stats['file_cached_items'] = count($cache_files);
        
        // Tamaño de archivos de cache
        $total_size = 0;
        foreach ($cache_files as $file) {
            $total_size += filesize($file);
        }
        $stats['total_cache_size_bytes'] = $total_size;
        
        return $stats;
    }
}

// Inicializar cache al incluir el archivo
SimpleCache::init();
?>