<?php
/**
 * Script de Debug para Verificar Estado de Licencia
 * Guardar como: debug_license_status.php
 * Ejecutar desde: http://tudominio.com/debug_license_status.php
 */

// Configuración de debugging
ini_set('display_errors', 1);
error_reporting(E_ALL);

echo "<!DOCTYPE html>
<html lang='es'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Debug - Estado de Licencia</title>
    <style>
        body { font-family: 'Courier New', monospace; margin: 20px; background: #f5f5f5; }
        .container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .success { background: #d4edda; border-color: #c3e6cb; }
        .warning { background: #fff3cd; border-color: #ffeaa7; }
        .error { background: #f8d7da; border-color: #f5c6cb; }
        .info { background: #d1ecf1; border-color: #bee5eb; }
        pre { background: #f8f9fa; padding: 10px; border-radius: 4px; overflow-x: auto; }
        .badge { padding: 4px 8px; border-radius: 4px; color: white; font-size: 12px; }
        .badge-success { background: #28a745; }
        .badge-danger { background: #dc3545; }
        .badge-warning { background: #ffc107; color: #212529; }
        .badge-info { background: #17a2b8; }
    </style>
</head>
<body>
<div class='container'>
    <h1>🔍 Debug - Estado de Licencia</h1>
    <p><strong>Fecha/Hora:</strong> " . date('Y-m-d H:i:s') . "</p>
";

try {
    // 1. Verificar archivo license_client.php
    echo "<div class='section info'>
        <h3>📁 1. Verificación de Archivos</h3>";
    
    $license_client_path = 'license_client.php';
    if (file_exists($license_client_path)) {
        echo "<span class='badge badge-success'>✓</span> license_client.php encontrado<br>";
        require_once $license_client_path;
    } else {
        echo "<span class='badge badge-danger'>✗</span> license_client.php NO encontrado<br>";
        echo "Buscando en rutas alternativas...<br>";
        
        $possible_paths = [
            '../license_client.php',
            './license_client.php',
            __DIR__ . '/license_client.php',
            __DIR__ . '/../license_client.php'
        ];
        
        foreach ($possible_paths as $path) {
            if (file_exists($path)) {
                echo "<span class='badge badge-success'>✓</span> Encontrado en: $path<br>";
                require_once $path;
                break;
            }
        }
    }
    echo "</div>";
    
    // 2. Crear instancia del cliente
    echo "<div class='section info'>
        <h3>🔧 2. Inicialización del Cliente</h3>";
    
    if (class_exists('ClientLicense')) {
        echo "<span class='badge badge-success'>✓</span> Clase ClientLicense encontrada<br>";
        $license_client = new ClientLicense();
        echo "<span class='badge badge-success'>✓</span> Instancia creada exitosamente<br>";
    } else {
        throw new Exception("Clase ClientLicense no encontrada");
    }
    echo "</div>";
    
    // 3. Información diagnóstica
    echo "<div class='section info'>
        <h3>🔍 3. Información Diagnóstica</h3>";
    
    $diagnostic = $license_client->getDiagnosticInfo();
    echo "<pre>";
    foreach ($diagnostic as $key => $value) {
        $status = is_bool($value) ? ($value ? '✓' : '✗') : $value;
        echo sprintf("%-20s: %s\n", $key, $status);
    }
    echo "</pre>";
    echo "</div>";
    
    // 4. Estado actual de la licencia
    echo "<div class='section " . ($license_client->isLicenseValid() ? 'success' : 'error') . "'>
        <h3>📋 4. Estado Actual de la Licencia</h3>";
    
    $is_valid = $license_client->isLicenseValid();
    echo "<strong>Estado:</strong> <span class='badge badge-" . ($is_valid ? 'success' : 'danger') . "'>" . 
         ($is_valid ? 'VÁLIDA' : 'INVÁLIDA') . "</span><br>";
    
    $license_info = $license_client->getLicenseInfo();
    if ($license_info) {
        echo "<pre>";
        print_r($license_info);
        echo "</pre>";
    } else {
        echo "<span class='badge badge-warning'>⚠</span> No se pudo obtener información de licencia<br>";
    }
    echo "</div>";
    
    // 5. Contenido del archivo de licencia
    echo "<div class='section info'>
        <h3>📄 5. Contenido del Archivo de Licencia</h3>";
    
    $license_file = $diagnostic['license_file'] ?? '';
    if (file_exists($license_file)) {
        echo "<strong>Archivo:</strong> $license_file<br>";
        echo "<strong>Tamaño:</strong> " . filesize($license_file) . " bytes<br>";
        echo "<strong>Modificado:</strong> " . date('Y-m-d H:i:s', filemtime($license_file)) . "<br>";
        
        $content = file_get_contents($license_file);
        $decoded = base64_decode($content);
        $data = unserialize($decoded);
        
        if ($data) {
            echo "<strong>Datos decodificados:</strong><br>";
            echo "<pre>";
            print_r($data);
            echo "</pre>";
            
            // Calcular tiempo desde última verificación
            $last_check = $data['last_check'] ?? 0;
            $time_diff = time() - $last_check;
            $hours_ago = round($time_diff / 3600, 1);
            $next_check = 86400 - $time_diff; // 24 horas - tiempo transcurrido
            $hours_until = round($next_check / 3600, 1);
            
            echo "<div class='section " . ($time_diff < 86400 ? 'success' : 'warning') . "'>
                <h4>⏰ Información de Temporización</h4>
                <strong>Última verificación:</strong> $hours_ago horas atrás<br>
                <strong>Próxima verificación:</strong> " . ($next_check > 0 ? "$hours_until horas" : "PENDIENTE") . "<br>
                <strong>Estado temporal:</strong> <span class='badge badge-" . 
                ($time_diff < 86400 ? 'success' : 'warning') . "'>" . 
                ($time_diff < 86400 ? 'Dentro del período de 24h' : 'Requiere verificación remota') . "</span>
            </div>";
        } else {
            echo "<span class='badge badge-error'>✗</span> Error decodificando datos del archivo<br>";
        }
    } else {
        echo "<span class='badge badge-danger'>✗</span> Archivo de licencia no encontrado: $license_file<br>";
    }
    echo "</div>";
    
    // 6. Test de conectividad
    echo "<div class='section info'>
        <h3>🌐 6. Test de Conectividad</h3>";
    
    $server_url = 'https://scode.warsup.shop/api.php';
    echo "<strong>Servidor de licencias:</strong> $server_url<br>";
    
    if (function_exists('curl_init')) {
        echo "<span class='badge badge-success'>✓</span> cURL disponible<br>";
        
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $server_url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_NOBODY => true, // Solo headers
            CURLOPT_SSL_VERIFYPEER => false
        ]);
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        
        if ($response !== false && empty($error)) {
            echo "<span class='badge badge-success'>✓</span> Conexión exitosa (HTTP $http_code)<br>";
        } else {
            echo "<span class='badge badge-danger'>✗</span> Error de conexión: $error<br>";
        }
    } else {
        echo "<span class='badge badge-danger'>✗</span> cURL no disponible<br>";
    }
    echo "</div>";
    
    // 7. Logs recientes (si existen)
    echo "<div class='section info'>
        <h3>📜 7. Logs del Sistema</h3>";
    
    // Verificar si existe el log personalizado
    $log_file = dirname($license_file) . '/license_activity.log';
    if (file_exists($log_file)) {
        echo "<strong>Log personalizado encontrado:</strong> $log_file<br>";
        $log_content = file_get_contents($log_file);
        $lines = explode("\n", trim($log_content));
        $recent_lines = array_slice($lines, -10); // Últimas 10 líneas
        
        echo "<strong>Últimas 10 entradas:</strong><br>";
        echo "<pre>";
        foreach ($recent_lines as $line) {
            if (!empty(trim($line))) {
                echo htmlspecialchars($line) . "\n";
            }
        }
        echo "</pre>";
    } else {
        echo "<span class='badge badge-warning'>⚠</span> Log personalizado no encontrado<br>";
    }
    
    // Buscar en error_log del servidor
    $error_log_paths = [
        ini_get('error_log'),
        '/var/log/apache2/error.log',
        '/var/log/nginx/error.log',
        $_SERVER['DOCUMENT_ROOT'] . '/error_log'
    ];
    
    foreach ($error_log_paths as $path) {
        if ($path && file_exists($path) && is_readable($path)) {
            echo "<strong>Revisando error_log:</strong> $path<br>";
            $command = "grep -i 'licencia\\|license' " . escapeshellarg($path) . " | tail -5";
            $output = shell_exec($command);
            if (!empty($output)) {
                echo "<pre>" . htmlspecialchars($output) . "</pre>";
            } else {
                echo "No se encontraron entradas relacionadas con licencias<br>";
            }
            break;
        }
    }
    echo "</div>";
    
    // 8. Recomendaciones
    echo "<div class='section " . ($is_valid ? 'success' : 'warning') . "'>
        <h3>💡 8. Recomendaciones</h3>";
    
    if ($is_valid) {
        echo "<span class='badge badge-success'>✓</span> Sistema funcionando correctamente<br>";
        if ($time_diff > 72000) { // Más de 20 horas
            echo "<span class='badge badge-warning'>⚠</span> Próxima verificación remota pronto<br>";
        }
    } else {
        echo "<span class='badge badge-danger'>⚠</span> <strong>Acciones requeridas:</strong><br>";
        echo "1. Verificar conectividad a internet<br>";
        echo "2. Comprobar que el dominio coincide con la licencia<br>";
        echo "3. Contactar soporte si el problema persiste<br>";
    }
    echo "</div>";

} catch (Exception $e) {
    echo "<div class='section error'>
        <h3>❌ Error</h3>
        <strong>Error:</strong> " . htmlspecialchars($e->getMessage()) . "<br>
        <strong>Archivo:</strong> " . $e->getFile() . "<br>
        <strong>Línea:</strong> " . $e->getLine() . "
    </div>";
}

echo "
    <div class='section info'>
        <h3>🔄 Actualizar</h3>
        <button onclick='location.reload()' style='padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer;'>
            Actualizar Estado
        </button>
    </div>
</div>
</body>
</html>";
?>