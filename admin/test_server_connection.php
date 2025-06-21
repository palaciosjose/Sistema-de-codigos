<?php
// Sistema híbrido inteligente - Detecta problemas DNS y sugiere soluciones
error_reporting(E_ALL);
ini_set('display_errors', 1);

header('Content-Type: application/json; charset=utf-8');

try {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['success' => false, 'error' => 'Método no permitido']);
        exit();
    }

    if (!extension_loaded('imap')) {
        echo json_encode([
            'success' => false, 
            'error' => 'La extensión PHP IMAP no está instalada en este servidor'
        ]);
        exit();
    }

    $base_dir = dirname(__DIR__);
    $required_files = [
        $base_dir . '/instalacion/basededatos.php',
        $base_dir . '/security/auth.php'
    ];

    foreach ($required_files as $file) {
        if (!file_exists($file)) {
            echo json_encode([
                'success' => false, 
                'error' => "Archivo requerido no encontrado: " . basename($file)
            ]);
            exit();
        }
        require_once $file;
    }

    if (!function_exists('is_admin') || !is_admin()) {
        echo json_encode([
            'success' => false, 
            'error' => 'Acceso denegado. Se requieren permisos de administrador.'
        ]);
        exit();
    }

    // Manejar actualización automática de configuración a IP
    if (isset($_POST['action']) && $_POST['action'] === 'update_to_ip') {
        $server_id = intval($_POST['server_id'] ?? 0);
        $new_ip = trim($_POST['suggested_ip'] ?? '');
        
        if ($server_id && $new_ip && filter_var($new_ip, FILTER_VALIDATE_IP)) {
            try {
                $update_conn = new mysqli($db_host, $db_user, $db_password, $db_name);
                $update_conn->set_charset("utf8mb4");
                
                if (!$update_conn->connect_error) {
                    $stmt = $update_conn->prepare("UPDATE email_servers SET imap_server = ? WHERE id = ?");
                    $stmt->bind_param("si", $new_ip, $server_id);
                    
                    if ($stmt->execute()) {
                        $stmt->close();
                        $update_conn->close();
                        
                        echo json_encode([
                            'success' => true,
                            'message' => "Configuración actualizada a IP: {$new_ip}",
                            'updated' => true
                        ]);
                        exit();
                    } else {
                        $stmt->close();
                        $update_conn->close();
                        echo json_encode([
                            'success' => false,
                            'error' => 'Error al actualizar la configuración'
                        ]);
                        exit();
                    }
                } else {
                    echo json_encode([
                        'success' => false,
                        'error' => 'Error de conexión a la base de datos'
                    ]);
                    exit();
                }
            } catch (Exception $e) {
                echo json_encode([
                    'success' => false,
                    'error' => 'Error actualizando configuración: ' . $e->getMessage()
                ]);
                exit();
            }
        } else {
            echo json_encode([
                'success' => false,
                'error' => 'Datos inválidos para actualización'
            ]);
            exit();
        }
    }

    $required_fields = ['imap_server', 'imap_port', 'imap_user', 'imap_password'];
    foreach ($required_fields as $field) {
        if (!isset($_POST[$field]) || empty(trim($_POST[$field]))) {
            echo json_encode([
                'success' => false, 
                'error' => "Campo requerido faltante: $field"
            ]);
            exit();
        }
    }

    $imap_server = trim($_POST['imap_server']);
    $imap_port = intval($_POST['imap_port']);
    $imap_user = trim($_POST['imap_user']);
    $imap_password = trim($_POST['imap_password']);
    $server_id = isset($_POST['server_id']) ? intval($_POST['server_id']) : null;

    if ($imap_port < 1 || $imap_port > 65535) {
        echo json_encode([
            'success' => false, 
            'error' => 'Puerto IMAP inválido (debe estar entre 1 y 65535)'
        ]);
        exit();
    }

    if (!filter_var($imap_user, FILTER_VALIDATE_EMAIL)) {
        echo json_encode([
            'success' => false, 
            'error' => 'Formato de email inválido para el usuario IMAP'
        ]);
        exit();
    }

    // Si la contraseña es la máscara y tenemos un server_id, buscar la contraseña real en la BD
    if ($imap_password === '**********' && $server_id) {
        try {
            $temp_conn = new mysqli($db_host, $db_user, $db_password, $db_name);
            $temp_conn->set_charset("utf8mb4");
            
            if ($temp_conn->connect_error) {
                echo json_encode([
                    'success' => false, 
                    'error' => 'Error de conexión a la base de datos'
                ]);
                exit();
            }
            
            $stmt = $temp_conn->prepare("SELECT imap_password FROM email_servers WHERE id = ?");
            if (!$stmt) {
                echo json_encode([
                    'success' => false, 
                    'error' => 'Error preparando consulta: ' . $temp_conn->error
                ]);
                $temp_conn->close();
                exit();
            }
            
            $stmt->bind_param("i", $server_id);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($row = $result->fetch_assoc()) {
                $imap_password = $row['imap_password'];
                if (empty($imap_password)) {
                    $stmt->close();
                    $temp_conn->close();
                    echo json_encode([
                        'success' => false, 
                        'error' => 'Este servidor no tiene contraseña configurada. Por favor, configúrala primero.'
                    ]);
                    exit();
                }
            } else {
                $stmt->close();
                $temp_conn->close();
                echo json_encode([
                    'success' => false, 
                    'error' => 'Servidor no encontrado en la base de datos'
                ]);
                exit();
            }
            
            $stmt->close();
            $temp_conn->close();
            
        } catch (Exception $e) {
            echo json_encode([
                'success' => false, 
                'error' => 'Error al obtener contraseña del servidor: ' . $e->getMessage()
            ]);
            exit();
        }
    } elseif ($imap_password === '**********' && !$server_id) {
        echo json_encode([
            'success' => false, 
            'error' => 'Para probar un servidor ya configurado, guarda primero los cambios'
        ]);
        exit();
    }

    // Ejecutar la prueba de conexión híbrida
    $test_result = testImapConnectionHybrid($imap_server, $imap_port, $imap_user, $imap_password, $server_id);

    // Registrar intento en logs
    try {
        $log_conn = new mysqli($db_host, $db_user, $db_password, $db_name);
        $log_conn->set_charset("utf8mb4");
        
        if (!$log_conn->connect_error) {
            $log_stmt = $log_conn->prepare("INSERT INTO logs (user_id, email_consultado, plataforma, ip, resultado, fecha) VALUES (?, ?, ?, ?, ?, NOW())");
            if ($log_stmt) {
                $user_id = $_SESSION['user_id'] ?? 0;
                $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                $plataforma = "test_imap";
                $resultado = "Prueba de conexión IMAP a {$imap_server}:{$imap_port} - " . ($test_result['success'] ? 'ÉXITO' : 'ERROR');
                
                $log_stmt->bind_param("issss", $user_id, $imap_user, $plataforma, $ip, $resultado);
                $log_stmt->execute();
                $log_stmt->close();
            }
            $log_conn->close();
        }
    } catch (Exception $e) {
        error_log("Error logging IMAP test: " . $e->getMessage());
    }

    echo json_encode([
        'success' => $test_result['success'],
        'error' => $test_result['error'],
        'details' => $test_result['details'],
        'server_info' => [
            'server' => $imap_server,
            'port' => $imap_port,
            'user' => $imap_user
        ],
        'suggestion' => $test_result['suggestion'] ?? null
    ]);

} catch (Exception $e) {
    echo json_encode([
        'success' => false,
        'error' => 'Error interno del servidor: ' . $e->getMessage()
    ]);
} catch (Error $e) {
    echo json_encode([
        'success' => false,
        'error' => 'Error fatal de PHP: ' . $e->getMessage()
    ]);
}

/**
 * Función híbrida que detecta problemas DNS y sugiere soluciones
 */
function testImapConnectionHybrid($server, $port, $username, $password, $server_id = null) {
    $result = [
        'success' => false,
        'error' => '',
        'details' => []
    ];
    
    // Mapeo de servidores conocidos a IPs
    $server_ips = [
        'imap.gmail.com' => ['142.250.185.109', '142.250.185.108', '173.194.76.109'],
        'outlook.office365.com' => ['40.101.42.82', '40.101.15.82', '52.97.135.82'],
        'imap.mail.yahoo.com' => ['98.136.96.63', '98.136.176.63', '206.190.60.37'],
        'imap.aol.com' => ['205.188.106.23', '64.12.88.131']
    ];
    
    try {
        $result['details'][] = "🔍 Iniciando prueba de conexión a {$server}:{$port}";
        $result['details'][] = "👤 Usuario: {$username}";
        
        // PASO 1: Intentar conexión original
        $result['details'][] = "📡 PASO 1: Probando con configuración original ({$server})";
        
        $original_test = testSingleImapConnection($server, $port, $username, $password);
        
        if ($original_test['success']) {
            // ¡Funciona perfecto con la configuración original!
            $result['success'] = true;
            $result['details'] = array_merge($result['details'], $original_test['details']);
            $result['details'][] = "✅ ¡Conexión exitosa con configuración original!";
            return $result;
        }
        
        // PASO 2: Analizar el error
        $result['details'][] = "❌ Fallo con configuración original: " . $original_test['error'];
        
        $is_dns_error = strpos($original_test['error'], 'No such host') !== false ||
                       strpos($original_test['error'], 'Name or service not known') !== false ||
                       strpos($original_test['error'], 'hostname resolution failed') !== false;
        
        if (!$is_dns_error) {
            // Si no es error de DNS, devolver el error original
            $result['error'] = $original_test['error'];
            $result['details'] = array_merge($result['details'], $original_test['details']);
            return $result;
        }
        
        // PASO 3: Es error de DNS, intentar con IP
        $result['details'][] = "🔧 PASO 2: Error de DNS detectado, intentando con IP directa...";
        
        $suggested_ip = null;
        $server_lower = strtolower($server);
        
        if (isset($server_ips[$server_lower])) {
            $ips = $server_ips[$server_lower];
            $suggested_ip = $ips[0];
            $result['details'][] = "💡 IP sugerida para {$server}: {$suggested_ip}";
            $result['details'][] = "💡 IPs alternativas: " . implode(', ', array_slice($ips, 1));
        } else {
            // Intentar obtener IP via ping
            $ping_result = @exec("ping -c 1 {$server} 2>/dev/null | grep 'PING' | awk '{print $3}' | tr -d '()'");
            if ($ping_result && filter_var($ping_result, FILTER_VALIDATE_IP)) {
                $suggested_ip = $ping_result;
                $result['details'][] = "🎯 IP obtenida via ping: {$suggested_ip}";
            } else {
                $result['error'] = "No se pudo resolver DNS para {$server} y no hay IP alternativa conocida";
                $result['details'][] = "❌ No se pudo obtener IP alternativa";
                return $result;
            }
        }
        
        if (!$suggested_ip) {
            $result['error'] = $original_test['error'];
            $result['details'] = array_merge($result['details'], $original_test['details']);
            return $result;
        }
        
        // PASO 4: Probar con IP
        $result['details'][] = "🚀 Probando conexión con IP: {$suggested_ip}";
        
        $ip_test = testSingleImapConnection($suggested_ip, $port, $username, $password);
        
        if ($ip_test['success']) {
            // ¡Funciona con IP!
            $result['success'] = true;
            $result['details'] = array_merge($result['details'], $ip_test['details']);
            $result['details'][] = "🎉 ¡Conexión exitosa usando IP directa!";
            $result['details'][] = "💡 SOLUCIÓN: Tu servidor tiene problemas de DNS pero la conectividad funciona";
            
            // Agregar sugerencia para actualizar configuración
            $result['suggestion'] = [
                'type' => 'dns_fix',
                'message' => "Tu servidor no puede resolver DNS pero la conectividad IMAP funciona perfectamente. ¿Quieres actualizar la configuración para usar la IP directa?",
                'current_server' => $server,
                'suggested_ip' => $suggested_ip,
                'server_id' => $server_id,
                'action_text' => "Usar IP: {$suggested_ip}",
                'benefits' => [
                    "✅ Conexión más rápida (sin resolución DNS)",
                    "✅ Más estable (no depende de DNS externo)", 
                    "✅ Funciona inmediatamente",
                    "⚠️ Nota: La IP podría cambiar eventualmente"
                ]
            ];
            
            return $result;
        } else {
            // Tampoco funciona con IP
            $result['error'] = "No funciona ni con nombre ({$original_test['error']}) ni con IP ({$ip_test['error']})";
            $result['details'] = array_merge($result['details'], $ip_test['details']);
            $result['details'][] = "❌ Problema más profundo que DNS - revisar conectividad y credenciales";
            return $result;
        }
        
    } catch (Exception $e) {
        $result['error'] = "Excepción durante prueba híbrida: " . $e->getMessage();
        $result['details'][] = "❌ Error: " . $e->getMessage();
        return $result;
    }
}

/**
 * Función para probar una sola conexión IMAP
 */
function testSingleImapConnection($host, $port, $username, $password) {
    $result = [
        'success' => false,
        'error' => '',
        'details' => []
    ];
    
    try {
        $imap_server_string = "{{$host}:{$port}/imap/ssl/novalidate-cert}";
        $result['details'][] = "🔗 Conectando a: {$imap_server_string}";
        
        // Limpiar errores previos
        imap_errors();
        imap_alerts();
        
        $start_time = microtime(true);
        $connection = @imap_open($imap_server_string, $username, $password, OP_READONLY);
        $connection_time = round((microtime(true) - $start_time) * 1000, 2);
        
        if ($connection === false) {
            $imap_errors = imap_errors();
            $imap_alerts = imap_alerts();
            
            $error_message = "Error de conexión IMAP";
            if ($imap_errors) {
                $error_message .= ": " . implode(", ", $imap_errors);
            }
            
            $result['error'] = $error_message;
            $result['details'][] = "❌ Conexión fallida en {$connection_time}ms";
            return $result;
        }
        
        $result['details'][] = "✅ Conexión establecida en {$connection_time}ms";
        
        // Obtener información del buzón
        $mailbox_info = @imap_status($connection, $imap_server_string . "INBOX", SA_ALL);
        if ($mailbox_info) {
            $result['details'][] = "📊 Total de mensajes: " . ($mailbox_info->messages ?? 0);
            $result['details'][] = "📊 Mensajes recientes: " . ($mailbox_info->recent ?? 0);
            $result['details'][] = "📊 Mensajes no leídos: " . ($mailbox_info->unseen ?? 0);
        }
        
        @imap_close($connection);
        $result['success'] = true;
        
        return $result;
        
    } catch (Exception $e) {
        $result['error'] = "Excepción: " . $e->getMessage();
        $result['details'][] = "❌ Error: " . $e->getMessage();
        return $result;
    }
}
?>