<?php
// Inicia una sesión para almacenar datos temporales
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Incluye el archivo de configuración para acceder a las constantes y funciones necesarias
require_once 'config/config.php';
// Incluye el archivo encargado de decodificar correos
require_once 'decodificador.php';
require_once 'instalacion/basededatos.php';
// Incluir sistema de cache
require_once 'cache/cache_helper.php';

// Función para escapar caracteres especiales y prevenir ataques XSS
function escape_string($string) {
    return htmlspecialchars($string, ENT_QUOTES, 'UTF-8');
}

// Función para validar el correo electrónico ingresado
function validate_email($email) {
    // Verifica si el correo está vacío o es inválido
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return 'El correo electrónico proporcionado es inválido o está vacío.';
    }
    // Verifica que el correo no exceda los 50 caracteres
    if (strlen($email) > 50) {
        return 'El correo electrónico no debe superar los 50 caracteres.';
    }
    return ''; // Retorna vacío si el correo es válido
}

// Función optimizada para verificar si el correo está autorizado (USA CACHE)
function is_authorized_email($email, $conn) {
    // Usar función optimizada que usa cache
    $email_auth_enabled = is_setting_enabled('EMAIL_AUTH_ENABLED', $conn, false);

    // Si el filtro está desactivado, permitir el correo
    if (!$email_auth_enabled) {
        return true;
    }

    // Si el filtro está activado, consultar la tabla authorized_emails
    // NOTA: Esta consulta SÍ necesita ser en tiempo real por seguridad
    $stmt = $conn->prepare("SELECT COUNT(*) FROM authorized_emails WHERE email = ?");
    if (!$stmt) {
        error_log("Error al preparar consulta para authorized_emails: " . $conn->error);
        return false; // Por seguridad, denegar si hay error
    }
    
    $count = 0;
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->bind_result($count);
    $stmt->fetch();
    $stmt->close();

    return $count > 0;
}

// Función optimizada para buscar correos SIN doble filtrado de tiempo
function search_emails_optimized($inbox, $email, $asuntos_array, $time_limit_minutes = 100, $settings = null) {
    if (empty($asuntos_array)) {
        return false;
    }
    
    // Obtener configuraciones de filtrado
    $trust_imap_date = ($settings['TRUST_IMAP_DATE_FILTER'] ?? '1') === '1';
    $use_precise_search = ($settings['USE_PRECISE_IMAP_SEARCH'] ?? '1') === '1';
    $max_emails_check = (int)($settings['MAX_EMAILS_TO_CHECK'] ?? 50);
    
    // Calcular fecha límite de forma más precisa
    $time_limit_seconds = $time_limit_minutes * 60;
    $current_time = time();
    $cutoff_time = $current_time - $time_limit_seconds;
    
    // Formato de fecha para IMAP (más preciso)
    if ($use_precise_search) {
        // Usar fecha y hora específica para mayor precisión
        $search_date = date("d-M-Y H:i:s", $cutoff_time);
        $since_criteria = 'SINCE "' . date("d-M-Y", $cutoff_time) . '"';
    } else {
        // Usar solo fecha (método original, más compatible)
        $search_date = date("d-M-Y", $cutoff_time);
        $since_criteria = 'SINCE "' . $search_date . '"';
    }
    
    // Construir búsqueda IMAP optimizada
    $search_criteria = 'TO "' . $email . '" ' . $since_criteria . ' (';
    
    // Añadir todos los asuntos con OR
    $subject_criteria = [];
    foreach ($asuntos_array as $asunto) {
        if (!empty(trim($asunto))) {
            // Escapar caracteres especiales en asuntos para IMAP
            $escaped_subject = str_replace('"', '\"', trim($asunto));
            $subject_criteria[] = 'SUBJECT "' . $escaped_subject . '"';
        }
    }
    
    if (empty($subject_criteria)) {
        return false;
    }
    
    // Combinar con OR para buscar cualquier asunto
    $search_criteria .= implode(' OR ', $subject_criteria) . ')';
    
    // Log de performance si está habilitado
    $start_time = microtime(true);
    log_performance("Iniciando búsqueda IMAP optimizada: " . $search_criteria, null, $settings);
    
    // Configurar timeout para la búsqueda IMAP
    $search_timeout = (int)($settings['IMAP_SEARCH_TIMEOUT'] ?? 30);
    $old_timeout = ini_get('default_socket_timeout');
    ini_set('default_socket_timeout', $search_timeout);
    
    // Ejecutar búsqueda IMAP con manejo de errores mejorado
    $emails = false;
    $search_error = '';
    
    try {
        // Deshabilitar reportes de error temporalmente
        $old_error_reporting = error_reporting(0);
        
        $emails = imap_search($inbox, $search_criteria);
        
        // Restaurar reporte de errores
        error_reporting($old_error_reporting);
        
        // Verificar errores IMAP
        $imap_errors = imap_errors();
        if ($imap_errors) {
            $search_error = 'Errores IMAP: ' . implode('; ', $imap_errors);
            error_log("Errores en búsqueda IMAP optimizada: " . $search_error);
        }
        
    } catch (Exception $e) {
        error_reporting($old_error_reporting);
        $search_error = 'Excepción en búsqueda IMAP: ' . $e->getMessage();
        error_log($search_error);
        $emails = false;
    } finally {
        // Restaurar timeout original
        ini_set('default_socket_timeout', $old_timeout);
    }


// Función optimizada para abrir conexión IMAP con timeouts configurables
function open_imap_connection_optimized($server_config, $settings = null) {
    // Verificar configuración
    if (empty($server_config['imap_server']) || empty($server_config['imap_port']) || 
        empty($server_config['imap_user']) || empty($server_config['imap_password'])) {
        error_log("Configuración IMAP incompleta para servidor ID: " . ($server_config['id'] ?? 'Desconocido'));
        return false;
    }
    
    // Obtener timeout desde configuración o usar valor por defecto
    $connection_timeout = 10; // valor por defecto
    if ($settings && isset($settings['IMAP_CONNECTION_TIMEOUT'])) {
        $connection_timeout = (int)$settings['IMAP_CONNECTION_TIMEOUT'];
        // Validar rango razonable
        if ($connection_timeout < 5 || $connection_timeout > 60) {
            $connection_timeout = 10;
        }
    }
    
    // Configurar timeouts optimizados para conexiones más rápidas
    $old_default_socket_timeout = ini_get('default_socket_timeout');
    ini_set('default_socket_timeout', $connection_timeout);
    
    // Deshabilitar reportes de error para manejo propio
    $old_error_reporting = error_reporting(0);
    
    try {
        // Construir cadena de conexión optimizada
        $mailbox = '{' . $server_config['imap_server'] . ':' . $server_config['imap_port'] . '/imap/ssl/novalidate-cert}INBOX';
        
        // Intentar conexión con opciones optimizadas y mejor manejo de fechas
        $connection_options = array(
            'DISABLE_AUTHENTICATOR' => 'GSSAPI',
            'timeout' => $connection_timeout
        );

        // Añadir opciones específicas para mejor búsqueda de fechas
        if ($settings && ($settings['USE_PRECISE_IMAP_SEARCH'] ?? '1') === '1') {
            $connection_options['IMAP.ENABLE-QRESYNC'] = 1;
        }

            $inbox = imap_open(
            $mailbox,
            $server_config['imap_user'],
            $server_config['imap_password'],
            OP_READONLY | CL_EXPUNGE, // Flags optimizados
            1, // Máximo 1 reintento
            $connection_options
    );
        
        // Restaurar configuraciones
        error_reporting($old_error_reporting);
        ini_set('default_socket_timeout', $old_default_socket_timeout);
        
        if ($inbox === false) {
            $errors = imap_errors();
            $last_error = $errors ? end($errors) : 'Error de conexión desconocido';
            error_log("Error IMAP optimizado - " . $server_config['imap_server'] . ": " . $last_error);
            return false;
        }
        
        return $inbox;
        
    } catch (Exception $e) {
        // Restaurar configuraciones en caso de excepción
        error_reporting($old_error_reporting);
        ini_set('default_socket_timeout', $old_default_socket_timeout);
        
        error_log("Excepción en conexión IMAP optimizada: " . $e->getMessage());
        return false;
    }
}

// Función para cerrar la conexión al servidor de correo
function close_imap_connection() {
    global $inbox; // Accede a la variable $inbox
    if ($inbox) { // Comprueba si hay una conexión abierta
        imap_close($inbox); // Cierra la conexión
    }
}

// Función optimizada que usa cache para obtener configuraciones
function get_all_settings($conn) {
    // Usar el sistema de cache en lugar de consulta directa
    return SimpleCache::get_settings($conn);
}

// NUEVA: Función para obtener plataformas y asuntos con cache
function get_platform_subjects_cached($conn) {
    return SimpleCache::get_platform_subjects($conn);
}

// NUEVA: Función para verificar si una configuración específica está habilitada (con cache)
function is_setting_enabled($setting_name, $conn, $default = false) {
    $settings = SimpleCache::get_settings($conn);
    $value = $settings[$setting_name] ?? ($default ? '1' : '0');
    return $value === '1';
}

// NUEVA: Función para obtener una configuración específica (con cache)
function get_setting_value($setting_name, $conn, $default = '') {
    $settings = SimpleCache::get_settings($conn);
    return $settings[$setting_name] ?? $default;
}

// Busca correos en TODOS los servidores IMAP habilitados
if (isset($_POST['email']) && isset($_POST['plataforma'])) {
    $conn = new mysqli($db_host, $db_user, $db_password, $db_name);
    // Establecer correctamente la codificación UTF-8
    $conn->set_charset("utf8mb4");
    
    if ($conn->connect_error) {
        die("Error de conexión a la base de datos: " . $conn->connect_error);
    }

    // Cargar settings desde cache (OPTIMIZADO)
    $settings = SimpleCache::get_settings($conn);
    
    // Cargar plataformas y asuntos desde cache (OPTIMIZADO)
    $platforms_cache = SimpleCache::get_platform_subjects($conn);

    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $plataforma = $_POST['plataforma'];
    $user_id = isset($_POST['user_id']) ? (int)$_POST['user_id'] : null; // Capturar user_id si está disponible
    $ip = $_SERVER['REMOTE_ADDR']; // Capturar IP del usuario
    
    // Establecer variable para guardar el resultado
    $resultado_consulta = '';
    $found = false; // Inicializar $found aquí
    
    // Código para registrar la consulta en el log
    function registrarLog($conn, $user_id, $email, $plataforma, $ip, $resultado) {
        $stmt = $conn->prepare("INSERT INTO logs (user_id, email_consultado, plataforma, ip, resultado) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("issss", $user_id, $email, $plataforma, $ip, $resultado);
        $stmt->execute();
        $stmt->close();
    }

    $resultado_validacion_formato = validate_email($email);

    // 1. Validar formato del correo
    if ($resultado_validacion_formato !== '') {
        $_SESSION['error_message'] = '<div class="alert alert-danger text-center" role="alert">' . htmlspecialchars($resultado_validacion_formato) . '</div>';
        $log_result_status = "Error Formato";
        $log_detail = $resultado_validacion_formato;
        registrarLog($conn, $user_id, $email, $plataforma, $ip, $log_result_status . ": " . substr(strip_tags($log_detail), 0, 200));
        header('Location: inicio.php');
        exit();
    }
    
    // 2. Verificar autorización si el formato es válido
    if (!is_authorized_email($email, $conn)) {
        // El filtro está activado y el correo no está autorizado
        $_SESSION['error_message'] = '<div class="alert alert-danger text-center" role="alert">No tiene permisos para consultar este correo electrónico.</div>';
        $log_result_status = "Acceso Denegado";
        $log_detail = "Correo no autorizado: " . $email;
        registrarLog($conn, $user_id, $email, $plataforma, $ip, $log_result_status . ": " . substr(strip_tags($log_detail), 0, 200));
        header('Location: inicio.php');
        exit();
    }

    // 3. Si el formato es válido y está autorizado (o el filtro desactivado), proceder con la búsqueda
    $servers_array = SimpleCache::get_enabled_servers($conn);
    $servers_found = !empty($servers_array);
    
    // Variables para manejo de errores y estado de búsqueda
    $error_messages = []; 
    $config_error_only = true; 
    $real_connection_error_occurred = false; 

    if ($servers_found) {
        // OPTIMIZADO: Obtener asuntos UNA SOLA VEZ antes del bucle
        $platform_name_from_user = $plataforma;
        $asuntos = [];
        
        if (isset($platforms_cache[$platform_name_from_user])) {
            $asuntos = $platforms_cache[$platform_name_from_user];
        } else {
            error_log("La plataforma '" . htmlspecialchars($platform_name_from_user) . "' no se encontró en cache.");
        }
        
        // Si no hay asuntos, no tiene sentido buscar
        if (empty($asuntos)) {
            $_SESSION['resultado'] = '<div class="alert alert-warning text-center" role="alert">
                No se encontraron asuntos configurados para la plataforma seleccionada.
            </div>';
            registrarLog($conn, $user_id, $email, $plataforma, $ip, "Sin Asuntos: Plataforma sin configurar");
            header('Location: inicio.php');
            exit();
        }
        
        // Obtener configuraciones de performance
        $time_limit_minutes = (int)($settings['EMAIL_QUERY_TIME_LIMIT_MINUTES'] ?? 100);
        $early_stop_enabled = ($settings['EARLY_SEARCH_STOP'] ?? '1') === '1';
        $optimization_enabled = ($settings['IMAP_SEARCH_OPTIMIZATION'] ?? '1') === '1';
        
        // Log de performance del inicio
        $search_start_time = microtime(true);
        log_performance("Iniciando búsqueda optimizada para: $email en $platform_name_from_user", null, $settings);
        
        foreach ($servers_array as $srv) {
            unset($_SESSION['error_message']); 
            
            // OPTIMIZADO: Usar nueva función de conexión con configuraciones
            $inbox = open_imap_connection_optimized($srv, $settings);

            if ($inbox !== false) {
                $config_error_only = false; // Hubo al menos una conexión exitosa
                
                // OPTIMIZADO: Buscar según configuración
                if ($optimization_enabled) {
                    // Usar búsqueda con fallback automático (OPTIMIZADO v2)
                    $emails_found = search_emails_with_fallback($inbox, $email, $asuntos, $time_limit_minutes, $settings);
                } else {
                    // Usar búsqueda tradicional (compatibilidad)
                    $emails_found = false;
                    foreach ($asuntos as $asunto) {
                        if (empty(trim($asunto))) continue;
                        // Usar búsqueda con fallback para modo compatibilidad
                        $emails_found = search_emails_with_fallback($inbox, $email, [$asunto], $time_limit_minutes, $settings);
                        if ($emails_found && !empty($emails_found)) {
                            break; // Parar en el primer asunto encontrado
                        }
                    }
                }
                
                if ($emails_found && !empty($emails_found)) {
                    // Obtener el email más reciente
                    $latest_email_id = max($emails_found); 
                    $email_data = imap_fetch_overview($inbox, $latest_email_id, 0);

                    if (!empty($email_data)) {
                        $header = $email_data[0];
                        $body = get_email_body($inbox, $latest_email_id, $header);
                        
                        if (!empty($body)) {
                            $processed_body = process_email_body($body);
                            $resultado = $processed_body;
                            $found = true;
                            
                            // Log de éxito
                            log_performance("Búsqueda exitosa en servidor: " . $srv['server_name'], $search_start_time, $settings);
                            
                            // Cerrar conexión y salir inmediatamente
                            imap_close($inbox);
                            
                            // Verificar si debe parar temprano
                            if ($early_stop_enabled) {
                                break; // Salir del bucle de servidores
                            }
                        }
                    }
                }
                
                // Cerrar conexión después de buscar en este servidor
                imap_close($inbox);
                
            } else { // $inbox es false
                // Error de conexión - mantener lógica de manejo de errores existente
                $config_error_only = false;
                $real_connection_error_occurred = true;
                $error_messages[] = "Error conectando a " . $srv['server_name'] . ": Error de conexión optimizada";
                // Continuar al siguiente servidor
            }
        } // Fin while servidores
        
        // Log final de performance
        log_performance("Búsqueda completa finalizada", $search_start_time, $settings);
        
        // Limpiar mensaje de error si se encontró resultado o no hubo errores reales
        if ($found || !$real_connection_error_occurred) {
            unset($_SESSION['error_message']);
        }

        // Establecer mensaje final basado en resultados
        if (!$found) {
            if ($real_connection_error_occurred) {
                $_SESSION['error_message'] = '<div class="alert alert-danger text-center" role="alert">
                    Error de conexión con los servidores de correo. Inténtalo de nuevo en unos momentos.
                </div>';
                $error_log = implode("; ", $error_messages);
                error_log("Errores de búsqueda IMAP optimizada: " . $error_log);
                unset($_SESSION['resultado']);
            } else if (!empty($error_messages)) { 
                $_SESSION['resultado'] = '<div class="alert alert-info text-center" role="alert">
                    0 mensajes encontrados (problema de configuración del servidor).
                </div>';
                error_log("Búsqueda optimizada finalizada sin encontrar correo. Errores de configuración: " . implode("; ", $error_messages));
                unset($_SESSION['error_message']); 
            } else {
                $_SESSION['resultado'] = '<div class="alert alert-success alert-light text-center" style="background-color: #d1e7dd; color: #0f5132;" role="alert">
                    0 mensajes encontrados.
                </div>'; 
                unset($_SESSION['error_message']);
            }
        } else {
            // Correo encontrado
            $_SESSION['resultado'] = $resultado;
            unset($_SESSION['error_message']);
        }
    } else {
        // No hay servidores habilitados
        $_SESSION['error_message'] = '<div class="alert alert-danger text-center" role="alert">
            No hay servidores IMAP habilitados. Por favor, configure al menos un servidor en el panel de administración.
        </div>';
        unset($_SESSION['resultado']); // Asegurar que no haya resultado
    }
    
    // Registrar la consulta en el log (esto se alcanza solo si la autorización pasó)
    $log_result_status = $found ? "Éxito" : ($real_connection_error_occurred ? "Error Conexión" : (!empty($error_messages) ? "Error Config" : "No Encontrado"));
    // Para el detalle, priorizar el mensaje de error si existe, si no, el de resultado
    $log_detail = $_SESSION['error_message'] ?? $_SESSION['resultado'] ?? "Estado desconocido";
    if ($found) {
        $log_detail = "[Cuerpo Omitido]"; // No loguear cuerpos exitosos
    }
     
    registrarLog($conn, $user_id, $email, $plataforma, $ip, $log_result_status . ": " . substr(strip_tags($log_detail), 0, 200)); 
    
    header('Location: inicio.php'); // Redirecciona a la página de inicio
    exit();
}

// Función para verificar si el sistema está instalado
function is_installed() {
    global $db_host, $db_user, $db_password, $db_name;
    
    // Si no existen las variables de conexión, el sistema no está instalado
    if (empty($db_host) || empty($db_user) || empty($db_name)) {
        return false;
    }
        
    // Intentar conectar a la base de datos
    $conn = new mysqli($db_host, $db_user, $db_password, $db_name);
    $conn->set_charset("utf8mb4"); // Establecer UTF-8 para la conexión
    
    if ($conn->connect_error) {
        return false;
    }
            
    // Verificar si la tabla settings existe y si el valor de INSTALLED es 1
    $result = $conn->query("SELECT value FROM settings WHERE name = 'INSTALLED'");
            
    if (!$result || $result->num_rows === 0) {
        $conn->close();
        return false;
    }
    
    $row = $result->fetch_assoc();
    $installed = $row['value'] === '1';
    
    $conn->close();
    return $installed;
}

// FUNCIONES DE COMPATIBILIDAD Y FALLBACK

// Mantener función original como fallback
function search_email($inbox, $email, $asunto) {
    // Usar la nueva función optimizada con un solo asunto
    return search_emails_optimized($inbox, $email, [$asunto]);
}

// Función de conexión original como fallback
function open_imap_connection($server_config) {
    global $inbox;
    // Usar configuraciones globales si están disponibles
    global $settings;
    $inbox = open_imap_connection_optimized($server_config, $settings ?? null);
    return $inbox !== false;
}

// Función para estadísticas de rendimiento (configurable)
function log_performance($message, $start_time = null, $settings = null) {
    // Verificar si está habilitado
    $logging_enabled = false;
    if ($settings && isset($settings['PERFORMANCE_LOGGING'])) {
        $logging_enabled = $settings['PERFORMANCE_LOGGING'] === '1';
    }
    
    if (!$logging_enabled) {
        return; // No hacer nada si está deshabilitado
    }
    
    if ($start_time) {
        $execution_time = microtime(true) - $start_time;
        error_log("PERFORMANCE: $message - Tiempo: " . round($execution_time, 3) . "s");
    } else {
        error_log("PERFORMANCE: $message");
    }
}

// Función para diagnosticar performance del filtrado de tiempo
function diagnose_time_filtering_performance($conn) {
    $settings = SimpleCache::get_settings($conn);
    $diagnostics = [];
    
    // Verificar configuraciones de performance
    $diagnostics['trust_imap_date'] = ($settings['TRUST_IMAP_DATE_FILTER'] ?? '1') === '1';
    $diagnostics['use_precise_search'] = ($settings['USE_PRECISE_IMAP_SEARCH'] ?? '1') === '1';
    $diagnostics['max_emails_check'] = (int)($settings['MAX_EMAILS_TO_CHECK'] ?? 50);
    $diagnostics['search_timeout'] = (int)($settings['IMAP_SEARCH_TIMEOUT'] ?? 30);
    
    // Calcular eficiencia estimada
    $efficiency_score = 0;
    if ($diagnostics['trust_imap_date']) $efficiency_score += 40; // Mayor impacto
    if ($diagnostics['use_precise_search']) $efficiency_score += 20;
    if ($diagnostics['max_emails_check'] <= 50) $efficiency_score += 20;
    if ($diagnostics['search_timeout'] <= 30) $efficiency_score += 20;
    
    $diagnostics['efficiency_score'] = $efficiency_score;
    $diagnostics['efficiency_level'] = $efficiency_score >= 80 ? 'Óptimo' : 
                                     ($efficiency_score >= 60 ? 'Bueno' : 
                                     ($efficiency_score >= 40 ? 'Regular' : 'Necesita mejoras'));
    
    // Recomendaciones
    $recommendations = [];
    if (!$diagnostics['trust_imap_date']) {
        $recommendations[] = 'Activar "Confiar en filtrado IMAP" para mayor velocidad';
    }
    if ($diagnostics['max_emails_check'] > 100) {
        $recommendations[] = 'Reducir "Máximo emails a verificar" a 50 o menos';
    }
    if ($diagnostics['search_timeout'] > 45) {
        $recommendations[] = 'Reducir timeout de búsqueda a 30 segundos o menos';
    }
    
    $diagnostics['recommendations'] = $recommendations;
    
    return $diagnostics;
}

// Función para test de velocidad del filtrado
function test_time_filtering_speed($conn, $test_email = 'test@test.com', $test_platform = 'Netflix') {
    $settings = SimpleCache::get_settings($conn);
    $platforms_cache = SimpleCache::get_platform_subjects($conn);
    
    if (!isset($platforms_cache[$test_platform])) {
        return ['error' => 'Plataforma de prueba no encontrada'];
    }
    
    $asuntos = $platforms_cache[$test_platform];
    $servers_array = SimpleCache::get_enabled_servers($conn);
    
    if (empty($servers_array)) {
        return ['error' => 'No hay servidores IMAP habilitados'];
    }
    
    $test_results = [];
    $total_start_time = microtime(true);
    
    foreach ($servers_array as $srv) {
        $server_start_time = microtime(true);
        
        // Probar conexión
        $inbox = open_imap_connection_optimized($srv, $settings);
        if ($inbox !== false) {
            // Probar búsqueda (pero no procesar resultados reales)
            try {
                $search_start_time = microtime(true);
                $emails_found = search_emails_with_fallback($inbox, $test_email, $asuntos, 100, $settings);
                $search_time = microtime(true) - $search_start_time;
                
                $test_results[$srv['server_name']] = [
                    'connection_time' => round((microtime(true) - $server_start_time) * 1000, 2),
                    'search_time' => round($search_time * 1000, 2),
                    'total_time' => round((microtime(true) - $server_start_time) * 1000, 2),
                    'emails_found' => is_array($emails_found) ? count($emails_found) : 0,
                    'status' => 'success'
                ];
                
                imap_close($inbox);
            } catch (Exception $e) {
                $test_results[$srv['server_name']] = [
                    'error' => $e->getMessage(),
                    'status' => 'error'
                ];
            }
        } else {
            $test_results[$srv['server_name']] = [
                'error' => 'No se pudo conectar',
                'status' => 'connection_failed'
            ];
        }
    }
    
    $total_time = microtime(true) - $total_start_time;
    
    return [
        'total_time_ms' => round($total_time * 1000, 2),
        'server_results' => $test_results,
        'efficiency_data' => diagnose_time_filtering_performance($conn)
    ];
}

?>