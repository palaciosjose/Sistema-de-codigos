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

// Función de búsqueda ROBUSTA que maneja codificación UTF-8 y variaciones
function search_emails_optimized($inbox, $email, $asuntos_array, $time_limit_minutes = 100, $settings = null) {
    if (empty($asuntos_array)) {
        return false;
    }
    
    // Configuraciones con valores seguros por defecto
    $trust_imap_date = ($settings['TRUST_IMAP_DATE_FILTER'] ?? '1') === '1';
    $max_emails_check = (int)($settings['MAX_EMAILS_TO_CHECK'] ?? 50);
    $search_timeout = (int)($settings['IMAP_SEARCH_TIMEOUT'] ?? 30);
    $early_stop = ($settings['EARLY_SEARCH_STOP'] ?? '1') === '1';
    
    $start_time = microtime(true);
    log_performance("Iniciando búsqueda robusta para: $email", null, $settings);
    
    // MÉTODO HÍBRIDO: Combinar búsqueda básica + verificación manual
    try {
        // Configurar timeout
        $old_timeout = ini_get('default_socket_timeout');
        ini_set('default_socket_timeout', $search_timeout);
        
        // PASO 1: Buscar todos los emails del destinatario (más confiable)
        $basic_search = 'TO "' . $email . '"';
        
        // Añadir filtro de fecha si se confía en IMAP
        if ($trust_imap_date) {
            $time_limit_seconds = $time_limit_minutes * 60;
            $search_date = date("d-M-Y", time() - $time_limit_seconds);
            $basic_search .= ' SINCE "' . $search_date . '"';
        }
        
        log_performance("Ejecutando búsqueda IMAP: $basic_search", $start_time, $settings);
        
        $all_emails = imap_search($inbox, $basic_search);
        
        if (!$all_emails || empty($all_emails)) {
            log_performance("No se encontraron emails para el destinatario", $start_time, $settings);
            return false;
        }
        
        log_performance("Encontrados " . count($all_emails) . " emails del destinatario", $start_time, $settings);
        
        // PASO 2: Filtrar por asuntos usando verificación manual inteligente
        $found_emails = [];
        $emails_to_check = array_reverse($all_emails); // Más recientes primero
        $check_limit = min($max_emails_check, count($emails_to_check));
        
        // Crear patrones de búsqueda flexibles
        $search_patterns = [];
        foreach ($asuntos_array as $asunto) {
            if (empty(trim($asunto))) continue;
            
            // Patrón 1: Texto completo
            $search_patterns[] = trim($asunto);
            
            // Patrón 2: Palabras clave principales (para manejar codificación)
            $keywords = extract_key_words($asunto);
            if (!empty($keywords)) {
                $search_patterns = array_merge($search_patterns, $keywords);
            }
        }
        
        log_performance("Verificando asuntos en $check_limit emails con " . count($search_patterns) . " patrones", $start_time, $settings);
        
        for ($i = 0; $i < $check_limit; $i++) {
            $msg_num = $emails_to_check[$i];
            
            try {
                // Obtener header del email
                $header = imap_headerinfo($inbox, $msg_num);
                if (!$header || !isset($header->subject)) {
                    continue;
                }
                
                // Decodificar asunto si está codificado
                $decoded_subject = decode_mime_subject($header->subject);
                
                // Verificar coincidencias con patrones flexibles
                foreach ($search_patterns as $pattern) {
                    if (flexible_subject_match($decoded_subject, $pattern)) {
                        $found_emails[] = $msg_num;
                        log_performance("COINCIDENCIA: '$decoded_subject' con patrón '$pattern'", $start_time, $settings);
                        
                        if ($early_stop) {
                            break 2; // Salir de ambos bucles
                        } else {
                            break; // Solo salir del bucle de patrones
                        }
                    }
                }
                
                // Verificar límite de tiempo manual si no confiamos en IMAP
                if (!$trust_imap_date && isset($header->udate)) {
                    $time_limit_seconds = $time_limit_minutes * 60;
                    if (time() - $header->udate > $time_limit_seconds) {
                        continue; // Saltar emails muy antiguos
                    }
                }
                
            } catch (Exception $e) {
                log_performance("Error procesando email $msg_num: " . $e->getMessage(), $start_time, $settings);
                continue;
            }
        }
        
        log_performance("Búsqueda completada: " . count($found_emails) . " emails encontrados", $start_time, $settings);
        
        return !empty($found_emails) ? $found_emails : false;
        
    } catch (Exception $e) {
        log_performance("Error en búsqueda robusta: " . $e->getMessage(), $start_time, $settings);
        return false;
    } finally {
        // Restaurar timeout
        if (isset($old_timeout)) {
            ini_set('default_socket_timeout', $old_timeout);
        }
    }
}

// Función auxiliar para decodificar asuntos MIME
function decode_mime_subject($subject) {
    // Decodificar asuntos codificados como =?UTF-8?Q?...?=
    $decoded = imap_mime_header_decode($subject);
    
    $result = '';
    foreach ($decoded as $part) {
        $charset = isset($part->charset) ? $part->charset : 'utf-8';
        if (strtolower($charset) == 'default') {
            $result .= $part->text;
        } else {
            $result .= mb_convert_encoding($part->text, 'UTF-8', $charset);
        }
    }
    
    return trim($result);
}

// Función auxiliar para extraer palabras clave importantes
function extract_key_words($subject) {
    $keywords = [];
    
    // Palabras clave por tipo de servicio
    $key_patterns = [
        'código' => ['codigo', 'code', 'verification'],
        'Netflix' => ['Netflix'],
        'Disney' => ['Disney'],
        'Prime' => ['Prime', 'Amazon'],
        'inicio' => ['inicio', 'login', 'sign'],
        'sesión' => ['sesion', 'session'],
        'contraseña' => ['contraseña', 'password', 'restablec'],
        'temporal' => ['temporal', 'temporary'],
        'acceso' => ['acceso', 'access']
    ];
    
    $subject_lower = strtolower($subject);
    
    foreach ($key_patterns as $concept => $words) {
        foreach ($words as $word) {
            if (stripos($subject_lower, $word) !== false) {
                $keywords[] = $word;
            }
        }
    }
    
    // También incluir palabras de más de 4 caracteres del asunto original
    $words = preg_split('/\s+/', $subject);
    foreach ($words as $word) {
        $clean_word = preg_replace('/[^\w\s]/', '', $word);
        if (strlen($clean_word) > 4) {
            $keywords[] = $clean_word;
        }
    }
    
    return array_unique($keywords);
}

// Función auxiliar para coincidencia flexible de asuntos
function flexible_subject_match($decoded_subject, $pattern) {
    $subject_clean = strtolower(strip_tags($decoded_subject));
    $pattern_clean = strtolower(strip_tags($pattern));
    
    // Método 1: Coincidencia exacta
    if (stripos($subject_clean, $pattern_clean) !== false) {
        return true;
    }
    
    // Método 2: Coincidencia por palabras clave (70% de las palabras coinciden)
    $subject_words = preg_split('/\s+/', $subject_clean);
    $pattern_words = preg_split('/\s+/', $pattern_clean);
    
    if (count($pattern_words) > 1) {
        $matches = 0;
        foreach ($pattern_words as $word) {
            if (strlen($word) > 3) { // Solo palabras significativas
                foreach ($subject_words as $subject_word) {
                    if (stripos($subject_word, $word) !== false || stripos($word, $subject_word) !== false) {
                        $matches++;
                        break;
                    }
                }
            }
        }
        
        $match_ratio = $matches / count($pattern_words);
        if ($match_ratio >= 0.7) { // 70% de coincidencia
            return true;
        }
    }
    
    return false;
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
        
        // Intentar conexión con opciones optimizadas
        $inbox = imap_open(
            $mailbox,
            $server_config['imap_user'],
            $server_config['imap_password'],
            OP_READONLY | CL_EXPUNGE, // Flags optimizados
            1, // Máximo 1 reintento
            array(
                'DISABLE_AUTHENTICATOR' => 'GSSAPI',
                'timeout' => $connection_timeout // Timeout configurable
            )
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
                
                // VERSIÓN OPTIMIZADA CON FALLBACK AUTOMÁTICO
                $emails_found = search_emails_with_fallback($inbox, $email, $asuntos, $time_limit_minutes, $settings);
                
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

// *** FUNCIONES OPTIMIZADAS FALTANTES ***

// Función principal de búsqueda con fallback automático
function search_emails_with_fallback($inbox, $email, $asuntos_array, $time_limit_minutes = 100, $settings = null) {
    if (empty($asuntos_array)) {
        return false;
    }
    
    // Si no hay configuraciones, usar valores por defecto
    if ($settings === null) {
        $settings = [
            'TRUST_IMAP_DATE_FILTER' => '1',
            'USE_PRECISE_IMAP_SEARCH' => '1',
            'MAX_EMAILS_TO_CHECK' => '50',
            'IMAP_SEARCH_TIMEOUT' => '30',
            'EARLY_SEARCH_STOP' => '1',
            'PERFORMANCE_LOGGING' => '0'
        ];
    }
    
    try {
        // Intentar búsqueda optimizada primero
        $emails_found = search_emails_optimized_v2($inbox, $email, $asuntos_array, $time_limit_minutes, $settings);
        
        // Si falla o no encuentra nada, intentar búsqueda simple
        if ($emails_found === false || empty($emails_found)) {
            log_performance("Búsqueda optimizada falló, intentando búsqueda simple", null, $settings);
            $emails_found = search_emails_simple_fallback($inbox, $email, $asuntos_array, $time_limit_minutes, $settings);
        }
        
        return $emails_found;
        
    } catch (Exception $e) {
        error_log("Error en search_emails_with_fallback: " . $e->getMessage());
        
        // En caso de error, intentar método más simple
        try {
            return search_emails_simple_fallback($inbox, $email, $asuntos_array, $time_limit_minutes, $settings);
        } catch (Exception $e2) {
            error_log("Error en fallback simple: " . $e2->getMessage());
            return false;
        }
    }
}

// Función de búsqueda optimizada v2 (mejorada)
function search_emails_optimized_v2($inbox, $email, $asuntos_array, $time_limit_minutes = 100, $settings = null) {
    if (empty($asuntos_array)) {
        return false;
    }
    
    // Configuraciones por defecto
    $trust_imap_date = true;
    $max_emails_check = 50;
    $search_timeout = 30;
    
    if ($settings) {
        $trust_imap_date = ($settings['TRUST_IMAP_DATE_FILTER'] ?? '1') === '1';
        $max_emails_check = (int)($settings['MAX_EMAILS_TO_CHECK'] ?? 50);
        $search_timeout = (int)($settings['IMAP_SEARCH_TIMEOUT'] ?? 30);
    }
    
    // Calcular fecha límite
    $time_limit_seconds = $time_limit_minutes * 60;
    $search_date = date("d-M-Y", time() - $time_limit_seconds);
    
    // Construir búsqueda IMAP combinada
    $search_criteria = 'TO "' . $email . '" SINCE "' . $search_date . '" (';
    
    // Añadir todos los asuntos con OR
    $subject_criteria = [];
    foreach ($asuntos_array as $asunto) {
        if (!empty(trim($asunto))) {
            $escaped_subject = str_replace('"', '\"', trim($asunto));
            $subject_criteria[] = 'SUBJECT "' . $escaped_subject . '"';
        }
    }
    
    if (empty($subject_criteria)) {
        return false;
    }
    
    // Combinar con OR
    $search_criteria .= implode(' OR ', $subject_criteria) . ')';
    
    // Configurar timeout
    $old_timeout = ini_get('default_socket_timeout');
    ini_set('default_socket_timeout', $search_timeout);
    
    try {
        // Ejecutar búsqueda IMAP
        $emails = imap_search($inbox, $search_criteria);
        
        if ($emails === false || empty($emails)) {
            return false;
        }
        
        // Ordenar por más recientes
        rsort($emails);
        
        // Si confiamos en IMAP, devolver directamente
        if ($trust_imap_date) {
            $limited_emails = array_slice($emails, 0, $max_emails_check);
            return $limited_emails;
        }
        
        // Si no confiamos, verificar fechas en PHP
        $verified_emails = [];
        $checked_count = 0;
        $cutoff_time = time() - $time_limit_seconds;
        
        foreach ($emails as $msg_num) {
            if ($checked_count >= $max_emails_check) {
                break;
            }
            
            try {
                $header_info = imap_headerinfo($inbox, $msg_num);
                if ($header_info && isset($header_info->udate)) {
                    if ($header_info->udate >= $cutoff_time) {
                        $verified_emails[] = $msg_num;
                        
                        // Early stop si está habilitado
                        if (($settings['EARLY_SEARCH_STOP'] ?? '1') === '1') {
                            break;
                        }
                    }
                }
            } catch (Exception $e) {
                continue;
            }
            
            $checked_count++;
        }
        
        return !empty($verified_emails) ? $verified_emails : false;
        
    } catch (Exception $e) {
        error_log("Error en búsqueda optimizada v2: " . $e->getMessage());
        return false;
    } finally {
        ini_set('default_socket_timeout', $old_timeout);
    }
}

// Función de búsqueda simple y confiable
function search_emails_simple_fallback($inbox, $email, $asuntos_array, $time_limit_minutes = 100, $settings = null) {
    if (empty($asuntos_array)) {
        return false;
    }
    
    $max_emails = 50;
    if ($settings && isset($settings['MAX_EMAILS_TO_CHECK'])) {
        $max_emails = (int)$settings['MAX_EMAILS_TO_CHECK'];
    }
    
    $found_emails = [];
    
    // Buscar cada asunto por separado (método más compatible)
    foreach ($asuntos_array as $asunto) {
        if (empty(trim($asunto))) continue;
        
        try {
            // Búsqueda simple por destinatario
            $simple_criteria = 'TO "' . $email . '"';
            $all_emails = imap_search($inbox, $simple_criteria);
            
            if ($all_emails && !empty($all_emails)) {
                // Ordenar por más recientes
                rsort($all_emails);
                
                // Verificar asuntos manualmente en los más recientes
                $check_count = 0;
                foreach ($all_emails as $msg_num) {
                    if ($check_count >= 20) break; // Limitar para velocidad
                    
                    try {
                        $header = imap_headerinfo($inbox, $msg_num);
                        if ($header && isset($header->subject)) {
                            // Verificar si el asunto contiene el texto buscado
                            if (stripos($header->subject, trim($asunto)) !== false) {
                                $found_emails[] = $msg_num;
                                break; // Encontramos uno, pasar al siguiente asunto
                            }
                        }
                    } catch (Exception $e) {
                        continue;
                    }
                    $check_count++;
                }
            }
        } catch (Exception $e) {
            error_log("Error en búsqueda simple de asunto '$asunto': " . $e->getMessage());
            continue;
        }
    }
    
    return !empty($found_emails) ? $found_emails : false;
}

// FUNCIÓN TEMPORAL - Búsqueda simple y confiable (última opción)
function search_email_simple_reliable($inbox, $email, $asuntos_array) {
    if (empty($asuntos_array)) {
        return false;
    }
    
    $found_emails = [];
    
    // Método simple pero confiable
    foreach ($asuntos_array as $asunto) {
        if (empty(trim($asunto))) continue;
        
        try {
            // Búsqueda básica por destinatario
            $basic_search = 'TO "' . $email . '"';
            $all_emails = imap_search($inbox, $basic_search);
            
            if ($all_emails && !empty($all_emails)) {
                // Ordenar por más recientes
                rsort($all_emails);
                
                // Verificar asuntos manualmente en los 20 más recientes
                $check_count = 0;
                foreach ($all_emails as $msg_num) {
                    if ($check_count >= 20) break; // Limitar para velocidad
                    
                    try {
                        $header = imap_headerinfo($inbox, $msg_num);
                        if ($header && isset($header->subject)) {
                            // Verificar si el asunto contiene el texto buscado
                            if (stripos($header->subject, trim($asunto)) !== false) {
                                $found_emails[] = $msg_num;
                                break; // Encontramos uno, pasar al siguiente asunto
                            }
                        }
                    } catch (Exception $e) {
                        // Continuar si hay error con este email
                        continue;
                    }
                    $check_count++;
                }
            }
        } catch (Exception $e) {
            error_log("Error en búsqueda simple: " . $e->getMessage());
            continue;
        }
    }
    
    return !empty($found_emails) ? $found_emails : false;
}


// FUNCIÓN DE TEST para verificar que la búsqueda robusta funciona
function test_robust_search_with_real_data($inbox, $email, $settings = null) {
    echo "<h3>🧪 TEST de Búsqueda Robusta</h3>";
    
    // Asuntos de Netflix configurados
    $netflix_subjects = [
        'Completa tu solicitud de restablecimiento de contraseña',
        'Importante: Cómo actualizar tu Hogar con Netflix', 
        'Netflix: Tu código de inicio de sesión',
        'Tu código de acceso temporal de Netflix'
    ];
    
    // Asuntos reales encontrados en el diagnóstico
    $real_subjects = [
        '=?UTF-8?Q?Netflix:_Tu_c=C3=B3digo_de_inicio_de_sesi=C3=B3n?=',
        '=?UTF-8?Q?Completa_tu_solicitud_de_restablecimiento_de_contrase=C3=B1a?='
    ];
    
    echo "<h4>📝 Test de decodificación:</h4>";
    foreach ($real_subjects as $coded_subject) {
        $decoded = decode_mime_subject($coded_subject);
        echo "<p><strong>Codificado:</strong> " . htmlspecialchars($coded_subject) . "</p>";
        echo "<p><strong>Decodificado:</strong> " . htmlspecialchars($decoded) . "</p>";
        
        // Test de coincidencia
        foreach ($netflix_subjects as $search_pattern) {
            if (flexible_subject_match($decoded, $search_pattern)) {
                echo "<p class='success'>✅ COINCIDE con patrón: " . htmlspecialchars($search_pattern) . "</p>";
            }
        }
        echo "<hr>";
    }
    
    echo "<h4>🔍 Test de búsqueda robusta:</h4>";
    $start_time = microtime(true);
    $results = search_emails_optimized($inbox, $email, $netflix_subjects, 100, $settings);
    $time_taken = round((microtime(true) - $start_time) * 1000, 2);
    
    if ($results && !empty($results)) {
        echo "<p class='success'>✅ ÉXITO: Encontrados " . count($results) . " emails</p>";
        echo "<p>📧 IDs: " . implode(", ", $results) . "</p>";
    } else {
        echo "<p class='error'>❌ No encontró emails</p>";
    }
    echo "<p>⏱️ Tiempo: {$time_taken}ms</p>";
    
    return $results;
}

?>
