<?php
/**
 * Instalador del Sistema con Verificación de Licencia 
 * Versión 2.1 - 
 */

session_start();

// ==========================================
// DEFINIR RUTAS BASE CORRECTAS
// ==========================================
// Definir que estamos en modo instalador para evitar la verificación de licencia
define('INSTALLER_MODE', true);

// **SOLUCIÓN AL PROBLEMA DE RUTAS**
define('PROJECT_ROOT', dirname(__DIR__)); // Definir la ruta base del proyecto

define('LICENSE_DIR', PROJECT_ROOT . '/license');
define('LICENSE_FILE', LICENSE_DIR . '/license.dat');

if (!file_exists(LICENSE_DIR)) {
    if (!mkdir(LICENSE_DIR, 0755, true)) {
        die('Error: No se pudo crear el directorio de licencias: ' . LICENSE_DIR);
    }
}

$license_htaccess_content = "Deny from all\n<Files \"*.dat\">\nDeny from all\n</Files>";
file_put_contents(LICENSE_DIR . '/.htaccess', $license_htaccess_content);

require_once PROJECT_ROOT . '/license_client.php';

// Verificar si la base de datos ya está configurada
require_once 'basededatos.php';
require_once '../funciones.php';

header('Content-Type: text/html; charset=utf-8');

$required_extensions = [
    'session' => 'Para manejar sesiones.',
    'imap' => 'Para conectarse y manejar correos a través de IMAP.',
    'mbstring' => 'Para manejar cadenas multibyte.',
    'fileinfo' => 'Para manejar la detección de tipos MIME.',
    'json' => 'Para manejar datos en formato JSON.',
    'openssl' => 'Para manejar conexiones seguras y cifrado.',
    'filter' => 'Para la sanitización y validación de datos.',
    'ctype' => 'Para la verificación de tipos de caracteres.',
    'iconv' => 'Para la conversión de conjuntos de caracteres.',
    'curl' => 'Para realizar peticiones HTTP (requerido para verificación de licencia).'
];

$php_version_required = '8.2.0';
$php_version = phpversion();
$extensions_status = [];

foreach ($required_extensions as $ext => $description) {
    $extensions_status[$ext] = extension_loaded($ext);
}

$all_extensions_loaded = !in_array(false, $extensions_status, true);
$php_version_valid = version_compare($php_version, $php_version_required, '>=');

$current_step = $_GET['step'] ?? 'requirements';
$license_client = new ClientLicense();

function verificarSistemaLicencias() {
    $diagnostico = [
        'license_dir_exists' => file_exists(LICENSE_DIR),
        'license_dir_writable' => is_writable(dirname(LICENSE_DIR)),
        'license_file_path' => LICENSE_FILE,
        'project_root' => PROJECT_ROOT,
        'current_working_dir' => getcwd(),
        'installer_dir' => __DIR__
    ];
    
    return $diagnostico;  
}    

$diagnostico_licencias = verificarSistemaLicencias();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['activate_license'])) {
    $license_key = trim($_POST['license_key'] ?? '');
    
    if (empty($license_key)) {
        $license_error = 'Por favor, ingrese una clave de licencia válida.';
    } else {
        try {
            if (!is_writable(LICENSE_DIR)) {
                throw new Exception('El directorio de licencias no tiene permisos de escritura: ' . LICENSE_DIR);
            }
            
            $activation_result = $license_client->activateLicense($license_key);
            
            if ($activation_result['success']) {
                $verification_attempts = 0;
                $max_attempts = 3;
                $license_verified = false;
                
                while ($verification_attempts < $max_attempts && !$license_verified) {
                    sleep(1);
                    $license_verified = $license_client->isLicenseValid();
                    $verification_attempts++;
                }
                
                if ($license_verified) {
                    $_SESSION['license_activated'] = true;
                    $_SESSION['license_key'] = $license_key;
                    $_SESSION['license_verified_at'] = time();
                    $license_success = 'Licencia activada y verificada exitosamente.';
                } else {
                    $_SESSION['license_activated'] = true;
                    $_SESSION['license_key'] = $license_key;
                    $_SESSION['license_verified_at'] = time();
                    $license_warning = 'Licencia activada exitosamente, pero la verificación tardó más de lo esperado. Continuando con la instalación.';
                }
            } else {
                $license_error = $activation_result['message'];
            }
        } catch (Exception $e) {
            $license_error = 'Error durante la activación: ' . $e->getMessage();
            error_log('Error activación licencia: ' . $e->getMessage());
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['configure'])) {
    try {
        $license_valid = false;
        
        if ($license_client->isLicenseValid()) {
            $license_valid = true;
        } elseif (isset($_SESSION['license_activated']) && $_SESSION['license_activated']) {
            $time_since_activation = time() - ($_SESSION['license_verified_at'] ?? 0);
            if ($time_since_activation < 300) {
                $license_valid = true;
            }
        }
        
        if (!$license_valid) {
            throw new Exception('Debe activar una licencia válida antes de continuar con la instalación.');
        }
        
        $validation_errors = validateInstallationData($_POST);
        if (!empty($validation_errors)) {
            throw new Exception(implode('<br>', $validation_errors));
        }
        
        $db_host = trim($_POST['db_host']);
        $db_name = trim($_POST['db_name']);
        $db_user = trim($_POST['db_user']);
        $db_password = $_POST['db_password'];
        $admin_user = trim($_POST['admin_user']);
        $admin_password = $_POST['admin_password'];
        
        testDatabaseConnection($db_host, $db_user, $db_password);
        createConfigurationFiles($db_host, $db_name, $db_user, $db_password);
        $pdo = setupDatabase($db_host, $db_name, $db_user, $db_password);
        createDatabaseStructure($pdo);
        insertInitialData($pdo, $admin_user, $admin_password);
        setupFileSystem();
        
        ensureLicenseIsSaved($_SESSION['license_key'] ?? '');
        
        finalizeInstallation($pdo);
        
        $installation_successful = true;
        
        unset($_SESSION['license_activated']);
        unset($_SESSION['license_key']);
        unset($_SESSION['license_verified_at']);
        
    } catch (Exception $e) {
        $installation_error = true;
        $error_message = $e->getMessage();
        error_log("Error en instalación: " . $error_message);
    }
}

function ensureLicenseIsSaved($license_key) {
    if (empty($license_key)) {
        return;
    }
    
    global $license_client;
    
    if (!file_exists(LICENSE_FILE)) {
        try {
            error_log('Reactivando licencia porque no se encontró archivo en: ' . LICENSE_FILE);
            $activation_result = $license_client->activateLicense($license_key);
            if (!$activation_result['success']) {
                throw new Exception('No se pudo reactivar la licencia durante la instalación');
            }
            error_log('Licencia reactivada exitosamente en: ' . LICENSE_FILE);
        } catch (Exception $e) {
            error_log('Error reactivando licencia durante instalación: ' . $e->getMessage());
        }
    } else {
        error_log('Archivo de licencia encontrado correctamente en: ' . LICENSE_FILE);
    }
}

function validateInstallationData($data) {
    $errors = [];
    
    if (empty($data['db_host'])) $errors[] = "El servidor de BD es obligatorio";
    if (empty($data['db_name'])) $errors[] = "El nombre de la BD es obligatorio";
    if (empty($data['db_user'])) $errors[] = "El usuario de BD es obligatorio";
    if (empty($data['admin_user'])) $errors[] = "El usuario admin es obligatorio";
    if (strlen($data['admin_user']) < 3) $errors[] = "El usuario admin debe tener al menos 3 caracteres";
    if (empty($data['admin_password'])) $errors[] = "La contraseña admin es obligatoria";
    if (strlen($data['admin_password']) < 6) $errors[] = "La contraseña admin debe tener al menos 6 caracteres";
    
    if (!preg_match('/^[a-zA-Z0-9_.-]+$/', $data['db_name'])) {
        $errors[] = "El nombre de BD solo puede contener letras, números, guiones y puntos";
    }
    
    if (!preg_match('/^[a-zA-Z0-9_.-]+$/', $data['admin_user'])) {
        $errors[] = "El usuario admin solo puede contener letras, números y guiones";
    }
    
    return $errors;
}

// **CORRECCIÓN:** Añadir la variable $password a la función testDatabaseConnection
function testDatabaseConnection($host, $user, $password) { //
    try {
        // Asegurarse de que la contraseña se pase como tercer argumento a PDO
        $test_conn = new PDO("mysql:host={$host}", $user, $password); //
        $test_conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $test_conn = null;
    } catch (PDOException $e) {
        throw new Exception("No se pudo conectar a la base de datos: " . $e->getMessage());
    }
}

function createConfigurationFiles($db_host, $db_name, $db_user, $db_password) {
    $db_host_escaped = addslashes($db_host);
    $db_name_escaped = addslashes($db_name);
    $db_user_escaped = addslashes($db_user);
    $db_password_escaped = addslashes($db_password);
    
    $basededatos_content = "<?php
// Archivo generado automáticamente durante la instalación
\$db_host = '{$db_host_escaped}';
\$db_user = '{$db_user_escaped}';
\$db_password = '{$db_password_escaped}';
\$db_name = '{$db_name_escaped}';
?>";

    if (!file_put_contents(__DIR__ . '/basededatos.php', $basededatos_content)) {
        throw new Exception("No se pudo actualizar el archivo basededatos.php");
    }
}

function setupDatabase($db_host, $db_name, $db_user, $db_password) {
    $pdo = new PDO("mysql:host={$db_host}", $db_user, $db_password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec("SET NAMES utf8mb4");
    $pdo->exec("SET CHARACTER SET utf8mb4");
    $pdo->exec("CREATE DATABASE IF NOT EXISTS `{$db_name}` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_spanish_ci");
    $pdo->exec("USE `{$db_name}`");
    $pdo->exec("SET NAMES utf8mb4");
    $pdo->exec("SET CHARACTER SET utf8mb4");
    return $pdo;
}

function createDatabaseStructure($pdo) {
    $tables = [
        "CREATE TABLE IF NOT EXISTS admin (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci",
        
        "CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            email VARCHAR(100),
            status TINYINT(1) DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci",
        
        "CREATE TABLE IF NOT EXISTS authorized_emails (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci",

        "CREATE TABLE IF NOT EXISTS user_authorized_emails (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL COMMENT 'ID del usuario',
            authorized_email_id INT NOT NULL COMMENT 'ID del correo autorizado',
            assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Fecha de asignación',
            assigned_by INT DEFAULT NULL COMMENT 'ID del admin que asignó',
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (authorized_email_id) REFERENCES authorized_emails(id) ON DELETE CASCADE,
            FOREIGN KEY (assigned_by) REFERENCES users(id) ON DELETE SET NULL,
            UNIQUE KEY unique_user_email (user_id, authorized_email_id),
            INDEX idx_user_id (user_id),
            INDEX idx_email_id (authorized_email_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci",
        
        "CREATE TABLE IF NOT EXISTS logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            email_consultado VARCHAR(100) NOT NULL,
            plataforma VARCHAR(50) NOT NULL,
            ip VARCHAR(45),
            fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resultado TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
            INDEX idx_user_id (user_id),
            INDEX idx_fecha (fecha),
            INDEX idx_email (email_consultado)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci",
        
        "CREATE TABLE IF NOT EXISTS settings (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL UNIQUE,
            value TEXT NOT NULL,
            description TEXT,
            INDEX idx_name (name)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci",
        
        "CREATE TABLE IF NOT EXISTS email_servers (
            id INT AUTO_INCREMENT PRIMARY KEY,
            server_name VARCHAR(50) NOT NULL,
            enabled TINYINT(1) NOT NULL DEFAULT 0,
            imap_server VARCHAR(100) NOT NULL,
            imap_port INT NOT NULL DEFAULT 993,
            imap_user VARCHAR(100) NOT NULL,
            imap_password VARCHAR(100) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci",
        
        "CREATE TABLE IF NOT EXISTS platforms (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL UNIQUE COMMENT 'Nombre único de la plataforma',
            sort_order INT NOT NULL DEFAULT 0 COMMENT 'Orden de visualización',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_sort_order (sort_order)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci",

        "CREATE TABLE IF NOT EXISTS platform_subjects (
            id INT AUTO_INCREMENT PRIMARY KEY,
            platform_id INT NOT NULL COMMENT 'Referencia a la tabla platforms',
            subject VARCHAR(255) NOT NULL COMMENT 'Asunto del correo electrónico a buscar',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (platform_id) REFERENCES platforms(id) ON DELETE CASCADE ON UPDATE CASCADE,
            INDEX idx_platform_id (platform_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_spanish_ci"
    ];
    
    foreach ($tables as $sql) {
        $pdo->exec($sql);
    }
}

function insertInitialData($pdo, $admin_user, $admin_password) {
    $pdo->beginTransaction();
    
    try {
        insertSystemSettings($pdo);
        insertDefaultPlatforms($pdo);
        insertSystemUsers($pdo, $admin_user, $admin_password);
        insertExampleEmailsAndAssignments($pdo);
        insertDefaultServers($pdo);
        $pdo->commit();
    } catch (Exception $e) {
        $pdo->rollBack();
        throw new Exception("Error insertando datos iniciales: " . $e->getMessage());
    }
}

function insertSystemSettings($pdo) {
    $settings = [
        ['PAGE_TITLE', 'Consulta tu Código', 'Título de la página principal'],
        ['EMAIL_AUTH_ENABLED', '1', 'Habilitar filtro de correos electrónicos'],
        ['REQUIRE_LOGIN', '1', 'Si está activado (1), se requiere inicio de sesión para todos los usuarios'],
        ['USER_EMAIL_RESTRICTIONS_ENABLED', '0', 'Activar restricciones de correos por usuario (0=todos pueden consultar cualquier correo, 1=solo correos asignados)'],
        
        // Enlaces y personalización
        ['enlace_global_1', 'https://', 'Enlace del botón 1 en el header'],
        ['enlace_global_1_texto', 'Ir a Página web', 'Texto del botón 1 en el header'],
        ['enlace_global_2', 'https://t.me/', 'Enlace del botón 2 en el header'],
        ['enlace_global_2_texto', 'Ir a Telegram', 'Texto del botón 2 en el header'],
        ['enlace_global_numero_whatsapp', '0000000', 'Número de WhatsApp para contacto'],
        ['enlace_global_texto_whatsapp', 'Hola, necesito soporte técnico', 'Mensaje predeterminado para WhatsApp'],
        ['ID_VENDEDOR', '0', 'ID del vendedor para enlaces de afiliados'],
        ['LOGO', 'logo.png', 'Nombre del archivo de logo'],
        
        // Configuraciones de performance OPTIMIZADAS CON ZONA HORARIA
        ['EMAIL_QUERY_TIME_LIMIT_MINUTES', '30', 'Tiempo máximo (en minutos) para considerar emails válidos - OPTIMIZADO'],
        ['TIMEZONE_DEBUG_HOURS', '48', 'Horas hacia atrás para búsqueda inicial IMAP (para manejar zonas horarias)'],
        ['IMAP_CONNECTION_TIMEOUT', '8', 'Tiempo límite para conexiones IMAP (segundos) - OPTIMIZADO'],
        ['IMAP_SEARCH_OPTIMIZATION', '1', 'Activar optimizaciones de búsqueda IMAP'],
        ['PERFORMANCE_LOGGING', '0', 'Activar logs de rendimiento (temporal para debugging)'],
        ['EARLY_SEARCH_STOP', '1', 'Parar búsqueda al encontrar primer resultado - OPTIMIZADO'],
        
        // Configuraciones de cache
        ['CACHE_ENABLED', '1', 'Activar sistema de cache para mejorar performance'],
        ['CACHE_TIME_MINUTES', '5', 'Tiempo de vida del cache en minutos'],
        ['CACHE_MEMORY_ENABLED', '1', 'Activar cache en memoria para consultas repetidas'],
        
        // Configuraciones de filtrado OPTIMIZADAS
        ['TRUST_IMAP_DATE_FILTER', '1', 'Confiar en el filtrado de fechas IMAP sin verificación adicional'],
        ['USE_PRECISE_IMAP_SEARCH', '1', 'Usar búsquedas IMAP más precisas con fecha y hora específica - OPTIMIZADO'],
        ['MAX_EMAILS_TO_CHECK', '35', 'Número máximo de emails a verificar por consulta - OPTIMIZADO'],
        ['IMAP_SEARCH_TIMEOUT', '30', 'Tiempo límite para búsquedas IMAP en segundos'],
        ['LICENSE_PROTECTED', '1', 'Sistema protegido por licencia']
    ];
    
    $stmt = $pdo->prepare("INSERT IGNORE INTO settings (name, value, description) VALUES (?, ?, ?)");
    foreach ($settings as $setting) {
        $stmt->execute($setting);
    }
}

function insertSystemUsers($pdo, $admin_user, $admin_password) {
    $hashed_password = password_hash($admin_password, PASSWORD_DEFAULT);
    
    $stmt_user = $pdo->prepare("INSERT INTO users (username, password, email, status) VALUES (?, ?, ?, 1)");
    $admin_email = $admin_user . "@admin.local";
    $stmt_user->execute([$admin_user, $hashed_password, $admin_email]);
    $admin_user_id = $pdo->lastInsertId();
    
    $stmt_admin = $pdo->prepare("INSERT INTO admin (id, username, password) VALUES (?, ?, ?)");
    $stmt_admin->execute([$admin_user_id, $admin_user, $hashed_password]);
    
    $cliente_password = password_hash('cliente123', PASSWORD_DEFAULT);
    $stmt_cliente = $pdo->prepare("INSERT INTO users (username, password, email, status) VALUES (?, ?, ?, 1)");
    $stmt_cliente->execute(['cliente', $cliente_password, 'cliente@ejemplo.com']);
}

function insertExampleEmailsAndAssignments($pdo) {
    $example_emails = [
        'ejemplo1@gmail.com',
        'ejemplo2@outlook.com',
        'test@yahoo.com'
    ];
    
    $stmt_email = $pdo->prepare("INSERT IGNORE INTO authorized_emails (email) VALUES (?)");
    $email_ids = [];
    
    foreach ($example_emails as $email) {
        $stmt_email->execute([$email]);
        $email_id = $pdo->lastInsertId();
        if ($email_id == 0) {
            $stmt_get = $pdo->prepare("SELECT id FROM authorized_emails WHERE email = ?");
            $stmt_get->execute([$email]);
            $email_id = $stmt_get->fetchColumn();
        }
        $email_ids[] = $email_id;
    }
    
    $stmt_get_cliente = $pdo->prepare("SELECT id FROM users WHERE username = 'cliente'");
    $stmt_get_cliente->execute();
    $cliente_id = $stmt_get_cliente->fetchColumn();
    
    if ($cliente_id && !empty($email_ids)) {
        $stmt_assign = $pdo->prepare("INSERT IGNORE INTO user_authorized_emails (user_id, authorized_email_id, assigned_by) VALUES (?, ?, ?)");
        foreach ($email_ids as $email_id) {
            $stmt_assign->execute([$cliente_id, $email_id, 1]);
        }
    }
}

function insertDefaultPlatforms($pdo) {
    $platforms = [
        'Netflix' => [
            'Tu código de acceso temporal de Netflix',
            'Importante: Cómo actualizar tu Hogar con Netflix',
            'Netflix: Tu código de inicio de sesión',
            'Completa tu solicitud de restablecimiento de contraseña'
        ],
        'Disney+' => [
            'Tu código de acceso único para Disney+',
            'Disney+: Verificación de cuenta',
            'Disney+: Código de seguridad',
            'Disney+: Actualización de perfil'
        ],
        'Prime Video' => [
            'amazon.com: Sign-in attempt',
            'amazon.com: Intento de inicio de sesión',
            'Amazon Prime: Código de verificación',
            'Amazon: Actividad inusual en tu cuenta'
        ],
        'MAX' => [
            'Tu código de acceso MAX',
            'MAX: Intento de inicio de sesión',
            'MAX: Tu código de verificación',
            'MAX: Actualización de tu cuenta'
        ],
        'Spotify' => [
            'Spotify: Código de verificación',
            'Spotify: Cambio de contraseña solicitado',
            'Spotify: Nuevo inicio de sesión detectado',
            'Spotify: Confirma tu dirección de email'
        ],
        'Crunchyroll' => [
            'Crunchyroll: Código de acceso',
            'Crunchyroll: Actualización de cuenta',
            'Crunchyroll: Solicitud de inicio de sesión',
            'Crunchyroll: Restablecimiento de contraseña'
        ],
        'Paramount+' => [
            'Paramount Plus: Código de acceso',
            'Paramount Plus: Actualización de cuenta',
            'Paramount Plus: Solicitud de inicio de sesión',
            'Paramount Plus: Restablecimiento de contraseña'
        ],
        'ChatGPT' => [
            'Cambio de Contraseña',
            'Cambio de Correo Electrónico',
            'Cambio de Nombre',
            'Cambio de Cuenta'
        ]
    ];

    $stmt_platform = $pdo->prepare("INSERT IGNORE INTO platforms (name, sort_order) VALUES (?, ?)");
    $stmt_subject = $pdo->prepare("INSERT INTO platform_subjects (platform_id, subject) VALUES (?, ?)");

    $sort_order = 0;
    foreach ($platforms as $platform_name => $subjects) {
        $stmt_platform->execute([$platform_name, $sort_order]);
        $platform_id = $pdo->lastInsertId();
        
        if ($platform_id == 0) {
            $stmt_find = $pdo->prepare("SELECT id FROM platforms WHERE name = ?");
            $stmt_find->execute([$platform_name]);
            $platform_id = $stmt_find->fetchColumn();
        }

        if ($platform_id) {
            foreach ($subjects as $subject) {
                $stmt_subject->execute([$platform_id, $subject]);
            }
        }
        $sort_order++;
    }
}

function insertDefaultServers($pdo) {
    $default_servers = [
        ["SERVIDOR_1", 0, "imap.gmail.com", 993, "usuario1@gmail.com", ""],
        ["SERVIDOR_2", 0, "imap.gmail.com", 993, "usuario2@gmail.com", ""],
        ["SERVIDOR_3", 0, "imap.gmail.com", 993, "usuario3@gmail.com", ""],
        ["SERVIDOR_4", 0, "outlook.office365.com", 993, "usuario4@outlook.com", ""],
        ["SERVIDOR_5", 0, "imap.mail.yahoo.com", 993, "usuario5@yahoo.com", ""]
    ];
    
    $stmt = $pdo->prepare("INSERT IGNORE INTO email_servers (server_name, enabled, imap_server, imap_port, imap_user, imap_password) VALUES (?, ?, ?, ?, ?, ?)");
    
    foreach ($default_servers as $server) {
        $stmt->execute($server);
    }
}

function setupFileSystem() {
    $directories = [
        PROJECT_ROOT . '/cache/' => 0755,
        PROJECT_ROOT . '/cache/data/' => 0777,
        PROJECT_ROOT . '/images/logo/' => 0755,
        PROJECT_ROOT . '/images/fondo/' => 0755,
        LICENSE_DIR => 0755  // Usar la constante definida correctamente
    ];
    
    foreach ($directories as $dir => $permissions) {
        if (!file_exists($dir)) {
            if (!mkdir($dir, $permissions, true)) {
                throw new Exception("No se pudo crear el directorio: {$dir}");
            }
        }
        chmod($dir, $permissions);
    }
    
    $htaccess_content = "# Proteger carpeta de cache\nDeny from all\n<Files \"*.json\">\nDeny from all\n</Files>";
    file_put_contents(PROJECT_ROOT . '/cache/data/.htaccess', $htaccess_content);
    
    // Proteger directorio de licencias
    $license_htaccess = "Deny from all\n<Files \"*.dat\">\nDeny from all\n</Files>";
    file_put_contents(LICENSE_DIR . '/.htaccess', $license_htaccess);
    
    $files = [
        PROJECT_ROOT . '/cache/cache_helper.php' => 0755,
        PROJECT_ROOT . '/config/config.php' => 0644
    ];
    
    foreach ($files as $file => $permissions) {
        if (file_exists($file)) {
            chmod($file, $permissions);
        }
    }
}

function finalizeInstallation($pdo) {
    $stmt = $pdo->prepare("UPDATE settings SET value = '1' WHERE name = 'INSTALLED'");
    $stmt->execute();
    
    file_put_contents(__DIR__ . '/installed.txt', 
        date('Y-m-d H:i:s') . " - Instalación completada exitosamente con licencia activada\n" .
        "Archivo de licencia: " . LICENSE_FILE . "\n" .
        "Directorio de licencias: " . LICENSE_DIR
    );
    
    if (class_exists('SimpleCache')) {
        SimpleCache::clear_cache();
    }
}

// Verificar si ya está instalado
if (!isset($installation_successful) && !isset($installation_error)) {
    if (is_installed()) {
        header('Location: ../inicio.php');
        exit();
    }
}

?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Instalador del Sistema de Códigos</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="../styles/modern_global.css">
    <link rel="stylesheet" href="../styles/modern_admin.css">
    <style>
        /* Variables de color específicas para el instalador, sobreescriben si es necesario */
        :root {
            --neon-primary: #00f2fe; /* Color primario del instalador neon.css */
            --neon-secondary: #a162f7; /* Color secundario del instalador neon.css */
            --neon-success: #32FFB5; /* Verde de éxito del instalador neon.css */
            --neon-danger: #ff4d4d; /* Rojo de peligro del instalador neon.css */
            --neon-warning: #f59e0b; /* Amarillo de advertencia del instalador neon.css */
            --bg-dark: #0f172a; /* Fondo oscuro del instalador neon.css */
            --card-bg: rgba(26, 18, 53, 0.6); /* Fondo de tarjeta del instalador neon.css */
            --input-bg: rgba(0, 0, 0, 0.3); /* Fondo de input del instalador neon.css */
            --text-light: #FFFFFF; /* Texto claro del instalador neon.css */
            --text-muted: #bcaee5; /* Texto muted del instalador neon.css */
            --border-color: rgba(0, 242, 254, 0.25); /* Color de borde del instalador neon.css */
            --glow-color: rgba(0, 242, 254, 0.2); /* Color de glow del instalador neon.css */
            --glow-strong: 0 0 25px var(--glow-color); /* Sombra de glow fuerte del instalador neon.css */

            /* Re-definir algunas variables de modern_admin.css para que instalador_neon.css tenga prioridad */
            --bg-purple-dark: var(--bg-dark); /* Usar el fondo oscuro de instalador_neon.css */
            --card-purple: var(--card-bg); /* Usar el fondo de tarjeta de instalador_neon.css */
            --input-dark: var(--input-bg); /* Usar el fondo de input de instalador_neon.css */
            --accent-green: var(--neon-success); /* Usar el verde de éxito de instalador_neon.css */
            --glow-green: var(--glow-color); /* Usar el glow de instalador_neon.ESTILOS CSS */
            --glow-border: var(--border-color); /* Usar el borde de instalador_neon.css */
            --danger-red: var(--neon-danger); /* Usar el rojo de peligro de instalador_neon.css */

            /* Nuevas variables para los textos más visibles */
            --text-info-light: var(--text-muted); /* Usar el texto muted de instalador_neon.css */
            --text-success-light: var(--neon-success); /* Usar el verde de éxito de instalador_neon.css */
        }
        
        /* Aplicar el fondo animado de modern_admin.css al body del instalador */
        body {
            font-family: 'Poppins', sans-serif;
            position: relative;
            background-color: var(--bg-purple-dark); /* Color de fondo principal de modern_admin.css */
            color: var(--text-primary); /* Color de texto principal de modern_admin.css */
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow-x: hidden; /* Evita el scroll horizontal */
        }

        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image: url('../images/fondo/fondo.jpg'); /* Ruta de la imagen de fondo */
            background-size: cover;
            background-position: center;
            background-attachment: fixed;
            filter: brightness(0.5) saturate(1.1) blur(2px);
            z-index: -2;
            animation: kenburns-effect 40s ease-in-out infinite alternate;
        }

        body::after {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(rgba(26, 18, 53, 0.6), rgba(26, 18, 53, 0.6));
            z-index: -1;
        }

        /* Re-definir animaciones si es necesario, de lo contrario usar las de modern_admin.css */
        @keyframes kenburns-effect {
            from { transform: scale(1) translate(0, 0); }
            to { transform: scale(1.1) translate(2%, -2%); }
        }

        /* Contenedor principal con estilos de tarjeta de admin.css */
        .container {
            background: var(--card-purple); /* Color de tarjeta de modern_admin.css */
            border: 1px solid var(--glow-border); /* Borde de glow de modern_admin.css */
            border-radius: 20px; /* Radio de borde de modern_admin.css */
            box-shadow: var(--shadow-lg); /* Usar una sombra más prominente del global_design */
            padding: 2.5rem; /* Padding más grande para coincidir con el diseño */
            position: relative; /* Para z-index si hay elementos flotantes */
            z-index: 1; /* Asegura que esté por encima de los fondos */
            width: 100%; /* Asegurar que ocupe el ancho disponible */
            max-width: 900px; /* Limitar el ancho máximo para legibilidad */
        }
        .form-section {
            background: rgba(0,0,0,0.2); /* Fondo más oscuro para secciones internas */
            border: 1px solid var(--glow-border); /* Borde de glow de modern_admin.css */
            border-radius: 16px; /* Radio de borde para secciones */
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: var(--shadow-sm); /* Sombra sutil para secciones */
        }
        .step-indicator {
            background: var(--card-purple); /* Fondo de los indicadores de paso */
            border-radius: 15px;
            padding: 1rem;
            margin-bottom: 2rem;
            box-shadow: var(--shadow-md); /* Sombra para los indicadores de paso */
        }
        .step-indicator .step {
            color: var(--text-secondary); /* Color de texto secundario de modern_admin.css */
            font-weight: 500;
        }
        .step-indicator .step.active {
            color: var(--accent-green); /* Color de acento de modern_admin.css */
            font-weight: 600;
            text-shadow: 0 0 8px var(--glow-green); /* Efecto de glow para el paso activo */
        }
        .step-indicator .step.completed {
            color: var(--accent-green); /* Color de acento para completado */
        }
        /* Clases de texto de modern_admin.css */
        h1, h2, h3, h4 { color: var(--text-primary); font-weight: 600; }
        .text-primary { color: var(--accent-green) !important; }
        .text-secondary { color: var(--text-secondary) !important; }
        .text-muted, .form-text { color: var(--text-info-light) !important; opacity: 0.9; }

        /* Iconos de estado */
        .requirement-ok { color: var(--accent-green) !important; font-weight: 600; }
        .requirement-error { color: var(--danger-red) !important; font-weight: 600; }
        .requirement-ok .fas, .requirement-error .fas { text-shadow: 0 0 8px currentColor; }

        /* Inputs y Labels */
        .form-label {
            font-weight: 500;
            color: var(--text-secondary);
            margin-bottom: 0.5rem;
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .form-control {
            background: var(--input-dark);
            border: 1px solid var(--text-secondary); /* Borde sutil por defecto */
            border-radius: 10px;
            color: var(--text-primary);
            padding: 0.75rem 1rem;
            width: 100%;
            transition: border-color 0.3s ease, box-shadow 0.3s ease;
        }
        .form-control:focus {
            border-color: var(--accent-green);
            box-shadow: 0 0 0 3px var(--glow-green);
            outline: none;
        }
        .license-key-input {
            font-family: 'monospace', sans-serif;
            font-size: 1.1rem;
            letter-spacing: 1px; /* Ajustado para mejor legibilidad */
            text-transform: uppercase;
        }
        .diagnostics-box {
            background: rgba(0,0,0,0.2);
            border: 1px solid var(--glow-border);
            border-radius: 8px;
            padding: 1rem;
            margin-top: 1rem;
            font-family: monospace;
            font-size: 0.9rem;
            color: var(--text-secondary);
        }

        /* Botones */
        .btn {
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            display: inline-flex; /* Para alinear íconos y texto */
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
        }
        .btn-primary, .btn-success {
            background: var(--accent-green);
            color: var(--bg-purple-dark);
            box-shadow: 0 0 15px var(--glow-green);
        }
        .btn-primary:hover, .btn-success:hover {
            transform: translateY(-2px);
            box-shadow: 0 0 25px var(--glow-green);
        }
        .btn-secondary {
            background: rgba(255, 255, 255, 0.1);
            color: var(--text-primary);
            border: 1px solid var(--glow-border);
        }
        .btn-secondary:hover {
            background: rgba(255, 255, 255, 0.2);
            border-color: var(--accent-green);
            color: var(--accent-green);
        }

        /* Alertas */
        .alert {
            padding: 1rem;
            border-radius: 12px;
            display: flex;
            align-items: center;
            gap: 12px;
            font-weight: 500;
        }
        .alert-success {
            background: rgba(50, 255, 181, 0.1);
            border: 1px solid rgba(50, 255, 181, 0.3);
            color: #adffde;
        }
        .alert-warning {
            background: rgba(245, 158, 11, 0.1);
            border: 1px solid rgba(245, 158, 11, 0.3);
            color: #f59e0b;
        }
        .alert-danger {
            background: rgba(255, 77, 77, 0.1);
            border: 1px solid rgba(255, 77, 77, 0.3);
            color: #ff9a9a;
        }
        .alert-info {
            background-color: rgba(0, 242, 254, 0.1);
            border-color: rgba(0, 242, 254, 0.3);
            color: var(--neon-primary);
        }

        /* Barra de progreso superior */
        #topProgressBar {
            position: fixed;
            top: 0;
            left: 0;
            width: 0; /* Se controla con JS */
            height: 4px; /* Altura de la barra */
            background: linear-gradient(90deg, var(--neon-primary), var(--neon-secondary));
            box-shadow: 0 0 10px var(--neon-primary);
            z-index: 10000; /* Asegura que esté por encima de todo */
            transition: width 0.4s ease-in-out;
        }

        /* Ajustes específicos para la tabla de requerimientos */
        .table {
            border-collapse: separate; /* Permite aplicar border-spacing */
            border-spacing: 0 8px; /* Espacio vertical entre filas */
            background-color: transparent; /* Asegura que no tenga fondo por defecto */
        }
        .table thead th {
            color: var(--accent-green);
            text-transform: uppercase;
            font-size: 0.9rem;
            border-bottom: 2px solid var(--accent-green) !important;
            vertical-align: middle; /* Alinea verticalmente el texto en el encabezado */
            padding: 1rem; /* Espaciado uniforme para encabezados */
        }
        .table tbody tr {
            background: var(--card-purple-light); /* Fondo de fila más claro para contraste, de modern_admin.css */
            border: 1px solid var(--glow-border); /* Borde sutil entre filas */
            color: var(--text-primary); /* Color de texto claro */
            transition: background-color 0.3s ease, box-shadow 0.3s ease;
        }
        .table tbody td {
            vertical-align: middle; /* Alinea verticalmente el texto en las celdas */
            padding: 0.75rem 1rem; /* Espaciado interno */
        }
        .table tbody td:first-child {
            border-left: 1px solid var(--glow-border); /* Mantiene el borde izquierdo */
            border-top-left-radius: 10px; /* Redondea las esquinas */
            border-bottom-left-radius: 10px;
        }
        .table tbody td:last-child {
            border-right: 1px solid var(--glow-border); /* Mantiene el borde derecho */
            border-top-right-radius: 10px; /* Redondea las esquinas */
            border-bottom-right-radius: 10px;
            white-space: nowrap; /* Fuerza el contenido a una sola línea para la columna final */
            overflow: hidden; /* Oculta el desbordamiento si el contenido es muy largo */
            text-overflow: ellipsis; /* Añade puntos suspensivos */
            min-width: 120px; /* Aumenta el ancho mínimo para el texto de estado */
            max-width: 150px; /* Ancho máximo si es necesario para evitar desbordamiento excesivo */
        }
        .table tbody tr:hover {
            background-color: rgba(50, 255, 181, 0.1); /* Un poco más de glow al pasar el ratón */
            box-shadow: 0 0 15px var(--glow-color); /* Agrega sombra al hover */
        }
        /* Para asegurar que los iconos estén bien alineados y no afecten el espaciado del texto */
        .table tbody td .fab, .table tbody td .fas {
            margin-right: 0.5rem;
            font-size: 1rem; /* Tamaño de fuente normal para iconos */
        }
        /* Ajuste específico para el texto de estado para evitar que ocupe dos líneas */
        .table tbody td span.requirement-ok, .table tbody td span.requirement-error {
            display: inline-flex; /* Permite alinear el icono y el texto */
            align-items: center;
            white-space: nowrap; /* Mantiene el texto en una sola línea */
            justify-content: flex-start; /* Alinea a la izquierda */
        }
        /* Asegurar que el encabezado ESTADO no se corte y se ajuste a la izquierda */
        .table thead th:last-child {
            white-space: nowrap; /* Evita que el encabezado se corte */
            min-width: 120px; /* Ajusta este valor para que "ESTADO" se vea completo */
            text-align: left; /* Alinea el texto del encabezado a la izquierda */
            padding-right: 1rem; /* Asegura espacio si el texto es largo */
        }
        /* Alineación del texto "Estado" en las celdas, que parece ser el problema */
        .table tbody td:last-child {
            text-align: left; /* Alinea el contenido de la última columna a la izquierda */
        }
    </style>
</head>
<body class="d-flex align-items-center justify-content-center min-vh-100">
    
    <div id="topProgressBar"></div>

    <div class="container py-4">
        <?php if (isset($installation_successful) && $installation_successful): ?>
            <div class="text-center">
                <div class="mb-4">
                    <i class="fas fa-check-circle text-success" style="font-size: 4rem;"></i>
                </div>
                <h1 class="text-center mb-4">¡Instalación Exitosa!</h1>
                <div class="form-section">
                    <p class="mb-3">La configuración se ha guardado correctamente y la instalación se ha completado con éxito.</p>
                    <?php
                    $license_info = $license_client->getLicenseInfo();
                    if ($license_info): ?>
                        <div class="alert alert-success">
                            <h6><i class="fas fa-certificate me-2"></i>Información de Licencia</h6>
                            <ul class="list-unstyled mb-0 text-start">
                                <li><strong>Dominio:</strong> <span class="text-success"><?= htmlspecialchars($license_info['domain']) ?></span></li>
                                <li><strong>Activada:</strong> <span class="text-success"><?= htmlspecialchars($license_info['activated_at']) ?></span></li>
                                <li><strong>Estado:</strong> <span class="badge bg-success">Válida</span></li>
                            </ul>
                        </div>
                    <?php else: ?>
                        <div class="alert alert-info">
                            <h6><i class="fas fa-info-circle me-2"></i>Información de Licencia</h6>
                            <ul class="list-unstyled mb-0 text-start">
                                <li><strong>Estado:</strong> <span class="badge bg-success">Activada durante instalación</span></li>
                            </ul>
                        </div>
                    <?php endif; ?>
                    <ul class="list-unstyled text-start">
                        <li><i class="fas fa-check text-success me-2"></i> Licencia activada y verificada</li>
                        <li><i class="fas fa-check text-success me-2"></i> Base de datos configurada</li>
                        <li><i class="fas fa-check text-success me-2"></i> Usuario administrador creado</li>
                        <li><i class="fas fa-check text-success me-2"></i> Sistema de protección habilitado</li>
                        <li><i class="fas fa-check text-success me-2"></i> Rutas de licencia corregidas</li>
                    </ul>
                </div>
                <div class="d-flex justify-content-center">
                    <a href="../inicio.php" class="btn btn-primary btn-lg">
                        <i class="fas fa-home me-2"></i>Ir al Sistema
                    </a>
                </div>
            </div>
            
        <?php elseif (isset($installation_error) && $installation_error): ?>
            <div class="text-center">
                <div class="mb-4">
                    <i class="fas fa-exclamation-triangle text-danger" style="font-size: 4rem;"></i>
                </div>
                <h1 class="text-center mb-4">Error en la Instalación</h1>
                <div class="form-section">
                    <div class="alert alert-danger">
                        <?= htmlspecialchars($error_message) ?>
                    </div>
                    
                    <div class="diagnostics-box">
                        <h6><i class="fas fa-wrench me-2"></i>Información de Diagnóstico:</h6>
                        <ul class="list-unstyled mb-0">
                            <li>📁 <span class="text-secondary">PROJECT_ROOT:</span> <?= htmlspecialchars(PROJECT_ROOT) ?></li>
                            <li>📂 <span class="text-secondary">Dir. actual:</span> <?= htmlspecialchars(getcwd()) ?></li>
                            <li>📂 <span class="text-secondary">Dir. instalador:</span> <?= htmlspecialchars(__DIR__) ?></li>
                            <li>✅ <span class="<?= file_exists(LICENSE_DIR) ? 'requirement-ok' : 'requirement-error' ?>">License dir existe:</span> <?= file_exists(LICENSE_DIR) ? 'SÍ' : 'NO' ?></li>
                            <li>✏️ <span class="<?= is_writable(dirname(LICENSE_DIR)) ? 'requirement-ok' : 'requirement-error' ?>">License dir escribible:</span> <?= is_writable(dirname(LICENSE_DIR)) ? 'SÍ' : 'NO' ?></li>
                        </ul>
                    </div>
                </div>
                <div class="d-flex justify-content-center gap-3">
                    <button type="button" class="btn btn-secondary" onclick="window.location.href='?step=license'">
                        <i class="fas fa-redo me-2"></i>Reintentar
                    </button>
                </div>
            </div>
            
        <?php else: ?>
            <div class="step-indicator">
                <div class="step <?= $current_step === 'requirements' ? 'active' : ($current_step !== 'requirements' ? 'completed' : '') ?>">
                    <i class="fas fa-server me-2"></i>Requerimientos
                </div>
                <div class="step <?= $current_step === 'license' ? 'active' : ($current_step === 'configuration' ? 'completed' : '') ?>">
                    <i class="fas fa-key me-2"></i>Licencia
                </div>
                <div class="step <?= $current_step === 'configuration' ? 'active' : '' ?>">
                    <i class="fas fa-cogs me-2"></i>Configuración
                </div>
            </div>
            
            <?php if ($current_step === 'requirements'): ?>
                <div class="text-center mb-4">
                    <i class="fas fa-server text-primary" style="font-size: 3rem;"></i>
                    <h1 class="mt-3">Verificación de Requerimientos</h1>
                    <p class="text-secondary">Comprobando que su servidor cumple con los requisitos</p>
                </div>
                
                <div class="form-section">
                    <div class="table-responsive">
                        <table class="table table-dark table-striped">
                            <thead>
                                <tr>
                                    <th>Componente</th>
                                    <th>Requerido</th>
                                    <th>Estado</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td><i class="fab fa-php me-2"></i>PHP</td>
                                    <td><?= $php_version_required ?> o superior</td>
                                    <td>
                                        <span class="<?= $php_version_valid ? 'requirement-ok' : 'requirement-error' ?>">
                                            <i class="fas <?= $php_version_valid ? 'fa-check' : 'fa-times' ?> me-1"></i>
                                            <?= $php_version ?>
                                        </span>
                                    </td>
                                </tr>
                                <?php foreach ($required_extensions as $ext => $description): ?>
                                    <tr>
                                        <td><i class="fas fa-puzzle-piece me-2"></i><?= $ext ?></td>
                                        <td><?= $description ?></td>
                                        <td>
                                            <span class="<?= $extensions_status[$ext] ? 'requirement-ok' : 'requirement-error' ?>">
                                                <i class="fas <?= $extensions_status[$ext] ? 'fa-check' : 'fa-times' ?> me-1"></i>
                                                <?= $extensions_status[$ext] ? 'Habilitada' : 'Faltante' ?>
                                            </span>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    
                    <div class="diagnostics-box">
                        <h6><i class="fas fa-folder me-2"></i>Información de Rutas:</h6>
                        <ul class="list-unstyled mb-0 small">
                            <li>📁 <span class="text-secondary">Raíz del proyecto:</span> <?= htmlspecialchars(PROJECT_ROOT) ?></li>
                            <li>✅ <span class="<?= file_exists(LICENSE_DIR) ? 'requirement-ok' : 'requirement-error' ?>">Directorio existe:</span> <?= file_exists(LICENSE_DIR) ? 'SÍ' : 'NO' ?></li>
                            <li>✏️ <span class="<?= is_writable(dirname(LICENSE_DIR)) ? 'requirement-ok' : 'requirement-error' ?>">Directorio escribible:</span> <?= is_writable(dirname(LICENSE_DIR)) ? 'SÍ' : 'NO' ?></li>
                        </ul>
                    </div>
                    
                    <div class="text-center mt-3">
                        <?php if ($all_extensions_loaded && $php_version_valid): ?>
                            <div class="alert alert-success">
                                <i class="fas fa-check-circle me-2"></i>
                                ¡Todos los requerimientos están satisfechos!
                            </div>
                            <a href="?step=license" class="btn btn-success btn-lg">
                                <i class="fas fa-key me-2"></i>Continuar con la Licencia
                            </a>
                        <?php else: ?>
                            <div class="alert alert-warning">
                                <i class="fas fa-exclamation-triangle me-2"></i>
                                Hay requerimientos faltantes. Contacte a su proveedor de hosting.
                            </div>
                            <button type="button" class="btn btn-warning" onclick="location.reload()">
                                <i class="fas fa-sync me-2"></i>Verificar Nuevamente
                            </button>
                        <?php endif; ?>
                    </div>
                </div>
                
            <?php elseif ($current_step === 'license'): ?>
                <div class="text-center mb-4">
                    <i class="fas fa-key text-primary" style="font-size: 3rem;"></i>
                    <h1 class="mt-3">Activación de Licencia</h1>
                    <p class="text-secondary">Ingrese su clave de licencia para continuar</p>
                </div>
                
                <?php if (isset($license_error)): ?>
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        <?= htmlspecialchars($license_error) ?>
                        
                        <div class="diagnostics-box mt-3">
                            <h6><i class="fas fa-bug me-2"></i>Información de Debugging:</h6>
                            <ul class="list-unstyled mb-0 small">
                                <li>✅ <span class="<?= file_exists(LICENSE_DIR) ? 'requirement-ok' : 'requirement-error' ?>">Directorio existe:</span> <?= file_exists(LICENSE_DIR) ? 'SÍ' : 'NO' ?></li>
                                <li>✏️ <span class="<?= is_writable(LICENSE_DIR) ? 'requirement-ok' : 'requirement-error' ?>">Directorio escribible:</span> <?= is_writable(LICENSE_DIR) ? 'SÍ' : 'NO' ?></li>
                                <li>📄 <span class="<?= file_exists(LICENSE_FILE) ? 'requirement-ok' : 'requirement-error' ?>">Archivo existe:</span> <?= file_exists(LICENSE_FILE) ? 'SÍ' : 'NO' ?></li>
                            </ul>
                        </div>
                    </div>
                <?php endif; ?>
                
                <?php if (isset($license_success)): ?>
                    <div class="alert alert-success">
                        <i class="fas fa-check-circle me-2"></i>
                        <?= htmlspecialchars($license_success) ?>
                    </div>
                <?php endif; ?>
                
                <?php if (isset($license_warning)): ?>
                    <div class="alert alert-warning">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        <?= htmlspecialchars($license_warning) ?>
                    </div>
                <?php endif; ?>
                
                <div class="form-section">
                    <?php 
                    // Verificación mejorada de licencia válida
                    $license_is_valid = false;
                    if ($license_client->isLicenseValid()) {
                        $license_is_valid = true;
                    } elseif (isset($_SESSION['license_activated']) && $_SESSION['license_activated']) {
                        $time_since_activation = time() - ($_SESSION['license_verified_at'] ?? 0);
                        if ($time_since_activation < 300) { // 5 minutos de gracia
                            $license_is_valid = true;
                        }
                    }
                    
                    if ($license_is_valid): ?>
                        <div class="alert alert-success text-center">
                            <i class="fas fa-shield-alt fa-3x mb-3"></i>
                            <h4>Licencia Activada</h4>
                            <?php
                            $license_info = $license_client->getLicenseInfo();
                            if ($license_info): ?>
                                <p class="mb-0">
                                    <strong>Dominio:</strong> <span class="text-success"><?= htmlspecialchars($license_info['domain']) ?></span><br>
                                    <strong>Activada:</strong> <span class="text-success"><?= htmlspecialchars($license_info['activated_at']) ?></span><br>
                                    <strong>Estado:</strong> <span class="badge bg-success">Válida</span><br>
                                </p>
                            <?php else: ?>
                                <p class="mb-0">
                                    <strong>Estado:</strong> <span class="badge bg-success">Activada en Sesión</span><br>
                                </p>
                            <?php endif; ?>
                        </div>
                        
                        <div class="text-center">
                            <a href="?step=configuration" class="btn btn-primary btn-lg">
                                <i class="fas fa-cogs me-2"></i>Continuar con la Configuración
                            </a>
                        </div>
                    <?php else: ?>
                        <form method="POST" class="text-center">
                            <div class="mb-4">
                                <label for="license_key" class="form-label h5">
                                    <i class="fas fa-key me-2"></i>Clave de Licencia
                                </label>
                                <input type="text" 
                                       class="form-control form-control-lg license-key-input text-center" 
                                       name="license_key" 
                                       placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
                                       maxlength="50"
                                       required>
                                <div class="form-text">
                                    Ingrese la clave de licencia proporcionada por el proveedor
                                </div>
                            </div>
                            
                            <div class="alert alert-info">
                                <h6><i class="fas fa-info-circle me-2"></i>Información de Activación</h6>
                                <p class="mb-0">
                                    • La licencia se activará para el dominio: <strong class="text-primary"><?= htmlspecialchars($_SERVER['HTTP_HOST']) ?></strong><br>
                                    • Se verificará la validez con el servidor de licencias<br>
                                    • La activación requiere conexión a internet<br>
                                </p>
                            </div>
                            
                            <div class="d-flex justify-content-center gap-3">
                                <a href="?step=requirements" class="btn btn-secondary btn-lg">
                                    <i class="fas fa-arrow-left me-2"></i>Atrás
                                </a>
                                <button type="submit" name="activate_license" class="btn btn-success btn-lg">
                                    <i class="fas fa-shield-alt me-2"></i>Activar Licencia
                                </button>
                            </div>
                        </form>
                    <?php endif; ?>
                </div>
                
            <?php elseif ($current_step === 'configuration'): ?>
                <?php 
                // Verificación final antes de mostrar configuración
                $can_proceed = false;
                if ($license_client->isLicenseValid()) {
                    $can_proceed = true;
                } elseif (isset($_SESSION['license_activated']) && $_SESSION['license_activated']) {
                    $time_since_activation = time() - ($_SESSION['license_verified_at'] ?? 0);
                    if ($time_since_activation < 300) { // 5 minutos de gracia
                        $can_proceed = true;
                    }
                }
                
                if (!$can_proceed): ?>
                    <div class="alert alert-danger text-center">
                        <i class="fas fa-exclamation-triangle fa-2x mb-3"></i>
                        <h4>Licencia Requerida</h4>
                        <p>Debe activar una licencia válida antes de continuar.</p>
                        <a href="?step=license" class="btn btn-warning">
                            <i class="fas fa-key me-2"></i>Activar Licencia
                        </a>
                    </div>
                <?php else: ?>
                    <div class="text-center mb-4">
                        <i class="fas fa-cogs text-primary" style="font-size: 3rem;"></i>
                        <h1 class="mt-3">Configuración del Sistema</h1>
                        <p class="text-secondary">Complete los datos para finalizar la instalación</p>
                    </div>
                    
                    <form method="POST" id="installForm">
                        <div class="form-section">
                            <h4 class="mb-3"><i class="fas fa-database me-2 text-info"></i>Base de Datos</h4>
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label for="db_host" class="form-label">
                                            <i class="fas fa-server me-2"></i>Servidor
                                        </label>
                                        <input type="text" class="form-control" name="db_host" value="localhost" required>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label for="db_name" class="form-label">
                                            <i class="fas fa-database me-2"></i>Nombre de la Base de Datos
                                        </label>
                                        <input type="text" class="form-control" name="db_name" placeholder="mi_sistema_codigos" required>
                                    </div>
                                </div>
                            </div>
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label for="db_user" class="form-label">
                                            <i class="fas fa-user me-2"></i>Usuario de la Base de Datos
                                        </label>
                                        <input type="text" class="form-control" name="db_user" placeholder="usuario_bd" required>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label for="db_password" class="form-label">
                                            <i class="fas fa-key me-2"></i>Contraseña de la Base de Datos
                                        </label>
                                        <input type="password" class="form-control" name="db_password" placeholder="Contraseña BD">
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="form-section">
                            <h4 class="mb-3"><i class="fas fa-user-shield me-2 text-warning"></i>Usuario Administrador</h4>
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label for="admin_user" class="form-label">
                                            <i class="fas fa-user-cog me-2"></i>Usuario Administrador
                                        </label>
                                        <input type="text" class="form-control" name="admin_user" placeholder="admin" required minlength="3">
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label for="admin_password" class="form-label">
                                            <i class="fas fa-lock me-2"></i>Contraseña Administrador
                                        </label>
                                        <input type="password" class="form-control" name="admin_password" placeholder="Contraseña segura" required minlength="6">
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="form-section">
                            <div class="alert alert-success">
                                <h6><i class="fas fa-shield-alt me-2"></i>Estado de Licencia</h6>
                                <?php
                                $license_info = $license_client->getLicenseInfo();
                                if ($license_info): ?>
                                    <ul class="mb-0 text-start">
                                        <li>✅ <span class="text-success">Licencia válida y activada</span></li>
                                        <li>🌐 <span class="text-secondary">Dominio autorizado:</span> <strong class="text-primary"><?= htmlspecialchars($license_info['domain']) ?></strong></li>
                                        <li>📅 <span class="text-secondary">Activada el:</span> <span class="text-primary"><?= htmlspecialchars($license_info['activated_at']) ?></span></li>
                                        <li>🔒 <span class="text-success">Sistema protegido contra uso no autorizado</span></li>
                                    </ul>
                                <?php else: ?>
                                    <ul class="mb-0 text-start">
                                        <li>✅ <span class="text-success">Licencia activada en esta sesión</span></li>
                                        <li>🌐 <span class="text-secondary">Dominio:</span> <strong class="text-primary"><?= htmlspecialchars($_SERVER['HTTP_HOST']) ?></strong></li>
                                        <li>🔒 <span class="text-success">Sistema protegido contra uso no autorizado</span></li>
                                    </ul>
                                <?php endif; ?>
                            </div>
                        </div>

                        <div class="d-flex justify-content-center gap-3">
                            <a href="?step=license" class="btn btn-secondary btn-lg">
                                <i class="fas fa-arrow-left me-2"></i>Atrás
                            </a>
                            <button type="submit" name="configure" class="btn btn-success btn-lg">
                                <i class="fas fa-rocket me-2"></i>Instalar Sistema
                            </button>
                        </div>
                    </form>
                <?php endif; ?>
            <?php endif; ?>
        <?php endif; ?>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Obtener la barra de progreso
        const topProgressBar = document.getElementById('topProgressBar');

        // Función para mostrar la barra de progreso
        function showProgressBar() {
            topProgressBar.style.width = '100%';
        }

        // Función para ocultar la barra de progreso (reiniciar)
        function hideProgressBar() {
            topProgressBar.style.width = '0';
        }

        // Mostrar la barra de progreso cuando se envía el formulario de instalación
        document.getElementById('installForm')?.addEventListener('submit', function() {
            showProgressBar();
        });
        
        // Ocultar la barra de progreso si la página carga completamente (ej. después de un error o éxito)
        document.addEventListener('DOMContentLoaded', function() {
            hideProgressBar(); // Asegurarse de que esté oculta al cargar
        });

        // Formatear clave de licencia automáticamente
        document.querySelector('.license-key-input')?.addEventListener('input', function(e) {
            let value = e.target.value.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
            let formatted = value.match(/.{1,4}/g)?.join('-') || value;
            if (formatted.length > 47) formatted = formatted.substring(0, 47);
            e.target.value = formatted;
        });
    </script>
</body>
</html>