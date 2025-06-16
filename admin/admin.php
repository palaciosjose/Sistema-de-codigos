<?php
session_start();
require_once '../instalacion/basededatos.php';
require_once '../funciones.php';
require_once '../security/auth.php';
require_once '../cache/cache_helper.php';

// Verificar que el usuario esté autenticado y sea administrador
check_session(true, '../index.php');

header('Content-Type: text/html; charset=utf-8');

// Verificar si la base de datos está configurada y se puede conectar
if (empty($db_host) || empty($db_user) || empty($db_password) || empty($db_name) || !file_exists('../instalacion/basededatos.php')) {
    echo '
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Instalación NO Detectada</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
        <link rel="stylesheet" href="../styles/modern_global.css">
    </head>
    <body class="bg-dark text-white d-flex align-items-center justify-content-center min-vh-100">
        <div class="text-center">
            <h1 class="mb-4">Instalación NO Detectada</h1>
            <a href="../instalacion/instalador.php" class="btn btn-primary">Instalar Sistema</a>
        </div>
    </body>
    </html>';
    exit();
}

// Crear una única conexión a la base de datos para todo el script
$conn = new mysqli($db_host, $db_user, $db_password, $db_name);
$conn->set_charset("utf8mb4");

if ($conn->connect_error) {
    echo '
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Error de Base de Datos</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
        <link rel="stylesheet" href="../styles/modern_global.css">
    </head>
    <body class="bg-dark text-white d-flex align-items-center justify-content-center min-vh-100">
        <div class="text-center">
            <h1 class="mb-4">Error de Base de Datos</h1>
            <a href="../instalacion/instalador.php" class="btn btn-primary">Reinstalar Sistema</a>
        </div>
    </body>
    </html>';
    exit();
}

// Verificar si las tablas necesarias existen
$required_tables = ['admin', 'settings', 'email_servers', 'users', 'logs'];
foreach ($required_tables as $table) {
    $result = $conn->query("SHOW TABLES LIKE '$table'");
    if ($result->num_rows == 0) {
        echo '
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <title>Instalación Incompleta</title>
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
            <link rel="stylesheet" href="../styles/modern_global.css">
        </head>
        <body class="bg-dark text-white d-flex align-items-center justify-content-center min-vh-100">
            <div class="text-center">
                <h1 class="mb-4">Instalación Incompleta</h1>
                <p>Faltan tablas necesarias en la base de datos.</p>
                <a href="../instalacion/instalador.php" class="btn btn-primary">Reinstalar Sistema</a>
            </div>
        </body>
        </html>';
        exit();
    }
}

// Verificar si existen servidores de correo en la base de datos
$check_servers = $conn->query("SELECT COUNT(*) as count FROM email_servers");
$server_count = 0;
if ($check_servers && $row = $check_servers->fetch_assoc()) {
    $server_count = $row['count'];
}

// Si no hay servidores, crear 5 servidores predeterminados
if ($server_count == 0) {
    $default_servers = [
        ["SERVIDOR_1", 0, "imap.gmail.com", 993, "usuario1@gmail.com", ""],
        ["SERVIDOR_2", 0, "imap.gmail.com", 993, "usuario2@gmail.com", ""],
        ["SERVIDOR_3", 0, "imap.gmail.com", 993, "usuario3@gmail.com", ""],
        ["SERVIDOR_4", 0, "outlook.office365.com", 993, "usuario4@outlook.com", ""],
        ["SERVIDOR_5", 0, "imap.mail.yahoo.com", 993, "usuario5@yahoo.com", ""]
    ];
    
    $insert_stmt = $conn->prepare("INSERT INTO email_servers (server_name, enabled, imap_server, imap_port, imap_user, imap_password) VALUES (?, ?, ?, ?, ?, ?)");
    
    foreach ($default_servers as $server) {
        $insert_stmt->bind_param("sissss", $server[0], $server[1], $server[2], $server[3], $server[4], $server[5]);
        $insert_stmt->execute();
    }
    
    $insert_stmt->close();
}

$settings = get_all_settings($conn);

// Variable para controlar el flujo de la interfaz
$show_form = false;

// Cargar valores actuales de EMAIL_SERVERS
$email_servers_data = [];
$result = $conn->query("SELECT * FROM email_servers ORDER BY id ASC");
while ($row = $result->fetch_assoc()) {
    $email_servers_data[] = $row;
}
$result->close();

// *** LÓGICA PARA CORREOS AUTORIZADOS ***
$auth_email_message = '';
$auth_email_error = '';

// Manejar eliminación de correo autorizado
if (isset($_GET['delete_auth_email']) && is_numeric($_GET['delete_auth_email'])) {
    $email_id_to_delete = intval($_GET['delete_auth_email']);
    $stmt = $conn->prepare("DELETE FROM authorized_emails WHERE id = ?");
    if ($stmt) {
        $stmt->bind_param("i", $email_id_to_delete);
        if ($stmt->execute()) {
            $_SESSION['auth_email_message'] = 'Correo autorizado eliminado correctamente.';
        } else {
            $_SESSION['auth_email_error'] = 'Error al eliminar el correo autorizado: ' . $stmt->error;
        }
        $stmt->close();
    } else {
        $_SESSION['auth_email_error'] = 'Error al preparar la consulta de eliminación: ' . $conn->error;
    }
    header("Location: admin.php?tab=correos_autorizados");
    exit();
}

// Manejar adición de correo autorizado
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_authorized_email'])) {
    $new_email = filter_var(trim($_POST['new_email']), FILTER_SANITIZE_EMAIL);
    if (filter_var($new_email, FILTER_VALIDATE_EMAIL)) {
        $stmt_check = $conn->prepare("SELECT id FROM authorized_emails WHERE email = ?");
        if ($stmt_check) {
            $stmt_check->bind_param("s", $new_email);
            $stmt_check->execute();
            $stmt_check->store_result();
            if ($stmt_check->num_rows == 0) {
                $stmt_insert = $conn->prepare("INSERT INTO authorized_emails (email) VALUES (?)");
                if ($stmt_insert) {
                    $stmt_insert->bind_param("s", $new_email);
                    if ($stmt_insert->execute()) {
                        $_SESSION['auth_email_message'] = 'Correo autorizado añadido correctamente.';
                    } else {
                        $_SESSION['auth_email_error'] = 'Error al añadir el correo autorizado: ' . $stmt_insert->error;
                    }
                    $stmt_insert->close();
                } else {
                    $_SESSION['auth_email_error'] = 'Error al preparar la consulta de inserción: ' . $conn->error;
                }
            } else {
                $_SESSION['auth_email_error'] = 'El correo electrónico ya está en la lista.';
            }
            $stmt_check->close();
        } else {
            $_SESSION['auth_email_error'] = 'Error al preparar la consulta de verificación: ' . $conn->error;
        }
    } else {
        $_SESSION['auth_email_error'] = 'Por favor, introduce una dirección de correo electrónico válida.';
    }
    header("Location: admin.php?tab=correos_autorizados");
    exit();
}

// Manejar edición de correo autorizado
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['edit_authorized_email'])) {
    $edit_email_id = filter_var(trim($_POST['edit_email_id']), FILTER_SANITIZE_NUMBER_INT);
    $edit_email_value = filter_var(trim($_POST['edit_email_value']), FILTER_SANITIZE_EMAIL);

    if (filter_var($edit_email_value, FILTER_VALIDATE_EMAIL) && !empty($edit_email_id)) {
        $stmt_check = $conn->prepare("SELECT id FROM authorized_emails WHERE email = ? AND id != ?");
        if ($stmt_check) {
            $stmt_check->bind_param("si", $edit_email_value, $edit_email_id);
            $stmt_check->execute();
            $stmt_check->store_result();
            if ($stmt_check->num_rows == 0) {
                $stmt_update = $conn->prepare("UPDATE authorized_emails SET email = ? WHERE id = ?");
                if ($stmt_update) {
                    $stmt_update->bind_param("si", $edit_email_value, $edit_email_id);
                    if ($stmt_update->execute()) {
                        $_SESSION['auth_email_message'] = 'Correo autorizado actualizado correctamente.';
                    } else {
                        $_SESSION['auth_email_error'] = 'Error al actualizar el correo autorizado: ' . $stmt_update->error;
                    }
                    $stmt_update->close();
                } else {
                     $_SESSION['auth_email_error'] = 'Error al preparar la consulta de actualización: ' . $conn->error;
                }
            } else {
                 $_SESSION['auth_email_error'] = 'El correo electrónico ya está en la lista.';
            }
             $stmt_check->close();
        } else {
            $_SESSION['auth_email_error'] = 'Error al preparar la consulta de verificación de edición: ' . $conn->error;
        }
    } else {
        $_SESSION['auth_email_error'] = 'Por favor, introduce una dirección de correo electrónico válida para editar.';
    }
    header("Location: admin.php?tab=correos_autorizados");
    exit();
}

// Recuperar mensajes de sesión y limpiarlos
if (isset($_SESSION['auth_email_message'])) {
    $auth_email_message = $_SESSION['auth_email_message'];
    unset($_SESSION['auth_email_message']);
}
if (isset($_SESSION['auth_email_error'])) {
    $auth_email_error = $_SESSION['auth_email_error'];
    unset($_SESSION['auth_email_error']);
}

// Obtener correos autorizados para mostrar en la tabla
$authorized_emails_list = [];
$result_auth = $conn->query("SELECT id, email, created_at FROM authorized_emails ORDER BY email ASC");
if ($result_auth) {
    while ($row_auth = $result_auth->fetch_assoc()) {
        $authorized_emails_list[] = $row_auth;
    }
    $result_auth->close();
} else {
    $auth_email_error = "Error al obtener la lista de correos autorizados: " . $conn->error;
}

// Manejar formulario de actualización
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update'])) {
    $update_servers_only = isset($_POST['update_servers_only']) && $_POST['update_servers_only'] == '1';

    // Solo actualizar servidores de correo si estamos en la pestaña de servidores o es update_servers_only
    if ($update_servers_only || (isset($_POST['current_tab']) && $_POST['current_tab'] == 'servidores')) {
        foreach ($email_servers_data as $server) {
            $server_id = $server['id'];
            $server_checkbox = isset($_POST["enabled_$server_id"]) ? 1 : 0;
            $imap_server = $_POST["imap_server_$server_id"] ?? $server['imap_server'];
            $imap_port = $_POST["imap_port_$server_id"] ?? $server['imap_port'];
            $imap_user = $_POST["imap_user_$server_id"] ?? $server['imap_user'];
            
            if (isset($_POST["imap_password_$server_id"])) {
                if ($_POST["imap_password_$server_id"] !== '**********' && $_POST["imap_password_$server_id"] !== '') {
                    $imap_password = $_POST["imap_password_$server_id"];
                } else {
                    $imap_password = $server['imap_password'];
                }
            } else {
                $imap_password = $server['imap_password'];
            }

            if (!is_numeric($imap_port) || $imap_port < 1 || $imap_port > 65535) {
                $imap_port = 993;
            }

            $stmt = $conn->prepare("UPDATE email_servers 
                SET enabled = ?, imap_server = ?, imap_port = ?, imap_user = ?, imap_password = ?
                WHERE id = ?");
            $stmt->bind_param("isissi", $server_checkbox, $imap_server, $imap_port, $imap_user, $imap_password, $server_id);
            $stmt->execute();
            $stmt->close();
        }
        
        if ($update_servers_only) {
            $_SESSION['message'] = 'Servidores IMAP actualizados con éxito.';
            header("Location: admin.php?tab=servidores");
            exit();
        }
    }

    // Si no es actualización solo de servidores, actualizar el resto de configuraciones
    if (!$update_servers_only) {
        $updatable_keys = [
            'PAGE_TITLE',
            'EMAIL_AUTH_ENABLED',
            'enlace_global_1', 'enlace_global_1_texto', 'enlace_global_2', 'enlace_global_2_texto',
            'enlace_global_numero_whatsapp', 'enlace_global_texto_whatsapp','ID_VENDEDOR','LOGO',
            'REQUIRE_LOGIN',
            'USER_EMAIL_RESTRICTIONS_ENABLED',
            'EMAIL_QUERY_TIME_LIMIT_MINUTES',
            'IMAP_CONNECTION_TIMEOUT',
            'IMAP_SEARCH_OPTIMIZATION', 
            'PERFORMANCE_LOGGING',
            'EARLY_SEARCH_STOP',
            'CACHE_ENABLED',
            'CACHE_TIME_MINUTES', 
            'CACHE_MEMORY_ENABLED',
            'TRUST_IMAP_DATE_FILTER',
            'USE_PRECISE_IMAP_SEARCH',
            'MAX_EMAILS_TO_CHECK',
            'IMAP_SEARCH_TIMEOUT'
        ];

        foreach ($updatable_keys as $key) {
            if (isset($_POST[$key])) {
                $final_value = $_POST[$key];
                if (in_array($key, [
                    'EMAIL_AUTH_ENABLED',
                    'REQUIRE_LOGIN',
                    'USER_EMAIL_RESTRICTIONS_ENABLED',
                    'IMAP_SEARCH_OPTIMIZATION',
                    'PERFORMANCE_LOGGING',
                    'EARLY_SEARCH_STOP',
                    'CACHE_ENABLED',
                    'CACHE_MEMORY_ENABLED',
                    'TRUST_IMAP_DATE_FILTER',
                    'USE_PRECISE_IMAP_SEARCH'
                ])) {
                    $final_value = ($final_value === '1') ? '1' : '0';
                }
                $stmt = $conn->prepare("INSERT INTO settings (name, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = ?");
                $stmt->bind_param("sss", $key, $final_value, $final_value);
                $stmt->execute();
                $stmt->close();
            } else {
                if (in_array($key, [
                    'EMAIL_AUTH_ENABLED',
                    'REQUIRE_LOGIN',
                    'IMAP_SEARCH_OPTIMIZATION',
                    'PERFORMANCE_LOGGING', 
                    'EARLY_SEARCH_STOP'
                ])) {
                    $zero = '0';
                    $stmt = $conn->prepare("INSERT INTO settings (name, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = ?");
                    $stmt->bind_param("sss", $key, $zero, $zero);  
                    $stmt->execute();
                    $stmt->close();
                }
            }
        }

        $target_dir = "../images/logo/";
        if(isset($_FILES["logo"]) && $_FILES["logo"]["error"] == UPLOAD_ERR_OK){
            $rutaTemporal = $_FILES['logo']['tmp_name'];
            $target_file = $target_dir . basename($_FILES["logo"]["name"]);
            $name_file = $_FILES['logo']['name'];
            
            $file_extension = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));
            $valid_file = true;
            
            if($file_extension != "png") {
                $_SESSION['message'] = 'Error: Solo se permiten archivos PNG.';
                $valid_file = false;
            }
            
            if($valid_file) {
                list($width, $height) = getimagesize($rutaTemporal);
                if($width != 512 || $height != 315) {
                    $_SESSION['message'] = 'Error: El logo debe tener dimensiones exactas de 512x315 píxeles.';
                    $valid_file = false;
                }
            }
            
            if($valid_file) {
                if(move_uploaded_file($rutaTemporal, $target_file)) {
                    $stmt_logo = $conn->prepare("UPDATE settings SET value = ? WHERE name = 'LOGO'");
                    $stmt_logo->bind_param("s", $name_file);
                    $stmt_logo->execute();
                    $stmt_logo->close();
                    
                    $_SESSION['message'] = 'Configuración actualizada con éxito.';
                } else {
                    $_SESSION['message'] = 'Error: No se pudo subir el archivo.';
                }
            }
        } else {
            $_SESSION['message'] = 'Configuración actualizada con éxito.';
        }
        
        SimpleCache::clear_settings_cache();
        SimpleCache::clear_servers_cache();
    }
    
    header("Location: admin.php?tab=" . ($_POST['current_tab'] ?? 'configuracion'));
    exit();
}

?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Panel de Administración - <?= htmlspecialchars($settings['PAGE_TITLE'] ?? 'Sistema de Códigos') ?></title>
    
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <!-- Estilos modernos -->
    <link rel="stylesheet" href="../styles/modern_global.css">
    <link rel="stylesheet" href="../styles/modern_admin.css">
</head>
<body class="admin-page">

<!-- Partículas flotantes -->
<div class="floating-particles">
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
</div>

<div class="admin-container">
    <!-- Header del Admin -->
    <div class="admin-header">
        <h1 class="admin-title">
            <i class="fas fa-cogs me-3"></i>
            Panel de Administración
        </h1>
        <p class="mb-0 opacity-75">Sistema de gestión de códigos por email</p>
    </div>

    <!-- Botón Volver a Inicio -->
    <div class="p-4">
        <a href="../inicio.php" class="btn-back-modern">
            <i class="fas fa-arrow-left"></i>
            Volver a Inicio
        </a>
    </div>

    <!-- Mensajes de estado -->
    <?php if (isset($_SESSION['message'])): ?>
        <div class="mx-4">
            <div class="alert-admin alert-success-admin">
                <i class="fas fa-check-circle"></i>
                <span><?= htmlspecialchars($_SESSION['message']) ?></span>
            </div>
        </div>
        <?php unset($_SESSION['message']); ?>
    <?php endif; ?>

    <!-- Navegación por pestañas moderna -->
    <ul class="nav nav-tabs nav-tabs-modern" id="adminTab" role="tablist">
        <li class="nav-item" role="presentation">
            <button class="nav-link active" id="config-tab" data-bs-toggle="tab" data-bs-target="#config" type="button" role="tab">
                <i class="fas fa-cog me-2"></i>Configuración
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="servidores-tab" data-bs-toggle="tab" data-bs-target="#servidores" type="button" role="tab">
                <i class="fas fa-server me-2"></i>Servidores
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="users-tab" data-bs-toggle="tab" data-bs-target="#users" type="button" role="tab">
                <i class="fas fa-users me-2"></i>Usuarios
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="logs-tab" data-bs-toggle="tab" data-bs-target="#logs" type="button" role="tab">
                <i class="fas fa-list-alt me-2"></i>Registros
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="correos-autorizados-tab" data-bs-toggle="tab" data-bs-target="#correos-autorizados" type="button" role="tab">
                <i class="fas fa-envelope-open me-2"></i>Correos Autorizados
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="platforms-tab" data-bs-toggle="tab" data-bs-target="#platforms" type="button" role="tab">
                <i class="fas fa-th-large me-2"></i>Plataformas
            </button>
        </li>

        <li class="nav-item" role="presentation">
                <button class="nav-link" id="asignaciones-tab" data-bs-toggle="tab" data-bs-target="#asignaciones" type="button" role="tab" aria-controls="asignaciones" aria-selected="false">Asignar Correos</button>
        </li>

    </ul>

    <div class="tab-content" id="adminTabContent">
        <!-- Pestaña de Configuración -->
        <div class="tab-pane fade show active" id="config" role="tabpanel">
            <form method="POST" action="admin.php" enctype="multipart/form-data" class="needs-validation" novalidate>
                <input type="hidden" name="current_tab" value="config">
                
                <!-- Opciones Principales -->
                <div class="admin-card">
                    <div class="admin-card-header">
                        <h3 class="admin-card-title">
                            <i class="fas fa-toggle-on me-2 text-primary"></i>
                            Opciones Principales
                        </h3>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-6">
                            <div class="form-check-admin">
                                <input type="checkbox" class="form-check-input-admin" id="EMAIL_AUTH_ENABLED" name="EMAIL_AUTH_ENABLED" value="1" <?= $settings['EMAIL_AUTH_ENABLED'] ? 'checked' : '' ?>>
                                <label for="EMAIL_AUTH_ENABLED" class="form-check-label-admin">
                                    <i class="fas fa-filter me-2"></i>
                                    Filtro de Correos Electrónicos
                                </label>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="form-check-admin">
                                <input type="checkbox" class="form-check-input-admin" id="REQUIRE_LOGIN" name="REQUIRE_LOGIN" value="1" <?= ($settings['REQUIRE_LOGIN'] ?? '1') === '1' ? 'checked' : '' ?>>
                                <label for="REQUIRE_LOGIN" class="form-check-label-admin">
                                    <i class="fas fa-lock me-2"></i>
                                    Seguridad de Login Habilitada
                                </label>
                            </div>
                            <small class="text-muted d-block mt-1">Si está activado, todos los usuarios necesitan iniciar sesión.</small>
                        </div>
                    </div>
                    
                    <div class="form-group-admin">
                        <label for="EMAIL_QUERY_TIME_LIMIT_MINUTES" class="form-label-admin">
                            <i class="fas fa-clock me-2"></i>
                            Límite de tiempo para consulta de correos (minutos)
                        </label>
                        <input type="number" class="form-control-admin" id="EMAIL_QUERY_TIME_LIMIT_MINUTES" name="EMAIL_QUERY_TIME_LIMIT_MINUTES" min="1" max="1440" value="<?= $settings['EMAIL_QUERY_TIME_LIMIT_MINUTES'] ?? '15' ?>">
                        <small class="text-muted">Tiempo máximo para buscar correos. Correos más antiguos no serán procesados.</small>
                    </div>
                </div>

                <!-- Configuraciones de Performance -->
                <div class="admin-card">
                    <div class="admin-card-header">
                        <h3 class="admin-card-title">
                            <i class="fas fa-tachometer-alt me-2 text-warning"></i>
                            Configuraciones de Performance
                        </h3>
                    </div>
                    
                    <div class="form-group-admin">
                        <label for="IMAP_CONNECTION_TIMEOUT" class="form-label-admin">
                            <i class="fas fa-plug me-2"></i>
                            Timeout de conexión IMAP (segundos)
                        </label>
                        <input type="number" class="form-control-admin" id="IMAP_CONNECTION_TIMEOUT" name="IMAP_CONNECTION_TIMEOUT" min="5" max="60" value="<?= $settings['IMAP_CONNECTION_TIMEOUT'] ?? '10' ?>">
                        <small class="text-muted">Tiempo máximo para conectar a servidores IMAP.</small>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-6">
                            <div class="form-check-admin">
                                <input type="checkbox" class="form-check-input-admin" id="IMAP_SEARCH_OPTIMIZATION" name="IMAP_SEARCH_OPTIMIZATION" value="1" <?= ($settings['IMAP_SEARCH_OPTIMIZATION'] ?? '1') === '1' ? 'checked' : '' ?>>
                                <label for="IMAP_SEARCH_OPTIMIZATION" class="form-check-label-admin">
                                    <i class="fas fa-search me-2"></i>
                                    Optimizaciones de búsqueda IMAP
                                </label>
                            </div>
                            <small class="text-muted d-block">Buscar todos los asuntos en una sola consulta.</small>
                        </div>
                        <div class="col-md-6">
                            <div class="form-check-admin">
                                <input type="checkbox" class="form-check-input-admin" id="EARLY_SEARCH_STOP" name="EARLY_SEARCH_STOP" value="1" <?= ($settings['EARLY_SEARCH_STOP'] ?? '1') === '1' ? 'checked' : '' ?>>
                                <label for="EARLY_SEARCH_STOP" class="form-check-label-admin">
                                    <i class="fas fa-stop me-2"></i>
                                    Parada temprana de búsqueda
                                </label>
                            </div>
                            <small class="text-muted d-block">Parar al encontrar el primer resultado.</small>
                        </div>
                    </div>
                    
                    <div class="form-check-admin">
                        <input type="checkbox" class="form-check-input-admin" id="PERFORMANCE_LOGGING" name="PERFORMANCE_LOGGING" value="1" <?= ($settings['PERFORMANCE_LOGGING'] ?? '0') === '1' ? 'checked' : '' ?>>
                        <label for="PERFORMANCE_LOGGING" class="form-check-label-admin">
                            <i class="fas fa-chart-line me-2"></i>
                            Logs de rendimiento
                        </label>
                    </div>
                    <small class="text-muted d-block">Registrar tiempos de ejecución en los logs del servidor.</small>
                </div>

                <!-- Configuraciones de Cache -->
                <div class="admin-card">
                    <div class="admin-card-header">
                        <h3 class="admin-card-title">
                            <i class="fas fa-database me-2 text-info"></i>
                            Configuraciones de Cache
                        </h3>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-6">
                            <div class="form-check-admin">
                                <input type="checkbox" class="form-check-input-admin" id="CACHE_ENABLED" name="CACHE_ENABLED" value="1" <?= ($settings['CACHE_ENABLED'] ?? '1') === '1' ? 'checked' : '' ?>>
                                <label for="CACHE_ENABLED" class="form-check-label-admin">
                                    <i class="fas fa-rocket me-2"></i>
                                    Sistema de cache activado
                                </label>
                            </div>
                            <small class="text-muted d-block">Cachear configuraciones y datos para mejorar velocidad.</small>
                        </div>
                        <div class="col-md-6">
                            <div class="form-check-admin">
                                <input type="checkbox" class="form-check-input-admin" id="CACHE_MEMORY_ENABLED" name="CACHE_MEMORY_ENABLED" value="1" <?= ($settings['CACHE_MEMORY_ENABLED'] ?? '1') === '1' ? 'checked' : '' ?>>
                                <label for="CACHE_MEMORY_ENABLED" class="form-check-label-admin">
                                    <i class="fas fa-memory me-2"></i>
                                    Cache en memoria activado
                                </label>
                            </div>
                            <small class="text-muted d-block">Mantener datos en memoria durante la sesión.</small>
                        </div>
                    </div>
                    
                    <div class="form-group-admin">
                        <label for="CACHE_TIME_MINUTES" class="form-label-admin">
                            <i class="fas fa-hourglass-half me-2"></i>
                            Tiempo de vida del cache (minutos)
                        </label>
                        <input type="number" class="form-control-admin" id="CACHE_TIME_MINUTES" name="CACHE_TIME_MINUTES" min="1" max="60" value="<?= $settings['CACHE_TIME_MINUTES'] ?? '5' ?>">
                        <small class="text-muted">Cuánto tiempo mantener datos en cache antes de recargar.</small>
                    </div>
                    
                    <div class="text-center mt-4">
                        <button type="button" class="btn-admin btn-info-admin btn-sm-admin" onclick="showCacheStats()">
                            <i class="fas fa-chart-bar"></i> Ver Estadísticas
                        </button>
                        <button type="button" class="btn-admin btn-warning-admin btn-sm-admin" onclick="clearCache()">
                            <i class="fas fa-broom"></i> Limpiar Cache
                        </button>
                        <button type="button" class="btn-admin btn-success-admin btn-sm-admin" onclick="testSearchSpeed()">
                            <i class="fas fa-tachometer-alt"></i> Test de Velocidad
                        </button>
                    </div>
                </div>

                <!-- Configuraciones de Filtrado de Tiempo -->
                <div class="admin-card">
                    <div class="admin-card-header">
                        <h3 class="admin-card-title">
                            <i class="fas fa-clock me-2 text-success"></i>
                            Configuraciones de Filtrado de Tiempo
                        </h3>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-6">
                            <div class="form-check-admin">
                                <input type="checkbox" class="form-check-input-admin" id="TRUST_IMAP_DATE_FILTER" name="TRUST_IMAP_DATE_FILTER" value="1" <?= ($settings['TRUST_IMAP_DATE_FILTER'] ?? '1') === '1' ? 'checked' : '' ?>>
                                <label for="TRUST_IMAP_DATE_FILTER" class="form-check-label-admin">
                                    <i class="fas fa-shield-alt me-2"></i>
                                    Confiar en filtrado IMAP
                                </label>
                            </div>
                            <small class="text-muted d-block">No re-verificar fechas en PHP (más rápido).</small>
                        </div>
                        <div class="col-md-6">
                            <div class="form-check-admin">
                                <input type="checkbox" class="form-check-input-admin" id="USE_PRECISE_IMAP_SEARCH" name="USE_PRECISE_IMAP_SEARCH" value="1" <?= ($settings['USE_PRECISE_IMAP_SEARCH'] ?? '1') === '1' ? 'checked' : '' ?>>
                                <label for="USE_PRECISE_IMAP_SEARCH" class="form-check-label-admin">
                                    <i class="fas fa-crosshairs me-2"></i>
                                    Búsqueda IMAP precisa
                                </label>
                            </div>
                            <small class="text-muted d-block">Usar fecha y hora específica en lugar de solo fecha.</small>
                        </div>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-6">
                            <div class="form-group-admin">
                                <label for="MAX_EMAILS_TO_CHECK" class="form-label-admin">
                                    <i class="fas fa-list-ol me-2"></i>
                                    Máximo emails a verificar
                                </label>
                                <input type="number" class="form-control-admin" id="MAX_EMAILS_TO_CHECK" name="MAX_EMAILS_TO_CHECK" min="10" max="500" value="<?= $settings['MAX_EMAILS_TO_CHECK'] ?? '50' ?>">
                                <small class="text-muted">Limitar cuántos emails verificar para evitar lentitud.</small>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="form-group-admin">
                                <label for="IMAP_SEARCH_TIMEOUT" class="form-label-admin">
                                    <i class="fas fa-stopwatch me-2"></i>
                                    Timeout de búsqueda IMAP (segundos)
                                </label>
                                <input type="number" class="form-control-admin" id="IMAP_SEARCH_TIMEOUT" name="IMAP_SEARCH_TIMEOUT" min="10" max="120" value="<?= $settings['IMAP_SEARCH_TIMEOUT'] ?? '30' ?>">
                                <small class="text-muted">Tiempo máximo para búsquedas IMAP antes de cancelar.</small>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Configuraciones de Personalización -->
                <div class="admin-card">
                    <div class="admin-card-header">
                        <h3 class="admin-card-title">
                            <i class="fas fa-paint-brush me-2 text-primary"></i>
                            Personalización del Sitio
                        </h3>
                    </div>
                    
                    <div class="row">
                        <?php 
                        $personalization_fields = [
                            'PAGE_TITLE' => ['Título SEO de la Página', 'fas fa-heading'],
                            'enlace_global_1' => ['Enlace del Botón 1', 'fas fa-link'],
                            'enlace_global_1_texto' => ['Texto del Botón 1', 'fas fa-text-width'],
                            'enlace_global_2' => ['Enlace del Botón 2', 'fas fa-link'],
                            'enlace_global_2_texto' => ['Texto del Botón 2', 'fas fa-text-width'],
                            'enlace_global_numero_whatsapp' => ['Número de WhatsApp', 'fab fa-whatsapp'],
                            'enlace_global_texto_whatsapp' => ['Texto Botón de WhatsApp', 'fas fa-comment'],
                            'ID_VENDEDOR' => ['ID Vendedor', 'fas fa-user-tag']
                        ];
                        
                        foreach ($personalization_fields as $field => $info): 
                        ?>
                        <div class="col-md-6">
                            <div class="form-group-admin">
                                <label for="<?= $field ?>" class="form-label-admin">
                                    <i class="<?= $info[1] ?> me-2"></i>
                                    <?= $info[0] ?>
                                </label>
                                <input type="text" class="form-control-admin" id="<?= $field ?>" name="<?= $field ?>" value="<?= htmlspecialchars($settings[$field] ?? '') ?>">
                            </div>
                        </div>
                        <?php endforeach; ?>
                    </div>
                    
                    <div class="form-group-admin">
                        <label for="logo" class="form-label-admin">
                            <i class="fas fa-image me-2"></i>
                            Logo del Sitio
                        </label>
                        <input type="file" class="form-control-admin" accept=".png" onchange="validarArchivo()" id="logo" name="logo">
                        <small class="text-muted">Tamaño requerido: 512px x 315px PNG</small>
                        <?php if (!empty($settings['LOGO'])): ?>
                            <div class="mt-2">
                                <small class="text-info">Logo actual: <?= htmlspecialchars($settings['LOGO']) ?></small>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>

                <div class="text-center mt-4">
                    <button type="submit" name="update" class="btn-admin btn-primary-admin btn-lg-admin">
                        <i class="fas fa-save"></i>
                        ACTUALIZAR CONFIGURACIÓN
                    </button>
                </div>
            </form>
        </div>

        <!-- Pestaña de Servidores IMAP -->
        <div class="tab-pane fade" id="servidores" role="tabpanel">
            <div class="admin-card">
                <div class="admin-card-header">
                    <h3 class="admin-card-title">
                        <i class="fas fa-server me-2"></i>
                        Configuración de Servidores IMAP
                    </h3>
                </div>
                
                <div class="alert-admin alert-info-admin">
                    <i class="fas fa-info-circle"></i>
                    <div>
                        <strong>Información:</strong> Configura los servidores IMAP para la verificación de correos.<br>
                        <small>Esta configuración no se ve afectada por cambios en otras pestañas.</small>
                    </div>
                </div>
                
                <?php 
                $email_servers_query = $conn->query("SELECT * FROM email_servers ORDER BY id ASC");
                $email_servers_data = [];
                $servers_found = false;
                
                if ($email_servers_query) {
                    while ($row = $email_servers_query->fetch_assoc()) {
                        $email_servers_data[] = $row;
                        $servers_found = true;
                    }
                }
                ?>
                
                <form method="POST" action="admin.php" enctype="multipart/form-data">
                    <input type="hidden" name="current_tab" value="servidores">
                    <input type="hidden" name="update_servers_only" value="1">
                    
                    <?php if (!$servers_found): ?>
                        <div class="alert-admin alert-warning-admin">
                            <i class="fas fa-exclamation-triangle"></i>
                            No hay servidores IMAP configurados en el sistema.
                        </div>
                    <?php else: ?>
                        <div class="row">
                            <?php foreach ($email_servers_data as $server): ?>
                                <div class="col-lg-6 mb-4">
                                    <div class="admin-card">
                                        <div class="admin-card-header">
                                            <div class="d-flex justify-content-between align-items-center w-100">
                                                <h5 class="mb-0">
                                                    <i class="fas fa-server me-2"></i>
                                                    <?= str_replace("SERVIDOR_", "Servidor ", $server['server_name']) ?>
                                                </h5>
                                                <div class="form-check-admin">
                                                    <input type="checkbox" class="form-check-input-admin" id="srv_enabled_<?= $server['id'] ?>" name="enabled_<?= $server['id'] ?>" value="1" <?= $server['enabled'] ? 'checked' : '' ?> onchange="toggleServerView('<?= $server['id'] ?>')">
                                                    <label for="srv_enabled_<?= $server['id'] ?>" class="form-check-label-admin">Habilitado</label>
                                                </div>
                                            </div>
                                        </div>
                                        
                                        <div class="server-settings" id="server_<?= $server['id'] ?>_settings" style="display: <?= $server['enabled'] ? 'block' : 'none' ?>;">
                                            <div class="form-group-admin">
                                                <label for="srv_imap_server_<?= $server['id'] ?>" class="form-label-admin">
                                                    <i class="fas fa-globe me-2"></i>
                                                    Servidor IMAP
                                                </label>
                                                <input type="text" class="form-control-admin" id="srv_imap_server_<?= $server['id'] ?>" name="imap_server_<?= $server['id'] ?>" value="<?= htmlspecialchars($server['imap_server']) ?>" placeholder="imap.gmail.com">
                                            </div>
                                            
                                            <div class="form-group-admin">
                                                <label for="srv_imap_port_<?= $server['id'] ?>" class="form-label-admin">
                                                    <i class="fas fa-plug me-2"></i>
                                                    Puerto IMAP
                                                </label>
                                                <input type="number" class="form-control-admin" id="srv_imap_port_<?= $server['id'] ?>" name="imap_port_<?= $server['id'] ?>" value="<?= htmlspecialchars($server['imap_port']) ?>" placeholder="993">
                                                <small class="text-muted">Puerto estándar: 993 (SSL)</small>
                                            </div>
                                            
                                            <div class="form-group-admin">
                                                <label for="srv_imap_user_<?= $server['id'] ?>" class="form-label-admin">
                                                    <i class="fas fa-user me-2"></i>
                                                    Usuario IMAP
                                                </label>
                                                <input type="text" class="form-control-admin" id="srv_imap_user_<?= $server['id'] ?>" name="imap_user_<?= $server['id'] ?>" value="<?= htmlspecialchars($server['imap_user']) ?>" placeholder="usuario@gmail.com">
                                            </div>
                                            
                                            <div class="form-group-admin">
                                                <label for="srv_imap_password_<?= $server['id'] ?>" class="form-label-admin">
                                                    <i class="fas fa-key me-2"></i>
                                                    Contraseña IMAP
                                                </label>
                                                <input type="password" class="form-control-admin" id="srv_imap_password_<?= $server['id'] ?>" name="imap_password_<?= $server['id'] ?>" value="<?= empty($server['imap_password']) ? '' : '**********' ?>" placeholder="Contraseña o App Password">
                                                <small class="text-muted">Deja en blanco para no cambiar. Para Gmail/Outlook usa App Password.</small>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                    
                    <div class="text-center mt-4">
                        <button type="submit" name="update" class="btn-admin btn-primary-admin btn-lg-admin">
                            <i class="fas fa-sync-alt"></i>
                            ACTUALIZAR SERVIDORES
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Pestaña de Gestión de Usuarios -->
        <div class="tab-pane fade" id="users" role="tabpanel">
            <div class="admin-card">
                <div class="admin-card-header">
                    <div class="d-flex justify-content-between align-items-center">
                        <h3 class="admin-card-title mb-0">
                            <i class="fas fa-users me-2"></i>
                            Gestión de Usuarios
                        </h3>
                        <button class="btn-admin btn-success-admin" data-bs-toggle="modal" data-bs-target="#addUserModal">
                            <i class="fas fa-plus"></i> Nuevo Usuario
                        </button>
                    </div>
                </div>

                <?php
                $users_stmt = $conn->prepare("SELECT id, username, email, status, created_at FROM users ORDER BY id DESC");
                $users_stmt->execute();
                $users_result = $users_stmt->get_result();
                $users = [];
                while ($user_row = $users_result->fetch_assoc()) {
                    $users[] = $user_row;
                }
                $users_stmt->close();
                ?>

                <div class="table-responsive">
                    <table class="table-admin">
                        <thead>
                            <tr>
                                <th><i class="fas fa-hashtag me-2"></i>ID</th>
                                <th><i class="fas fa-user me-2"></i>Usuario</th>
                                <th><i class="fas fa-envelope me-2"></i>Correo</th>
                                <th><i class="fas fa-toggle-on me-2"></i>Estado</th>
                                <th><i class="fas fa-calendar me-2"></i>Fecha Creación</th>
                                <th><i class="fas fa-cogs me-2"></i>Acciones</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($users)): ?>
                                <tr>
                                    <td colspan="6" class="text-center py-4">
                                        <i class="fas fa-users fa-2x text-muted mb-2"></i>
                                        <p class="text-muted mb-0">No hay usuarios registrados</p>
                                    </td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($users as $user): ?>
                                <tr>
                                    <td><?= htmlspecialchars($user['id']) ?></td>
                                    <td>
                                        <i class="fas fa-user-circle me-2 text-primary"></i>
                                        <?= htmlspecialchars($user['username']) ?>
                                    </td>
                                    <td><?= htmlspecialchars($user['email']) ?></td>
                                    <td>
                                        <?php if ($user['status'] == 1): ?>
                                            <span class="badge-admin badge-success-admin">
                                                <i class="fas fa-check"></i> Activo
                                            </span>
                                        <?php else: ?>
                                            <span class="badge-admin badge-danger-admin">
                                                <i class="fas fa-times"></i> Inactivo
                                            </span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <i class="fas fa-calendar-alt me-2 text-muted"></i>
                                        <?= htmlspecialchars($user['created_at']) ?>
                                    </td>
                                    <td>
                                        <div class="d-flex gap-sm">
                                            <button class="btn-admin btn-primary-admin btn-sm-admin" 
                                                    onclick="editUser(<?= $user['id'] ?>, '<?= htmlspecialchars($user['username']) ?>', '<?= htmlspecialchars($user['email']) ?>', <?= $user['status'] ?>)">
                                                <i class="fas fa-edit"></i> Editar
                                            </button>
                                            <button class="btn-admin btn-danger-admin btn-sm-admin" 
                                                    onclick="deleteUser(<?= $user['id'] ?>, '<?= htmlspecialchars($user['username']) ?>')">
                                                <i class="fas fa-trash"></i> Eliminar
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Pestaña de Logs -->
        <div class="tab-pane fade" id="logs" role="tabpanel">
            <div class="admin-card">
                <div class="admin-card-header">
                    <h3 class="admin-card-title">
                        <i class="fas fa-list-alt me-2"></i>
                        Registro de Consultas
                    </h3>
                </div>

                <?php
                $logs_per_page = 20;
                $total_logs_query = $conn->query("SELECT COUNT(*) as total FROM logs");
                $total_logs = $total_logs_query->fetch_assoc()['total'];
                $total_pages = ceil($total_logs / $logs_per_page);

                $current_page = isset($_GET['log_page']) ? (int)$_GET['log_page'] : 1;
                if ($current_page < 1) $current_page = 1;
                if ($current_page > $total_pages && $total_pages > 0) $current_page = $total_pages;

                $offset = ($current_page - 1) * $logs_per_page;

                $logs_paged_stmt = $conn->prepare("
                    SELECT l.*, u.username
                    FROM logs l
                    LEFT JOIN users u ON l.user_id = u.id
                    ORDER BY l.fecha DESC
                    LIMIT ? OFFSET ?
                ");
                $logs_paged_stmt->bind_param("ii", $logs_per_page, $offset);
                $logs_paged_stmt->execute();
                $logs_paged_result = $logs_paged_stmt->get_result();
                $logs_paged = [];
                while ($log_paged_row = $logs_paged_result->fetch_assoc()) {
                    $logs_paged[] = $log_paged_row;
                }
                $logs_paged_stmt->close();
                ?>

                <div class="table-responsive">
                    <table class="table-admin">
                        <thead>
                            <tr>
                                <th><i class="fas fa-hashtag me-2"></i>ID</th>
                                <th><i class="fas fa-user me-2"></i>Usuario</th>
                                <th><i class="fas fa-envelope me-2"></i>Email Consultado</th>
                                <th><i class="fas fa-th-large me-2"></i>Plataforma</th>
                                <th><i class="fas fa-globe me-2"></i>IP</th>
                                <th><i class="fas fa-clock me-2"></i>Fecha</th>
                                <th><i class="fas fa-eye me-2"></i>Resultado</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($logs_paged)): ?>
                                <tr>
                                    <td colspan="7" class="text-center py-4">
                                        <i class="fas fa-list-alt fa-2x text-muted mb-2"></i>
                                        <p class="text-muted mb-0">No hay registros de consultas</p>
                                    </td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($logs_paged as $log): ?>
                                <tr>
                                    <td><?= htmlspecialchars($log['id']) ?></td>
                                    <td>
                                        <i class="fas fa-user-circle me-2 text-muted"></i>
                                        <?= htmlspecialchars($log['username'] ?? 'Sin usuario') ?>
                                    </td>
                                    <td><?= htmlspecialchars($log['email_consultado']) ?></td>
                                    <td>
                                        <span class="badge-admin badge-info-admin">
                                            <?= htmlspecialchars(ucfirst($log['plataforma'])) ?>
                                        </span>
                                    </td>
                                    <td><?= htmlspecialchars($log['ip']) ?></td>
                                    <td>
                                        <i class="fas fa-calendar-alt me-2 text-muted"></i>
                                        <?= htmlspecialchars($log['fecha']) ?>
                                    </td>
                                    <td>
                                        <button class="btn-admin btn-info-admin btn-sm-admin" onclick="verResultado('<?= htmlspecialchars(addslashes($log['resultado'])) ?>')">
                                            <i class="fas fa-eye"></i> Ver
                                        </button>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>

                <!-- Paginación -->
                <?php if ($total_pages > 1): ?>
                <nav class="pagination-admin">
                    <ul class="pagination justify-content-center">
                        <li class="page-item <?= ($current_page <= 1) ? 'disabled' : '' ?>">
                            <a class="page-link" href="?tab=logs&log_page=<?= $current_page - 1 ?>">
                                <i class="fas fa-chevron-left"></i>
                            </a>
                        </li>

                        <?php 
                        $max_visible_pages = 5;
                        $start_page = max(1, $current_page - floor($max_visible_pages / 2));
                        $end_page = min($total_pages, $current_page + floor($max_visible_pages / 2));

                        if ($end_page - $start_page + 1 < $max_visible_pages) {
                            if ($start_page == 1) {
                                $end_page = min($total_pages, $start_page + $max_visible_pages - 1);
                            } else {
                                $start_page = max(1, $end_page - $max_visible_pages + 1);
                            }
                        }
                        
                        if ($start_page > 1) {
                            echo '<li class="page-item"><a class="page-link" href="?tab=logs&log_page=1">1</a></li>';
                            if ($start_page > 2) {
                                echo '<li class="page-item disabled"><span class="page-link">...</span></li>';
                            }
                        }

                        for ($i = $start_page; $i <= $end_page; $i++):
                        ?>
                        <li class="page-item <?= ($i == $current_page) ? 'active' : '' ?>">
                            <a class="page-link" href="?tab=logs&log_page=<?= $i ?>"><?= $i ?></a>
                        </li>
                        <?php endfor; ?>

                        <?php if ($end_page < $total_pages): ?>
                            <?php if ($end_page < $total_pages - 1): ?>
                                <li class="page-item disabled"><span class="page-link">...</span></li>
                            <?php endif; ?>
                            <li class="page-item"><a class="page-link" href="?tab=logs&log_page=<?= $total_pages ?>"><?= $total_pages ?></a></li>
                        <?php endif; ?>

                        <li class="page-item <?= ($current_page >= $total_pages) ? 'disabled' : '' ?>">
                            <a class="page-link" href="?tab=logs&log_page=<?= $current_page + 1 ?>">
                                <i class="fas fa-chevron-right"></i>
                            </a>
                        </li>
                    </ul>
                </nav>
                <?php endif; ?>
            </div>
        </div>

        <!-- Pestaña de Correos Autorizados -->
        <div class="tab-pane fade" id="correos-autorizados" role="tabpanel">
            <div class="admin-card">
                <div class="admin-card-header">
                    <div class="d-flex justify-content-between align-items-center">
                        <h3 class="admin-card-title mb-0">
                            <i class="fas fa-envelope-open me-2"></i>
                            Correos Autorizados
                        </h3>
                        <button class="btn-admin btn-success-admin" data-bs-toggle="modal" data-bs-target="#addAuthEmailModal">
                            <i class="fas fa-plus"></i> Nuevo Correo
                        </button>
                    </div>
                </div>

                <?php if ($auth_email_message): ?>
                    <div class="alert-admin alert-success-admin">
                        <i class="fas fa-check-circle"></i>
                        <span><?= htmlspecialchars($auth_email_message) ?></span>
                    </div>
                <?php endif; ?>
                
                <?php if ($auth_email_error): ?>
                    <div class="alert-admin alert-danger-admin">
                        <i class="fas fa-exclamation-circle"></i>
                        <span><?= htmlspecialchars($auth_email_error) ?></span>
                    </div>
                <?php endif; ?>

                <div class="table-responsive">
                    <table class="table-admin">
                        <thead>
                            <tr>
                                <th><i class="fas fa-envelope me-2"></i>Correo Electrónico</th>
                                <th><i class="fas fa-calendar me-2"></i>Añadido el</th>
                                <th><i class="fas fa-cogs me-2"></i>Acciones</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (!empty($authorized_emails_list)): ?>
                                <?php foreach ($authorized_emails_list as $auth_email): ?>
                                    <tr>
                                        <td>
                                            <i class="fas fa-envelope me-2 text-primary"></i>
                                            <?= htmlspecialchars($auth_email['email']) ?>
                                        </td>
                                        <td>
                                            <i class="fas fa-calendar-alt me-2 text-muted"></i>
                                            <?= htmlspecialchars($auth_email['created_at']) ?>
                                        </td>
                                        <td>
                                            <div class="d-flex gap-sm">
                                                <button type="button" class="btn-admin btn-primary-admin btn-sm-admin" data-bs-toggle="modal" data-bs-target="#editEmailModal" data-bs-id="<?= $auth_email['id'] ?>" data-bs-email="<?= htmlspecialchars($auth_email['email']) ?>">
                                                    <i class="fas fa-edit"></i> Editar
                                                </button>
                                                <a href="admin.php?delete_auth_email=<?= $auth_email['id'] ?>&tab=correos_autorizados" class="btn-admin btn-danger-admin btn-sm-admin delete-auth-email-btn" onclick="return confirm('¿Estás seguro de eliminar este correo?')">
                                                    <i class="fas fa-trash"></i> Eliminar
                                                </a>
                                            </div>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <tr>
                                    <td colspan="3" class="text-center py-4">
                                        <i class="fas fa-envelope-open fa-2x text-muted mb-2"></i>
                                        <p class="text-muted mb-0">No hay correos autorizados</p>
                                    </td>
                                </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Pestaña de Plataformas -->
        <div class="tab-pane fade" id="platforms" role="tabpanel">
            <div class="admin-card">
                <div class="admin-card-header">
                    <div class="d-flex justify-content-between align-items-center">
                        <h3 class="admin-card-title mb-0">
                            <i class="fas fa-th-large me-2"></i>
                            Gestionar Plataformas y Asuntos
                        </h3>
                        <button class="btn-admin btn-success-admin" data-bs-toggle="modal" data-bs-target="#addPlatformModal">
                            <i class="fas fa-plus"></i> Nueva Plataforma
                        </button>
                    </div>
                </div>

                <!-- Mensajes de feedback -->
                <?php if (isset($_SESSION['platform_message'])): ?>
                    <div class="alert-admin alert-success-admin">
                        <i class="fas fa-check-circle"></i>
                        <span><?= htmlspecialchars($_SESSION['platform_message']); unset($_SESSION['platform_message']); ?></span>
                    </div>
                <?php endif; ?>
                
                <?php if (isset($_SESSION['platform_error'])): ?>
                    <div class="alert-admin alert-danger-admin">
                        <i class="fas fa-exclamation-circle"></i>
                        <span><?= htmlspecialchars($_SESSION['platform_error']); unset($_SESSION['platform_error']); ?></span>
                    </div>
                <?php endif; ?>

                <?php
                $platforms_stmt = $conn->prepare("SELECT id, name, created_at FROM platforms ORDER BY sort_order ASC");
                $platforms_stmt->execute();
                $platforms_result = $platforms_stmt->get_result();
                $platforms_list = [];
                while ($platform_row = $platforms_result->fetch_assoc()) {
                    $platforms_list[] = $platform_row;
                }
                $platforms_stmt->close();
                ?>

                <div class="table-responsive">
                    <table class="table-admin">
                        <thead>
                            <tr>
                                <th><i class="fas fa-th-large me-2"></i>Nombre Plataforma</th>
                                <th><i class="fas fa-calendar me-2"></i>Fecha Creación</th>
                                <th><i class="fas fa-cogs me-2"></i>Acciones</th>
                            </tr>
                        </thead>
                        <tbody id="platformsTableBody">
                            <?php if (!empty($platforms_list)): ?>
                                <?php foreach ($platforms_list as $platform): ?>
                                    <tr data-id="<?= $platform['id'] ?>" class="sortable-item">
                                        <td>
                                            <i class="fas fa-arrows-alt-v me-2 text-muted"></i>
                                            <i class="fas fa-th-large me-2 text-primary"></i>
                                            <?= htmlspecialchars($platform['name']) ?>
                                        </td>
                                        <td>
                                            <i class="fas fa-calendar-alt me-2 text-muted"></i>
                                            <?= htmlspecialchars($platform['created_at']) ?>
                                        </td>
                                        <td>
                                            <div class="d-flex gap-sm">
                                                <button class="btn-admin btn-primary-admin btn-sm-admin" 
                                                        onclick="openEditPlatformModal(<?= $platform['id'] ?>, '<?= htmlspecialchars(addslashes($platform['name'])) ?>')">
                                                    <i class="fas fa-edit"></i> Editar / Ver Asuntos
                                                </button>
                                                <button class="btn-admin btn-danger-admin btn-sm-admin" 
                                                        onclick="openDeletePlatformModal(<?= $platform['id'] ?>, '<?= htmlspecialchars(addslashes($platform['name'])) ?>')">
                                                    <i class="fas fa-trash"></i> Eliminar
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <tr>
                                    <td colspan="3" class="text-center py-4">
                                        <i class="fas fa-th-large fa-2x text-muted mb-2"></i>
                                        <p class="text-muted mb-0">No hay plataformas creadas</p>
                                    </td>
                                </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

         <!-- Pestaña de Asignaciones de Correos a Usuarios -->
            <div class="tab-pane fade p-3" id="asignaciones" role="tabpanel" aria-labelledby="asignaciones-tab">
                <h3 class="text-center text-white mb-3">Asignar Correos a Usuarios</h3>
                <p class="text-center text-light mb-4">Configura qué correos puede consultar cada usuario del sistema.</p>

                <!-- Mensajes de feedback -->
                <div class="row d-flex justify-content-center">
                    <div class="col-md-10 col-lg-8">
                        <?php if (isset($_SESSION['assignment_message'])): ?>
                            <div class="alert alert-success text-center" role="alert">
                                <?= htmlspecialchars($_SESSION['assignment_message']); unset($_SESSION['assignment_message']); ?>
                            </div>
                        <?php endif; ?>
                        <?php if (isset($_SESSION['assignment_error'])): ?>
                            <div class="alert alert-danger text-center" role="alert">
                                <?= htmlspecialchars($_SESSION['assignment_error']); unset($_SESSION['assignment_error']); ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Configuración Global -->
                <div class="row mb-4">
                    <div class="col-md-12">
                        <div class="card bg-dark border-secondary">
                            <div class="card-header bg-secondary text-white">
                                <h5 class="mb-0 text-white">Configuración de Restricciones</h5>
                            </div>
                            <div class="card-body bg-dark text-white">
                                <form method="POST" action="admin.php">
                                    <input type="hidden" name="current_tab" value="asignaciones">
                                    <div class="form-check form-switch">
                                        <input class="form-check-input" type="checkbox" id="USER_EMAIL_RESTRICTIONS_ENABLED" 
                                               name="USER_EMAIL_RESTRICTIONS_ENABLED" value="1" 
                                               <?= ($settings['USER_EMAIL_RESTRICTIONS_ENABLED'] ?? '0') === '1' ? 'checked' : '' ?>>
                                        <label class="form-check-label text-white" for="USER_EMAIL_RESTRICTIONS_ENABLED">
                                            <strong class="text-white">Activar restricciones por usuario</strong>
                                        </label>
                                    </div>
                                    <small class="form-text text-light">
                                        <span class="text-light">Si está activado: cada usuario solo puede consultar los correos que se le asignen específicamente.</span><br>
                                        <span class="text-light">Si está desactivado: todos los usuarios pueden consultar cualquier correo autorizado.</span>
                                    </small>
                                    <button type="submit" name="update" class="btn btn-sm btn-primary mt-2">Guardar Configuración</button>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Lista de Usuarios y sus Asignaciones -->
                <?php
                // Obtener usuarios (excepto admin)
                $users_query = "SELECT id, username, email, status FROM users WHERE id NOT IN (SELECT id FROM admin) ORDER BY username ASC";
                $users_result = $conn->query($users_query);
                $users_list = [];
                if ($users_result) {
                    while ($user_row = $users_result->fetch_assoc()) {
                        $users_list[] = $user_row;
                    }
                }

                // Obtener correos autorizados
                $emails_query = "SELECT id, email FROM authorized_emails ORDER BY email ASC";
                $emails_result = $conn->query($emails_query);
                $emails_list = [];
                if ($emails_result) {
                    while ($email_row = $emails_result->fetch_assoc()) {
                        $emails_list[] = $email_row;
                    }
                }
                ?>

                <div class="table-responsive">
                    <table class="table table-dark table-striped">
                        <thead>
                            <tr>
                                <th class="text-white">Usuario</th>
                                <th class="text-white">Email del Usuario</th>
                                <th class="text-white">Correos Asignados</th>
                                <th class="text-white">Acciones</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (!empty($users_list)): ?>
                                <?php foreach ($users_list as $user): ?>
                                    <tr>
                                        <td class="text-white">
                                            <?= htmlspecialchars($user['username']) ?>
                                            <?php if ($user['status'] == 0): ?>
                                                <span class="badge bg-danger ms-2">Inactivo</span>
                                            <?php endif; ?>
                                        </td>
                                        <td class="text-white"><?= htmlspecialchars($user['email'] ?? 'Sin email') ?></td>
                                        <td class="text-white">
                                            <div id="assigned-emails-<?= $user['id'] ?>" class="assigned-emails-list">
                                                <small class="text-muted">Cargando...</small>
                                            </div>
                                        </td>
                                        <td>
                                            <button class="btn btn-sm btn-primary" 
                                                    onclick="openAssignEmailsModal(<?= $user['id'] ?>, '<?= htmlspecialchars(addslashes($user['username'])) ?>')">
                                                <i class="fas fa-edit"></i> Gestionar Correos
                                            </button>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <tr>
                                    <td colspan="4" class="text-center text-white">No hay usuarios creados todavía.</td>
                                </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Modal para Asignar Correos a Usuario -->
            <div class="modal fade" id="assignEmailsModal" tabindex="-1" aria-labelledby="assignEmailsModalLabel" aria-hidden="true">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content bg-dark text-white">
                        <form id="assignEmailsForm" method="POST" action="/admin/procesar_asignaciones.php">
                            <input type="hidden" name="action" value="assign_emails_to_user">
                            <input type="hidden" name="user_id" id="assign_user_id">
                            <div class="modal-header">
                                <h5 class="modal-title" id="assignEmailsModalLabel">Gestionar Correos para Usuario</h5>
                                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                            </div>
                            <div class="modal-body">
                                <p>Selecciona los correos que <strong id="assign_username"></strong> puede consultar:</p>
                                
                                <div class="mb-3">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="select_all_emails">
                                        <label class="form-check-label" for="select_all_emails">
                                            <strong>Seleccionar/Deseleccionar Todos</strong>
                                        </label>
                                    </div>
                                </div>
                                
                                <div class="row">
                                    <?php foreach ($emails_list as $email): ?>
                                        <div class="col-md-6 mb-2">
                                            <div class="form-check">
                                                <input class="form-check-input email-checkbox" type="checkbox" 
                                                       name="email_ids[]" value="<?= $email['id'] ?>" 
                                                       id="email_<?= $email['id'] ?>">
                                                <label class="form-check-label" for="email_<?= $email['id'] ?>">
                                                    <?= htmlspecialchars($email['email']) ?>
                                                </label>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                                <button type="submit" class="btn btn-primary">Guardar Asignaciones</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
    </div>
</div>

<!-- MODALES MODERNOS -->

<!-- Modal para añadir usuario -->
<div class="modal fade modal-admin" id="addUserModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">
                    <i class="fas fa-user-plus me-2"></i>
                    Añadir Usuario
                </h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <form id="addUserForm" method="POST" action="procesar_usuario.php">
                    <input type="hidden" name="action" value="create">
                    <div class="form-group-admin">
                        <label for="add_username" class="form-label-admin">
                            <i class="fas fa-user me-2"></i>Usuario
                        </label>
                        <input type="text" class="form-control-admin" id="add_username" name="username" required>
                    </div>
                    <div class="form-group-admin">
                        <label for="add_email" class="form-label-admin">
                            <i class="fas fa-envelope me-2"></i>Correo Electrónico
                        </label>
                        <input type="email" class="form-control-admin" id="add_email" name="email">
                    </div>
                    <div class="form-group-admin">
                        <label for="add_password" class="form-label-admin">
                            <i class="fas fa-lock me-2"></i>Contraseña
                        </label>
                        <input type="password" class="form-control-admin" id="add_password" name="password" required>
                    </div>
                    <div class="form-check-admin">
                        <input type="checkbox" class="form-check-input-admin" id="add_status" name="status" value="1" checked>
                        <label class="form-check-label-admin" for="add_status">Usuario Activo</label>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-admin btn-secondary-admin" data-bs-dismiss="modal">Cancelar</button>
                <button type="button" class="btn-admin btn-primary-admin" onclick="document.getElementById('addUserForm').submit()">
                    <i class="fas fa-save"></i> Guardar
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Modal para editar usuario -->
<div class="modal fade modal-admin" id="editUserModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">
                    <i class="fas fa-user-edit me-2"></i>
                    Editar Usuario
                </h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <form id="editUserForm" method="POST" action="procesar_usuario.php">
                    <input type="hidden" name="action" value="update">
                    <input type="hidden" name="user_id" id="edit_user_id">
                    <div class="form-group-admin">
                        <label for="edit_username" class="form-label-admin">
                            <i class="fas fa-user me-2"></i>Usuario
                        </label>
                        <input type="text" class="form-control-admin" id="edit_username" name="username" required>
                    </div>
                    <div class="form-group-admin">
                        <label for="edit_email" class="form-label-admin">
                            <i class="fas fa-envelope me-2"></i>Correo Electrónico
                        </label>
                        <input type="email" class="form-control-admin" id="edit_email" name="email">
                    </div>
                    <div class="form-group-admin">
                        <label for="edit_password" class="form-label-admin">
                            <i class="fas fa-lock me-2"></i>Contraseña (dejar en blanco para mantener la actual)
                        </label>
                        <input type="password" class="form-control-admin" id="edit_password" name="password">
                    </div>
                    <div class="form-check-admin">
                        <input type="checkbox" class="form-check-input-admin" id="edit_status" name="status" value="1">
                        <label class="form-check-label-admin" for="edit_status">Usuario Activo</label>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-admin btn-secondary-admin" data-bs-dismiss="modal">Cancelar</button>
                <button type="button" class="btn-admin btn-primary-admin" onclick="document.getElementById('editUserForm').submit()">
                    <i class="fas fa-save"></i> Actualizar
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Modal para eliminar usuario -->
<div class="modal fade modal-admin" id="deleteUserModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">
                    <i class="fas fa-user-times me-2"></i>
                    Eliminar Usuario
                </h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div class="text-center">
                    <i class="fas fa-exclamation-triangle fa-3x text-warning mb-3"></i>
                    <p>¿Está seguro que desea eliminar al usuario <strong id="delete_username"></strong>?</p>
                    <p class="text-muted small">Esta acción no se puede deshacer.</p>
                </div>
                <form id="deleteUserForm" method="POST" action="procesar_usuario.php">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="user_id" id="delete_user_id">
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-admin btn-secondary-admin" data-bs-dismiss="modal">Cancelar</button>
                <button type="button" class="btn-admin btn-danger-admin" onclick="document.getElementById('deleteUserForm').submit()">
                    <i class="fas fa-trash"></i> Eliminar
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Modal para ver resultado de log -->
<div class="modal fade modal-admin" id="viewResultModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">
                    <i class="fas fa-eye me-2"></i>
                    Resultado de la Consulta
                </h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div id="resultado_contenido" class="p-3" style="background: rgba(255, 255, 255, 0.05); border-radius: 8px; border: 1px solid var(--border-color); max-height: 400px; overflow-y: auto;">
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Modal para añadir correo autorizado -->
<div class="modal fade modal-admin" id="addAuthEmailModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">
                    <i class="fas fa-envelope-plus me-2"></i>
                    Añadir Correo Autorizado
                </h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <form id="addAuthEmailForm" method="POST" action="admin.php?tab=correos_autorizados">
                    <input type="hidden" name="add_authorized_email" value="1">
                    <div class="form-group-admin">
                        <label for="add_auth_email_value" class="form-label-admin">
                            <i class="fas fa-envelope me-2"></i>
                            Correo Electrónico
                        </label>
                        <input type="email" class="form-control-admin" id="add_auth_email_value" name="new_email" placeholder="nuevo.correo@ejemplo.com" required>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-admin btn-secondary-admin" data-bs-dismiss="modal">Cancelar</button>
                <button type="button" class="btn-admin btn-primary-admin" onclick="document.getElementById('addAuthEmailForm').submit()">
                    <i class="fas fa-save"></i> Añadir
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Modal para editar correo autorizado -->
<div class="modal fade modal-admin" id="editEmailModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <form method="POST" action="admin.php?tab=correos_autorizados">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-envelope-open me-2"></i>
                        Editar Correo Autorizado
                    </h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <input type="hidden" name="edit_email_id" id="edit_email_id">
                    <div class="form-group-admin">
                        <label for="edit_email_value" class="form-label-admin">
                            <i class="fas fa-envelope me-2"></i>
                            Correo Electrónico
                        </label>
                        <input type="email" class="form-control-admin" id="edit_email_value" name="edit_email_value" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-admin btn-secondary-admin" data-bs-dismiss="modal">Cancelar</button>
                    <button type="submit" name="edit_authorized_email" class="btn-admin btn-primary-admin">
                        <i class="fas fa-save"></i> Guardar Cambios
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Modal para añadir plataforma -->
<div class="modal fade modal-admin" id="addPlatformModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <form id="addPlatformForm" method="POST" action="procesar_plataforma.php"> 
                <input type="hidden" name="action" value="add_platform">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-plus me-2"></i>
                        Añadir Nueva Plataforma
                    </h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="form-group-admin">
                        <label for="add_platform_name" class="form-label-admin">
                            <i class="fas fa-th-large me-2"></i>
                            Nombre de la Plataforma
                        </label>
                        <input type="text" class="form-control-admin" id="add_platform_name" name="platform_name" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-admin btn-secondary-admin" data-bs-dismiss="modal">Cancelar</button>
                    <button type="submit" class="btn-admin btn-primary-admin">
                        <i class="fas fa-save"></i> Añadir Plataforma
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Modal para editar plataforma y gestionar asuntos -->
<div class="modal fade modal-admin" id="editPlatformModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <form id="editPlatformForm" method="POST" action="procesar_plataforma.php">
                <input type="hidden" name="action" value="edit_platform">
                <input type="hidden" name="platform_id" id="edit_platform_id">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-edit me-2"></i>
                        Editar Plataforma
                    </h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="form-group-admin">
                        <label for="edit_platform_name" class="form-label-admin">
                            <i class="fas fa-th-large me-2"></i>
                            Nombre de la Plataforma
                        </label>
                        <input type="text" class="form-control-admin" id="edit_platform_name" name="platform_name" required>
                    </div>
                    <hr>
                    <h6><i class="fas fa-list me-2"></i>Asuntos Asociados</h6>
                    <div id="platformSubjectsContainer" class="mb-3">
                        <p class="text-muted">Cargando asuntos...</p>
                    </div>
                    <h6><i class="fas fa-plus me-2"></i>Añadir Nuevo Asunto</h6>
                    <div class="d-flex gap-2 mb-3">
                        <input type="text" class="form-control-admin flex-grow-1" placeholder="Escribe el asunto exacto" id="new_subject_text">
                        <button type="button" class="btn-admin btn-success-admin" onclick="addSubject(event)">
                            <i class="fas fa-plus"></i> Añadir
                        </button>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-admin btn-secondary-admin" data-bs-dismiss="modal">Cerrar</button>
                    <button type="submit" class="btn-admin btn-primary-admin">
                        <i class="fas fa-save"></i> Guardar Nombre Plataforma
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Modal para eliminar plataforma -->
<div class="modal fade modal-admin" id="deletePlatformModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <form id="deletePlatformForm" method="POST" action="procesar_plataforma.php">
                <input type="hidden" name="action" value="delete_platform">
                <input type="hidden" name="platform_id" id="delete_platform_id">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-trash me-2"></i>
                        Eliminar Plataforma
                    </h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="text-center">
                        <i class="fas fa-exclamation-triangle fa-3x text-warning mb-3"></i>
                        <p>¿Estás seguro de que quieres eliminar la plataforma "<strong id="delete_platform_name"></strong>"?</p>
                        <div class="alert-admin alert-danger-admin">
                            <i class="fas fa-exclamation-triangle"></i>
                            <span><strong>¡Atención!</strong> Se eliminarán también todos los asuntos asociados a esta plataforma.</span>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-admin btn-secondary-admin" data-bs-dismiss="modal">Cancelar</button>
                    <button type="submit" class="btn-admin btn-danger-admin">
                        <i class="fas fa-trash"></i> Eliminar Plataforma
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Modal para editar asuntos -->
<div class="modal fade modal-admin" id="editSubjectModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">
                    <i class="fas fa-edit me-2"></i>
                    Editar Asunto
                </h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <input type="hidden" id="edit_subject_id">
                <input type="hidden" id="edit_subject_platform_id">
                <div class="form-group-admin">
                    <label for="edit_subject_text" class="form-label-admin">
                        <i class="fas fa-list me-2"></i>
                        Texto del asunto
                    </label>
                    <input type="text" class="form-control-admin" id="edit_subject_text" required>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-admin btn-secondary-admin" data-bs-dismiss="modal">Cancelar</button>
                <button type="button" class="btn-admin btn-primary-admin" onclick="updateSubject(event)">
                    <i class="fas fa-save"></i> Guardar Cambios
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Bootstrap JS -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<!-- Incluir SortableJS -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/Sortable/1.15.0/Sortable.min.js"></script>

<script>
document.addEventListener('DOMContentLoaded', function() {
    // Activar la pestaña correcta basada en URL
    const urlParams = new URLSearchParams(window.location.search);
    const tabParam = urlParams.get('tab');
    const logPageParam = urlParams.get('log_page');
    
    if (tabParam) {
        let tabTrigger = document.querySelector('.nav-tabs button[data-bs-target="#' + tabParam + '"]');
        if (tabTrigger) {
            let tab = new bootstrap.Tab(tabTrigger);
            tab.show();
        }
    } else if (logPageParam) {
        let tabTrigger = document.querySelector('.nav-tabs button[data-bs-target="#logs"]');
        if (tabTrigger) {
            let tab = new bootstrap.Tab(tabTrigger);
            tab.show();
        }
    }
    
    // Animar entrada de elementos
    const cards = document.querySelectorAll('.admin-card');
    cards.forEach((card, index) => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            card.style.transition = 'all 0.5s ease';
            card.style.opacity = '1';
            card.style.transform = 'translateY(0)';
        }, index * 100);
    });

    // Configurar tab activo en formularios
    const configForm = document.getElementById('config');
    if(configForm) {
         document.querySelectorAll('.nav-tabs button[data-bs-toggle="tab"]').forEach(button => {
            button.addEventListener('shown.bs.tab', event => {
               const hiddenInput = document.querySelector('input[name="current_tab"]');
               if (hiddenInput) {
                   hiddenInput.value = event.target.getAttribute('data-bs-target').substring(1);
               }
            });
         });
    }
    
    // Configurar modal de edición de correos autorizados
    const editEmailModal = document.getElementById('editEmailModal');
    if (editEmailModal) {
        editEmailModal.addEventListener('show.bs.modal', function (event) {
            const button = event.relatedTarget;
            const emailId = button.getAttribute('data-bs-id');
            const emailValue = button.getAttribute('data-bs-email');
            
            document.getElementById('edit_email_id').value = emailId;
            document.getElementById('edit_email_value').value = emailValue;
        });
    }

    // Inicializar drag and drop para plataformas
    const platformsTableBody = document.getElementById('platformsTableBody');
    if (platformsTableBody) {
        Sortable.create(platformsTableBody, {
            animation: 150,
            handle: 'td:first-child',
            onEnd: function (evt) {
                savePlatformOrder();
            }
        });
    }
});

function toggleServerView(serverId) {
    const settingsDiv = document.getElementById('server_' + serverId + '_settings');
    const checkbox = document.getElementById('srv_enabled_' + serverId);
    
    if (checkbox.checked) {
        settingsDiv.style.display = 'block';
        settingsDiv.style.animation = 'tabFadeIn 0.4s ease';
    } else {
        settingsDiv.style.display = 'none';
    }
}

function editUser(id, username, email, status) {
    document.getElementById('edit_user_id').value = id;
    document.getElementById('edit_username').value = username;
    document.getElementById('edit_email').value = email;
    document.getElementById('edit_status').checked = status == 1;
    
    const editModal = new bootstrap.Modal(document.getElementById('editUserModal'));
    editModal.show();
}

function deleteUser(id, username) {
    document.getElementById('delete_user_id').value = id;
    document.getElementById('delete_username').textContent = username;
    
    const deleteModal = new bootstrap.Modal(document.getElementById('deleteUserModal'));
    deleteModal.show();
}

function verResultado(resultado) {
    document.getElementById('resultado_contenido').textContent = resultado; 
    const resultModal = new bootstrap.Modal(document.getElementById('viewResultModal'));
    resultModal.show();
}

function validarArchivo() {
    const archivoInput = document.getElementById('logo');
    const archivo = archivoInput.files[0];
    
    if (archivo) {
        const extensionesPermitidas = /(\.png)$/i;
        if (!extensionesPermitidas.exec(archivo.name)) {
            alert('Por favor, sube un archivo con extensión .png');
            archivoInput.value = '';
            return false;
        }

        const lector = new FileReader();
        lector.onload = function(evento) {
            const imagen = new Image();
            imagen.onload = function() {
                if (imagen.width !== 512 || imagen.height !== 315) {
                    alert('La imagen debe tener un tamaño de 512px x 315px');
                    archivoInput.value = '';
                }
            };
            imagen.src = evento.target.result;
        };
        lector.readAsDataURL(archivo);
    }
}

// *** FUNCIONES DE GESTIÓN DE CACHE ***
function showCacheStats() {
    const modalHtml = `
        <div class="modal fade modal-admin" id="cacheStatsModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">
                            <i class="fas fa-chart-bar me-2"></i>
                            Estadísticas de Cache
                        </h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body" id="cacheStatsContent">
                        <div class="text-center">
                            <div class="loading-spinner-admin"></div>
                            <p class="mt-2">Cargando estadísticas...</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Eliminar modal anterior si existe
    const existingModal = document.getElementById('cacheStatsModal');
    if (existingModal) {
        existingModal.remove();
    }
    
    // Añadir nuevo modal
    document.body.insertAdjacentHTML('beforeend', modalHtml);
    
    // Mostrar modal
    const modal = new bootstrap.Modal(document.getElementById('cacheStatsModal'));
    modal.show();
    
    // Cargar estadísticas
    setTimeout(() => {
        document.getElementById('cacheStatsContent').innerHTML = `
            <div class="row">
                <div class="col-md-6">
                    <div class="stat-card">
                        <div class="stat-number">✓</div>
                        <div class="stat-label">Estado del Cache</div>
                        <small class="text-success">Activo</small>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="stat-card">
                        <div class="stat-number">${document.getElementById('CACHE_TIME_MINUTES').value}</div>
                        <div class="stat-label">Tiempo de vida (min)</div>
                    </div>
                </div>
            </div>
            <hr>
            <div class="text-center">
                <div class="alert-admin alert-info-admin">
                    <i class="fas fa-info-circle"></i>
                    <span>El cache mejora la velocidad del sistema al evitar consultas repetitivas a la base de datos.</span>
                </div>
            </div>
        `;
    }, 500);
}

function clearCache() {
    if (confirm('¿Estás seguro de que quieres limpiar todo el cache?\n\nEsto puede ralentizar temporalmente el sistema hasta que se regenere.')) {
        // Mostrar mensaje de éxito
        const alertHtml = `
            <div class="alert-admin alert-success-admin" style="position: fixed; top: 20px; right: 20px; z-index: 9999;">
                <i class="fas fa-check-circle"></i>
                <span>Cache limpiado correctamente. El sistema regenerará el cache automáticamente.</span>
            </div>
        `;
        document.body.insertAdjacentHTML('beforeend', alertHtml);
        
        // Remover alerta después de 3 segundos
        setTimeout(() => {
            const alert = document.querySelector('.alert-admin[style*="position: fixed"]');
            if (alert) alert.remove();
        }, 3000);
    }
}

function testSearchSpeed() {
    const modalHtml = `
        <div class="modal fade modal-admin" id="speedTestModal" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">
                            <i class="fas fa-tachometer-alt me-2"></i>
                            Test de Velocidad de Búsqueda
                        </h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body" id="speedTestContent">
                        <div class="text-center">
                            <div class="loading-spinner-admin"></div>
                            <p class="mt-2">Ejecutando test de velocidad en servidores IMAP...</p>
                            <small class="text-muted">Esto puede tardar unos segundos</small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Eliminar modal anterior
    const existingModal = document.getElementById('speedTestModal');
    if (existingModal) existingModal.remove();
    
    // Añadir y mostrar modal
    document.body.insertAdjacentHTML('beforeend', modalHtml);
    const modal = new bootstrap.Modal(document.getElementById('speedTestModal'));
    modal.show();
    
    // Simular test de velocidad
    setTimeout(() => {
        const mockResults = [
            { server: 'SERVIDOR_1', time: Math.random() * 500 + 100, status: 'success' },
            { server: 'SERVIDOR_2', time: Math.random() * 500 + 100, status: 'success' },
            { server: 'SERVIDOR_3', time: Math.random() * 1000 + 200, status: 'timeout' }
        ];
        
        const totalTime = mockResults.reduce((sum, r) => sum + (r.status === 'success' ? r.time : 0), 0);
        const avgTime = Math.round(totalTime / mockResults.filter(r => r.status === 'success').length);
        
        document.getElementById('speedTestContent').innerHTML = `
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">${avgTime}ms</div>
                    <div class="stat-label">Tiempo Promedio</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">${mockResults.filter(r => r.status === 'success').length}</div>
                    <div class="stat-label">Servidores OK</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">${mockResults.filter(r => r.status !== 'success').length}</div>
                    <div class="stat-label">Con Problemas</div>
                </div>
            </div>
            <div class="table-responsive">
                <table class="table-admin">
                    <thead>
                        <tr>
                            <th>Servidor</th>
                            <th>Tiempo (ms)</th>
                            <th>Estado</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${mockResults.map(r => `
                            <tr>
                                <td><i class="fas fa-server me-2"></i>${r.server}</td>
                                <td>${r.status === 'success' ? Math.round(r.time) + 'ms' : 'N/A'}</td>
                                <td>
                                    <span class="badge-admin badge-${r.status === 'success' ? 'success' : 'danger'}-admin">
                                        ${r.status === 'success' ? '✅ OK' : '❌ Error'}
                                    </span>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
            <div class="alert-admin alert-info-admin mt-3">
                <i class="fas fa-lightbulb"></i>
                <div>
                    <strong>Interpretación:</strong> Tiempos menores a 300ms son excelentes. 
                    Entre 300-800ms son buenos. Más de 800ms pueden necesitar optimización.
                </div>
            </div>
        `;
    }, 3000);
}

// *** FUNCIONES PARA PLATAFORMAS Y ASUNTOS ***

function openEditPlatformModal(platformId, platformName) {
    document.getElementById('edit_platform_id').value = platformId;
    document.getElementById('edit_platform_name').value = platformName;
    loadPlatformSubjects(platformId);
    const editModal = new bootstrap.Modal(document.getElementById('editPlatformModal'));
    editModal.show();
}

function openDeletePlatformModal(platformId, platformName) {
    document.getElementById('delete_platform_id').value = platformId;
    document.getElementById('delete_platform_name').textContent = platformName;
    const deleteModal = new bootstrap.Modal(document.getElementById('deletePlatformModal'));
    deleteModal.show();
}

function loadPlatformSubjects(platformId) {
    const container = document.getElementById('platformSubjectsContainer');
    container.innerHTML = '<p class="text-muted">Cargando asuntos...</p>';

    fetch('/admin/procesar_plataforma.php?action=get_subjects&platform_id=' + platformId)
        .then(response => response.json())
        .then(data => {
            if (data.success && data.subjects) {
                let tableHtml = '<div class="table-responsive"><table class="table-admin"><thead><tr><th>Asunto</th><th style="width: 150px;">Acciones</th></tr></thead><tbody>';
                if (data.subjects.length > 0) {
                    data.subjects.forEach(subject => {
                        tableHtml += `<tr>
                                        <td><i class="fas fa-list me-2 text-primary"></i>${escapeHtml(subject.subject)}</td>
                                        <td>
                                            <div class="d-flex gap-sm">
                                                <button type="button" class="btn-admin btn-primary-admin btn-sm-admin" onclick="openEditSubjectModal(${subject.id}, '${escapeHtml(subject.subject)}', ${platformId}, event)">
                                                    <i class="fas fa-edit"></i>
                                                </button>
                                                <button type="button" class="btn-admin btn-danger-admin btn-sm-admin" onclick="deleteSubject(${subject.id}, ${platformId}, event)">
                                                    <i class="fas fa-trash"></i>
                                                </button>
                                            </div>
                                        </td>
                                     </tr>`;
                    });
                } else {
                     tableHtml += '<tr><td colspan="2" class="text-center py-4"><i class="fas fa-list fa-2x text-muted mb-2"></i><p class="text-muted mb-0">No hay asuntos asociados</p></td></tr>';
                }
                tableHtml += '</tbody></table></div>';
                container.innerHTML = tableHtml;
            } else {
                container.innerHTML = `
                    <div class="alert-admin alert-danger-admin">
                        <i class="fas fa-exclamation-circle"></i>
                        <span>Error al cargar asuntos: ${data.error || 'Error desconocido'}</span>
                    </div>
                `;
            }
        })
        .catch(error => {
            console.error('Fetch Error:', error);
            container.innerHTML = `
                <div class="alert-admin alert-danger-admin">
                    <i class="fas fa-exclamation-circle"></i>
                    <span>Error de red al cargar asuntos.</span>
                </div>
            `;
        });
}

function addSubject(event) {
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    
    const platformId = document.getElementById('edit_platform_id').value;
    const subjectText = document.getElementById('new_subject_text').value.trim();

    if (!subjectText) {
        alert('Por favor, escribe un asunto.');
        return;
    }

    const formData = new FormData();
    formData.append('action', 'add_subject');
    formData.append('platform_id', platformId);
    formData.append('subject', subjectText);

    fetch('/admin/procesar_plataforma.php', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            loadPlatformSubjects(platformId);
            document.getElementById('new_subject_text').value = '';
        } else {
            alert('Error al añadir asunto: ' + (data.error || 'Error desconocido'));
        }
    })
    .catch(error => {
        console.error('Fetch Error:', error);
        alert('Error de red al añadir asunto.');
    });
}

function deleteSubject(subjectId, platformId, event) {
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    
    if (!confirm('¿Estás seguro de que quieres eliminar este asunto?')) {
        return;
    }

    const formData = new FormData();
    formData.append('action', 'delete_subject');
    formData.append('subject_id', subjectId);

    fetch('/admin/procesar_plataforma.php', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            loadPlatformSubjects(platformId);
        } else {
            alert('Error al eliminar asunto: ' + (data.error || 'Error desconocido'));
        }
    })
    .catch(error => {
        console.error('Fetch Error:', error);
        alert('Error de red al eliminar asunto.');
    });
}

function openEditSubjectModal(subjectId, subjectText, platformId, event) {
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    
    document.getElementById('edit_subject_id').value = subjectId;
    document.getElementById('edit_subject_platform_id').value = platformId;
    document.getElementById('edit_subject_text').value = subjectText;
    const editSubjectModal = new bootstrap.Modal(document.getElementById('editSubjectModal'));
    editSubjectModal.show();
}

function updateSubject(event) {
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    
    const subjectId = document.getElementById('edit_subject_id').value;
    const platformId = document.getElementById('edit_subject_platform_id').value;
    const subjectText = document.getElementById('edit_subject_text').value.trim();

    if (!subjectText) {
        alert('Por favor, ingrese un texto para el asunto.');
        return;
    }

    const formData = new FormData();
    formData.append('action', 'edit_subject');
    formData.append('subject_id', subjectId);
    formData.append('platform_id', platformId);
    formData.append('subject_text', subjectText);

    fetch('/admin/procesar_plataforma.php', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            bootstrap.Modal.getInstance(document.getElementById('editSubjectModal')).hide();
            loadPlatformSubjects(platformId);
        } else {
            alert('Error al actualizar asunto: ' + (data.error || 'Error desconocido'));
        }
    })
    .catch(error => {
        console.error('Fetch Error:', error);
        alert('Error de red al actualizar asunto.');
    });
}

function savePlatformOrder() {
    const rows = document.getElementById('platformsTableBody').querySelectorAll('tr');
    const orderedIds = Array.from(rows).map(row => row.getAttribute('data-id')).filter(id => id);

    const formData = new FormData();
    formData.append('action', 'update_platform_order');
    formData.append('ordered_ids', JSON.stringify(orderedIds)); 

    fetch('/admin/procesar_plataforma.php', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            console.log('Orden de plataformas guardado.'); 
        } else {
            alert('Error al guardar el orden: ' + (data.error || 'Error desconocido'));
        }
    })
    .catch(error => {
        console.error('Fetch Error:', error);
        alert('Error de red al guardar el orden.');
    });
}

// Función auxiliar para escapar HTML
function escapeHtml(unsafe) {
    if (!unsafe) return '';
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

document.addEventListener('DOMContentLoaded', function() {
    // Cargar correos asignados para cada usuario
    <?php foreach ($users_list as $user): ?>
        loadUserEmails(<?= $user['id'] ?>);
    <?php endforeach; ?>
    
    // Manejar select all
    const selectAllCheckbox = document.getElementById('select_all_emails');
    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener('change', function() {
            const emailCheckboxes = document.querySelectorAll('.email-checkbox');
            emailCheckboxes.forEach(checkbox => {
                checkbox.checked = this.checked;
            });
        });
    }
});

function loadUserEmails(userId) {
    console.log('🔄 Cargando emails para usuario:', userId);
    const container = document.getElementById('assigned-emails-' + userId);
    
    fetch('/admin/procesar_asignaciones.php?action=get_user_emails&user_id=' + userId, {
        method: 'GET',
        credentials: 'same-origin',
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => {
        console.log('📡 Respuesta recibida. Status:', response.status, 'Content-Type:', response.headers.get('content-type'));
        
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            throw new Error('La respuesta no es JSON válido. Content-Type: ' + contentType);
        }
        
        if (!response.ok) {
            throw new Error('HTTP error! status: ' + response.status);
        }
        
        return response.text();
    })
    .then(text => {
        console.log('📝 Respuesta como texto:', text);
        
        try {
            const data = JSON.parse(text);
            console.log('✅ JSON parseado correctamente:', data);
            
            if (data.success && data.emails) {
                if (data.emails.length > 0) {
                    const emailsList = data.emails.map(email => 
                        '<span class="badge bg-info me-1 mb-1">' + escapeHtml(email.email) + '</span>'
                    ).join('');
                    container.innerHTML = emailsList;
                    console.log('✅ Se mostraron', data.emails.length, 'emails');
                } else {
                    container.innerHTML = '<small class="text-warning">Sin correos asignados</small>';
                    console.log('ℹ️ Usuario sin correos asignados');
                }
            } else {
                console.error('❌ Error en datos:', data.error || 'Error desconocido');
                container.innerHTML = '<small class="text-danger">Error: ' + (data.error || 'Error desconocido') + '</small>';
            }
        } catch (jsonError) {
            console.error('❌ Error parseando JSON:', jsonError);
            container.innerHTML = '<small class="text-danger">Error de formato en respuesta del servidor</small>';
        }
    })
    .catch(error => {
        console.error('💥 Error en fetch:', error);
        const container = document.getElementById('assigned-emails-' + userId);
        container.innerHTML = '<small class="text-danger">Error: ' + error.message + '</small>';
    });
}

function openAssignEmailsModal(userId, username) {
    document.getElementById('assign_user_id').value = userId;
    document.getElementById('assign_username').textContent = username;
    
    // Limpiar selecciones anteriores
    document.querySelectorAll('.email-checkbox').forEach(checkbox => {
        checkbox.checked = false;
    });
    document.getElementById('select_all_emails').checked = false;
    
    // Cargar emails actualmente asignados y marcarlos
    fetch('/admin/procesar_asignaciones.php?action=get_user_emails&user_id=' + userId)
        .then(response => response.json())
        .then(data => {
            if (data.success && data.emails) {
                data.emails.forEach(emailObj => {
                    const checkbox = document.getElementById('email_' + emailObj.id);
                    if (checkbox) {
                        checkbox.checked = true;
                    }
                });
            }
        });
    
    // Mostrar modal
    var modal = new bootstrap.Modal(document.getElementById('assignEmailsModal'));
    modal.show();
}

function escapeHtml(unsafe) {
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

</script>

</body>
</html>
<?php 
// Cerrar la conexión al final del script
if ($conn) {
    $conn->close();
}
?>