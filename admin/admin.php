<?php
session_start();
require_once '../instalacion/basededatos.php';
require_once '../funciones.php';
require_once '../security/auth.php';
require_once '../cache/cache_helper.php';
require_once '../license_client.php';

check_session(true, '../index.php');

header('Content-Type: text/html; charset=utf-8');

// --- Verificaciones de instalación y base de datos (tu código existente) ---
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

$check_servers = $conn->query("SELECT COUNT(*) as count FROM email_servers");
$server_count = 0;
if ($check_servers && $row = $check_servers->fetch_assoc()) {
    $server_count = $row['count'];
}

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

$show_form = false;

$email_servers_data = [];
$result = $conn->query("SELECT * FROM email_servers ORDER BY id ASC");
while ($row = $result->fetch_assoc()) {
    $email_servers_data[] = $row;
}
$result->close();

$license_client = new ClientLicense();
$license_info = $license_client->getLicenseInfo();
$is_license_valid = $license_client->isLicenseValid();

$auth_email_message = '';
$auth_email_error = '';

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

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['new_email'])) {
    header('Content-Type: application/json');

    $new_email = filter_var(trim($_POST['new_email']), FILTER_SANITIZE_EMAIL);
    $response = ['success' => false, 'error' => '', 'message' => ''];

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
                        $response['success'] = true;
                        $response['message'] = 'Correo autorizado añadido correctamente.';
                    } else {
                        $response['error'] = 'Error al añadir el correo autorizado: ' . $stmt_insert->error;
                    }
                    $stmt_insert->close();
                } else {
                    $response['error'] = 'Error al preparar la consulta de inserción: ' . $conn->error;
                }
            } else {
                $response['error'] = 'El correo electrónico ya está en la lista.';
            }
            $stmt_check->close();
        } else {
            $response['error'] = 'Error al preparar la consulta de verificación: ' . $conn->error;
        }
    } else {
        $response['error'] = 'Por favor, introduce una dirección de correo electrónico válida.';
    }

    echo json_encode($response);
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['edit_authorized_email'])) {
    header('Content-Type: application/json');
    $response = ['success' => false, 'error' => '', 'message' => ''];

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
                        $response['success'] = true;
                        $response['message'] = 'Correo autorizado actualizado correctamente.';
                    } else {
                        $response['error'] = 'Error al actualizar el correo autorizado: ' . $stmt_update->error;
                    }
                    $stmt_update->close();
                } else {
                     $response['error'] = 'Error al preparar la consulta de actualización: ' . $conn->error;
                }
            } else {
                 $response['error'] = 'El correo electrónico ya está en la lista.';
            }
             $stmt_check->close();
        } else {
            $response['error'] = 'Error al preparar la consulta de verificación de edición: ' . $conn->error;
        }
    } else {
        $response['error'] = 'Por favor, introduce una dirección de correo electrónico válida para editar.';
    }

    echo json_encode($response);
    exit();
}

if (isset($_SESSION['auth_email_message'])) {
    $auth_email_message = $_SESSION['auth_email_message'];
    unset($_SESSION['auth_email_message']);
}
if (isset($_SESSION['auth_email_error'])) {
    $auth_email_error = $_SESSION['auth_email_error'];
    unset($_SESSION['auth_email_error']);
}

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

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update'])) {
    
    $update_servers_only = isset($_POST['update_servers_only']) && $_POST['update_servers_only'] == '1';
    $current_tab = $_POST['current_tab'] ?? 'configuracion';
    
    // PROCESAMIENTO DE SERVIDORES
    if ($update_servers_only || $current_tab == 'servidores') {
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
        
        SimpleCache::clear_servers_cache();

        if ($update_servers_only) {
            $_SESSION['message'] = 'Servidores IMAP actualizados con éxito.';
            header("Location: admin.php?tab=servidores");
            exit();
        }
    }

    // PROCESAMIENTO DE CONFIGURACIÓN GENERAL
    if (!$update_servers_only) {
        
        // LISTA COMPLETA de configuraciones manejadas
        $updatable_keys = [
            // Campos de texto
            'PAGE_TITLE',
            'enlace_global_1', 
            'enlace_global_1_texto', 
            'enlace_global_2', 
            'enlace_global_2_texto',
            'enlace_global_numero_whatsapp', 
            'enlace_global_texto_whatsapp',
            'ID_VENDEDOR',
            'LOGO',
            
            // Campos numéricos
            'EMAIL_QUERY_TIME_LIMIT_MINUTES',
            'CACHE_TIME_MINUTES',
            'MAX_EMAILS_TO_CHECK',
            'IMAP_CONNECTION_TIMEOUT',
            'IMAP_SEARCH_TIMEOUT',
            'TIMEZONE_DEBUG_HOURS',
            
            // Checkboxes principales
            'EMAIL_AUTH_ENABLED',
            'REQUIRE_LOGIN',
            'USER_EMAIL_RESTRICTIONS_ENABLED',
            
            // Checkboxes de cache
            'CACHE_ENABLED',
            'CACHE_MEMORY_ENABLED',
            
            // Checkboxes de optimización
            'IMAP_SEARCH_OPTIMIZATION', 
            'PERFORMANCE_LOGGING',
            'EARLY_SEARCH_STOP',
            'TRUST_IMAP_DATE_FILTER',
            'USE_PRECISE_IMAP_SEARCH'
        ];

        // Lista de configuraciones que son checkboxes (0/1)
        $checkbox_keys = [
            'EMAIL_AUTH_ENABLED',
            'REQUIRE_LOGIN',
            'USER_EMAIL_RESTRICTIONS_ENABLED',
            'CACHE_ENABLED',
            'CACHE_MEMORY_ENABLED',
            'IMAP_SEARCH_OPTIMIZATION',
            'PERFORMANCE_LOGGING',
            'EARLY_SEARCH_STOP',
            'TRUST_IMAP_DATE_FILTER',
            'USE_PRECISE_IMAP_SEARCH'
        ];

        $updates_count = 0;
        $errors_count = 0;

        foreach ($updatable_keys as $key) {
            $value_to_save = null;
            
            if (in_array($key, $checkbox_keys)) {
                // Para checkboxes: si está en POST con valor '1' es '1', si no es '0'
                $value_to_save = isset($_POST[$key]) && $_POST[$key] === '1' ? '1' : '0';
            } else {
                // Para campos de texto/numéricos: solo actualizar si está presente en POST
                if (isset($_POST[$key])) {
                    $value_to_save = trim($_POST[$key]);
                }
            }
            
            if ($value_to_save !== null) {
                try {
                    // Verificar si ya existe
                    $check_stmt = $conn->prepare("SELECT value FROM settings WHERE name = ?");
                    $check_stmt->bind_param("s", $key);
                    $check_stmt->execute();
                    $check_result = $check_stmt->get_result();
                    $exists = $check_result->num_rows > 0;
                    $check_stmt->close();
                    
                    if ($exists) {
                        // Actualizar
                        $stmt = $conn->prepare("UPDATE settings SET value = ? WHERE name = ?");
                        $stmt->bind_param("ss", $value_to_save, $key);
                    } else {
                        // Insertar
                        $stmt = $conn->prepare("INSERT INTO settings (name, value) VALUES (?, ?)");
                        $stmt->bind_param("ss", $key, $value_to_save);
                    }
                    
                    $success = $stmt->execute();
                    $stmt->close();
                    
                    if ($success) {
                        $updates_count++;
                    } else {
                        
                        $errors_count++;
                    }
                } catch (Exception $e) {

                    $errors_count++;
                }
            }
        }

        // PROCESAMIENTO DE LOGO
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
                    
                    $_SESSION['message'] = 'Configuración actualizada con éxito (incluido logo).';
                } else {
                    $_SESSION['message'] = 'Error: No se pudo subir el archivo.';
                }
            }
        } else {
            if ($errors_count > 0) {
                $_SESSION['message'] = "Configuración actualizada con $errors_count errores. Revisa los logs.";
            } else {
                $_SESSION['message'] = 'Configuración actualizada con éxito.';
            }
        }
        
        // LIMPIAR CACHE AGRESIVAMENTE
        SimpleCache::clear_settings_cache();
        SimpleCache::clear_platforms_cache();
        SimpleCache::clear_cache(); // Limpia TODO el cache
        
        // VERIFICAR QUE LOS VALORES SE GUARDARON CORRECTAMENTE
        $critical_keys = ['EMAIL_AUTH_ENABLED', 'USER_EMAIL_RESTRICTIONS_ENABLED', 'CACHE_ENABLED'];
        foreach ($critical_keys as $key) {
            $verification_stmt = $conn->prepare("SELECT value FROM settings WHERE name = ?");
            $verification_stmt->bind_param("s", $key);
            $verification_stmt->execute();
            $verification_result = $verification_stmt->get_result();
            if ($verification_result->num_rows > 0) {
                $row = $verification_result->fetch_assoc();
            } else {
            }
            $verification_stmt->close();
        }
        
        // VERIFICAR CACHE REGENERADO
        try {
            $fresh_settings = SimpleCache::get_settings($conn);
            foreach ($critical_keys as $key) {
                $cache_value = $fresh_settings[$key] ?? 'NOT_FOUND';
            }
        } catch (Exception $e) {
        }
    }
    
    header("Location: admin.php?tab=" . $current_tab . "&debug=1&updated=" . time());
    exit();
}

?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Panel de Administración - <?= htmlspecialchars($settings['PAGE_TITLE'] ?? 'Sistema de Códigos') ?></title>
    
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="../styles/modern_global.css">
    <link rel="stylesheet" href="../styles/modern_admin.css">
</head>
<body class="admin-page">

<div class="floating-particles">
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
</div>

<div class="admin-container">
    <div class="admin-header">
        <h1 class="admin-title">
            <i class="fas fa-cogs me-3"></i>
            Panel de Administración
        </h1>
        <p class="mb-0 opacity-75">Sistema de gestión de códigos por email</p>
    </div>

    <div class="p-4">
        <a href="../inicio.php" class="btn-back-modern">
            <i class="fas fa-arrow-left"></i>
            Volver a Inicio
        </a>
    </div>

    <?php if (isset($_SESSION['message'])): ?>
        <div class="mx-4">
            <div class="alert-admin alert-success-admin">
                <i class="fas fa-check-circle"></i>
                <span><?= htmlspecialchars($_SESSION['message']) ?></span>
            </div>
        </div>
        <?php unset($_SESSION['message']); ?>
    <?php endif; ?>

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
         <li class="nav-item" role="presentation">
            <button class="nav-link" id="licencia-tab" data-bs-toggle="tab" data-bs-target="#licencia" type="button" role="tab">
                <i class="fas fa-certificate me-2"></i>Licencia
            </button>
        </li>
    </ul>

    <div class="tab-content" id="adminTabContent">
        <div class="tab-pane fade show active" id="config" role="tabpanel">
            
            <!-- 
AGREGAR ESTA SECCIÓN AL INICIO DE LA PESTAÑA DE CONFIGURACIÓN EN admin.php 
Colocar justo después de: <div class="tab-pane fade show active" id="config" role="tabpanel">
-->

<!-- Dashboard de Estadísticas en Tiempo Real -->
<div class="admin-card dashboard-stats-card">
    <div class="admin-card-header">
        <h3 class="admin-card-title">
            <i class="fas fa-chart-line me-2 text-primary"></i>
            Dashboard en Tiempo Real
        </h3>
        <div class="dashboard-controls">
            <span class="last-update">Última actualización: <span id="lastUpdateTime">--:--:--</span></span>
            <button type="button" class="btn-admin btn-secondary-admin btn-sm-admin" onclick="refreshDashboard()">
                <i class="fas fa-sync-alt" id="refreshIcon"></i> Actualizar
            </button>
        </div>
    </div>
    
    <!-- Estadísticas principales -->
    <div class="dashboard-main-stats">
        <div class="stat-card stat-primary">
            <div class="stat-icon">
                <i class="fas fa-search"></i>
            </div>
            <div class="stat-content">
                <div class="stat-number" id="searchesToday">--</div>
                <div class="stat-label">Búsquedas Hoy</div>
                <div class="stat-trend" id="searchesTrend">
                    <i class="fas fa-arrow-up"></i>
                    <span>+12% vs ayer</span>
                </div>
            </div>
        </div>
        
        <div class="stat-card stat-success">
            <div class="stat-icon">
                <i class="fas fa-chart-pie"></i>
            </div>
            <div class="stat-content">
                <div class="stat-number" id="successRate">--%</div>
                <div class="stat-label">Tasa de Éxito</div>
                <div class="stat-trend positive">
                    <i class="fas fa-arrow-up"></i>
                    <span>+3% esta semana</span>
                </div>
            </div>
        </div>
        
        <div class="stat-card stat-info">
            <div class="stat-icon">
                <i class="fas fa-users"></i>
            </div>
            <div class="stat-content">
                <div class="stat-number" id="activeUsers">--</div>
                <div class="stat-label">Usuarios Activos</div>
                <div class="stat-trend" id="usersTrend">
                    <i class="fas fa-circle"></i>
                    <span>Últimas 24h</span>
                </div>
            </div>
        </div>
        
        <div class="stat-card stat-warning">
            <div class="stat-icon">
                <i class="fas fa-clock"></i>
            </div>
            <div class="stat-content">
                <div class="stat-number" id="avgTime">-.-s</div>
                <div class="stat-label">Tiempo Promedio</div>
                <div class="stat-trend positive">
                    <i class="fas fa-arrow-down"></i>
                    <span>-0.2s vs ayer</span>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Estadísticas adicionales -->
    <div class="dashboard-secondary-stats">
        <div class="row">
            <div class="col-md-3">
                <div class="mini-stat">
                    <div class="mini-stat-icon">
                        <i class="fas fa-user-check text-success"></i>
                    </div>
                    <div class="mini-stat-content">
                        <div class="mini-stat-number" id="totalUsers">--</div>
                        <div class="mini-stat-label">Total Usuarios</div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="mini-stat">
                    <div class="mini-stat-icon">
                        <i class="fas fa-server text-info"></i>
                    </div>
                    <div class="mini-stat-content">
                        <div class="mini-stat-number" id="activeServers">--</div>
                        <div class="mini-stat-label">Servidores Activos</div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="mini-stat">
                    <div class="mini-stat-icon">
                        <i class="fas fa-th-large text-warning"></i>
                    </div>
                    <div class="mini-stat-content">
                        <div class="mini-stat-number" id="totalPlatforms">--</div>
                        <div class="mini-stat-label">Plataformas</div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="mini-stat">
                    <div class="mini-stat-icon">
                        <i class="fas fa-chart-bar text-primary"></i>
                    </div>
                    <div class="mini-stat-content">
                        <div class="mini-stat-number" id="weekSearches">--</div>
                        <div class="mini-stat-label">Esta Semana</div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Gráfico de actividad por horas -->
    <div class="dashboard-chart-section">
        <h6 class="chart-title">
            <i class="fas fa-chart-area me-2"></i>
            Actividad por Horas (Hoy)
        </h6>
        <div class="chart-container">
            <canvas id="hourlyChart" width="400" height="100"></canvas>
        </div>
    </div>
</div>

<!-- CSS Styles para el Dashboard -->
<style>
/* Estilos específicos para el dashboard */
.dashboard-stats-card {
    background: linear-gradient(135deg, rgba(26, 18, 53, 0.8) 0%, rgba(42, 31, 77, 0.9) 100%);
    border: 1px solid var(--glow-border);
    border-radius: 16px;
    padding: 1.5rem;
    margin-bottom: 2rem;
    position: relative;
    overflow: hidden;
}

.dashboard-stats-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 3px;
    background: linear-gradient(90deg, var(--accent-green), #00f2fe, var(--accent-green));
    animation: dashboard-glow 3s ease-in-out infinite;
}

@keyframes dashboard-glow {
    0%, 100% { opacity: 0.6; }
    50% { opacity: 1; }
}

.dashboard-controls {
    display: flex;
    align-items: center;
    gap: 1rem;
}

.last-update {
    font-size: 0.85rem;
    color: var(--text-secondary);
}

/* Estadísticas principales */
.dashboard-main-stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1.5rem;
    margin: 1.5rem 0;
}

.stat-card {
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 1.5rem;
    display: flex;
    align-items: center;
    transition: all 0.3s ease;
    position: relative;
    overflow: hidden;
}

.stat-card:hover {
    transform: translateY(-3px);
    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
}

.stat-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 4px;
    height: 100%;
    background: var(--accent-green);
}

.stat-card.stat-success::before { background: #32FFB5; }
.stat-card.stat-info::before { background: #00f2fe; }
.stat-card.stat-warning::before { background: #f59e0b; }
.stat-card.stat-primary::before { background: #6366f1; }

.stat-icon {
    background: rgba(255, 255, 255, 0.1);
    border-radius: 12px;
    width: 60px;
    height: 60px;
    display: flex;
    align-items: center;
    justify-content: center;
    margin-right: 1rem;
    font-size: 1.5rem;
    color: var(--accent-green);
}

.stat-success .stat-icon { color: #32FFB5; }
.stat-info .stat-icon { color: #00f2fe; }
.stat-warning .stat-icon { color: #f59e0b; }
.stat-primary .stat-icon { color: #6366f1; }

.stat-content {
    flex: 1;
}

.stat-number {
    font-size: 2rem;
    font-weight: 700;
    color: var(--text-primary);
    line-height: 1;
    margin-bottom: 0.25rem;
}

.stat-label {
    font-size: 0.9rem;
    color: var(--text-secondary);
    margin-bottom: 0.5rem;
}

.stat-trend {
    font-size: 0.8rem;
    color: var(--text-muted);
    display: flex;
    align-items: center;
    gap: 0.25rem;
}

.stat-trend.positive {
    color: #32FFB5;
}

/* Estadísticas secundarias */
.dashboard-secondary-stats {
    margin: 2rem 0;
    padding: 1rem;
    background: rgba(0, 0, 0, 0.2);
    border-radius: 8px;
}

.mini-stat {
    display: flex;
    align-items: center;
    padding: 0.75rem;
    background: rgba(255, 255, 255, 0.05);
    border-radius: 8px;
    margin-bottom: 0.5rem;
}

.mini-stat-icon {
    margin-right: 0.75rem;
    font-size: 1.2rem;
}

.mini-stat-number {
    font-size: 1.2rem;
    font-weight: 600;
    color: var(--text-primary);
    line-height: 1;
}

.mini-stat-label {
    font-size: 0.8rem;
    color: var(--text-secondary);
}

/* Sección del gráfico */
.dashboard-chart-section {
    margin-top: 2rem;
    padding: 1rem;
    background: rgba(0, 0, 0, 0.2);
    border-radius: 8px;
}

.chart-title {
    color: var(--text-secondary);
    margin-bottom: 1rem;
    font-weight: 500;
}

.chart-container {
    position: relative;
    height: 200px;
    background: rgba(255, 255, 255, 0.02);
    border-radius: 8px;
    padding: 1rem;
}

/* Animaciones de carga */
.loading-shimmer {
    background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.1), transparent);
    background-size: 200% 100%;
    animation: shimmer 1.5s infinite;
}

@keyframes shimmer {
    0% { background-position: 200% 0; }
    100% { background-position: -200% 0; }
}

/* Responsive */
@media (max-width: 768px) {
    .dashboard-main-stats {
        grid-template-columns: 1fr;
        gap: 1rem;
    }
    
    .stat-card {
        padding: 1rem;
    }
    
    .stat-number {
        font-size: 1.5rem;
    }
    
    .dashboard-controls {
        flex-direction: column;
        align-items: flex-start;
        gap: 0.5rem;
    }
}

/* Estados de conexión */
.connection-status {
    position: absolute;
    top: 1rem;
    right: 1rem;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: var(--accent-green);
    animation: pulse 2s infinite;
}

.connection-status.offline {
    background: var(--danger-red);
    animation: none;
}

@keyframes pulse {
    0% { opacity: 1; }
    50% { opacity: 0.5; }
    100% { opacity: 1; }
}

/* Efectos de contador animado */
.stat-number.counting {
    animation: countUp 0.8s ease-out;
}

@keyframes countUp {
    from {
        transform: scale(1.2);
        opacity: 0.7;
    }
    to {
        transform: scale(1);
        opacity: 1;
    }
}
</style>

<!-- JavaScript para el Dashboard -->
<script>
// Variables globales para el dashboard
let dashboardChart = null;
let dashboardUpdateInterval = null;
let isUpdatingDashboard = false;

// Función para inicializar el dashboard
function initializeDashboard() {
    console.log('Inicializando dashboard...');
    
    // Crear el gráfico
    createHourlyChart();
    
    // Cargar datos iniciales
    refreshDashboard();
    
    // Configurar actualización automática cada 30 segundos
    dashboardUpdateInterval = setInterval(refreshDashboard, 30000);
    
    // Añadir indicador de conexión
    addConnectionIndicator();
}

// Función para actualizar el dashboard
async function refreshDashboard() {
    if (isUpdatingDashboard) return;
    
    isUpdatingDashboard = true;
    const refreshIcon = document.getElementById('refreshIcon');
    
    try {
        // Animar icono de actualización
        if (refreshIcon) {
            refreshIcon.classList.add('fa-spin');
        }
        
        // Realizar petición AJAX
        const response = await fetch('get_dashboard_stats.php', {
            method: 'GET',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'Cache-Control': 'no-cache'
            }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const data = await response.json();
        
        if (data.success) {
            updateDashboardData(data);
            updateConnectionStatus(true);
        } else {
            throw new Error(data.error || 'Error desconocido');
        }
        
    } catch (error) {
        console.error('Error actualizando dashboard:', error);
        updateConnectionStatus(false);
        showDashboardError(error.message);
    } finally {
        isUpdatingDashboard = false;
        if (refreshIcon) {
            refreshIcon.classList.remove('fa-spin');
        }
    }
}

// Función para actualizar los datos en el DOM
function updateDashboardData(data) {
    const stats = data.main_stats;
    const additional = data.additional_stats;
    
    // Actualizar estadísticas principales con animación
    animateNumber('searchesToday', stats.searches_today);
    animateNumber('successRate', stats.success_rate, '%');
    animateNumber('activeUsers', stats.active_users);
    animateNumber('avgTime', stats.avg_response_time, 's');
    
    // Actualizar estadísticas adicionales
    updateElement('totalUsers', additional.total_users);
    updateElement('activeServers', additional.active_servers);
    updateElement('totalPlatforms', additional.total_platforms);
    updateElement('weekSearches', additional.week_searches);
    
    // Actualizar timestamp
    updateElement('lastUpdateTime', data.last_updated);
    
    // Actualizar gráfico
    if (dashboardChart && data.hourly_chart) {
        updateHourlyChart(data.hourly_chart);
    }
}

// Función para animar números
function animateNumber(elementId, newValue, suffix = '') {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    const currentValue = parseInt(element.textContent) || 0;
    const increment = (newValue - currentValue) / 20;
    let current = currentValue;
    
    const animation = setInterval(() => {
        current += increment;
        if ((increment > 0 && current >= newValue) || (increment < 0 && current <= newValue)) {
            current = newValue;
            clearInterval(animation);
        }
        
        if (suffix === '%') {
            element.textContent = Math.round(current) + suffix;
        } else if (suffix === 's') {
            element.textContent = current.toFixed(1) + suffix;
        } else {
            element.textContent = Math.round(current).toLocaleString();
        }
    }, 50);
    
    // Añadir efecto visual
    element.classList.add('counting');
    setTimeout(() => element.classList.remove('counting'), 800);
}

// Función para actualizar elementos simples
function updateElement(elementId, value) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = typeof value === 'number' ? value.toLocaleString() : value;
    }
}

// Función para crear el gráfico de actividad por horas
function createHourlyChart() {
    const canvas = document.getElementById('hourlyChart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    // Configuración básica del gráfico
    const chartData = {
        labels: Array.from({length: 24}, (_, i) => i + ':00'),
        datasets: [{
            label: 'Búsquedas',
            data: new Array(24).fill(0),
            borderColor: '#32FFB5',
            backgroundColor: 'rgba(50, 255, 181, 0.1)',
            fill: true,
            tension: 0.4,
            pointBackgroundColor: '#32FFB5',
            pointBorderColor: '#32FFB5',
            pointHoverBackgroundColor: '#fff',
            pointHoverBorderColor: '#32FFB5'
        }]
    };
    
    // Crear gráfico simple con Canvas
    dashboardChart = {
        canvas: canvas,
        ctx: ctx,
        data: chartData,
        update: function(newData) {
            this.data.datasets[0].data = newData.map(item => item.searches);
            this.render();
        },
        render: function() {
            const ctx = this.ctx;
            const canvas = this.canvas;
            const data = this.data.datasets[0].data;
            const max = Math.max(...data) || 1;
            
            // Limpiar canvas
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            
            // Configurar estilos
            ctx.strokeStyle = '#32FFB5';
            ctx.fillStyle = 'rgba(50, 255, 181, 0.1)';
            ctx.lineWidth = 2;
            
            // Dibujar línea y área
            ctx.beginPath();
            data.forEach((value, index) => {
                const x = (index / (data.length - 1)) * canvas.width;
                const y = canvas.height - (value / max) * canvas.height;
                
                if (index === 0) {
                    ctx.moveTo(x, y);
                } else {
                    ctx.lineTo(x, y);
                }
            });
            
            // Rellenar área bajo la curva
            ctx.lineTo(canvas.width, canvas.height);
            ctx.lineTo(0, canvas.height);
            ctx.closePath();
            ctx.fill();
            
            // Dibujar línea
            ctx.beginPath();
            data.forEach((value, index) => {
                const x = (index / (data.length - 1)) * canvas.width;
                const y = canvas.height - (value / max) * canvas.height;
                
                if (index === 0) {
                    ctx.moveTo(x, y);
                } else {
                    ctx.lineTo(x, y);
                }
            });
            ctx.stroke();
        }
    };
    
    dashboardChart.render();
}

// Función para actualizar el gráfico
function updateHourlyChart(hourlyData) {
    if (dashboardChart) {
        dashboardChart.update(hourlyData);
    }
}

// Función para mostrar el estado de conexión
function addConnectionIndicator() {
    const header = document.querySelector('.dashboard-stats-card .admin-card-header');
    if (header) {
        const indicator = document.createElement('div');
        indicator.className = 'connection-status';
        indicator.id = 'connectionStatus';
        header.appendChild(indicator);
    }
}

// Función para actualizar el estado de conexión
function updateConnectionStatus(isOnline) {
    const indicator = document.getElementById('connectionStatus');
    if (indicator) {
        indicator.className = isOnline ? 'connection-status' : 'connection-status offline';
    }
}

// Función para mostrar errores
function showDashboardError(message) {
    console.error('Dashboard Error:', message);
    // Aquí podrías mostrar una notificación temporal al usuario
}

// Inicializar cuando la pestaña de configuración esté activa
document.addEventListener('DOMContentLoaded', function() {
    // Verificar si estamos en la pestaña de configuración
    const configTab = document.getElementById('config');
    if (configTab && configTab.classList.contains('active')) {
        setTimeout(initializeDashboard, 500);
    }
    
    // Escuchar cambios de pestaña
    const configTabButton = document.getElementById('config-tab');
    if (configTabButton) {
        configTabButton.addEventListener('shown.bs.tab', function() {
            setTimeout(initializeDashboard, 200);
        });
    }
});

// Limpiar intervalos cuando se cambie de pestaña
document.addEventListener('visibilitychange', function() {
    if (document.hidden && dashboardUpdateInterval) {
        clearInterval(dashboardUpdateInterval);
        dashboardUpdateInterval = null;
    } else if (!document.hidden && !dashboardUpdateInterval) {
        dashboardUpdateInterval = setInterval(refreshDashboard, 30000);
    }
});
</script>
            
            <form method="POST" action="admin.php" enctype="multipart/form-data" class="needs-validation" novalidate>
                <input type="hidden" name="current_tab" value="config" class="current-tab-input">

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
                <input type="checkbox" 
                       class="form-check-input-admin" 
                       id="EMAIL_AUTH_ENABLED" 
                       name="EMAIL_AUTH_ENABLED" 
                       value="1" 
                       <?= (isset($settings['EMAIL_AUTH_ENABLED']) && $settings['EMAIL_AUTH_ENABLED'] === '1') ? 'checked' : '' ?>>
                <label for="EMAIL_AUTH_ENABLED" class="form-check-label-admin">
                    <i class="fas fa-filter me-2"></i>
                    Filtro de Correos Electrónicos
                </label>
            </div>
            <small class="text-muted d-block mt-1">Activar lista de correos autorizados</small>
        </div>
        
        <div class="col-md-6">
            <div class="form-check-admin">
                <input type="checkbox" 
                       class="form-check-input-admin" 
                       id="REQUIRE_LOGIN" 
                       name="REQUIRE_LOGIN" 
                       value="1" 
                       <?= (isset($settings['REQUIRE_LOGIN']) && $settings['REQUIRE_LOGIN'] === '1') ? 'checked' : '' ?>>
                <label for="REQUIRE_LOGIN" class="form-check-label-admin">
                    <i class="fas fa-lock me-2"></i>
                    Seguridad de Login Habilitada
                </label>
            </div>
            <small class="text-muted d-block mt-1">Si está activado, todos los usuarios necesitan iniciar sesión.</small>
        </div>
    </div>

    <!-- Segunda fila de checkboxes -->
    <div class="row mt-3">
        <div class="col-md-6">
            <div class="form-check-admin">
                <input type="checkbox" 
                       class="form-check-input-admin" 
                       id="CACHE_ENABLED" 
                       name="CACHE_ENABLED" 
                       value="1" 
                       <?= (isset($settings['CACHE_ENABLED']) && $settings['CACHE_ENABLED'] === '1') ? 'checked' : '' ?>>
                <label for="CACHE_ENABLED" class="form-check-label-admin">
                    <i class="fas fa-database me-2"></i>
                    Sistema de Cache Habilitado
                </label>
            </div>
            <small class="text-muted d-block mt-1">Mejora el rendimiento guardando resultados en cache</small>
        </div>
        
        <div class="col-md-6">
            <div class="form-check-admin">
                <input type="checkbox" 
                       class="form-check-input-admin" 
                       id="CACHE_MEMORY_ENABLED" 
                       name="CACHE_MEMORY_ENABLED" 
                       value="1" 
                       <?= (isset($settings['CACHE_MEMORY_ENABLED']) && $settings['CACHE_MEMORY_ENABLED'] === '1') ? 'checked' : '' ?>>
                <label for="CACHE_MEMORY_ENABLED" class="form-check-label-admin">
                    <i class="fas fa-memory me-2"></i>
                    Cache en Memoria
                </label>
            </div>
            <small class="text-muted d-block mt-1">Cache temporal en memoria para consultas repetidas</small>
        </div>
    </div>

    <!-- Separador visual -->
    <hr class="my-4" style="border-color: rgba(255,255,255,0.2); margin: 2rem 0;">

    <!-- Checkbox de restricciones por usuario -->
    <div class="row">
        <div class="col-md-12">
            <div class="form-check-admin">
                <input type="checkbox" 
                       class="form-check-input-admin" 
                       id="USER_EMAIL_RESTRICTIONS_ENABLED" 
                       name="USER_EMAIL_RESTRICTIONS_ENABLED" 
                       value="1" 
                       <?= (isset($settings['USER_EMAIL_RESTRICTIONS_ENABLED']) && $settings['USER_EMAIL_RESTRICTIONS_ENABLED'] === '1') ? 'checked' : '' ?>>
                <label for="USER_EMAIL_RESTRICTIONS_ENABLED" class="form-check-label-admin">
                    <i class="fas fa-users-cog me-2"></i>
                    <strong>Activar restricciones por usuario</strong>
                </label>
            </div>
            <div class="form-text text-muted mt-2">
                <span class="d-block">
                    <i class="fas fa-info-circle me-1"></i>
                    <strong>Si está activado:</strong> cada usuario solo puede consultar los correos que se le asignen específicamente.
                </span>
                <span class="d-block">
                    <i class="fas fa-info-circle me-1"></i>
                    <strong>Si está desactivado:</strong> todos los usuarios pueden consultar cualquier correo autorizado.
                </span>
                <span class="d-block mt-1 text-warning">
                    <i class="fas fa-exclamation-triangle me-1"></i>
                    <strong>Nota:</strong> Esta opción requiere que "Filtro de Correos Electrónicos" esté activado.
                </span>
            </div>
        </div>
    </div>
    
    <!-- Campos numéricos -->
    <div class="row mt-4">
        <div class="col-md-6">
            <div class="form-group-admin">
                <label for="EMAIL_QUERY_TIME_LIMIT_MINUTES" class="form-label-admin">
                    <i class="fas fa-clock me-2"></i>
                    Límite de tiempo para consulta de correos (minutos)
                </label>
                <input type="number" class="form-control-admin" id="EMAIL_QUERY_TIME_LIMIT_MINUTES" name="EMAIL_QUERY_TIME_LIMIT_MINUTES" min="1" max="1440" value="<?= htmlspecialchars($settings['EMAIL_QUERY_TIME_LIMIT_MINUTES'] ?? '30') ?>">
                <small class="text-muted">Tiempo máximo para buscar correos. Valor recomendado: 30 minutos para mejor performance.</small>
            </div>
        </div>
        
        <div class="col-md-6">
            <div class="form-group-admin">
                <label for="CACHE_TIME_MINUTES" class="form-label-admin">
                    <i class="fas fa-hourglass-half me-2"></i>
                    Tiempo de vida del cache (minutos)
                </label>
                <input type="number" class="form-control-admin" id="CACHE_TIME_MINUTES" name="CACHE_TIME_MINUTES" min="1" max="60" value="<?= htmlspecialchars($settings['CACHE_TIME_MINUTES'] ?? '5') ?>">
                <small class="text-muted">Tiempo que se mantienen los datos en cache antes de refrescar.</small>
            </div>
        </div>
    </div>
</div>

<!-- NUEVA SECCIÓN: OPTIMIZACIONES DE PERFORMANCE -->
<div class="admin-card">
    <div class="admin-card-header">
        <h3 class="admin-card-title">
            <i class="fas fa-rocket me-2 text-warning"></i>
            Optimizaciones de Performance
        </h3>
    </div>
    
    <div class="alert-admin alert-info-admin">
        <i class="fas fa-info-circle"></i>
        <div>
            <strong>Configuraciones avanzadas:</strong> Ajusta estos valores para optimizar el rendimiento del sistema según tu servidor y necesidades.
        </div>
    </div>
    
    <!-- Checkboxes de optimización -->
    <div class="row">
        <div class="col-md-6">
            <div class="form-check-admin">
                <input type="checkbox" 
                       class="form-check-input-admin" 
                       id="USE_PRECISE_IMAP_SEARCH" 
                       name="USE_PRECISE_IMAP_SEARCH" 
                       value="1" 
                       <?= (isset($settings['USE_PRECISE_IMAP_SEARCH']) && $settings['USE_PRECISE_IMAP_SEARCH'] === '1') ? 'checked' : '' ?>>
                <label for="USE_PRECISE_IMAP_SEARCH" class="form-check-label-admin">
                    <i class="fas fa-search-plus me-2"></i>
                    Búsquedas IMAP precisas
                </label>
            </div>
            <small class="text-muted d-block mt-1">Usar búsquedas más específicas con fecha y hora exacta.</small>
        </div>
        
        <div class="col-md-6">
            <div class="form-check-admin">
                <input type="checkbox" 
                       class="form-check-input-admin" 
                       id="EARLY_SEARCH_STOP" 
                       name="EARLY_SEARCH_STOP" 
                       value="1" 
                       <?= (isset($settings['EARLY_SEARCH_STOP']) && $settings['EARLY_SEARCH_STOP'] === '1') ? 'checked' : '' ?>>
                <label for="EARLY_SEARCH_STOP" class="form-check-label-admin">
                    <i class="fas fa-stop-circle me-2"></i>
                    Parada temprana de búsqueda
                </label>
            </div>
            <small class="text-muted d-block mt-1">Detener búsqueda al encontrar el primer resultado válido.</small>
        </div>
    </div>
    
    <div class="row mt-3">
        <div class="col-md-6">
            <div class="form-check-admin">
                <input type="checkbox" 
                       class="form-check-input-admin" 
                       id="IMAP_SEARCH_OPTIMIZATION" 
                       name="IMAP_SEARCH_OPTIMIZATION" 
                       value="1" 
                       <?= (isset($settings['IMAP_SEARCH_OPTIMIZATION']) && $settings['IMAP_SEARCH_OPTIMIZATION'] === '1') ? 'checked' : '' ?>>
                <label for="IMAP_SEARCH_OPTIMIZATION" class="form-check-label-admin">
                    <i class="fas fa-tachometer-alt me-2"></i>
                    Optimizaciones de búsqueda IMAP
                </label>
            </div>
            <small class="text-muted d-block mt-1">Activar todas las optimizaciones automáticas de búsqueda.</small>
        </div>
        
        <div class="col-md-6">
            <div class="form-check-admin">
                <input type="checkbox" 
                       class="form-check-input-admin" 
                       id="TRUST_IMAP_DATE_FILTER" 
                       name="TRUST_IMAP_DATE_FILTER" 
                       value="1" 
                       <?= (isset($settings['TRUST_IMAP_DATE_FILTER']) && $settings['TRUST_IMAP_DATE_FILTER'] === '1') ? 'checked' : '' ?>>
                <label for="TRUST_IMAP_DATE_FILTER" class="form-check-label-admin">
                    <i class="fas fa-calendar-check me-2"></i>
                    Confiar en filtrado de fechas IMAP
                </label>
            </div>
            <small class="text-muted d-block mt-1">Confiar en el servidor IMAP para filtrar fechas (más rápido).</small>
        </div>
    </div>
    
    <div class="row mt-3">
        <div class="col-md-6">
            <div class="form-check-admin">
                <input type="checkbox" 
                       class="form-check-input-admin" 
                       id="PERFORMANCE_LOGGING" 
                       name="PERFORMANCE_LOGGING" 
                       value="1" 
                       <?= (isset($settings['PERFORMANCE_LOGGING']) && $settings['PERFORMANCE_LOGGING'] === '1') ? 'checked' : '' ?>>
                <label for="PERFORMANCE_LOGGING" class="form-check-label-admin">
                    <i class="fas fa-chart-line me-2"></i>
                    Logging de performance
                </label>
            </div>
            <small class="text-muted d-block mt-1">Registrar métricas de rendimiento en logs.</small>
        </div>
    </div>
    
    <!-- Campos numéricos de performance -->
    <div class="row mt-4">
        <div class="col-md-4">
            <div class="form-group-admin">
                <label for="MAX_EMAILS_TO_CHECK" class="form-label-admin">
                    <i class="fas fa-envelope me-2"></i>
                    Máximo de emails a verificar por consulta
                </label>
                <input type="number" class="form-control-admin" id="MAX_EMAILS_TO_CHECK" name="MAX_EMAILS_TO_CHECK" min="10" max="100" value="<?= htmlspecialchars($settings['MAX_EMAILS_TO_CHECK'] ?? '35') ?>">
                <small class="text-muted">Valor recomendado: 35. Reducir para buzones muy grandes.</small>
            </div>
        </div>
        
        <div class="col-md-4">
            <div class="form-group-admin">
                <label for="IMAP_CONNECTION_TIMEOUT" class="form-label-admin">
                    <i class="fas fa-clock me-2"></i>
                    Timeout de conexión IMAP (segundos)
                </label>
                <input type="number" class="form-control-admin" id="IMAP_CONNECTION_TIMEOUT" name="IMAP_CONNECTION_TIMEOUT" min="5" max="30" value="<?= htmlspecialchars($settings['IMAP_CONNECTION_TIMEOUT'] ?? '8') ?>">
                <small class="text-muted">Valor recomendado: 8. Conexiones más rápidas para servidores estables.</small>
            </div>
        </div>
        
        <div class="col-md-4">
            <div class="form-group-admin">
                <label for="IMAP_SEARCH_TIMEOUT" class="form-label-admin">
                    <i class="fas fa-hourglass-half me-2"></i>
                    Timeout de búsqueda IMAP (segundos)
                </label>
                <input type="number" class="form-control-admin" id="IMAP_SEARCH_TIMEOUT" name="IMAP_SEARCH_TIMEOUT" min="10" max="120" value="<?= htmlspecialchars($settings['IMAP_SEARCH_TIMEOUT'] ?? '30') ?>">
                <small class="text-muted">Tiempo máximo para cada operación de búsqueda individual.</small>
            </div>
        </div>
    </div>
</div>
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
                
                <form method="POST" action="admin.php" enctype="multipart/form-data">
                    <input type="hidden" name="current_tab" value="servidores" class="current-tab-input">
                    <input type="hidden" name="update_servers_only" value="1">
                    
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
                    
                    <div class="text-center mt-4">
                        <button type="submit" name="update" class="btn-admin btn-primary-admin btn-lg-admin">
                            <i class="fas fa-sync-alt"></i>
                            ACTUALIZAR SERVIDORES
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <div class="tab-pane fade" id="users" role="tabpanel">
            <div class="admin-card">
                <div class="admin-card-header">
                    <h3 class="admin-card-title mb-0">
                        <i class="fas fa-users me-2"></i>
                        Gestión de Usuarios
                    </h3>
                    <div class="action-buttons-group">
                        <button class="btn-admin btn-success-admin" data-bs-toggle="modal" data-bs-target="#addUserModal">
                            <i class="fas fa-plus"></i> Nuevo Usuario
                        </button>
                        <div class="search-box-admin">
                            <i class="fas fa-search search-icon-admin"></i>
                            <input type="text" id="searchInputUsers" class="search-input-admin" placeholder="Buscar por usuario o correo...">
                        </div>
                    </div>
                </div>
                <div class="search-results-info" id="usersSearchResultsInfo"></div>
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
                    <table class="table-admin" id="usersTable">
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
                                            <button class="btn-admin btn-primary-admin btn-sm-admin" onclick="editUser(<?= $user['id'] ?>, '<?= htmlspecialchars($user['username']) ?>', '<?= htmlspecialchars($user['email']) ?>', <?= $user['status'] ?>)">
                                                <i class="fas fa-edit"></i> Editar
                                            </button>
                                            <button class="btn-admin btn-danger-admin btn-sm-admin" onclick="deleteUser(<?= $user['id'] ?>, '<?= htmlspecialchars($user['username']) ?>')">
                                                <i class="fas fa-trash"></i> Eliminar
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                            <tr class="no-results-row" style="display: none;">
                                <td colspan="6" class="text-center py-4">
                                    <i class="fas fa-search fa-2x text-muted mb-2"></i>
                                    <p class="text-muted mb-0">No se encontraron resultados para tu búsqueda.</p>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

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
                                    <td>
                                        <i class="fas fa-globe me-2 text-muted"></i>
                                        <?= htmlspecialchars($log['ip']) ?>
                                    </td>
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
            </div>
        </div>

        <div class="tab-pane fade" id="correos-autorizados" role="tabpanel">
            <div class="admin-card">
                <div class="admin-card-header">
                    <h3 class="admin-card-title mb-0">
                        <i class="fas fa-envelope-open me-2"></i>
                        Correos Autorizados
                    </h3>
                    <div class="action-buttons-group">
                        <button class="btn-admin btn-success-admin" data-bs-toggle="modal" data-bs-target="#addAuthEmailModal">
                            <i class="fas fa-plus"></i> Nuevo Correo
                        </button>
                        <div class="search-box-admin">
                            <i class="fas fa-search search-icon-admin"></i>
                            <input type="text" id="searchInputEmails" class="search-input-admin" placeholder="Buscar por correo...">
                        </div>
                    </div>
                </div>
                <div class="search-results-info" id="emailsSearchResultsInfo"></div>
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
                    <table class="table-admin" id="emailsTable">
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
                            <tr class="no-results-row" style="display: none;">
                                <td colspan="3" class="text-center py-4">
                                    <i class="fas fa-search fa-2x text-muted mb-2"></i>
                                    <p class="text-muted mb-0">No se encontraron resultados para tu búsqueda.</p>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="tab-pane fade" id="platforms" role="tabpanel">
            <div class="admin-card">
                <div class="admin-card-header">
                    <h3 class="admin-card-title mb-0">
                        <i class="fas fa-th-large me-2"></i>
                        Gestionar Plataformas y Asuntos
                    </h3>
                    <div class="action-buttons-group">
                        <button class="btn-admin btn-success-admin" data-bs-toggle="modal" data-bs-target="#addPlatformModal">
                            <i class="fas fa-plus"></i> Nueva Plataforma
                        </button>
                        <div class="search-box-admin">
                            <i class="fas fa-search search-icon-admin"></i>
                            <input type="text" id="searchInputPlatforms" class="search-input-admin" placeholder="Buscar por plataforma...">
                        </div>
                    </div>
                </div>
                <div class="search-results-info" id="platformsSearchResultsInfo"></div>
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
                    <table class="table-admin" id="platformsTable">
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
                                                <button class="btn-admin btn-primary-admin btn-sm-admin" onclick="openEditPlatformModal(<?= $platform['id'] ?>, '<?= htmlspecialchars(addslashes($platform['name'])) ?>')">
                                                    <i class="fas fa-edit"></i> Editar / Ver Asuntos
                                                </button>
                                                <button class="btn-admin btn-danger-admin btn-sm-admin" onclick="openDeletePlatformModal(<?= $platform['id'] ?>, '<?= htmlspecialchars(addslashes($platform['name'])) ?>')">
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
                             <tr class="no-results-row" style="display: none;">
                                <td colspan="3" class="text-center py-4">
                                    <i class="fas fa-search fa-2x text-muted mb-2"></i>
                                    <p class="text-muted mb-0">No se encontraron resultados para tu búsqueda.</p>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <div class="tab-pane fade" id="asignaciones" role="tabpanel" aria-labelledby="asignaciones-tab">
            <div class="admin-card">
                <div class="admin-card-header">
                    <h3 class="admin-card-title mb-0">
                        <i class="fas fa-users-cog me-2"></i>
                        Gestión de Permisos por Usuario
                    </h3>
                     <div class="action-buttons-group">
                        <div class="search-box-admin">
                            <i class="fas fa-search search-icon-admin"></i>
                            <input type="text" id="searchInputAssignments" class="search-input-admin" placeholder="Buscar por usuario...">
                        </div>
                    </div>
                </div>
                 <div class="search-results-info" id="assignmentsSearchResultsInfo"></div>
                 <!-- Aviso sobre restricciones desactivadas -->
<?php if (!isset($settings['USER_EMAIL_RESTRICTIONS_ENABLED']) || $settings['USER_EMAIL_RESTRICTIONS_ENABLED'] !== '1'): ?>
    <div class="alert-admin alert-warning-admin">
        <i class="fas fa-exclamation-triangle"></i>
        <div>
            <strong>Restricciones por usuario desactivadas.</strong>
            Para usar esta funcionalidad, activa "Restricciones por usuario" en la pestaña de <strong>Configuración</strong>.
        </div>
    </div>
<?php endif; ?>
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
                    <table class="table-admin" id="assignmentsTable">
                        <thead>
                            <tr>
                                <th><i class="fas fa-user me-2"></i>Usuario</th>
                                <th><i class="fas fa-envelope me-2"></i>Email del Usuario</th>
                                <th><i class="fas fa-list me-2"></i>Correos Asignados</th>
                                <th><i class="fas fa-cogs me-2"></i>Acciones</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (!empty($users_list)): ?>
                                <?php foreach ($users_list as $user): ?>
                                    <tr>
                                        <td>
                                            <i class="fas fa-user-circle me-2 text-primary"></i>
                                            <strong><?= htmlspecialchars($user['username']) ?></strong>
                                            <?php if ($user['status'] == 0): ?>
                                                <span class="badge-admin badge-danger-admin ms-2">
                                                    <i class="fas fa-pause"></i> Inactivo
                                                </span>
                                            <?php else: ?>
                                                <span class="badge-admin badge-success-admin ms-2">
                                                    <i class="fas fa-check"></i> Activo
                                                </span>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <i class="fas fa-at me-2 text-muted"></i>
                                            <?= htmlspecialchars($user['email'] ?? 'Sin email configurado') ?>
                                        </td>
                                        <td>
                                            <div id="assigned-emails-<?= $user['id'] ?>" class="assigned-emails-list">
                                                <span class="text-muted">
                                                    <i class="fas fa-spinner fa-spin me-1"></i>
                                                    Cargando...
                                                </span>
                                            </div>
                                        </td>
                                        <td>
                                            <button class="btn-admin btn-primary-admin btn-sm-admin" onclick="openAssignEmailsModal(<?= $user['id'] ?>, '<?= htmlspecialchars(addslashes($user['username'])) ?>')">
                                                <i class="fas fa-edit"></i> Gestionar Correos
                                            </button>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <tr>
                                    <td colspan="4" class="text-center py-4">
                                        <i class="fas fa-users fa-2x text-muted mb-2"></i>
                                        <p class="text-muted mb-0">No hay usuarios creados todavía.</p>
                                        <small class="text-muted">
                                            Puedes crear usuarios en la pestaña <strong>Usuarios</strong>
                                        </small>
                                    </td>
                                </tr>
                            <?php endif; ?>
                             <tr class="no-results-row" style="display: none;">
                                <td colspan="4" class="text-center py-4">
                                    <i class="fas fa-search fa-2x text-muted mb-2"></i>
                                    <p class="text-muted mb-0">No se encontraron resultados para tu búsqueda.</p>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="tab-pane fade" id="licencia" role="tabpanel">
            <div class="admin-card">
                <div class="admin-card-header">
                    <h3 class="admin-card-title">
                        <i class="fas fa-certificate me-2 text-primary"></i>
                        Estado de la Licencia
                    </h3>
                </div>
                <div class="mb-4">
                    <?php if ($is_license_valid): ?>
                        <div class="alert-admin alert-success-admin">
                            <i class="fas fa-check-circle me-2"></i>
                            <strong>¡Licencia Válida!</strong> Tu sistema está activo y funcionando correctamente.
                        </div>
                        <p><strong>Dominio de la Licencia:</strong> <span class="text-primary"><?= htmlspecialchars($license_info['domain'] ?? 'N/A') ?></span></p>
                        <p><strong>Activada el:</strong> <span class="text-primary"><?= htmlspecialchars($license_info['activated_at'] ?? 'N/A') ?></span></p>
                        <p><strong>Última Verificación:</strong> <span class="text-primary"><?= htmlspecialchars($license_info['last_check'] ?? 'N/A') ?></span></p>
                    <?php else: ?>
                        <div class="alert-admin alert-danger-admin">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            <strong>¡Licencia Inválida o no Encontrada!</strong> Por favor, activa o verifica tu licencia.
                        </div>
                        <?php if ($license_info): ?>
                            <p><strong>Estado Actual:</strong> <span class="text-danger"><?= htmlspecialchars($license_info['status'] ?? 'Desconocido') ?></span></p>
                            <p><strong>Última Verificación:</strong> <span class="text-danger"><?= htmlspecialchars($license_info['last_check'] ?? 'N/A') ?></span></p>
                        <?php endif; ?>
                        <div class="text-center mt-3">
                            <a href="../instalacion/instalador.php?step=license" class="btn-admin btn-primary-admin">
                                <i class="fas fa-key me-2"></i>Activar/Verificar Licencia
                            </a>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
</div>

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

<div class="modal fade modal-admin" id="addAuthEmailModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <form id="addAuthEmailForm"> 
                <input type="hidden" name="action" value="add_authorized_email">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-envelope-plus me-2"></i>
                        Añadir Correo Autorizado
                    </h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="form-group-admin">
                        <label for="add_auth_email_value" class="form-label-admin">
                            <i class="fas fa-envelope me-2"></i>
                            Correo Electrónico
                        </label>
                        <input type="email" class="form-control-admin" id="add_auth_email_value" name="new_email" placeholder="nuevo.correo@ejemplo.com" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-admin btn-secondary-admin" data-bs-dismiss="modal">Cancelar</button>
                    <button type="button" class="btn-admin btn-primary-admin" onclick="submitAddAuthEmailForm()">
                        <i class="fas fa-save"></i> Añadir
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<div class="modal fade modal-admin" id="editEmailModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <form id="editAuthEmailForm">
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
                    <button type="button" name="edit_authorized_email" class="btn-admin btn-primary-admin" onclick="submitEditAuthEmail()">
                        <i class="fas fa-save"></i> Guardar Cambios
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

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

<div class="modal fade modal-admin" id="assignEmailsModal" tabindex="-1" aria-labelledby="assignEmailsModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <form id="assignEmailsForm" method="POST" action="procesar_asignaciones.php">
                <input type="hidden" name="action" value="assign_emails_to_user">
                <input type="hidden" name="user_id" id="assign_user_id">
                
                <div class="modal-header">
                    <h5 class="modal-title" id="assignEmailsModalLabel">
                        <i class="fas fa-user-cog me-2"></i>
                        Gestionar Correos para Usuario
                    </h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                
                <div class="modal-body">
                    <div class="alert-admin alert-info-admin mb-3">
                        <i class="fas fa-info-circle"></i>
                        <div>
                            Selecciona los correos que <strong id="assign_username"></strong> puede consultar en el sistema.
                            <br><small>Los cambios se aplicarán inmediatamente después de guardar.</small>
                        </div>
                    </div>
                    
                    <div class="form-group-admin">
                        <div class="form-check-admin">
                            <input class="form-check-input-admin" type="checkbox" id="select_all_emails">
                            <label class="form-check-label-admin" for="select_all_emails">
                                <i class="fas fa-check-double me-2"></i>
                                <strong>Seleccionar/Deseleccionar Todos</strong>
                            </label>
                        </div>
                    </div>
                    
                    <hr class="my-3">
                    
                    <h6 class="mb-3">
                        <i class="fas fa-envelope-open me-2"></i>
                        Correos Disponibles:
                    </h6>
                    
                    <?php if (!empty($emails_list)): ?>
                        <div class="row">
                            <?php foreach ($emails_list as $email): ?>
                                <div class="col-md-6 mb-2">
                                    <div class="form-check-admin">
                                        <input class="form-check-input-admin email-checkbox" type="checkbox" name="email_ids[]" value="<?= $email['id'] ?>" id="email_<?= $email['id'] ?>">
                                        <label class="form-check-label-admin" for="email_<?= $email['id'] ?>">
                                            <i class="fas fa-envelope me-2 text-muted"></i>
                                            <?= htmlspecialchars($email['email']) ?>
                                        </label>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php else: ?>
                        <div class="alert-admin alert-warning-admin">
                            <i class="fas fa-exclamation-triangle"></i>
                            <div>
                                <strong>No hay correos autorizados configurados.</strong>
                                <br>Primero debes añadir correos en la pestaña <strong>Correos Autorizados</strong>.
                            </div>
                        </div>
                    <?php endif; ?>
                </div>
                
                <div class="modal-footer">
                    <button type="button" class="btn-admin btn-secondary-admin" data-bs-dismiss="modal">
                        <i class="fas fa-times"></i> Cancelar
                    </button>
                    <button type="submit" class="btn-admin btn-primary-admin">
                        <i class="fas fa-save"></i> Guardar Asignaciones
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Sortable/1.15.0/Sortable.min.js"></script>

<script>
// ===== DEFINICIÓN DE TODAS LAS FUNCIONES (SE DEFINEN ANTES DEL DOMContentLoaded) =====

// Función para editar usuario
function editUser(id, username, email, status) {
    console.log('Editando usuario:', id, username, email, status);
    document.getElementById('edit_user_id').value = id;
    document.getElementById('edit_username').value = username;
    document.getElementById('edit_email').value = email || '';
    document.getElementById('edit_status').checked = status == 1;
    
    const modal = new bootstrap.Modal(document.getElementById('editUserModal'));
    modal.show();
}

// Función para eliminar usuario
function deleteUser(id, username) {
    console.log('Eliminando usuario:', id, username);
    document.getElementById('delete_user_id').value = id;
    document.getElementById('delete_username').textContent = username;
    
    const modal = new bootstrap.Modal(document.getElementById('deleteUserModal'));
    modal.show();
}

// Función para toggle de servidores
function toggleServerView(serverId) {
    console.log('Toggle servidor:', serverId);
    const settingsDiv = document.getElementById('server_' + serverId + '_settings');
    const checkbox = document.getElementById('srv_enabled_' + serverId);
    
    if (settingsDiv && checkbox) {
        settingsDiv.style.display = checkbox.checked ? 'block' : 'none';
    }
}

// Función para ver resultado de logs
function verResultado(resultado) {
    console.log('Viendo resultado');
    document.getElementById('resultado_contenido').textContent = resultado;
    const modal = new bootstrap.Modal(document.getElementById('viewResultModal'));
    modal.show();
}

// Función para validar archivo
function validarArchivo() {
    const archivoInput = document.getElementById('logo');
    const archivo = archivoInput.files[0];
    
    if (!archivo) return;
    
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
    return true;
}

// Función para abrir modal de editar plataforma
function openEditPlatformModal(platformId, platformName) {
    console.log('Abriendo modal de plataforma:', platformId, platformName);
    document.getElementById('edit_platform_id').value = platformId;
    document.getElementById('edit_platform_name').value = platformName;
    loadPlatformSubjects(platformId);
    
    const modal = new bootstrap.Modal(document.getElementById('editPlatformModal'));
    modal.show();
}

// Función para abrir modal de eliminar plataforma
function openDeletePlatformModal(platformId, platformName) {
    console.log('Abriendo modal de eliminar plataforma:', platformId, platformName);
    document.getElementById('delete_platform_id').value = platformId;
    document.getElementById('delete_platform_name').textContent = platformName;
    
    const modal = new bootstrap.Modal(document.getElementById('deletePlatformModal'));
    modal.show();
}

// Función para cargar asuntos de plataforma
function loadPlatformSubjects(platformId) {
    const container = document.getElementById('platformSubjectsContainer');
    if (!container) return;
    
    container.innerHTML = '<p class="text-muted">Cargando asuntos...</p>';

    fetch('procesar_plataforma.php?action=get_subjects&platform_id=' + platformId)
        .then(response => response.json())
        .then(data => {
            if (data.success && data.subjects) {
                let tableHtml = '<div class="table-responsive"><table class="table-admin"><thead><tr><th>Asunto</th><th style="width: 150px;">Acciones</th></tr></thead><tbody>';
                
                if (data.subjects.length > 0) {
                    data.subjects.forEach(subject => {
                        tableHtml += '<tr>' +
                                        '<td><i class="fas fa-list me-2 text-primary"></i>' + escapeHtml(subject.subject) + '</td>' +
                                        '<td>' +
                                            '<div class="d-flex gap-sm">' +
                                                '<button type="button" class="btn-admin btn-primary-admin btn-sm-admin" onclick="openEditSubjectModal(' + subject.id + ', \'' + escapeHtml(subject.subject).replace(/'/g, "\\'") + '\', ' + platformId + ', event)">' +
                                                    '<i class="fas fa-edit"></i>' +
                                                '</button>' +
                                                '<button type="button" class="btn-admin btn-danger-admin btn-sm-admin" onclick="deleteSubject(' + subject.id + ', ' + platformId + ', event)">' +
                                                    '<i class="fas fa-trash"></i>' +
                                                '</button>' +
                                            '</div>' +
                                        '</td>' +
                                     '</tr>';
                    });
                } else {
                     tableHtml += '<tr><td colspan="2" class="text-center py-4"><i class="fas fa-list fa-2x text-muted mb-2"></i><p class="text-muted mb-0">No hay asuntos asociados</p></td></tr>';
                }
                tableHtml += '</tbody></table></div>';
                container.innerHTML = tableHtml;
            } else {
                container.innerHTML = '<div class="alert-admin alert-danger-admin">' +
                    '<i class="fas fa-exclamation-circle"></i>' +
                    '<span>Error al cargar asuntos: ' + (data.error || 'Error desconocido') + '</span>' +
                    '</div>';
            }
        })
        .catch(error => {
            console.error('Error cargando asuntos:', error);
            container.innerHTML = '<div class="alert-admin alert-danger-admin">' +
                '<i class="fas fa-exclamation-circle"></i>' +
                '<span>Error de red al cargar asuntos.</span>' +
                '</div>';
        });
}

// Función para añadir asunto
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

    fetch('procesar_plataforma.php', {
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
        console.error('Error añadiendo asunto:', error);
        alert('Error de red al añadir asunto.');
    });
}

// Función para eliminar asunto
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

    fetch('procesar_plataforma.php', {
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
        console.error('Error eliminando asunto:', error);
        alert('Error de red al eliminar asunto.');
    });
}

// Función para abrir modal de editar asunto
function openEditSubjectModal(subjectId, subjectText, platformId, event) {
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    
    document.getElementById('edit_subject_id').value = subjectId;
    document.getElementById('edit_subject_platform_id').value = platformId;
    document.getElementById('edit_subject_text').value = subjectText;
    
    const modal = new bootstrap.Modal(document.getElementById('editSubjectModal'));
    modal.show();
}

// Función para actualizar asunto
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

    fetch('procesar_plataforma.php', {
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
        console.error('Error actualizando asunto:', error);
        alert('Error de red al actualizar asunto.');
    });
}

// Función para guardar orden de plataformas
function savePlatformOrder() {
    const rows = document.getElementById('platformsTableBody').querySelectorAll('tr');
    const orderedIds = Array.from(rows).map(row => row.getAttribute('data-id')).filter(id => id);

    if (orderedIds.length === 0) return;

    const formData = new FormData();
    formData.append('action', 'update_platform_order');
    formData.append('ordered_ids', JSON.stringify(orderedIds)); 

    fetch('procesar_plataforma.php', {
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
        console.error('Error guardando orden:', error);
        alert('Error de red al guardar el orden.');
    });
}

// Función para abrir modal de asignar correos
function openAssignEmailsModal(userId, username) {
    console.log('Abriendo modal para usuario:', userId, username);
    
    if (!userId || !username) {
        alert('Error: Datos de usuario inválidos');
        return;
    }
    
    document.getElementById('assign_user_id').value = userId;
    document.getElementById('assign_username').textContent = username;
    
    // Limpiar selecciones anteriores
    document.querySelectorAll('.email-checkbox').forEach(checkbox => {
        checkbox.checked = false;
    });
    
    const selectAllCheckbox = document.getElementById('select_all_emails');
    if (selectAllCheckbox) {
        selectAllCheckbox.checked = false;
    }
    
    // Cargar emails actualmente asignados
    loadUserEmailsForAssignModal(userId);
    
    // Mostrar modal
    const modal = new bootstrap.Modal(document.getElementById('assignEmailsModal'));
    modal.show();
}

// Función para cargar emails para modal de asignación
function loadUserEmailsForAssignModal(userId) {
    console.log('Cargando emails para modal de usuario:', userId);
    
    fetch('procesar_asignaciones.php?action=get_user_emails&user_id=' + userId, {
        method: 'GET',
        credentials: 'same-origin',
        headers: {
            'X-Requested-With': 'XMLHttpRequest',
            'Accept': 'application/json'
        }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('HTTP ' + response.status + ': ' + response.statusText);
        }
        
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            throw new Error('Respuesta no es JSON válido');
        }
        
        return response.json();
    })
    .then(data => {
        console.log('Datos recibidos para modal:', data);
        
        if (data.success && data.emails) {
            data.emails.forEach(emailObj => {
                const checkbox = document.getElementById('email_' + emailObj.id);
                if (checkbox) {
                    checkbox.checked = true;
                }
            });
        } else {
            // Manejo de error si la respuesta AJAX indica un fallo
            throw new Error(data.error || 'Error desconocido al obtener correos para el modal');
        }
    })
    .catch(error => {
        console.error('Error cargando emails para modal:', error);
        // Alertar al usuario si la carga falla
        alert('Error cargando datos para el modal: ' + error.message);
    });
}

// Función para cargar emails de usuario en tabla
function loadUserEmails(userId) {
    console.log('Cargando emails para usuario en tabla:', userId);
    const container = document.getElementById('assigned-emails-' + userId);
    
    if (!container) {
        console.error('Container no encontrado para usuario:', userId);
        return;
    }
    
    container.innerHTML = '<span class="text-muted"><i class="fas fa-spinner fa-spin me-1"></i>Cargando...</span>';
    
    fetch('procesar_asignaciones.php?action=get_user_emails&user_id=' + userId, {
        method: 'GET',
        credentials: 'same-origin',
        headers: {
            'X-Requested-With': 'XMLHttpRequest',
            'Accept': 'application/json'
        }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('HTTP ' + response.status + ': ' + response.statusText);
        }
        
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            return response.json();
        } else {
            return response.text().then(text => {
                console.error('Respuesta no es JSON. Contenido:', text);
                throw new Error('Respuesta del servidor no es JSON válido');
            });
        }
    })
    .then(data => {
        console.log('Datos para usuario', userId, ':', data);
        
        if (data.success && data.emails) {
            if (data.emails.length > 0) {
                const emailsList = data.emails.map(email => 
                    '<span class="badge-admin badge-info-admin me-1 mb-1">' +
                    '<i class="fas fa-envelope me-1"></i>' +
                    escapeHtml(email.email) +
                    '</span>'
                ).join('');
                
                container.innerHTML = emailsList;
            } else {
                container.innerHTML = '<span class="text-warning"><i class="fas fa-exclamation-triangle me-1"></i>Sin correos asignados</span>';
            }
        } else {
            // Manejo de error si la respuesta AJAX indica un fallo
            throw new Error(data.error || 'Error desconocido al obtener correos asignados');
        }
    })
    .catch(error => {
        console.error('Error cargando emails para usuario', userId, ':', error);
        container.innerHTML = '<span class="text-danger"><i class="fas fa-times me-1"></i>Error: ' + error.message + '</span>';
    });
}

// Función para añadir correo autorizado
function submitAddAuthEmailForm() {
    const form = document.getElementById('addAuthEmailForm');
    const emailInput = document.getElementById('add_auth_email_value');
    
    // Validación del lado del cliente
    if (!emailInput.value.trim()) {
        alert('Por favor, introduce un correo electrónico.');
        return;
    }
    
    // Validación básica de formato de email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(emailInput.value.trim())) {
        alert('Por favor, introduce un correo electrónico válido.');
        return;
    }
    
    const formData = new FormData(form);
    
    console.log('Enviando email:', formData.get('new_email'));

    const modalInstance = bootstrap.Modal.getInstance(document.getElementById('addAuthEmailModal'));
    if (modalInstance) {
        modalInstance.hide();
    }

    fetch('admin.php', {
        method: 'POST',
        body: formData
    })
    .then(response => response.text()) // Usamos .text() primero para depurar respuestas no JSON
    .then(text => {
        console.log('Respuesta del servidor:', text); // Log la respuesta cruda
        try {
            const data = JSON.parse(text);
            if (data.success) {
                alert(data.message || 'Correo autorizado añadido correctamente.');
                // Recargar solo la tabla de correos autorizados si es posible, o toda la página
                // Idealmente, aquí solo se actualizaría la fila en la tabla si se usa AJAX para esa tabla
                setTimeout(() => {
                    location.reload(); 
                }, 1000); 
            } else {
                alert(data.error || 'Ocurrió un error al añadir el correo.');
                console.error('Error al añadir correo:', data.error);
                
                // Reabrir el modal si hay error
                setTimeout(() => {
                    const modal = new bootstrap.Modal(document.getElementById('addAuthEmailModal'));
                    modal.show();
                }, 500);
            }
        } catch (e) {
            alert('Error en la respuesta del servidor (no JSON válido).');
            console.error('Respuesta del servidor no es JSON válido:', text, e);
            
            // Reabrir el modal si hay error
            setTimeout(() => {
                const modal = new bootstrap.Modal(document.getElementById('addAuthEmailModal'));
                modal.show();
            }, 500);
        }
    })
    .catch(error => {
        alert('Error de red o del sistema al añadir correo.');
        console.error('Error de fetch:', error);
        
        // Reabrir el modal si hay error
        setTimeout(() => {
            const modal = new bootstrap.Modal(document.getElementById('addAuthEmailModal'));
            modal.show();
        }, 500);
    });
}

// Función de utilidad para escapar HTML
function escapeHtml(unsafe) {
    if (!unsafe) return '';
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

// ===== INICIO: LÓGICA DE BÚSQUEDA DINÁMICA =====

/**
 * Configura un campo de búsqueda para filtrar una tabla dinámicamente.
 * @param {string} inputId - El ID del elemento <input> de búsqueda.
 * @param {string} tableId - El ID del elemento <table> a filtrar.
 * @param {number[]} columnsToSearch - Un array de índices de las columnas (<td>) a buscar.
 * @param {string} infoId - El ID del elemento donde se mostrará el contador de resultados.
 */
function setupTableSearch(inputId, tableId, columnsToSearch, infoId) {
    const searchInput = document.getElementById(inputId);
    const table = document.getElementById(tableId);
    const infoContainer = document.getElementById(infoId);

    if (!searchInput || !table || !infoContainer) {
        console.error(`Error al configurar la búsqueda: Elementos no encontrados (Input: ${inputId}, Table: ${tableId}, Info: ${infoId})`);
        return;
    }

    const tableBody = table.querySelector('tbody');
    const allRows = Array.from(tableBody.querySelectorAll('tr:not(.no-results-row)'));
    const noResultsRow = tableBody.querySelector('.no-results-row');

    searchInput.addEventListener('keyup', function() {
        const filter = searchInput.value.toLowerCase().trim();
        let visibleCount = 0;

        allRows.forEach(row => {
            let foundMatch = false;
            // Solo buscar en las columnas especificadas
            columnsToSearch.forEach(colIndex => {
                const cell = row.getElementsByTagName('td')[colIndex];
                if (cell) {
                    const cellText = cell.textContent || cell.innerText;
                    if (cellText.toLowerCase().includes(filter)) {
                        foundMatch = true;
                    }
                }
            });

            if (foundMatch) {
                row.style.display = '';
                visibleCount++;
            } else {
                row.style.display = 'none';
            }
        });

        // Mostrar u ocultar la fila "sin resultados"
        if (noResultsRow) {
            noResultsRow.style.display = visibleCount === 0 ? '' : 'none';
        }

        // Actualizar contador de resultados
        infoContainer.innerHTML = `Mostrando <span class="search-match">${visibleCount}</span> de ${allRows.length} registros.`;
    });
    
    // Disparar un evento keyup inicial para establecer el contador
    searchInput.dispatchEvent(new Event('keyup'));
}


// Función para enviar la edición de correo autorizado vía AJAX
function submitEditAuthEmail() {
    const modalInstance = bootstrap.Modal.getInstance(document.getElementById('editEmailModal'));
    const emailId = document.getElementById('edit_email_id').value;
    const emailValue = document.getElementById('edit_email_value').value.trim();

    // Validación simple para asegurar que el correo no esté vacío
    if (!emailValue) {
        alert('El campo de correo no puede estar vacío.');
        return;
    }

    // Preparamos los datos que enviaremos al servidor
    const formData = new FormData();
    formData.append('edit_authorized_email', '1'); // Para que tu PHP sepa qué hacer
    formData.append('edit_email_id', emailId);
    formData.append('edit_email_value', emailValue);

    // Usamos fetch para enviar los datos en segundo plano
    fetch('admin.php', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json()) // Esperamos una respuesta en formato JSON
    .then(data => {
        if (data.success) {
            // Si el servidor responde que todo fue exitoso
            alert(data.message || 'Correo actualizado exitosamente.');
            modalInstance.hide(); // Ocultamos la ventana modal

            // ---- ¡La Magia Sucede Aquí! ----
            // Actualizamos la tabla sin recargar la página.
            const triggerButton = document.querySelector(`button[data-bs-id='${emailId}']`);
            if (triggerButton) {
                const row = triggerButton.closest('tr');
                if (row) {
                    const emailCell = row.cells[0]; // La celda del correo es la primera (índice 0)
                    // Actualizamos el HTML de la celda con el nuevo correo
                    emailCell.innerHTML = `<i class="fas fa-envelope me-2 text-primary"></i> ${escapeHtml(emailValue)}`;
                    // Actualizamos también el botón para que tenga el valor nuevo si se vuelve a editar
                    triggerButton.setAttribute('data-bs-email', emailValue);
                }
            } else {
                // Si por alguna razón no encontramos la fila, recargamos la página como plan B
                location.reload();
            }
        } else {
            // Si el servidor responde con un error
            alert('Error: ' + (data.error || 'Ocurrió un problema.'));
        }
    })
    .catch(error => {
        // Si hay un error de red o algo inesperado
        console.error('Error en la petición de edición:', error);
        alert('Ocurrió un error de conexión. Inténtalo de nuevo.');
    });
}


document.addEventListener('DOMContentLoaded', function() {
    console.log('Iniciando panel de administración...');
    
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

    // Configurar seleccionar todos los emails en modal de asignación
    const selectAllCheckbox = document.getElementById('select_all_emails');
    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener('change', function() {
            const emailCheckboxes = document.querySelectorAll('.email-checkbox');
            emailCheckboxes.forEach(checkbox => {
                checkbox.checked = this.checked;
            });
        });
    }

    // Inicializar drag and drop para plataformas
    const platformsTableBody = document.getElementById('platformsTableBody');
    if (platformsTableBody && typeof Sortable !== 'undefined') {
        try {
            Sortable.create(platformsTableBody, {
                animation: 150,
                handle: 'td:first-child',
                onEnd: function (evt) {
                    savePlatformOrder();
                }
            });
            console.log('Drag and drop configurado para plataformas');
        } catch (error) {
            console.warn('No se pudo configurar drag and drop:', error);
        }
    }

    // ===== FUNCIÓN PARA CARGAR TODOS LOS EMAILS DE USUARIOS =====
    function loadAllUserEmails() {
        console.log('Cargando todos los emails de usuarios...');
        const assignmentsTab = document.getElementById('asignaciones');
        if (!assignmentsTab) {
            console.log('Pestaña de asignaciones no encontrada');
            return;
        }
        
        const userContainers = assignmentsTab.querySelectorAll('[id^="assigned-emails-"]');
        console.log('Contenedores encontrados:', userContainers.length);
        
        userContainers.forEach(container => {
            const userId = container.id.replace('assigned-emails-', '');
            if (userId && !isNaN(userId)) {
                console.log('Cargando emails para usuario:', userId);
                loadUserEmails(parseInt(userId));
            }
        });
    }

    // ===== FUNCIÓN PARA DETECTAR SI UNA PESTAÑA ESTÁ ACTIVA =====
    function isTabActive(tabId) {
        const tabButton = document.getElementById(tabId + '-tab');
        const tabPane = document.getElementById(tabId);
        
        if (!tabButton || !tabPane) return false;
        
        // Verificar si el botón tiene la clase active
        const buttonActive = tabButton.classList.contains('active');
        
        // Verificar si el panel tiene las clases show y active
        const paneActive = tabPane.classList.contains('show') && tabPane.classList.contains('active');
        
        // Verificar por URL
        const urlParams = new URLSearchParams(window.location.search);
        const tabFromUrl = urlParams.get('tab');
        const urlActive = tabFromUrl === tabId;
        
        console.log(`Tab ${tabId} - Button active: ${buttonActive}, Pane active: ${paneActive}, URL active: ${urlActive}`);
        
        return buttonActive || paneActive || urlActive;
    }

    // ===== CONFIGURAR NAVEGACIÓN DE PESTAÑAS DESDE URL (MEJORADO) =====
    const urlParams = new URLSearchParams(window.location.search);
    const tabFromUrl = urlParams.get('tab');
    
    if (tabFromUrl) {
        const tabButton = document.getElementById(tabFromUrl + '-tab');
        if (tabButton) {
            const tab = new bootstrap.Tab(tabButton);
            tab.show();
            
            // Si es la pestaña de asignaciones, cargar emails después de un pequeño delay
            if (tabFromUrl === 'asignaciones') {
                console.log('Cargando asignaciones desde URL...');
                setTimeout(() => {
                    loadAllUserEmails();
                }, 500); // 500ms delay para asegurar que la pestaña esté completamente cargada
            }
        }
    } else {
        // Si no hay pestaña en URL, verificar si asignaciones está activa por defecto
        setTimeout(() => {
            if (isTabActive('asignaciones')) {
                console.log('Asignaciones activa por defecto, cargando emails...');
                loadAllUserEmails();
            }
        }, 200);
    }

    // ===== CONFIGURAR EVENTOS DE PESTAÑAS (MEJORADO) =====
    const tabButtons = document.querySelectorAll('[data-bs-toggle="tab"]');
    tabButtons.forEach(button => {
        button.addEventListener('shown.bs.tab', function(event) {
            const newTab = event.target.getAttribute('data-bs-target').replace('#', '');
            console.log('Cambiando a pestaña:', newTab);
            
            const currentTabInputs = document.querySelectorAll('.current-tab-input');
            currentTabInputs.forEach(input => {
                input.value = newTab;
            });

            // Si la pestaña de asignaciones se activa, recargar los correos
            if (newTab === 'asignaciones') {
                console.log('Pestaña asignaciones activada manualmente, cargando emails...');
                setTimeout(() => {
                    loadAllUserEmails();
                }, 200); // Delay para asegurar que el DOM esté listo
            }
        });
    });

    // Configurar búsquedas en las tablas si existen
    if (typeof setupTableSearch === 'function') {
        setupTableSearch('searchInputUsers', 'usersTable', [1, 2], 'usersSearchResultsInfo');
        setupTableSearch('searchInputEmails', 'emailsTable', [0], 'emailsSearchResultsInfo');
        setupTableSearch('searchInputPlatforms', 'platformsTable', [0], 'platformsSearchResultsInfo');
        setupTableSearch('searchInputAssignments', 'assignmentsTable', [0], 'assignmentsSearchResultsInfo');
    }

    // ===== FUNCIÓN PARA DEBUGGING (OPCIONAL) =====
    window.forceReloadAllEmails = function() {
        console.log('Forzando recarga de todos los emails...');
        loadAllUserEmails();
    };

    console.log('Panel de administración inicializado correctamente');
});

// ===== TAMBIÉN MEJORA LA FUNCIÓN loadUserEmails =====
// Busca esta función en tu archivo y mejórala con mejor manejo de errores:

function loadUserEmails(userId) {
    console.log('Cargando emails para usuario en tabla:', userId);
    const container = document.getElementById('assigned-emails-' + userId);
    
    if (!container) {
        console.error('Container no encontrado para usuario:', userId);
        return;
    }
    
    container.innerHTML = '<span class="text-muted"><i class="fas fa-spinner fa-spin me-1"></i>Cargando...</span>';
    
    // Añadir timestamp para evitar cache
    const timestamp = new Date().getTime();
    
    fetch(`procesar_asignaciones.php?action=get_user_emails&user_id=${userId}&_t=${timestamp}`, {
        method: 'GET',
        credentials: 'same-origin',
        headers: {
            'X-Requested-With': 'XMLHttpRequest',
            'Accept': 'application/json',
            'Cache-Control': 'no-cache'
        }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('HTTP ' + response.status + ': ' + response.statusText);
        }
        
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            return response.json();
        } else {
            return response.text().then(text => {
                console.error('Respuesta no es JSON. Contenido:', text);
                throw new Error('Respuesta del servidor no es JSON válido');
            });
        }
    })
    .then(data => {
        console.log('Datos para usuario', userId, ':', data);
        
        if (data.success && data.emails) {
            if (data.emails.length > 0) {
                const emailsList = data.emails.map(email => 
                    '<span class="badge-admin badge-info-admin me-1 mb-1">' +
                    '<i class="fas fa-envelope me-1"></i>' +
                    escapeHtml(email.email) +
                    '</span>'
                ).join('');
                
                container.innerHTML = emailsList;
            } else {
                container.innerHTML = '<span class="text-warning"><i class="fas fa-exclamation-triangle me-1"></i>Sin correos asignados</span>';
            }
        } else {
            throw new Error(data.error || 'Error desconocido al obtener correos asignados');
        }
    })
    .catch(error => {
        console.error('Error cargando emails para usuario', userId, ':', error);
        container.innerHTML = '<span class="text-danger"><i class="fas fa-times me-1"></i>Error: ' + error.message + '</span>';
        
        // Reintentar después de 2 segundos
        setTimeout(() => {
            console.log('Reintentando carga para usuario:', userId);
            loadUserEmails(userId);
        }, 2000);
    });
}
</script>