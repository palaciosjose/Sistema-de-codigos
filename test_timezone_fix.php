<?php
/*
HERRAMIENTA DE DEBUG TEMPORAL
Crear archivo: debug_test.php en la raíz de tu proyecto
Acceder vía: http://tudominio.com/debug_test.php
¡ELIMINAR DESPUÉS DE LAS PRUEBAS!
*/

session_start();
require_once 'funciones.php';
require_once 'instalacion/basededatos.php';

// Solo permitir acceso a admin
if (!isset($_SESSION['user_role']) || $_SESSION['user_role'] !== 'admin') {
    die('❌ Acceso denegado. Solo para administradores.');
}

$conn = new mysqli($db_host, $db_user, $db_password, $db_name);
$conn->set_charset("utf8mb4");

if ($conn->connect_error) {
    die("Error de conexión: " . $conn->connect_error);
}

?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🧪 Debug - Sistema de Restricciones</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .section { margin-bottom: 30px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .success { background: #d4edda; border-color: #c3e6cb; color: #155724; }
        .error { background: #f8d7da; border-color: #f5c6cb; color: #721c24; }
        .info { background: #d1ecf1; border-color: #bee5eb; color: #0c5460; }
        .warning { background: #fff3cd; border-color: #ffeaa7; color: #856404; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 10px; border: 1px solid #ddd; text-align: left; }
        th { background: #f8f9fa; }
        .status-ok { color: #28a745; font-weight: bold; }
        .status-error { color: #dc3545; font-weight: bold; }
        .test-form { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .btn { padding: 8px 15px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn:hover { background: #0056b3; }
        .btn-test { background: #28a745; }
        .btn-danger { background: #dc3545; }
        pre { background: #f8f9fa; padding: 10px; border-radius: 4px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🧪 Debug - Sistema de Restricciones de Correos</h1>
        <p><strong>Usuario actual:</strong> <?= htmlspecialchars($_SESSION['username']) ?> (<?= htmlspecialchars($_SESSION['user_role']) ?>)</p>
        
        <div class="section info">
            <h2>📋 1. Verificación de Configuración</h2>
            <?php
            $settings = SimpleCache::get_settings($conn);
            $email_auth = ($settings['EMAIL_AUTH_ENABLED'] ?? '0') === '1';
            $user_restrictions = ($settings['USER_EMAIL_RESTRICTIONS_ENABLED'] ?? '0') === '1';
            ?>
            <table>
                <tr>
                    <th>Configuración</th>
                    <th>Estado</th>
                    <th>Valor</th>
                </tr>
                <tr>
                    <td>Filtro de Correos Electrónicos</td>
                    <td><span class="<?= $email_auth ? 'status-ok' : 'status-error' ?>"><?= $email_auth ? '✅ ACTIVADO' : '❌ DESACTIVADO' ?></span></td>
                    <td><?= $settings['EMAIL_AUTH_ENABLED'] ?? '0' ?></td>
                </tr>
                <tr>
                    <td>Restricciones por Usuario</td>
                    <td><span class="<?= $user_restrictions ? 'status-ok' : 'status-error' ?>"><?= $user_restrictions ? '✅ ACTIVADO' : '❌ DESACTIVADO' ?></span></td>
                    <td><?= $settings['USER_EMAIL_RESTRICTIONS_ENABLED'] ?? '0' ?></td>
                </tr>
            </table>
            
            <?php if (!$email_auth || !$user_restrictions): ?>
                <div class="error" style="margin-top: 15px;">
                    <strong>⚠️ Configuración Incorrecta:</strong> Para probar el sistema completo, ambas opciones deben estar activadas.
                </div>
            <?php endif; ?>
        </div>

        <div class="section">
            <h2>📧 2. Correos Autorizados</h2>
            <?php
            $result = $conn->query("SELECT id, email, created_at FROM authorized_emails ORDER BY email ASC");
            ?>
            <table>
                <tr>
                    <th>ID</th>
                    <th>Email</th>
                    <th>Fecha Creación</th>
                </tr>
                <?php while ($row = $result->fetch_assoc()): ?>
                <tr>
                    <td><?= $row['id'] ?></td>
                    <td><?= htmlspecialchars($row['email']) ?></td>
                    <td><?= $row['created_at'] ?></td>
                </tr>
                <?php endwhile; ?>
            </table>
        </div>

        <div class="section">
            <h2>👥 3. Usuarios y Asignaciones</h2>
            <?php
            $query = "
                SELECT 
                    u.id as user_id,
                    u.username,
                    u.email as user_email,
                    u.status,
                    GROUP_CONCAT(ae.email ORDER BY ae.email SEPARATOR ', ') as assigned_emails,
                    COUNT(ae.id) as email_count
                FROM users u
                LEFT JOIN user_authorized_emails uae ON u.id = uae.user_id
                LEFT JOIN authorized_emails ae ON uae.authorized_email_id = ae.id
                WHERE u.id NOT IN (SELECT id FROM admin)
                GROUP BY u.id, u.username, u.email, u.status
                ORDER BY u.username
            ";
            $result = $conn->query($query);
            ?>
            <table>
                <tr>
                    <th>ID</th>
                    <th>Usuario</th>
                    <th>Email Usuario</th>
                    <th>Estado</th>
                    <th>Correos Asignados</th>
                    <th>Cantidad</th>
                </tr>
                <?php while ($row = $result->fetch_assoc()): ?>
                <tr>
                    <td><?= $row['user_id'] ?></td>
                    <td><?= htmlspecialchars($row['username']) ?></td>
                    <td><?= htmlspecialchars($row['user_email']) ?></td>
                    <td><span class="<?= $row['status'] ? 'status-ok' : 'status-error' ?>"><?= $row['status'] ? 'Activo' : 'Inactivo' ?></span></td>
                    <td><?= $row['assigned_emails'] ?: '<em>Sin asignaciones</em>' ?></td>
                    <td><?= $row['email_count'] ?></td>
                </tr>
                <?php endwhile; ?>
            </table>
        </div>

        <div class="section">
            <h2>🧪 4. Prueba en Vivo del Sistema</h2>
            
            <?php if (isset($_POST['test_email']) && isset($_POST['test_user'])): ?>
                <div class="test-form">
                    <h3>🔍 Resultado de la Prueba</h3>
                    <?php
                    $test_email = $_POST['test_email'];
                    $test_user = intval($_POST['test_user']);
                    
                    // Simular sesión del usuario de prueba
                    $original_user_id = $_SESSION['user_id'];
                    $original_user_role = $_SESSION['user_role'];
                    
                    // Obtener datos del usuario de prueba
                    $stmt = $conn->prepare("SELECT username FROM users WHERE id = ?");
                    $stmt->bind_param("i", $test_user);
                    $stmt->execute();
                    $user_result = $stmt->get_result();
                    $user_data = $user_result->fetch_assoc();
                    $stmt->close();
                    
                    if ($user_data) {
                        // Cambiar sesión temporalmente
                        $_SESSION['user_id'] = $test_user;
                        $_SESSION['user_role'] = 'usuario'; // No admin para la prueba
                        
                        // Probar con la clase EmailProcessor
                        $emailProcessor = new EmailProcessor($conn);
                        
                        // Llamar al método privado usando reflection para debug
                        $reflection = new ReflectionClass($emailProcessor);
                        $method = $reflection->getMethod('isAuthorizedEmail');
                        $method->setAccessible(true);
                        
                        $result = $method->invoke($emailProcessor, $test_email);
                        
                        // Restaurar sesión original
                        $_SESSION['user_id'] = $original_user_id;
                        $_SESSION['user_role'] = $original_user_role;
                        
                        echo "<strong>📧 Email consultado:</strong> " . htmlspecialchars($test_email) . "<br>";
                        echo "<strong>👤 Usuario de prueba:</strong> " . htmlspecialchars($user_data['username']) . " (ID: $test_user)<br>";
                        echo "<strong>🎯 Resultado:</strong> ";
                        
                        if ($result) {
                            echo "<span class='status-ok'>✅ PERMITIDO</span>";
                        } else {
                            echo "<span class='status-error'>❌ DENEGADO</span>";
                        }
                        
                        echo "<br><br>";
                        echo "<em>Revisa los logs de error del servidor para ver el debug detallado de esta consulta.</em>";
                    } else {
                        echo "<div class='error'>❌ Usuario de prueba no encontrado.</div>";
                    }
                    ?>
                </div>
            <?php endif; ?>
            
            <form method="POST" class="test-form">
                <h3>Simular Consulta de Usuario</h3>
                <p>Esta prueba simula qué pasaría si un usuario específico intenta consultar un correo.</p>
                
                <label><strong>Email a consultar:</strong></label>
                <select name="test_email" required style="width: 100%; padding: 5px; margin: 5px 0;">
                    <option value="">Seleccionar correo...</option>
                    <?php
                    $emails_result = $conn->query("SELECT email FROM authorized_emails ORDER BY email ASC");
                    while ($email_row = $emails_result->fetch_assoc()):
                    ?>
                    <option value="<?= htmlspecialchars($email_row['email']) ?>"><?= htmlspecialchars($email_row['email']) ?></option>
                    <?php endwhile; ?>
                </select>
                
                <label><strong>Usuario que consulta:</strong></label>
                <select name="test_user" required style="width: 100%; padding: 5px; margin: 5px 0;">
                    <option value="">Seleccionar usuario...</option>
                    <?php
                    $users_result = $conn->query("SELECT id, username FROM users WHERE id NOT IN (SELECT id FROM admin) ORDER BY username ASC");
                    while ($user_row = $users_result->fetch_assoc()):
                    ?>
                    <option value="<?= $user_row['id'] ?>"><?= htmlspecialchars($user_row['username']) ?> (ID: <?= $user_row['id'] ?>)</option>
                    <?php endwhile; ?>
                </select>
                
                <br><br>
                <button type="submit" class="btn btn-test">🧪 Ejecutar Prueba</button>
            </form>
        </div>

        <div class="section warning">
            <h2>🚨 Configurar Debug Logs</h2>
            <p>Para ver el debug detallado, agrega este código temporalmente al inicio de la función <code>isAuthorizedEmail()</code> en <code>funciones.php</code>:</p>
            <pre>// Al inicio de la función isAuthorizedEmail()
error_log("=== DEBUG RESTRICCIONES ===");
error_log("Email: $email");
error_log("Auth enabled: " . ($auth_enabled ? 'SÍ' : 'NO'));
error_log("User restrictions: " . ($user_restrictions_enabled ? 'SÍ' : 'NO'));
error_log("User ID: " . ($_SESSION['user_id'] ?? 'NULL'));
error_log("User role: " . ($_SESSION['user_role'] ?? 'NULL'));</pre>
            <p><strong>Ubicación de logs:</strong></p>
            <ul>
                <li><strong>Linux/Apache:</strong> <code>/var/log/apache2/error.log</code></li>
                <li><strong>XAMPP Windows:</strong> <code>C:\xampp\apache\logs\error.log</code></li>
                <li><strong>WAMP:</strong> <code>C:\wamp\logs\apache_error.log</code></li>
            </ul>
        </div>

        <div class="section">
            <h2>🔧 Acciones Rápidas</h2>
            <a href="admin/admin.php?tab=config" class="btn">⚙️ Ir a Configuración</a>
            <a href="admin/admin.php?tab=asignaciones" class="btn">👥 Gestionar Asignaciones</a>
            <a href="admin/admin.php?tab=correos_autorizados" class="btn">📧 Correos Autorizados</a>
            <a href="inicio.php" class="btn">🏠 Volver al Sistema</a>
            <br><br>
            <p style="color: #dc3545; font-weight: bold;">⚠️ ¡IMPORTANTE! Elimina este archivo (debug_test.php) después de completar las pruebas por seguridad.</p>
        </div>
    </div>
</body>
</html>