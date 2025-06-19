<?php
/**
 * SCRIPT DE ACTUALIZACIÓN PARA INSTALACIÓN EXISTENTE
 * Ejecutar UNA SOLA VEZ después de aplicar los cambios
 * Eliminar después de usar
 */

session_start();
require_once 'instalacion/basededatos.php';
require_once 'security/auth.php';

// Verificar que sea admin
check_session(true, 'index.php');

$conn = new mysqli($db_host, $db_user, $db_password, $db_name);
$conn->set_charset("utf8mb4");

if ($conn->connect_error) {
    die("Error de conexión: " . $conn->connect_error);
}

echo "🔧 <strong>Actualizando configuración para zona horaria...</strong><br><br>";

// Agregar nueva configuración si no existe
$new_settings = [
    'TIMEZONE_DEBUG_HOURS' => ['48', 'Horas hacia atrás para búsqueda inicial IMAP (para manejar zonas horarias)'],
    'PERFORMANCE_LOGGING' => ['0', 'Activar logs de rendimiento (temporal para debugging)']
];

foreach ($new_settings as $name => $data) {
    $value = $data[0];
    $description = $data[1];
    
    // Verificar si ya existe
    $check_stmt = $conn->prepare("SELECT name FROM settings WHERE name = ?");
    $check_stmt->bind_param("s", $name);
    $check_stmt->execute();
    $result = $check_stmt->get_result();
    
    if ($result->num_rows == 0) {
        // No existe, crear
        $insert_stmt = $conn->prepare("INSERT INTO settings (name, value, description) VALUES (?, ?, ?)");
        $insert_stmt->bind_param("sss", $name, $value, $description);
        if ($insert_stmt->execute()) {
            echo "✅ Agregada configuración: <strong>$name</strong> = $value<br>";
        } else {
            echo "❌ Error agregando $name: " . $insert_stmt->error . "<br>";
        }
        $insert_stmt->close();
    } else {
        echo "ℹ️ Configuración <strong>$name</strong> ya existe<br>";
    }
    $check_stmt->close();
}

// Opcional: Ajustar EMAIL_QUERY_TIME_LIMIT_MINUTES si está en 20 (muy restrictivo)
$current_limit_stmt = $conn->prepare("SELECT value FROM settings WHERE name = 'EMAIL_QUERY_TIME_LIMIT_MINUTES'");
$current_limit_stmt->execute();
$current_limit_result = $current_limit_stmt->get_result();

if ($current_limit_result->num_rows > 0) {
    $current_limit = $current_limit_result->fetch_assoc()['value'];
    
    if ($current_limit == '20') {
        echo "<br>⚠️ <strong>Recomendación:</strong> Tu límite actual es de 20 minutos, que puede ser muy restrictivo.<br>";
        echo "📧 Los emails en tu test son de hace ~174 minutos, sugiriendo que los códigos pueden tardar más.<br>";
        echo "<br>¿Quieres actualizar a 30 minutos? (más realista para códigos de verificación)<br>";
        echo "<a href='?update_limit=30' style='background: #32FFB5; color: #000; padding: 8px 16px; text-decoration: none; border-radius: 5px; margin: 5px;'>✅ SÍ, actualizar a 30 min</a> ";
        echo "<a href='?keep_limit=1' style='background: #666; color: #fff; padding: 8px 16px; text-decoration: none; border-radius: 5px; margin: 5px;'>⏸️ Mantener 20 min</a><br><br>";
    }
}
$current_limit_stmt->close();

// Procesar actualización de límite si se solicita
if (isset($_GET['update_limit'])) {
    $new_limit = (int)$_GET['update_limit'];
    $update_stmt = $conn->prepare("UPDATE settings SET value = ? WHERE name = 'EMAIL_QUERY_TIME_LIMIT_MINUTES'");
    $update_stmt->bind_param("s", $new_limit);
    if ($update_stmt->execute()) {
        echo "✅ <strong>Límite actualizado a $new_limit minutos</strong><br>";
    } else {
        echo "❌ Error actualizando límite: " . $update_stmt->error . "<br>";
    }
    $update_stmt->close();
    
    // Limpiar cache
    require_once 'cache/cache_helper.php';
    SimpleCache::clear_settings_cache();
    echo "🧹 Cache de configuración limpiado<br>";
}

if (isset($_GET['keep_limit'])) {
    echo "ℹ️ Límite mantenido en 20 minutos<br>";
}

echo "<br><hr>";
echo "<h3>✅ Actualización completada</h3>";
echo "<p><strong>Próximos pasos:</strong></p>";
echo "<ol>";
echo "<li>Ve al Panel Admin → Configuración → Optimizaciones de Performance</li>";
echo "<li>Verifica que 'Rango de búsqueda' esté en 48 horas</li>";
echo "<li>Activa temporalmente 'Logs de performance' para debugging</li>";
echo "<li>Prueba una búsqueda real</li>";
echo "<li>Elimina este archivo: <code>rm update_timezone_config.php</code></li>";
echo "</ol>";

$conn->close();
?>