<?php
/**
 * MONITOR DE PERFORMANCE CONTINUO
 * Ejecutar mensualmente para verificar que el sistema sigue optimizado
 */

session_start();
require_once 'instalacion/basededatos.php';
require_once 'funciones.php';

echo "<h1>📊 MONITOR DE PERFORMANCE CONTINUO</h1>";
echo "<style>
    body { font-family: Arial, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }
    .alert { padding: 15px; margin: 10px 0; border-radius: 8px; }
    .good { background: #1b5e20; border-left: 4px solid #4CAF50; }
    .warning { background: #ff8f00; border-left: 4px solid #FF9800; color: #000; }
    .critical { background: #c62828; border-left: 4px solid #F44336; }
    .metric { background: #16213e; padding: 10px; margin: 5px 0; border-radius: 5px; }
    table { width: 100%; border-collapse: collapse; margin: 15px 0; }
    th, td { padding: 8px; text-align: left; border-bottom: 1px solid #333; }
    th { background: #2a2a40; }
</style>";

$conn = new mysqli($db_host, $db_user, $db_password, $db_name);
$conn->set_charset("utf8mb4");

if ($conn->connect_error) {
    die("❌ Error de conexión: " . $conn->connect_error);
}

// 1. VERIFICAR CONFIGURACIÓN CRÍTICA
echo "<h2>⚙️ Verificación de Configuración Crítica</h2>";
checkCriticalSettings($conn);

// 2. TEST RÁPIDO DE PERFORMANCE
echo "<h2>🚀 Test Rápido de Performance</h2>";
quickPerformanceTest($conn);

// 3. ANÁLISIS DE LOGS RECIENTES
echo "<h2>📈 Análisis de Logs (Últimos 7 días)</h2>";
analyzeRecentLogs($conn);

// 4. SALUD DEL SISTEMA
echo "<h2>💊 Salud General del Sistema</h2>";
systemHealthCheck($conn);

/**
 * Verificar configuraciones críticas
 */
function checkCriticalSettings($conn) {
    $critical_settings = [
        'EARLY_SEARCH_STOP' => ['expected' => '1', 'critical' => true],
        'EMAIL_QUERY_TIME_LIMIT_MINUTES' => ['expected' => ['15', '20', '30'], 'critical' => false],
        'MAX_EMAILS_TO_CHECK' => ['expected' => ['30', '35', '40', '50'], 'critical' => false],
        'CACHE_ENABLED' => ['expected' => '1', 'critical' => false]
    ];
    
    foreach ($critical_settings as $setting_name => $config) {
        $stmt = $conn->prepare("SELECT value FROM settings WHERE name = ?");
        $stmt->bind_param("s", $setting_name);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($row = $result->fetch_assoc()) {
            $current_value = $row['value'];
            $expected = $config['expected'];
            $is_critical = $config['critical'];
            
            $is_correct = is_array($expected) ? in_array($current_value, $expected) : ($current_value === $expected);
            
            if ($is_correct) {
                echo "<div class='alert good'>✅ $setting_name: $current_value (Correcto)</div>";
            } else {
                $alert_class = $is_critical ? 'critical' : 'warning';
                $expected_str = is_array($expected) ? implode(', ', $expected) : $expected;
                echo "<div class='alert $alert_class'>⚠️ $setting_name: $current_value (Esperado: $expected_str)</div>";
            }
        } else {
            echo "<div class='alert critical'>❌ $setting_name: No configurado</div>";
        }
        $stmt->close();
    }
}

/**
 * Test rápido de performance
 */
function quickPerformanceTest($conn) {
    try {
        $search_engine = new EmailSearchEngine($conn);
        
        // Obtener un email autorizado para test
        $result = $conn->query("SELECT email FROM authorized_emails LIMIT 1");
        if (!$result || $result->num_rows === 0) {
            echo "<div class='alert warning'>⚠️ No hay emails autorizados para probar</div>";
            return;
        }
        
        $test_email = $result->fetch_assoc()['email'];
        
        // Obtener una plataforma para test
        $platforms = SimpleCache::get_platform_subjects($conn);
        if (empty($platforms)) {
            echo "<div class='alert warning'>⚠️ No hay plataformas configuradas para probar</div>";
            return;
        }
        
        $test_platform = array_key_first($platforms);
        
        echo "<div class='metric'>🧪 Probando: $test_email en $test_platform</div>";
        
        $start_time = microtime(true);
        $result = $search_engine->searchEmails($test_email, $test_platform, null);
        $search_time = (microtime(true) - $start_time) * 1000;
        
        if ($search_time < 2000) {
            echo "<div class='alert good'>🚀 Excelente: {$search_time}ms (< 2s)</div>";
        } elseif ($search_time < 5000) {
            echo "<div class='alert good'>✅ Bueno: {$search_time}ms (2-5s)</div>";
        } elseif ($search_time < 10000) {
            echo "<div class='alert warning'>⚠️ Aceptable: {$search_time}ms (5-10s)</div>";
        } else {
            echo "<div class='alert critical'>❌ Lento: {$search_time}ms (> 10s)</div>";
        }
        
        if ($result['found']) {
            echo "<div class='metric'>✅ Resultado encontrado correctamente</div>";
        } else {
            echo "<div class='metric'>⚪ Sin resultados (normal para emails de prueba)</div>";
        }
        
    } catch (Exception $e) {
        echo "<div class='alert critical'>❌ Error en test: " . htmlspecialchars($e->getMessage()) . "</div>";
    }
}

/**
 * Analizar logs recientes
 */
function analyzeRecentLogs($conn) {
    $seven_days_ago = date('Y-m-d H:i:s', strtotime('-7 days'));
    
    // Estadísticas generales
    $stats_query = "
        SELECT 
            COUNT(*) as total_searches,
            COUNT(CASE WHEN resultado LIKE '%Éxito%' THEN 1 END) as successful_searches,
            AVG(CASE WHEN resultado LIKE '%Éxito%' THEN 1 ELSE 0 END) * 100 as success_rate
        FROM logs 
        WHERE fecha >= ?
    ";
    
    $stmt = $conn->prepare($stats_query);
    $stmt->bind_param("s", $seven_days_ago);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($row = $result->fetch_assoc()) {
        echo "<table>";
        echo "<tr><th>Métrica</th><th>Valor</th><th>Estado</th></tr>";
        
        $total = $row['total_searches'];
        $successful = $row['successful_searches'];
        $success_rate = round($row['success_rate'], 1);
        
        echo "<tr><td>Total de búsquedas</td><td>$total</td><td>📊</td></tr>";
        echo "<tr><td>Búsquedas exitosas</td><td>$successful</td><td>📈</td></tr>";
        
        if ($success_rate >= 30) {
            echo "<tr><td>Tasa de éxito</td><td>{$success_rate}%</td><td>✅</td></tr>";
        } elseif ($success_rate >= 10) {
            echo "<tr><td>Tasa de éxito</td><td>{$success_rate}%</td><td>⚠️</td></tr>";
        } else {
            echo "<tr><td>Tasa de éxito</td><td>{$success_rate}%</td><td>❌</td></tr>";
        }
        
        echo "</table>";
    }
    $stmt->close();
    
    // Emails más consultados
    echo "<h4>📧 Emails Más Consultados</h4>";
    $top_emails_query = "
        SELECT email_consultado, COUNT(*) as consultas 
        FROM logs 
        WHERE fecha >= ? 
        GROUP BY email_consultado 
        ORDER BY consultas DESC 
        LIMIT 5
    ";
    
    $stmt = $conn->prepare($top_emails_query);
    $stmt->bind_param("s", $seven_days_ago);
    $stmt->execute();
    $result = $stmt->get_result();
    
    echo "<table>";
    echo "<tr><th>Email</th><th>Consultas</th></tr>";
    while ($row = $result->fetch_assoc()) {
        echo "<tr><td>" . htmlspecialchars($row['email_consultado']) . "</td><td>{$row['consultas']}</td></tr>";
    }
    echo "</table>";
    $stmt->close();
}

/**
 * Verificar salud general del sistema
 */
function systemHealthCheck($conn) {
    $health_score = 0;
    $max_score = 5;
    
    // 1. Verificar servidores IMAP habilitados
    $result = $conn->query("SELECT COUNT(*) as count FROM email_servers WHERE enabled = 1");
    $enabled_servers = $result->fetch_assoc()['count'];
    
    if ($enabled_servers > 0) {
        echo "<div class='alert good'>✅ Servidores IMAP: $enabled_servers habilitado(s)</div>";
        $health_score++;
    } else {
        echo "<div class='alert critical'>❌ Sin servidores IMAP habilitados</div>";
    }
    
    // 2. Verificar emails autorizados
    $result = $conn->query("SELECT COUNT(*) as count FROM authorized_emails");
    $auth_emails = $result->fetch_assoc()['count'];
    
    if ($auth_emails > 0) {
        echo "<div class='alert good'>✅ Emails autorizados: $auth_emails configurados</div>";
        $health_score++;
    } else {
        echo "<div class='alert warning'>⚠️ Sin emails autorizados configurados</div>";
    }
    
    // 3. Verificar plataformas
    $result = $conn->query("SELECT COUNT(*) as count FROM platforms");
    $platforms = $result->fetch_assoc()['count'];
    
    if ($platforms > 0) {
        echo "<div class='alert good'>✅ Plataformas: $platforms configuradas</div>";
        $health_score++;
    } else {
        echo "<div class='alert critical'>❌ Sin plataformas configuradas</div>";
    }
    
    // 4. Verificar actividad reciente
    $result = $conn->query("SELECT COUNT(*) as count FROM logs WHERE fecha >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");
    $recent_activity = $result->fetch_assoc()['count'];
    
    if ($recent_activity > 0) {
        echo "<div class='alert good'>✅ Actividad reciente: $recent_activity búsquedas en 24h</div>";
        $health_score++;
    } else {
        echo "<div class='alert warning'>⚠️ Sin actividad en las últimas 24 horas</div>";
    }
    
    // 5. Verificar espacio de caché
    $cache_dir = 'cache/data/';
    if (is_dir($cache_dir)) {
        $cache_files = glob($cache_dir . '*.json');
        $cache_count = count($cache_files);
        
        if ($cache_count > 0) {
            echo "<div class='alert good'>✅ Caché: $cache_count archivos activos</div>";
            $health_score++;
        } else {
            echo "<div class='alert warning'>⚠️ Caché vacío</div>";
        }
    }
    
    // Puntuación final
    $health_percentage = ($health_score / $max_score) * 100;
    
    echo "<h4>🏥 Puntuación de Salud del Sistema</h4>";
    if ($health_percentage >= 80) {
        echo "<div class='alert good'>🌟 Excelente: {$health_percentage}% ({$health_score}/{$max_score})</div>";
    } elseif ($health_percentage >= 60) {
        echo "<div class='alert warning'>⚠️ Bueno: {$health_percentage}% ({$health_score}/{$max_score})</div>";
    } else {
        echo "<div class='alert critical'>❌ Necesita atención: {$health_percentage}% ({$health_score}/{$max_score})</div>";
    }
}

echo "<hr><small>📅 Monitor ejecutado: " . date('Y-m-d H:i:s') . "</small>";
echo "<br><small>🔄 Ejecutar mensualmente para monitoreo continuo</small>";
echo "<br><small>🗑️ Eliminar después de usar</small>";
?>