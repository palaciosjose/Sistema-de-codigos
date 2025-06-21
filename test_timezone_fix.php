<?php
/**
 * Archivo de debugging COMPLETO para verificar configuraciones de admin
 * Incluye TODAS las configuraciones del sistema + test de guardado en tiempo real
 */

session_start();
require_once 'instalacion/basededatos.php';
require_once 'cache/cache_helper.php';

echo "<h1>🔧 Diagnóstico COMPLETO de Configuraciones de Admin</h1>";
echo "<style>
    body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
    .section { background: white; padding: 20px; margin: 10px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .success { color: #28a745; font-weight: bold; }
    .error { color: #dc3545; font-weight: bold; }
    .warning { color: #ffc107; font-weight: bold; }
    .info { color: #17a2b8; font-weight: bold; }
    table { width: 100%; border-collapse: collapse; margin: 10px 0; }
    th, td { padding: 8px; border: 1px solid #ddd; text-align: left; }
    th { background-color: #f8f9fa; }
    .value-1 { background-color: #d4edda; }
    .value-0 { background-color: #f8d7da; }
    .value-numeric { background-color: #e7f3ff; }
    .value-text { background-color: #f0f0f0; }
    .discrepancy { background-color: #fff3cd; border-left: 4px solid #856404; }
    .real-time-test { background: #e8f5e8; padding: 15px; border-radius: 5px; margin: 10px 0; }
    .test-result { padding: 10px; margin: 5px 0; border-radius: 5px; }
    .test-success { background: #d4edda; border: 1px solid #c3e6cb; }
    .test-error { background: #f8d7da; border: 1px solid #f5c6cb; }
    .category-header { background: #007bff; color: white; font-weight: bold; }
</style>";

// Verificar conexión a BD
echo "<div class='section'>";
echo "<h2>1. 🔌 Conexión a Base de Datos</h2>";
try {
    $conn = new mysqli($db_host, $db_user, $db_password, $db_name);
    $conn->set_charset("utf8mb4");
    
    if ($conn->connect_error) {
        throw new Exception("Error de conexión: " . $conn->connect_error);
    }
    
    echo "<span class='success'>✅ Conexión exitosa a la base de datos</span><br>";
    echo "📊 Host: $db_host | Base de datos: $db_name<br>";
    
} catch (Exception $e) {
    echo "<span class='error'>❌ Error de conexión: " . $e->getMessage() . "</span>";
    exit();
}
echo "</div>";

// Verificar tabla settings
echo "<div class='section'>";
echo "<h2>2. 📋 Tabla de Configuraciones</h2>";
$settings_check = $conn->query("SHOW TABLES LIKE 'settings'");
if ($settings_check->num_rows > 0) {
    echo "<span class='success'>✅ Tabla 'settings' existe</span><br>";
    
    $count_query = $conn->query("SELECT COUNT(*) as total FROM settings");
    $count = $count_query->fetch_assoc()['total'];
    echo "📈 Total de configuraciones: $count<br>";
    
    // Mostrar todas las configuraciones que existen en BD
    $all_configs = $conn->query("SELECT name, value FROM settings ORDER BY name");
    echo "<details><summary>📋 Ver todas las configuraciones en BD ($count)</summary>";
    echo "<ul style='font-family: monospace; font-size: 12px;'>";
    while ($config = $all_configs->fetch_assoc()) {
        $value_preview = strlen($config['value']) > 50 ? substr($config['value'], 0, 50) . '...' : $config['value'];
        echo "<li><strong>{$config['name']}</strong>: \"{$value_preview}\"</li>";
    }
    echo "</ul></details>";
} else {
    echo "<span class='error'>❌ Tabla 'settings' no existe</span><br>";
}
echo "</div>";

// Configuraciones COMPLETAS del sistema (extraídas del código real)
echo "<div class='section'>";
echo "<h2>3. 📊 TODAS las Configuraciones del Sistema</h2>";

$config_definitions = [
    // === CONFIGURACIONES PRINCIPALES ===
    'PAGE_TITLE' => ['type' => 'text', 'name' => 'Título de la página', 'category' => 'general', 'default' => 'Sistema de Consulta'],
    'EMAIL_AUTH_ENABLED' => ['type' => 'checkbox', 'name' => 'Filtro de Correos Electrónicos', 'category' => 'seguridad'],
    'REQUIRE_LOGIN' => ['type' => 'checkbox', 'name' => 'Requerir Login', 'category' => 'seguridad'],
    'USER_EMAIL_RESTRICTIONS_ENABLED' => ['type' => 'checkbox', 'name' => 'Restricciones por Usuario', 'category' => 'seguridad'],
    
    // === ENLACES Y PERSONALIZACIÓN ===
    'enlace_global_1' => ['type' => 'text', 'name' => 'Enlace Botón 1', 'category' => 'enlaces', 'default' => 'https://'],
    'enlace_global_1_texto' => ['type' => 'text', 'name' => 'Texto Botón 1', 'category' => 'enlaces', 'default' => 'Ir a Página web'],
    'enlace_global_2' => ['type' => 'text', 'name' => 'Enlace Botón 2', 'category' => 'enlaces', 'default' => 'https://t.me/'],
    'enlace_global_2_texto' => ['type' => 'text', 'name' => 'Texto Botón 2', 'category' => 'enlaces', 'default' => 'Ir a Telegram'],
    'enlace_global_numero_whatsapp' => ['type' => 'text', 'name' => 'Número WhatsApp', 'category' => 'enlaces', 'default' => '000000'],
    'enlace_global_texto_whatsapp' => ['type' => 'text', 'name' => 'Mensaje WhatsApp', 'category' => 'enlaces', 'default' => 'Hola, necesito soporte técnico'],
    'ID_VENDEDOR' => ['type' => 'text', 'name' => 'ID del Vendedor', 'category' => 'enlaces', 'default' => '0'],
    'LOGO' => ['type' => 'text', 'name' => 'Archivo de Logo', 'category' => 'general', 'default' => 'logo.png'],
    
    // === CONFIGURACIONES DE PERFORMANCE ===
    'EMAIL_QUERY_TIME_LIMIT_MINUTES' => ['type' => 'number', 'name' => 'Límite Tiempo Consulta (min)', 'category' => 'performance', 'default' => 30],
    'TIMEZONE_DEBUG_HOURS' => ['type' => 'number', 'name' => 'Horas Debug Zona Horaria', 'category' => 'performance', 'default' => 48],
    'IMAP_CONNECTION_TIMEOUT' => ['type' => 'number', 'name' => 'Timeout Conexión IMAP (seg)', 'category' => 'performance', 'default' => 8],
    'IMAP_SEARCH_TIMEOUT' => ['type' => 'number', 'name' => 'Timeout Búsqueda IMAP (seg)', 'category' => 'performance', 'default' => 30],
    'MAX_EMAILS_TO_CHECK' => ['type' => 'number', 'name' => 'Máximo Emails a Verificar', 'category' => 'performance', 'default' => 35],
    
    // === CONFIGURACIONES DE CACHÉ ===
    'CACHE_ENABLED' => ['type' => 'checkbox', 'name' => 'Cache Habilitado', 'category' => 'cache'],
    'CACHE_TIME_MINUTES' => ['type' => 'number', 'name' => 'Tiempo Cache (min)', 'category' => 'cache', 'default' => 5],
    'CACHE_MEMORY_ENABLED' => ['type' => 'checkbox', 'name' => 'Cache en Memoria', 'category' => 'cache'],
    
    // === OPTIMIZACIONES IMAP ===
    'TRUST_IMAP_DATE_FILTER' => ['type' => 'checkbox', 'name' => 'Confiar Filtro Fechas IMAP', 'category' => 'optimizacion'],
    'USE_PRECISE_IMAP_SEARCH' => ['type' => 'checkbox', 'name' => 'Búsquedas IMAP Precisas', 'category' => 'optimizacion'],
    'IMAP_SEARCH_OPTIMIZATION' => ['type' => 'checkbox', 'name' => 'Optimización IMAP', 'category' => 'optimizacion'],
    'EARLY_SEARCH_STOP' => ['type' => 'checkbox', 'name' => 'Parada Temprana', 'category' => 'optimizacion'],
    'PERFORMANCE_LOGGING' => ['type' => 'checkbox', 'name' => 'Logging Performance', 'category' => 'optimizacion'],
    
    // === CONFIGURACIONES DEL SISTEMA ===
    'LICENSE_PROTECTED' => ['type' => 'checkbox', 'name' => 'Sistema Protegido por Licencia', 'category' => 'sistema'],
    'INSTALLED' => ['type' => 'checkbox', 'name' => 'Sistema Instalado', 'category' => 'sistema'],
];

// Obtener valores directamente de BD
$db_values = [];
foreach (array_keys($config_definitions) as $setting_name) {
    $stmt = $conn->prepare("SELECT value FROM settings WHERE name = ?");
    $stmt->bind_param("s", $setting_name);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $db_values[$setting_name] = $row['value'];
    } else {
        $db_values[$setting_name] = null;
    }
    $stmt->close();
}

// Obtener valores del cache
try {
    $cache_values = SimpleCache::get_settings($conn);
    echo "<span class='success'>✅ Cache cargado exitosamente (" . count($cache_values) . " valores)</span><br>";
} catch (Exception $e) {
    echo "<span class='error'>❌ Error cargando cache: " . $e->getMessage() . "</span><br>";
    $cache_values = [];
}

// Agrupar por categorías
$categories = [
    'general' => 'Configuraciones Generales',
    'seguridad' => 'Seguridad y Acceso',
    'enlaces' => 'Enlaces y Personalización',
    'performance' => 'Rendimiento del Sistema',
    'cache' => 'Sistema de Cache',
    'optimizacion' => 'Optimizaciones IMAP',
    'sistema' => 'Configuraciones del Sistema'
];

foreach ($categories as $cat_key => $cat_name) {
    echo "<h4>📋 $cat_name</h4>";
    echo "<table>";
    echo "<tr class='category-header'><th>Configuración</th><th>Tipo</th><th>Valor en BD</th><th>Valor en Cache</th><th>Estado</th><th>Coinciden</th></tr>";
    
    foreach ($config_definitions as $setting_name => $config) {
        if ($config['category'] !== $cat_key) continue;
        
        $db_value = $db_values[$setting_name];
        $cache_value = $cache_values[$setting_name] ?? null;
        $type = $config['type'];
        $name = $config['name'];
        $default = $config['default'] ?? 'N/A';
        
        // Determinar estado basado en tipo
        if ($type === 'checkbox') {
            $db_status = $db_value === '1' ? '✅ ACTIVADO' : ($db_value === '0' ? '❌ DESACTIVADO' : '⚠️ NO DEFINIDO');
            $status_class = $db_value === '1' ? 'value-1' : 'value-0';
        } elseif ($type === 'number') {
            $db_status = $db_value !== null ? "📊 $db_value" : "⚠️ Default: $default";
            $status_class = 'value-numeric';
        } else {
            $display_value = $db_value !== null ? (strlen($db_value) > 30 ? substr($db_value, 0, 30) . '...' : $db_value) : "Default: $default";
            $db_status = "📝 $display_value";
            $status_class = 'value-text';
        }
        
        // Verificar si coinciden BD y Cache
        $match = $db_value === $cache_value;
        $match_text = $match ? '✅ SÍ' : '❌ NO';
        $row_class = $match ? $status_class : 'discrepancy';
        
        echo "<tr class='$row_class'>";
        echo "<td><strong>$setting_name</strong><br><small>$name</small></td>";
        echo "<td>$type</td>";
        echo "<td title='Valor completo: " . htmlspecialchars($db_value ?? 'NULL') . "'>\"" . htmlspecialchars($db_value ?? 'NULL') . "\"</td>";
        echo "<td title='Valor completo: " . htmlspecialchars($cache_value ?? 'NULL') . "'>\"" . htmlspecialchars($cache_value ?? 'NULL') . "\"</td>";
        echo "<td>$db_status</td>";
        echo "<td>$match_text</td>";
        echo "</tr>";
    }
    echo "</table>";
}
echo "</div>";

// NUEVA SECCIÓN: PLATAFORMAS Y ASUNTOS
echo "<div class='section'>";
echo "<h2>4. 📋 Plataformas y Asuntos (CRÍTICO)</h2>";

// Obtener plataformas y asuntos directamente de BD
echo "<h4>📊 Comparación BD vs Cache - Plataformas</h4>";

// Datos de BD
$platforms_bd = [];
$query_platforms = "
    SELECT p.id, p.name as platform_name, p.sort_order,
           COUNT(ps.id) as subject_count
    FROM platforms p 
    LEFT JOIN platform_subjects ps ON p.id = ps.platform_id 
    GROUP BY p.id, p.name, p.sort_order
    ORDER BY p.sort_order ASC, p.name ASC
";

$result_platforms = $conn->query($query_platforms);
if ($result_platforms) {
    while ($row = $result_platforms->fetch_assoc()) {
        $platforms_bd[$row['platform_name']] = [
            'id' => $row['id'],
            'sort_order' => $row['sort_order'],
            'subject_count' => $row['subject_count']
        ];
    }
}

// Datos del Cache
try {
    $platforms_cache = SimpleCache::get_platform_subjects($conn);
    echo "<span class='success'>✅ Cache de plataformas cargado (" . count($platforms_cache) . " plataformas)</span><br>";
} catch (Exception $e) {
    echo "<span class='error'>❌ Error cargando cache de plataformas: " . $e->getMessage() . "</span><br>";
    $platforms_cache = [];
}

echo "<table>";
echo "<tr><th>Plataforma</th><th>ID en BD</th><th>Asuntos en BD</th><th>Asuntos en Cache</th><th>Estado</th></tr>";

$platform_discrepancies = [];

foreach ($platforms_bd as $platform_name => $bd_info) {
    $cache_subjects = $platforms_cache[$platform_name] ?? [];
    $bd_subject_count = $bd_info['subject_count'];
    $cache_subject_count = count($cache_subjects);
    
    $match = $bd_subject_count == $cache_subject_count;
    $status = $match ? '✅ SINCRONIZADO' : '❌ DESINCRONIZADO';
    $row_class = $match ? 'value-1' : 'discrepancy';
    
    if (!$match) {
        $platform_discrepancies[] = [
            'platform' => $platform_name,
            'bd_count' => $bd_subject_count,
            'cache_count' => $cache_subject_count
        ];
    }
    
    echo "<tr class='$row_class'>";
    echo "<td><strong>$platform_name</strong></td>";
    echo "<td>{$bd_info['id']}</td>";
    echo "<td>📊 $bd_subject_count</td>";
    echo "<td>📊 $cache_subject_count</td>";
    echo "<td>$status</td>";
    echo "</tr>";
}

// Verificar plataformas que están en cache pero no en BD
foreach ($platforms_cache as $cache_platform => $cache_subjects) {
    if (!isset($platforms_bd[$cache_platform])) {
        echo "<tr class='discrepancy'>";
        echo "<td><strong>$cache_platform</strong></td>";
        echo "<td>❌ NO EXISTE</td>";
        echo "<td>❌ N/A</td>";
        echo "<td>📊 " . count($cache_subjects) . "</td>";
        echo "<td>⚠️ SOLO EN CACHE</td>";
        echo "</tr>";
        
        $platform_discrepancies[] = [
            'platform' => $cache_platform,
            'bd_count' => 'NO EXISTE',
            'cache_count' => count($cache_subjects)
        ];
    }
}

echo "</table>";

// Mostrar detalles de cada plataforma
echo "<h4>📝 Detalle de Asuntos por Plataforma</h4>";

foreach ($platforms_bd as $platform_name => $bd_info) {
    echo "<details style='margin: 10px 0; padding: 10px; border: 1px solid #ddd; border-radius: 5px;'>";
    echo "<summary><strong>📋 $platform_name</strong> (ID: {$bd_info['id']}) - {$bd_info['subject_count']} asuntos</summary>";
    
    // Obtener asuntos de BD para esta plataforma
    $stmt_subjects = $conn->prepare("
        SELECT id, subject, created_at, updated_at 
        FROM platform_subjects 
        WHERE platform_id = ? 
        ORDER BY subject ASC
    ");
    $stmt_subjects->bind_param("i", $bd_info['id']);
    $stmt_subjects->execute();
    $subjects_result = $stmt_subjects->get_result();
    
    $bd_subjects = [];
    echo "<div style='display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 10px;'>";
    
    // Columna BD
    echo "<div>";
    echo "<h6>🗃️ Asuntos en BD ({$bd_info['subject_count']}):</h6>";
    echo "<ul style='font-size: 12px; max-height: 200px; overflow-y: auto;'>";
    while ($subject_row = $subjects_result->fetch_assoc()) {
        $bd_subjects[] = $subject_row['subject'];
        $created = date('Y-m-d H:i', strtotime($subject_row['created_at']));
        $updated = date('Y-m-d H:i', strtotime($subject_row['updated_at']));
        echo "<li><strong>ID {$subject_row['id']}:</strong> " . htmlspecialchars($subject_row['subject']) . "<br>";
        echo "<small style='color: #666;'>Creado: $created | Actualizado: $updated</small></li>";
    }
    echo "</ul>";
    echo "</div>";
    
    // Columna Cache
    echo "<div>";
    $cache_subjects = $platforms_cache[$platform_name] ?? [];
    echo "<h6>💾 Asuntos en Cache (" . count($cache_subjects) . "):</h6>";
    echo "<ul style='font-size: 12px; max-height: 200px; overflow-y: auto;'>";
    foreach ($cache_subjects as $cache_subject) {
        $in_bd = in_array($cache_subject, $bd_subjects);
        $icon = $in_bd ? '✅' : '❌';
        echo "<li>$icon " . htmlspecialchars($cache_subject) . "</li>";
    }
    echo "</ul>";
    echo "</div>";
    
    echo "</div>";
    
    // Mostrar diferencias
    $missing_in_cache = array_diff($bd_subjects, $cache_subjects);
    $extra_in_cache = array_diff($cache_subjects, $bd_subjects);
    
    if (!empty($missing_in_cache) || !empty($extra_in_cache)) {
        echo "<div style='background: #fff3cd; padding: 10px; margin-top: 10px; border-radius: 3px;'>";
        echo "<strong>⚠️ DIFERENCIAS DETECTADAS:</strong><br>";
        
        if (!empty($missing_in_cache)) {
            echo "<span style='color: #dc3545;'>❌ En BD pero NO en cache:</span><br>";
            foreach ($missing_in_cache as $missing) {
                echo "&nbsp;&nbsp;• " . htmlspecialchars($missing) . "<br>";
            }
        }
        
        if (!empty($extra_in_cache)) {
            echo "<span style='color: #fd7e14;'>⚠️ En cache pero NO en BD:</span><br>";
            foreach ($extra_in_cache as $extra) {
                echo "&nbsp;&nbsp;• " . htmlspecialchars($extra) . "<br>";
            }
        }
        echo "</div>";
    }
    
    echo "</details>";
    $stmt_subjects->close();
}

// Verificar asuntos recientes (últimas 24 horas)
echo "<h4>🕐 Asuntos Agregados Recientemente (últimas 24 horas)</h4>";
$recent_query = "
    SELECT ps.id, ps.subject, ps.created_at, ps.updated_at, p.name as platform_name
    FROM platform_subjects ps
    JOIN platforms p ON ps.platform_id = p.id
    WHERE ps.created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
       OR ps.updated_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
    ORDER BY ps.updated_at DESC, ps.created_at DESC
";

$recent_result = $conn->query($recent_query);
if ($recent_result && $recent_result->num_rows > 0) {
    echo "<table>";
    echo "<tr><th>Asunto</th><th>Plataforma</th><th>Creado</th><th>Actualizado</th><th>En Cache</th></tr>";
    
    while ($recent = $recent_result->fetch_assoc()) {
        $in_cache = in_array($recent['subject'], $platforms_cache[$recent['platform_name']] ?? []);
        $cache_status = $in_cache ? '✅ SÍ' : '❌ NO';
        $row_class = $in_cache ? 'value-1' : 'discrepancy';
        
        echo "<tr class='$row_class'>";
        echo "<td>" . htmlspecialchars($recent['subject']) . "</td>";
        echo "<td>" . htmlspecialchars($recent['platform_name']) . "</td>";
        echo "<td>" . date('Y-m-d H:i:s', strtotime($recent['created_at'])) . "</td>";
        echo "<td>" . date('Y-m-d H:i:s', strtotime($recent['updated_at'])) . "</td>";
        echo "<td>$cache_status</td>";
        echo "</tr>";
    }
    echo "</table>";
} else {
    echo "<span class='info'>ℹ️ No hay asuntos agregados o modificados en las últimas 24 horas</span><br>";
}

echo "</div>";

// Análisis de discrepancias (configuraciones)
echo "<div class='section'>";
echo "<h2>5. 🔍 Análisis de Discrepancias (Configuraciones)</h2>";

$discrepancies = [];
foreach ($config_definitions as $setting_name => $config) {
    $db_value = $db_values[$setting_name];
    $cache_value = $cache_values[$setting_name] ?? null;
    
    if ($db_value !== $cache_value) {
        $discrepancies[] = [
            'name' => $setting_name,
            'description' => $config['name'],
            'category' => $config['category'],
            'db' => $db_value,
            'cache' => $cache_value
        ];
    }
}

if (empty($discrepancies)) {
    echo "<span class='success'>✅ No hay discrepancias entre BD y Cache</span>";
} else {
    echo "<span class='warning'>⚠️ Se encontraron " . count($discrepancies) . " discrepancias:</span><br><br>";
    
    // Agrupar discrepancias por categoría
    $disc_by_category = [];
    foreach ($discrepancies as $disc) {
        $disc_by_category[$disc['category']][] = $disc;
    }
    
    foreach ($disc_by_category as $category => $discs) {
        echo "<h5>📂 " . ($categories[$category] ?? $category) . "</h5>";
        foreach ($discs as $disc) {
            echo "<div style='padding: 10px; margin: 5px 0; border-left: 4px solid #ffc107; background: #fff3cd;'>";
            echo "<strong>{$disc['name']}</strong> ({$disc['description']})<br>";
            echo "BD: \"{$disc['db']}\" → Cache: \"{$disc['cache']}\"<br>";
            echo "</div>";
        }
    }
}
echo "</div>";

// TEST DE GUARDADO EN TIEMPO REAL Y PLATAFORMAS
echo "<div class='section'>";
echo "<h2>6. ⚡ Tests en Tiempo Real</h2>";

if (isset($_GET['action'])) {
    if ($_GET['action'] === 'test_platform_sync') {
        echo "<div class='real-time-test'>";
        echo "<h4>🧪 Test de Sincronización de Plataformas...</h4>";
        
        $start_time = microtime(true);
        
        // 1. Limpiar cache de plataformas
        SimpleCache::clear_platforms_cache();
        echo "<div class='test-result test-success'>✅ Paso 1: Cache de plataformas limpiado</div>";
        
        // 2. Recargar desde BD
        $fresh_platforms = SimpleCache::get_platform_subjects($conn);
        echo "<div class='test-result test-success'>✅ Paso 2: Plataformas recargadas desde BD (" . count($fresh_platforms) . " plataformas)</div>";
        
        // 3. Verificar asuntos recientes
        $recent_subjects_query = "
            SELECT ps.subject, p.name as platform_name, ps.created_at
            FROM platform_subjects ps
            JOIN platforms p ON ps.platform_id = p.id
            WHERE ps.created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
            ORDER BY ps.created_at DESC
            LIMIT 5
        ";
        
        $recent_result = $conn->query($recent_subjects_query);
        $recent_subjects = [];
        
        if ($recent_result && $recent_result->num_rows > 0) {
            while ($row = $recent_result->fetch_assoc()) {
                $recent_subjects[] = $row;
                $platform_name = $row['platform_name'];
                $subject = $row['subject'];
                $in_cache = in_array($subject, $fresh_platforms[$platform_name] ?? []);
                $status = $in_cache ? '✅ VISIBLE' : '❌ NO VISIBLE';
                
                echo "<div class='test-result " . ($in_cache ? 'test-success' : 'test-error') . "'>";
                echo "📝 \"$subject\" en $platform_name: $status</div>";
            }
        } else {
            echo "<div class='test-result test-success'>ℹ️ No hay asuntos agregados en la última hora</div>";
        }
        
        $end_time = microtime(true);
        $total_time = round(($end_time - $start_time) * 1000, 2);
        
        echo "<div class='test-result test-success'>⏱️ Tiempo total del test: {$total_time}ms</div>";
        echo "<div class='test-result test-success'><strong>🔄 Cache de plataformas actualizado</strong></div>";
        
        echo "</div>";
    }
    
    if ($_GET['action'] === 'search_recent_subject') {
        echo "<div class='real-time-test'>";
        echo "<h4>🔍 Buscar Asunto Reciente...</h4>";
        
        $search_term = $_GET['subject'] ?? '';
        if (!empty($search_term)) {
            echo "<div class='test-result test-success'>🔍 Buscando: \"" . htmlspecialchars($search_term) . "\"</div>";
            
            // Buscar en BD
            $search_query = "
                SELECT ps.id, ps.subject, p.name as platform_name, ps.created_at, ps.updated_at
                FROM platform_subjects ps
                JOIN platforms p ON ps.platform_id = p.id
                WHERE ps.subject LIKE ?
                ORDER BY ps.updated_at DESC, ps.created_at DESC
                LIMIT 10
            ";
            
            $search_param = "%$search_term%";
            $stmt = $conn->prepare($search_query);
            $stmt->bind_param("s", $search_param);
            $stmt->execute();
            $search_result = $stmt->get_result();
            
            if ($search_result->num_rows > 0) {
                echo "<div class='test-result test-success'>✅ Encontrado en BD (" . $search_result->num_rows . " resultados):</div>";
                
                $platforms_cache = SimpleCache::get_platform_subjects($conn);
                
                while ($row = $search_result->fetch_assoc()) {
                    $subject = $row['subject'];
                    $platform = $row['platform_name'];
                    $in_cache = in_array($subject, $platforms_cache[$platform] ?? []);
                    $cache_status = $in_cache ? '✅ EN CACHE' : '❌ NO EN CACHE';
                    
                    echo "<div class='test-result " . ($in_cache ? 'test-success' : 'test-error') . "'>";
                    echo "📝 ID {$row['id']}: \"$subject\" ({$platform}) - $cache_status<br>";
                    echo "<small>Actualizado: " . date('Y-m-d H:i:s', strtotime($row['updated_at'])) . "</small>";
                    echo "</div>";
                }
            } else {
                echo "<div class='test-result test-error'>❌ No encontrado en BD</div>";
            }
            $stmt->close();
        } else {
            echo "<div class='test-result test-error'>❌ No se proporcionó término de búsqueda</div>";
        }
        
        echo "</div>";
    }
    
    if ($_GET['action'] === 'test_instant_save') {
        echo "<div class='real-time-test'>";
        echo "<h4>🧪 Probando guardado instantáneo...</h4>";
        
        $test_config = 'CACHE_ENABLED';
        $start_time = microtime(true);
        
        // 1. Leer valor actual
        $stmt = $conn->prepare("SELECT value FROM settings WHERE name = ?");
        $stmt->bind_param("s", $test_config);
        $stmt->execute();
        $result = $stmt->get_result();
        $current_value = $result->num_rows > 0 ? $result->fetch_assoc()['value'] : '0';
        $stmt->close();
        
        echo "<div class='test-result test-success'>✅ Paso 1: Valor actual de $test_config: \"$current_value\"</div>";
        
        // 2. Cambiar valor
        $new_value = $current_value === '1' ? '0' : '1';
        $stmt = $conn->prepare("UPDATE settings SET value = ? WHERE name = ?");
        $stmt->bind_param("ss", $new_value, $test_config);
        $update_success = $stmt->execute();
        $stmt->close();
        
        if ($update_success) {
            echo "<div class='test-result test-success'>✅ Paso 2: Valor actualizado a \"$new_value\" en BD</div>";
        } else {
            echo "<div class='test-result test-error'>❌ Paso 2: Error actualizando BD: " . $conn->error . "</div>";
        }
        
        // 3. Limpiar cache específico
        SimpleCache::clear_settings_cache();
        echo "<div class='test-result test-success'>✅ Paso 3: Cache de configuraciones limpiado</div>";
        
        // 4. Verificar nuevo valor en cache
        $fresh_settings = SimpleCache::get_settings($conn);
        $new_cache_value = $fresh_settings[$test_config] ?? 'NOT_FOUND';
        
        if ($new_cache_value === $new_value) {
            echo "<div class='test-result test-success'>✅ Paso 4: Nuevo valor en cache: \"$new_cache_value\" ✅ COINCIDE</div>";
        } else {
            echo "<div class='test-result test-error'>❌ Paso 4: Valor en cache: \"$new_cache_value\" ❌ NO COINCIDE</div>";
        }
        
        // 5. Verificar persistencia (re-leer de BD)
        $stmt = $conn->prepare("SELECT value FROM settings WHERE name = ?");
        $stmt->bind_param("s", $test_config);
        $stmt->execute();
        $result = $stmt->get_result();
        $persisted_value = $result->num_rows > 0 ? $result->fetch_assoc()['value'] : 'NOT_FOUND';
        $stmt->close();
        
        if ($persisted_value === $new_value) {
            echo "<div class='test-result test-success'>✅ Paso 5: Valor persistido en BD: \"$persisted_value\" ✅ GUARDADO CORRECTAMENTE</div>";
        } else {
            echo "<div class='test-result test-error'>❌ Paso 5: Valor persistido: \"$persisted_value\" ❌ NO SE GUARDÓ</div>";
        }
        
        $end_time = microtime(true);
        $total_time = round(($end_time - $start_time) * 1000, 2);
        
        echo "<div class='test-result test-success'>⏱️ Tiempo total del test: {$total_time}ms</div>";
        
        if ($update_success && $new_cache_value === $new_value && $persisted_value === $new_value) {
            echo "<div class='test-result test-success'><strong>🎉 RESULTADO: ¡Los cambios se guardan AL INSTANTE!</strong></div>";
        } else {
            echo "<div class='test-result test-error'><strong>⚠️ RESULTADO: Hay problemas en el proceso de guardado</strong></div>";
        }
        
        echo "</div>";
    }
    
    if ($_GET['action'] === 'force_cache_refresh') {
        echo "<hr>";
        echo "<h4>🔄 Regenerando cache completo...</h4>";
        
        SimpleCache::clear_cache();
        echo "1. ✅ Cache completamente limpiado<br>";
        
        $fresh_settings = SimpleCache::get_settings($conn);
        echo "2. ✅ Cache de configuraciones regenerado (" . count($fresh_settings) . " valores)<br>";
        
        echo "<br><span class='success'>✅ Cache regenerado exitosamente</span><br>";
        echo "<a href='debug_admin_config.php'>↻ Recargar página para verificar</a>";
    }
}

echo "<h3>🔧 Acciones Disponibles:</h3>";
echo "<div style='display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 10px;'>";

// Acciones de configuraciones
echo "<div style='background: #f8f9fa; padding: 15px; border-radius: 5px;'>";
echo "<h5>⚙️ Configuraciones</h5>";
echo "<a href='?action=test_instant_save' class='btn' style='background: #28a745; color: white; padding: 8px 12px; text-decoration: none; border-radius: 3px; display: block; margin: 5px 0;'>⚡ Test Guardado Instantáneo</a>";
echo "<a href='?action=force_cache_refresh' class='btn' style='background: #007bff; color: white; padding: 8px 12px; text-decoration: none; border-radius: 3px; display: block; margin: 5px 0;'>🔄 Regenerar Cache General</a>";
echo "</div>";

// Acciones de plataformas
echo "<div style='background: #f8f9fa; padding: 15px; border-radius: 5px;'>";
echo "<h5>📋 Plataformas y Asuntos</h5>";
echo "<a href='?action=test_platform_sync' class='btn' style='background: #17a2b8; color: white; padding: 8px 12px; text-decoration: none; border-radius: 3px; display: block; margin: 5px 0;'>🔄 Sincronizar Plataformas</a>";

// Formulario de búsqueda
echo "<form method='GET' style='margin: 5px 0;'>";
echo "<input type='hidden' name='action' value='search_recent_subject'>";
echo "<div style='display: flex; gap: 5px;'>";
echo "<input type='text' name='subject' placeholder='Buscar asunto...' style='flex: 1; padding: 6px;' value='" . htmlspecialchars($_GET['subject'] ?? '') . "'>";
echo "<button type='submit' style='background: #ffc107; color: black; border: none; padding: 6px 10px; border-radius: 3px;'>🔍</button>";
echo "</div>";
echo "</form>";
echo "</div>";

// Acciones de administración
echo "<div style='background: #f8f9fa; padding: 15px; border-radius: 5px;'>";
echo "<h5>🔧 Administración</h5>";
echo "<a href='admin/admin.php?debug=1' class='btn' style='background: #6c757d; color: white; padding: 8px 12px; text-decoration: none; border-radius: 3px; display: block; margin: 5px 0;'>🔧 Panel de Admin</a>";
echo "<a href='admin/admin.php?tab=platforms' class='btn' style='background: #e83e8c; color: white; padding: 8px 12px; text-decoration: none; border-radius: 3px; display: block; margin: 5px 0;'>📋 Gestionar Plataformas</a>";
echo "</div>";

echo "</div>";

// Mensaje de ayuda específico para el problema del usuario
if (!empty($platform_discrepancies) || !empty($discrepancies)) {
    echo "<div style='background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 15px 0; border-radius: 5px;'>";
    echo "<h5>💡 ¿Tu asunto recién agregado no aparece?</h5>";
    echo "<ol>";
    echo "<li><strong>Usa la búsqueda arriba</strong> para encontrar tu asunto específico</li>";
    echo "<li><strong>Haz clic en 'Sincronizar Plataformas'</strong> para limpiar el cache</li>";
    echo "<li><strong>Verifica en 'Asuntos Recientes'</strong> si tu asunto aparece en las últimas 24 horas</li>";
    echo "<li><strong>Si persiste el problema</strong>, ve al Panel de Admin → Gestionar Plataformas</li>";
    echo "</ol>";
    echo "</div>";
}

echo "</div>";

// Verificar sistema de cache
echo "<div class='section'>";
echo "<h2>7. 🗄️ Sistema de Cache</h2>";

$cache_dir = 'cache/data/';
if (file_exists($cache_dir)) {
    echo "<span class='success'>✅ Directorio de cache existe: $cache_dir</span><br>";
    
    $cache_files = glob($cache_dir . '*.json');
    echo "📁 Archivos de cache encontrados: " . count($cache_files) . "<br>";
    
    if (!empty($cache_files)) {
        echo "<table style='margin-top: 10px;'>";
        echo "<tr><th>Archivo</th><th>Antigüedad</th><th>Tamaño</th><th>Última modificación</th></tr>";
        foreach ($cache_files as $file) {
            $filename = basename($file);
            $age = time() - filemtime($file);
            $size = filesize($file);
            $last_mod = date('Y-m-d H:i:s', filemtime($file));
            
            $age_text = $age < 60 ? "{$age}s" : ($age < 3600 ? round($age/60) . "m" : round($age/3600) . "h");
            $size_text = $size < 1024 ? "{$size}b" : round($size/1024, 1) . "KB";
            
            echo "<tr>";
            echo "<td>$filename</td>";
            echo "<td>$age_text</td>";
            echo "<td>$size_text</td>";
            echo "<td>$last_mod</td>";
            echo "</tr>";
        }
        echo "</table>";
    }
    
} else {
    echo "<span class='error'>❌ Directorio de cache no existe</span><br>";
}

$cache_writable = is_writable($cache_dir);
echo "📝 Cache directorio escribible: " . ($cache_writable ? '✅ SÍ' : '❌ NO') . "<br>";
echo "</div>";

// Información del sistema
echo "<div class='section'>";
echo "<h2>8. 📋 Información del Sistema</h2>";
echo "🕐 Fecha y hora: " . date('Y-m-d H:i:s') . "<br>";
echo "🌐 PHP versión: " . phpversion() . "<br>";
echo "💾 MySQL versión: " . $conn->server_info . "<br>";
echo "📁 Directorio actual: " . __DIR__ . "<br>";
echo "🔑 Usuario de sesión: " . ($_SESSION['username'] ?? 'No hay sesión') . "<br>";
echo "💽 Memoria PHP usada: " . round(memory_get_usage(true) / 1024 / 1024, 2) . " MB<br>";
echo "⏱️ Tiempo de ejecución del script: " . round(microtime(true) - $_SERVER['REQUEST_TIME_FLOAT'], 3) . "s<br>";
echo "</div>";

$conn->close();

echo "<hr>";
echo "<p><strong>💡 Resumen:</strong> Este debugging muestra las <strong>" . count($config_definitions) . " configuraciones del sistema + " . count($platforms_bd) . " plataformas con sus asuntos</strong>. Perfecto para diagnosticar problemas de sincronización entre BD y cache.</p>";
echo "<p><strong>🎯 Para tu problema específico:</strong> Si agregaste un asunto y no aparece, usa la búsqueda de asuntos o el botón 'Sincronizar Plataformas' para forzar la actualización del cache.</p>";
?>