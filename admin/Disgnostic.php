<?php
/**
 * Diagnóstico de Conectividad de Red
 * Para probar conectividad a servidores IMAP
 */

header('Content-Type: text/html; charset=utf-8');

if (isset($_POST['test_connectivity'])) {
    header('Content-Type: application/json');
    
    $host = $_POST['host'] ?? 'imap.gmail.com';
    $port = intval($_POST['port'] ?? 993);
    $timeout = 10;
    
    $results = [];
    
    // 1. Prueba de resolución DNS
    $results['dns'] = testDNS($host);
    
    // 2. Prueba de conectividad básica
    $results['connectivity'] = testConnectivity($host, $port, $timeout);
    
    // 3. Prueba de socket
    $results['socket'] = testSocket($host, $port, $timeout);
    
    // 4. Información del servidor
    $results['server_info'] = getServerInfo();
    
    echo json_encode([
        'success' => true,
        'results' => $results
    ]);
    exit();
}

function testDNS($host) {
    $result = [
        'status' => 'unknown',
        'message' => '',
        'ip' => null
    ];
    
    try {
        $ip = gethostbyname($host);
        
        if ($ip && $ip !== $host) {
            $result['status'] = 'success';
            $result['message'] = "DNS resuelto correctamente";
            $result['ip'] = $ip;
        } else {
            $result['status'] = 'error';
            $result['message'] = "No se pudo resolver DNS para $host";
        }
    } catch (Exception $e) {
        $result['status'] = 'error';
        $result['message'] = "Error en resolución DNS: " . $e->getMessage();
    }
    
    return $result;
}

function testConnectivity($host, $port, $timeout) {
    $result = [
        'status' => 'unknown',
        'message' => '',
        'time' => 0
    ];
    
    $start_time = microtime(true);
    
    try {
        $connection = @fsockopen($host, $port, $errno, $errstr, $timeout);
        $end_time = microtime(true);
        $result['time'] = round(($end_time - $start_time) * 1000, 2);
        
        if ($connection) {
            $result['status'] = 'success';
            $result['message'] = "Conexión exitosa a $host:$port en {$result['time']}ms";
            fclose($connection);
        } else {
            $result['status'] = 'error';
            $result['message'] = "Error conectando a $host:$port - $errstr (Código: $errno)";
        }
    } catch (Exception $e) {
        $result['status'] = 'error';
        $result['message'] = "Excepción durante conexión: " . $e->getMessage();
    }
    
    return $result;
}

function testSocket($host, $port, $timeout) {
    $result = [
        'status' => 'unknown',
        'message' => '',
        'banner' => null
    ];
    
    try {
        $context = stream_context_create([
            'socket' => [
                'timeout' => $timeout,
            ]
        ]);
        
        $socket = @stream_socket_client("tcp://$host:$port", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $context);
        
        if ($socket) {
            $result['status'] = 'success';
            $result['message'] = "Socket creado exitosamente";
            
            // Intentar leer banner del servidor
            $banner = @fread($socket, 1024);
            if ($banner) {
                $result['banner'] = trim($banner);
            }
            
            fclose($socket);
        } else {
            $result['status'] = 'error';
            $result['message'] = "Error creando socket: $errstr (Código: $errno)";
        }
    } catch (Exception $e) {
        $result['status'] = 'error';
        $result['message'] = "Error en socket: " . $e->getMessage();
    }
    
    return $result;
}

function getServerInfo() {
    return [
        'php_version' => PHP_VERSION,
        'os' => PHP_OS,
        'server_ip' => $_SERVER['SERVER_ADDR'] ?? 'Unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
        'allow_url_fopen' => ini_get('allow_url_fopen') ? 'Enabled' : 'Disabled',
        'curl_available' => extension_loaded('curl') ? 'Available' : 'Not Available',
        'openssl_available' => extension_loaded('openssl') ? 'Available' : 'Not Available'
    ];
}

?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Diagnóstico de Conectividad de Red</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .test-form { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .test-btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin: 5px; }
        .test-btn:hover { background: #0056b3; }
        .test-btn:disabled { background: #6c757d; cursor: not-allowed; }
        .results { margin-top: 20px; }
        .result-item { padding: 10px; margin: 5px 0; border-radius: 4px; border-left: 4px solid; }
        .result-success { background: #d4edda; border-left-color: #28a745; color: #155724; }
        .result-error { background: #f8d7da; border-left-color: #dc3545; color: #721c24; }
        .result-warning { background: #fff3cd; border-left-color: #ffc107; color: #856404; }
        .servers-list { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin: 15px 0; }
        .server-btn { background: #28a745; color: white; padding: 8px 12px; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; }
        .server-btn:hover { background: #218838; }
        input, select { padding: 8px; margin: 5px; border: 1px solid #ddd; border-radius: 4px; width: 150px; }
        .loading { color: #007bff; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🌐 Diagnóstico de Conectividad de Red</h1>
        <p>Esta herramienta verifica si tu servidor puede conectarse a servidores IMAP externos.</p>

        <div class="test-form">
            <h3>🔧 Configurar Prueba</h3>
            <form id="testForm">
                <label>
                    <strong>Servidor:</strong>
                    <input type="text" id="host" name="host" value="imap.gmail.com" placeholder="imap.gmail.com">
                </label>
                
                <label>
                    <strong>Puerto:</strong>
                    <input type="number" id="port" name="port" value="993" placeholder="993">
                </label>
                
                <button type="submit" class="test-btn" id="testBtn">
                    🚀 Probar Conectividad
                </button>
            </form>
        </div>

        <div class="servers-list">
            <h4>📧 Servidores Comunes para Probar:</h4>
            <button class="server-btn" onclick="testServer('imap.gmail.com', 993)">Gmail IMAP</button>
            <button class="server-btn" onclick="testServer('outlook.office365.com', 993)">Outlook IMAP</button>
            <button class="server-btn" onclick="testServer('imap.mail.yahoo.com', 993)">Yahoo IMAP</button>
            <button class="server-btn" onclick="testServer('8.8.8.8', 53)">Google DNS</button>
            <button class="server-btn" onclick="testServer('google.com', 80)">Google HTTP</button>
            <button class="server-btn" onclick="testServer('httpbin.org', 443)">Test HTTPS</button>
        </div>

        <div id="results" class="results" style="display: none;">
            <h3>📊 Resultados de la Prueba</h3>
            <div id="resultsContent"></div>
        </div>
    </div>

    <script>
        function testServer(host, port) {
            document.getElementById('host').value = host;
            document.getElementById('port').value = port;
            document.getElementById('testForm').dispatchEvent(new Event('submit'));
        }

        document.getElementById('testForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const host = document.getElementById('host').value;
            const port = document.getElementById('port').value;
            const testBtn = document.getElementById('testBtn');
            const resultsDiv = document.getElementById('results');
            const resultsContent = document.getElementById('resultsContent');
            
            if (!host || !port) {
                alert('Por favor, completa servidor y puerto');
                return;
            }
            
            // Mostrar estado de carga
            testBtn.disabled = true;
            testBtn.innerHTML = '⏳ Probando...';
            resultsDiv.style.display = 'block';
            resultsContent.innerHTML = '<div class="loading">🔄 Ejecutando pruebas de conectividad...</div>';
            
            // Realizar prueba
            const formData = new FormData();
            formData.append('test_connectivity', '1');
            formData.append('host', host);
            formData.append('port', port);
            
            fetch(window.location.href, {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    displayResults(data.results, host, port);
                } else {
                    resultsContent.innerHTML = '<div class="result-item result-error">❌ Error: ' + (data.error || 'Error desconocido') + '</div>';
                }
            })
            .catch(error => {
                resultsContent.innerHTML = '<div class="result-item result-error">❌ Error de red: ' + error.message + '</div>';
            })
            .finally(() => {
                testBtn.disabled = false;
                testBtn.innerHTML = '🚀 Probar Conectividad';
            });
        });

        function displayResults(results, host, port) {
            const resultsContent = document.getElementById('resultsContent');
            let html = `<h4>Resultados para ${host}:${port}</h4>`;
            
            // DNS Test
            const dns = results.dns;
            html += `<div class="result-item result-${dns.status}">
                <strong>🔍 Resolución DNS:</strong> ${dns.message}
                ${dns.ip ? `<br><small>IP: ${dns.ip}</small>` : ''}
            </div>`;
            
            // Connectivity Test
            const conn = results.connectivity;
            html += `<div class="result-item result-${conn.status}">
                <strong>🌐 Conectividad:</strong> ${conn.message}
                ${conn.time ? `<br><small>Tiempo: ${conn.time}ms</small>` : ''}
            </div>`;
            
            // Socket Test
            const socket = results.socket;
            html += `<div class="result-item result-${socket.status}">
                <strong>🔌 Socket:</strong> ${socket.message}
                ${socket.banner ? `<br><small>Banner: ${socket.banner}</small>` : ''}
            </div>`;
            
            // Server Info
            const info = results.server_info;
            html += `<div class="result-item result-warning">
                <strong>ℹ️ Información del Servidor:</strong>
                <br><small>PHP: ${info.php_version} | OS: ${info.os}</small>
                <br><small>OpenSSL: ${info.openssl_available} | cURL: ${info.curl_available}</small>
                <br><small>allow_url_fopen: ${info.allow_url_fopen}</small>
            </div>`;
            
            // Recommendations
            html += getRecommendations(results);
            
            resultsContent.innerHTML = html;
        }

        function getRecommendations(results) {
            let html = '<div class="result-item result-warning"><strong>💡 Recomendaciones:</strong><ul>';
            
            if (results.dns.status === 'error') {
                html += '<li>🔧 Problema de DNS: Contacta a tu proveedor de hosting</li>';
                html += '<li>🔧 Verifica configuración de DNS del servidor</li>';
            }
            
            if (results.connectivity.status === 'error') {
                html += '<li>🔧 Sin conectividad externa: Hosting puede estar bloqueando conexiones salientes</li>';
                html += '<li>🔧 Verifica que los puertos 993, 143 estén abiertos</li>';
                html += '<li>🔧 Contacta al soporte técnico de tu hosting</li>';
            }
            
            if (results.dns.status === 'success' && results.connectivity.status === 'error') {
                html += '<li>🔧 DNS funciona pero no hay conectividad: Firewall bloqueando</li>';
                html += '<li>🔧 Solicita whitelist para imap.gmail.com en tu hosting</li>';
            }
            
            if (results.connectivity.status === 'success') {
                html += '<li>✅ Conectividad OK: El problema puede ser de autenticación IMAP</li>';
                html += '<li>✅ Verifica credenciales y configuración SSL</li>';
            }
            
            html += '</ul></div>';
            return html;
        }
    </script>
</body>
</html>