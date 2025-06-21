<?php
/**
 * Panel de Monitoreo de Licencias
 * Interfaz web para monitorear el estado y actividad de licencias
 * Versión: 3.0
 */

// Configuración de seguridad
session_start();

// Verificar si el usuario tiene permisos (ajustar según tu sistema de autenticación)
if (!isset($_SESSION['admin_logged_in']) || !$_SESSION['admin_logged_in']) {
    // Si no tienes sistema de autenticación, comenta estas líneas
    // header('Location: /admin/login.php');
    // exit();
}

require_once 'license_client.php';

$license_client = new ClientLicense();
$message = '';
$message_type = 'info';

// Procesar acciones (se mantienen por si las quieres usar en el futuro, aunque la UI las oculte)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    switch ($_POST['action'] ?? '') {
        case 'force_validation':
            $result = $license_client->forceValidation();
            $message = $result['message'];
            $message_type = $result['success'] ? 'success' : 'danger';
            break;
            
        case 'clean_logs':
            $license_client->cleanOldLogs();
            $message = 'Logs antiguos limpiados correctamente';
            $message_type = 'success';
            break;
            
        case 'download_activity':
            $activity = $license_client->getLicenseActivity(1000);
            
            header('Content-Type: text/plain');
            header('Content-Disposition: attachment; filename="license_activity_' . date('Y-m-d_H-i-s') . '.log"');
            
            foreach ($activity as $entry) {
                echo "[{$entry['timestamp']}] [{$entry['type']}] {$entry['message']}\n";
            }
            exit();
            break;
    }
}

// Obtener información actual
$license_info = $license_client->getLicenseInfo();
$license_stats = $license_client->getLicenseStats();
$diagnostic_info = $license_client->getDiagnosticInfo();
$activity = $license_client->getLicenseActivity(30); // Se mantiene para depuración si es necesario, aunque no se muestre
$is_valid = $license_client->isLicenseValid();

?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Monitor de Licencias - Sistema de Códigos</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body { background: #f8f9fa; }
        .monitor-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem 0;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: white;
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #007bff;
        }
        .stat-card.success { border-left-color: #28a745; }
        .stat-card.warning { border-left-color: #ffc107; }
        .stat-card.danger { border-left-color: #dc3545; }
        /* Ocultar log de actividad para simplificar la vista si no es necesario */
        .activity-log {
            display: none; /* Oculta completamente el log de actividad */
        }
        .status-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 8px;
            animation: pulse 2s infinite;
        }
        .status-indicator.online { background: #28a745; }
        .status-indicator.offline { background: #dc3545; }
        .status-indicator.warning { background: #ffc107; }
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        .diagnostic-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1rem;
        }
    </style>
</head>
<body>
    <div class="monitor-header">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-md-8">
                    <h1><i class="fas fa-shield-alt me-3"></i>Monitor de Licencias</h1>
                    <p class="mb-0">Sistema de monitoreo y diagnóstico de licencias en tiempo real</p>
                </div>
                <div class="col-md-4 text-end">
                    <div class="d-flex align-items-center justify-content-end">
                        <span class="status-indicator <?= $is_valid ? 'online' : 'offline' ?>"></span>
                        <span class="fw-bold"><?= $is_valid ? 'LICENCIA VÁLIDA' : 'LICENCIA INVÁLIDA' ?></span>
                    </div>
                    <small>Última actualización: <span class="live-timestamp"><?= date('H:i:s') ?></span></small>
                </div>
            </div>
        </div>
    </div>

    <div class="container">
        <?php if (!empty($message)): ?>
            <div class="alert alert-<?= $message_type ?> alert-dismissible fade show" role="alert">
                <i class="fas fa-<?= $message_type === 'success' ? 'check-circle' : ($message_type === 'danger' ? 'exclamation-triangle' : 'info-circle') ?> me-2"></i>
                <?= htmlspecialchars($message) ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>

        <div class="row mb-4">
            <div class="col-md-3">
                <div class="stat-card <?= $is_valid ? 'success' : 'danger' ?>">
                    <div class="d-flex align-items-center">
                        <div class="flex-grow-1">
                            <h6 class="text-muted mb-1">Estado General</h6>
                            <h4 class="mb-0"><?= $is_valid ? 'Válida' : 'Inválida' ?></h4>
                        </div>
                        <div class="text-end">
                            <i class="fas fa-shield-alt fa-2x text-<?= $is_valid ? 'success' : 'danger' ?>"></i>
                        </div>
                    </div>
                </div>
            </div>
            
            <?php if ($license_stats): ?>
            <div class="col-md-3">
                <div class="stat-card">
                    <div class="d-flex align-items-center">
                        <div class="flex-grow-1">
                            <h6 class="text-muted mb-1">Verificaciones</h6>
                            <h4 class="mb-0"><?= $license_stats['validation_count'] ?></h4>
                        </div>
                        <div class="text-end">
                            <i class="fas fa-sync fa-2x text-info"></i>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-3">
                <div class="stat-card <?= $license_stats['hours_since_last_check'] > 24 ? 'warning' : 'success' ?>">
                    <div class="d-flex align-items-center">
                        <div class="flex-grow-1">
                            <h6 class="text-muted mb-1">Última Verificación</h6>
                            <h4 class="mb-0"><?= round($license_stats['hours_since_last_check'], 1) ?>h</h4>
                        </div>
                        <div class="text-end">
                            <i class="fas fa-clock fa-2x text-primary"></i>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-3">
                <div class="stat-card <?= $license_stats['error_count'] > 0 ? 'warning' : 'success' ?>">
                    <div class="d-flex align-items-center">
                        <div class="flex-grow-1">
                            <h6 class="text-muted mb-1">Errores</h6>
                            <h4 class="mb-0"><?= $license_stats['error_count'] ?></h4>
                        </div>
                        <div class="text-end">
                            <i class="fas fa-exclamation-triangle fa-2x text-warning"></i>
                        </div>
                    </div>
                </div>
            </div>
            <?php endif; ?>
        </div>

        <div class="row mb-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fas fa-info-circle me-2"></i>Información de Licencia</h5>
                    </div>
                    <div class="card-body">
                        <?php if ($license_info): ?>
                            <table class="table table-sm">
                                <tr>
                                    <td><strong>Dominio:</strong></td>
                                    <td><?= htmlspecialchars($license_info['domain']) ?></td>
                                </tr>
                                <tr>
                                    <td><strong>Estado:</strong></td>
                                    <td>
                                        <span class="badge bg-<?= $license_info['status'] === 'active' ? 'success' : 'danger' ?>">
                                            <?= ucfirst($license_info['status']) ?>
                                        </span>
                                    </td>
                                </tr>
                                <tr>
                                    <td><strong>Activada:</strong></td>
                                    <td><?= htmlspecialchars($license_info['activated_at']) ?></td>
                                </tr>
                                <tr>
                                    <td><strong>Última Verificación:</strong></td>
                                    <td><?= htmlspecialchars($license_info['last_check']) ?></td>
                                </tr>
                                <?php if (!empty($license_info['license_key_preview'])): ?>
                                <tr>
                                    <td><strong>Clave:</strong></td>
                                    <td><code><?= htmlspecialchars($license_info['license_key_preview']) ?></code></td>
                                </tr>
                                <?php endif; ?>
                            </table>
                        <?php else: ?>
                            <div class="alert alert-warning">
                                <i class="fas fa-exclamation-triangle me-2"></i>
                                No se pudo obtener información de licencia
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fas fa-chart-line me-2"></i>Estadísticas</h5>
                    </div>
                    <div class="card-body">
                        <?php if ($license_stats): ?>
                            <table class="table table-sm">
                                <tr>
                                    <td><strong>Días activa:</strong></td>
                                    <td><?= $license_stats['days_since_activation'] ?> días</td>
                                </tr>
                                <tr>
                                    <td><strong>Total verificaciones:</strong></td>
                                    <td><?= $license_stats['validation_count'] ?></td>
                                </tr>
                                <tr>
                                    <td><strong>Próxima verificación:</strong></td>
                                    <td>
                                        <?php if ($license_stats['hours_until_next_check'] > 0): ?>
                                            En <?= round($license_stats['hours_until_next_check'], 1) ?> horas
                                        <?php else: ?>
                                            <span class="text-warning">Pendiente</span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                                <tr>
                                    <td><strong>Período de gracia:</strong></td>
                                    <td>
                                        <?php if ($license_stats['grace_period_remaining'] > 0): ?>
                                            <?= round($license_stats['grace_period_remaining'], 1) ?> días restantes
                                        <?php else: ?>
                                            <span class="text-danger">Expirado</span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                                <?php if (!empty($license_stats['last_error'])): ?>
                                <tr>
                                    <td><strong>Último error:</strong></td>
                                    <td><small class="text-danger"><?= htmlspecialchars($license_stats['last_error']) ?></small></td>
                                </tr>
                                <?php endif; ?>
                            </table>
                        <?php else: ?>
                            <div class="alert alert-warning">
                                <i class="fas fa-exclamation-triangle me-2"></i>
                                No se pudieron obtener estadísticas
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fas fa-cogs me-2"></i>Acciones del Sistema</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-4">
                                <form method="post" class="d-inline">
                                    <input type="hidden" name="action" value="force_validation">
                                    <button type="submit" class="btn btn-primary w-100">
                                        <i class="fas fa-sync me-1"></i>Forzar Verificación
                                    </button>
                                </form>
                            </div>
                            <div class="col-md-4">
                                <button class="btn btn-info w-100" onclick="location.reload()">
                                    <i class="fas fa-refresh me-1"></i>Actualizar Página
                                </button>
                            </div>
                             <div class="col-md-4">
                                <form method="post" class="d-inline" onsubmit="return confirm('¿Está seguro de limpiar los logs antiguos?')">
                                    <input type="hidden" name="action" value="clean_logs">
                                    <button type="submit" class="btn btn-warning w-100">
                                        <i class="fas fa-trash me-1"></i>Limpiar Logs de Licencia
                                    </button>
                                </form>
                            </div>
                            </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row mb-4 d-none"> <?php /* Añade 'd-none' para ocultar esta sección por defecto */ ?>
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fas fa-wrench me-2"></i>Información Diagnóstica</h5>
                    </div>
                    <div class="card-body">
                        <div class="diagnostic-grid">
                            <div>
                                <h6>Archivos y Directorios</h6>
                                <table class="table table-sm">
                                    <tr>
                                        <td>Directorio licencias:</td>
                                        <td>
                                            <i class="fas fa-<?= $diagnostic_info['directory_exists'] ? 'check text-success' : 'times text-danger' ?> me-1"></i>
                                            <?= $diagnostic_info['directory_exists'] ? 'Existe' : 'No existe' ?>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td>Archivo licencia:</td>
                                        <td>
                                            <i class="fas fa-<?= $diagnostic_info['file_exists'] ? 'check text-success' : 'times text-danger' ?> me-1"></i>
                                            <?= $diagnostic_info['file_exists'] ? 'Existe' : 'No existe' ?>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td>Permisos escritura:</td>
                                        <td>
                                            <i class="fas fa-<?= $diagnostic_info['directory_writable'] ? 'check text-success' : 'times text-danger' ?> me-1"></i>
                                            <?= $diagnostic_info['directory_writable'] ? 'Correcto' : 'Sin permisos' ?>
                                        </td>
                                    </tr>
                                </table>
                            </div>
                            
                            <div>
                                <h6>Configuración</h6>
                                <table class="table table-sm">
                                    <tr>
                                        <td>Servidor licencias:</td>
                                        <td><code><?= htmlspecialchars($diagnostic_info['server_url']) ?></code></td>
                                    </tr>
                                    <tr>
                                        <td>Raíz proyecto:</td>
                                        <td><code><?= htmlspecialchars($diagnostic_info['project_root']) ?></code></td>
                                    </tr>
                                    <tr>
                                        <td>Directorio actual:</td>
                                        <td><code><?= htmlspecialchars($diagnostic_info['current_dir']) ?></code></td>
                                    </tr>
                                </table>
                            </div>
                        </div>
                        
                        <div class="mt-3">
                            <h6>Constantes Definidas</h6>
                            <div class="row">
                                <?php foreach ($diagnostic_info['constants_defined'] as $constant => $defined): ?>
                                    <div class="col-md-3 mb-2">
                                        <span class="badge bg-<?= $defined ? 'success' : 'secondary' ?>">
                                            <?= $constant ?>: <?= $defined ? 'SÍ' : 'NO' ?>
                                        </span>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="text-center text-muted mb-4">
            <small>
                Sistema de Códigos - Monitor de Licencias v3.0<br>
                Última actualización: <span class="live-timestamp"><?= date('Y-m-d H:i:s') ?></span>
            </small>
        </div>
    </div>

    <script>
        // Auto-refresh cada 30 segundos (solo si no hay alertas)
        <?php if (empty($message)): ?>
        setTimeout(function() {
            location.reload();
        }, 30000);
        <?php endif; ?>
        
        // Mostrar timestamp en tiempo real
        function updateTimestamp() {
            const now = new Date();
            const timestamp = now.toLocaleTimeString();
            // Actualizar cualquier elemento con clase 'live-timestamp'
            document.querySelectorAll('.live-timestamp').forEach(el => {
                el.textContent = timestamp;
            });
        }
        
        // Actualizar cada segundo
        setInterval(updateTimestamp, 1000);
    </script>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>