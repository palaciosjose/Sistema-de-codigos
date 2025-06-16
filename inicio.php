<?php
// Inicia una sesión para almacenar datos temporales
session_start();

// Incluimos SOLO UNA VEZ los archivos necesarios
require_once 'funciones.php'; // Primero incluir funciones para tener is_installed()
require_once 'decodificador.php'; 

// Verificar primero si el sistema está instalado
if (!is_installed()) {
    // Mostrar página de instalación
    echo '
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta charset="UTF-8">
        <title>Sistema NO Instalado</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    </head>
    <body class="bg-dark text-white d-flex align-items-center justify-content-center min-vh-100">
        <div class="text-center">
            <h1 class="mb-4">Sistema NO Instalado</h1>
            <a href="/instalacion/instalador.php" class="btn btn-primary">Instalar Sistema</a>
        </div>
    </body>
    </html>';
    exit();
}

// Si llegamos aquí, el sistema está instalado
if (file_exists('instalacion/basededatos.php')) {
    require_once 'instalacion/basededatos.php';
}

// Crear una única conexión a la base de datos utilizando mysqli ANTES de auth.php
try {
    $conn = new mysqli($db_host, $db_user, $db_password, $db_name);
    $conn->set_charset("utf8mb4"); // Establecer UTF-8 para la conexión
    
    if ($conn->connect_error) {
        mostrarPaginaInstalacion('Error de conexión a la base de datos'); 
    }
} catch (Exception $e) {
    mostrarPaginaInstalacion('Error crítico al conectar con la base de datos');
}

// Ahora que $conn está definida, incluir auth.php
require_once 'security/auth.php';

// Verificar la sesión del usuario de forma condicional
check_session(false, 'index.php', true);

header('Content-Type: text/html; charset=utf-8');

// Función para mostrar la página de instalación
function mostrarPaginaInstalacion($mensaje = 'Instalación NO Detectada') {
    echo '
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta charset="UTF-8">
        <title>Sistema NO Instalado</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    </head>
    <body class="bg-dark text-white d-flex align-items-center justify-content-center min-vh-100">
        <div class="text-center">
            <h1 class="mb-4">' . htmlspecialchars($mensaje) . '</h1>
            <a href="/instalacion/instalador.php" class="btn btn-primary">Instalar Sistema</a>
        </div>
    </body>
    </html>';
    exit();
}

// Obtener todas las configuraciones desde cache (OPTIMIZADO)
$settings = SimpleCache::get_settings($conn);
$page_title = $settings['PAGE_TITLE'] ?? 'Sistema de Consulta';
$require_login = ($settings['REQUIRE_LOGIN'] ?? '1') === '1';

// Procesar logout
if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    session_start();
    header("Location: inicio.php");
    exit();
}

// Recuperar mensajes de sesión
$resultado = $_SESSION['resultado'] ?? '';
$error_message = $_SESSION['error_message'] ?? '';

unset($_SESSION['resultado']);
unset($_SESSION['error_message']);

$user_logged_in = isset($_SESSION['user_id']);

// Determinar si hay resultados para mostrar
$has_results = !empty($resultado) || !empty($error_message);
?>

<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title><?= htmlspecialchars($page_title) ?></title>

  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"/>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css"/>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
  
  <link rel="stylesheet" href="styles/modern_inicio.css">
  
  <script src="security/autorizados.js"></script>
</head>
<body>

<nav class="navbar navbar-expand-lg navbar-dark navbar-modern fixed-top">
  <div class="container">
    <a class="navbar-brand" href="javascript:location.reload();">
      <i class="fas fa-code"></i> <?= htmlspecialchars($page_title) ?>
    </a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarOpciones" aria-controls="navbarOpciones" aria-expanded="false" aria-label="Toggle navigation">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarOpciones">
      <ul class="navbar-nav ms-auto">
        <?php if (is_admin()): ?>
          <li class="nav-item">
            <a class="nav-link" href="admin/admin.php"><i class="fas fa-cogs"></i> Configurar Sistema</a>
          </li>
        <?php endif; ?>
        <li class="nav-item">
          <a class="nav-link" href="<?= htmlspecialchars($settings['enlace_global_1'] ?? '#'); ?>" target="_blank"><i class="fas fa-bookmark"></i> <?= htmlspecialchars($settings['enlace_global_1_texto'] ?? 'Sitio Web'); ?></a>
        </li>
        <li class="nav-item">
          <a class="nav-link" href="<?= htmlspecialchars($settings['enlace_global_2'] ?? '#'); ?>" target="_blank"><i class="fab fa-telegram-plane"></i> <?= htmlspecialchars($settings['enlace_global_2_texto'] ?? 'Telegram'); ?></a>
        </li>
        <?php
          $whatsappNumero = $settings['enlace_global_numero_whatsapp'] ?? '';
          $whatsappTexto = $settings['enlace_global_texto_whatsapp'] ?? '';
          $whatsappLink = 'https://wa.me/' . $whatsappNumero . '?text=' . urlencode($whatsappTexto);
        ?>
        <li class="nav-item">
          <a class="nav-link" href="<?= htmlspecialchars($whatsappLink) ?>" target="_blank"><i class="fab fa-whatsapp"></i> Contacto</a>
        </li>
        <?php if ($user_logged_in): ?>
        <li class="nav-item">
          <a class="nav-link" href="inicio.php?logout=1"><i class="fas fa-sign-out-alt"></i> Cerrar Sesión</a>
        </li>
        <?php endif; ?>
      </ul>
    </div>
  </div>
</nav>

<div class="main-container">
  <!-- Añadir clase 'expanded' cuando hay resultados -->
  <div class="main-card<?= $has_results ? ' expanded' : '' ?>">
    
    <!-- Contenedor del formulario de búsqueda -->
    <div id="search-container" class="<?= $has_results ? 'hidden' : '' ?>">
        <div class="logo-container">
          <img src="/images/logo/<?= htmlspecialchars($settings['LOGO'] ?? 'logo.png'); ?>" alt="Logo" class="logo"/>
        </div>
        <h1 class="main-title" id="typing-title"></h1>
        <form action="funciones.php" method="POST" class="search-form" id="searchForm">
          <div class="form-group-modern">
            <input type="email" id="email" name="email" class="form-input-modern" placeholder="Ingrese el correo a consultar" required maxlength="50"/>
            <i class="fas fa-envelope form-icon"></i>
          </div>
          
          <div class="form-group-modern">
              <div class="custom-select-wrapper">
                  <div class="custom-select">
                      <div class="custom-select__trigger">
                          <span>Seleccione una plataforma...</span>
                          <div class="arrow"></div>
                      </div>
                      <div class="custom-options">
                          <?php
                            $platforms_query = "SELECT name FROM platforms ORDER BY sort_order ASC";
                            $platforms_result = $conn->query($platforms_query);
                            if ($platforms_result && $platforms_result->num_rows > 0) {
                                while ($platform_row = $platforms_result->fetch_assoc()) {
                                    $platform_name = htmlspecialchars($platform_row['name']);
                                    echo '<span class="custom-option" data-value="' . $platform_name . '">' . $platform_name . '</span>';
                                }
                            } else {
                                echo '<span class="custom-option" style="color: #888; pointer-events: none;">No hay plataformas disponibles</span>';
                            }
                          ?>
                      </div>
                  </div>
              </div>
              <input type="hidden" name="plataforma" id="plataforma" required>
              <i class="fas fa-list form-icon"></i>
          </div>

          <?php if ($user_logged_in): ?>
            <input type="hidden" name="user_id" value="<?= htmlspecialchars($_SESSION['user_id']) ?>">
          <?php endif; ?>

          <button type="submit" class="btn-search-modern" id="searchBtn">
            <span class="btn-text">Buscar Códigos</span>
          </button>
        </form>
    </div>

    <!-- Contenedor de resultados -->
    <div id="results-container" class="results-container <?= !$has_results ? 'hidden' : '' ?>">
      <!-- Botón de nueva búsqueda AL INICIO -->
      <div class="text-center" style="margin-bottom: 0.5rem;">
          <a href="inicio.php" class="btn-back">
            <i class="fas fa-search"></i> Nueva Búsqueda
          </a>
      </div>
      
      <?php if (!empty($resultado)): ?>
        <!-- Indicador de éxito -->
        <div class="alert-modern alert-success-modern" style="margin-bottom: 0.5rem;">
          <i class="fas fa-check-circle"></i>
          <strong>¡Código encontrado!</strong> Tu código de verificación está listo.
        </div>
        
        <!-- Contenido del resultado - SIN MODIFICAR -->
        <div class="result-content-wrapper">
          <?= $resultado ?>
        </div>
      <?php endif; ?>
      
      <?php if (!empty($error_message)): ?>
        <!-- Mensaje de error -->
        <div class="alert-modern alert-danger-modern" style="margin-bottom: 0.5rem;">
          <i class="fas fa-exclamation-triangle"></i>
          <?= strip_tags($error_message, '<strong><b><i><em>') ?>
        </div>
      <?php endif; ?>
    </div>

  </div>
</div>

<footer class="footer-modern">
  <div class="container">
    <p class="mb-0">
      ¿Estás interesado en una página web y en un bot de códigos?<br>
      <a href="https://clientes.hostsbl.com/aff.php?aff=<?= htmlspecialchars($settings['ID_VENDEDOR'] ?? ''); ?>" target="_blank">
        Click aquí para más información
      </a>
    </p>
  </div>
</footer>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
document.addEventListener('DOMContentLoaded', function() {
    // Efecto máquina de escribir para el título
    const title = document.getElementById('typing-title');
    const titleText = 'Consulta tu Código Aquí';
    let i = 0;
    
    function typeWriter() {
        if (i < titleText.length) {
            title.innerHTML += titleText.charAt(i);
            i++;
            setTimeout(typeWriter, 100); // Velocidad de escritura (100ms por letra)
        } else {
            // Añadir cursor parpadeante al final
            title.style.borderRight = '2px solid var(--accent-green)';
            title.style.animation = 'blink 1s infinite';
        }
    }
    
    // Iniciar el efecto después de un pequeño delay
    setTimeout(typeWriter, 500);
    
    // Manejar el select personalizado
    const customSelect = document.querySelector('.custom-select');
    if (customSelect) {
        const trigger = customSelect.querySelector('.custom-select__trigger');
        const options = customSelect.querySelectorAll('.custom-option');
        const hiddenInput = document.getElementById('plataforma');
        const triggerSpan = trigger.querySelector('span');

        trigger.addEventListener('click', function() {
            customSelect.classList.toggle('open');
        });

        options.forEach(option => {
            option.addEventListener('click', function(e) {
                if (e.target.hasAttribute('data-value')) {
                    triggerSpan.textContent = this.textContent;
                    triggerSpan.style.color = 'var(--text-primary)';
                    hiddenInput.value = this.getAttribute('data-value');
                    hiddenInput.dispatchEvent(new Event('input', { bubbles: true }));
                    customSelect.classList.remove('open');
                }
            });
        });

        window.addEventListener('click', function(e) {
            if (!customSelect.contains(e.target)) {
                customSelect.classList.remove('open');
            }
        });
    }

    // Efectos adicionales para resultados
    const resultsContainer = document.getElementById('results-container');
    if (resultsContainer && !resultsContainer.classList.contains('hidden')) {
        // Añadir animación de entrada para los resultados
        resultsContainer.style.opacity = '0';
        resultsContainer.style.transform = 'translateY(30px)';
        
        setTimeout(() => {
            resultsContainer.style.transition = 'all 0.6s ease';
            resultsContainer.style.opacity = '1';
            resultsContainer.style.transform = 'translateY(0)';
        }, 100);
    }

    // Asegurar que el fondo siempre esté visible
    document.body.style.position = 'relative';
    document.body.style.zIndex = '0';
});
</script>

</body>
</html>