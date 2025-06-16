<?php
// Iniciar la sesión
session_start();

// Incluir el archivo de funciones centralizadas
require_once 'funciones.php';

// Verificar si el sistema está instalado
if (!is_installed()) {
    // Redirigir a la página de instalación
    header("Location: instalacion/instalador.php");
    exit();
}

// A partir de aquí, sabemos que el sistema está instalado
// Incluir archivos necesarios de configuración
if (file_exists('instalacion/basededatos.php')) {
    require_once 'instalacion/basededatos.php';
}

// Configurar sesión solo si no está activa
if (session_status() === PHP_SESSION_NONE) {
    // Establecer la duración de la sesión (15 minutos)
    ini_set('session.gc_maxlifetime', 900);
    ini_set('session.cookie_lifetime', 900);
    session_set_cookie_params([
        'lifetime' => 900,
        'path' => '/',
        'domain' => '',
        'secure' => false,
        'httponly' => true,
        'samesite' => 'Lax'
    ]);
}

// Evitar almacenamiento en caché
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

// Verificar si el usuario ya está autenticado
if (isset($_SESSION['user_id'])) {
    // Redirigir a inicio.php si ya está autenticado
    header("Location: inicio.php");
    exit();
}

// Continuar con la lógica de login existente...
// Obtener la configuración de login requerido
$conn = new mysqli($db_host, $db_user, $db_password, $db_name);
$conn->set_charset("utf8mb4");

if ($conn->connect_error) {
    die("Error de conexión a la base de datos: " . $conn->connect_error);
}

// Obtener la configuración de login requerido
$stmt = $conn->prepare("SELECT value FROM settings WHERE name = 'REQUIRE_LOGIN'");
$stmt->execute();
$stmt->bind_result($require_login);
$stmt->fetch();
$stmt->close();

// Si no existe la configuración, establecerla como habilitada por defecto
if ($require_login === null) {
    $require_login = '1';
    $stmt = $conn->prepare("INSERT INTO settings (name, value, description) VALUES ('REQUIRE_LOGIN', '1', 'Si está activado (1), se requiere inicio de sesión para todos los usuarios. Si está desactivado (0), solo se requiere para administradores.')");
    $stmt->execute();
    $stmt->close();
}

// Verificar si el usuario ya está autenticado
if (isset($_SESSION['user_id'])) {
    // Redirigir a inicio.php si ya está autenticado
    header("Location: inicio.php");
    exit();
}

// Variable para mostrar mensajes de error
$login_error = '';
$show_login_form = true;
$admin_only_login = false;

// Verificar si es un acceso para admin o acceso normal
if ($require_login === '0' && !isset($_GET['action'])) {
    // Si no se requiere login y no es un acceso específico para admin, redireccionar a inicio.php
    header("Location: inicio.php");
    exit();
} else if ($require_login === '0' && isset($_GET['action']) && $_GET['action'] === 'admin_login') {
    // Es un acceso específico para admin
    $admin_only_login = true;
    $show_login_form = true;
}

// Procesar el formulario de inicio de sesión
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    // Sanitizar entradas
    $username = $conn->real_escape_string(trim($_POST['username']));
    $password = $_POST['password'];

    if ($admin_only_login) {
        // Solo verificar credenciales de administrador
        $stmt = $conn->prepare("SELECT id, username, password FROM admin WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            // Es un administrador
            $user = $result->fetch_assoc();
            if (password_verify($password, $user['password'])) {
                // Autenticación exitosa
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['user_role'] = 'admin';
                $_SESSION['last_activity'] = time();
                
                // Redirigir a inicio.php
                header("Location: inicio.php");
                exit();
            } else {
                $login_error = "Contraseña incorrecta";
            }
        } else {
            $login_error = "Usuario no encontrado o no es administrador";
        }
        
        $stmt->close();
    } else {
        // Verificar si es administrador o usuario regular
        // Primero verificar si es un administrador
        $stmt = $conn->prepare("SELECT id, username, password FROM admin WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            // Es un administrador
            $user = $result->fetch_assoc();
            if (password_verify($password, $user['password'])) {
                // Autenticación exitosa
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['user_role'] = 'admin';
                $_SESSION['last_activity'] = time();
                
                // Redirigir a inicio.php
                header("Location: inicio.php");
                exit();
            } else {
                $login_error = "Contraseña incorrecta";
            }
        } else {
            // No es admin, verificar si es usuario regular
            $stmt = $conn->prepare("SELECT id, username, password FROM users WHERE username = ? AND status = 1");
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows > 0) {
                $user = $result->fetch_assoc();
                if (password_verify($password, $user['password'])) {
                    // Autenticación exitosa
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['username'] = $user['username'];
                    $_SESSION['user_role'] = 'usuario';
                    $_SESSION['last_activity'] = time();
                    
                    // Redirigir a inicio.php
                    header("Location: inicio.php");
                    exit();
                } else {
                    $login_error = "Contraseña incorrecta";
                }
            } else {
                $login_error = "Usuario no encontrado o inactivo";
            }
        }
        
        $stmt->close();
    }
    
    $conn->close();
}

// Obtener configuraciones (si existen)
$page_title = 'Sistema de Códigos';
$settings_query = $conn->query("SELECT * FROM settings WHERE name = 'PAGE_TITLE'");
if ($settings_query && $settings_query->num_rows > 0) {
    $setting = $settings_query->fetch_assoc();
    $page_title = $setting['value'];
}

$conn->close();

// Mostrar el formulario solo si es necesario
if ($show_login_form):
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($page_title) ?> - Iniciar Sesión</title>
    
    <!-- Bootstrap CSS (CDN) -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    
    <!-- Font Awesome (CDN) -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <!-- Estilos modernos -->
    <link rel="stylesheet" href="styles/modern_global.css">
    
    <style>
        /* Estilos específicos para la página de login */
        body {
            min-height: 100vh;
            overflow: hidden;
        }

        /* Fondo animado específico */
        .animated-background {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            background: var(--dark-gradient);
        }

        .animated-background::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image: 
                radial-gradient(circle at 25% 25%, rgba(102, 126, 234, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 75% 75%, rgba(139, 92, 246, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 50% 50%, rgba(6, 182, 212, 0.1) 0%, transparent 50%);
            animation: backgroundPulse 6s ease-in-out infinite alternate;
        }

        /* Container de login */
        .login-container {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: var(--spacing-xl) var(--spacing-md);
            position: relative;
        }

        /* Card de login */
        .login-card {
            background: var(--bg-glass);
            backdrop-filter: blur(30px);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-2xl);
            padding: var(--spacing-2xl);
            max-width: 450px;
            width: 100%;
            box-shadow: var(--shadow-xl);
            position: relative;
            overflow: hidden;
            animation: loginCardEntry 1s ease;
        }

        .login-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: var(--primary-gradient);
            opacity: 0.8;
        }

        @keyframes loginCardEntry {
            from {
                opacity: 0;
                transform: translateY(50px) scale(0.9);
            }
            to {
                opacity: 1;
                transform: translateY(0) scale(1);
            }
        }

        /* Header del login */
        .login-header {
            text-align: center;
            margin-bottom: var(--spacing-2xl);
        }

        .login-logo {
            width: 80px;
            height: 80px;
            border-radius: var(--radius-xl);
            background: var(--primary-gradient);
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto var(--spacing-lg);
            box-shadow: var(--shadow-md);
            animation: logoFloat 4s ease-in-out infinite;
        }

        .login-logo i {
            font-size: 2rem;
            color: white;
        }

        @keyframes logoFloat {
            0%, 100% {
                transform: translateY(0);
            }
            50% {
                transform: translateY(-10px);
            }
        }

        .login-title {
            font-family: 'Poppins', sans-serif;
            font-weight: 600;
            font-size: var(--font-3xl);
            margin-bottom: var(--spacing-sm);
            background: var(--primary-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .login-subtitle {
            color: var(--text-secondary);
            font-size: var(--font-base);
        }

        /* Formulario */
        .login-form {
            position: relative;
        }

        .form-group {
            position: relative;
            margin-bottom: var(--spacing-lg);
        }

        .form-input {
            width: 100%;
            padding: var(--spacing-md) var(--spacing-md) var(--spacing-md) 3.5rem;
            background: rgba(255, 255, 255, 0.05);
            border: 2px solid var(--border-color);
            border-radius: var(--radius-lg);
            color: var(--text-primary);
            font-size: var(--font-base);
            transition: all var(--transition-base);
            backdrop-filter: blur(10px);
        }

        .form-input::placeholder {
            color: var(--text-muted);
        }

        .form-input:focus {
            outline: none;
            border-color: var(--primary-color);
            background: rgba(255, 255, 255, 0.1);
            box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.1);
            transform: translateY(-2px);
        }

        .form-icon {
            position: absolute;
            left: var(--spacing-md);
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted);
            font-size: var(--font-lg);
            transition: all var(--transition-base);
            z-index: 2;
        }

        .form-input:focus + .form-icon {
            color: var(--primary-color);
            transform: translateY(-50%) scale(1.1);
        }

        /* Botón de login */
        .login-btn {
            width: 100%;
            padding: var(--spacing-lg) var(--spacing-xl);
            background: var(--primary-gradient);
            border: none;
            border-radius: var(--radius-lg);
            color: white;
            font-weight: 600;
            font-size: var(--font-lg);
            cursor: pointer;
            transition: all var(--transition-base);
            position: relative;
            overflow: hidden;
            margin-top: var(--spacing-lg);
            display: flex;
            align-items: center;
            justify-content: center;
            gap: var(--spacing-sm);
        }

        .login-btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
            transition: left var(--transition-slow);
        }

        .login-btn:hover {
            transform: translateY(-3px);
            box-shadow: var(--shadow-xl);
        }

        .login-btn:hover::before {
            left: 100%;
        }

        .login-btn:active {
            transform: translateY(-1px);
        }

        /* Alertas */
        .alert-modern {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-left: 4px solid var(--error-color);
            border-radius: var(--radius-lg);
            padding: var(--spacing-md) var(--spacing-lg);
            margin-bottom: var(--spacing-lg);
            color: var(--error-color);
            backdrop-filter: blur(10px);
            animation: alertSlide 0.5s ease;
            display: flex;
            align-items: center;
            gap: var(--spacing-sm);
        }

        @keyframes alertSlide {
            from {
                opacity: 0;
                transform: translateX(-20px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }

        /* Enlaces adicionales */
        .login-links {
            text-align: center;
            margin-top: var(--spacing-xl);
            padding-top: var(--spacing-lg);
            border-top: 1px solid var(--border-color);
        }

        .login-link {
            color: var(--text-secondary);
            text-decoration: none;
            font-size: var(--font-sm);
            transition: all var(--transition-base);
            display: inline-flex;
            align-items: center;
            gap: var(--spacing-sm);
        }

        .login-link:hover {
            color: var(--primary-color);
            transform: translateX(-5px);
        }

        /* Responsive */
        @media (max-width: 768px) {
            .login-card {
                padding: var(--spacing-xl) var(--spacing-lg);
                margin: var(--spacing-md);
                border-radius: var(--radius-xl);
            }

            .login-title {
                font-size: var(--font-2xl);
            }

            .form-input {
                padding: var(--spacing-md) var(--spacing-md) var(--spacing-md) 3rem;
            }

            .form-icon {
                left: var(--spacing-sm);
                font-size: var(--font-base);
            }
        }
    </style>
</head>
<body>
    <!-- Fondo animado -->
    <div class="animated-background"></div>

    <!-- Partículas flotantes -->
    <div class="floating-particles">
        <div class="particle"></div>
        <div class="particle"></div>
        <div class="particle"></div>
        <div class="particle"></div>
        <div class="particle"></div>
    </div>

    <!-- Container principal -->
    <div class="login-container">
        <div class="login-card">
            <!-- Header -->
            <div class="login-header">
                <div class="login-logo">
                    <i class="fas fa-code"></i>
                </div>
                <h1 class="login-title">Iniciar Sesión</h1>
                <p class="login-subtitle">
                    <?php if ($admin_only_login): ?>
                        Acceso exclusivo para administradores
                    <?php else: ?>
                        Accede a tu sistema de códigos
                    <?php endif; ?>
                </p>
            </div>

            <!-- Alerta de error -->
            <?php if (!empty($login_error)): ?>
                <div class="alert-modern">
                    <i class="fas fa-exclamation-circle"></i>
                    <span><?= htmlspecialchars($login_error) ?></span>
                </div>
            <?php endif; ?>

            <!-- Formulario -->
            <form class="login-form" method="POST" action="<?= $admin_only_login ? 'index.php?action=admin_login' : 'index.php' ?>">
                <div class="form-group">
                    <input 
                        type="text" 
                        class="form-input" 
                        name="username" 
                        placeholder="Usuario" 
                        required 
                        autofocus
                        autocomplete="username"
                    >
                    <i class="fas fa-user form-icon"></i>
                </div>

                <div class="form-group">
                    <input 
                        type="password" 
                        class="form-input" 
                        name="password" 
                        placeholder="Contraseña" 
                        required
                        autocomplete="current-password"
                    >
                    <i class="fas fa-lock form-icon"></i>
                </div>

                <button type="submit" name="login" class="login-btn">
                    <i class="fas fa-sign-in-alt"></i>
                    <span>Ingresar</span>
                </button>
            </form>

            <!-- Enlaces adicionales -->
            <div class="login-links">
                <?php if ($admin_only_login): ?>
                    <a href="inicio.php" class="login-link">
                        <i class="fas fa-arrow-left"></i>
                        Volver a la página principal
                    </a>
                <?php else: ?>
                    <a href="inicio.php" class="login-link">
                        <i class="fas fa-home"></i>
                        Ir al inicio
                    </a>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS (CDN) -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const form = document.querySelector('.login-form');
            const inputs = document.querySelectorAll('.form-input');
            
            // Efectos de entrada para los inputs
            inputs.forEach((input, index) => {
                input.style.opacity = '0';
                input.style.transform = 'translateY(20px)';
                
                setTimeout(() => {
                    input.style.transition = 'all 0.5s ease';
                    input.style.opacity = '1';
                    input.style.transform = 'translateY(0)';
                }, 300 + (index * 150));
            });

            // Efectos de hover en inputs
            inputs.forEach(input => {
                input.addEventListener('focus', function() {
                    this.parentElement.style.transform = 'translateY(-2px)';
                });
                
                input.addEventListener('blur', function() {
                    this.parentElement.style.transform = 'translateY(0)';
                });
            });

            // Efecto de shake en error
            <?php if (!empty($login_error)): ?>
            const loginCard = document.querySelector('.login-card');
            loginCard.style.animation = 'loginCardEntry 1s ease, shake 0.5s ease 1s';
            
            const style = document.createElement('style');
            style.textContent = `
                @keyframes shake {
                    0%, 100% { transform: translateX(0); }
                    25% { transform: translateX(-10px); }
                    75% { transform: translateX(10px); }
                }
            `;
            document.head.appendChild(style);
            <?php endif; ?>
        });
    </script>
</body>
</html>
<?php endif; ?>