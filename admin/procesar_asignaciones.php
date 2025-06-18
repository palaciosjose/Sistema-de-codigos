<?php
// Asegurarse de que la sesión esté iniciada
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Incluir dependencias
require_once '../instalacion/basededatos.php';
require_once '../security/auth.php';

// Verificar autenticación (admin requerido)
check_session(true, '../index.php');

// Crear conexión a la base de datos
$conn = new mysqli($db_host, $db_user, $db_password, $db_name);
$conn->set_charset("utf8mb4");

if ($conn->connect_error) {
    header('Content-Type: application/json');
    echo json_encode(['success' => false, 'error' => 'Error de conexión a la base de datos: ' . $conn->connect_error]);
    exit();
}

$action = $_REQUEST['action'] ?? null;

// Manejar diferentes métodos HTTP
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    switch ($action) {
        case 'assign_emails_to_user':
            assignEmailsToUser($conn);
            break;
        case 'remove_email_from_user':
            removeEmailFromUser($conn);
            break;
        case 'get_user_emails':
            getUserEmails($conn);
            break;
        default:
            header('Content-Type: application/json');
            echo json_encode(['success' => false, 'error' => 'Acción POST no válida.']);
            exit();
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'GET') {
    switch ($action) {
        case 'get_user_emails':
            getUserEmails($conn);
            break;
        default:
            header('Content-Type: application/json');
            echo json_encode(['success' => false, 'error' => 'Acción GET no válida.']);
            exit();
    }
} else {
    header('Content-Type: application/json');
    echo json_encode(['success' => false, 'error' => 'Método de solicitud no soportado.']);
    exit();
}

function assignEmailsToUser($conn) {
    $user_id = filter_var($_POST['user_id'] ?? null, FILTER_VALIDATE_INT);
    $email_ids = $_POST['email_ids'] ?? [];
    $assigned_by = $_SESSION['user_id'] ?? null;
    
    if (!$user_id || !is_array($email_ids)) {
        $_SESSION['assignment_error'] = 'Datos incompletos para la asignación.';
        header('Location: admin.php?tab=asignaciones');
        exit();
    }
    
    // Verificar que el usuario existe
    $stmt_check = $conn->prepare("SELECT id FROM users WHERE id = ?");
    if (!$stmt_check) {
        $_SESSION['assignment_error'] = 'Error al preparar consulta de verificación de usuario: ' . $conn->error;
        header('Location: admin.php?tab=asignaciones');
        exit();
    }
    
    $stmt_check->bind_param("i", $user_id);
    $stmt_check->execute();
    $result = $stmt_check->get_result();
    
    if ($result->num_rows == 0) {
        $_SESSION['assignment_error'] = 'Usuario no encontrado.';
        $stmt_check->close();
        header('Location: admin.php?tab=asignaciones');
        exit();
    }
    $stmt_check->close();
    
    // Iniciar transacción
    $conn->begin_transaction();
    
    try {
        // Eliminar asignaciones existentes para este usuario
        $stmt_delete = $conn->prepare("DELETE FROM user_authorized_emails WHERE user_id = ?");
        if (!$stmt_delete) {
            throw new Exception('Error al preparar eliminación de asignaciones: ' . $conn->error);
        }
        
        $stmt_delete->bind_param("i", $user_id);
        if (!$stmt_delete->execute()) {
            throw new Exception('Error al eliminar asignaciones existentes: ' . $stmt_delete->error);
        }
        $stmt_delete->close();
        
        // Insertar nuevas asignaciones
        if (!empty($email_ids)) {
            $stmt_insert = $conn->prepare("INSERT INTO user_authorized_emails (user_id, authorized_email_id, assigned_by) VALUES (?, ?, ?)");
            if (!$stmt_insert) {
                throw new Exception('Error al preparar inserción de asignaciones: ' . $conn->error);
            }
            
            $inserted = 0;
            foreach ($email_ids as $email_id) {
                $email_id_int = filter_var($email_id, FILTER_VALIDATE_INT);
                if ($email_id_int) {
                    $stmt_insert->bind_param("iii", $user_id, $email_id_int, $assigned_by);
                    if ($stmt_insert->execute()) {
                        $inserted++;
                    } else {
                        error_log("Error insertando asignación para user_id: $user_id, email_id: $email_id_int - " . $stmt_insert->error);
                    }
                }
            }
            $stmt_insert->close();
            
            $_SESSION['assignment_message'] = "Se asignaron $inserted correos al usuario correctamente.";
        } else {
            $_SESSION['assignment_message'] = "Se removieron todos los correos asignados al usuario.";
        }
        
        $conn->commit();
        
    } catch (Exception $e) {
        $conn->rollback();
        $_SESSION['assignment_error'] = 'Error en la transacción de asignación: ' . $e->getMessage();
        error_log("Error en asignación de emails: " . $e->getMessage());
    }
    
    header('Location: admin.php?tab=asignaciones');
    exit();
}

function removeEmailFromUser($conn) {
    header('Content-Type: application/json');
    
    $user_id = filter_var($_POST['user_id'] ?? null, FILTER_VALIDATE_INT);
    $email_id = filter_var($_POST['email_id'] ?? null, FILTER_VALIDATE_INT);
    
    if (!$user_id || !$email_id) {
        echo json_encode(['success' => false, 'error' => 'Datos incompletos para eliminar asignación']);
        exit();
    }
    
    $stmt = $conn->prepare("DELETE FROM user_authorized_emails WHERE user_id = ? AND authorized_email_id = ?");
    if (!$stmt) {
        echo json_encode(['success' => false, 'error' => 'Error al preparar eliminación: ' . $conn->error]);
        exit();
    }
    
    $stmt->bind_param("ii", $user_id, $email_id);
    
    if ($stmt->execute()) {
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['success' => false, 'error' => 'Error al eliminar asignación: ' . $stmt->error]);
    }
    
    $stmt->close();
    exit();
}

function getUserEmails($conn) {
    // Limpiar cualquier salida previa
    if (ob_get_level()) {
        ob_clean();
    }
    
    header('Content-Type: application/json');
    header('Cache-Control: no-cache, must-revalidate');
    header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');
    
    $user_id = filter_var($_GET['user_id'] ?? null, FILTER_VALIDATE_INT);
    
    if (!$user_id) {
        echo json_encode(['success' => false, 'error' => 'ID de usuario inválido']);
        exit();
    }
    
    $query = "
        SELECT ae.id, ae.email, uae.assigned_at 
        FROM user_authorized_emails uae 
        JOIN authorized_emails ae ON uae.authorized_email_id = ae.id 
        WHERE uae.user_id = ? 
        ORDER BY ae.email ASC
    ";
    
    $stmt = $conn->prepare($query);
    if (!$stmt) {
        echo json_encode(['success' => false, 'error' => 'Error al preparar la consulta: ' . $conn->error]);
        exit();
    }
    
    $stmt->bind_param("i", $user_id);
    
    if ($stmt->execute()) {
        $result = $stmt->get_result();
        
        $emails = [];
        while ($row = $result->fetch_assoc()) {
            $emails[] = [
                'id' => $row['id'],
                'email' => $row['email'],
                'assigned_at' => $row['assigned_at']
            ];
        }
        
        echo json_encode([
            'success' => true, 
            'emails' => $emails,
            'count' => count($emails),
            'user_id' => $user_id
        ]);
    } else {
        echo json_encode(['success' => false, 'error' => 'Error al ejecutar la consulta: ' . $stmt->error]);
    }
    
    $stmt->close();
    exit();
}

// Cerrar conexión
$conn->close();
?>