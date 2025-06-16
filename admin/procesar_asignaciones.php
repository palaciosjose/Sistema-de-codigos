<?php
// admin/procesar_asignaciones.php
session_start();
require_once '../instalacion/basededatos.php';
require_once '../security/auth.php';

// Verificar si el usuario es admin
check_session(true, '../index.php');

// Crear conexión a la base de datos
$conn = new mysqli($db_host, $db_user, $db_password, $db_name);
$conn->set_charset("utf8mb4");

if ($conn->connect_error) {
    die("Error de conexión: " . $conn->connect_error);
}

$action = $_REQUEST['action'] ?? null;

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
            $_SESSION['assignment_error'] = 'Acción no válida.';
            header('Location: admin.php?tab=asignaciones');
            exit();
    }
}

function assignEmailsToUser($conn) {
    $user_id = filter_var($_POST['user_id'] ?? null, FILTER_VALIDATE_INT);
    $email_ids = $_POST['email_ids'] ?? [];
    $assigned_by = $_SESSION['user_id'] ?? null;
    
    if (!$user_id || empty($email_ids)) {
        $_SESSION['assignment_error'] = 'Datos incompletos para la asignación.';
        header('Location: admin.php?tab=asignaciones');
        exit();
    }
    
    // Verificar que el usuario existe
    $stmt_check = $conn->prepare("SELECT id FROM users WHERE id = ?");
    $stmt_check->bind_param("i", $user_id);
    $stmt_check->execute();
    if ($stmt_check->get_result()->num_rows == 0) {
        $_SESSION['assignment_error'] = 'Usuario no encontrado.';
        header('Location: admin.php?tab=asignaciones');
        exit();
    }
    $stmt_check->close();
    
    // Primero, eliminar asignaciones existentes para este usuario
    $stmt_delete = $conn->prepare("DELETE FROM user_authorized_emails WHERE user_id = ?");
    $stmt_delete->bind_param("i", $user_id);
    $stmt_delete->execute();
    $stmt_delete->close();
    
    // Insertar nuevas asignaciones
    $stmt_insert = $conn->prepare("INSERT INTO user_authorized_emails (user_id, authorized_email_id, assigned_by) VALUES (?, ?, ?)");
    $inserted = 0;
    
    foreach ($email_ids as $email_id) {
        $email_id_int = filter_var($email_id, FILTER_VALIDATE_INT);
        if ($email_id_int) {
            $stmt_insert->bind_param("iii", $user_id, $email_id_int, $assigned_by);
            if ($stmt_insert->execute()) {
                $inserted++;
            }
        }
    }
    
    $stmt_insert->close();
    
    if ($inserted > 0) {
        $_SESSION['assignment_message'] = "Se asignaron $inserted correos al usuario correctamente.";
    } else {
        $_SESSION['assignment_error'] = 'No se pudo asignar ningún correo.';
    }
    
    header('Location: admin.php?tab=asignaciones');
    exit();
}

function removeEmailFromUser($conn) {
    $user_id = filter_var($_POST['user_id'] ?? null, FILTER_VALIDATE_INT);
    $email_id = filter_var($_POST['email_id'] ?? null, FILTER_VALIDATE_INT);
    
    if (!$user_id || !$email_id) {
        echo json_encode(['success' => false, 'error' => 'Datos incompletos']);
        exit();
    }
    
    $stmt = $conn->prepare("DELETE FROM user_authorized_emails WHERE user_id = ? AND authorized_email_id = ?");
    $stmt->bind_param("ii", $user_id, $email_id);
    
    if ($stmt->execute()) {
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['success' => false, 'error' => 'Error al eliminar asignación']);
    }
    $stmt->close();
    exit();
}

function getUserEmails($conn) {
    header('Content-Type: application/json');
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
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $emails = [];
    while ($row = $result->fetch_assoc()) {
        $emails[] = $row;
    }
    
    echo json_encode(['success' => true, 'emails' => $emails]);
    $stmt->close();
    exit();
}

$conn->close();
?>