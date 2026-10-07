"""
Reglas de autorización PURAS — el corazón testable del módulo.

Estas funciones NO tocan la base de datos, ni la red, ni el reloj.
Reciben argumentos y devuelven un valor: son FUNCIONES PURAS, el caso
ideal para test unitario (rápido, determinista, sin setup).

Son las mismas reglas que viste en el módulo 06 (autorización RBAC),
sacadas del framework para que puedas testearlas aisladas.
"""

def scope_allows_write(scope: str) -> bool:
    """True si el scope del token incluye "write".

    "read write" -> True ; "read" -> False
    """
    return "write" in scope.split()


def can_manage_users(role: str) -> bool:
    """Solo un admin puede gestionar (listar) usuarios."""
    return role == "admin"


def can_change_role(role: str) -> bool:
    """Solo un admin puede cambiar el rol de otro usuario."""
    return role == "admin"


def can_delete(role: str) -> bool:
    """Solo un admin puede borrar documentos."""
    return role == "admin"


def can_edit(owner_id: int, user_id: int, role: str) -> bool:
    """Puede editar si es el dueño del documento o un admin.

    object-level access control: el dueño siempre puede sobre lo suyo;
    un admin puede sobre cualquier documento de su empresa.
    """
    return owner_id == user_id or role == "admin"

def can_publish(owner_id: int, user_id: int, role: str) -> bool:
    return owner_id == user_id or role == "admin"