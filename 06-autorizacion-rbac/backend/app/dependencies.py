"""
Dependencias de AUTORIZACIÓN — el corazón de la entrega del módulo 06.

Acá viven las 3 dependencias reutilizables que protegen TODOS los endpoints:

  1. get_current_user  → AUTENTICACIÓN (ya lo resolviste en el módulo 04,
                         acá está resuelto como referencia: 401 si no hay
                         token válido). ADEMÁS guarda el payload del token en
                         `request.state` para que require_scope lo lea.

  2. require_role      → AUTORIZACIÓN por rol. 403 si el rol no alcanza.
      ─────────────────────────────────────────────────────────────────────
      🔴 ESTADO ACTUAL: VULNERABLE. Devuelve al usuario sin verificar nada:
      cualquier autenticado "pasa" como si tuviera el rol pedido.
      💡 TU TRABAJO: comparar `current_user.role` contra `required` y
         responder 403 si no coinciden. El 403 (Forbidden) es el código
         de la AUTORIZACIÓN: autenticado pero sin permiso.
      ─────────────────────────────────────────────────────────────────────

  3. require_scope     → AUTORIZACIÓN por scope del TOKEN. 403 si el scope
                         del token no alcanza para la operación.
      ─────────────────────────────────────────────────────────────────────
      🔴 ESTADO ACTUAL: VULNERABLE. Lee el payload pero no valida nada.
      💡 TU TRABAJO: leer `request.state.token_payload` (que dejó
         get_current_user) y responder 403 si el scope pedido NO está
         dentro del scope del token.
      🧠 LECCIÓN (Pilar 3): el ROL es del usuario (lo relees de storage en
         cada request → el cambio de rol es inmediato). El SCOPE es del
         TOKEN (vive en el claim `scope`, lo fijó el login). Por eso
         require_scope lee del token y require_role del usuario.
      ─────────────────────────────────────────────────────────────────────
"""

from typing import Annotated, Callable

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer
from jwt import InvalidTokenError

from app import security, storage
from app.models import Role, User

bearer_scheme = HTTPBearer(auto_error=False)


# ── 1 · Autenticación (resuelto — referencia del módulo 04) ────────────────


def get_current_user(
    request: Request,
    credentials: Annotated[dict | None, Depends(bearer_scheme)],
) -> User:
    """Quién sos: decodifica el JWT y carga el usuario desde storage.

    - Token ausente / inválido / expirado / usuario inexistente → 401.
    - Usuario cargado → se guarda el payload en `request.state.token_payload`
      para que require_scope (que sí lee del token) lo tenga a mano.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales inválidas",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None:
        raise credentials_exception

    try:
        payload = security.decode_token(credentials.credentials)
        user_id = int(payload["sub"])
    except (InvalidTokenError, KeyError, ValueError):
        raise credentials_exception

    user = storage.get_user_by_id(user_id)
    if user is None:
        raise credentials_exception

    # El payload del token queda accesible para las dependencias que
    # autorizan por SCOPE. El rol, en cambio, se relee del usuario fresco.
    request.state.token_payload = payload
    return user


# ── 2 · Autorización por ROL (🔓 COMPLETÁS VOS) ────────────────────────────


def require_role(required: Role) -> Callable:
    """Factory de dependencia: exige que el usuario tenga `required` (o 403).

    Uso en los endpoints:
        current_user: User = Depends(require_role(Role.ADMIN))

    🔴 ESTADO ACTUAL (VULNERABLE): devuelve al usuario sin verificar el rol.
    Si corrés el script de verificación ahora, los checks de "gestionar
    usuarios → 403" van a fallar porque CUALQUIER autenticado pasa acá.

    ✅ COMPLETALO:
        1. Compará `current_user.role` con `required`. ¿Coinciden?
           NO → lanzá HTTPException 403 con un detail claro
                ("No tenés el rol necesario para esta operación").
           SÍ → devolvé `current_user` (los endpoints lo usan).
    """
    def checker(
        current_user: Annotated[User, Depends(get_current_user)],
    ) -> User:
        if current_user.role != required:
            raise HTTPException(
                status_code=403,
                detail="No tenés el rol necesario para esta operación",
            )
        return current_user
    return checker


# ── 3 · Autorización por SCOPE del token (🔓 COMPLETÁS VOS) ────────────────


def require_scope(required: str) -> Callable:
    """Factory de dependencia: exige que el TOKEN tenga `required` en su scope.

    Uso en los endpoints:
        current_user: User = Depends(require_scope("write"))

    🧠 La diferencia con require_role:
        - Un ADMIN que logueó con scope "read" (token de integración de solo
          lectura) NO puede crear documentos aunque sea admin. El scope se
          lee del TOKEN (request.state.token_payload), no del usuario.

    🔴 ESTADO ACTUAL (VULNERABLE): no valida nada.

    ✅ COMPLETALO:
        1. Leé el scope del token:
               payload = request.state.token_payload
               token_scope = payload.get("scope", "")
        2. Si `required` NO está dentro de token_scope → 403 con un detail
           claro ("El token no tiene el scope necesario para esta operación").
        3. Si querés soportar varios scopes separados por espacio
           ("read write"), pensá en dividir con .split().
        4. Devolvé `current_user`.
    """
    def checker(
        request: Request,
        current_user: Annotated[User, Depends(get_current_user)],
    ) -> User:
        payload = request.state.token_payload
        token_scope = payload.get("scope", "")
        if required not in token_scope.split():
            raise HTTPException(
                status_code=403,
                detail="El token no tiene el scope necesario para esta operación",
            )
        return current_user
    return checker