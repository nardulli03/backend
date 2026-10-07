"""
Política de contraseña — funciones PURAS de validación.

Otro ejemplo de función pura: le pasás un string y devuelve un resultado.
No depende de nada externo, así que testearla es trivial.
"""

MIN_LENGTH = 8


def validate_password(password: str) -> list[str]:
    """Devuelve la lista de problemas de una contraseña (vacía si es válida)."""
    errors: list[str] = []

    if len(password) < MIN_LENGTH:
        errors.append("muy corta (mínimo 8 caracteres)")
    if not any(c.isupper() for c in password):
        errors.append("falta una mayúscula")
    if not any(c.isdigit() for c in password):
        errors.append("falta un número")


    return errors


def is_strong(password: str) -> bool:
    """True si la contraseña no tiene ningún problema."""
    return not validate_password(password)
