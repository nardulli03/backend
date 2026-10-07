"""Tests de referencia — leé estos ANTES de hacer el ejercicio.

Son tests COMPLETOS que pasan. Fijate en cada uno las tres fases AAA
(Arrange / Act / Assert) y cómo el nombre del test describe el comportamiento.
"""

from app.password import is_strong, validate_password

def test_validate_password_devuelve_vacio_si_es_valida():
    # Arrange
    password = "Supersecreta1"
    # Act
    errores = validate_password(password)
    # Assert
    assert errores == []


def test_validate_password_detecta_corta():
    errores = validate_password("abc")
    assert any("corta" in e for e in errores)


def test_validate_password_detecta_falta_mayuscula():
    errores = validate_password("supersecreta1")
    assert any("mayúscula" in e for e in errores)


def test_validate_password_detecta_falta_numero():
    errores = validate_password("Supersecreta")
    assert any("número" in e for e in errores)


def test_is_strong_true_cuando_no_hay_errores():
    assert is_strong("Supersecreta1") is True


def test_is_strong_false_cuando_hay_errores():
    assert is_strong("corta") is False

"""Verificar los 3 requisitos incumplidos de una contraseña vacía."""  
 
def test_validate_password_vacia():
    errores = validate_password("")

    assert len(errores) == 3
    assert "muy corta (mínimo 8 caracteres)" in errores
    assert "falta una mayúscula" in errores
    assert "falta un número" in errores

"""Verificar que una contraseña con solo números detecta la falta de mayúscula."""

def test_validate_password_solo_numeros():
    errores = validate_password("12345678")
    assert len(errores) == 1
    assert "falta una mayúscula" in errores