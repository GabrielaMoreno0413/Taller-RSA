from RSA import *
import time
import random

# ================================
# FUNCIÓN PKCS1
# ================================

def pkcs1_pad(mensaje_bytes, longitud_modulo_bytes):
    payload_len = len(mensaje_bytes)
    pad_len = longitud_modulo_bytes - 3 - payload_len
    
    if pad_len < 8:
        raise ValueError("Mensaje demasiado largo")
    
    relleno = bytes([0x00, 0x02])
    
    while len(relleno) < 2 + pad_len:
        b = random.randint(1, 255)
        if b != 0:
            relleno += bytes([b])
    
    relleno += bytes([0x00])
    return relleno + mensaje_bytes


# ================================
# INICIO
# ================================

print("\n" + "="*70)
print("Parte 3" )
print("="*70)

M = 1234
print(f"\nMensaje original: {M}")

# Generar claves (1024 bits)
pub, priv, n, phi, d, p, q = generate_keys_auto(512)
e, _ = pub

print("\nClaves generadas:")
print(f"e = {e}")
print(f"n (bits) = {n.bit_length()}")


# ================================
#  1: SIN PADDING
# ================================

print("\n" + "-"*70)
print(" EJERCICIO 1. SIN PADDING")
print("-"*70)

# Cifrar directamente
C = encrypt_int(M, pub)
print(f"\nCifrado de M={M} → C={C}")

# Ataque
print("\nIniciando ataque por fuerza bruta (0 - 9999)...")

inicio = time.time()
intentos = 0
M_encontrado = None

for intento in range(0, 10000):
    intentos += 1
    if encrypt_int(intento, pub) == C:
        M_encontrado = intento
        break

tiempo = time.time() - inicio

print("\nRESULTADO:")
print(f"Mensaje encontrado: {M_encontrado}")
print(f"¿Correcto?: {M_encontrado == M}")
print(f"Intentos realizados: {intentos}")
print(f"Tiempo: {tiempo:.6f} segundos")

print("\n CONCLUSIÓN: El mensaje fue encontrado fácilmente (inseguro)")


# ================================
# 2: CON PADDING PKCS1
# ================================

print("\n" + "-"*70)
print("EJERCICIO 2. CON PADDING PKCS1")
print("-"*70)

# Convertir a bytes
mensaje_bytes = M.to_bytes((M.bit_length() + 7) // 8, byteorder='big')

# Longitud del módulo en bytes
longitud_modulo_bytes = (n.bit_length() + 7) // 8

# Aplicar padding (no se muestra)
mensaje_padded = pkcs1_pad(mensaje_bytes, longitud_modulo_bytes)

# Convertir a entero
M_pad = int.from_bytes(mensaje_padded, byteorder='big')

print("\nMensaje original:", M)
print("Mensaje protegido con padding (oculto por seguridad)")

# Cifrar
C_pad = encrypt_int(M_pad, pub)
print(f"\nCifrado con padding → C={C_pad}")

# Ataque nuevamente
print("\nIntentando ataque por fuerza bruta (0 - 9999)...")

inicio = time.time()
intentos = 0
M_encontrado_pad = None

for intento in range(0, 10000):
    intentos += 1
    if encrypt_int(intento, pub) == C_pad:
        M_encontrado_pad = intento
        break

tiempo = time.time() - inicio

print("\nRESULTADO:")
print(f"Mensaje encontrado: {M_encontrado_pad}")
print(f"Intentos realizados: {intentos}")
print(f"Tiempo: {tiempo:.6f} segundos")

if M_encontrado_pad is None:
    print("\n CONCLUSIÓN: No fue posible recuperar el mensaje (seguro)")
else:
    print("\n CONCLUSIÓN: El mensaje fue encontrado (inseguro)")
