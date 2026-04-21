from RSA import *

# ================================
# EJERCICIO 1
# ================================

print("=== EJERCICIO 1 ===")

p = 257
q = 31
e = 7
M = 1000

# Generar claves
pub, priv, n, phi, d = generate_keys_manual(p, q, e)

print("\nResultados:")
print("n =", n)
print("phi =", phi)
print("d =", d)

# Cifrado
C = encrypt_int(M, pub)
print("C =", C)

# Descifrado
M_desc = decrypt_to_int(C, priv)
print("M descifrado =", M_desc)

# ================================
# EJERCICIO 2 (VALIDACIÓN)
# ================================

print("\n=== EJERCICIO 2 ===")

M_invalido = 8000

print("\nProbando valor inválido:")
print("M =", M_invalido)
print("n =", n)
print("¿M >= n?", M_invalido >= n)

try:
    C_test = encrypt_int(M_invalido, pub)
    print("Cifrado:", C_test)
except ValueError as e:
    print("Error:", e)

# ================================
# EJERCICIO 3 (TEXTO UTF-8)
# ================================

print("\n=== EJERCICIO 3 ===")

mensaje = "Este es un texto de prueba usado para observar el cifrado RSA en el taller 4"

print("\nMensaje original:")
print(mensaje)

# Generar claves automáticamente (1024 bits)
print("\nGenerando claves RSA...")
pub, priv, n, phi, d, p, q = generate_keys_auto(512)  # 512 + 512 = 1024 bits

e, _ = pub

print("\nClave pública (e, n):", pub)
print("Clave privada (d, n):", priv)

# Convertir a entero (UTF-8)
M = text_to_int(mensaje)
print("\nMensaje en entero (UTF-8):")
print(M)

print("\nTamaño del mensaje:", M.bit_length(), "bits")
print("Tamaño de n:", n.bit_length(), "bits")

# Verificar si se puede cifrar
if not can_encrypt_single_block(mensaje, n):
    print("\n El mensaje es demasiado grande para un solo bloque")
else:
    # Cifrar
    C = encrypt(mensaje, pub)
    print("\nCifrado:")
    print(C)

    # Descifrar
    M_desc = decrypt(C, priv)
    print("\nDescifrado:")
    print(M_desc)

    print("\n¿Coincide con el original?", mensaje == M_desc)

# ================================
# EJERCICIO 4 - DESCIFRADO COMPLETO
# ================================

print("\n=== EJERCICIO 4 ===")

# Ya tenemos C del ejercicio 3
print("\nDescifrando con clave privada correcta...")

M_desc = decrypt(C, priv)

print("Mensaje descifrado:")
print(M_desc)

print("¿Coincide con el original?", M_desc == mensaje)


# ================================
# EJERCICIO 5 - d INCORRECTO
# ================================

print("\n=== EJERCICIO 5 ===")

d_incorrecto = d + 1  # alterar d
priv_falsa = (d_incorrecto, n)

print("\nd correcto:", d)
print("d incorrecto:", d_incorrecto)

print("\nIntentando descifrar con d incorrecto...")

M_falso = pow(C, d_incorrecto, n)

print("Resultado numérico:", M_falso)

try:
    texto_falso = int_to_text(M_falso)
    print("Texto obtenido:", texto_falso)
except:
    print("Texto no decodificable (basura)")

print("\nConclusión: No se puede descifrar correctamente con un d incorrecto")


# ================================
# EJERCICIO 6 - USAR e PARA DESCIFRAR
# ================================

print("\n=== EJERCICIO 6 ===")

e, _ = pub

print("\nIntentando descifrar con clave pública (e)...")

M_publico = pow(C, e, n)

print("Resultado numérico:", M_publico)

try:
    texto_publico = int_to_text(M_publico)
    print("Texto obtenido:", texto_publico)
except:
    print("Texto no decodificable (basura)")

print("\n¿Coincide con el mensaje original?", M_publico == text_to_int(mensaje))

print("\nConclusión: NO se puede descifrar con la clave pública")

# ================================
# FIRMA DIGITAL
# ================================

print("\n" + "="*70)
print("SECCIÓN DE FIRMADO")
print("="*70)

# 1. Mensaje completo
mensaje = "Este es un mensaje de prueba att. Gabriela y Diego"
nombre = "Gabriela y Diego"

print("\nMensaje completo:")
print(mensaje)

print("\nNombre a firmar:")
print(nombre)

# Generar claves RSA (1024 bits)
print("\nGenerando claves...")
pub, priv, n, phi, d, p, q = generate_keys_auto(512)

# ================================
# 1. CIFRAR MENSAJE
# ================================

C_msg = encrypt(mensaje, pub)
print("\nMensaje cifrado:")
print(C_msg)

# ================================
# 2. FIRMAR (con clave privada)
# ================================

firma = sign(nombre, priv)
print("\nFirma (nombre firmado con clave privada):")
print(firma)

# ================================
# 3. COMPARACIÓN
# ================================

print("\nComparación:")
print("Mensaje cifrado:", C_msg)
print("Firma:", firma)
print("¿Son iguales?", C_msg == firma)

# ================================
# 4. VERIFICACIÓN
# ================================

print("\n=== VERIFICACIÓN ===")

# Descifrar mensaje
mensaje_desc = decrypt(C_msg, priv)
print("\nMensaje descifrado:")
print(mensaje_desc)

# Verificar firma
es_valida = verify(nombre, firma, pub)
print("\n¿Firma válida?", es_valida)

# ================================
# 5. PROTOCOLO SIN HASH
# ================================

print("\n" + "="*70)
print("PROTOCOLO CIFRADO-FIRMADO (SIN HASH)")
print("="*70)

# EMISOR
print("\n--- EMISOR ---")

mensaje_envio = "Este es un mensaje de prueba att. Gabriela y Diego"
nombre_envio = "Gabriela y Diego"

# Cifrar mensaje
C = encrypt(mensaje_envio, pub)
print("Mensaje cifrado:", C)

# Firmar nombre
firma_envio = sign(nombre_envio, priv)
print("Firma:", firma_envio)

print("\nSe envía: (C, firma)")

# RECEPTOR
print("\n--- RECEPTOR ---")

# Descifrar mensaje
mensaje_recibido = decrypt(C, priv)
print("Mensaje recibido:", mensaje_recibido)

# Verificar firma
firma_valida = verify(nombre_envio, firma_envio, pub)
print("¿Firma válida?", firma_valida)

# Extraer nombre del mensaje
nombre_extraido = mensaje_recibido.split("att.")[-1].strip()

print("\nNombre extraído:", nombre_extraido)
print("¿Coincide con el firmado?", nombre_extraido == nombre_envio)

# Validación final
print("\nValidaciones finales:")
print("Mensaje íntegro:", mensaje_recibido == mensaje_envio)
print("Firma válida:", firma_valida)
print("Identidad correcta:", nombre_extraido == nombre_envio)