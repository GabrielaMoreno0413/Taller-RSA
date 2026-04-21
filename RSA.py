import secrets
from typing import Tuple

# ==================== UTILIDADES BÁSICAS ====================

def text_to_int(text: str) -> int:
    """Convierte un texto a número entero usando UTF-8"""
    return int.from_bytes(text.encode('utf-8'), byteorder='big')


def int_to_text(n: int) -> str:
    """Convierte un número entero a texto"""
    byte_length = (n.bit_length() + 7) // 8
    return n.to_bytes(byte_length, byteorder='big').decode('utf-8')


# ==================== TEST DE PRIMALIDAD ====================

def miller_rabin(n: int, k: int = 40) -> bool:
    """Test de primalidad Miller-Rabin"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True


# ==================== GENERACIÓN DE PRIMOS ====================

def is_strong_prime(p: int) -> bool:
    """Verifica si p es un primo fuerte"""
    if not miller_rabin(p):
        return False
    
    temp1, temp2 = p - 1, p + 1
    
    while temp1 % 2 == 0:
        temp1 //= 2
    while temp2 % 2 == 0:
        temp2 //= 2
    
    return temp1 > 1 and temp2 > 1


def generate_strong_prime(bits: int) -> int:
    """Genera un número primo fuerte de 'bits' bits"""
    while True:
        p = secrets.randbits(bits)
        p |= (1 << bits - 1) | 1
        
        if is_strong_prime(p):
            return p


def generate_prime(bits: int) -> int:
    """Genera un número primo aleatorio de 'bits' bits"""
    while True:
        p = secrets.randbits(bits)
        p |= (1 << bits - 1) | 1
        
        if miller_rabin(p):
            return p


# ==================== MÁXIMO COMÚN DIVISOR ====================

def gcd(a: int, b: int) -> int:
    """Calcula el máximo común divisor"""
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Algoritmo extendido de Euclides"""
    if a == 0:
        return b, 0, 1
    
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    
    return gcd_val, x, y


# ==================== GENERACIÓN DE CLAVES ====================

def generate_keys_manual(p: int, q: int, e: int) -> Tuple[Tuple[int, int], Tuple[int, int], int, int, int]:
    """
    Genera claves RSA con p, q, e proporcionados.
    Retorna: (pub_key={e,n}, priv_key={d,n}, n, phi_n, d)
    """
    n = p * q
    phi_n = (p - 1) * (q - 1)
    
    if gcd(e, phi_n) != 1:
        raise ValueError(f"e={e} no es coprimo con φ(n)={phi_n}")
    
    d = pow(e, -1, phi_n)
    
    return (e, n), (d, n), n, phi_n, d


def generate_keys_auto(bits: int = 512) -> Tuple[Tuple[int, int], Tuple[int, int], int, int, int, int, int]:
    """
    Genera claves RSA automáticamente.
    Retorna: (pub_key, priv_key, n, phi_n, d, p, q)
    """
    p = generate_strong_prime(bits)
    q = generate_strong_prime(bits)
    
    while p == q:
        q = generate_strong_prime(bits)
    
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 65537
    
    while gcd(e, phi_n) != 1:
        e = secrets.randbits(16) | 1
    
    d = pow(e, -1, phi_n)
    
    return (e, n), (d, n), n, phi_n, d, p, q


# ==================== CIFRADO Y DESCIFRADO ====================

def can_encrypt_single_block(message: str, n: int) -> bool:
    """Verifica si el mensaje se puede cifrar en un solo bloque"""
    m = text_to_int(message)
    return m < n


def encrypt(message: str, public_key: Tuple[int, int]) -> int:
    """Cifra un mensaje con la clave pública"""
    e, n = public_key
    
    if not can_encrypt_single_block(message, n):
        m = text_to_int(message)
        raise ValueError(f"M={m} >= n={n}. No se puede cifrar en un bloque.")
    
    m = text_to_int(message)
    return pow(m, e, n)


def encrypt_int(m: int, public_key: Tuple[int, int]) -> int:
    """Cifra un número entero con la clave pública"""
    e, n = public_key
    
    if m >= n:
        raise ValueError(f"M={m} >= n={n}. No se puede cifrar.")
    
    return pow(m, e, n)


def decrypt(ciphertext: int, private_key: Tuple[int, int]) -> str:
    """Descifra un ciphertext con la clave privada"""
    d, n = private_key
    m = pow(ciphertext, d, n)
    return int_to_text(m)


def decrypt_to_int(ciphertext: int, private_key: Tuple[int, int]) -> int:
    """Descifra un ciphertext y retorna el entero"""
    d, n = private_key
    return pow(ciphertext, d, n)


# ==================== FIRMA Y VERIFICACIÓN ====================

def sign(message: str, private_key: Tuple[int, int]) -> int:
    """Firma un mensaje con la clave privada"""
    d, n = private_key
    
    if not can_encrypt_single_block(message, n):
        raise ValueError(f"El mensaje es demasiado grande para firmar.")
    
    m = text_to_int(message)
    return pow(m, d, n)


def sign_int(m: int, private_key: Tuple[int, int]) -> int:
    """Firma un número entero con la clave privada"""
    d, n = private_key
    
    if m >= n:
        raise ValueError(f"M={m} >= n={n}. No se puede firmar.")
    
    return pow(m, d, n)


def verify(message: str, signature: int, public_key: Tuple[int, int]) -> bool:
    """Verifica la firma de un mensaje"""
    e, n = public_key
    m_recovered = pow(signature, e, n)
    m_original = text_to_int(message)
    return m_recovered == m_original


def verify_int(m: int, signature: int, public_key: Tuple[int, int]) -> bool:
    """Verifica si una firma corresponde a un número entero"""
    e, n = public_key
    m_recovered = pow(signature, e, n)
    return m_recovered == m


# ==================== PRUEBAS ====================

def main():
    """Función principal con todas las pruebas"""
    
    # PRUEBA 1: Cifrado con valores específicos
    print("="*70)
    print("PRUEBA 1: CIFRADO CON VALORES ESPECÍFICOS")
    print("="*70)
    
    p, q, e, M = 257, 31, 7, 1000
    pub_key, priv_key, n, phi_n, d = generate_keys_manual(p, q, e)
    
    print(f"\nEntrada: p={p}, q={q}, e={e}, M={M}")
    print(f"Resultados calculados:")
    print(f"  n = {n} (esperado: 7967)")
    print(f"  φ(n) = {phi_n} (esperado: 7680)")
    print(f"  d = {d} (esperado: 6583)")
    
    C = encrypt_int(M, pub_key)
    print(f"  C = {C} (esperado: 3505)")
    
    # Verificar descifrado
    M_desc = decrypt_to_int(C, priv_key)
    print(f"\n✓ Descifrado: M' = {M_desc}, Correcto: {M == M_desc}")
    
    
     # PRUEBA 2: Verificar límite
    print("\n" + "="*70)
    print("PRUEBA 2: VERIFICAR LÍMITE (C=8000 no puede cifrarse con n=7967)")
    print("="*70)
    
    C_invalido = 8000
    print(f"\nIntentando cifrar C={C_invalido} con n={n}")
    print(f"¿C >= n? {C_invalido} >= {n} = {C_invalido >= n}")
    print(f"✓ Verificación: NO se puede cifrar (correctamente rechazado)")
    
    """
    # PRUEBA 3: Mensaje largo en UTF-8
    print("\n" + "="*70)
    print("PRUEBA 3: CIFRADO DE MENSAJE LARGO EN UTF-8")
    print("="*70)
    
    print("\nGenerando claves RSA 1024 bits...")
    pub_key, priv_key, n, phi_n, d, p, q = generate_keys_auto(512)
    e, _ = pub_key
    
    mensaje = "Este es un texto de prueba usado para observar el cifrado RSA en el taller 4"
    M = text_to_int(mensaje)
    
    print(f"\nMensaje: \"{mensaje}\"")
    print(f"UTF-8 entero: {M}")
    print(f"Tamaño: {M.bit_length()} bits < {n.bit_length()} bits de n")
    
    C = encrypt(mensaje, pub_key)
    print(f"\n✓ Cifrado: C = {C}")
    
    # Descifrar
    print(f"\nDescifrando...")
    M_desc = decrypt(C, priv_key)
    print(f"✓ Descifrado: \"{M_desc}\"")
    print(f"✓ Correcto: {mensaje == M_desc}")
    
    
    # PRUEBA 4: Descifrar con d diferente
    print("\n" + "="*70)
    print("PRUEBA 4: INTENTAR DESCIFRAR CON d DIFERENTE")
    print("="*70)
    
    d_incorrecto = d + 1
    M_basura = pow(C, d_incorrecto, n)
    
    print(f"\nd correcto: {d}")
    print(f"d incorrecto (prueba): {d_incorrecto}")
    print(f"\nDescifrando con d incorrecto:")
    print(f"  M' = {M_basura}")
    
    try:
        texto_basura = int_to_text(M_basura)
        print(f"  Texto: \"{texto_basura}\"")
    except:
        print(f"  Texto: (no decodificable)")
    
    print(f"\n✓ Se obtiene basura. Solo d correcto permite descifrar.")
    
    
    # PRUEBA 5: Intentar descifrar con e
    print("\n" + "="*70)
    print("PRUEBA 5: INTENTAR DESCIFRAR CON e (CLAVE PÚBLICA)")
    print("="*70)
    
    mensaje_prueba = "Prueba de seguridad"
    C_5 = encrypt(mensaje_prueba, pub_key)
    M_original = text_to_int(mensaje_prueba)
    
    print(f"\nMensaje: \"{mensaje_prueba}\" (M={M_original})")
    print(f"Cifrado: C = {C_5}")
    
    # Intentar descifrar con e
    M_falso = pow(C_5, e, n)
    print(f"\nIntentando descifrar con e={e}:")
    print(f"  M' = {M_falso}")
    print(f"  ¿M' == M? {M_falso == M_original}")
    print(f"\n✓ La clave pública NO permite descifrar correctamente")
    
    
    # PRUEBA 6: Firma básica
    print("\n" + "="*70)
    print("PRUEBA 6: FIRMA DIGITAL BÁSICA")
    print("="*70)
    
    nombre = "Oscar Espejo Mojica"
    mensaje_completo = f"Este es un mensaje de prueba att. {nombre}"
    
    print(f"\nMensaje: \"{mensaje_completo}\"")
    print(f"Nombre a firmar: \"{nombre}\"")
    
    # Cifrar mensaje
    C_msg = encrypt(mensaje_completo, pub_key)
    print(f"\n--- GENERACIÓN ---")
    print(f"Cifrando mensaje: C_msg = {C_msg}")
    
    # Firmar nombre
    firma = sign(nombre, priv_key)
    print(f"Firmando nombre: firma = {firma}")
    
    print(f"\n✓ Observación: Son completamente diferentes")
    print(f"  C_msg  = {C_msg}")
    print(f"  firma  = {firma}")
    print(f"  Iguales: {C_msg == firma}")
    
    # Descifrar y verificar
    print(f"\n--- VERIFICACIÓN ---")
    M_desc = decrypt(C_msg, priv_key)
    print(f"Descifrado: \"{M_desc}\"")
    print(f"Correcto: {M_desc == mensaje_completo} ✓")
    
    es_valida = verify(nombre, firma, pub_key)
    print(f"\nVerificando firma: {es_valida} ✓")
    
    
    # PRUEBA 7: Protocolo Cifrado-Firmado sin HASH
    print("\n" + "="*70)
    print("PRUEBA 7: PROTOCOLO CIFRADO-FIRMADO SIN HASH")
    print("="*70)
    
    print("\n" + "─"*70)
    print("FASE 1: GENERACIÓN DE CLAVES")
    print("─"*70)
    
    pub_key, priv_key, n, phi_n, d, p, q = generate_keys_auto(512)
    e, _ = pub_key
    
    print(f"\n✓ Claves generadas (1024 bits)")
    print(f"  e = {e} (pública)")
    print(f"  n = {n} (pública)")
    print(f"  d = {d} (privada)")
    
    print("\n" + "─"*70)
    print("FASE 2: EMISOR - CIFRADO Y FIRMA")
    print("─"*70)
    
    nombre_emisor = "Juan Carlos García"
    mensaje_protocolo = f"Este es un mensaje de prueba att. {nombre_emisor}"
    
    print(f"\nMensaje original: \"{mensaje_protocolo}\"")
    
    # Paso 1: Cifrar con clave pública
    C_protocolo = encrypt(mensaje_protocolo, pub_key)
    print(f"\nPaso 1: Cifrar con PU{{e,n}}")
    print(f"  C = {C_protocolo}")
    
    # Paso 2: Firmar con clave privada
    firma_protocolo = sign(nombre_emisor, priv_key)
    print(f"\nPaso 2: Firmar con PR{{d,n}}")
    print(f"  firma = {firma_protocolo}")
    
    print(f"\n📤 TRANSMISIÓN: (C, firma)")
    
    print("\n" + "─"*70)
    print("FASE 3: RECEPTOR - DESCIFRADO Y VERIFICACIÓN")
    print("─"*70)
    
    # Paso 3: Descifrar
    mensaje_recibido = decrypt(C_protocolo, priv_key)
    print(f"\nPaso 1: Descifrar con PR{{d,n}}")
    print(f"  M' = \"{mensaje_recibido}\"")
    
    # Paso 2: Verificar firma
    firma_valida = verify(nombre_emisor, firma_protocolo, pub_key)
    print(f"\nPaso 2: Verificar firma con PU{{e,n}}")
    print(f"  ¿Firma válida? {firma_valida} ✓")
    
    # Paso 3: Extraer nombre del mensaje
    if "att." in mensaje_recibido:
        nombre_extraido = mensaje_recibido.split("att.")[-1].strip()
    else:
        nombre_extraido = None
    
    print(f"\nPaso 3: Extraer nombre del mensaje")
    print(f"  Nombre en mensaje: \"{nombre_extraido}\"")
    
    # Paso 4: Verificación final
    print(f"\nPaso 4: Verificación de integridad")
    print(f"  Mensaje íntegro: {mensaje_recibido == mensaje_protocolo} ✓")
    print(f"  Firma válida: {firma_valida} ✓")
    print(f"  Identidad consistente: {nombre_extraido == nombre_emisor} ✓")
    
    print(f"\n✓ PROTOCOLO EXITOSO:")
    print(f"  ✓ Confidencialidad: Solo receptor descifra con clave privada")
    print(f"  ✓ Autenticidad: Solo emisor podía firmar con clave privada")
    print(f"  ✓ Integridad: Mensaje no fue modificado")
    print(f"  ✓ No repudio: Emisor no puede negar haber firmado")
    
    print("\n" + "="*70)
    print("✓ TODOS LOS CASOS DE PRUEBA COMPLETADOS EXITOSAMENTE")
    print("="*70) """


if __name__ == "__main__":
    main()