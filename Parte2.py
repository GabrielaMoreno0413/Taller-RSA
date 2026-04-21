from RSA import *

print("="*60)
print("EJERCICIO 1. CLAVES PRIVADAS PAREJAS")
print("="*60)

# Datos
p = 61
q = 53
e = 17

# Generar claves
pub, priv, n, phi, d = generate_keys_manual(p, q, e)

print("\nValores base:")
print("n =", n)
print("phi =", phi)
print("d original =", d)

# Mensaje de prueba
M = 123
C = encrypt_int(M, pub)

print("\nMensaje de prueba:", M)
print("Cifrado:", C)

print("\nClaves privadas parejas y prueba de descifrado:\n")

for k in range(1, 4):
    d_pareja = d + k * phi
    M_desc = pow(C, d_pareja, n)

    print(f"k = {k}")
    print(f"d' = {d_pareja}")
    print("Descifrado:", M_desc)
    print("¿Funciona?", M_desc == M)
    print("-"*40)


print("="*60)
print("EJERCICIO 2. NÚMEROS NO CIFRABLES")
print("="*60)

# Datos
p = 61
q = 53
e = 17

# Generar claves
pub, priv, n, phi, d = generate_keys_manual(p, q, e)

print("\nBuscando números no cifrables...\n")

no_cifrables = []

for M in range(0, n):
    C = encrypt_int(M, pub)
    
    if C == M:
        no_cifrables.append(M)

print("Números no cifrables encontrados:")
print(no_cifrables)
print("\nCantidad:", len(no_cifrables))