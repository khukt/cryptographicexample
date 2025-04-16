import streamlit as st
import hashlib
import random

st.set_page_config(page_title="Cryptographic Algorithms Explorer", layout="centered")
st.title("🔐 Cryptographic Algorithms Interactive Demo")

algo = st.sidebar.selectbox("Choose an Algorithm to Explore:", [
    "Block Cipher (Caesar Shift)",
    "Stream Cipher (XOR)",
    "Hash Function",
    "MAC (HMAC Simulation)",
    "Diffie-Hellman Key Exchange",
    "RSA Encryption (Simplified)",
    "ElGamal Digital Signature (Conceptual)"
])

# BLOCK CIPHER
if algo == "Block Cipher (Caesar Shift)":
    st.subheader("Block Cipher - Caesar Shift")
    message = st.text_input("Enter message (A-Z only):", "HELLOCRYPTO")
    shift = st.slider("Shift value:", 1, 25, 3)
    block_size = st.slider("Block size:", 1, 6, 4)

    def caesar_block(text, shift):
        return ''.join(chr((ord(c) - 65 + shift) % 26 + 65) for c in text.upper() if c.isalpha())

    blocks = [message[i:i+block_size] for i in range(0, len(message), block_size)]
    encrypted = [caesar_block(b, shift) for b in blocks]
    st.code(f"Blocks: {blocks}\nEncrypted: {encrypted}")

# STREAM CIPHER
elif algo == "Stream Cipher (XOR)":
    st.subheader("Stream Cipher - XOR")
    text = st.text_input("Enter a binary message (e.g. 101010):", "101010")
    key = ''.join(random.choice('01') for _ in text)
    st.text(f"Random Key: {key}")
    xor = ''.join(str(int(text[i]) ^ int(key[i])) for i in range(len(text)))
    st.code(f"Ciphertext: {xor}")

# HASHING
elif algo == "Hash Function":
    st.subheader("Hash Function")
    text = st.text_input("Enter text to hash:", "hello")
    sha = hashlib.sha256(text.encode()).hexdigest()
    st.code(f"SHA-256: {sha}")

# MAC (SIMULATION)
elif algo == "MAC (HMAC Simulation)":
    st.subheader("MAC - Message Authentication Code")
    message = st.text_input("Message:", "GRADE=100")
    secret = st.text_input("Shared Secret Key:", "42")
    hmac_input = message + secret
    mac = hashlib.sha256(hmac_input.encode()).hexdigest()
    st.code(f"MAC: {mac}")

# DIFFIE-HELLMAN
elif algo == "Diffie-Hellman Key Exchange":
    st.subheader("Diffie-Hellman Key Exchange")
    p = st.number_input("Prime (p):", min_value=5, value=23)
    g = st.number_input("Base (g):", min_value=2, value=5)
    a = st.slider("Alice's Private Key (a):", 1, 20, 6)
    b = st.slider("Bob's Private Key (b):", 1, 20, 15)

    A = pow(g, a, p)
    B = pow(g, b, p)
    shared_A = pow(B, a, p)
    shared_B = pow(A, b, p)
    st.code(f"Alice sends: {A}, Bob sends: {B}\nShared Secret (Alice): {shared_A}, Shared Secret (Bob): {shared_B}")

# RSA
elif algo == "RSA Encryption (Simplified)":
    st.subheader("RSA (Simplified Demo)")
    p = 17
    q = 11
    n = p * q
    phi = (p-1)*(q-1)
    e = 7
    d = 23  # Precomputed for demo

    m = st.number_input("Enter message as a number (m < n):", min_value=0, max_value=n-1, value=8)
    enc = pow(m, e, n)
    dec = pow(enc, d, n)
    st.code(f"Public Key: (e={e}, n={n}), Private Key: (d={d})\nEncrypted: {enc}, Decrypted: {dec}")

# ELGAMAL SIGNATURE (Conceptual)
elif algo == "ElGamal Digital Signature (Conceptual)":
    st.subheader("ElGamal Signature - Conceptual View")
    st.markdown("This section gives a high-level idea of how ElGamal signatures work:")
    st.markdown("1. Generate keys using Diffie-Hellman setup.")
    st.markdown("2. Sign message using private key + random value.")
    st.markdown("3. Verify using public key and signature.")
    st.info("Real implementation is complex and uses modular arithmetic. This is just a concept preview.")
