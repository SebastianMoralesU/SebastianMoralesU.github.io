from flask import Flask, render_template, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib

Encriptacion = Flask(__name__)

# Cifrar con AES
def cifrar_aes(texto, clave):
    
    clave_bytes = hashlib.sha256(clave.encode()).digest()  # Clave de 32 bytes
    cipher = AES.new(clave_bytes, AES.MODE_CBC)  
    
    texto_bytes = texto.encode('utf-8')
    texto_cifrado = cipher.encrypt(pad(texto_bytes, AES.block_size))
    
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    texto_cifrado = base64.b64encode(texto_cifrado).decode('utf-8')
    return iv, texto_cifrado

# Descifrar con AES
def descifrar_aes(texto_cifrado, clave, iv):
    clave_bytes = hashlib.sha256(clave.encode()).digest()  # Clave de 32 bytes
    iv_bytes = base64.b64decode(iv)  
    texto_cifrado_bytes = base64.b64decode(texto_cifrado) 
    cipher = AES.new(clave_bytes, AES.MODE_CBC, iv_bytes)
    texto_descifrado = unpad(cipher.decrypt(texto_cifrado_bytes), AES.block_size)
    return texto_descifrado.decode('utf-8')

# Ruta principal
@Encriptacion.route('/')
def index():
    return render_template('Encriptacion.html', texto_cifrado="", texto_descifrado="", 
                           usuario="", mensaje="", clave="", usuario_cifrado="", usuario_descifrado="", 
                           clave_cifrada="", clave_descifrada="")

# Ruta para cifrar el mensaje
@Encriptacion.route('/cifrar', methods=['POST'])
def cifrar():
    # Obtener los valores del formulario
    usuario = request.form['usuario']
    texto_original = request.form['mensaje']
    clave = request.form['clave']

    # Cifrar el mensaje
    iv, texto_cifrado = cifrar_aes(texto_original, clave)
    # Descifrar el mensaje
    texto_descifrado = descifrar_aes(texto_cifrado, clave, iv)

    # Cifrar el usuario
    iv_usuario, usuario_cifrado = cifrar_aes(usuario, clave)
    usuario_descifrado = descifrar_aes(usuario_cifrado, clave, iv_usuario)

    # Cifrar la clave (contraseña)
    iv_clave, clave_cifrada = cifrar_aes(clave, clave)
    clave_descifrada = descifrar_aes(clave_cifrada, clave, iv_clave)

    # Pasar los resultados a la plantilla
    return render_template('Encriptacion.html', 
                           texto_cifrado=texto_cifrado, 
                           texto_descifrado=texto_descifrado,
                           usuario=usuario, 
                           mensaje=texto_original, 
                           clave=clave,
                           usuario_cifrado=usuario_cifrado, 
                           usuario_descifrado=usuario_descifrado,
                           clave_cifrada=clave_cifrada, 
                           clave_descifrada=clave_descifrada,
                           iv_usuario=iv_usuario, iv_clave=iv_clave, iv=iv)

if __name__ == '__main__':
    Encriptacion.run(debug=True)
