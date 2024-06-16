import secrets as sc
from tinyec import registry
from tkinter import *
from tkinter import ttk
import base64
CURVA = registry.get_curve('secp192r1')
def regenerate_keys():
    global keys
    keys = generate_keys()
    privKeyEntry.config(state="normal")
    pubKeyEntry.config(state="normal")
    privKeyEntry.delete(0, END)
    pubKeyEntry.delete(0, END)
    privKeyEntry.insert(0, str(keys[0])[2:])
    pubKeyEntry.insert(0, keys[2])
    privKeyEntry.config(state="readonly")
    pubKeyEntry.config(state="readonly")

def generate_keys():
    clavePriv = sc.randbelow(CURVA.field.n)
    clavePub = clavePriv * CURVA.g
    comClavePub = '0' + str(2 + clavePub.y % 2) + str(hex(clavePub.x)[2:])
    return clavePriv, clavePub, comClavePub

def generate_dynamic_privk():
    global cifradoClavePriv
    cifradoClavePriv = sc.randbelow(CURVA.field.n)
    t1.delete("1.0", END)
    t2.delete("1.0", END)

def xor_simple(data, clave):
    return bytes(a ^ b for a, b in zip(data, clave))

def enkryptar(msg):
    global secreto
    claveKompartida = cifradoClavePriv * pubClave
    claveKompartidaB = claveKompartida.x.to_bytes((claveKompartida.x.bit_length() + 7) // 8, 'big')
    ciphertxt = xor_simple(msg, claveKompartidaB)
    secreto = cifradoClavePriv * CURVA.g
    return ciphertxt

def desenkryptar(cMsg):
    cTxt = cMsg
    claveKompartida = privClave * secreto
    claveKompartidaB = claveKompartida.x.to_bytes((claveKompartida.x.bit_length() + 7) // 8, 'big')
    plaintext = xor_simple(cTxt, claveKompartidaB)
    return plaintext
def procesar_text1(event=None):
    txt = t1.get("1.0", END).strip()
    txt_output = enkryptar(txt.encode("utf-8"))
    txt_output_b = base64.b64encode(txt_output)
    t2.delete("1.0", END)
    t2.insert("1.0", txt_output_b.decode("utf-8"))
def procesar_text2(event=None):
    txt = t2.get("1.0", END).strip()
    txt_output = desenkryptar(txt.encode("utf-8"))
    txt_output_b = base64.b64encode(txt_output)
    t1.delete("1.0", END)
    t1.insert("1.0", txt_output_b.decode("utf-8"))

root = Tk()
root.title("Feet to Meters")
root.resizable(False, False)

mainframe = ttk.Frame(root, padding="3 3 12 12")
keys_frame = ttk.Frame(root)

keys = generate_keys()
privClave = keys[0]
privKey_as_hex = str(hex(keys[0]))[2:]
pubClave = keys[1]
cifradoClavePriv = sc.randbelow(CURVA.field.n)
secreto = ''


mainframe.grid(column=0, row=1, sticky=(N, W, E, S))
keys_frame.grid(column=0, row=0, sticky=(N, W, E, S))

root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

t1 = Text(mainframe, width=39, height=20, wrap="char")
t2 = Text(mainframe, width=39, height=20, wrap="char")

privKeylbl = ttk.Label(keys_frame, text="Clave privada:")
pubKeylbl = ttk.Label(keys_frame, text="Clave pública:")
cifradoSimetrico = ttk.Label(keys_frame, text="Cifrado simétrico:")
privKeyEntry = ttk.Entry(keys_frame, width=len(str(privKey_as_hex)))
pubKeyEntry = ttk.Entry(keys_frame, width=len(str(keys[2])))

privKeyEntry.insert(0, privKey_as_hex)
privKeyEntry.config(state='readonly')

pubKeyEntry.insert(0, keys[2])
pubKeyEntry.config(state='readonly')

ttk.Button(keys_frame, text="Generar par", command=regenerate_keys).grid(column=2, row=0, sticky=W, padx=10, pady=(5, 0))
ttk.Button(keys_frame, text="Nueva clave dinámica", command=generate_dynamic_privk).grid(column=2, row=1, sticky=W, padx=10)


t1.grid(column=0, row=0, padx=(20, 0), pady=15, sticky=(E, S))
t2.grid(column=1, row=0, padx=20, pady=15, sticky=(W, S))

privKeylbl.grid(column=0, row=0, sticky=S, padx=20, pady=10)
pubKeylbl.grid(column=0, row=1, sticky=N, padx=20)
cifradoSimetrico.grid(column=0, row=2, sticky=W, padx=20, pady=(4,0), columnspan=2)

privKeyEntry.grid(column=1, row=0, sticky=W)
pubKeyEntry.grid(column=1, row=1, sticky=(N, W))

t1.bind("<KeyRelease>", procesar_text1)
t2.bind("<KeyRelease>", procesar_text2)

root.mainloop()