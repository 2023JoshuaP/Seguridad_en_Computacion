import tkinter as tk
from tkinter import messagebox, filedialog

def decrypt(cipher_text, group_size, permutation):
    inverse = [0] * group_size
    for i, p in enumerate(permutation):
        inverse[p-1] = i + 1

    blocks = cipher_text.replace(" ", "").strip()
    result = []

    for i in range(0, len(blocks), group_size):
        block = blocks[i:i+group_size]
        if len(block) < group_size:
            continue
        new_block = "".join(block[inverse[j]-1] for j in range(group_size))
        result.append(new_block)

    return "".join(result)

def run_decryption():
    text = input_text.get("1.0", tk.END).strip().upper()

    try:
        group_size = int(entry_group.get())
    except ValueError:
        messagebox.showerror("Error", "El tamaño del grupo debe ser un número entero.")
        return

    try:
        perm = list(map(int, entry_permutation.get().split()))
    except ValueError:
        messagebox.showerror("Error", "La permutación debe contener solo números separados por espacio.")
        return

    if sorted(perm) != list(range(1, group_size+1)):
        messagebox.showerror("Error", f"La permutación debe ser una reordenación de 1 a {group_size}.")
        return

    decrypted_text = decrypt(text, group_size, perm)

    output_text.config(state="normal")
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, decrypted_text)
    output_text.config(state="disabled")

    messagebox.showinfo("Éxito", "Texto descifrado generado correctamente.")

def load_file():
    file = filedialog.askopenfile(
        title="Seleccionar archivo cifrado",
        filetypes=[("Archivos de texto", "*.txt")]
    )
    if file:
        try:
            with open(file.name, 'r', encoding='utf-8') as f:
                content = f.read()
            input_text.delete("1.0", tk.END)
            input_text.insert(tk.END, content)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo leer el archivo:\n{e}")

window = tk.Tk()
window.title("Descifrado por Permutación de Grupos")
window.geometry("550x550")

tk.Label(window, text="Texto cifrado (ingrese manualmente o cargue un archivo):").pack()
input_text = tk.Text(window, height=6, width=60)
input_text.pack()

tk.Button(window, text="Cargar archivo .txt", command=load_file).pack(pady=5)

tk.Label(window, text="Tamaño del grupo:").pack()
entry_group = tk.Entry(window)
entry_group.pack()

tk.Label(window, text="Permutación usada en el cifrado:").pack()
entry_permutation = tk.Entry(window)
entry_permutation.pack()

tk.Button(window, text="Descifrar", command=run_decryption).pack(pady=10)

tk.Label(window, text="Texto descifrado:").pack()
output_text = tk.Text(window, height=6, width=60, state="disabled")
output_text.pack()

window.mainloop()