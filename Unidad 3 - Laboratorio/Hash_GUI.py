import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from Hash_algorithms import MD4, MD5, SHA1, SHA224, SHA256, HMAC

class HashCalculatorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Hash Calculator - Algoritmos de Hash Criptográficos")
        self.root.geometry("800x700")
        self.root.resizable(True, True)
        
        self.bg_color = "#1e1e2e"
        self.fg_color = "#cdd6f4"
        self.accent_color = "#89b4fa"
        self.button_color = "#a6e3a1"
        self.entry_bg = "#313244"
        self.frame_bg = "#181825"
        
        self.root.configure(bg=self.bg_color)
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background=self.bg_color)
        style.configure('TLabelframe', background=self.bg_color, foreground=self.fg_color,
                       bordercolor=self.accent_color, borderwidth=2)
        style.configure('TLabelframe.Label', background=self.bg_color, foreground=self.accent_color,
                       font=('Segoe UI', 10, 'bold'))
        style.configure('TLabel', background=self.bg_color, foreground=self.fg_color,
                       font=('Segoe UI', 9))
        style.configure('TButton', background=self.button_color, foreground='#000000',
                       font=('Segoe UI', 9, 'bold'), borderwidth=1)
        style.map('TButton', background=[('active', '#94e2d5'), ('pressed', '#74c7ec')])
        style.configure('TCombobox', fieldbackground=self.entry_bg, background=self.entry_bg,
                       foreground=self.fg_color, arrowcolor=self.accent_color)
        style.configure('TEntry', fieldbackground=self.entry_bg, foreground=self.fg_color)
        
        self.default_message = "The quick brown fox jumps over the lazy dog"
        
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        algo_frame = ttk.LabelFrame(main_frame, text="Seleccionar Algoritmo", padding="10")
        algo_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        algo_frame.columnconfigure(1, weight=1)
        
        ttk.Label(algo_frame, text="Algoritmo:", font=('Segoe UI', 10, 'bold')).grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        
        self.algorithm_var = tk.StringVar(value="SHA256")
        algorithms = ["MD4", "MD5", "SHA1", "SHA224", "SHA256", "HMAC"]
        
        self.algorithm_combo = ttk.Combobox(algo_frame, textvariable=self.algorithm_var, 
                                           values=algorithms, state="readonly", width=30,
                                           font=('Segoe UI', 10))
        self.algorithm_combo.grid(row=0, column=1, sticky=(tk.W, tk.E))
        self.algorithm_combo.bind("<<ComboboxSelected>>", self.on_algorithm_change)
        
        self.hmac_frame = ttk.LabelFrame(main_frame, text="Configuración HMAC", padding="10")
        self.hmac_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        self.hmac_frame.columnconfigure(1, weight=1)
        self.hmac_frame.grid_remove()
        ttk.Label(self.hmac_frame, text="Clave:", font=('Segoe UI', 10, 'bold')).grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.hmac_key_var = tk.StringVar(value="secret_key")
        self.hmac_key_entry = ttk.Entry(self.hmac_frame, textvariable=self.hmac_key_var, width=40,
                                        font=('Segoe UI', 10))
        self.hmac_key_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=(0, 5))
        
        ttk.Label(self.hmac_frame, text="Algoritmo Hash:", font=('Segoe UI', 10, 'bold')).grid(row=1, column=0, sticky=tk.W, padx=(0, 10))
        self.hmac_hash_var = tk.StringVar(value="SHA256")
        hmac_algorithms = ["MD4", "MD5", "SHA1", "SHA224", "SHA256"]
        self.hmac_hash_combo = ttk.Combobox(self.hmac_frame, textvariable=self.hmac_hash_var,
                                           values=hmac_algorithms, state="readonly", width=30,
                                           font=('Segoe UI', 10))
        self.hmac_hash_combo.grid(row=1, column=1, sticky=(tk.W, tk.E))
        
        self.sha224_frame = ttk.LabelFrame(main_frame, text="Configuración SHA224", padding="10")
        self.sha224_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        self.sha224_frame.columnconfigure(1, weight=1)
        self.sha224_frame.grid_remove()
        self.sha224_hmac_enabled = tk.BooleanVar(value=False)
        self.sha224_hmac_check = ttk.Checkbutton(self.sha224_frame, 
                                                 text="🔐 Habilitar HMAC-SHA224",
                                                 variable=self.sha224_hmac_enabled,
                                                 command=self.on_sha224_hmac_toggle)
        self.sha224_hmac_check.grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 5))
        
        ttk.Label(self.sha224_frame, text="Clave:", font=('Segoe UI', 10, 'bold')).grid(row=1, column=0, sticky=tk.W, padx=(0, 10))
        self.sha224_key_var = tk.StringVar(value="secret_key")
        self.sha224_key_entry = ttk.Entry(self.sha224_frame, textvariable=self.sha224_key_var, width=40,
                                          font=('Segoe UI', 10), state=tk.DISABLED)
        self.sha224_key_entry.grid(row=1, column=1, sticky=(tk.W, tk.E))
        input_frame = ttk.LabelFrame(main_frame, text="Mensaje de Entrada", padding="10")
        input_frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        input_frame.columnconfigure(0, weight=1)
        input_frame.rowconfigure(1, weight=1)
        
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        btn_default = ttk.Button(button_frame, text="🔄 Usar Mensaje por Defecto", 
                  command=self.use_default_message)
        btn_default.pack(side=tk.LEFT, padx=(0, 5))
        
        btn_clear = ttk.Button(button_frame, text="🗑️ Limpiar", 
                  command=self.clear_input)
        btn_clear.pack(side=tk.LEFT)
        
        self.input_text = scrolledtext.ScrolledText(input_frame, height=8, width=70, wrap=tk.WORD,
                                                    bg=self.entry_bg, fg=self.fg_color,
                                                    insertbackground=self.accent_color,
                                                    font=('Consolas', 10),
                                                    borderwidth=2, relief=tk.FLAT)
        self.input_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.input_text.insert(1.0, self.default_message)
        calc_frame = ttk.Frame(main_frame)
        calc_frame.grid(row=4, column=0, pady=(0, 10))
        
        self.calc_button = ttk.Button(calc_frame, text="⚡ CALCULAR HASH", 
                                      command=self.calculate_hash)
        self.calc_button.pack(pady=5)
        
        style.configure('Accent.TButton', background='#f38ba8', foreground='#000000',
                       font=('Segoe UI', 11, 'bold'), padding=10)
        style.map('Accent.TButton', background=[('active', '#eba0ac'), ('pressed', '#f9e2af')])
        self.calc_button.configure(style='Accent.TButton')
        
        result_frame = ttk.LabelFrame(main_frame, text="Resultado (Hash Hexadecimal)", padding="10")
        result_frame.grid(row=5, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        result_frame.columnconfigure(0, weight=1)
        
        self.info_label = ttk.Label(result_frame, text="", foreground=self.accent_color,
                                    font=('Segoe UI', 10, 'bold'))
        self.info_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        result_text_frame = ttk.Frame(result_frame)
        result_text_frame.grid(row=1, column=0, sticky=(tk.W, tk.E))
        result_text_frame.columnconfigure(0, weight=1)
        
        self.result_text = tk.Text(result_text_frame, height=4, width=70, wrap=tk.WORD,
                                   font=("Courier", 10), state=tk.DISABLED,
                                   bg=self.entry_bg, fg='#a6e3a1',
                                   insertbackground=self.accent_color,
                                   borderwidth=2, relief=tk.FLAT)
        self.result_text.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        result_scrollbar = ttk.Scrollbar(result_text_frame, orient=tk.VERTICAL, 
                                        command=self.result_text.yview)
        result_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.result_text.configure(yscrollcommand=result_scrollbar.set)
        btn_copy = ttk.Button(result_frame, text="📋 Copiar al Portapapeles", 
                  command=self.copy_result)
        btn_copy.grid(row=2, column=0, pady=(5, 0))
        
        status_frame = ttk.Frame(main_frame, relief=tk.SUNKEN, borderwidth=2)
        status_frame.grid(row=6, column=0, sticky=(tk.W, tk.E))
        status_frame.configure(style='Status.TFrame')
        
        self.status_label = ttk.Label(status_frame, text="✅ Listo para calcular hash", 
                                     anchor=tk.W, font=('Segoe UI', 9))
        self.status_label.pack(fill=tk.X, padx=5, pady=2)
    
    def on_algorithm_change(self, event=None):
        algorithm = self.algorithm_var.get()
        
        if algorithm == "HMAC":
            self.hmac_frame.grid()
            self.sha224_frame.grid_remove()
        elif algorithm == "SHA224":
            self.hmac_frame.grid_remove()
            self.sha224_frame.grid()
        else:
            self.hmac_frame.grid_remove()
            self.sha224_frame.grid_remove()
    
    def on_sha224_hmac_toggle(self):
        if self.sha224_hmac_enabled.get():
            self.sha224_key_entry.config(state=tk.NORMAL)
        else:
            self.sha224_key_entry.config(state=tk.DISABLED)
    
    def use_default_message(self):
        self.input_text.delete(1.0, tk.END)
        self.input_text.insert(1.0, self.default_message)
        self.status_label.config(text="🔄 Mensaje por defecto restaurado")
    
    def clear_input(self):
        self.input_text.delete(1.0, tk.END)
        self.status_label.config(text="🗑️ Mensaje limpiado")
    
    def calculate_hash(self):
        try:
            message = self.input_text.get(1.0, tk.END).strip()
            
            if not message:
                messagebox.showwarning("Advertencia", "Por favor ingrese un mensaje")
                return
            
            message_bytes = message.encode("utf-8")
            
            algorithm = self.algorithm_var.get()
            
            if algorithm == "MD4":
                hash_obj = MD4(message_bytes)
                info = f"MD4 Hash ({len(hash_obj.hexdigest()) * 4} bits)"
            elif algorithm == "MD5":
                hash_obj = MD5(message_bytes)
                info = f"MD5 Hash ({len(hash_obj.hexdigest()) * 4} bits)"
            elif algorithm == "SHA1":
                hash_obj = SHA1(message_bytes)
                info = f"SHA-1 Hash ({len(hash_obj.hexdigest()) * 4} bits)"
            elif algorithm == "SHA224":
                if self.sha224_hmac_enabled.get():
                    key = self.sha224_key_var.get()
                    if not key:
                        messagebox.showwarning("Advertencia", "Por favor ingrese una clave para HMAC-SHA224")
                        return
                    hash_obj = HMAC(key.encode("utf-8"), message_bytes, SHA224)
                    info = f"HMAC-SHA224 ({len(hash_obj.hexdigest()) * 4} bits) | Clave: '{key}'"
                else:
                    hash_obj = SHA224(message_bytes)
                    info = f"SHA-224 Hash ({len(hash_obj.hexdigest()) * 4} bits)"
            elif algorithm == "SHA256":
                hash_obj = SHA256(message_bytes)
                info = f"SHA-256 Hash ({len(hash_obj.hexdigest()) * 4} bits)"
            elif algorithm == "HMAC":
                key = self.hmac_key_var.get()
                if not key:
                    messagebox.showwarning("Advertencia", "Por favor ingrese una clave HMAC")
                    return
                
                hmac_hash_algo = self.hmac_hash_var.get()
                hash_classes = {
                    "MD4": MD4,
                    "MD5": MD5,
                    "SHA1": SHA1,
                    "SHA224": SHA224,
                    "SHA256": SHA256
                }
                hash_class = hash_classes[hmac_hash_algo]
                
                hash_obj = HMAC(key.encode("utf-8"), message_bytes, hash_class)
                info = f"HMAC-{hmac_hash_algo} ({len(hash_obj.hexdigest()) * 4} bits) | Clave: '{key}'"
            
            result_hash = hash_obj.hexdigest()
            
            self.result_text.config(state=tk.NORMAL)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(1.0, result_hash)
            self.result_text.config(state=tk.DISABLED)
            
            self.info_label.config(text=info)
            self.status_label.config(text=f"✅ Hash calculado exitosamente usando {algorithm}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al calcular el hash:\n{str(e)}")
            self.status_label.config(text="❌ Error al calcular hash")
    
    def copy_result(self):
        result = self.result_text.get(1.0, tk.END).strip()
        if result:
            self.root.clipboard_clear()
            self.root.clipboard_append(result)
            self.status_label.config(text="📋 Hash copiado al portapapeles")
            messagebox.showinfo("Éxito", "Hash copiado al portapapeles ✓")
        else:
            messagebox.showwarning("Advertencia", "No hay hash para copiar")

def main():
    root = tk.Tk()
    HashCalculatorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()