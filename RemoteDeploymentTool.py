import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
import threading
import queue
import subprocess
import os
import csv
from datetime import datetime
import sys

class DeploymentApp:
    """
    A multithreaded Tkinter application that deploys to all hosts simultaneously.
    It uses psexec.exe from the script's directory and robocopy from the system PATH.
    """
    def __init__(self, root):
        self.root = root
        self.root.title("Remote Deployment Tool (Multithreaded)")
        self.root.geometry("950x600")

        # --- Determine the base path for psexec.exe ---
        if getattr(sys, 'frozen', False):
            self.base_path = os.path.dirname(sys.executable)
        else:
            self.base_path = os.path.dirname(os.path.abspath(__file__))
        
        self.psexec_path = os.path.join(self.base_path, "psexec.exe")

        # --- Style Configuration ---
        self.style = ttk.Style(self.root)
        self.style.theme_use('clam')
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TLabel", background="#f0f0f0", font=("Arial", 10))
        self.style.configure("TButton", font=("Arial", 10, "bold"))
        self.style.configure("Header.TLabel", font=("Arial", 16, "bold"))

        # --- Log Queue & CSV File Setup ---
        self.log_queue = queue.Queue()
        self.csv_lock = threading.Lock() # Lock for thread-safe CSV writing
        self.log_file = 'deployment_log.csv'
        self.setup_csv_log()

        # --- Main Frame ---
        main_frame = ttk.Frame(self.root, padding="10 10 10 10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Input Frame (Left Side) ---
        input_frame = ttk.Frame(main_frame, padding="10")
        input_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=1)

        ttk.Label(input_frame, text="Deployment Configuration", style="Header.TLabel").grid(row=0, column=0, columnspan=3, pady=(0, 15), sticky="w")

        # Source File
        ttk.Label(input_frame, text="Source Executable:").grid(row=1, column=0, sticky="w", pady=5)
        self.source_file_var = tk.StringVar()
        source_entry = ttk.Entry(input_frame, textvariable=self.source_file_var, width=45)
        source_entry.grid(row=1, column=1, sticky="ew", padx=5)
        browse_button = ttk.Button(input_frame, text="Browse...", command=self.browse_source_file)
        browse_button.grid(row=1, column=2, sticky="w")

        # Target Hostnames
        ttk.Label(input_frame, text="Target Hostnames:").grid(row=2, column=0, sticky="nw", pady=5)
        self.hostnames_text = tk.Text(input_frame, height=8, width=45, borderwidth=1, relief="solid")
        self.hostnames_text.grid(row=2, column=1, columnspan=2, sticky="ew", padx=5)

        # Destination Path
        ttk.Label(input_frame, text="Destination Path:").grid(row=3, column=0, sticky="w", pady=5)
        self.dest_path_var = tk.StringVar(value="")
        dest_entry = ttk.Entry(input_frame, textvariable=self.dest_path_var, width=45)
        dest_entry.grid(row=3, column=1, columnspan=2, sticky="ew", padx=5)

        # Service Name
        ttk.Label(input_frame, text="Service Name:").grid(row=4, column=0, sticky="w", pady=5)
        self.service_name_var = tk.StringVar(value="")
        service_entry = ttk.Entry(input_frame, textvariable=self.service_name_var, width=45)
        service_entry.grid(row=4, column=1, columnspan=2, sticky="ew", padx=5)
        
        input_frame.columnconfigure(1, weight=1)

        # --- Control Buttons ---
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=5, column=0, columnspan=3, pady=(20, 0), sticky="ew")
        
        self.deploy_button = ttk.Button(button_frame, text="Deploy", command=self.start_deployment_thread)
        self.deploy_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        self.clear_log_button = ttk.Button(button_frame, text="Clear Log", command=self.clear_log)
        self.clear_log_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))

        # --- Log Frame (Right Side) ---
        log_frame = ttk.Frame(main_frame, padding="10")
        log_frame.grid(row=0, column=1, sticky="nsew")
        main_frame.columnconfigure(1, weight=2)

        ttk.Label(log_frame, text="Deployment Log", style="Header.TLabel").pack(anchor="w", pady=(0, 10))
        self.log_widget = scrolledtext.ScrolledText(log_frame, state='disabled', height=25, wrap=tk.WORD, borderwidth=1, relief="solid", font=("Consolas", 9))
        self.log_widget.pack(fill=tk.BOTH, expand=True)

        self.log_widget.tag_config('INFO', foreground='blue')
        self.log_widget.tag_config('SUCCESS', foreground='green')
        self.log_widget.tag_config('ERROR', foreground='red')
        self.log_widget.tag_config('HEADER', font=("Arial", 10, "bold"))
        self.log_widget.tag_config('CMD', foreground='purple', font=("Consolas", 9, "italic"))
        
        self.add_log("INFO", f"System Ready. Logs will be saved to '{self.log_file}'.")

        self.root.after(100, self.process_log_queue)

    def setup_csv_log(self):
        if not os.path.exists(self.log_file):
            with open(self.log_file, mode='w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Timestamp', 'Hostname', 'Status', 'Action', 'Details'])

    def log_to_csv(self, hostname, status, action, details=""):
        """Appends a new record to the CSV log file in a thread-safe manner."""
        with self.csv_lock:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean_details = str(details).replace('\n', ' ').replace('\r', '')
            with open(self.log_file, mode='a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([timestamp, hostname, status, action, clean_details])

    def browse_source_file(self):
        filename = filedialog.askopenfilename(title="Select an Executable", filetypes=(("Executable files", "*.exe"), ("All files", "*.*")))
        if filename:
            self.source_file_var.set(filename)

    def add_log(self, tag, message):
        self.log_widget.configure(state='normal')
        if tag == "HEADER":
             self.log_widget.insert(tk.END, f"\n--- {message} ---\n", ('HEADER',))
        else:
            self.log_widget.insert(tk.END, f"[{tag}] {message}\n", (tag,))
        self.log_widget.configure(state='disabled')
        self.log_widget.see(tk.END)

    def clear_log(self):
        self.log_widget.configure(state='normal')
        self.log_widget.delete(1.0, tk.END)
        self.log_widget.configure(state='disabled')
        self.add_log("INFO", "Log cleared by user.")

    def process_log_queue(self):
        try:
            while True:
                tag, message = self.log_queue.get_nowait()
                if tag == '__RE-ENABLE-BUTTON__':
                    self.deploy_button.config(state="normal")
                else:
                    self.add_log(tag, message)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_log_queue)

    def start_deployment_thread(self):
        source_file = self.source_file_var.get().strip()
        hostnames = [h.strip() for h in self.hostnames_text.get("1.0", tk.END).strip().split('\n') if h.strip()]
        dest_path = self.dest_path_var.get().strip()
        service_name = self.service_name_var.get().strip()

        if not all([source_file, hostnames, dest_path, service_name]):
            self.add_log("ERROR", "All fields are required.")
            return
        
        if not os.path.exists(self.psexec_path):
            self.add_log("ERROR", f"psexec.exe not found in the script directory: {self.base_path}")
            return

        self.deploy_button.config(state="disabled")
        self.add_log("INFO", f"Starting parallel deployment to {len(hostnames)} host(s)...")

        # This master thread will spawn a worker thread for each host
        master_thread = threading.Thread(
            target=self.run_master_deployment,
            args=(source_file, hostnames, dest_path, service_name),
            daemon=True
        )
        master_thread.start()

    def run_master_deployment(self, source_file, hostnames, dest_path, service_name):
        """Creates, starts, and manages a thread for each host."""
        threads = []
        for host in hostnames:
            # Create a thread for each host, targeting the deploy_to_host method
            thread = threading.Thread(
                target=self.deploy_to_host,
                args=(host, source_file, dest_path, service_name),
                daemon=True
            )
            threads.append(thread)
            thread.start()

        # Wait for all worker threads to complete
        for thread in threads:
            thread.join()

        # Once all hosts are processed, send final messages
        self.log_queue.put(('SUCCESS', "--- All deployment tasks completed. ---"))
        self.log_queue.put(('__RE-ENABLE-BUTTON__', ''))

    def deploy_to_host(self, host, source_file, dest_path, service_name):
        """This method contains the deployment logic for a single host and runs in its own thread."""
        self.log_queue.put(('HEADER', f"Processing Host: {host}"))
        
        psexec_base_cmd = [self.psexec_path, f'\\\\{host}', '-s', '-accepteula', '-nobanner']
        
        try:
            # STEP 1: Check if service exists and stop it if it does
            self.log_queue.put(('INFO', f"[{host}] Checking for service '{service_name}'..."))
            check_cmd = psexec_base_cmd + ['sc', 'query', service_name]
            
            service_exists_result = subprocess.run(check_cmd, capture_output=True, text=True)
            service_exists = service_exists_result.returncode == 0

            if service_exists:
                self.log_queue.put(('INFO', f"[{host}] Service found. Attempting to stop..."))
                stop_cmd = psexec_base_cmd + ['sc', 'stop', service_name]
                result = subprocess.run(stop_cmd, capture_output=True, text=True, check=True)
                self.log_queue.put(('SUCCESS', f"[{host}] Service '{service_name}' stopped."))
                self.log_to_csv(host, 'SUCCESS', 'Stop Service', result.stdout)
            else:
                self.log_queue.put(('INFO', f"[{host}] Service '{service_name}' does not exist. Will create it later."))
                self.log_to_csv(host, 'INFO', 'Check Service', f"Service '{service_name}' not found.")

            # STEP 2: Copy the file to the remote host
            self.log_queue.put(('INFO', f"[{host}] Copying file using Robocopy..."))
            source_dir = os.path.dirname(source_file)
            file_name = os.path.basename(source_file)
            unc_dest = f'\\\\{host}\\{dest_path.replace(":", "$")}'
            copy_cmd = ['robocopy', source_dir, unc_dest, file_name, '/R:2', '/W:5']
            result = subprocess.run(copy_cmd, capture_output=True, text=True)
            if result.returncode >= 8: # Robocopy failure threshold
                 raise subprocess.CalledProcessError(result.returncode, copy_cmd, output=result.stdout, stderr=result.stderr)
            self.log_queue.put(('SUCCESS', f"[{host}] File copied successfully."))
            self.log_to_csv(host, 'SUCCESS', 'Copy File', f"Copied {file_name} to {dest_path}")

            # STEP 3: Start or Create the service
            remote_exe_path = os.path.join(dest_path, file_name).replace('/', '\\')
            if service_exists:
                self.log_queue.put(('INFO', f"[{host}] Service exists. Attempting to start..."))
                start_cmd = psexec_base_cmd + ['sc', 'start', service_name]
                result = subprocess.run(start_cmd, capture_output=True, text=True, check=True)
                self.log_queue.put(('SUCCESS', f"[{host}] Service '{service_name}' started."))
                self.log_to_csv(host, 'SUCCESS', 'Start Service', result.stdout)
            else:
                self.log_queue.put(('INFO', f"[{host}] Service does not exist. Creating and starting..."))
                create_cmd = psexec_base_cmd + ['sc', 'create', service_name, 'binPath=', f'"{remote_exe_path}"']
                result = subprocess.run(create_cmd, capture_output=True, text=True, check=True)
                self.log_queue.put(('SUCCESS', f"[{host}] Service '{service_name}' created."))
                self.log_to_csv(host, 'SUCCESS', 'Create Service', result.stdout)
                
                start_cmd = psexec_base_cmd + ['sc', 'start', service_name]
                result = subprocess.run(start_cmd, capture_output=True, text=True, check=True)
                self.log_queue.put(('SUCCESS', f"[{host}] Service '{service_name}' started."))
                self.log_to_csv(host, 'SUCCESS', 'Start Service (after create)', result.stdout)

        except FileNotFoundError as e:
             msg = f"Command '{os.path.basename(e.filename)}' not found. Ensure it's in the script directory or system PATH."
             self.log_queue.put(('ERROR', f"[{host}] {msg}"))
             self.log_to_csv(host, 'ERROR', 'Prerequisite Check', msg)
        except subprocess.CalledProcessError as e:
            error_message = (e.stdout or '') + (e.stderr or '')
            self.log_queue.put(('ERROR', f"[{host}] A command failed.\nOutput:\n{error_message}"))
            self.log_to_csv(host, 'ERROR', 'Command Execution', error_message)

if __name__ == "__main__":
    root = tk.Tk()
    app = DeploymentApp(root)
    root.mainloop()
