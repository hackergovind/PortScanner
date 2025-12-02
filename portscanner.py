# The Blackhat CIDR Range Scanner - A Tkinter GUI application for mass port scanning.
# It integrates non-blocking sockets and threading for high speed across a range of IPs (CIDR).
import socket
import threading
import time
from queue import Queue
import ipaddress
import tkinter as tk
from tkinter import scrolledtext
import sys
import os

# --- Configuration Constants ---
DEFAULT_THREADS = 100 
DEFAULT_TIMEOUT = 0.5 
OUTPUT_FILENAME = "open_ips.txt"

# --- Global State and Locks ---
port_queue = Queue()
print_lock = threading.Lock() 
scan_in_progress = False

# --- Output Redirection Class (to send print() output to the GUI text widget) ---
class RedirectText:
    """Class to redirect stdout to a tkinter Text widget."""
    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, string):
        """Inserts text into the widget and scrolls to the end."""
        self.text_widget.insert(tk.END, string)
        self.text_widget.see(tk.END) # Auto-scroll to the bottom

    def flush(self):
        """Required for file-like object compatibility."""
        pass

# --- Core Scanner Functions ---

def parse_ports(port_input):
    """Parses a string of ports (e.g., '21,80,443' or '1-1024') into a list."""
    ports = set()
    try:
        if '-' in port_input:
            start, end = map(int, port_input.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.update(map(int, port_input.split(',')))
        
        # Filter for valid port range
        return [p for p in ports if 1 <= p <= 65535]
    except Exception:
        return None

def check_port(ip, port, timeout):
    """Attempts a non-blocking connection to the specified IP and port."""
    global print_lock, OUTPUT_FILENAME, OPEN_IPS_WITH_PORTS
    
    # Check if the scan has been stopped externally
    if not scan_in_progress:
        return

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        result = sock.connect_ex((ip, port))
        
        if result == 0:
            # Connection successful, port is open
            with print_lock:
                print(f"[{ip}]: {port}/TCP is Open") 
                
                # Store the IP/Port pair
                if ip not in OPEN_IPS_WITH_PORTS:
                    OPEN_IPS_WITH_PORTS[ip] = []
                OPEN_IPS_WITH_PORTS[ip].append(port)
        
        sock.close()

    except socket.gaierror:
        # Handle invalid hostname/IP (should be caught by ipaddress but serves as a safeguard)
        with print_lock:
            print(f"Error: Hostname resolution failed for {ip}.")
    except socket.error:
        pass # Port is closed or connection error

def worker_thread(timeout):
    """Worker function for threads to pull (IP, Port) tuples from the queue and scan."""
    global port_queue, scan_in_progress
    while scan_in_progress:
        try:
            # Non-blocking get with a timeout allows the thread to check the scan_in_progress flag
            ip, port = port_queue.get(timeout=0.1) 
            check_port(ip, port, timeout)
            port_queue.task_done()
        except Queue.Empty:
            # If the queue is empty, exit gracefully
            if not scan_in_progress:
                break
            continue
        except Exception as e:
            with print_lock:
                print(f"Worker Error: {e}")
            break

def start_scan_engine(cidr_range, ports_list, threads_count, timeout):
    """Initializes the engine, fills the queue, and manages threads."""
    global port_queue, OPEN_IPS_WITH_PORTS, scan_in_progress
    
    OPEN_IPS_WITH_PORTS = {}
    scan_in_progress = True
    start_time = time.time()
    
    try:
        network = ipaddress.ip_network(cidr_range, strict=False)
        ip_count = len(list(network.hosts()))
        
        print(f"--- Starting high-speed CIDR scan on {cidr_range} ({ip_count} hosts) with {threads_count} threads... ---")
        
        # 1. Create and start worker threads
        threads = []
        for _ in range(threads_count):
            thread = threading.Thread(target=worker_thread, args=(timeout,), daemon=True)
            threads.append(thread)
            thread.start()

        # 2. Fill the queue with all (IP, Port) combinations
        for ip in network.hosts():
            ip_str = str(ip)
            for port in ports_list:
                port_queue.put((ip_str, port))
                
        # 3. Wait for all items in the queue to be processed
        port_queue.join()
        
    except ValueError as e:
        print(f"\n[ERROR] Invalid CIDR or IP Range: {e}")
    except Exception as e:
        print(f"\n[ERROR] An unexpected error occurred: {e}")
    finally:
        scan_in_progress = False
        end_time = time.time()
        
        print("\n--- Scan Complete ---")
        print(f"Total time elapsed: {end_time - start_time:.2f} seconds")
        
        # Output results to file: only IP address as requested
        if OPEN_IPS_WITH_PORTS:
            # Write to file: only the IP address as requested
            try:
                with open(OUTPUT_FILENAME, 'w') as f:
                    for ip in sorted(OPEN_IPS_WITH_PORTS.keys()):
                        f.write(f"{ip}\n")
                print(f"[*] All open IPs written successfully to {os.path.abspath(OUTPUT_FILENAME)}")
            except Exception as e:
                print(f"[!] Failed to write to file: {e}")
                
        else:
            print("No open ports found in the specified range.")


# --- Tkinter GUI Application Class ---

class ScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Blackhat CIDR Mass Scanner")
        self.geometry("800x600")
        self.scan_thread = None
        self.configure(bg='#1e1e1e')
        
        # Use a nice, hacker-ish font and colors
        self.font_main = ('Consolas', 11)
        self.fg_color = '#00ff00' # Bright green
        self.bg_color = '#1e1e1e' # Deep dark gray
        self.button_color = '#3c3c3c'
        self.button_active = '#006400'
        
        self.create_widgets()
        
        # Redirect stdout to the text widget
        sys.stdout = RedirectText(self.output_text)

    def create_widgets(self):
        # --- Input Frame (Top) ---
        input_frame = tk.Frame(self, bg=self.bg_color, padx=10, pady=10)
        input_frame.pack(fill='x')

        # 1. CIDR Input
        tk.Label(input_frame, text="CIDR/IP Range:", fg=self.fg_color, bg=self.bg_color, font=self.font_main).grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.cidr_entry = tk.Entry(input_frame, width=30, bg='#3c3c3c', fg=self.fg_color, insertbackground=self.fg_color, font=self.font_main)
        self.cidr_entry.insert(0, "127.0.0.1/30") 
        self.cidr_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

        # 2. Port Input
        tk.Label(input_frame, text="Ports (e.g., 80,443 or 1-1000):", fg=self.fg_color, bg=self.bg_color, font=self.font_main).grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.ports_entry = tk.Entry(input_frame, width=30, bg='#3c3c3c', fg=self.fg_color, insertbackground=self.fg_color, font=self.font_main)
        self.ports_entry.insert(0, "21,22,80,443")
        self.ports_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')
        
        # 3. Threads Input (Optional for fine-tuning)
        tk.Label(input_frame, text="Threads Count:", fg=self.fg_color, bg=self.bg_color, font=self.font_main).grid(row=0, column=2, padx=5, pady=5, sticky='w')
        self.threads_entry = tk.Entry(input_frame, width=10, bg='#3c3c3c', fg=self.fg_color, insertbackground=self.fg_color, font=self.font_main)
        self.threads_entry.insert(0, str(DEFAULT_THREADS))
        self.threads_entry.grid(row=0, column=3, padx=5, pady=5, sticky='w')

        # 4. Timeout Input
        tk.Label(input_frame, text="Timeout (s):", fg=self.fg_color, bg=self.bg_color, font=self.font_main).grid(row=1, column=2, padx=5, pady=5, sticky='w')
        self.timeout_entry = tk.Entry(input_frame, width=10, bg='#3c3c3c', fg=self.fg_color, insertbackground=self.fg_color, font=self.font_main)
        self.timeout_entry.insert(0, str(DEFAULT_TIMEOUT))
        self.timeout_entry.grid(row=1, column=3, padx=5, pady=5, sticky='w')
        
        # Configure grid expansion
        input_frame.grid_columnconfigure(1, weight=1)

        # --- Control Frame ---
        control_frame = tk.Frame(self, bg=self.bg_color, padx=10, pady=5)
        control_frame.pack(fill='x')

        self.start_button = tk.Button(control_frame, text="START MASS SCAN", command=self.start_scan_thread, 
                                     bg=self.button_color, fg=self.fg_color, activebackground=self.button_active, 
                                     activeforeground=self.fg_color, font=('Consolas', 12, 'bold'), relief=tk.RAISED, bd=3)
        self.start_button.pack(side=tk.LEFT, fill='x', expand=True, padx=5)

        self.stop_button = tk.Button(control_frame, text="STOP SCAN", command=self.stop_scan, state=tk.DISABLED,
                                     bg='#8b0000', fg='white', activebackground='#b22222',
                                     activeforeground='white', font=('Consolas', 12, 'bold'), relief=tk.RAISED, bd=3)
        self.stop_button.pack(side=tk.LEFT, fill='x', expand=True, padx=5)


        # --- Output Text Area (Bottom) ---
        tk.Label(self, text="--- Real-Time Output ---", fg='#ff00ff', bg=self.bg_color, font=('Consolas', 12, 'bold')).pack(fill='x', padx=10, pady=(5,0))
        
        output_frame = tk.Frame(self, bg=self.bg_color, padx=10, pady=5)
        output_frame.pack(fill='both', expand=True)

        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, bg='#000000', fg=self.fg_color, 
                                                    font=self.font_main, relief=tk.FLAT, insertbackground=self.fg_color)
        self.output_text.pack(fill='both', expand=True)
        self.output_text.insert(tk.END, "System Ready. Enter CIDR range and ports, then click START.\n")
        self.output_text.config(state=tk.NORMAL) # Ensure it's writable

    def start_scan_thread(self):
        """Validates input and starts the scanning engine in a separate thread."""
        global scan_in_progress
        if scan_in_progress:
            print("\n[!] Scan is already running. Please wait or stop the current operation.")
            return

        cidr_input = self.cidr_entry.get()
        ports_input = self.ports_entry.get()
        threads_input = self.threads_entry.get()
        timeout_input = self.timeout_entry.get()
        
        # --- Validation ---
        ports_list = parse_ports(ports_input)
        if not ports_list:
            print("\n[ERROR] Invalid port input. Use '80,443' or '1-1024'.")
            return
        
        try:
            threads_count = int(threads_input)
            timeout = float(timeout_input)
            if threads_count <= 0 or timeout <= 0:
                 raise ValueError("Values must be positive.")
        except ValueError:
            print("\n[ERROR] Threads/Timeout must be valid positive numbers.")
            return
            
        # Clear output and update button states
        self.output_text.delete('1.0', tk.END)
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Start the engine in a new thread so the GUI remains responsive
        self.scan_thread = threading.Thread(target=start_scan_engine, 
                                            args=(cidr_input, ports_list, threads_count, timeout), 
                                            daemon=True)
        self.scan_thread.start()

    def stop_scan(self):
        """Signals the scanning threads to stop gracefully."""
        global scan_in_progress
        if scan_in_progress:
            scan_in_progress = False
            # Wait a moment for threads to check the flag and exit
            time.sleep(1)
            # Drain the queue to unblock the main thread if it's waiting on join()
            while not port_queue.empty():
                try:
                    port_queue.get_nowait()
                    port_queue.task_done()
                except Queue.Empty:
                    break
            
            # Re-enable the start button
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            print("\n[!] Scan was manually stopped.")
        else:
             print("\n[!] No scan is currently running.")
        
# --- Execution ---
if __name__ == "__main__":
    app = ScannerApp()
    # Handle window close event to ensure proper cleanup
    def on_closing():
        global scan_in_progress
        scan_in_progress = False # Signal threads to stop
        app.destroy()
        
    app.protocol("WM_DELETE_WINDOW", on_closing)
    app.mainloop()