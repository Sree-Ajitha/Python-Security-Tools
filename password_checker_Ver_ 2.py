import re
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from pathlib import Path
import threading
import time
import urllib.request
import zipfile
import io
import json
import os
from datetime import datetime
import random

class AnimatedProgressbar(ttk.Progressbar):
    """Custom animated progressbar for background tasks"""
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        self.animation_active = False
        self.animation_value = 0
        
    def start_animation(self):
        self.animation_active = True
        self.animate()
        
    def stop_animation(self):
        self.animation_active = False
        
    def animate(self):
        if not self.animation_active:
            return
            
        self.animation_value = (self.animation_value + 3) % 100
        self["value"] = self.animation_value
        self.after(50, self.animate)

class PasswordLibraryManager:
    """Manages password libraries/dictionaries"""
    def __init__(self):
        self.available_libraries = [
            {
                "name": "RockYou (10M passwords)",
                "description": "Famous leaked password list with ~10M entries",
                "url": "https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz",
                "size": "60 MB",
                "format": "tar.gz"
            },
            {
                "name": "Common Credentials (200K)",
                "description": "Common usernames and passwords",
                "url": "https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt",
                "size": "1.0 MB",
                "format": "txt"
            },
            {
                "name": "Top 10K Passwords",
                "description": "10,000 most common passwords",
                "url": "https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10k-most-common.txt",
                "size": "0.1 MB",
                "format": "txt"
            },
            {
                "name": "Password Dictionary (479K)",
                "description": "Large English dictionary for password cracking",
                "url": "https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/english.txt",
                "size": "4.0 MB",
                "format": "txt"
            }
        ]
        
        # Create libraries directory if it doesn't exist
        self.libraries_dir = Path("password_libraries")
        self.libraries_dir.mkdir(exist_ok=True)
    
    def get_available_libraries(self):
        return self.available_libraries
        
    def download_library(self, library_info, progress_callback=None, completion_callback=None):
        """Download a password library with progress updates"""
        try:
            url = library_info["url"]
            filename = url.split("/")[-1]
            save_path = self.libraries_dir / filename
            
            # Create a request with a user agent
            req = urllib.request.Request(
                url,
                data=None,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
            )
            
            # Function to report download progress
            def report_progress(block_num, block_size, total_size):
                if total_size > 0:
                    percent = min(100, int(block_num * block_size * 100 / total_size))
                    if progress_callback:
                        progress_callback(percent)
            
            # Download the file
            urllib.request.urlretrieve(url, save_path, reporthook=report_progress)
            
            # Extract if needed
            if filename.endswith('.tar.gz') or filename.endswith('.zip'):
                # For simplicity, just report extraction started
                if progress_callback:
                    progress_callback(-1)  # -1 indicates indeterminate progress (extraction)
                
                if filename.endswith('.tar.gz'):
                    import tarfile
                    with tarfile.open(save_path, 'r:gz') as tar:
                        tar.extractall(path=self.libraries_dir)
                elif filename.endswith('.zip'):
                    with zipfile.ZipFile(save_path, 'r') as zip_ref:
                        zip_ref.extractall(path=self.libraries_dir)
                
                # Delete the archive after extraction
                save_path.unlink()
            
            if completion_callback:
                completion_callback(True, f"Downloaded to {self.libraries_dir}")
                
        except Exception as e:
            if completion_callback:
                completion_callback(False, f"Error: {str(e)}")
    
    def get_local_libraries(self):
        """Get list of locally available password libraries"""
        libraries = []
        for file in self.libraries_dir.glob("*.txt"):
            size_bytes = file.stat().st_size
            size_mb = size_bytes / (1024 * 1024)
            
            # Count lines in the file (limited sampling for large files)
            line_count = 0
            sample_size = min(size_bytes, 1024 * 1024)  # Sample 1MB max
            if size_bytes > 0:
                with open(file, 'r', errors='ignore') as f:
                    sample = f.read(int(sample_size))
                    line_count = sample.count('\n')
                    
                # Estimate total lines
                if size_bytes > sample_size:
                    line_count = int(line_count * (size_bytes / sample_size))
                    
            libraries.append({
                "name": file.name,
                "path": str(file),
                "size": f"{size_mb:.2f} MB",
                "estimated_entries": f"{line_count:,}"
            })
            
        return libraries

class GlowingButton(tk.Canvas):
    """Custom animated button with glow effect"""
    def __init__(self, master=None, text="Button", command=None, width=120, height=30, **kwargs):
        super().__init__(master, width=width, height=height, highlightthickness=0, **kwargs)
        
        # Fix: Use a default background color that matches the theme instead of trying to get it from master
        self.config(bg="#ffffff")  # Default white background
        
        self.command = command
        self.text = text
        self.width = width
        self.height = height
        
        # Colors
        self.normal_color = "#1976D2"
        self.hover_color = "#2196F3"
        self.glow_color = "#90CAF9"
        self.text_color = "#FFFFFF"
        
        # Animation state
        self.glow_intensity = 0
        self.glow_direction = 1
        self.animating = False
        
        # Create the button
        self.button = self.create_rounded_rectangle(2, 2, width-2, height-2, 8, fill=self.normal_color, outline="")
        self.text_id = self.create_text(width//2, height//2, text=text, fill=self.text_color, font=("Helvetica", 10, "bold"))
        
        # Bind events
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        self.bind("<Button-1>", self.on_click)
        self.bind("<ButtonRelease-1>", self.on_release)
    
    def create_rounded_rectangle(self, x1, y1, x2, y2, radius, **kwargs):
        points = [
            x1+radius, y1,
            x2-radius, y1,
            x2, y1,
            x2, y1+radius,
            x2, y2-radius,
            x2, y2,
            x2-radius, y2,
            x1+radius, y2,
            x1, y2,
            x1, y2-radius,
            x1, y1+radius,
            x1, y1
        ]
        return self.create_polygon(points, smooth=True, **kwargs)
    
    def on_enter(self, event):
        self.itemconfig(self.button, fill=self.hover_color)
        if not self.animating:
            self.animating = True
            self.animate_glow()
    
    def on_leave(self, event):
        self.itemconfig(self.button, fill=self.normal_color)
        self.animating = False
    
    def on_click(self, event):
        self.itemconfig(self.button, fill="#0D47A1")
    
    def on_release(self, event):
        self.itemconfig(self.button, fill=self.hover_color)
        if self.command:
            self.command()
    
    def animate_glow(self):
        if not self.animating:
            return
            
        self.glow_intensity += self.glow_direction * 0.05
        
        if self.glow_intensity >= 1.0:
            self.glow_intensity = 1.0
            self.glow_direction = -1
        elif self.glow_intensity <= 0.0:
            self.glow_intensity = 0.0
            self.glow_direction = 1
            
        # Create glow effect
        glow_width = int(2 + self.glow_intensity * 2)
        self.itemconfig(self.button, outline=self.glow_color, width=glow_width)
        
        self.after(50, self.animate_glow)

class PasswordStrengthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Analyzer")
        self.root.geometry("900x650")
        self.root.configure(bg="#f5f5f7")
        
        # Password dictionary
        self.common_passwords = set()
        self.password_dict_path = ""
        self.loading_complete = False
        
        # Library manager
        self.library_manager = PasswordLibraryManager()
        
        # Animation elements
        self.particles = []
        self.particle_canvas = None
        
        # Create UI elements
        self.create_ui()
        
        # Start loading default password dictionary in background
        self.load_status_var.set("Searching for password libraries...")
        threading.Thread(target=self.load_default_dictionary, daemon=True).start()
        
        # Setup clipboard notification
        self.clipboard_label = None
        
        # Set timestamp to current time
        current_time = "2025-08-04 08:45:57"  # Use the provided time
        self.update_timestamp(current_time)
        
        # Update username in status bar
        self.update_username("Sree-Ajitha")
    
    def update_timestamp(self, timestamp_str):
        """Update the timestamp in the UI"""
        self.timestamp_var.set(f"Last updated: {timestamp_str}")
        
    def update_username(self, username):
        """Update the username in the status bar"""
        if hasattr(self, 'username_var'):
            self.username_var.set(f"User: {username}")
    
    def create_ui(self):
        # Configure styles for ttk widgets
        self.configure_styles()
        
        # Main container
        main_container = ttk.Frame(self.root, style="Main.TFrame")
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Header with logo/icon and title
        header_frame = ttk.Frame(main_container, style="Header.TFrame")
        header_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Logo/Icon - Create a simple "key" icon using Canvas
        canvas_size = 40
        logo_canvas = tk.Canvas(header_frame, width=canvas_size, height=canvas_size, 
                               bg="#f5f5f7", highlightthickness=0)
        logo_canvas.pack(side=tk.LEFT, padx=(0, 10))
        
        # Draw a key icon
        self.draw_key_icon(logo_canvas, canvas_size)
        
        # Title and subtitle
        title_frame = ttk.Frame(header_frame, style="Header.TFrame")
        title_frame.pack(side=tk.LEFT)
        
        title_label = ttk.Label(
            title_frame, 
            text="Password Strength Analyzer", 
            font=("Helvetica", 18, "bold"),
            style="Title.TLabel"
        )
        title_label.pack(anchor=tk.W)
        
        subtitle_label = ttk.Label(
            title_frame, 
            text="Check your password against common dictionaries and security standards", 
            font=("Helvetica", 10),
            style="Subtitle.TLabel"
        )
        subtitle_label.pack(anchor=tk.W)
        
        # Date/time display on right side of header
        self.timestamp_var = tk.StringVar(value="Last updated: 2025-08-04 08:45:57")
        time_label = ttk.Label(
            header_frame, 
            textvariable=self.timestamp_var,
            font=("Helvetica", 9),
            style="Time.TLabel"
        )
        time_label.pack(side=tk.RIGHT, padx=5)
        
        # Main content notebook for tabs
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create tabs
        analyzer_tab = ttk.Frame(self.notebook, style="Tab.TFrame")
        library_tab = ttk.Frame(self.notebook, style="Tab.TFrame")
        
        self.notebook.add(analyzer_tab, text="Password Analyzer")
        self.notebook.add(library_tab, text="Library Manager")
        
        # ----------- PASSWORD ANALYZER TAB -----------
        # Password entry section with card-like appearance
        input_card = ttk.Frame(analyzer_tab, style="Card.TFrame")
        input_card.pack(fill=tk.X, padx=10, pady=10)
        
        # Password entry header
        entry_header = ttk.Frame(input_card, style="Card.TFrame")
        entry_header.pack(fill=tk.X, padx=15, pady=(15, 5))
        
        ttk.Label(entry_header, text="Enter Your Password", 
                 font=("Helvetica", 12, "bold"), style="Card.TLabel").pack(anchor=tk.W)
        
        # Password input with icon
        input_frame = ttk.Frame(input_card, style="Card.TFrame")
        input_frame.pack(fill=tk.X, padx=15, pady=(0, 15))
        
        # Key icon for password field
        password_icon = tk.Canvas(input_frame, width=20, height=20, bg="#ffffff", highlightthickness=0)
        password_icon.pack(side=tk.LEFT, padx=(0, 10))
        self.draw_lock_icon(password_icon, 20)
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(
            input_frame, 
            textvariable=self.password_var, 
            show="•", 
            width=40, 
            font=("Helvetica", 12),
            style="Password.TEntry"
        )
        self.password_entry.pack(side=tk.LEFT, padx=(0, 10), fill=tk.X, expand=True)
        self.password_entry.bind("<KeyRelease>", lambda e: self.check_password())
        
        # Button container for password actions
        password_actions = ttk.Frame(input_frame, style="Card.TFrame")
        password_actions.pack(side=tk.RIGHT)
        
        # Toggle password visibility
        self.show_password = tk.BooleanVar(value=False)
        self.show_password_check = ttk.Checkbutton(
            password_actions, 
            text="Show Password", 
            variable=self.show_password,
            command=self.toggle_password_visibility,
            style="TCheckbutton"
        )
        self.show_password_check.pack(side=tk.LEFT, padx=(0, 10))
        
        # Copy to clipboard button
        self.copy_button = GlowingButton(
            password_actions, 
            text="Copy", 
            command=self.copy_to_clipboard,
            width=60,
            height=30
        )
        self.copy_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Check button - using custom animated button
        self.check_button = GlowingButton(
            password_actions, 
            text="Analyze", 
            command=self.check_password,
            width=100,
            height=30
        )
        self.check_button.pack(side=tk.LEFT)
        
        # Results section
        results_card = ttk.Frame(analyzer_tab, style="Card.TFrame")
        results_card.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Strength meter section
        meter_frame = ttk.Frame(results_card, style="Card.TFrame")
        meter_frame.pack(fill=tk.X, padx=15, pady=15)
        
        ttk.Label(meter_frame, text="Password Strength:", 
                 style="Card.TLabel").pack(side=tk.LEFT, padx=(0, 10))
        
        self.strength_var = tk.StringVar(value="Not checked")
        self.strength_label = ttk.Label(
            meter_frame, 
            textvariable=self.strength_var, 
            font=("Helvetica", 12, "bold"),
            style="Strength.TLabel"
        )
        self.strength_label.pack(side=tk.LEFT, padx=(0, 10))
        
        self.meter_var = tk.DoubleVar(value=0)
        self.strength_meter = ttk.Progressbar(
            meter_frame, 
            variable=self.meter_var, 
            length=300, 
            mode="determinate",
            style="Strength.Horizontal.TProgressbar"
        )
        self.strength_meter.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        # Time to crack estimate
        self.crack_time_var = tk.StringVar(value="Time to crack: Not calculated")
        crack_time_label = ttk.Label(
            meter_frame, 
            textvariable=self.crack_time_var,
            font=("Helvetica", 9),
            style="Card.TLabel"
        )
        crack_time_label.pack(side=tk.RIGHT)
        
        # Results text area with fancy header
        results_header = ttk.Frame(results_card, style="Card.TFrame")
        results_header.pack(fill=tk.X, padx=15, pady=(0, 5))
        
        ttk.Label(results_header, text="Analysis Results", 
                 font=("Helvetica", 12, "bold"), style="Card.TLabel").pack(anchor=tk.W)
        
        # Create canvas for particle animations
        self.particle_canvas = tk.Canvas(results_card, height=20, highlightthickness=0, bg="#ffffff")
        self.particle_canvas.pack(fill=tk.X, padx=15)
        
        # Results text with custom styling
        results_container = ttk.Frame(results_card, style="Card.TFrame", padding=(15, 0, 15, 15))
        results_container.pack(fill=tk.BOTH, expand=True)
        
        self.results_text = scrolledtext.ScrolledText(
            results_container, 
            height=10, 
            wrap=tk.WORD, 
            font=("Helvetica", 11),
            borderwidth=1,
            relief=tk.SOLID
        )
        self.results_text.pack(fill=tk.BOTH, expand=True)
        self.results_text.config(state=tk.DISABLED)
        
        # ----------- LIBRARY MANAGER TAB -----------
        # Available libraries section
        libraries_frame = ttk.Frame(library_tab, style="Card.TFrame")
        libraries_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        lib_header = ttk.Frame(libraries_frame, style="Card.TFrame")
        lib_header.pack(fill=tk.X, padx=15, pady=(15, 5))
        
        ttk.Label(lib_header, text="Password Libraries", 
                 font=("Helvetica", 12, "bold"), style="Card.TLabel").pack(side=tk.LEFT)
        
        # Select library button
        select_lib_button = GlowingButton(
            lib_header, 
            text="Select Library", 
            command=self.select_library,
            width=120,
            height=30
        )
        select_lib_button.pack(side=tk.RIGHT)
        
        # Library manager section - Split into two parts
        lib_container = ttk.Frame(libraries_frame, style="Card.TFrame")
        lib_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Left: Local libraries
        local_frame = ttk.LabelFrame(lib_container, text="Local Libraries", style="Card.TLabelframe")
        local_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Local libraries list with scrollbar
        local_scroll = ttk.Scrollbar(local_frame)
        local_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.local_libs_list = ttk.Treeview(
            local_frame,
            columns=("name", "size", "entries"),
            show="headings",
            selectmode="browse",
            height=10
        )
        self.local_libs_list.pack(fill=tk.BOTH, expand=True)
        
        self.local_libs_list.heading("name", text="Library Name")
        self.local_libs_list.heading("size", text="Size")
        self.local_libs_list.heading("entries", text="Entries")
        
        self.local_libs_list.column("name", width=150)
        self.local_libs_list.column("size", width=70, anchor="center")
        self.local_libs_list.column("entries", width=100, anchor="center")
        
        local_scroll.config(command=self.local_libs_list.yview)
        self.local_libs_list.config(yscrollcommand=local_scroll.set)
        
        # Button to load selected library
        load_lib_frame = ttk.Frame(local_frame, style="Card.TFrame")
        load_lib_frame.pack(fill=tk.X, pady=10)
        
        load_lib_button = ttk.Button(
            load_lib_frame, 
            text="Load Selected Library", 
            command=self.load_selected_library,
            style="Accent.TButton"
        )
        load_lib_button.pack(side=tk.RIGHT)
        
        refresh_button = ttk.Button(
            load_lib_frame, 
            text="Refresh", 
            command=self.refresh_local_libraries,
            style="TButton"
        )
        refresh_button.pack(side=tk.LEFT)
        
        # Right: Download libraries
        download_frame = ttk.LabelFrame(lib_container, text="Download Libraries", style="Card.TLabelframe")
        download_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Download libraries list
        download_scroll = ttk.Scrollbar(download_frame)
        download_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.download_libs_list = ttk.Treeview(
            download_frame,
            columns=("name", "size", "format"),
            show="headings",
            selectmode="browse",
            height=10
        )
        self.download_libs_list.pack(fill=tk.BOTH, expand=True)
        
        self.download_libs_list.heading("name", text="Library Name")
        self.download_libs_list.heading("size", text="Size")
        self.download_libs_list.heading("format", text="Format")
        
        self.download_libs_list.column("name", width=150)
        self.download_libs_list.column("size", width=70, anchor="center")
        self.download_libs_list.column("format", width=70, anchor="center")
        
        download_scroll.config(command=self.download_libs_list.yview)
        self.download_libs_list.config(yscrollcommand=download_scroll.set)
        
        # Download button and progress
        download_controls = ttk.Frame(download_frame, style="Card.TFrame")
        download_controls.pack(fill=tk.X, pady=10)
        
        self.download_progress = AnimatedProgressbar(
            download_controls, 
            mode="determinate", 
            length=200
        )
        self.download_progress.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        download_button = ttk.Button(
            download_controls,
            text="Download Selected",
            command=self.download_selected_library,
            style="Accent.TButton"
        )
        download_button.pack(side=tk.RIGHT)
        
        # Status bar with signature and username
        status_bar = ttk.Frame(self.root, style="StatusBar.TFrame")
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        
        # Left side - status message
        self.load_status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(status_bar, textvariable=self.load_status_var, anchor=tk.W, style="Status.TLabel")
        status_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        # Center - username
        self.username_var = tk.StringVar(value="User: Not set")
        username_label = ttk.Label(
            status_bar, 
            textvariable=self.username_var,
            font=("Helvetica", 9),
            foreground="#666666",
            background="#f0f0f0"
        )
        username_label.pack(side=tk.LEFT, padx=10, pady=5, expand=True)
        
        # Right side - signature
        signature_label = ttk.Label(
            status_bar, 
            text="created by TooT", 
            font=("Helvetica", 9, "italic"),
            foreground="#666666",
            background="#f0f0f0"
        )
        signature_label.pack(side=tk.RIGHT, padx=10, pady=5)
        
        # Populate library lists
        self.populate_download_libraries()
        self.refresh_local_libraries()
        
        # Set up particle animation system
        self.setup_particle_animation()
    
    def copy_to_clipboard(self):
        """Copy the current password to clipboard"""
        password = self.password_var.get()
        
        if not password:
            self.show_clipboard_notification("No password to copy", "#F44336")
            return
            
        # Copy to clipboard
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        
        # Show notification
        self.show_clipboard_notification("Password copied to clipboard!", "#4CAF50")
    
    def show_clipboard_notification(self, message, color="#4CAF50"):
        """Show a temporary notification for clipboard actions"""
        # Remove any existing notification
        if self.clipboard_label:
            self.clipboard_label.destroy()
            
        # Create notification frame
        notification = tk.Frame(self.root, bg=color, padx=10, pady=5)
        notification.place(relx=0.5, rely=0.1, anchor="center")
        
        # Add message
        self.clipboard_label = tk.Label(
            notification,
            text=message,
            fg="white",
            bg=color,
            font=("Helvetica", 11)
        )
        self.clipboard_label.pack()
        
        # Schedule removal
        self.root.after(1500, lambda: notification.destroy())
        
    def configure_styles(self):
        style = ttk.Style()
        
        # Main styles
        style.configure("Main.TFrame", background="#f5f5f7")
        style.configure("Header.TFrame", background="#f5f5f7")
        style.configure("Tab.TFrame", background="#ffffff")
        style.configure("Card.TFrame", background="#ffffff")
        
        # Card with subtle shadow appearance
        style.configure("Card.TLabelframe", background="#ffffff")
        style.configure("Card.TLabelframe.Label", background="#ffffff", font=("Helvetica", 11, "bold"))
        
        # Label styles
        style.configure("Title.TLabel", background="#f5f5f7", foreground="#333333")
        style.configure("Subtitle.TLabel", background="#f5f5f7", foreground="#666666")
        style.configure("Time.TLabel", background="#f5f5f7", foreground="#666666")
        style.configure("Card.TLabel", background="#ffffff")
        style.configure("Strength.TLabel", background="#ffffff")
        style.configure("Status.TLabel", background="#f0f0f0", foreground="#555555")
        
        # Button styles
        style.configure("Accent.TButton", font=("Helvetica", 10, "bold"))
        style.configure("TButton", font=("Helvetica", 10))
        
        # Status bar style
        style.configure("StatusBar.TFrame", background="#f0f0f0")
        
        # Progressbar styles
        style.configure("Strength.Horizontal.TProgressbar", background="#1976D2")
    
    def draw_key_icon(self, canvas, size):
        # Draw key icon
        canvas.create_oval(5, 10, 25, 30, fill="#1976D2", outline="#1565C0", width=2)
        canvas.create_rectangle(22, 17, 38, 23, fill="#1976D2", outline="#1565C0", width=2)
        canvas.create_rectangle(30, 15, 33, 18, fill="#ffffff", outline="")
        canvas.create_rectangle(35, 19, 38, 22, fill="#ffffff", outline="")
    
    def draw_lock_icon(self, canvas, size):
        # Simple lock icon
        s = size
        canvas.create_rectangle(s*0.25, s*0.45, s*0.75, s*0.9, fill="#666666", outline="#444444")
        canvas.create_arc(s*0.3, s*0.2, s*0.7, s*0.6, start=0, extent=180, outline="#444444", style="arc", width=2)
    
    def setup_particle_animation(self):
        """Setup particle animation system for visual feedback"""
        self.particles = []
        if self.particle_canvas:
            self.particle_canvas.delete("all")
    
    def animate_particles(self, strength_score):
        """Create and animate particles based on password strength"""
        if not self.particle_canvas:
            return
            
        # Clear existing particles
        self.particles = []
        self.particle_canvas.delete("all")
        
        # Determine particle color based on strength
        if strength_score >= 80:
            colors = ["#4CAF50", "#81C784", "#A5D6A7"]  # Green shades
        elif strength_score >= 60:
            colors = ["#2196F3", "#64B5F6", "#90CAF9"]  # Blue shades
        elif strength_score >= 40:
            colors = ["#FFC107", "#FFD54F", "#FFE082"]  # Yellow/amber shades
        elif strength_score >= 20:
            colors = ["#FF9800", "#FFB74D", "#FFCC80"]  # Orange shades
        else:
            colors = ["#F44336", "#E57373", "#EF9A9A"]  # Red shades
        
        # Create particles based on strength
        canvas_width = self.particle_canvas.winfo_width()
        num_particles = int(strength_score / 10)  # 0-10 particles based on strength
        
        for i in range(num_particles):
            x = random.randint(5, canvas_width-5)
            y = random.randint(5, 15)
            size = random.randint(3, 6)
            color = random.choice(colors)
            
            particle = {
                'id': self.particle_canvas.create_oval(x-size, y-size, x+size, y+size, fill=color, outline=""),
                'vx': random.uniform(-0.5, 0.5),
                'vy': random.uniform(-0.2, 0.2),
                'life': random.randint(20, 40)
            }
            self.particles.append(particle)
        
        if self.particles:
            self.update_particles()
    
    def update_particles(self):
        """Update particle positions and properties"""
        if not self.particles or not self.particle_canvas:
            return
            
        still_alive = False
        canvas_width = self.particle_canvas.winfo_width()
        
        for p in self.particles:
            if p['life'] > 0:
                # Update position
                self.particle_canvas.move(p['id'], p['vx'], p['vy'])
                
                # Apply "gravity" effect
                p['vy'] += 0.05
                
                # Reduce life
                p['life'] -= 1
                
                # Fade out
                opacity = min(1.0, p['life'] / 20.0)
                self.particle_canvas.itemconfig(p['id'], fill=self.adjust_color_opacity(
                    self.particle_canvas.itemcget(p['id'], 'fill'), opacity))
                
                still_alive = True
        
        # Clean up dead particles
        self.particles = [p for p in self.particles if p['life'] > 0]
        
        if still_alive:
            self.particle_canvas.after(50, self.update_particles)
    
    def adjust_color_opacity(self, color, opacity):
        """Adjust color opacity for particle fade effect"""
        if color.startswith('#') and len(color) == 7:
            # Convert hex to RGB
            r = int(color[1:3], 16)
            g = int(color[3:5], 16)
            b = int(color[5:7], 16)
            
            # Apply opacity
            r = int(r * opacity + 255 * (1 - opacity))
            g = int(g * opacity + 255 * (1 - opacity))
            b = int(b * opacity + 255 * (1 - opacity))
            
            return f"#{r:02x}{g:02x}{b:02x}"
        return color
    
    def toggle_password_visibility(self):
        self.password_entry.config(show="" if self.show_password.get() else "•")
    
    def load_default_dictionary(self):
        """Try to load a default password dictionary"""
        # First check for rockyou.txt in various locations
        rockyou_paths = [
            Path("rockyou.txt"),
            Path("password_libraries/rockyou.txt"),
            Path("/usr/share/wordlists/rockyou.txt"),  # Common Linux path
            Path.home() / "wordlists/rockyou.txt"
        ]
        
        for path in rockyou_paths:
            if path.exists():
                self.password_dict_path = str(path)
                self.root.after(0, lambda: self.load_status_var.set(f"Found password library: {path.name}"))
                self.load_password_dict(str(path))
                return
        
        # Then check for any text files in the libraries folder
        libraries_dir = Path("password_libraries")
        if libraries_dir.exists():
            for path in libraries_dir.glob("*.txt"):
                self.password_dict_path = str(path)
                self.root.after(0, lambda: self.load_status_var.set(f"Found password library: {path.name}"))
                self.load_password_dict(str(path))
                return
        
        # If no dictionaries found, use minimal fallback
        self.root.after(0, lambda: self.load_status_var.set("No password libraries found. Using minimal default list."))
        self.common_passwords = {"123456", "password", "admin", "qwerty", "welcome", "12345678", 
                                "football", "baseball", "123456789", "test", "princess", "dragon"}
        self.loading_complete = True
    
    def load_password_dict(self, path=None):
        """Load a password dictionary from file"""
        if path is None and not self.password_dict_path:
            self.common_passwords = {"123456", "password", "admin", "qwerty", "welcome"}
            self.loading_complete = True
            return
            
        dict_path = path if path else self.password_dict_path
        
        try:
            # Update load status
            self.root.after(0, lambda: self.load_status_var.set(f"Loading library: {Path(dict_path).name}"))
            
            # Read the file line by line to handle large files
            start_time = time.time()
            count = 0
            self.common_passwords = set()
            
            with open(dict_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    pwd = line.strip()
                    if pwd:  # Skip empty lines
                        self.common_passwords.add(pwd.lower())
                        count += 1
                        
                        # Update status occasionally
                        if count % 100000 == 0:
                            self.root.after(0, lambda c=count: self.load_status_var.set(f"Loading... {c:,} passwords"))
            
            elapsed = time.time() - start_time
            self.loading_complete = True
            self.password_dict_path = dict_path
            self.root.after(0, lambda: self.load_status_var.set(
                f"Library loaded: {len(self.common_passwords):,} passwords from {Path(dict_path).name} ({elapsed:.1f}s)"
            ))
        except Exception as e:
            self.root.after(0, lambda: self.load_status_var.set(f"Error loading library: {str(e)}"))
            # Use fallback minimal list
            self.common_passwords = {"123456", "password", "admin", "qwerty", "welcome", "12345678"}
            self.loading_complete = True
    
    def select_library(self):
        """Open file dialog to select a password library"""
        file_path = filedialog.askopenfilename(
            title="Select Password Library",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            initialdir=str(self.library_manager.libraries_dir)
        )
        
        if file_path:
            self.password_dict_path = file_path
            self.loading_complete = False
            self.common_passwords = set()
            self.load_status_var.set(f"Loading library: {Path(file_path).name}")
            threading.Thread(target=lambda: self.load_password_dict(file_path), daemon=True).start()
    
    def check_password(self):
        password = self.password_var.get()
        
        if not password:
            self.update_results("Please enter a password to check.", [], 0)
            return
        
        # Wait for dictionary to load if not loaded yet
        if not self.loading_complete:
            self.update_results(
                "Library is still loading. Please wait a moment...",
                ["Dictionary loading in progress. Results may be incomplete."],
                0
            )
        
        # Check password strength
        errors = []
        recommendations = []
        strengths = []
        score = 100  # Start with perfect score and deduct
        
        # Check length
        if len(password) < 8:
            errors.append("❌ Too short (minimum 8 characters)")
            score -= 30
            recommendations.append("• Use at least 8 characters")
        elif len(password) >= 16:
            strengths.append("✓ Excellent length (16+ characters)")
            score += 5  # Bonus for extra length
        elif len(password) >= 12:
            strengths.append("✓ Good length (12+ characters)")
        
        # Check for common password
        if password.lower() in self.common_passwords:
            errors.append("❌ CRITICAL: Password found in common password dictionary!")
            score -= 70
            recommendations.append("• Avoid using known common passwords")
        
        # Check for repeating characters
        if re.search(r"(.)\1{2,}", password):
            errors.append("❌ Contains repeating characters (e.g., 'aaa')")
            score -= 15
            recommendations.append("• Avoid repeating characters")
        
        # Check character diversity
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        diversity_score = sum([has_upper, has_lower, has_digit, has_special])
        
        if diversity_score >= 4:
            strengths.append("✓ Excellent character diversity (all character types)")
        elif diversity_score >= 3:
            strengths.append("✓ Good character diversity")
        
        if not has_upper:
            recommendations.append("• Add uppercase letters (A-Z)")
            score -= 10
        
        if not has_lower:
            recommendations.append("• Add lowercase letters (a-z)")
            score -= 10
        
        if not has_digit:
            recommendations.append("• Add numbers (0-9)")
            score -= 10
        
        if not has_special:
            recommendations.append("• Add special characters (!@#$%^&*)")
            score -= 10
        
        # Detect sequences
        if re.search(r"(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)", password.lower()):
            errors.append("❌ Contains alphabetic sequence")
            score -= 15
            recommendations.append("• Avoid sequential letters")
        
        if re.search(r"(123|234|345|456|567|678|789|890)", password):
            errors.append("❌ Contains numeric sequence")
            score -= 15
            recommendations.append("• Avoid sequential numbers")
            
        # Keyboard patterns (simplified)
        keyboard_patterns = ["qwerty", "asdfgh", "zxcvbn", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
        for pattern in keyboard_patterns:
            if pattern in password.lower():
                errors.append("❌ Contains keyboard pattern")
                score -= 20
                recommendations.append("• Avoid keyboard patterns")
                break
        
        # Calculate entropy
        char_set_size = 0
        if has_lower: char_set_size += 26
        if has_upper: char_set_size += 26
        if has_digit: char_set_size += 10
        if has_special: char_set_size += 33  # Approximate
        
        if char_set_size > 0:
            entropy = len(password) * (char_set_size.bit_length() - 1)
            if entropy >= 60:
                strengths.append(f"✓ High entropy (~{entropy} bits)")
            elif entropy >= 40:
                strengths.append(f"✓ Good entropy (~{entropy} bits)")
        
        # Calculate final score (ensure it's between 0-100)
        score = max(0, min(100, score))
        
        # Calculate time to crack (very rough estimate)
        time_to_crack = self.estimate_crack_time(password, has_upper, has_lower, has_digit, has_special)
        self.crack_time_var.set(f"Time to crack: {time_to_crack}")
        
        # Determine strength level
        strength_level = ""
        if score >= 80:
            strength_level = "Very Strong"
            color = "#2E7D32"  # Dark green
        elif score >= 60:
            strength_level = "Strong"
            color = "#4CAF50"  # Green
        elif score >= 40:
            strength_level = "Moderate"
            color = "#FFC107"  # Amber/yellow
        elif score >= 20:
            strength_level = "Weak"
            color = "#FF9800"  # Orange
        else:
            strength_level = "Very Weak"
            color = "#F44336"  # Red
        
        # Update the UI
        feedback = []
        
        if strengths:
            feedback.append("Strengths:")
            feedback.extend(strengths)
            feedback.append("")
            
        if errors:
            feedback.append("Weaknesses:")
            feedback.extend(errors)
            feedback.append("")
        
        if recommendations:
            feedback.append("Recommendations:")
            feedback.extend(recommendations)
        
        self.update_results(f"Password Strength: {strength_level}", feedback, score, color)
        
        # Trigger particle animation
        self.animate_particles(score)
    
    def estimate_crack_time(self, password, has_upper, has_lower, has_digit, has_special):
        """Estimate time to crack password (very simplified)"""
        # Calculate possible combinations
        char_set_size = 0
        if has_lower: char_set_size += 26
        if has_upper: char_set_size += 26
        if has_digit: char_set_size += 10
        if has_special: char_set_size += 33  # Approximate
        
        if char_set_size == 0:
            char_set_size = 26  # Fallback
        
        # Estimated guesses per second for various attack scenarios
        online_attack_speed = 100  # guesses/second
        offline_attack_speed = 1_000_000_000  # 1 billion guesses/second
        
        # Calculate combinations
        combinations = char_set_size ** len(password)
        
        # If password is in common dictionary, it's trivial to crack
        if password.lower() in self.common_passwords:
            return "Instantly (found in dictionary)"
        
        # Calculate time for offline attack
        seconds = combinations / offline_attack_speed
        
        # Convert to human readable format
        if seconds < 0.001:
            return "Instantly"
        elif seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 2592000:  # 30 days
            return f"{seconds/86400:.1f} days"
        elif seconds < 31536000:  # 365 days
            return f"{seconds/2592000:.1f} months"
        elif seconds < 3153600000:  # 100 years
            return f"{seconds/31536000:.1f} years"
        else:
            return "Centuries"
    
    def update_results(self, heading_text="", feedback_list=None, strength_score=0, color="#000000"):
        # Update strength meter
        self.meter_var.set(strength_score)
        self.strength_var.set(heading_text)
        self.strength_label.configure(foreground=color)
        
        # Update results text
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        
        # Set heading
        self.results_text.insert(tk.END, heading_text + "\n\n", "heading")
        
        # Add feedback items
        if feedback_list:
            for item in feedback_list:
                if item.startswith("✓"):
                    self.results_text.insert(tk.END, item + "\n", "positive")
                elif item.startswith("❌"):
                    self.results_text.insert(tk.END, item + "\n", "negative")
                elif item == "":
                    self.results_text.insert(tk.END, "\n")
                elif item.startswith("Strengths:") or item.startswith("Weaknesses:") or item.startswith("Recommendations:"):
                    self.results_text.insert(tk.END, item + "\n", "section")
                else:
                    self.results_text.insert(tk.END, item + "\n", "feedback")
        
        # Configure text tags
        self.results_text.tag_configure("heading", font=("Helvetica", 12, "bold"), foreground=color)
        self.results_text.tag_configure("section", font=("Helvetica", 11, "bold"))
        self.results_text.tag_configure("feedback", font=("Helvetica", 11))
        self.results_text.tag_configure("positive", font=("Helvetica", 11), foreground="#2E7D32")
        self.results_text.tag_configure("negative", font=("Helvetica", 11), foreground="#C62828")
        
        self.results_text.config(state=tk.DISABLED)
        
        # Change meter color
        self.strength_meter.configure(style=f"Strength.Horizontal.TProgressbar")
        style = ttk.Style()
        style.configure(f"Strength.Horizontal.TProgressbar", background=color)

    def populate_download_libraries(self):
        """Populate the download libraries list"""
        # Clear existing items
        for item in self.download_libs_list.get_children():
            self.download_libs_list.delete(item)
            
        # Add libraries from manager
        libraries = self.library_manager.get_available_libraries()
        for i, lib in enumerate(libraries):
            self.download_libs_list.insert("", "end", values=(lib["name"], lib["size"], lib["format"]))
    
    def refresh_local_libraries(self):
        """Refresh the list of local libraries"""
        # Clear existing items
        for item in self.local_libs_list.get_children():
            self.local_libs_list.delete(item)
            
        # Add local libraries from manager
        libraries = self.library_manager.get_local_libraries()
        for i, lib in enumerate(libraries):
            self.local_libs_list.insert("", "end", values=(lib["name"], lib["size"], lib["estimated_entries"]))
    
    def load_selected_library(self):
        """Load the selected library from the list"""
        selected = self.local_libs_list.selection()
        if not selected:
            messagebox.showinfo("No Selection", "Please select a library to load.")
            return
            
        item = self.local_libs_list.item(selected[0])
        lib_name = item["values"][0]
        lib_path = str(self.library_manager.libraries_dir / lib_name)
        
        # Load the selected library
        self.password_dict_path = lib_path
        self.loading_complete = False
        self.common_passwords = set()
        self.load_status_var.set(f"Loading library: {lib_name}")
        threading.Thread(target=lambda: self.load_password_dict(lib_path), daemon=True).start()
        
        # Switch to password analyzer tab
        self.notebook.select(0)
    
    def download_selected_library(self):
        """Download the selected library from the list"""
        selected = self.download_libs_list.selection()
        if not selected:
            messagebox.showinfo("No Selection", "Please select a library to download.")
            return
            
        item = self.download_libs_list.item(selected[0])
        lib_name = item["values"][0]
        
        # Find the library info
        libraries = self.library_manager.get_available_libraries()
        lib_info = next((lib for lib in libraries if lib["name"] == lib_name), None)
        
        if not lib_info:
            messagebox.showerror("Error", "Library information not found.")
            return
            
        # Start download with progress updates
        self.download_progress.start_animation()
        self.load_status_var.set(f"Downloading {lib_name}...")
        
        # Download in background thread
        threading.Thread(
            target=self.library_manager.download_library,
            args=(lib_info, self.update_download_progress, self.download_complete),
            daemon=True
        ).start()
    
    def update_download_progress(self, percent):
        """Update download progress bar"""
        if percent < 0:
            # Indeterminate progress for extraction
            self.download_progress["value"] = 0
            self.load_status_var.set("Extracting library...")
        else:
            self.download_progress["value"] = percent
            self.load_status_var.set(f"Downloading: {percent}%")
    
    def download_complete(self, success, message):
        """Handle download completion"""
        self.download_progress.stop_animation()
        self.download_progress["value"] = 100 if success else 0
        
        if success:
            self.load_status_var.set(f"Download complete: {message}")
            messagebox.showinfo("Download Complete", "Library downloaded successfully.")
            self.refresh_local_libraries()
        else:
            self.load_status_var.set(f"Download failed: {message}")
            messagebox.showerror("Download Failed", f"Failed to download library: {message}")


if __name__ == "__main__":
    root = tk.Tk()
    root.title("Password Strength Analyzer - created by TooT")
    app = PasswordStrengthApp(root)
    root.mainloop()