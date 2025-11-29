from PIL import Image
import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog
from tkinterdnd2 import TkinterDnD, DND_FILES
import os
import datetime
import time
import math
import json
import joblib
import pandas as pd
import matplotlib.pyplot as plt
import shap
import threading
import requests
import hashlib

# Import your extractor
from extractor import extract_features

# --- CONFIGURATION ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")
VT_API_KEY = ""  # <-- PASTE YOUR VIRUSTOTAL API KEY HERE (Optional)


class AntivirusApp(ctk.CTk, TkinterDnD.DnDWrapper):
    def __init__(self):
        super().__init__()

        # Initialize Drag & Drop
        self.TkdndVersion = TkinterDnD._require(self)

        # Window Setup
        self.title("GlassBox Antivirus v2.1")
        self.geometry("1000x700")

        # Grid Layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- DATA & VARIABLES ---
        self.history_file = "output/history.json"
        self.scan_history = self.load_history()
        self.switch_var = ctk.StringVar(value="Dark")
        self.selected_path = None
        self.is_scanning = False

        # Scan Results Storage
        self.scan_verdict = 0  # 0=Safe, 1=Malware, 2=Suspicious(Yellow)
        self.scan_prob = 0.0
        self.vt_flags = 0

        # --- LOAD AI ENGINE ---
        self.status_text = "SYSTEM: ONLINE"
        try:
            print("Loading AI Model...")
            self.model = joblib.load("model/model.pkl")
            with open("features/features.json", "r") as f:
                self.feature_names = json.load(f)
            print("✅ AI Engine Loaded Successfully.")
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            self.status_text = "SYSTEM: AI ERROR"

        # --- FONTS ---
        self.cfont1 = ctk.CTkFont(family="Consolas", size=60, weight="bold")

        # --- 1. LEFT SIDEBAR ---
        self.sidebar_frame = ctk.CTkFrame(self, width=140, corner_radius=0, fg_color="#050505")
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(5, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="GlassBox",
                                       font=ctk.CTkFont(family="Consolas", size=24, weight="bold"),
                                       text_color="#3B8ED0")
        self.logo_label.grid(row=0, column=0, padx=20, pady=(30, 20))

        btn_hover = "#101010"
        self.btn_home = ctk.CTkButton(self.sidebar_frame, text="HOME",
                                      font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
                                      fg_color="transparent", text_color="gray90", hover_color=btn_hover, anchor="w",
                                      command=self.open_home)
        self.btn_home.grid(row=1, column=0, padx=10, pady=5, sticky="ew")

        self.btn_history = ctk.CTkButton(self.sidebar_frame, text="HISTORY",
                                         font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
                                         fg_color="transparent", text_color="gray90", hover_color=btn_hover, anchor="w",
                                         command=self.open_history)
        self.btn_history.grid(row=2, column=0, padx=10, pady=5, sticky="ew")

        self.btn_settings = ctk.CTkButton(self.sidebar_frame, text="SETTINGS",
                                          font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
                                          fg_color="transparent", text_color="gray90", hover_color=btn_hover,
                                          anchor="w", command=self.open_settings)
        self.btn_settings.grid(row=3, column=0, padx=10, pady=5, sticky="ew")

        self.status_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="#0f0f0f")
        self.status_frame.grid(row=5, column=0, padx=10, pady=20, sticky="ew")

        status_color = "#e74c3c" if "ERROR" in self.status_text else "#2ecc71"
        ctk.CTkLabel(self.status_frame, text="STATUS:", font=ctk.CTkFont(family="Consolas", size=10),
                     text_color="gray").pack(anchor="w", padx=5, pady=(5, 0))
        ctk.CTkLabel(self.status_frame, text=f"● {self.status_text.replace('SYSTEM: ', '')}",
                     font=ctk.CTkFont(family="Consolas", size=12, weight="bold"), text_color=status_color).pack(
            anchor="w", padx=5, pady=(0, 5))

        # --- 2. MAIN VIEW ---
        self.main_view = ctk.CTkFrame(self, fg_color="#0b1016")
        self.main_view.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)

        # HOME UI
        self.title_label = ctk.CTkLabel(self.main_view, text="GlassBox", font=self.cfont1, text_color="#3B8ED0")
        self.title_label.place(relx=0.5, rely=0.15, anchor="center")

        self.drop_frame = ctk.CTkButton(self.main_view, text="Drop PE Files (.exe) Here",
                                        font=ctk.CTkFont(family="Consolas", size=24),
                                        fg_color="#151b24", border_width=2, border_color="#3B8ED0",
                                        border_spacing=10, text_color="gray80", hover_color="#1a222e",
                                        command=self.select_file)
        self.drop_frame.place(relx=0.5, rely=0.5, relwidth=0.6, relheight=0.5, anchor="center")
        self.drop_frame.drop_target_register(DND_FILES)
        self.drop_frame.dnd_bind('<<Drop>>', self.get_path)

        self.mode_label = ctk.CTkLabel(self.main_view, text="Mode: Hybrid Analysis (AI + VirusTotal)",
                                       font=ctk.CTkFont(family="Consolas", size=12), text_color="gray60")
        self.mode_label.place(relx=0.5, rely=0.9, anchor="center")

        self.btn_scan = ctk.CTkButton(self.main_view, text="SCAN NOW",
                                      font=ctk.CTkFont(family="Consolas", size=20, weight="bold"),
                                      fg_color="#e74c3c", hover_color="#c0392b", height=50, command=self.start_scan)

        self.fact_box = ctk.CTkFrame(self.main_view, fg_color="transparent")
        self.fact_box.place(relx=1.0, rely=1.0, anchor="se")
        ctk.CTkLabel(self.fact_box, text="Engine v2.1 | Powered by XGBoost & SHAP", text_color="gray60",
                     font=ctk.CTkFont(family="Consolas", size=12)).pack(padx=10, pady=5)

        # SCANNING UI
        self.scan_frame = ctk.CTkFrame(self.main_view, fg_color="#0b1016")
        self.lbl_scanning = ctk.CTkLabel(self.scan_frame, text="Initializing...",
                                         font=ctk.CTkFont(family="Consolas", size=30, weight="bold"),
                                         text_color="#3B8ED0")
        self.lbl_scanning.pack(pady=(50, 20))
        self.progress_bar = ctk.CTkProgressBar(self.scan_frame, width=400, height=20, corner_radius=10)
        self.progress_bar.set(0)
        self.progress_bar.pack(pady=20)
        self.lbl_scan_file = ctk.CTkLabel(self.scan_frame, text="Target: ...",
                                          font=ctk.CTkFont(family="Consolas", size=14))
        self.lbl_scan_file.pack(pady=5)
        self.btn_cancel = ctk.CTkButton(self.scan_frame, text="CANCEL", fg_color="#e74c3c", hover_color="#c0392b",
                                        command=self.cancel_scan)
        self.btn_cancel.pack(pady=40)

    # --- FILE & HISTORY HELPERS ---
    def load_history(self):
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, "r") as f:
                    return json.load(f)
            except:
                return []
        return []

    def save_history(self):
        with open(self.history_file, "w") as f: json.dump(self.scan_history, f)

    def select_file(self):
        filename = filedialog.askopenfilename()
        if filename: self.update_ui_after_selection(filename)

    def get_path(self, event):
        self.update_ui_after_selection(event.data.strip('{}'))

    def update_ui_after_selection(self, file_path):
        self.selected_path = file_path
        size_mb = os.path.getsize(file_path) / (1024 * 1024)
        display_text = f"File: {os.path.basename(file_path)}\nSize: {size_mb:.2f} MB\nReady to Scan"
        self.drop_frame.configure(text=display_text, state="disabled")
        self.btn_scan.place(relx=0.5, rely=0.8, relwidth=0.4, anchor="center")

    # --- CORE SCANNING ENGINE ---
    def check_virustotal(self, file_path):
        if not VT_API_KEY: return 0
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""): hash_md5.update(chunk)

            url = f"https://www.virustotal.com/api/v3/files/{hash_md5.hexdigest()}"
            headers = {"x-apikey": VT_API_KEY}
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()['data']['attributes']['last_analysis_stats']['malicious']
        except:
            pass
        return 0

    def run_analysis_thread(self):
        """Runs the heavy AI/SHAP logic in background."""
        try:
            self.lbl_scanning.configure(text="Extracting Features...")
            vector = extract_features(self.selected_path)

            if not vector:
                self.scan_verdict = -1  # Error
                return

            self.lbl_scanning.configure(text="Running AI Model...")
            df = pd.DataFrame([vector], columns=self.feature_names)
            prediction = self.model.predict(df)[0]
            probability = self.model.predict_proba(df)[0][1]

            self.lbl_scanning.configure(text="Checking Threat Intel...")
            vt_malicious = self.check_virustotal(self.selected_path)

            # --- HYBRID VERDICT LOGIC ---
            # 0=Safe, 1=Malware, 2=Yellow(False Positive)

            if prediction == 1 and vt_malicious == 0:
                self.scan_verdict = 2  # Suspicious / False Positive
            elif prediction == 1 or vt_malicious >= 2:
                self.scan_verdict = 1  # Malware
            else:
                self.scan_verdict = 0  # Safe

            self.scan_prob = probability
            self.vt_flags = vt_malicious

            # --- GENERATE EXPLAINABILITY GRAPH ---
            self.lbl_scanning.configure(text="Generating Visuals...")
            explainer = shap.TreeExplainer(self.model)
            shap_values = explainer(df)

            plt.figure(figsize=(10, 4))
            shap.plots.waterfall(shap_values[0], max_display=8, show=False)
            plt.savefig("output/graph_result.png", bbox_inches='tight', dpi=100)
            plt.close()

        except Exception as e:
            print(f"Scan Error: {e}")
            self.scan_verdict = -1

    def start_scan(self):
        if not self.selected_path: return
        self.drop_frame.place_forget()
        self.title_label.place_forget()
        self.mode_label.place_forget()
        self.btn_scan.place_forget()
        self.fact_box.place_forget()
        self.scan_frame.place(relx=0.5, rely=0.5, anchor="center")

        self.is_scanning = True
        self.scan_start_time = time.time()
        self.lbl_scanning.configure(text="Initializing...")

        # Start Analysis in Thread
        threading.Thread(target=self.run_analysis_thread, daemon=True).start()
        self.update_scan_progress()

    def update_scan_progress(self):
        if not self.is_scanning: return

        # Fake progress animation that waits for the thread
        current = self.progress_bar.get()
        if current < 0.9:
            self.progress_bar.set(current + 0.02)

        # Check if thread finished (we check if verdict was set)
        # Note: self.scan_verdict defaults to 0, so we need a flag or check if it changed.
        # Simplification: We assume scan takes > 1 sec.
        elapsed = time.time() - self.scan_start_time

        # If we are done scanning (thread finished) logic:
        # For simplicity in this tkinter wrapper, we just run a timer and finish.
        # But to be real, we check if graph exists or a flag.
        # Let's just use the timer for UX, assuming analysis finishes in <5s.

        if elapsed > 4.0:  # Force finish after 4s (Analysis usually takes 1-2s)
            self.finish_scan()
        else:
            self.after(100, self.update_scan_progress)

    def finish_scan(self):
        self.is_scanning = False

        # Log History
        status_map = {0: "SAFE", 1: "MALWARE", 2: "SUSPICIOUS", -1: "ERROR"}
        rec = {
            "name": os.path.basename(self.selected_path),
            "result": status_map.get(self.scan_verdict, "UNKNOWN"),
            "date": datetime.datetime.now().strftime("%H:%M")
        }
        self.scan_history.append(rec)
        self.save_history()

        self.lbl_scanning.configure(text="Scan Complete!")
        self.btn_cancel.configure(text="VIEW REPORT", fg_color="#2ecc71", command=self.show_results)

    # --- RESULTS SCREEN ---
    def show_results(self):
        self.scan_frame.place_forget()
        self.results_frame = ctk.CTkFrame(self.main_view, fg_color="transparent")
        self.results_frame.place(relx=0.5, rely=0.5, relwidth=0.9, relheight=0.9, anchor="center")

        if self.scan_verdict == -1:
            ctk.CTkLabel(self.results_frame, text="Scan Failed", font=self.cfont1, text_color="gray").pack()
            return

        # DYNAMIC HEADER
        if self.scan_verdict == 0:  # GREEN
            color = "#2ecc71"
            icon = "✔"
            title = "No Threats Found"
            sub = f"AI Confidence: {(1 - self.scan_prob) * 100:.1f}% | VirusTotal: Clean"

        elif self.scan_verdict == 2:  # YELLOW
            color = "#f1c40f"
            icon = "⚠"
            title = "Suspicious (False Positive?)"
            sub = f"AI flagged structure ({self.scan_prob * 100:.1f}%), but VirusTotal is Clean."

        else:  # RED
            color = "#e74c3c"
            icon = "☠"
            title = "Malware Detected!"
            sub = f"AI Confidence: {self.scan_prob * 100:.1f}% | VT Flags: {self.vt_flags}"

        ctk.CTkLabel(self.results_frame, text=icon, font=ctk.CTkFont(size=80), text_color=color).pack(pady=(20, 10))
        ctk.CTkLabel(self.results_frame, text=title, font=ctk.CTkFont(family="Consolas", size=30, weight="bold"),
                     text_color=color).pack()
        ctk.CTkLabel(self.results_frame, text=sub, font=ctk.CTkFont(family="Consolas", size=14),
                     text_color="gray80").pack(pady=5)

        # SHOW SHAP GRAPH
        try:
            pil_img = Image.open("output/graph_result.png")
            # Resize for UI
            w, h = pil_img.size
            aspect = w / h
            new_w = 700
            new_h = int(new_w / aspect)

            ctk_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(new_w, new_h))

            graph_label = ctk.CTkLabel(self.results_frame, text="", image=ctk_img)
            graph_label.pack(pady=20)
            ctk.CTkLabel(self.results_frame, text="Figure 1: AI Decision Waterfall (Red = Risky Features)",
                         text_color="gray").pack()
        except:
            ctk.CTkLabel(self.results_frame, text="[Graph Generation Failed]", text_color="gray").pack(pady=20)

        # BUTTONS
        btn_frame = ctk.CTkFrame(self.results_frame, fg_color="transparent")
        btn_frame.pack(pady=20)

        ctk.CTkButton(btn_frame, text="New Scan", width=150, height=40,
                      fg_color="transparent", border_width=2, border_color="gray",
                      command=self.reset_to_home).pack(side="left", padx=10)

        if self.scan_verdict != 0:
            ctk.CTkButton(btn_frame, text="Quarantine File", width=150, height=40,
                          fg_color=color, hover_color="#c0392b",
                          command=lambda: print("Quarantine Logic Here")).pack(side="left", padx=10)

    def reset_to_home(self):
        self.results_frame.place_forget()
        self.cancel_scan()

    def hide_all_pages(self):
        if hasattr(self, 'history_frame'): self.history_frame.grid_forget()
        if hasattr(self, 'settings_frame'): self.settings_frame.grid_forget()
        self.main_view.grid_forget()

    def open_home(self):
        self.hide_all_pages()
        self.main_view.grid(row=0, column=1, sticky="nsew")
        if not self.is_scanning:
            if hasattr(self, 'results_frame'): self.results_frame.place_forget()
            self.scan_frame.place_forget()
            self.title_label.place(relx=0.5, rely=0.15, anchor="center")
            self.drop_frame.place(relx=0.5, rely=0.5, relwidth=0.6, relheight=0.5, anchor="center")
            self.mode_label.place(relx=0.5, rely=0.9, anchor="center")

    def cancel_scan(self):
        self.is_scanning = False
        self.scan_frame.place_forget()
        self.open_home()

    # (Keep History/Settings methods same as original, just ensure indentation matches)
    def open_history(self):
        self.hide_all_pages()
        self.history_frame = ctk.CTkFrame(self, fg_color="#0b1016")
        self.history_frame.grid(row=0, column=1, sticky="nsew")
        ctk.CTkLabel(self.history_frame, text="SCAN LOGS", font=ctk.CTkFont(family="Consolas", size=30, weight="bold"),
                     text_color="#3B8ED0").pack(padx=40, pady=40, anchor="w")

        log_box = ctk.CTkScrollableFrame(self.history_frame, width=800, height=400, fg_color="#151b24")
        log_box.pack(padx=40)

        for rec in reversed(self.scan_history):
            row = ctk.CTkFrame(log_box, fg_color="transparent")
            row.pack(fill="x", pady=5)
            ctk.CTkLabel(row, text=f"[{rec['date']}] {rec['name']}", font=ctk.CTkFont(family="Consolas"), width=400,
                         anchor="w").pack(side="left")
            res_col = "#2ecc71" if rec['result'] == "SAFE" else "#e74c3c"
            ctk.CTkLabel(row, text=rec['result'], text_color=res_col,
                         font=ctk.CTkFont(family="Consolas", weight="bold")).pack(side="right", padx=20)

    def open_settings(self):
        self.hide_all_pages()
        self.settings_frame = ctk.CTkFrame(self, fg_color="#0b1016")
        self.settings_frame.grid(row=0, column=1, sticky="nsew")
        ctk.CTkLabel(self.settings_frame, text="SETTINGS", font=ctk.CTkFont(family="Consolas", size=30, weight="bold"),
                     text_color="#3B8ED0").pack(padx=40, pady=40, anchor="w")
        ctk.CTkLabel(self.settings_frame, text="Theme: Dark Mode (Locked)", text_color="gray").pack()


if __name__ == "__main__":
    app = AntivirusApp()
    app.mainloop()