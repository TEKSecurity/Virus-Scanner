import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib
import time

# ==========================
# EMBEDDED HASH LIST (SHA-256 ONLY)
# ==========================
BAD_HASHES = {
    # Example hashes (SHA-256 = 64 hex chars)
    "08a2b9403e41abb07afeafe07933a7bae2052899d99f57395b7d7c69b3878c6f",  # test
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # empty file hash
    "335650f270bcbc765de5add883ca3e060ac3f7c02ddabff895fdaaba211becf7",
    "f541b4c456b6c232d9f4c8cdb60aa4c34d19776494a20b78391d2cfe51c826b8",
    "ea496a935dc9ef27c1a122a650f856e6b70770894b8e5aff23d47df7315cde67",
    "050611b09d8a9f4ed8194cbca44de55c7d137b719dc25cfcb309dd22c065704f",
    "a2ace890ae3f56005f269d871e44fbe7b1e20e5a9576771e4f7771ec5fa52853",
    "9c57caf3120b3ce67ab5a52e167f9768997dde1364a1a398ef61fb38ff3ed1f0",
    "1697f4fc2f3a759d63a514c1cfaaca8620dec3e82e066edbabcfac696a160cf4",
    "a30efaa22c253336dfbd6d6cbf89410fec5f69a7a8f6132156462d787d1d42d1",
    "e7215cfcf31712d165344622ef37fc3fd302247c78c81257a394bb8f35c9bf67",
    "7f1a037ae3fa124fe6be3821c4cde3f6d5163c5b9c133a196f8555c5146be832",
    "61f56e3fbf2c77baf532aba5d4457ac47e445f1e87eafb520c0474511a3fb1b3",
    "02d5062ed994db4435ba6fe6c9de9a0a63c7ccf646f24bb2b93e2e3fb457c5d1",
    "1752b5a94eb6f9a5998ed0f031547f34e4ba8e2e97b060949b4e06a96895220c",
    "d5d40fc75fafce97e61a4c0d4d84ff9f5e86f7cc98d25fc5a7046f1c19cd8a39",
    "3f1b15ae29a127d32d201e12bd59560581332442e9b23ecebacba25d1b1d60ff",
    "4aad2a91bbfe76657d9153ec41ba557a798102fabe77f276602deb7b7eaefe74",
    "b52f2d865326664c49fe1b8c22a7f7adeaabb68dbe9df53d71116198a7f837ad",
    "e360cd9e288469993da6cc5960e39865a1e9efbd57f747a86d432c4766baf99e",
    "a8997f7b77f90d348f1a55cde634f4e89a6cbef5f5914391663f31e69a244275",
    "eef6a2be2d108d13d18f38a61013bab9be3290a8a8f1a2ef1b632731367372d0",
    "751e45828a3ff877ed4add1508b3e54463376cfb11f3171bfac160653ca9813c",
    "73f97972cac66adb561c0a531f581ecab089374b482309bd317d952a919761d6",
    "ccecedc198d957c06665e05f3f63fefb2bf8d4a2a583ec976b5924345b84c582",
    "9f1f081198e8305eecc727d7f2f4a7c024ba21378fd2eaadbd2bb44a19d40b25",
    "a919dbcfac1a78d6d52acd328933ab641718b321ba4e8fab734e029cbbbf616a",
    "696cd5c7b0d8f0e3c751cafa60b2fab2a6317b4c6e94f1775321d3d1194b1e42",
    "b4a6f40b680f690eabb3261f12bf411808e2ec93d2f29289c6a2efe4668f76ff",
    "0049bd68937a94dc047a1ad06222fceb30315d6d26546a9a2665453045bd8403",
    "9cba817952b96392497d35e31fe1a64852c9de16ddd3dc5a75b78b2206ed9316",
}

# ==========================
# FILE SCANNING LOGIC
# ==========================
def hash_file(path: str) -> str | None:
    sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return None


def scan_directory(directory: str, on_progress=None):
    hits = []
    scanned = 0
    start = time.perf_counter()

    for root, _, files in os.walk(directory):
        for name in files:
            scanned += 1

            # update UI often, but not every single file
            if on_progress and (scanned == 1 or scanned % 25 == 0):
                elapsed = time.perf_counter() - start
                on_progress(scanned, elapsed)

            full_path = os.path.join(root, name)
            file_hash = hash_file(full_path)
            if file_hash and file_hash.lower() in BAD_HASHES:
                hits.append(full_path)

    if on_progress:
        elapsed = time.perf_counter() - start
        on_progress(scanned, elapsed)

    return hits


# ==========================
# GUI
# ==========================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("TEK Security Scanner (v1)")
        self.geometry("900x550")

        self.target_var = tk.StringVar(value=os.path.expandvars(r"%USERPROFILE%\Downloads"))
        self.status_var = tk.StringVar(value="Ready")

        self.counter_var = tk.StringVar(value="Total Files Scanned: 0")
        self.timer_var = tk.StringVar(value="Elapsed Time: 00:00:00")
        self.speed_var = tk.StringVar(value="Speed: 0 files/sec")

        top = tk.Frame(self)
        top.pack(fill="x", padx=10, pady=10)

        tk.Label(top, text="Target folder:").pack(side="left")
        tk.Entry(top, textvariable=self.target_var, width=70).pack(side="left", padx=8)

        tk.Button(top, text="Browse", command=self.browse).pack(side="left")
        tk.Button(top, text="Scan", command=self.start_scan).pack(side="left", padx=8)

        tk.Label(self, textvariable=self.status_var).pack(anchor="w", padx=10)

        tk.Label(self, textvariable=self.counter_var, font=("Consolas", 14)).pack(fill="x", padx=10, pady=(5, 2))
        tk.Label(self, textvariable=self.timer_var).pack(anchor="w", padx=10)
        tk.Label(self, textvariable=self.speed_var).pack(anchor="w", padx=10, pady=(0, 10))

        self.output = tk.Text(self)
        self.output.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.scanning = False

    def browse(self):
        folder = filedialog.askdirectory()
        if folder:
            self.target_var.set(folder)

    def start_scan(self):
        if self.scanning:
            return

        target = self.target_var.get().strip()
        if not target or not os.path.exists(target):
            messagebox.showerror("Error", "Target folder does not exist.")
            return

        self.scanning = True
        self.status_var.set("Scanning...")

        # reset stats at start
        self.counter_var.set("Total Files Scanned: 0")
        self.timer_var.set("Elapsed Time: 00:00:00")
        self.speed_var.set("Speed: 0 files/sec")

        self.output.delete("1.0", "end")

        t = threading.Thread(target=self.run_scan, args=(target,), daemon=True)
        t.start()

    def run_scan(self, target: str):
        def format_hms(seconds: float) -> str:
            seconds = int(seconds)
            h = seconds // 3600
            m = (seconds % 3600) // 60
            s = seconds % 60
            return f"{h:02d}:{m:02d}:{s:02d}"

        def on_progress(scanned: int, elapsed: float):
            speed = scanned / elapsed if elapsed > 0 else 0.0

            def update_ui():
                self.counter_var.set(f"Total Files Scanned: {scanned:,}")
                self.timer_var.set(f"Elapsed Time: {format_hms(elapsed)}")
                self.speed_var.set(f"Speed: {speed:,.0f} files/sec")

            self.after(0, update_ui)

        hits = scan_directory(target, on_progress=on_progress)

        def finish():
            self.status_var.set(f"Done. Matches: {len(hits)}")
            self.output.delete("1.0", "end")

            if hits:
                self.output.insert("end", "Matches:\n" + "\n".join(hits))
            else:
                self.output.insert("end", "No matches found.")

            self.scanning = False

        self.after(0, finish)


if __name__ == "__main__":
    App().mainloop()
