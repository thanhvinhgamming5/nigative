import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import zipfile
import os
import re

# (regex, thay thế) - áp dụng theo thứ tự, cho cả tên file lẫn nội dung
SUBS = [
    (re.compile(rb"com[./]zelix[./]klassmaster[./]?", re.I), b""),
    (re.compile(rb"com[./]zelix[./]annotation", re.I), b"annotation"),
    (re.compile(rb"bugs2?@zelix\.com", re.I), b"support"),
    (re.compile(rb"Zelix KlassMaster", re.I), b"the obfuscator"),
    (re.compile(rb"KlassMaster"), b"MainApp"),
    (re.compile(rb"klassMaster"), b"mainApp"),
    (re.compile(rb"klassmaster", re.I), b"mainapp"),
    (re.compile(rb"zkm", re.I), b""),
    (re.compile(rb"zelix", re.I), b""),
]
# dấu "." thừa ở đầu package/import (do lần chạy cũ để lại)
LEADING_DOT = re.compile(rb"^(package|import)(\s+static)?(\s+)\.", re.M)
# "import X;" không có package là lỗi cú pháp Java -> xóa dòng
BARE_IMPORT = re.compile(rb"^import\s+\w+;[ \t]*\r?\n", re.M)

BINARY_EXT = (".png", ".jpg", ".jpeg", ".gif", ".ogg", ".wav", ".mp3",
              ".ttf", ".otf", ".zip", ".jar", ".dll", ".so", ".dylib",
              ".nbt", ".dat", ".bin")


def is_text(name, data):
    if name.lower().endswith(BINARY_EXT):
        return False
    return b"\x00" not in data


def strip_bytes(b):
    total = 0
    for rx, rep in SUBS:
        b, c = rx.subn(rep, b)
        total += c
    return b, total


def strip_name(name):
    return strip_bytes(name.encode("utf-8"))[0].decode("utf-8")


def rewrite_class(data):
    """Ghi lại constant pool, xóa chuỗi trong từng Utf8 và cập nhật độ dài."""
    if data[:4] != b"\xca\xfe\xba\xbe":
        return data, 0
    count = int.from_bytes(data[8:10], "big")
    out = bytearray(data[:10])
    pos = 10
    i = 1
    total = 0
    while i < count:
        tag = data[pos]
        if tag == 1:
            ln = int.from_bytes(data[pos + 1:pos + 3], "big")
            s = data[pos + 3:pos + 3 + ln]
            new, c = strip_bytes(s)
            total += c
            out += b"\x01" + len(new).to_bytes(2, "big") + new
            pos += 3 + ln
        else:
            if tag in (3, 4, 9, 10, 11, 12, 17, 18):
                size = 5
            elif tag in (5, 6):
                size = 9
                i += 1
            elif tag in (7, 8, 16, 19, 20):
                size = 3
            elif tag == 15:
                size = 4
            else:
                return data, 0  # tag lạ, bỏ qua file này cho an toàn
            out += data[pos:pos + size]
            pos += size
        i += 1
    out += data[pos:]
    return bytes(out), total


def clean_data(name, data):
    low = name.lower()
    if low.endswith(".class"):
        return rewrite_class(data)
    if is_text(name, data):
        data, c = strip_bytes(data)
        if low.endswith(".java"):
            data, c2 = LEADING_DOT.subn(rb"\1\2\3", data)
            data, c3 = BARE_IMPORT.subn(b"", data)
            c += c2 + c3
        return data, c
    return data, 0


def process_zip(src, dst, log):
    total = 0
    with zipfile.ZipFile(src, "r") as zin:
        # kiểm tra trùng tên sau khi đổi
        seen = {}
        for item in zin.infolist():
            new = strip_name(item.filename)
            if new in seen and seen[new] != item.filename:
                raise Exception(f"Trùng tên sau khi đổi:\n{seen[new]}\n{item.filename}\n-> {new}")
            seen[new] = item.filename

        with zipfile.ZipFile(dst, "w") as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                new_name = strip_name(item.filename)
                if new_name != item.filename:
                    log(f"[rename] {item.filename} -> {new_name}")
                    total += 1
                if not item.is_dir():
                    data, c = clean_data(item.filename, data)
                    if c:
                        total += c
                        log(f"[{c}] {new_name}")
                zi = zipfile.ZipInfo(new_name, item.date_time)
                zi.external_attr = item.external_attr
                zi.compress_type = item.compress_type
                zout.writestr(zi, data)
    return total


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Remove ZKM")
        self.geometry("560x380")

        self.path = tk.StringVar()
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)

        row = ttk.Frame(frm)
        row.pack(fill="x")
        ttk.Entry(row, textvariable=self.path).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Chọn file...", command=self.browse).pack(side="left", padx=5)

        ttk.Button(frm, text="Xóa ZKM", command=self.run).pack(pady=10)

        self.log_box = tk.Text(frm, state="disabled")
        self.log_box.pack(fill="both", expand=True)

    def log(self, msg):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", msg + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")
        self.update_idletasks()

    def browse(self):
        p = filedialog.askopenfilename(
            filetypes=[("ZIP/JAR", "*.zip *.jar"), ("All", "*.*")]
        )
        if p:
            self.path.set(p)

    def run(self):
        src = self.path.get()
        if not os.path.isfile(src):
            messagebox.showerror("Lỗi", "Chưa chọn file hợp lệ")
            return
        base, ext = os.path.splitext(src)
        dst = base + "_clean" + ext
        try:
            total = process_zip(src, dst, self.log)
            self.log(f"Xong: {total} thay đổi -> {dst}")
            messagebox.showinfo("Xong", f"Đã xử lý {total} thay đổi.\nLưu tại:\n{dst}")
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))


if __name__ == "__main__":
    App().mainloop()