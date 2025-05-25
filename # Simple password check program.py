import tkinter as tk
from tkinter import messagebox
import json
import os
import hashlib
import datetime

# ----- Hashing Function -----
def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

# ----- Load or Initialize Users -----
if os.path.exists("users.json"):
    try:
        with open("users.json", "r") as f:
            users = json.load(f)
    except json.JSONDecodeError:
        users = {}
else:
    users = {}

# Ensure existing 'admin' account is flagged as admin
if "admin" in users:
    users["admin"]["is_admin"] = True

# ----- UI Style Constants -----
BG_COLOR = "#1e1e1e"
FG_COLOR = "#cccccc"
BTN_COLOR = "#2e2e2e"
BTN_HOVER_COLOR = "#3e3e3e"
ENTRY_BG = "#2a2a2a"
FONT = ("Helvetica", 11)
BTN_WIDTH = 20
TITLE_FONT = ("Helvetica", 16, "bold")
CHAT_FILE = "chat.json"

# ----- Save Users -----
def save_users():
    with open("users.json", "w") as f:
        json.dump(users, f, indent=2)

# ----- Hover Effects -----
def on_enter(e):
    e.widget["background"] = BTN_HOVER_COLOR

def on_leave(e):
    e.widget["background"] = BTN_COLOR

# ----- Create Toggle Button for Show/Hide -----
def create_toggle_button(entry, parent_frame):
    def toggle():
        if entry.cget("show") == "*":
            entry.config(show="")
            btn.config(text="Hide")
        else:
            entry.config(show="*")
            btn.config(text="Show")
    btn = tk.Button(parent_frame, text="Show", command=toggle, width=5, bg=BTN_COLOR, fg=FG_COLOR, font=FONT, relief="flat")
    btn.bind("<Enter>", on_enter)
    btn.bind("<Leave>", on_leave)
    return btn

# ----- Chat Forum Functions -----
def load_chat():
    if os.path.exists(CHAT_FILE):
        try:
            with open(CHAT_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return []
    return []

def save_chat(messages):
    with open(CHAT_FILE, "w") as f:
        json.dump(messages, f, indent=2)

def open_forum(username, is_admin=False):
    forum = tk.Toplevel(root)
    forum.title("User Forum")
    forum.configure(bg=BG_COLOR)
    forum.attributes("-fullscreen", True)
    forum.bind("<Escape>", lambda e: forum.attributes("-fullscreen", False))

    tk.Button(forum, text="Exit Fullscreen", command=lambda: forum.attributes("-fullscreen", False),
              bg=BTN_COLOR, fg=FG_COLOR, font=FONT, relief="flat").pack(pady=5)

    if is_admin:
        admin_frame = tk.Frame(forum, bg=BG_COLOR)
        admin_frame.pack(pady=5)

        def show_users():
            user_list = "\n".join(users.keys())
            messagebox.showinfo("Registered Users", user_list)

        def clear_chat():
            if messagebox.askyesno("Confirm", "Delete all chat messages?"):
                save_chat([])
                text_area.config(state="normal")
                text_area.delete("1.0", "end")
                text_area.config(state="disabled")

        tk.Button(admin_frame, text="Show Users", command=show_users, bg=BTN_COLOR, fg=FG_COLOR, font=FONT, relief="flat").pack(pady=2)
        tk.Button(admin_frame, text="Clear Chat", command=clear_chat, bg=BTN_COLOR, fg=FG_COLOR, font=FONT, relief="flat").pack(pady=2)

    text_frame = tk.Frame(forum, bg=BG_COLOR)
    text_frame.pack(pady=10, padx=10, fill="both", expand=True)

    text_area = tk.Text(text_frame, wrap="word", bg=ENTRY_BG, fg=FG_COLOR, font=FONT, state="disabled", insertbackground=FG_COLOR)
    text_area.pack(side="left", fill="both", expand=True)

    scrollbar = tk.Scrollbar(text_frame, command=text_area.yview)
    scrollbar.pack(side="right", fill="y")
    text_area.config(yscrollcommand=scrollbar.set)

    messages = load_chat()
    text_area.config(state="normal")
    for msg in messages:
        timestamp = msg["timestamp"]
        user = msg["user"]
        content = msg["message"]
        text_area.insert("end", f"[{timestamp}] {user}: {content}\n")
    text_area.config(state="disabled")

    entry = tk.Entry(forum, bg=ENTRY_BG, fg=FG_COLOR, font=FONT, insertbackground=FG_COLOR)
    entry.pack(pady=5, padx=10, fill="x")

    def send_message():
        content = entry.get().strip()
        if not content:
            return
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_msg = {"user": username, "timestamp": timestamp, "message": content}
        messages.append(new_msg)
        save_chat(messages)
        text_area.config(state="normal")
        text_area.insert("end", f"[{timestamp}] {username}: {content}\n")
        text_area.config(state="disabled")
        text_area.see("end")
        entry.delete(0, "end")

    send_btn = tk.Button(forum, text="Send", command=send_message, bg=BTN_COLOR, fg=FG_COLOR, font=FONT, relief="flat")
    send_btn.pack(pady=5)
    forum.bind('<Return>', lambda event: send_message())

# ----- Login Logic -----
def login():
    user = username_entry.get().strip()
    pw = password_entry.get()
    if not user or not pw:
        messagebox.showerror("Error", "Please enter both username and password.")
        return
    if user in users and users[user]["password"] == hash_text(pw):
        messagebox.showinfo("Login", "Login successful!")
        is_admin = users[user].get("is_admin", False)
        open_forum(user, is_admin)
    else:
        messagebox.showerror("Login Failed", "Incorrect username or password.")

# ----- Register Window -----
def register():
    def save_new_user():
        new_user = new_username_entry.get().strip()
        new_pw = new_password_entry.get()
        new_q = question_entry.get().strip()
        new_a = answer_entry.get()

        if not all([new_user, new_pw, new_q, new_a]):
            messagebox.showerror("Error", "All fields must be filled out.")
            return

        if new_user in users:
            messagebox.showerror("Error", "Username already exists.")
        else:
            users[new_user] = {
                "password": hash_text(new_pw),
                "question": new_q,
                "answer": hash_text(new_a),
                "is_admin": False
            }
            save_users()
            messagebox.showinfo("Success", "User registered!")
            register_window.destroy()

    register_window = tk.Toplevel(root)
    register_window.title("Register")
    register_window.configure(bg=BG_COLOR)
    register_window.geometry("400x330")

    tk.Label(register_window, text="Register New User", font=TITLE_FONT, bg=BG_COLOR, fg=FG_COLOR).pack(pady=10)

    frame = tk.Frame(register_window, bg=BG_COLOR)
    frame.pack(pady=5)

    tk.Label(frame, text="Username:", bg=BG_COLOR, fg=FG_COLOR, font=FONT).grid(row=0, column=0, sticky="w", pady=5, padx=10)
    new_username_entry = tk.Entry(frame, bg=ENTRY_BG, fg=FG_COLOR, font=FONT, width=30, insertbackground=FG_COLOR)
    new_username_entry.grid(row=0, column=1, pady=5)

    tk.Label(frame, text="Password:", bg=BG_COLOR, fg=FG_COLOR, font=FONT).grid(row=1, column=0, sticky="w", pady=5, padx=10)
    new_password_entry = tk.Entry(frame, bg=ENTRY_BG, fg=FG_COLOR, font=FONT, width=30, show="*", insertbackground=FG_COLOR)
    new_password_entry.grid(row=1, column=1, pady=5)
    new_pw_toggle = create_toggle_button(new_password_entry, frame)
    new_pw_toggle.grid(row=1, column=2, padx=5)

    tk.Label(frame, text="Security Question:", bg=BG_COLOR, fg=FG_COLOR, font=FONT).grid(row=2, column=0, sticky="w", pady=5, padx=10)
    question_entry = tk.Entry(frame, bg=ENTRY_BG, fg=FG_COLOR, font=FONT, width=30, insertbackground=FG_COLOR)
    question_entry.grid(row=2, column=1, pady=5)

    tk.Label(frame, text="Answer:", bg=BG_COLOR, fg=FG_COLOR, font=FONT).grid(row=3, column=0, sticky="w", pady=5, padx=10)
    answer_entry = tk.Entry(frame, bg=ENTRY_BG, fg=FG_COLOR, font=FONT, width=30, show="*", insertbackground=FG_COLOR)
    answer_entry.grid(row=3, column=1, pady=5)
    answer_toggle = create_toggle_button(answer_entry, frame)
    answer_toggle.grid(row=3, column=2, padx=5)

    register_btn = tk.Button(register_window, text="Register", command=save_new_user, width=BTN_WIDTH, bg=BTN_COLOR, fg=FG_COLOR, font=FONT, relief="flat")
    register_btn.pack(pady=10)
    register_btn.bind("<Enter>", on_enter)
    register_btn.bind("<Leave>", on_leave)

# ----- Forgot Password -----
def forgot_password():
    def verify_user():
        uname = fp_username_entry.get().strip()
        if uname not in users:
            messagebox.showerror("Not Found", "Username not found.")
            return

        def reset():
            ans = answer_entry.get()
            if hash_text(ans) != users[uname]["answer"]:
                messagebox.showerror("Incorrect", "Security answer is wrong.")
                return

            new_pass = new_password_entry.get()
            if not new_pass:
                messagebox.showwarning("Cancelled", "Password reset cancelled.")
                return

            users[uname]["password"] = hash_text(new_pass)
            save_users()
            messagebox.showinfo("Success", "Password has been reset.")
            fp_window.destroy()

        for widget in fp_frame.winfo_children():
            widget.destroy()

        tk.Label(fp_frame, text=users[uname]['question'], bg=BG_COLOR, fg=FG_COLOR, font=FONT).pack(pady=5)
        answer_entry = tk.Entry(fp_frame, show='*', bg=ENTRY_BG, fg=FG_COLOR, font=FONT, insertbackground=FG_COLOR)
        answer_entry.pack(pady=5)

        tk.Label(fp_frame, text="New Password:", bg=BG_COLOR, fg=FG_COLOR, font=FONT).pack(pady=5)
        new_password_entry = tk.Entry(fp_frame, show='*', bg=ENTRY_BG, fg=FG_COLOR, font=FONT, insertbackground=FG_COLOR)
        new_password_entry.pack(pady=5)

        tk.Button(fp_frame, text="Reset Password", command=reset, bg=BTN_COLOR, fg=FG_COLOR, font=FONT, relief="flat").pack(pady=10)

    fp_window = tk.Toplevel(root)
    fp_window.title("Forgot Password")
    fp_window.configure(bg=BG_COLOR)
    fp_window.geometry("350x250")

    fp_frame = tk.Frame(fp_window, bg=BG_COLOR)
    fp_frame.pack(pady=20)

    tk.Label(fp_frame, text="Enter Username:", bg=BG_COLOR, fg=FG_COLOR, font=FONT).pack(pady=5)
    fp_username_entry = tk.Entry(fp_frame, bg=ENTRY_BG, fg=FG_COLOR, font=FONT, insertbackground=FG_COLOR)
    fp_username_entry.pack(pady=5)

    tk.Button(fp_frame, text="Next", command=verify_user, bg=BTN_COLOR, fg=FG_COLOR, font=FONT, relief="flat").pack(pady=10)

# ----- Login Window UI -----
root = tk.Tk()
root.title("Secure Login System")
root.configure(bg=BG_COLOR)
root.geometry("400x300")
root.resizable(False, False)

# Center window on screen
root.update_idletasks()
w = root.winfo_screenwidth()
h = root.winfo_screenheight()
x = (w // 2) - (400 // 2)
y = (h // 2) - (300 // 2)
root.geometry(f"+{x}+{y}")

tk.Label(root, text="LOGIN", font=TITLE_FONT, bg=BG_COLOR, fg=FG_COLOR).pack(pady=15)

form_frame = tk.Frame(root, bg=BG_COLOR)
form_frame.pack(pady=5)

tk.Label(form_frame, text="Username:", bg=BG_COLOR, fg=FG_COLOR, font=FONT).grid(row=0, column=0, sticky="w", pady=5, padx=10)
username_entry = tk.Entry(form_frame, bg=ENTRY_BG, fg=FG_COLOR, font=FONT, width=30, insertbackground=FG_COLOR)
username_entry.grid(row=0, column=1, pady=5)

tk.Label(form_frame, text="Password:", bg=BG_COLOR, fg=FG_COLOR, font=FONT).grid(row=1, column=0, sticky="w", pady=5, padx=10)
password_entry = tk.Entry(form_frame, show="*", bg=ENTRY_BG, fg=FG_COLOR, font=FONT, width=30, insertbackground=FG_COLOR)
password_entry.grid(row=1, column=1, pady=5)

toggle_btn = create_toggle_button(password_entry, form_frame)
toggle_btn.grid(row=1, column=2, padx=5)

button_frame = tk.Frame(root, bg=BG_COLOR)
button_frame.pack(pady=15)

login_btn = tk.Button(button_frame, text="Login", command=login, width=BTN_WIDTH, bg=BTN_COLOR, fg=FG_COLOR, font=FONT, relief="flat")
login_btn.pack(pady=3)
login_btn.bind("<Enter>", on_enter)
login_btn.bind("<Leave>", on_leave)

register_btn = tk.Button(button_frame, text="Register", command=register, width=BTN_WIDTH, bg=BTN_COLOR, fg=FG_COLOR, font=FONT, relief="flat")
register_btn.pack(pady=3)
register_btn.bind("<Enter>", on_enter)
register_btn.bind("<Leave>", on_leave)

forgot_btn = tk.Button(button_frame, text="Forgot Password", command=forgot_password, width=BTN_WIDTH, bg=BTN_COLOR, fg=FG_COLOR, font=FONT, relief="flat")
forgot_btn.pack(pady=3)
forgot_btn.bind("<Enter>", on_enter)
forgot_btn.bind("<Leave>", on_leave)

username_entry.focus()
root.bind('<Return>', lambda event: login())
root.mainloop()
