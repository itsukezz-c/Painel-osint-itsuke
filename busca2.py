import tkinter as tk
from tkinter import ttk, messagebox
import socket
import requests
import subprocess

#ME SEGUE NO MEU GITHUB : itsukezz-c ❤
# ---------------- FUNÇÕES OSINT ---------------- #

def limpar_resultado():
    resultado.delete("1.0", tk.END)

def dns_lookup():
    dominio = entrada.get()
    if not dominio:
        messagebox.showerror("Erro", "Digite um domínio")
        return
    try:
        ip = socket.gethostbyname(dominio)
        limpar_resultado()
        resultado.insert(tk.END, f"IP encontrado: {ip}")
    except:
        messagebox.showerror("Erro", "Falha ao resolver DNS")

def ip_info():
    ip = entrada.get()
    if not ip:
        messagebox.showerror("Erro", "Digite um IP")
        return
    try:
        resposta = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        limpar_resultado()
        for k, v in resposta.items():
            resultado.insert(tk.END, f"{k}: {v}\n")
    except:
        messagebox.showerror("Erro", "Falha na consulta")
# me perdoe mas nao posso colocar nmap no codigo, pois isso ja nao é mais osint.
        

def username_search():
    username = entrada.get()
    if not username:
        messagebox.showerror("Erro", "Digite um username")
        return

    limpar_resultado()
    resultado.insert(tk.END, f"Resultados para username: {username}\n\n")

    sites = {
        "GitHub": f"https://github.com/{username}",
        "GitLab": f"https://gitlab.com/{username}",
        "Bitbucket": f"https://bitbucket.org/{username}",
        "Twitter/X": f"https://twitter.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}",
        "Facebook": f"https://www.facebook.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "YouTube": f"https://www.youtube.com/@{username}",
        "Medium": f"https://medium.com/@{username}",
        "Pinterest": f"https://www.pinterest.com/{username}",
        "SoundCloud": f"https://soundcloud.com/{username}",
        "Steam": f"https://steamcommunity.com/id/{username}",
        "Twitch": f"https://www.twitch.tv/{username}",
        "DeviantArt": f"https://www.deviantart.com/{username}",
        "HackerOne": f"https://hackerone.com/{username}",
        "Keybase": f"https://keybase.io/{username}",
        "Flickr": f"https://www.flickr.com/people/{username}",
        "About.me": f"https://about.me/{username}",
        "Pornhub": f"https://pornhub.com/{username}",
        "Spotify": f"https://spotify.com/{username}",


    }

    headers = {"User-Agent": "Mozilla/5.0"}

    for site, url in sites.items():
        try:
            r = requests.get(url, headers=headers, timeout=5)
            if r.status_code == 200:
                resultado.insert(tk.END, f"[✔] {site}: {url}\n")
            else:
                resultado.insert(tk.END, f"[✘] {site}: não encontrado\n")
        except:
            resultado.insert(tk.END, f"[!] {site}: erro na requisição\n")

# ---------------- INTERFACE ---------------- #

janela = tk.Tk()
janela.title("Painel OSINT! Github: itsukezz-c")
janela.geometry("760x540")
janela.configure(bg="#1e1e2f")

style = ttk.Style()
style.theme_use("clam")
style.configure("TButton", font=("Segoe UI", 10), padding=6)
style.configure("TLabel", background="#1e1e2f", foreground="white", font=("Segoe UI", 11))

titulo = ttk.Label(janela, text="Painel OSINT! Github: itsukezz-c", font=("Segoe UI", 16, "bold"))
titulo.pack(pady=10)

frame_input = tk.Frame(janela, bg="#1e1e2f")
frame_input.pack(pady=5)

ttk.Label(frame_input, text="Domínio / IP / Username:").pack(side=tk.LEFT, padx=5)
entrada = ttk.Entry(frame_input, width=42)
entrada.pack(side=tk.LEFT, padx=5)

frame_botoes = tk.Frame(janela, bg="#1e1e2f")
frame_botoes.pack(pady=10)

ttk.Button(frame_botoes, text="DNS Lookup", command=dns_lookup).pack(side=tk.LEFT, padx=4)
ttk.Button(frame_botoes, text="IP Info", command=ip_info).pack(side=tk.LEFT, padx=4)
ttk.Button(frame_botoes, text="Username", command=username_search).pack(side=tk.LEFT, padx=4)

resultado = tk.Text(
    janela,
    width=90,
    height=20,
    bg="#041225",
    fg="#38bdf8",
    insertbackground="white",
    font=("Consolas", 10)
)
resultado.pack(padx=10, pady=10)

rodape = ttk.Label(janela, text="OSINT • Uso educacional e legal! Github: itsukezz-c")
rodape.pack(pady=5)

janela.mainloop()