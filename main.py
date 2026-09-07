
import os, json, base64, secrets, string, hashlib, time
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pyotp
from kivymd.app import MDApp
from kivymd.uix.screen import MDScreen
from kivymd.uix.screenmanager import MDScreenManager
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.card import MDCard
from kivymd.uix.label import MDLabel
from kivymd.uix.button import MDButton, MDButtonText, MDIconButton
from kivymd.uix.textfield import MDTextField
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
from kivy.clock import Clock
from kivy.utils import platform

def get_storage_path(f):
    try:
        if platform == 'android':
            from android.storage import app_storage_path
            return os.path.join(app_storage_path(), f)
    except: pass
    return f
VAULT_FILE = get_storage_path("vault.enc")
SALT_FILE = get_storage_path("salt.bin")
RECOVERY_FILE = get_storage_path("recovery.json")

def derive_key(pw, salt):
    kdf = Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=64*1024)
    return kdf.derive(pw.encode())
def encrypt_vault(data, key):
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, json.dumps(data).encode(), None)
    return base64.b64encode(nonce + ct)
def decrypt_vault(enc, key):
    raw = base64.b64decode(enc)
    nonce, ct = raw[:12], raw[12:]
    aes = AESGCM(key)
    pt = aes.decrypt(nonce, ct, None)
    return json.loads(pt.decode())
def generate_password(length=20):
    lower, upper, digits = string.ascii_lowercase, string.ascii_uppercase, string.digits
    symbols = "!@#$%^&*()-_=+"
    pwd = [secrets.choice(lower), secrets.choice(upper), secrets.choice(digits), secrets.choice(symbols)]
    all_chars = lower + upper + digits + symbols
    pwd += [secrets.choice(all_chars) for _ in range(length-4)]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)

class RegisterScreen(MDScreen):
    def on_kv_post(self, base_widget):
        Clock.schedule_once(lambda dt: self.build_ui(), 0.2)
    def build_ui(self):
        self.clear_widgets()
        layout = MDBoxLayout(orientation='vertical', padding=20, spacing=15)
        layout.add_widget(MDLabel(text="VAULTPRO", halign='center', font_style='Display', bold=True))
        self.master = MDTextField(hint_text="Master Password (8+)", password=True)
        self.master2 = MDTextField(hint_text="Repite", password=True)
        layout.add_widget(self.master)
        layout.add_widget(self.master2)
        btn = MDButton(style='filled')
        btn.add_widget(MDButtonText(text="CREAR BOVEDA"))
        btn.bind(on_press=self.do_register)
        layout.add_widget(btn)
        self.msg = MDLabel(text="", halign='center')
        layout.add_widget(self.msg)
        self.add_widget(layout)
    def do_register(self, *a):
        m1, m2 = self.master.text.strip(), self.master2.text.strip()
        if len(m1)<8 or m1!=m2:
            self.msg.text="Error master"; return
        salt=os.urandom(16)
        key=derive_key(m1, salt)
        secret=pyotp.random_base32()
        data={'passwords':{}, 'totp_secret':secret}
        with open(VAULT_FILE,'wb') as f: f.write(encrypt_vault(data,key))
        with open(SALT_FILE,'wb') as f: f.write(salt)
        self.manager.get_screen('show2fa').set_secret(secret)
        self.manager.current='show2fa'

class Show2FAScreen(MDScreen):
    def set_secret(self, secret):
        self.secret=secret
        self.clear_widgets()
        layout=MDBoxLayout(orientation='vertical', padding=20, spacing=20)
        layout.add_widget(MDLabel(text="GUARDA ESTE CODIGO!", halign='center', font_style='Headline', bold=True))
        layout.add_widget(MDLabel(text=secret, halign='center', font_style='Title', bold=True))
        btn=MDButton(style='filled')
        btn.add_widget(MDButtonText(text="YA LO GUARDE"))
        btn.bind(on_press=lambda x: setattr(self.manager,'current','login'))
        layout.add_widget(btn)
        self.add_widget(layout)

class LoginScreen(MDScreen):
    def on_kv_post(self, b):
        Clock.schedule_once(lambda dt: self.build_ui(),0.2)
    def build_ui(self):
        self.clear_widgets()
        layout=MDBoxLayout(orientation='vertical', padding=20, spacing=15)
        layout.add_widget(MDLabel(text="VAULTPRO", halign='center', font_style='Display', bold=True))
        self.master=MDTextField(hint_text="Master Password", password=True)
        self.totp=MDTextField(hint_text="Codigo 2FA")
        layout.add_widget(self.master)
        layout.add_widget(self.totp)
        btn=MDButton(style='filled')
        btn.add_widget(MDButtonText(text="DESBLOQUEAR"))
        btn.bind(on_press=self.do_login)
        layout.add_widget(btn)
        self.msg=MDLabel(text="", halign='center')
        layout.add_widget(self.msg)
        self.add_widget(layout)
    def do_login(self,*a):
        try:
            with open(SALT_FILE,'rb') as f: salt=f.read()
            key=derive_key(self.master.text.strip(), salt)
            with open(VAULT_FILE,'rb') as f: data=decrypt_vault(f.read(), key)
            totp=pyotp.TOTP(data['totp_secret'])
            if not totp.verify(self.totp.text.strip(), valid_window=3):
                self.msg.text="2FA mal"; return
            app=MDApp.get_running_app()
            app.key=key; app.vault_data=data
            self.manager.get_screen('vault').refresh()
            self.manager.current='vault'
        except Exception as e:
            self.msg.text="Master incorrecta"

class VaultScreen(MDScreen):
    def refresh(self):
        self.clear_widgets()
        app=MDApp.get_running_app()
        pwds=app.vault_data.get('passwords',{})
        main=MDBoxLayout(orientation='vertical', padding=10, spacing=10)
        main.add_widget(MDLabel(text=f"{len(pwds)} claves", font_style='Title', bold=True, size_hint_y=None, height=40))
        form=MDBoxLayout(size_hint_y=None, height=60, spacing=5)
        self.site=MDTextField(hint_text="gmail.com")
        self.length=MDTextField(hint_text="20", text="20", size_hint_x=0.3)
        form.add_widget(self.site); form.add_widget(self.length)
        main.add_widget(form)
        self.pwd_field=MDTextField(hint_text="Deja vacio para generar")
        main.add_widget(self.pwd_field)
        btns=MDBoxLayout(size_hint_y=None, height=50, spacing=10)
        b1=MDButton(style='filled'); b1.add_widget(MDButtonText(text="GENERAR")); b1.bind(on_press=self.gen)
        b2=MDButton(style='tonal'); b2.add_widget(MDButtonText(text="GUARDAR")); b2.bind(on_press=self.save_pwd)
        btns.add_widget(b1); btns.add_widget(b2)
        main.add_widget(btns)
        scroll=ScrollView()
        grid=GridLayout(cols=1, spacing=10, size_hint_y=None, padding=5)
        grid.bind(minimum_height=grid.setter('height'))
        for site,pwd in pwds.items():
            card=MDCard(style='outlined', padding=10, size_hint_y=None, height=80, orientation='vertical')
            card.add_widget(MDLabel(text=site, bold=True))
            row=MDBoxLayout(spacing=5, size_hint_y=None, height=35)
            tf=MDTextField(text="•"*len(pwd), readonly=True, size_hint_x=0.7)
            btn_show=MDIconButton(icon="eye", size_hint_x=0.15)
            btn_show.bind(on_press=lambda x,p=pwd,t=tf: setattr(t,'text', p if "•" in t.text else "•"*len(p)))
            btn_del=MDIconButton(icon="delete", size_hint_x=0.15)
            btn_del.bind(on_press=lambda x,s=site: self.delete(s))
            row.add_widget(tf); row.add_widget(btn_show); row.add_widget(btn_del)
            card.add_widget(row)
            grid.add_widget(card)
        scroll.add_widget(grid)
        main.add_widget(scroll)
        self.add_widget(main)
    def gen(self,*a):
        try: l=int(self.length.text or 20)
        except: l=20
        self.pwd_field.text=generate_password(l)
    def save_pwd(self,*a):
        site=self.site.text.strip()
        pwd=self.pwd_field.text.strip() or generate_password(20)
        if not site: return
        app=MDApp.get_running_app()
        app.vault_data['passwords'][site]=pwd
        app.save_vault()
        self.refresh()
    def delete(self,site):
        app=MDApp.get_running_app()
        del app.vault_data['passwords'][site]
        app.save_vault()
        self.refresh()

class VaultProApp(MDApp):
    def build(self):
        self.theme_cls.theme_style="Dark"
        self.theme_cls.primary_palette="Blue"
        sm=MDScreenManager()
        sm.add_widget(RegisterScreen(name='register'))
        sm.add_widget(Show2FAScreen(name='show2fa'))
        sm.add_widget(LoginScreen(name='login'))
        sm.add_widget(VaultScreen(name='vault'))
        sm.current='register' if not os.path.exists(SALT_FILE) else 'login'
        return sm
    def save_vault(self):
        with open(VAULT_FILE,'wb') as f: f.write(encrypt_vault(self.vault_data, self.key))

if __name__=='__main__':
    VaultProApp().run()
