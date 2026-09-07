
import os, json, base64, secrets, string, hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pyotp

from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
from kivy.clock import Clock
from kivy.utils import platform

def get_path(f):
    try:
        if platform == 'android':
            from android.storage import app_storage_path
            return os.path.join(app_storage_path(), f)
    except: pass
    return f

VAULT = get_path("vault.enc")
SALT = get_path("salt.bin")

def derive_key(pw, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200000)
    return kdf.derive(pw.encode())

def enc(data, key):
    aes=AESGCM(key); n=os.urandom(12)
    ct=aes.encrypt(n, json.dumps(data).encode(), None)
    return base64.b64encode(n+ct)
def dec(encd, key):
    raw=base64.b64decode(encd); n,ct=raw[:12],raw[12:]
    aes=AESGCM(key)
    return json.loads(aes.decrypt(n,ct,None).decode())

def gen_pwd(l=20):
    chars=string.ascii_letters+string.digits+"!@#$%&_"
    return "".join(secrets.choice(chars) for _ in range(l))

class RegisterScreen(Screen):
    def on_enter(self):
        self.clear_widgets()
        lay=BoxLayout(orientation='vertical', padding=20, spacing=10)
        lay.add_widget(Label(text="VAULTPRO A36", font_size=32, bold=True))
        lay.add_widget(Label(text="Crea tu boveda", font_size=18))
        self.m1=TextInput(hint_text="Master 8+", password=True, multiline=False, size_hint_y=None, height=50)
        self.m2=TextInput(hint_text="Repite Master", password=True, multiline=False, size_hint_y=None, height=50)
        lay.add_widget(self.m1); lay.add_widget(self.m2)
        self.msg=Label(text="", color=(1,0,0,1))
        btn=Button(text="CREAR BOVEDA", size_hint_y=None, height=60, background_color=(0.2,0.6,1,1))
        btn.bind(on_press=self.do_reg)
        lay.add_widget(btn); lay.add_widget(self.msg)
        self.add_widget(lay)
    def do_reg(self,*a):
        m1,m2=self.m1.text.strip(), self.m2.text.strip()
        if len(m1)<8 or m1!=m2:
            self.msg.text="Error master"; return
        salt=os.urandom(16)
        key=derive_key(m1, salt)
        secret=pyotp.random_base32()
        data={'passwords':{}, 'totp_secret':secret}
        with open(VAULT,'wb') as f: f.write(enc(data,key))
        with open(SALT,'wb') as f: f.write(salt)
        # guardar secret en pantalla siguiente
        App.get_running_app().temp_secret=secret
        self.manager.current='show2fa'

class Show2FAScreen(Screen):
    def on_enter(self):
        self.clear_widgets()
        secret=getattr(App.get_running_app(),'temp_secret','')
        lay=BoxLayout(orientation='vertical', padding=20, spacing=20)
        lay.add_widget(Label(text="GUARDA ESTE CODIGO 2FA", font_size=24, bold=True))
        lay.add_widget(Label(text="Ponlo en Google Authenticator", font_size=16))
        lay.add_widget(Label(text=secret, font_size=20, bold=True))
        btn=Button(text="YA LO GUARDE", size_hint_y=None, height=60, background_color=(0,0.8,0.3,1))
        btn.bind(on_press=lambda x: setattr(self.manager,'current','login'))
        lay.add_widget(btn)
        self.add_widget(lay)

class LoginScreen(Screen):
    def on_enter(self):
        self.clear_widgets()
        lay=BoxLayout(orientation='vertical', padding=20, spacing=10)
        lay.add_widget(Label(text="VAULTPRO", font_size=32, bold=True))
        self.master=TextInput(hint_text="Master Password", password=True, multiline=False, size_hint_y=None, height=50)
        self.totp=TextInput(hint_text="Codigo 2FA 6 digitos", multiline=False, size_hint_y=None, height=50, input_filter='int')
        lay.add_widget(self.master); lay.add_widget(self.totp)
        self.msg=Label(text="", color=(1,0,0,1))
        btn=Button(text="DESBLOQUEAR", size_hint_y=None, height=60, background_color=(0.2,0.6,1,1))
        btn.bind(on_press=self.do_login)
        lay.add_widget(btn); lay.add_widget(self.msg)
        self.add_widget(lay)
    def do_login(self,*a):
        try:
            with open(SALT,'rb') as f: salt=f.read()
            key=derive_key(self.master.text.strip(), salt)
            with open(VAULT,'rb') as f: data=dec(f.read(), key)
            totp=pyotp.TOTP(data['totp_secret'])
            if not totp.verify(self.totp.text.strip(), valid_window=3):
                self.msg.text="2FA incorrecto"; return
            app=App.get_running_app()
            app.key=key; app.data=data
            self.manager.get_screen('vault').refresh()
            self.manager.current='vault'
            self.master.text=""; self.totp.text=""
        except Exception as e:
            self.msg.text=f"Master mal: {str(e)[:40]}"

class VaultScreen(Screen):
    def refresh(self):
        self.clear_widgets()
        app=App.get_running_app()
        pwds=app.data.get('passwords',{})
        main=BoxLayout(orientation='vertical', padding=10, spacing=10)
        main.add_widget(Label(text=f"TU BOVEDA - {len(pwds)} claves", size_hint_y=None, height=40, bold=True))
        form=BoxLayout(size_hint_y=None, height=50, spacing=5)
        self.site=TextInput(hint_text="ej: gmail.com", multiline=False)
        self.len=TextInput(text="20", multiline=False, size_hint_x=0.3)
        form.add_widget(self.site); form.add_widget(self.len)
        main.add_widget(form)
        self.pwd=TextInput(hint_text="Deja vacio para generar", multiline=False, size_hint_y=None, height=50)
        main.add_widget(self.pwd)
        btns=BoxLayout(size_hint_y=None, height=50, spacing=5)
        b1=Button(text="GENERAR"); b1.bind(on_press=self.do_gen)
        b2=Button(text="GUARDAR", background_color=(0,0.8,0.3,1)); b2.bind(on_press=self.do_save)
        btns.add_widget(b1); btns.add_widget(b2)
        main.add_widget(btns)
        scroll=ScrollView()
        grid=GridLayout(cols=1, spacing=5, size_hint_y=None); grid.bind(minimum_height=grid.setter('height'))
        for site,pwd in pwds.items():
            row=BoxLayout(size_hint_y=None, height=50, spacing=5)
            row.add_widget(Label(text=site, size_hint_x=0.5))
            # boton ver
            b_show=Button(text="VER", size_hint_x=0.2)
            b_show.bind(on_press=lambda x,p=pwd: self.show_pwd(p))
            b_del=Button(text="X", size_hint_x=0.2, background_color=(1,0.2,0.2,1))
            b_del.bind(on_press=lambda x,s=site: self.delete(s))
            row.add_widget(b_show); row.add_widget(b_del)
            grid.add_widget(row)
        scroll.add_widget(grid)
        main.add_widget(scroll)
        self.msg=Label(text="", size_hint_y=None, height=30, color=(0,1,0,1))
        main.add_widget(self.msg)
        b_out=Button(text="BLOQUEAR", size_hint_y=None, height=40); b_out.bind(on_press=lambda x: setattr(self.manager,'current','login'))
        main.add_widget(b_out)
        self.add_widget(main)
    def show_pwd(self,pwd):
        self.msg.text=f"CLAVE: {pwd}"
    def do_gen(self,*a):
        try: l=int(self.len.text or 20)
        except: l=20
        self.pwd.text=gen_pwd(l)
    def do_save(self,*a):
        site=self.site.text.strip()
        pwd=self.pwd.text.strip() or gen_pwd(20)
        if not site: return
        app=App.get_running_app()
        app.data['passwords'][site]=pwd
        with open(VAULT,'wb') as f: f.write(enc(app.data, app.key))
        self.site.text=""; self.pwd.text=""
        self.refresh()
    def delete(self,site):
        app=App.get_running_app()
        del app.data['passwords'][site]
        with open(VAULT,'wb') as f: f.write(enc(app.data, app.key))
        self.refresh()

class VaultApp(App):
    def build(self):
        sm=ScreenManager()
        sm.add_widget(RegisterScreen(name='register'))
        sm.add_widget(Show2FAScreen(name='show2fa'))
        sm.add_widget(LoginScreen(name='login'))
        sm.add_widget(VaultScreen(name='vault'))
        sm.current='register' if not os.path.exists(SALT) else 'login'
        return sm

if __name__=='__main__':
    VaultApp().run()
