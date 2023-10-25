import os
import ast
import random
from kmport import *
from datetime import datetime
#from simplepam import authenticate 
#from cryptography.fernet import Fernet

Import('import crypt')
Import('import pyotp')
Import('import pyqrcode')
Install('simplepam')  # Check of linux system authenticate 
from simplepam import authenticate  # Check of linux system authenticate 
Install('cryptography')
from cryptography.fernet import Fernet

KeyKey=b'7_4y35QSzPgBO7UnrMeZNzmZFbOOkoP7l0FSR-D-Anw='
keyfer=Fernet(KeyKey)

require_lower='abcdefghijklmnopqrstuvwxyxz'
require_capital='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
require_symbols='!@#$%^&*-+_=.?,:;"{}|'
require_int='0123456789'

def req_passwd(a):
    lc=False
    Lc=False
    nc=False
    sc=False
    for i in a:
        if  i in require_lower: lc=True
        if  i in require_capital: Lc=True
        if  i in require_int: nc=True
        if  i in require_symbols: sc=True
    if lc and Lc and nc and sc:
        return True
    if not lc: return 'lc'
    if not Lc: return 'Lc'
    if not lc: return 'nc'
    if not lc: return 'sc'
    return False

def is_right_password(password,RL=True,RC=True,RI=True,RS=True,LN=8):
    if len(password) < LN:
        return False,'Need more {} characters(length)'.format(LN)
    req_pass_ok=req_passwd(password)
    if req_pass_ok is not True:
        if RL and req_pass_ok == 'lc':
            return False,'Need low characters'
        elif RC and req_pass_ok == 'Lc':
            return False,'Need Capital characters'
        elif RI and req_pass_ok == 'nc':
            return False,'Need numbers(0-9)'
        elif RS and req_pass_ok == 'sc':
            return False,'Need special characters(!@#$^&*()_-=+{}[]|:,.<>?)'
    return True,'all is right'

def gen_random(req=['str','int','sym'],length=8):
    src=''
    choose_num=length//len(req)
    if 'int' in req:
        src=src+''.join([random.choice(require_int) for i in range(random.randint(1,choose_num))])
    if 'sym' in req:
        src=src+''.join([random.choice(require_symbols) for i in range(random.randint(1,choose_num))])
    if 'str' in req or 'capital' in req:
        choose_num=(length-len(src)) // 2
        src=src+''.join([random.choice(require_capital) for i in range(random.randint(1,choose_num))])
    if 'str' in req or 'lower' in req:
        src=src+''.join([random.choice(require_lower) for i in range(length-len(src))])
    src_a=list(src)
    for i in range(4):
        random.shuffle(src_a)
    return ''.join(src_a)

def enc_passwd(source):
    return Str(keyfer.encrypt(source.encode()))

def dec_passwd(source):
    return keyfer.decrypt(Bytes(source)).decode()

def enc_key(**source):
    # convert dictionary to string
    str_source='''{}'''.format(source)
    return Str(keyfer.encrypt(str_source.encode()))

def dec_key(key):
    # convert string to dictionary
    try:
        dkey=keyfer.decrypt(Bytes(key)).decode()
    except:
        return {}
    try:
         rt=ast.literal_eval(dkey)
         rt['key']=key
         return rt
    except:
         return dkey

def is_right_domain(source):
    # code here
    return True

def is_right_email(source,local=False):
    if isinstance(source,str):
        if local:
            if os.path.isdir(os.path.join('/home',source)):
                return True
        else:
            src_a=source.split('@')
            if len(src_a) == 2:
                username=src_a[0]
                domain=src_a[1]
                if is_right_domain(domain):
                    return True
    return False

def update_password_to_system(username,passwd):
    #update password to username on the linux system
    pass_env=crypt.crypt(passwd)
    rt=rshell('''echo '%s:%s' | chpasswd -e'''%(username,pass_env))
    if rt[0]==0:
        return True
    return False

def check_password_to_system(username,passwd):
    #if username and password is right on the linux system then return True, default False
    if authenticate(str(username),str(passwd)):
        return True
    return False

#2fa otp google auth
def read_otp_key_from_user_account(username):
    otp_key_file=os.path.join('/home',username,'.google_authenticator')
    if os.path.isfile(otp_key_file):
        with open(otp_key_file) as f:
            _key_=f.read()
        my_key=_key_.split('\n')
        if len(my_key) > 0:
            return my_key[0]
    return False

def get_otp(username):
    my_key=read_otp_key_from_user_account(username)
    if my_key:
        try:
            return pyotp.TOTP(my_key)
        except:
            pass
    return False

def get_otp_num(username,myotp=None):
    if myotp is None: myotp=get_otp(username)
    if myotp:
        try:
            return myotp.now()
        except:
            pass
    return False

def otp_remain_time(myotp):
    try:
        return int(myotp.interval - datetime.now().timestamp() % myotp.interval)
    except:
        pass
    return False

def send_otp_to_email(myotp,email_title='OTP',email_addr=None,local=False,minimum_time=20):
    rt=False,'NA'
    if is_right_email(email_addr,local=local):
        for i in range(0,30):
            if otp_remain_time(myotp) > minimum_time:
                rt=rshell('''echo {} | mail -s "{}" {}'''.format(myotp.now(),email_title,email_addr))
                if rt[0] == 0:
                    return True,'OK'
            time.sleep(1)
    return False,rt[1]

def verify_otp_num(username,otp_num,myotp=None):
    if myotp is None: myotp=get_otp(username)
    if myotp:
        if myotp.verify(otp_num):
            return True
    return False

def gen_otp_key():
    return '''{}
" RATE_LIMIT 3 30 1698214675
" DISALLOW_REUSE 56607154 56607155
" TOTP_AUTH
'''.format(pyotp.random_base32())
