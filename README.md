Open Kage's useful Auth methods
But, this is develope version.
So, suddenly it will be big change when I got some more good idea.

# Install
```javascript
pip3 install kAuth
```

# Custom Dictionary Class

## Contents
1. Added New commands
   1. is_right_password()    : Check requirements in the password string
   1. gen_random()           : Generate random password
   1. enc_passwd()           : Encript password
   1. dec_passwd()           : decript password
   1. is_right_email()       : check right email format
   1. is_right_domain()      : check right domain (not yet)
   1. update_password_to_system()      : update password to Linux system
   1. check_password_to_system()       : check username and password from the linux system
   1. read_otp_key_from_user_account() : 
   1. send_otp_to_email()              : Send my opt number to email
   1. verify_otp()                     : Verify OTP number

1. requirements
requirement package names are crypt, pyotp, pyqrcode, kmisc

1. Initialize Auth method  

```javascript
import kAuth 
```

1. is_right_password() : Check right password or not
 - default check everything
 - RL=True/False : Check Low characters
 - RC=True/False : Check Capital characters
 - RI=True/False : Check Integer (0-9)
 - RS=True/False : Check Symbols
 - LN=8          : Password length (default 8)

```javascript
>>> password='Test Password'
>>> rt=is_right_password(password,RI=False,RS=False)
    if rt[0]:
        print('right format')
    else:
        print(rt[1])
```

1. gen_random() : generate random string
 - req=[,,] : requirements
   - 'str'     : Strings (Capital and Lower)
   - 'lower'   : lower strings
   - 'captial' : Capital strings
   - 'int'     : integer (0-9)
   - 'sym'     : symbols
 - length   : make a string length (default 8)

```javascript
>>> print(gen_random(req=['lower','int'],length=12))
'h06ypaeay1mn'
```
