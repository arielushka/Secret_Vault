# Secret-Vault

Secret-Vault היא תוכנת CLI לשיתוף קבצים מוצפנים. בעל הקובץ בוחר 2–16 משתמשים מורשים וסף אישורים. הקובץ, המפתח הפרטי ושחזור המפתח נשארים בצד הלקוח; השרת מנהל חשבונות, הרשאות וחומר מוצפן.

## איך השיתוף עובד

1. הלקוח מצפין את הקובץ עם AES-256-GCM. השרת מקבל את ה־Nonce ואת הטקסט המוצפן, לא את מפתח AES.
2. הלקוח מחלק את מפתח AES ל־Shares באמצעות Shamir. הסף חייב להיות לפחות 2 ולא גדול ממספר הנמענים.
3. כל Share מוצפן עם RSA-4096 OAEP/SHA-256 למפתח הציבורי של המשתמש שלו.
4. השרת שומר את הקובץ המוצפן ואת ה־Shares המוצפנים.
5. משתמש מורשה יכול להפעיל את האישור שלו. הלקוח שלו מפענח את ה־Share האישי ומצפין אותו בנפרד עבור כל משתמש מורשה.
6. השרת בודק שהלקוח שלח Share מוצפן לכל מורשה בדיוק פעם אחת, שומר את העותקים המוצפנים ומסמן את האישור כפעיל.
7. כאשר יש מספיק אישורים פעילים, כל משתמש מורשה יכול לבקש הורדה, גם בלי להפעיל את האישור שלו.
8. השרת מחזיר לו את הקובץ המוצפן ואת ה־Shares שהוצפנו עבורו. פענוח ה־Shares ושחזור מפתח AES נעשים במחשב שלו.

ביטול אישור מסיר את העותקים המוצפנים של אותו Share ומסמן אותו כלא פעיל. הוא אינו יכול למחוק קובץ שכבר הורד או עותק ששרת זדוני שמר בעבר.

## התקנה

אפשר להוריד רק את קובצי השרת, רק את קובצי הלקוח, או את שניהם. הפקודות דורשות Git עם תמיכה ב־sparse checkout ו־PowerShell.

### הורדת השרת בלבד

```powershell
git clone --filter=blob:none --no-checkout https://github.com/arielushka/Secret_Vault.git Secret_Vault-server
Set-Location Secret_Vault-server
git sparse-checkout init --no-cone
git sparse-checkout set '/README.md' '/server/**' '/common/**' '/requirements-server.txt' '/server.crt'
git checkout main
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-server.txt
```

### הורדת הלקוח בלבד

```powershell
git clone --filter=blob:none --no-checkout https://github.com/arielushka/Secret_Vault.git Secret_Vault-client
Set-Location Secret_Vault-client
git sparse-checkout init --no-cone
git sparse-checkout set '/README.md' '/client/**' '/common/**' '/requirements-client.txt' '/server.crt'
git checkout main
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-client.txt
```

### הורדת השרת והלקוח יחד

הקובץ `requirements.txt` נמצא בפרויקט המלא וכולל את התלויות של שני הצדדים.

```powershell
git clone https://github.com/arielushka/Secret_Vault.git Secret_Vault
Set-Location Secret_Vault
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

אפשר להריץ את השרת והלקוח באותה סביבת Python, או ליצור סביבה נפרדת לכל אחד ולהתקין בה את `requirements-server.txt` או `requirements-client.txt`.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

במחשב השרת התקינו את תלויות השרת:

```powershell
python -m pip install -r requirements-server.txt
```

במחשב לקוח התקינו את תלויות הלקוח:

```powershell
python -m pip install -r requirements-client.txt
```

אם רוצים להתקין את כל התלויות באותה סביבה, משתמשים בקובץ המלא:

```powershell
python -m pip install -r requirements.txt
```

## הפעלה

בטרמינל הראשון הפעילו את השרת:

```powershell
python -m server.server
```

השרת דורש TLS 1.3. במחשב השרת, מתוך תיקיית הפרויקט, מריצים פעם אחת לפני ההפעלה את פקודת OpenSSL הבאה. היא יוצרת את תעודת השרת `server.crt` ואת המפתח הפרטי `server.key` עבור עבודה מקומית עם `localhost` ו־`127.0.0.1`:

```powershell
openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.crt -days 365 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

את `server.key` משאירים במחשב השרת בלבד ואין מעלים אותו ל־Git או שולחים ללקוחות. אחרי יצירת התעודה, מעבירים לכל לקוח את `server.crt` ושומרים אותו בתיקיית הפרויקט, כי הלקוח קורא אותו משם כדי לאמת את תעודת השרת. הלקוחות אינם מריצים OpenSSL.

בטרמינל נוסף הפעילו לקוח. אפשר לפתוח כמה לקוחות כדי להשתמש בכמה חשבונות:

```powershell
python -m client.client
```

השרת מקשיב ב־`127.0.0.1:5000`.

השרת יוצר את `database/vault.db` ואת תיקיית `server/uploads` בהפעלה/בהעלאה. הרישום יוצר זוג מפתחות RSA-4096 אצל הלקוח ושומר את המפתח הפרטי בקובץ PEM מוגן בסיסמה. סיסמאות החשבון נשמרות בשרת כ־Argon2 hash.

## מבנה הפרויקט

- `client/client.py`: ממשק ה־CLI.
- `client/vault_client.py`: חיבור לשרת, בדיקת מפתחות ופעולות משתמש.
- `client/file_manager.py` ו־`client/crypto/`: הצפנת קבצים, חלוקת Shares ושמירת מפתחות.
- `common/protocol.py`: מסגור הודעות JSON מעל TCP (עד 16 MiB להודעה).
- `server/server.py`, `server/handlers.py`: חיבורים וניתוב בקשות מאומתות.
- `server/file_handler.py`, `server/database.py`: אימות העלאות, קובצי ciphertext ומסד SQLite.
- כרגע אין בפרויקט תיקיית בדיקות; ראו את סעיף הבדיקות למטה.

## אישור מפתחות ציבוריים

בפעם הראשונה שמשתמש מקבל מפתח ציבורי של משתמש אחר, התוכנה מציגה את טביעת האצבע שלו. יש להשוות אותה למידע שקיבלת מהמשתמש בדרך נפרדת ואמינה, למשל שיחה ישירה. רק לאחר אישור היא נשמרת מקומית בקובץ `trusted_keys.json`. אם המפתח משתנה, התוכנה עוצרת ולא מחליפה את האישור השמור.

בהתחברות, הלקוח גם משווה את המפתח הציבורי שהשרת מחזיר למפתח הפרטי המקומי, כדי לוודא שהמפתח של המשתמש עצמו לא הוחלף.

## מפתחות פרטיים

המפתח הפרטי נשמר במחשב המשתמש בקובץ מוצפן בסיסמה, תחת `~/.secret_vault/keys` (ב־Windows: בתיקיית המשתמש). אפשר לבחור תיקייה אחרת בעזרת משתנה הסביבה `SECRET_VAULT_KEY_DIR`. השרת שומר מפתחות ציבוריים בלבד.

## בדיקת התקנה מלאה

הקובץ `test_installation.py` נמצא בהורדה המלאה בלבד, כי הוא בודק גם את קובצי השרת וגם את קובצי הלקוח. אחרי התקנת כל התלויות, יצירת התעודה והמפתח עם OpenSSL, והפעלת השרת בטרמינל הראשון, הריצו בטרמינל נוסף:

```powershell
python -m unittest test_installation -v
```

הבדיקה מוודאת שהתלויות וקובצי שני הצדדים זמינים, יוצרת חיבור TLS 1.3 לשרת המקומי, ושולחת בקשת פרוטוקול לא מאומתת כדי לוודא שהשרת מחזיר את שגיאת ההתחברות הנדרשת. היא אינה יוצרת משתמש או משנה קבצים במסד הנתונים.

## מגבלות

- השרת כרגע מאזין רק ל־localhost ומשתמש ב־TLS 1.3 עם תעודה מקומית. אין לחשוף אותו לרשת בלי הגדרת תעודה, אמון לקוחות ואמצעי אבטחה נוספים.
- מגבלת העלאה בצד השרת היא 10 MiB לקובץ מוצפן; מגבלת הודעת הפרוטוקול היא 16 MiB.
- טביעת אצבע שמתקבלת רק מהשרת אינה מוכיחה את זהות המשתמש. צריך להשוות אותה בדרך אמינה מחוץ לשרת.
- משתמש שקיבל קובץ מפוענח יכול לשמור או להעביר אותו.
- שרת זדוני יכול למנוע שירות או לשמור נתונים ישנים. ביטול אישור אינו מחיקה קריפטוגרפית.
- אם אובדים קובץ המפתח הפרטי המקומי או הסיסמה שלו, אי אפשר לפענח את ה־Shares של המשתמש.
- בהפעלה הראשונה על מסד נתונים מהגרסה הישנה, Shares מקוריים מועתקים לרשימת המשתמשים המורשים. אישורים קיימים אינם מועברים; כל המשתמשים מתחילים כלא מאושרים.
