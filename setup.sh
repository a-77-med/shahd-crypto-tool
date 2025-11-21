#!/bin/bash

# ShahD_RSA ULTRA PRO Installer
# Author: ShahD
# Usage: bash setup.sh

APP_NAME="shahd"
PYTHON_FILE="shahd.py"

# 1️⃣ تثبيت PyCryptodome
echo "[*] Installing PyCryptodome..."
python3 -m pip install pycryptodome --break-system-packages

# 2️⃣ إنشاء مجلد bin في /usr/local إذا مش موجود
if [ ! -d "/usr/local/bin" ]; then
    sudo mkdir -p /usr/local/bin
fi

# 3️⃣ نسخ الملف shahd.py إلى /usr/local/bin/shahd
echo "[*] Copying $PYTHON_FILE to /usr/local/bin/$APP_NAME ..."
sudo cp $PYTHON_FILE /usr/local/bin/$APP_NAME

# 4️⃣ إضافة صلاحيات تنفيذ
sudo chmod +x /usr/local/bin/$APP_NAME

# 5️⃣ انتهى
echo "[✓] Installation completed!"
echo "You can now run ShahD_RSA from anywhere using:"
echo "$APP_NAME"
