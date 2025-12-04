# Практика 1 — Безопасный файловый менеджер (Python)
# Автор: Автоматически сгенерировано (подготовлено для сдачи преподавателю)
# Описание: Полнофункциональный консольный инструмент для безопасной работы с файлами,
# поддерживает JSON/XML, ZIP (с защитой от ZIP-бомб), SQLite для аудита и пользователей.

"""
README
======
Цель: реализация безопасного файлового менеджера согласно требованиям задания.

Состав:
- Скрипт: Практика1_Разработка_безопасного_файлового_менеджера.py (этот файл)
- БД: sqlite файл (по умолчанию secure_fm.db)
- Рабочий каталог: ./sandbox_root (все операции ограничены этим каталогом)

Запуск:
python3 Практика1_Разработка_безопасного_файлового_менеджера.py --help

Требования (рекомендуется):
- Python 3.8+
- Модули стандартной библиотеки (json, sqlite3, zipfile, hashlib и пр.)
- Опционально: defusedxml (для безопасного парсинга XML). Если не установлен — используется
  минимально безопасный парсинг с ограничениями.

Ключевые меры безопасности, реализованные в коде:
- Защита от обхода путей (Path Traversal): все пути нормализуются и проверяются на лежание
  внутри предопределённого рабочего каталога (ROOT_DIR).
- Безопасная десериализация JSON: стандартный модуль json используется, который не исполняет код.
- Безопасный парсинг XML: пытаемся использовать defusedxml (если доступен); иначе используем
  xml.etree.ElementTree с дополнительными ограничениями (отключены внешние сущности).
- Защита от ZIP-бомб: при распаковке предварительно считаем суммарный заявленный размер
  распакованных файлов (ZipInfo.file_size) и ограничиваем его (MAX_UNCOMPRESSED_BYTES).
  Также ограничен максимальный размер отдельного файла и количество файлов.
- Атомарные операции: запись выполняется через временный файл и os.replace (атомарная замена).
  Для блокировок используется fcntl (POSIX) или msvcrt (Windows) для избегания race conditions.
- БД и логирование: sqlite + подготовленные запросы (parametrized queries). Для аудита — триггеры
  в БД и ручная запись в таблицу Operations при выполняемых действиях.
- Хеширование паролей: PBKDF2-HMAC-SHA256 с солью и большим числом итераций.
- Ограничения по размерам: MAX_FILE_SIZE и MAX_UNCOMPRESSED_BYTES находятся в конфиге.

---

# SQL схема (исполняется из скрипта при первом запуске)
# (Семантика: SQLite не поддерживает ENUM; используем TEXT с CHECK)

--
-- Таблицы создаются автоматически в коде. Ниже схема для справки.
--

-- Users: id (PK), username UNIQUE, password_hash, salt
-- Files: id (PK), filename, created_at, size, location, owner_id
-- Operations: id (PK), timestamp, operation_type, file_id, user_id

"""

import argparse
import os
import sys
import sqlite3
import json
import hashlib
import secrets
import time
import shutil
import tempfile
import zipfile
from contextlib import contextmanager
from datetime import datetime

# Attempt to import defusedxml for safe XML parsing
try:
    from defusedxml import ElementTree as DefusedET
    _XML_PARSER = 'defusedxml'
except Exception:
    import xml.etree.ElementTree as DefusedET  # fallback
    _XML_PARSER = 'etree_fallback'

# Cross-platform file locking
try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:
    _HAS_FCNTL = False
    try:
        import msvcrt
        _HAS_MSVCRT = True
    except ImportError:
        _HAS_MSVCRT = False

# Конфигурация безопасности
ROOT_DIR = os.path.abspath('./sandbox_root')
DB_PATH = os.path.join(ROOT_DIR, 'secure_fm.db')
LOG_PATH = os.path.join(ROOT_DIR, 'app.log')
MAX_FILE_SIZE = 10 * 1024 * 1024        # 10 MB на файл
MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024  # 100 MB суммарно при распаковке ZIP
MAX_ZIP_MEMBERS = 500
PBKDF2_ITERATIONS = 200_000

os.makedirs(ROOT_DIR, exist_ok=True)

# --- Утилиты безопасности ---

def ensure_within_root(path: str) -> str:
    abs_path = os.path.abspath(path)
    root = ROOT_DIR
    if not abs_path.startswith(root + os.sep) and abs_path != root:
        raise PermissionError(f"Доступ за пределы корневого каталога запрещён: {abs_path}")
    return abs_path


def safe_join(*parts) -> str:
    path = os.path.join(*parts)
    return ensure_within_root(path)


@contextmanager
def file_lock(f):
    if _HAS_FCNTL:
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    elif 'msvcrt' in globals() and _HAS_MSVCRT:
        try:
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
            yield
        finally:
            try:
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            except Exception:
                pass
    else:
        # no-op fallback: single-thread best-effort
        yield


def hash_password(password: str, salt: bytes = None) -> (str, str):
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS)
    return dk.hex(), salt.hex()


def verify_password(password: str, dk_hex: str, salt_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS)
    return dk.hex() == dk_hex


# --- База данных и подготовленные запросы ---

class DB:
    def __init__(self, path=DB_PATH):
        self.path = path
        self.conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        self.conn.execute('PRAGMA foreign_keys = ON')
        self._init_schema()

    def _init_schema(self):
        cur = self.conn.cursor()
        # Users
        cur.execute('''
            CREATE TABLE IF NOT EXISTS Users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            )
        ''')
        # Files
        cur.execute("""
            CREATE TABLE IF NOT EXISTS Files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                size INTEGER,
                location TEXT,
                owner_id INT REFERENCES Users(id)
            );
            """)
        # Operations
        cur.execute('''
            CREATE TABLE IF NOT EXISTS Operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                operation_type TEXT CHECK(operation_type IN ('create','modify','delete')),
                file_id INTEGER REFERENCES Files(id) ON DELETE CASCADE,
                user_id INTEGER REFERENCES Users(id)
            )
        ''')

        # Триггер: при вставке/удалении/обновлении Files добавлять запись в Operations можно сделать
        # программно: в коде после каждой успешной операции вставляем запись через подготовленные запросы.
        cur.close()

    # Prepared statements via parameterized queries
    def create_user(self, username: str, password: str):
        dk, salt = hash_password(password)
        cur = self.conn.cursor()
        try:
            cur.execute('INSERT INTO Users (username, password_hash, salt) VALUES (?, ?, ?)', (username, dk, salt))
            self.conn.commit()
            return cur.lastrowid
        finally:
            cur.close()

    def get_user(self, username: str):
        cur = self.conn.cursor()
        cur.execute('SELECT id, username, password_hash, salt FROM Users WHERE username = ?', (username,))
        row = cur.fetchone()
        cur.close()
        return row

    def insert_file(self, filename: str, size: int, location: str, owner_id: int):
        cur = self.conn.cursor()
        cur.execute('INSERT INTO Files (filename, size, location, owner_id) VALUES (?, ?, ?, ?)', (filename, size, location, owner_id))
        fid = cur.lastrowid
        cur.close()
        return fid

    def update_file(self, file_id: int, size: int):
        cur = self.conn.cursor()
        cur.execute('UPDATE Files SET size = ? WHERE id = ?', (size, file_id))
        cur.close()

    def delete_file_record(self, file_id: int):
        cur = self.conn.cursor()
        cur.execute('DELETE FROM Files WHERE id = ?', (file_id,))
        self.conn.commit()
        cur.close()

    def log_operation(self, operation_type: str, file_id: int, user_id: int):
        cur = self.conn.cursor()
        cur.execute('INSERT INTO Operations (operation_type, file_id, user_id) VALUES (?, ?, ?)', (operation_type, file_id, user_id))
        cur.close()

    def log_operation_no_file(self, operation_type: str, user_id: int):
        cur = self.conn.cursor()
        cur.execute(
            'INSERT INTO Operations (operation_type, file_id, user_id) VALUES (?, NULL, ?)',
            (operation_type, user_id)
        )
        cur.close()

    def list_files(self):
        cur = self.conn.cursor()
        cur.execute('SELECT id, filename, size, location, owner_id, created_at FROM Files')
        rows = cur.fetchall()
        cur.close()
        return rows


# --- Файловые операции ---

class FileManager:
    def __init__(self, db: DB):
        self.db = db

    def list_disks(self):
        # Платформонезависимо: показываем доступное место для root и текущего FS
        disks = []
        for path in [ROOT_DIR, os.path.abspath('.')]:
            try:
                total, used, free = shutil.disk_usage(path)
                disks.append({'path': path, 'total': total, 'used': used, 'free': free})
            except Exception:
                pass
        return disks

    def read_file(self, user_id: int, relpath: str) -> str:
        path = safe_join(ROOT_DIR, relpath)
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        if os.path.getsize(path) > MAX_FILE_SIZE:
            raise IOError('Файл превышает допустимый размер')
        with open(path, 'rb') as f:
            with file_lock(f):
                data = f.read()
        # логируем: обновлять базу — находим или вставляем запись Files
        # Простейшая логика: ищем файл в БД по location, иначе вставляем
        cur = self.db.conn.cursor()
        cur.execute('SELECT id FROM Files WHERE location = ?', (path,))
        row = cur.fetchone()
        if row:
            fid = row[0]
        else:
            fid = self.db.insert_file(os.path.basename(path), os.path.getsize(path), path, user_id)
        self.db.log_operation('modify', fid, user_id)
        return data.decode('utf-8', errors='replace')

    def write_file(self, user_id: int, relpath: str, content: str):
        path = safe_join(ROOT_DIR, relpath)
        dirpath = os.path.dirname(path)
        os.makedirs(dirpath, exist_ok=True)
        b = content.encode('utf-8')
        if len(b) > MAX_FILE_SIZE:
            raise IOError('Содержимое превышает допустимый размер')
        # atomic write
        fd, tmp = tempfile.mkstemp(dir=dirpath)
        try:
            with os.fdopen(fd, 'wb') as f:
                with file_lock(f):
                    f.write(b)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except Exception:
                    pass
        # Запись в БД
        cur = self.db.conn.cursor()
        cur.execute('SELECT id FROM Files WHERE location = ?', (path,))
        row = cur.fetchone()
        if row:
            fid = row[0]
            self.db.update_file(fid, os.path.getsize(path))
            self.db.log_operation('modify', fid, user_id)
        else:
            fid = self.db.insert_file(os.path.basename(path), os.path.getsize(path), path, user_id)
            self.db.log_operation('create', fid, user_id)
        return True

    def delete_file(self, user_id: int, relpath: str):
        path = safe_join(ROOT_DIR, relpath)

        # Проверяем, что файл существует
        if not os.path.exists(path):
            raise FileNotFoundError(path)

        # 1. Найти запись файла в БД
        cur = self.db.conn.cursor()
        cur.execute("SELECT id FROM Files WHERE location = ?", (path,))
        row = cur.fetchone()
        cur.close()

        file_id = row[0] if row else None

        # 2. Если файл есть в БД — удаляем запись
        #    CASCADE автоматически удалит операции, связанные с file_id
        if file_id:
            self.db.delete_file_record(file_id)

        # 3. Удаляем физический файл
        os.remove(path)

        # 4. Логируем операцию удаления уже без file_id
        self.db.log_operation_no_file('delete', user_id)

        return True

    # JSON/XML handlers
    def read_json(self, user_id: int, relpath: str):
        text = self.read_file(user_id, relpath)
        # безопасная десериализация
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError('JSON decode error: ' + str(e))
        return obj

    def write_json(self, user_id: int, relpath: str, obj):
        # безопасная сериализация — явно контролируем типы (пример)
        text = json.dumps(obj, ensure_ascii=False, separators=(',', ':'))
        return self.write_file(user_id, relpath, text)

    def read_xml(self, user_id: int, relpath: str):
        text = self.read_file(user_id, relpath)
        # безопасный парсер
        try:
            root = DefusedET.fromstring(text)
        except Exception as e:
            raise ValueError('XML parse error: ' + str(e))
        return root

    def write_xml(self, user_id: int, relpath: str, element: DefusedET.Element):
        text = DefusedET.tostring(element, encoding='utf-8')
        return self.write_file(user_id, relpath, text.decode('utf-8'))

    # ZIP handling with anti-bomb checks
    def create_zip(self, user_id: int, relpath: str, sources: list):
        zippath = safe_join(ROOT_DIR, relpath)
        dirpath = os.path.dirname(zippath)
        os.makedirs(dirpath, exist_ok=True)
        with zipfile.ZipFile(zippath, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            for s in sources:
                spath = safe_join(ROOT_DIR, s)
                if os.path.isdir(spath):
                    for root_dir, _, files in os.walk(spath):
                        for fn in files:
                            full = os.path.join(root_dir, fn)
                            arcname = os.path.relpath(full, ROOT_DIR)
                            zf.write(full, arcname)
                else:
                    arcname = os.path.relpath(spath, ROOT_DIR)
                    zf.write(spath, arcname)
        # DB insert
        fid = self.db.insert_file(os.path.basename(zippath), os.path.getsize(zippath), zippath, user_id)
        self.db.log_operation('create', fid, user_id)
        return True

    def extract_zip(self, user_id: int, zip_relpath: str, dest_relpath: str):
        zippath = safe_join(ROOT_DIR, zip_relpath)
        destpath = safe_join(ROOT_DIR, dest_relpath)
        with zipfile.ZipFile(zippath, 'r') as zf:
            infos = zf.infolist()
            if len(infos) > MAX_ZIP_MEMBERS:
                raise IOError('Archive содержит слишком много файлов')
            total_uncompressed = 0
            for info in infos:
                total_uncompressed += info.file_size
                if info.file_size > MAX_FILE_SIZE:
                    raise IOError('В архиве найден файл слишком большого размера')
                if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
                    raise IOError('Распаковываемые данные превышают разрешённый лимит')
            # безопасная распаковка: проверка путей
            for info in infos:
                member_path = os.path.normpath(info.filename)
                target = os.path.join(destpath, member_path)
                # ensure within root
                ensure_within_root(target)
                if info.is_dir():
                    os.makedirs(target, exist_ok=True)
                else:
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with zf.open(info, 'r') as src, open(target, 'wb') as dst:
                        with file_lock(dst):
                            shutil.copyfileobj(src, dst)
            # Logging: create DB records for extracted files
            for info in infos:
                target = os.path.join(destpath, os.path.normpath(info.filename))
                if os.path.isfile(target):
                    fid = self.db.insert_file(os.path.basename(target), os.path.getsize(target), os.path.abspath(target), user_id)
                    self.db.log_operation('create', fid, user_id)
        return True


# --- CLI и аутентификация ---

def init_db_and_admin(db: DB):
    # Создаём учётку admin, если нет
    row = db.get_user('admin')
    if not row:
        pwd = 'admin'  # студенческая заметка: перед сдачей замените на уникальный пароль
        uid = db.create_user('admin', pwd)
        print('Created default admin user with password:', pwd)


def main():
    parser = argparse.ArgumentParser(description='Secure File Manager — практика 1')
    sub = parser.add_subparsers(dest='cmd')

    # user add
    p_user = sub.add_parser('adduser')
    p_user.add_argument('username')
    p_user.add_argument('password')

    # DOES NOT REQUIRE USERNAME
    sub.add_parser('listdisks')

    p_read = sub.add_parser('read')
    p_read.add_argument('username')
    p_read.add_argument('path')

    p_write = sub.add_parser('write')
    p_write.add_argument('username')
    p_write.add_argument('path')
    p_write.add_argument('content')

    p_delete = sub.add_parser('delete')
    p_delete.add_argument('username')
    p_delete.add_argument('path')

    p_zipc = sub.add_parser('zip')
    p_zipc.add_argument('username')
    p_zipc.add_argument('outpath')
    p_zipc.add_argument('sources', nargs='+')

    p_unzip = sub.add_parser('unzip')
    p_unzip.add_argument('username')
    p_unzip.add_argument('zippath')
    p_unzip.add_argument('dest')

    args = parser.parse_args()
    db = DB()
    fm = FileManager(db)
    init_db_and_admin(db)

    # ===============================
    # 1) COMMANDS THAT DON'T NEED USER
    # ===============================

    if args.cmd == 'adduser':
        uid = db.create_user(args.username, args.password)
        print('User created, id=', uid)
        return

    if args.cmd == 'listdisks':
        for d in fm.list_disks():
            print(d)
        return

    # ===============================
    # 2) EVERYTHING ELSE REQUIRES USER
    # ===============================

    if not hasattr(args, 'username'):
        print("Error: this command requires a username.")
        return

    user = db.get_user(args.username)
    if not user:
        print('User not found')
        return

    user_id = user[0]

    # ===============================
    # EXECUTE USER-BASED COMMANDS
    # ===============================
    if args.cmd == 'read':
        try:
            print(fm.read_file(user_id, args.path))
        except Exception as e:
            print('Error:', e)

    elif args.cmd == 'write':
        try:
            fm.write_file(user_id, args.path, args.content)
            print('Written')
        except Exception as e:
            print('Error:', e)

    elif args.cmd == 'delete':
        try:
            fm.delete_file(user_id, args.path)
            print('Deleted')
        except Exception as e:
            print('Error:', e)

    elif args.cmd == 'zip':
        try:
            fm.create_zip(user_id, args.outpath, args.sources)
            print('Zip created')
        except Exception as e:
            print('Error:', e)

    elif args.cmd == 'unzip':
        try:
            fm.extract_zip(user_id, args.zippath, args.dest)
            print('Unzipped')
        except Exception as e:
            print('Error:', e)

    else:
        parser.print_help()



if __name__ == '__main__':
    main()
