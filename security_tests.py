import subprocess
import os

APP = "number_1.py"


def run(cmd, stdin_data=None):
    print("\n=== RUNNING:", " ".join(cmd))
    try:
        if stdin_data is None:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
            print(out)
        else:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=False
            )
            out = proc.communicate(stdin_data)[0]
            print(out.decode(errors="ignore"))
    except subprocess.CalledProcessError as e:
        print(e.output)



def test_path_traversal():
    print("\n============================================================")
    print("[1] Атака обхода путей (PATH TRAVERSAL ATTACK)")
    print("============================================================")
    run(["python3", APP, "read", "admin", "../etc/passwd"])



# 2. SQL injection

def test_sql():
    print("\n============================================================")
    print("[2] SQL INJECTION")
    print("============================================================")
    payload = "admin' OR 1=1 --"
    run(["python3", APP, "read", payload, "notes/test.txt"])


# 3. Fake ZIP bomb

def test_zip_bomb():
    print("\n============================================================")
    print("[3] ZIP ATTACK (SIMULATED)")
    print("============================================================")

    os.makedirs("sandbox_root", exist_ok=True)
    bomb = "sandbox_root/fake_bomb.zip"

    with open(bomb, "wb") as f:
        f.write(b"PK\x03\x04BADBADBAD")

    run(["python3", APP, "unzip", "admin", "fake_bomb.zip", "bomb_out"])



# 4. XXE attack

def test_xxe():
    print("\n============================================================")
    print("[4] XML XXE ATTEMPT")
    print("============================================================")

    xml_payload = """<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root>&xxe;</root>
"""

    path = "sandbox_root/xxe_payload.xml"
    with open(path, "w") as f:
        f.write(xml_payload)

    run(["python3", APP, "read", "admin", "xxe_payload.xml"])



# 5. Race condition imitation

def test_race():
    print("\n============================================================")
    print("[5] Атака через состояние (RACE CONDITION ATTACK)")
    print("============================================================")

    run(["python3", APP, "write", "admin", "race.txt", "FIRST"])
    run(["python3", APP, "write", "admin", "race.txt", "SECOND"])

    print("\n→ Checking final content:")
    run(["python3", APP, "read", "admin", "race.txt"])



if __name__ == "__main__":
    test_path_traversal()
    test_sql()
    test_zip_bomb()
    test_xxe()
    test_race()

    print("\n============================================================")
    print("Все тесты проведены")
    print("============================================================")
