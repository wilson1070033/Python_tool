import socket
import threading
import struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256

# 配置
SERVER_HOST = '127.0.0.1'  # 服務器地址（預設為本機回環地址）
SERVER_PORT = 5000         # 服務器埠（需與服務器端一致）

# RSA 密鑰全域變數
client_private_key = None
client_public_key = None
server_public_key = None

def generate_or_load_keys():
    """生成RSA密鑰對，如有現有密鑰則載入"""
    global client_private_key, client_public_key
    try:
        # 嘗試從文件載入已有的私鑰
        client_private_key = RSA.import_key(open("client_private.pem", "rb").read())
        client_public_key = RSA.import_key(open("client_public.pem", "rb").read())
        print("[Client] 已從現有文件載入 RSA 密鑰對。")
    except Exception as e:
        # 如無法載入則生成新的密鑰對並保存
        client_private_key = RSA.generate(2048)
        client_public_key = client_private_key.publickey()
        with open("client_private.pem", "wb") as f:
            f.write(client_private_key.export_key())
        with open("client_public.pem", "wb") as f:
            f.write(client_public_key.export_key())
        print("[Client] 生成新的 RSA 密鑰對並保存為 'client_private.pem' 和 'client_public.pem'。")

def recv_all(sock, length):
    """從套接字接收指定長度的資料"""
    data = b''
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            return None  # 連線關閉
        data += packet
    return data

def receive_messages(sock):
    """從服務器接收加密消息，解密並驗證後打印"""
    # 構造 解密器 和 簽名驗證器
    decryptor = PKCS1_OAEP.new(client_private_key, hashAlgo=SHA256)  # 用客戶端私鑰解密
    verifier = pss.new(server_public_key)  # 用服務器公鑰驗證簽名
    while True:
        try:
            # 接收密文長度 (4 bytes)
            data = recv_all(sock, 4)
            if not data:
                print("[Client] 連線已關閉。")
                break
            cipher_len = struct.unpack('!I', data)[0]
            cipher_text = recv_all(sock, cipher_len)
            if cipher_text is None:
                print("[Client] 未接收到完整密文，連線可能已關閉。")
                break
            # 接收簽名長度 (4 bytes)
            sig_len_data = recv_all(sock, 4)
            if not sig_len_data:
                print("[Client] 未接收到簽名長度。")
                break
            sig_len = struct.unpack('!I', sig_len_data)[0]
            signature = recv_all(sock, sig_len)
            if signature is None:
                print("[Client] 未接收到完整簽名，連線可能已關閉。")
                break

            # 解密
            try:
                plain_bytes = decryptor.decrypt(cipher_text)
            except Exception as e:
                print("[Client] 解密失敗，可能密文不正確或密鑰不匹配。")
                continue

            # 驗證簽名
            h = SHA256.new(plain_bytes)
            try:
                verifier.verify(h, signature)
                signature_ok = True
            except (ValueError, TypeError):
                signature_ok = False

            message = plain_bytes.decode('utf-8', errors='ignore')
            if signature_ok:
                print(f"[Client] 收到服務器的消息: '{message}' (簽名驗證通過)")
            else:
                print(f"[Client] 收到服務器的消息: '{message}' (簽名不正確！)")

        except ConnectionResetError:
            print("[Client] 與服務器的連線被重置。")
            break
        except Exception as e:
            print(f"[Client] 接收消息時發生錯誤: {e}")
            break

def client_program():
    global server_public_key
    # 生成或載入RSA密鑰
    generate_or_load_keys()
    # 與服務器建立連線
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_HOST, SERVER_PORT))
        print(f"[Client] 已連接到服務器 {SERVER_HOST}:{SERVER_PORT}")
    except Exception as e:
        print(f"[Client] 無法連接到服務器: {e}")
        return

    # 握手：發送客戶端公鑰，接收服務器公鑰
    try:
        client_pubkey_pem = client_public_key.export_key()
        # 發送客戶端公鑰（先發長度再發內容）
        sock.sendall(struct.pack('!I', len(client_pubkey_pem)))
        sock.sendall(client_pubkey_pem)
        # 接收服務器公鑰
        length_data = recv_all(sock, 4)
        if not length_data:
            print("[Client] 握手失敗：未收到服務器公鑰長度")
            sock.close()
            return
        pubkey_len = struct.unpack('!I', length_data)[0]
        pubkey_data = recv_all(sock, pubkey_len)
        if not pubkey_data:
            print("[Client] 握手失敗：未收到完整的服務器公鑰")
            sock.close()
            return
        server_public_key = RSA.import_key(pubkey_data)
        print(f"[Client] 收到服務器公鑰（{pubkey_len} bytes），握手成功。")
    except Exception as e:
        print(f"[Client] 握手過程中發生錯誤: {e}")
        sock.close()
        return

    # 啟動執行緒接收服務器的消息
    recv_thread = threading.Thread(target=receive_messages, args=(sock,), daemon=True)
    recv_thread.start()

    # 主執行緒讀取使用者輸入並發送給服務器
    encryptor = PKCS1_OAEP.new(server_public_key, hashAlgo=SHA256)  # 用服務器公鑰加密
    signer = pss.new(client_private_key)  # 用客戶端私鑰簽名
    print("[Client] 現在可以輸入消息發送給服務器，輸入 'exit' 結束對話。")
    while True:
        try:
            message = input("")
        except EOFError:
            # 控制臺輸入被關閉
            break
        if message.strip().lower() == 'exit':
            print("[Client] 結束與服務器的連線。")
            break
        if message == "":
            continue  # 空輸入不發送
        plain_bytes = message.encode('utf-8')
        # 加密並簽名
        cipher_bytes = encryptor.encrypt(plain_bytes)             # 使用服務器公鑰加密
        h = SHA256.new(plain_bytes)
        signature = signer.sign(h)                                # 用客戶端私鑰對明文簽名
        # 發送 密文和簽名 （包含長度資訊）
        try:
            sock.sendall(struct.pack('!I', len(cipher_bytes)))
            sock.sendall(cipher_bytes)
            sock.sendall(struct.pack('!I', len(signature)))
            sock.sendall(signature)
        except Exception as e:
            print(f"[Client] 發送消息時出錯: {e}")
            break

    # 結束時關閉套接字
    sock.close()

if __name__ == "__main__":
    client_program()
