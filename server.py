import socket
import threading
import struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256

# 配置
HOST = '0.0.0.0'    # 服務器監聽地址 (0.0.0.0 為本機所有介面)
PORT = 5000         # 服務器監聽埠

# RSA 密鑰與加密/簽名對象的全域變數
server_private_key = None
server_public_key = None
client_public_key = None

def generate_or_load_keys():
    """生成RSA密鑰對，如有現有密鑰則載入"""
    global server_private_key, server_public_key
    try:
        # 嘗試從文件載入已有的私鑰
        server_private_key = RSA.import_key(open("server_private.pem", "rb").read())
        server_public_key = RSA.import_key(open("server_public.pem", "rb").read())
        print("[Server] 已從現有文件載入 RSA 密鑰對。")
    except Exception as e:
        # 如無法載入則生成新的密鑰對並保存
        server_private_key = RSA.generate(2048)
        server_public_key = server_private_key.publickey()
        # 將密鑰保存為 PEM 文件，方便下次直接使用
        with open("server_private.pem", "wb") as f:
            f.write(server_private_key.export_key())
        with open("server_public.pem", "wb") as f:
            f.write(server_public_key.export_key())
        print("[Server] 生成新的 RSA 密鑰對並保存為 'server_private.pem' 和 'server_public.pem'。")

def recv_all(sock, length):
    """從套接字接收指定長度的資料"""
    data = b''
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            return None  # 連線關閉
        data += packet
    return data

def handle_client_connection(conn, addr):
    """處理與客戶端的通信（包括握手和隨後的消息收發）"""
    global client_public_key

    print(f"[Server] 有客戶端連接自 {addr}")

    # 1. 握手階段：接收客戶端公鑰，並發送服務器公鑰
    try:
        # 先接收4字節，表示客戶端公鑰長度
        length_data = recv_all(conn, 4)
        if not length_data:
            print("[Server] 握手失敗：未收到客戶端公鑰長度")
            conn.close()
            return
        pubkey_len = struct.unpack('!I', length_data)[0]
        # 接收指定長度的公鑰資料
        pubkey_data = recv_all(conn, pubkey_len)
        if not pubkey_data:
            print("[Server] 握手失敗：未收到完整的客戶端公鑰")
            conn.close()
            return
        # 載入客戶端公鑰
        client_public_key = RSA.import_key(pubkey_data)
        print(f"[Server] 收到客戶端的公鑰（{pubkey_len} bytes）")

        # 發送服務器的公鑰給客戶端
        server_pubkey_pem = server_public_key.export_key()  # 服務器公鑰PEM編碼 (bytes)
        # 先發送4字節表示長度，再發送公鑰內容
        conn.sendall(struct.pack('!I', len(server_pubkey_pem)))
        conn.sendall(server_pubkey_pem)
        print(f"[Server] 已發送服務器公鑰給客戶端（{len(server_pubkey_pem)} bytes）")
        print("[Server] RSA 公鑰交換完成（握手成功）")
    except Exception as e:
        print(f"[Server] 握手過程中發生錯誤: {e}")
        conn.close()
        return

    # 2. 建立 RSA 加密/解密、簽名/驗證 所需的對象
    # 解密器：使用服務器私鑰和 OAEP（默認 SHA-1，可指定 SHA-256 增強安全性）
    decryptor = PKCS1_OAEP.new(server_private_key, hashAlgo=SHA256)
    # 簽名驗證器：使用客戶端公鑰來驗證簽名 (PSS)
    verifier = pss.new(client_public_key)

    # 3. 啟動一個執行緒用於接收客戶端消息
    def receive_messages():
        while True:
            try:
                # 接收4字節獲取密文長度
                data = recv_all(conn, 4)
                if not data:
                    print("[Server] 與客戶端的連線已關閉。")
                    break
                cipher_len = struct.unpack('!I', data)[0]
                cipher_text = recv_all(conn, cipher_len)
                if cipher_text is None:
                    print("[Server] 未能接收到完整的密文，連線可能已關閉。")
                    break
                # 接收4字節獲取簽名長度
                sig_len_data = recv_all(conn, 4)
                if not sig_len_data:
                    print("[Server] 未接收到簽名長度，連線可能已關閉。")
                    break
                sig_len = struct.unpack('!I', sig_len_data)[0]
                signature = recv_all(conn, sig_len)
                if signature is None:
                    print("[Server] 未能接收到完整簽名，連線可能已關閉。")
                    break

                # 解密消息
                try:
                    plain_bytes = decryptor.decrypt(cipher_text)
                except Exception as e:
                    print("[Server] 解密失敗，可能使用了錯誤的密鑰或數據遭破壞。")
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
                    print(f"[Server] 收到來自客戶端的消息: '{message}' (簽名驗證通過)")
                else:
                    print(f"[Server] 收到來自客戶端的消息: '{message}' (簽名不正確！)")

            except ConnectionResetError:
                print("[Server] 連線被客戶端重置。")
                break
            except Exception as e:
                print(f"[Server] 接收消息時發生錯誤: {e}")
                break
        # 結束接收執行緒後，關閉連線
        conn.close()

    recv_thread = threading.Thread(target=receive_messages, daemon=True)
    recv_thread.start()

    # 4. 主執行緒迴圈：讀取服務器控制臺輸入並發送給客戶端
    encryptor = PKCS1_OAEP.new(client_public_key, hashAlgo=SHA256)  # 用客戶端公鑰加密
    signer = pss.new(server_private_key)  # 用服務器私鑰簽名
    print("[Server] 現在可以輸入消息並發送給客戶端，輸入 'exit' 可斷開連線。")
    while True:
        try:
            message = input("")  # 從服務器控制臺讀取輸入
        except EOFError:
            # 如果控制臺輸入被關閉，則退出
            break
        if message.strip().lower() == 'exit':
            print("[Server] 關閉與客戶端的連線。")
            break
        if message == "":
            continue  # 空消息不發送
        # 加密和簽名
        plain_bytes = message.encode('utf-8')
        cipher_bytes = encryptor.encrypt(plain_bytes)             # 使用客戶端公鑰加密
        h = SHA256.new(plain_bytes)
        signature = signer.sign(h)                                # 用服務器私鑰對明文簽名
        # 發送密文和簽名（帶長度前綴）
        try:
            conn.sendall(struct.pack('!I', len(cipher_bytes)))
            conn.sendall(cipher_bytes)
            conn.sendall(struct.pack('!I', len(signature)))
            conn.sendall(signature)
        except Exception as e:
            print(f"[Server] 發送消息時出錯: {e}")
            break

    # 結束時關閉連線
    conn.close()
    print("[Server] 連線已關閉。")

if __name__ == "__main__":
    # 生成或載入RSA密鑰對
    generate_or_load_keys()
    # 啟動Socket服務器
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((HOST, PORT))
        server_sock.listen(1)
        print(f"[Server] 等待客戶端連接 (埠: {PORT})...")
        try:
            conn, addr = server_sock.accept()
        except KeyboardInterrupt:
            print("\n[Server] 手動中斷服務器。")
            server_sock.close()
            exit(0)
        # 處理客戶端連接
        handle_client_connection(conn, addr)
