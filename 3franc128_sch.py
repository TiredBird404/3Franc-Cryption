import tkinter as tk
import time
from tkinter import messagebox

import zlib
import secrets
import hashlib
import hmac
from argon2.low_level import hash_secret_raw, Type

class Cryption:
    def __init__(self, text : str, key : str) -> None:
        self.key : str = StringProcessor(key).clean_space()
        self.text : str = text
        self.salt_length : int = 16 # 随机盐的字节大小
        self.mac_length : int = 16 # mac的字节大小

    def encryption(self) -> str:
        salt : bytes = secrets.token_bytes(self.salt_length) # 字节长度
        secret_key : bytes = self.generate_hash_secret(salt)

        compressed_text : str = StringProcessor(self.text).compress()
        shuffled_text : str = StringProcessor(compressed_text).intersect()
        encrypted_text : str = self.stream_cipher(shuffled_text, secret_key)
        
        hash_key : bytes = hashlib.sha3_256(secret_key).digest()
        mac : str = self.generate_mac(encrypted_text, hash_key)

        return salt.hex() + encrypted_text + mac
    
    def decryption(self) -> tuple[bool, str]:
        try:
            salt : bytes = bytes.fromhex(self.text[:self.salt_length*2])
            mac : str = self.text[-self.mac_length*2:]
            encrypted_text : str = self.text[self.salt_length*2:-self.mac_length*2]

            secret_key : bytes = self.generate_hash_secret(salt)
            hash_key : bytes = hashlib.sha3_256(secret_key).digest()
            check_mac : str = self.generate_mac(encrypted_text, hash_key)

            if not hmac.compare_digest(check_mac,mac):
                return False, ''

            decrypted_text : str = self.stream_cipher(encrypted_text, secret_key)
            unshuffled_text : str = StringProcessor(decrypted_text).reverse_intersect()
            decompressed_text : str = StringProcessor(unshuffled_text).decompress()

            return True, decompressed_text
        except:
            return False, ''
    
    @staticmethod
    def stream_cipher(text : str, key : bytes) -> str: # 流加密算法输出十六进制值
        bytes_text : bytes = bytes.fromhex(text) # text应是十六进制值
        len_text : int = len(bytes_text)
        derived_key : bytes = hashlib.shake_128(key).digest(len_text) # 将密钥派生至让每一个字节都有几乎随机的值

        return bytes([a ^ b for a, b in zip(bytes_text, derived_key)]).hex()

    def generate_hash_secret(self, salt : bytes) -> bytes:
        return hash_secret_raw( # 通过随机盐与密钥生成参数
            secret=self.key.encode('utf-8'),
            salt=salt,
            time_cost=4,
            memory_cost=256*1024, # KB
            parallelism=4,
            hash_len=16, # bytes
            type=Type.ID
        )
    
    def generate_mac(self, text : str, key : bytes) -> str: # 生成mac认证
        hmac_result : bytes = hmac.new(
            key=key,
            msg=bytes.fromhex(text),
            digestmod=hashlib.sha3_512
        ).digest()
        return hashlib.shake_128(hmac_result).hexdigest(self.mac_length)

class StringProcessor:
    def __init__(self, string : str) -> None:
        self.string = string
    
    def clean_space(self) -> str: # 清除字符串的空白字符
        return ''.join(self.string.split())

    def compress(self) -> str: # 压缩字符串，并输出十六进制文本
        data : bytes = self.string.encode('utf-8')
        data_compressed : bytes = zlib.compress(data)
        return data_compressed.hex()

    def decompress(self) -> str: # 解压十六进制的压缩结果，并输出明文
        data = bytes.fromhex(self.string)
        decompressed_data : bytes = zlib.decompress(data)
        return decompressed_data.decode("utf-8")
    
    def intersect(self) -> str: # 将文本交叉。例：abcdef -> bdface
        odd_chars : str = self.string[1::2]
        even_chars : str = self.string[::2]
        return odd_chars + even_chars
    
    def reverse_intersect(self) -> str: # 该逆向适用于偶数长度的文本，因为导入的十六进制字符串是bytes长度*2，所以其必然是偶数
        text : str = self.string
        half_len : int = len(text) // 2
        even_chars : str = text[:half_len]
        odd_chars : str = text[half_len:]
        return ''.join([second_char + first_char for second_char, first_char in zip(odd_chars, even_chars)])
    
    def change_line(self, line : int) -> str: # 每隔n个字符换行
        return '\n'.join([self.string[i:i + line] for i in range(0, len(self.string), line)])

class UIManager:
    def __init__(self, root : tk.Tk) -> None:
        self.root = root
        self.ui_setup()

    def ui_setup(self) -> None:
        self.root.title("3Franc-128bits")
        self.root.geometry("800x640")
        self.root.resizable(False,False)
        self.root.option_add("*Font", ("Noto Sans Mono",14))

        self.key_entry = tk.Entry(self.root)
        self.text_box = tk.Text(self.root)
        self.scrollbar = tk.Scrollbar(self.root,command=self.text_box.yview)

        self.generate_key_button = tk.Button(
            self.root,
            text="生成",
            command=self.generate_key
        )
        self.encryption_button = tk.Button(
            self.root,
            text="加密",
            command=self.access_encryption
        )
        self.decryption_button = tk.Button(
            self.root,
            text="解密",
            command=self.access_decryption
        )

        self.key_entry.place(x=15,y=15,width=715,height=35)
        self.text_box.place(x=15, y=55, width=755, height=510)
        self.scrollbar.place(x=770, y=55, width=15, height=510)
        self.text_box.config(yscrollcommand=self.scrollbar.set)

        self.key_entry.bind("<Control-Key-a>", self.select_all_entry)
        self.key_entry.bind("<Control-Key-A>", self.select_all_entry)
        self.text_box.bind("<Control-Key-a>", self.select_all_text)
        self.text_box.bind("<Control-Key-A>", self.select_all_text)

        self.generate_key_button.place(x=735,y=15,width=50,height=35)
        self.encryption_button.place(x=15, y=575,width=375, height=50)
        self.decryption_button.place(x=410, y=575,width=375, height=50)

        self.processing_ui(False)

    def processing_ui(self, is_processing : bool) -> None:
        if is_processing == True:
            self.root.config(cursor="watch")
            self.text_box.config(cursor="watch",state = "disabled")
            self.key_entry.config(cursor="watch",state = "disabled")
            self.encryption_button.config(state = "disabled")
            self.decryption_button.config(state = "disabled")
            self.generate_key_button.config(state = "disabled")
        else:
            self.root.config(cursor="arrow")
            self.text_box.config(cursor="xterm",state = "normal")
            self.key_entry.config(cursor="xterm",state = "normal")
            self.encryption_button.config(state = "normal")
            self.decryption_button.config(state = "normal")
            self.generate_key_button.config(state = "normal")
        self.root.update()

    def access_encryption(self) -> None:
        start_time : float = time.time()
        self.processing_ui(True)
        user_key : str = self.key_entry.get()
        user_text : str = self.text_box.get("1.0", "end-1c")

        cryption_program = Cryption(user_text, user_key)
        cryption_result : str = cryption_program.encryption()
        processed_result : str = StringProcessor(cryption_result).change_line(64)
        self.processing_ui(False)

        self.set_text_box(processed_result)
        end_time : float = time.time()
        messagebox.showinfo("加密完成",f"总共花费{int((end_time - start_time)*1000)/1000}秒")

    def access_decryption(self) -> None:
        start_time : float = time.time()
        self.processing_ui(True)
        user_key : str = self.key_entry.get()
        crypted_text : str = self.text_box.get("1.0", "end-1c")
        cryption_program = Cryption(StringProcessor(crypted_text).clean_space(), user_key)
        cryption_result : tuple[bool,str] = cryption_program.decryption()
        self.processing_ui(False)

        if cryption_result[0] == True:
            self.set_text_box(cryption_result[1])
            end_time : float = time.time()
            messagebox.showinfo("解密完成",f"总共花费{int((end_time - start_time)*1000)/1000}秒")
        else:
            messagebox.showerror("解密失败","密钥、密文不正确。")

    def generate_key(self) -> None:
        new_key : str = secrets.token_hex(16) # 字节长度
        self.key_entry.delete(0,tk.END)
        self.key_entry.insert(0,new_key)

    def set_text_box(self, new_text : str) -> None:
        self.text_box.delete("1.0", "end-1c")
        self.text_box.insert("1.0", new_text)

    def select_all_text(self,_) -> str:
        self.text_box.tag_add(tk.SEL, "1.0", tk.END)
        self.text_box.mark_set(tk.INSERT, "1.0")
        self.text_box.see(tk.INSERT)
        return "break"
    
    def select_all_entry(self,_) -> str:
        self.key_entry.select_range(0, tk.END)
        return "break"

def main() -> None:
    root = tk.Tk()
    app = UIManager(root)
    _ = app
    root.mainloop()

if __name__ == "__main__":
    main()
