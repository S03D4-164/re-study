import os
import struct
import sys

def decrypt_asset(input_path, output_dir):
    # Sa.java から取得した鍵 (signed byte -> unsigned byte)
    ak_signed = [69, 64, 127, 3, -88, 92, -120, -128, 94, 127, -91, 61, -68, 51, -87, -97, -70, -1, 107, -35, -90, -72, 68, -119, -79, 14, -80, -87, 15, -15, -71, 33];
    key = bytes([b & 0xFF for b in ak_signed])
    key_len = len(key)

    print(f"[*] Reading encrypted asset: {input_path}")
    with open(input_path, "rb") as f:
        data = bytearray(f.read())

    print(f"[*] Encrypted size: {len(data)} bytes")
    print(f"[*] Decrypting with XOR key (length: {key_len})...")
    
    # XOR 復号
    for i in range(len(data)):
        data[i] ^= key[i % key_len]

    # 出力先ディレクトリの準備
    os.makedirs(output_dir, exist_ok=True)
    
    # 復号済み生バイナリ全体の保存
    raw_path = os.path.join(output_dir, "decrypted_raw.bin")
    with open(raw_path, "wb") as f:
        f.write(data)
    print(f"[+] Saved full decrypted payload to: {raw_path}")

    # フォーマット解析
    if len(data) < 8:
        print("[-] Data too small")
        return

    num_dex = struct.unpack_from("<I", data, 0)[0]
    print(f"[+] Detected {num_dex} DEX file(s) in payload")

    offset = 4
    for i in range(num_dex):
        if offset + 4 > len(data):
            print(f"[-] Truncated before reading dex #{i} length")
            break
        dex_len = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        
        if offset + dex_len > len(data):
            print(f"[-] Truncated: dex #{i} expects {dex_len} bytes, only {len(data) - offset} left")
            break

        dex_bytes = data[offset:offset+dex_len]
        offset += dex_len

        dex_magic = bytes(dex_bytes[:4])
        print(f"[*] DEX #{i+1}: length = {dex_len} bytes, magic = {dex_magic}")

        out_dex_path = os.path.join(output_dir, f"classes_extracted_{i+1}.dex")
        with open(out_dex_path, "wb") as f:
            f.write(dex_bytes)
        print(f"[★] Extracted and saved: {out_dex_path}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        asset_file = sys.argv[1]
    else:
        asset_file = r"3rd_payload/jadx/resources/assets/hdjnwsmxo"
    
    out_dir = r"4th_payload"
    decrypt_asset(asset_file, out_dir)
