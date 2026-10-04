import os
import struct

def decrypt_xor_dex(input_path, output_dir, ak_signed):
    """
    libsa.so パッカーが使用する XOR 暗号化アセットを復号し、
    内包されている DEX ファイルを個別に抽出する。

    フォーマット:
      [先頭 4 バイト] : uint32_le  ... DEX ファイル数 (N)
      [N 回繰り返し]
        [4 バイト] : uint32_le  ... 各 DEX のサイズ
        [サイズバイト] : 生 DEX データ

    Args:
        input_path  (str): 暗号化アセットファイルのパス
        output_dir  (str): DEX ファイルの出力先ディレクトリ
        ak_signed (list): Sa.java に記載された signed byte の鍵配列
    """
    key = bytes([b & 0xFF for b in ak_signed])
    key_len = len(key)

    print(f"[*] Input  : {input_path}")
    print(f"[*] Key    : {key.hex()}")

    with open(input_path, "rb") as f:
        data = bytearray(f.read())

    print(f"[*] Size   : {len(data)} bytes")
    print(f"[*] XOR-decrypting (key length: {key_len})...")

    for i in range(len(data)):
        data[i] ^= key[i % key_len]

    os.makedirs(output_dir, exist_ok=True)

    if len(data) < 8:
        print("[-] Decrypted data too small")
        return

    num_dex = struct.unpack_from("<I", data, 0)[0]
    print(f"[+] DEX count: {num_dex}")

    offset = 4
    for i in range(num_dex):
        if offset + 4 > len(data):
            print(f"[-] Truncated before reading DEX #{i+1} length")
            break
        dex_len = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        if offset + dex_len > len(data):
            print(f"[-] Truncated: DEX #{i+1} expects {dex_len} bytes, only {len(data) - offset} left")
            break

        dex_bytes = bytes(data[offset:offset + dex_len])
        offset += dex_len

        magic = dex_bytes[:4]
        out_path = os.path.join(output_dir, f"dex_{i+1}.dex")
        with open(out_path, "wb") as f:
            f.write(dex_bytes)
        print(f"[★] DEX #{i+1}: {dex_len:,} bytes  magic={magic}  -> {out_path}")


# ============================================================
# 1st payload: assets/ueubdolfcxm
# ============================================================
AK_2ND_STAGE = [
    -10, -127, 8, 39, -10, 52, 124, -56, -12, 43, -107, -98,
    -87, -49, -61, -113, 7, 95, -107, -25, -117, -90, -122, -94,
    -1, -98, -76, -8, -115, -7, 66, 99
]

# ============================================================
# 2nd payload: assets/gyccuacowmgpj  (com.green.nest.titan 本体 DEX)
# ============================================================
AK_3RD_STAGE = [
    -56, -42, 95, 94, -28, -103, 6, 11, -72, 65, -5, 106,
    69, -12, 26, 15, -73, -95, -80, -91, -13, 29, 42, 44,
    -88, 107, -8, -117, -83, 27, -57, -115
]

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="XOR 復号 & DEX 抽出スクリプト (libsa.so パッカー対応)"
    )
    parser.add_argument(
        "--base",
        default=os.path.dirname(os.path.abspath(__file__)),
        help="ワークスペースのルートパス (デフォルト: スクリプトと同じディレクトリ)",
    )
    args = parser.parse_args()
    BASE = args.base

    print(f"[*] BASE: {BASE}")

    print("=" * 60)
    print("  [2nd stage] ueubdolfcxm")
    print("=" * 60)
    decrypt_xor_dex(
        input_path=os.path.join(BASE, "1st_payload", "apktool", "assets", "ueubdolfcxm"),
        output_dir=os.path.join(BASE, "2nd_payload", "extracted_dex"),
        ak_signed=AK_2ND_STAGE,
    )

    print()
    print("=" * 60)
    print("  [3rd stage] gyccuacowmgpj")
    print("=" * 60)
    decrypt_xor_dex(
        input_path=os.path.join(BASE, "3rd_payload", "jadx", "resources", "assets", "gyccuacowmgpj"),
        output_dir=os.path.join(BASE, "3rd_payload", "extracted_dex"),
        ak_signed=AK_3RD_STAGE,
    )
