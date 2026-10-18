import java.io.*;
import java.util.zip.InflaterInputStream;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

//2nd_payloadのCf.javaに対象のアセットと復号キーが埋め込まれている
public class DecryptPayload {
    private static byte[] hexToBytes(String hex) {
        int length = hex.length() / 2;
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }

    public static void main(String[] args) {
        String keyHex = "0bde93d47df32600eaa921ad328bcd32e450eaff2ac92a652f82ea6e51d9b1fb";
	    File inputFile = new File("1st_payload/jadx/resources/assets/dwIdXMCV");
        File outputDir = new File("3rd_payload");
        File outputFile = new File(outputDir, "extractad.apk");

        if (!inputFile.exists()) {
            System.err.println("[-] Input file does not exist: " + inputFile.getAbsolutePath());
            return;
        }

        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }

        System.out.println("[*] Target encrypted asset: " + inputFile.getAbsolutePath());
        System.out.println("[*] File size: " + inputFile.length() + " bytes");
        System.out.println("[*] Key (HEX): " + keyHex);

        try (FileInputStream fis = new FileInputStream(inputFile)) {
            byte[] iv = new byte[16];
            int readIv = 0;
            while (readIv < 16) {
                int r = fis.read(iv, readIv, 16 - readIv);
                if (r < 0) {
                    throw new IOException("Payload too small to read 16-byte IV");
                }
                readIv += r;
            }

            StringBuilder ivHex = new StringBuilder();
            for (byte b : iv) {
                ivHex.append(String.format("%02x", b));
            }
            System.out.println("[*] Extracted IV (HEX): " + ivHex.toString());

            byte[] keyBytes = hexToBytes(keyHex);
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

            System.out.println("[*] Decrypting AES-256-CTR and decompressing with Inflater...");
            try (CipherInputStream cis = new CipherInputStream(fis, cipher);
                 InflaterInputStream iis = new InflaterInputStream(cis);
                 FileOutputStream fos = new FileOutputStream(outputFile);
                 BufferedOutputStream bos = new BufferedOutputStream(fos, 131072)) {

                byte[] buffer = new byte[262144];
                long totalBytes = 0;
                int readBytes;
                while ((readBytes = iis.read(buffer)) != -1) {
                    bos.write(buffer, 0, readBytes);
                    totalBytes += readBytes;
                }
                bos.flush();

                System.out.println("[+] Decryption and inflation successful!");
                System.out.println("[+] Extracted APK: " + outputFile.getAbsolutePath());
                System.out.println("[+] Extracted APK size: " + totalBytes + " bytes (" + (totalBytes / (1024 * 1024.0)) + " MB)");

                // Check PK zip header
                try (FileInputStream checkFis = new FileInputStream(outputFile)) {
                    byte[] header = new byte[4];
                    checkFis.read(header);
                    if (header[0] == 0x50 && header[1] == 0x4B && header[2] == 0x03 && header[3] == 0x04) {
                        System.out.println("[★] Valid ZIP/APK magic header confirmed (PK\\x03\\x04)!");
                    } else {
                        System.out.println("[!] Warning: Header did not match standard PK magic: " + String.format("%02x %02x %02x %02x", header[0], header[1], header[2], header[3]));
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
