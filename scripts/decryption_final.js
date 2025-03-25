async function decryptText(encryptedBase64, password) {
    try {
        const encryptedData = atob(encryptedBase64);  // Decode Base64
        const iv = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]); // Static IV
        const cipherText = new Uint8Array(encryptedData.split('').map(c => c.charCodeAt(0))); 

        const key = await getKeyFromPassword(password);
        
        const decryptedData = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            cipherText
        );

        return new TextDecoder().decode(decryptedData);  
    } catch (error) {
        console.error("Decryption failed:", error);
        return null;
    }
}

async function getKeyFromPassword(password) {
    const encoder = new TextEncoder();
    let keyData = encoder.encode(password);

    if (keyData.length < 32) {
        keyData = new Uint8Array(32);
        keyData.set(encoder.encode(password));
    }

    return crypto.subtle.importKey(
        "raw",
        keyData,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );
}

async function hashCode(input) {
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuffer))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
}

async function verifyCode() {
    const input = document.getElementById("codeInput").value.trim().toUpperCase();
    const hashedInput = await hashCode(input);
    const decryptedText = await decryptText("Qc2XHXe+gaL3LfheBjT3CV2BhX5m7ojtiCvX+A==", input);

    const expectedHash = "68a29d3fdf204ed41630911a32c03ba84d15a73130fc07b373fe247c418a3843";
        
    if (hashedInput === expectedHash) {
        result.innerHTML = "<span style='color:#7CFC00;'>✅ Zugriff freigegeben.</span><br><br><strong>🔑 Schlüssel lokalisiert.</strong><br>Versteckt unter dem zentralen " + decryptedText + ".";
    } else {
        result.innerHTML = "<span style='color:#ff6347;'>❌ Zugriff verweigert. Code ungültig.</span>";
    }
}