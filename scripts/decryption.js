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
    const input = document.getElementById('code').value.trim().toUpperCase();
    const hashedInput = await hashCode(input);
    const expectedHash = "8af80f3216ade256c42867c1126a71ef23496ca68afd9700afb6f1a6d69db317";
    const decryptedText = await decryptText("19/J2Lr1kLmCpjNjl5bZticPhlc9kL5FVD0=", input);

    if (hashedInput === expectedHash) {
        document.getElementById('result').classList.remove('hidden');
        document.getElementById('result-failed').classList.add('hidden');
        document.getElementById('secret').textContent = decryptedText;
    } else {
        document.getElementById('result-failed').classList.remove('hidden');
        document.getElementById('result').classList.add('hidden');
    }
}