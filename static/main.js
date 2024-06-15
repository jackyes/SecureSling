// Function to encrypt a file
async function encryptFile(file) {
    if (!crypto || !crypto.subtle) {
        alert('Web Crypto API not supported. Please use a modern browser with HTTPS.');
        return;
    }
    const key = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedContent = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        new Uint8Array(await file.arrayBuffer())
    );
    return { encryptedContent, key, iv };
}

// Function to export a key in raw format
async function exportKey(key) {
    const exported = await crypto.subtle.exportKey("raw", key);
    return Array.from(new Uint8Array(exported));
}

// Function to import a key from an array
async function importKey(keyArray) {
    const key = new Uint8Array(keyArray);
    return await crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, true, ["decrypt"]);
}

// Function to display an error message
function displayError(message) {
    const errorMessage = document.getElementById('errorMessage');
    errorMessage.textContent = message;
    errorMessage.classList.remove('d-none');
    setTimeout(() => {
        errorMessage.classList.add('d-none');
    }, 5000);
}

// Function to upload a file
let isUploading = false;
async function uploadFile() {
    if (isUploading) {
        return;
    }

    isUploading = true;
    const uploadButton = document.getElementById('uploadButton');
    const selectFileButton = document.getElementById('selectFileButton');

    uploadButton.disabled = true;
    selectFileButton.disabled = true;

    const fileInput = document.getElementById('fileInput');
    const files = fileInput.files;
    if (files.length === 0) {
        displayError('Please select a file or drag and drop a file.');
        isUploading = false;
        uploadButton.disabled = false;
        selectFileButton.disabled = false;
        return;
    }

    const statusMessage = document.getElementById('statusMessage');
    statusMessage.textContent = 'Preparing files...';

    let fileToEncrypt;
    if (files.length === 1) {
        fileToEncrypt = files[0];
    } else {
        // Create a new zip file if there are multiple files
        const zip = new JSZip();
        for (let i = 0; i < files.length; i++) {
            zip.file(files[i].name, files[i]);
        }
        // Generate the zip file as a Blob
        fileToEncrypt = await zip.generateAsync({ type: 'blob' });
    }

    try {
        // Encrypt the file (or zip)
        statusMessage.textContent = 'Encrypting...';
        let password = null;
        const passwordInput = document.getElementById('password');
        if (passwordInput.value) {
            password = passwordInput.value;
        }

        const formData = new FormData();
        let encryptedContent, key, iv, salt;

        if (password) {
            const result = await encryptFileWithPassword(fileToEncrypt, password);
            encryptedContent = result.encryptedContent;
            key = result.key;
            iv = result.iv;
            salt = result.salt;
        } else {
            const result = await encryptFile(fileToEncrypt);
            encryptedContent = result.encryptedContent;
            key = result.key;
            iv = result.iv;
        }

        const exportedKey = await exportKey(key);
        formData.append('file', new Blob([encryptedContent]), files.length === 1 ? files[0].name : 'encrypted.zip');
        formData.append('oneTimeDownload', document.getElementById('oneTimeDownload').checked);

        const expiryDate = document.getElementById('expiryDate').value;
        if (expiryDate) {
            formData.append('expiryDate', expiryDate);
        }

        const maxDownloads = document.getElementById('maxDownloads').value;
        if (maxDownloads) {
            formData.append('maxDownloads', maxDownloads);
        }

        const progressBar = document.getElementById('progressBar');
        const progressContainer = document.getElementById('progressContainer');
        progressContainer.classList.remove('d-none');
        progressBar.style.width = '0%';
        progressBar.textContent = '0%';
        statusMessage.textContent = 'Uploading...';

        const xhr = new XMLHttpRequest();
        xhr.open('POST', `${window.location.origin}/share/upload`, true);
        const startTime = new Date().getTime();

        xhr.upload.addEventListener('progress', (e) => {
            if (e.lengthComputable) {
                const percentComplete = (e.loaded / e.total) * 100;
                progressBar.style.width = percentComplete + '%';
                progressBar.textContent = Math.round(percentComplete) + '%';

                // Calculate file size
                const fileSize = e.total;
                const fileSizeMB = (fileSize / (1024 * 1024)).toFixed(2);
                const fileSizeGB = (fileSize / (1024 * 1024 * 1024)).toFixed(2);
                const fileSizeText = fileSize < 1024 * 1024 ? `${fileSize} bytes` : (fileSize < 1024 * 1024 * 1024 ? `${fileSizeMB} MB` : `${fileSizeGB} GB`);

                // Calculate upload speed
                const now = new Date().getTime();
                const timeDiff = now - startTime;
                const speed = e.loaded / timeDiff;
                const speedMB = (speed / 1024).toFixed(2);
                const speedText = `${speedMB} MB/s`;

                // Calculate uploaded size
                const upfileSize = e.loaded;
                const upfileSizeMB = (upfileSize / (1024 * 1024)).toFixed(2);
                const upfileSizeGB = (upfileSize / (1024 * 1024 * 1024)).toFixed(2);
                const upfileSizeText = upfileSize < 1024 * 1024 ? `${upfileSize} bytes` : (upfileSize < 1024 * 1024 * 1024 ? `${upfileSizeMB} MB` : `${upfileSizeGB} GB`);

                uploadedBytes.textContent = `${upfileSizeText} / ${fileSizeText} - ${speedText}`;
            } else {
                console.log('Progress information cannot be calculated because the total size is unknown');
            }
        });

        xhr.onreadystatechange = async () => {
            if (xhr.readyState === XMLHttpRequest.DONE) {
                if (xhr.status === 200) {
                    const result = JSON.parse(xhr.responseText);
                    const fileID = result.file_id;
                    const keyString = btoa(JSON.stringify(exportedKey));
                    const ivString = base64UrlEncode(iv);
                    const fileName = encodeURIComponent(files.length === 1 ? files[0].name : 'encrypted.zip');
                    let encodedLink;

                    if (password) {
                        const saltForLink = base64UrlEncode(salt);
                        encodedLink = btoa(`fileID=${fileID}&iv=${ivString}&salt=${saltForLink}&filename=${fileName}`);
                    } else {
                        encodedLink = btoa(`fileID=${fileID}&key=${keyString}&iv=${ivString}&filename=${fileName}`);
                    }

                    const link = `${window.location.origin}/share/download.html#${encodedLink}`;

                    const fileIDElement = document.getElementById('fileID');
                    const fileLinkElement = document.getElementById('fileLink');
                    const linkContainer = document.getElementById('linkContainer');

                    fileIDElement.textContent = `File ID: ${fileID}`;
                    fileLinkElement.value = link;
                    linkContainer.classList.remove('d-none');
                    progressContainer.classList.add('d-none');
                    statusMessage.textContent = 'File uploaded successfully';
                    isUploading = false;
                    uploadButton.disabled = false;
                    selectFileButton.disabled = false;
                } else {
                    const errorText = await xhr.responseText();
                    displayError(`Error: ${errorText}`);
                    progressContainer.classList.add('d-none');
                    isUploading = false;
                    uploadButton.disabled = false;
                    selectFileButton.disabled = false;
                }
            }
        };

        xhr.onerror = () => {
            displayError('An error occurred while uploading the file.');
            progressContainer.classList.add('d-none');
            isUploading = false;
            uploadButton.disabled = false;
            selectFileButton.disabled = false;
        };

        xhr.send(formData);
    } catch (error) {
        displayError(`Error: ${error.message}`);
        progressContainer.classList.add('d-none');
        isUploading = false;
        uploadButton.disabled = false;
        selectFileButton.disabled = false;
    }
}

//function to generate encryption key from password
async function generateKeyFromPassword(password, salt) {
    if (!salt) {
        salt = window.crypto.getRandomValues(new Uint8Array(16));
    }
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );

    const key = await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 250000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );

    return { key, salt };
}

// Function to endecrypt a file with password
async function encryptFileWithPassword(file, password) {
    if (!window.crypto || !window.crypto.subtle) {
        alert('Web Crypto API not supported. Please use a modern browser with HTTPS.');
        return;
    }
    const { key, salt } = await generateKeyFromPassword(password);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedContent = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        new Uint8Array(await file.arrayBuffer())
    );
    return { encryptedContent, key, iv, salt };
}

// Function to decrypt a file with password
async function decryptFileWithPassword(encryptedContent, password, salt, iv) {
    const key = await generateKeyFromPassword(password, salt);
    return await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encryptedContent
    );
}

// Function to copy the link to the clipboard
function copyLink() {
    const fileLinkElement = document.getElementById('fileLink');
    fileLinkElement.select();
    fileLinkElement.setSelectionRange(0, 99999);
    document.execCommand("copy");
    alert("Link copied to clipboard: " + fileLinkElement.value);
}

// Function to activate file input
function triggerFileInput() {
    document.getElementById('fileInput').click();
}

// Function to manage file selection
function handleFileSelect(event) {
    const fileInput = event.target;
    const selectedFileName = document.getElementById('selectedFileName');
    if (fileInput.files.length > 0) {
        const fileName = fileInput.files[0].name;
        selectedFileName.textContent = `Selected file: ${fileName}`;
    } else {
        selectedFileName.textContent = '';
    }
}

// Event listener for drag and drop
document.addEventListener("DOMContentLoaded", () => {
    const dragDropArea = document.getElementById('dragDropArea');
    dragDropArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        dragDropArea.classList.add('drag-over');
    });
    dragDropArea.addEventListener('dragleave', (e) => {
        e.preventDefault();
        dragDropArea.classList.remove('drag-over');
    });
    dragDropArea.addEventListener('drop', (e) => {
        e.preventDefault();
        dragDropArea.classList.remove('drag-over');
        const droppedFile = e.dataTransfer.files[0];
        document.getElementById('fileInput').files = e.dataTransfer.files;
        handleFileSelect({ target: document.getElementById('fileInput') });
    });
});
function base64UrlEncode(arrayBuffer) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuffer)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

function base64UrlDecode(base64) {
    base64 = base64
        .replace(/-/g, '+')
        .replace(/_/g, '/');
    while (base64.length % 4) {
        base64 += '=';
    }
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

// Function to download a file
let isDownloading = false;

async function downloadFile() {
    if (isDownloading) {
        return;
    }

    isDownloading = true;
    const downloadButton = document.getElementById('downloadButton');
    downloadButton.disabled = true;

    const hashParams = new URLSearchParams(atob(window.location.hash.substring(1)));
    const fileID = hashParams.get('fileID');
    const salt = hashParams.has('salt') ? base64UrlDecode(hashParams.get('salt')) : null;
    const key = hashParams.has('key') ? JSON.parse(atob(hashParams.get('key'))) : null;
    const iv = base64UrlDecode(hashParams.get('iv'));
    const filename = decodeURIComponent(hashParams.get('filename'));

    const statusMessage = document.getElementById('statusMessage');
    const downloadedBytesElement = document.getElementById('downloadedBytes');
    const progressBar = document.getElementById('progressBar');
    const progressContainer = document.getElementById('progressContainer');
    const errorMessage = document.getElementById('errorMessage');

    if (!fileID || (!salt && !key) || !iv) {
        statusMessage.textContent = 'Missing parameters';
        return;
    }

    const passwordInputDiv = document.getElementById('passwordInputDiv');
    const passwordInput = document.getElementById('password');

    if (salt) {
        passwordInputDiv.classList.remove('d-none');
        passwordInput.focus();

        try {
            const password = await new Promise((resolve) => {
                passwordInput.addEventListener('keyup', function handler(event) {
                    if (event.key === 'Enter') {
                        passwordInput.removeEventListener('keyup', handler);
                        passwordInputDiv.classList.add('d-none');
                        resolve(passwordInput.value);
                    }
                });
            const submitPasswordButton = document.getElementById('submitPassword');
            submitPasswordButton.addEventListener('click', async () => {
                const passwordInputDiv = document.getElementById('passwordInputDiv');
                const passwordInput = document.getElementById('password');
                const password = passwordInput.value;
                passwordInputDiv.classList.add('d-none');
                const decryptionKey = await generateKeyFromPassword(password, salt);
                await startFileDownload(fileID, decryptionKey.key, iv, filename, statusMessage, downloadedBytesElement, progressBar, progressContainer, downloadButton);
            });
            });

            const decryptionKey = await generateKeyFromPassword(password, salt);
            await startFileDownload(fileID, decryptionKey.key, iv, filename, statusMessage, downloadedBytesElement, progressBar, progressContainer, downloadButton);

        } catch (error) {
            displayError(`Error: ${error.message}`);
        } finally {
            isDownloading = false;
            downloadButton.disabled = false;
        }
    } else {
        const decryptionKey = await importKey(key);
        await startFileDownload(fileID, decryptionKey, iv, filename, statusMessage, downloadedBytesElement, progressBar, progressContainer, downloadButton);
        isDownloading = false;
        downloadButton.disabled = false;
    }
}

async function startFileDownload(fileID, decryptionKey, iv, filename, statusMessage, downloadedBytesElement, progressBar, progressContainer, downloadButton) {
    progressContainer.classList.remove('d-none');
    progressBar.style.width = '0%';
    progressBar.textContent = '0%';
    statusMessage.textContent = 'Downloading...';

    const xhr = new XMLHttpRequest();
    xhr.open('GET', `/share/download/${fileID}`, true);
    xhr.responseType = 'arraybuffer';

    const startTime = new Date().getTime();

    xhr.onprogress = (e) => {
        if (e.lengthComputable) {
            const percentComplete = (e.loaded / e.total) * 100;
            progressBar.style.width = percentComplete + '%';
            progressBar.textContent = Math.round(percentComplete) + '%';

            const fileSize = e.total;
            const fileSizeMB = (fileSize / (1024 * 1024)).toFixed(2);
            const fileSizeGB = (fileSize / (1024 * 1024 * 1024)).toFixed(2);
            const fileSizeText = fileSize < 1024 * 1024 ? `${fileSize} bytes` : (fileSize < 1024 * 1024 * 1024 ? `${fileSizeMB} MB` : `${fileSizeGB} GB`);

            const now = new Date().getTime();
            const timeDiff = now - startTime;
            const speed = e.loaded / timeDiff;
            const speedMB = (speed / 1024).toFixed(2);
            const speedText = `${speedMB} MB/s`;

            const downfileSize = e.loaded;
            const downfileSizeMB = (downfileSize / (1024 * 1024)).toFixed(2);
            const downfileSizeGB = (downfileSize / (1024 * 1024 * 1024)).toFixed(2);
            const downfileSizeText = downfileSize < 1024 * 1024 ? `${downfileSize} bytes` : (downfileSize < 1024 * 1024 * 1024 ? `${downfileSizeMB} MB` : `${downfileSizeGB} GB`);

            downloadedBytesElement.textContent = `${downfileSizeText} / ${fileSizeText} - ${speedText}`;
        } else {
            console.log('Progress information cannot be calculated because the total size is unknown');
        }
    };

    xhr.onload = async () => {
        if (xhr.status === 200) {
            progressBar.style.width = '100%';
            progressBar.textContent = '100%';
            const encryptedContent = xhr.response;
            const file = await decryptFile(encryptedContent, decryptionKey, iv);
            const url = URL.createObjectURL(file);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename || 'decrypted_' + fileID;
            a.click();
            URL.revokeObjectURL(url);
            statusMessage.textContent = 'File downloaded and decrypted successfully';
            progressContainer.classList.add('d-none');
        } else {
            displayError('File not found');
        }
        downloadButton.disabled = false;
        isDownloading = false;
    };

    xhr.onerror = () => {
        displayError('An error occurred while downloading the file.');
        progressContainer.classList.add('d-none');
        downloadButton.disabled = false;
        isDownloading = false;
    };

    xhr.send();
}

// Function to decrypt a file
async function decryptFile(encryptedContent, key, iv) {
    try {
        const decryptedContent = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            encryptedContent
        );
        return new Blob([decryptedContent]);
    } catch (error) {
        console.error("Decryption failed or data integrity check failed:", error);
        throw new Error("Decryption failed or data integrity check failed.");
    }
}

document.getElementById('fileInput').addEventListener('change', (event) => {
    const fileName = event.target.files.length > 1
        ? `${event.target.files.length} files selected`
        : event.target.files[0].name;
    document.getElementById('selectedFileName').textContent = fileName;
});
