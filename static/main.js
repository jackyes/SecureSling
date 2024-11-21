const PBKDF2_ITERATIONS = 100000;
const AES_KEY_LENGTH = 256;
const SALT_LENGTH = 16; // Added salt length constant

// Function to encrypt a file
async function encryptFile(file) {
    if (!crypto || !crypto.subtle) {
        alert('Web Crypto API not supported. Please use a modern browser with HTTPS.');
        return;
    }
    try {
        const key = await crypto.subtle.generateKey(
            { name: "AES-GCM", length: AES_KEY_LENGTH },
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
    } catch (error) {
        // console.error("Error during encryption:", error);  //
        // displayError("An error occurred during encryption.");
        return null;
    }
}

// Function to export a key in raw format
async function exportKey(key) {
    try {
        const exported = await crypto.subtle.exportKey("raw", key);
        return Array.from(new Uint8Array(exported));
    } catch (error) {
        //console.error("Error exporting key:", error);
        //displayError("An error occurred while exporting the key.");
        return null;
    }
}

// Function to import a key from an array
async function importKey(keyArray) {
    try {
        const key = new Uint8Array(keyArray);
        return await crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, true, ["decrypt"]);
    } catch (error) {
        console.error("Error importing key:", error);
        displayError("An error occurred while importing the key.");
        return null;
    }
}

// Function to display an error message
function displayError(message) {
    const errorMessage = document.getElementById('errorMessage');
    errorMessage.textContent = message;
    errorMessage.classList.remove('d-none');
    setTimeout(() => {
        errorMessage.classList.add('d-none');
    }, 7000);
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
    const passwordInput = document.getElementById('password');
    const password = passwordInput ? passwordInput.value : null;
    const expiryDate = document.getElementById('expiryDate').value;
    const maxDownloads = document.getElementById('maxDownloads').value;

    if (!validateInputs(files, password, expiryDate, maxDownloads)) {
        isUploading = false;
        uploadButton.disabled = false;
        selectFileButton.disabled = false;
        return;
    }

    const statusMessage = document.getElementById('statusMessage');
    statusMessage.textContent = 'Preparing files...';

    let fileToEncrypt;
    if (files.length > 1) {
        try {
            fileToEncrypt = await compressFiles(files);
        } catch (error) {
            displayError(`Error during compression. Check if you have enough available RAM and ensure you are not trying to compress a folder, as they are not supported.`);
            return;
        }
    } else {
        fileToEncrypt = files[0];
    }

    try {
        // Encrypt the file (or zip)
        statusMessage.textContent = 'Encrypting...';
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

        if (expiryDate) {
            formData.append('expiryDate', expiryDate);
        }

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

        // Throttle function to limit the rate at which a function can fire.
        function throttle(fn, limit) {
            let lastCall = 0;
            return function (...args) {
                const now = (new Date).getTime();
                if (now - lastCall >= limit) {
                    lastCall = now;
                    fn.apply(this, args);
                }
            };
        }

        const throttledProgressHandler = throttle((e) => {
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
        }, 100); // Update every 100ms

        xhr.upload.addEventListener('progress', throttledProgressHandler);

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
                    console.error(`Error: Server responded with status ${xhr.status}`);
                    console.error(`Response text: ${xhr.responseText}`);
                    displayError(`Error ${xhr.status}: ${xhr.statusText}. Please try again later or contact support if the problem persists.`);
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

        try {
            xhr.send(formData);
        } catch (error) {
            console.error("Error uploading file:", error);
            displayError("An error occurred while uploading the file.");
            isUploading = false;
            uploadButton.disabled = false;
            selectFileButton.disabled = false;
        }
    } catch (error) {
        displayError(`Error: ${error.message}`);
        progressContainer.classList.add('d-none');
        isUploading = false;
        uploadButton.disabled = false;
        selectFileButton.disabled = false;
    }
}

// Function to generate encryption key from password
async function generateKeyFromPassword(password, salt) {
    if (!salt) {
        salt = window.crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    }

    try {
        const encoder = new TextEncoder();
        const passwordBuffer = encoder.encode(password);

        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            passwordBuffer,
            { name: 'PBKDF2' },
            false,
            ['deriveBits', 'deriveKey']
        );

        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: PBKDF2_ITERATIONS,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: AES_KEY_LENGTH },
            false, // Changed to false for better security
            ['encrypt', 'decrypt']
        );

        return { key, salt };
    } catch (err) {
        console.error('Key generation error:', err);
        displayError("An error occurred while generating key from password.");
        throw err; // Re-throw the error for proper handling
    }
}

// Function to encrypt file with password
// Function to encrypt a file with a password
async function encryptFileWithPassword(file, password) {
    if (!window.crypto || !window.crypto.subtle) {
        alert('Web Crypto API not supported. Please use a modern browser with HTTPS.');
        return;
    }
    try {
        // Generate a key from the password
        const { key, salt } = await generateKeyFromPassword(password);
        // Generate a random initialization vector
        const iv = crypto.getRandomValues(new Uint8Array(12));
        // Encrypt the file content
        const encryptedContent = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            new Uint8Array(await file.arrayBuffer())
        );
        return { encryptedContent, key, iv, salt };
    } catch (err) {
        if (err instanceof DOMException) {
            console.error('DOMException during encryption:', err);
            displayError("An error occurred while encrypting the file with password.");
        } else {
            console.error('Error during encryption:', err);
            displayError("An error occurred while encrypting the file with password.");
        }
        return null;
    }
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
        const fileNames = Array.from(fileInput.files).map(file => file.name).join(', ');
        selectedFileName.textContent = `Selected files: ${fileNames}`;
    } else {
        selectedFileName.textContent = '';
    }
}

// Function to validate inputs
function validateFiles(files) {
    if (files.length === 0) {
        displayError('Please select a file or drag and drop a file.');
        console.log('No files selected.');
        return false;
    }
    return true;
}

function validatePassword(password) {
    if (password !== null && password !== '') {
        const passwordStrength = checkPasswordStrength(password);
        if (passwordStrength < 3) {
            displayError('Password is too weak. It should be at least 8 characters long and include uppercase, lowercase, numbers, and special characters.');
            return false;
        }
    }
    return true;
}

function validateExpiryDate(expiryDate) {
    if (expiryDate && new Date(expiryDate) <= new Date()) {
        displayError('Expiry date must be in the future.');
        return false;
    }
    return true;
}

function validateMaxDownloads(maxDownloads) {
    if (maxDownloads && (!Number.isInteger(+maxDownloads) || +maxDownloads <= 0)) {
        displayError('Max downloads must be a positive integer.');
        return false;
    }
    return true;
}

function validateInputs(files, password, expiryDate, maxDownloads) {
    return validateFiles(files) && validatePassword(password) && validateExpiryDate(expiryDate) && validateMaxDownloads(maxDownloads);
}

// Make validateInputs available globally
window.validateInputs = validateInputs;

// Function to check password strength
function checkPasswordStrength(password) {
    let strength = 0;
    if (password.length >= 8) strength++;
    if (password.match(/[a-z]+/)) strength++;
    if (password.match(/[A-Z]+/)) strength++;
    if (password.match(/[0-9]+/)) strength++;
    if (password.match(/[^a-zA-Z0-9]+/)) strength++;
    return strength;
}

// Function to compress files
async function compressFiles(files) {
    const zip = new JSZip();
    for (let i = 0; i < files.length; i++) {
        zip.file(files[i].name, files[i]);
    }
    return await zip.generateAsync({ type: 'blob', compression: 'DEFLATE', compressionOptions: { level: 1 } });
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
        const files = e.dataTransfer.files;
        document.getElementById('fileInput').files = files;
        handleFileSelect({ target: document.getElementById('fileInput') });
    });
});

function base64UrlEncode(arrayBuffer) {
    const encoded = btoa(new TextEncoder().encode(arrayBuffer));
    return encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
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
                if (password === "") {
                    displayError("Password can't be empty.")
                    return
                }
                passwordInputDiv.classList.add('d-none');
                const decryptionKey = await generateKeyFromPassword(password, salt);
                await startFileDownload(fileID, decryptionKey.key, iv, filename, statusMessage, downloadedBytesElement, progressBar, progressContainer, downloadButton);
            });
            });
            if (password === "") {
                displayError("Password can't be empty.")
                return
            }
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
    try {
        progressContainer.classList.remove('d-none');
        progressBar.style.width = '0%';
        progressBar.textContent = '0%';
        statusMessage.textContent = 'Downloading...';

        const xhr = new XMLHttpRequest();
        xhr.open('GET', `/share/download/${fileID}`, true);
        xhr.responseType = 'arraybuffer';

        const startTime = new Date().getTime();

        // Throttle function to limit the rate at which a function can fire.
        function throttle(fn, limit) {
            let lastCall = 0;
            return function (...args) {
                const now = (new Date).getTime();
                if (now - lastCall >= limit) {
                    lastCall = now;
                    fn.apply(this, args);
                }
            };
        }

        const throttledProgressHandler = throttle((e) => {
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
        }, 100); // Update every 100 ms

        xhr.onprogress = throttledProgressHandler;

        xhr.onload = async () => {
            try {
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
            } catch (error) {
                console.error('Error during decryption or file processing:', error);
                displayError('An error occurred during file decryption or processing.');
            } finally {
                downloadButton.disabled = false;
                isDownloading = false;
            }
        };

        xhr.onerror = () => {
            console.error('Network error during file download:', xhr.statusText);
            displayError('An error occurred while downloading the file.');
            progressContainer.classList.add('d-none');
            downloadButton.disabled = false;
            isDownloading = false;
        };

        xhr.send();
    } catch (error) {
        console.error('Error during file download request:', error);
        displayError('An error occurred while preparing for file download.');
        progressContainer.classList.add('d-none');
        downloadButton.disabled = false;
        isDownloading = false;
    }
}

// Function to copy the link to the clipboard
function copyLink() {
    const fileLinkElement = document.getElementById('fileLink');
    navigator.clipboard.writeText(fileLinkElement.value)
        .then(() => alert("Link copied to clipboard: " + fileLinkElement.value))
        .catch(err => handleError(err, "Unable to copy the link to the clipboard"));
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
        displayError("An error occurred during decryption. This may be due to a decryption failure or a data integrity check failure.");
        throw new Error("Decryption failed or data integrity check failed.");
    }
}

// Event listeners
document.getElementById('uploadButton').addEventListener('click', uploadFile);
document.getElementById('fileInput').addEventListener('change', (event) => {
    const fileNames = Array.from(event.target.files).map(file => file.name).join(', ');
    document.getElementById('selectedFileName').textContent = fileNames;
});

// Function to verify file integrity
async function verifyFileIntegrity(originalFile, decryptedFile) {
    const originalHash = await crypto.subtle.digest('SHA-256', await originalFile.arrayBuffer());
    const decryptedHash = await crypto.subtle.digest('SHA-256', await decryptedFile.arrayBuffer());
    
    if (originalHash.byteLength !== decryptedHash.byteLength) {
        return false;
    }
    
    return crypto.subtle.timingSafeEqual(new Uint8Array(originalHash), new Uint8Array(decryptedHash));
}
// Function to validate and sanitize input
function validateInput(input, type = 'text') {
    if (typeof input !== 'string') {
        throw new Error('Input must be a string');
    }

    // Trim whitespace
    input = input.trim();

    switch (type) {
        case 'text':
            // Remove any potentially dangerous characters for general text
            return input.replace(/[&<>"']/g, function (m) {
                return {
                    '&': '&amp;',
                    '<': '&lt;',
                    '>': '&gt;',
                    '"': '&quot;',
                    "'": '&#39;'
                }[m];
            });
        case 'filename':
            // Remove any characters that are invalid in filenames
            return input.replace(/[<>:"/\\|?*\x00-\x1F]/g, '');
        case 'number':
            // Ensure the input is a valid number
            if (!/^\d+$/.test(input)) {
                throw new Error('Input must be a valid number');
            }
            return input;
        case 'date':
            // Ensure the input is a valid date
            const date = new Date(input);
            if (isNaN(date.getTime())) {
                throw new Error('Input must be a valid date');
            }
            return date.toISOString().split('T')[0]; // Return YYYY-MM-DD format
        default:
            throw new Error('Invalid input type specified');
    }
}
