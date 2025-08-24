// Performance-optimized constants
const PBKDF2_ITERATIONS = 100000;
const AES_KEY_LENGTH = 256;
const SALT_LENGTH = 16;
const PROGRESS_UPDATE_INTERVAL = 100; // ms
const MAX_FILE_SIZE_DISPLAY = 1024 * 1024 * 1024; // 1GB for display optimization

// Pre-compiled regex patterns for optimized input validation
const validationPatterns = {
    htmlEntities: /[&<>"']/g,
    filenameInvalid: /[<>:"/\\|?*\x00-\x1F]/g,
    numbersOnly: /^\d+$/,
    entityMap: new Map([
        ['&', '&'],
        ['<', '<'],
        ['>', '>'],
        ['"', '"'],
        ["'", '&#39;']
    ])
};

// Function to encrypt a file with performance optimizations
async function encryptFile(file) {
    if (!crypto || !crypto.subtle) {
        alert('Web Crypto API not supported. Please use a modern browser with HTTPS.');
        return null;
    }
    
    try {
        // Use requestIdleCallback for non-critical UI updates during encryption
        if ('requestIdleCallback' in window) {
            requestIdleCallback(() => {
                const statusMessage = document.getElementById('statusMessage');
                if (statusMessage) {
                    statusMessage.textContent = 'Generating encryption keys...';
                }
            }, { timeout: 100 });
        }
        
        // Generate key and IV in parallel for better performance
        const [key, iv] = await Promise.all([
            crypto.subtle.generateKey(
                { name: "AES-GCM", length: AES_KEY_LENGTH },
                true,
                ["encrypt", "decrypt"]
            ),
            Promise.resolve(crypto.getRandomValues(new Uint8Array(12)))
        ]);
        
        // Read file as array buffer
        const fileBuffer = await file.arrayBuffer();
        
        if ('requestIdleCallback' in window) {
            requestIdleCallback(() => {
                const statusMessage = document.getElementById('statusMessage');
                if (statusMessage) {
                    statusMessage.textContent = 'Encrypting file content...';
                }
            }, { timeout: 100 });
        }
        
        const encryptedContent = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
            fileBuffer
        );
        
        return { encryptedContent, key, iv };
    } catch (error) {
        // console.error("Error during encryption:", error);
        // displayError("An error occurred during encryption.");
        return null;
    } finally {
        // Clean up any temporary resources
        if (file.arrayBuffer) {
            // Ensure file buffer is released
            file.arrayBuffer = null;
        }
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

// Enhanced notification system with different types and better user feedback
const NotificationType = {
    ERROR: 'error',
    SUCCESS: 'success',
    WARNING: 'warning',
    INFO: 'info'
};

// Function to display a notification with enhanced features
function displayNotification(message, type = NotificationType.INFO, duration = 5000) {
    // Create notification container if it doesn't exist
    let notificationContainer = document.getElementById('notificationContainer');
    if (!notificationContainer) {
        notificationContainer = document.createElement('div');
        notificationContainer.id = 'notificationContainer';
        notificationContainer.className = 'notification-container';
        document.body.appendChild(notificationContainer);
    }

    // Create notification element
    const notification = document.createElement('div');
    notification.className = `alert alert-${getAlertClass(type)} notification-item`;
    notification.setAttribute('role', 'alert');
    notification.setAttribute('aria-live', type === NotificationType.ERROR ? 'assertive' : 'polite');
    
    // Add icon based on notification type
    const icon = getNotificationIcon(type);
    notification.innerHTML = `
        <div class="d-flex align-items-center">
            <span class="notification-icon me-2">${icon}</span>
            <span class="notification-message">${message}</span>
            <button type="button" class="btn-close ms-auto" aria-label="Close" onclick="this.parentElement.parentElement.remove()"></button>
        </div>
    `;
    
    // Add animation for entrance
    notification.style.opacity = '0';
    notification.style.transform = 'translateY(-20px)';
    notificationContainer.appendChild(notification);
    
    // Animate in
    requestAnimationFrame(() => {
        notification.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
        notification.style.opacity = '1';
        notification.style.transform = 'translateY(0)';
    });
    
    // Auto-remove after duration if not error (errors stay until dismissed)
    if (type !== NotificationType.ERROR) {
        setTimeout(() => {
            if (notification.parentElement) {
                notification.style.opacity = '0';
                notification.style.transform = 'translateY(-20px)';
                setTimeout(() => {
                    if (notification.parentElement) {
                        notification.remove();
                    }
                }, 300);
            }
        }, duration);
    }
    
    return notification;
}

// Helper function to get appropriate alert class
function getAlertClass(type) {
    switch (type) {
        case NotificationType.ERROR: return 'danger';
        case NotificationType.SUCCESS: return 'success';
        case NotificationType.WARNING: return 'warning';
        case NotificationType.INFO: return 'info';
        default: return 'info';
    }
}

// Helper function to get appropriate icon
function getNotificationIcon(type) {
    switch (type) {
        case NotificationType.ERROR: return '<i class="fas fa-exclamation-circle"></i>';
        case NotificationType.SUCCESS: return '<i class="fas fa-check-circle"></i>';
        case NotificationType.WARNING: return '<i class="fas fa-exclamation-triangle"></i>';
        case NotificationType.INFO: return '<i class="fas fa-info-circle"></i>';
        default: return '<i class="fas fa-info-circle"></i>';
    }
}

// Backward compatibility functions
function displayError(message, duration = 7000) {
    displayNotification(message, NotificationType.ERROR, duration);
    
    // Also update the existing error message element for compatibility
    const errorMessage = document.getElementById('errorMessage');
    if (errorMessage) {
        errorMessage.textContent = message;
        errorMessage.classList.remove('d-none');
        errorMessage.setAttribute('aria-live', 'assertive');
        errorMessage.classList.add('alert-shake');
        
        setTimeout(() => {
            errorMessage.classList.remove('alert-shake');
        }, 500);
        
        setTimeout(() => {
            errorMessage.classList.add('d-none');
        }, duration);
    }
}

function displaySuccess(message, duration = 5000) {
    displayNotification(message, NotificationType.SUCCESS, duration);
}

// New function for warnings
function displayWarning(message, duration = 6000) {
    displayNotification(message, NotificationType.WARNING, duration);
}

// New function for info messages
function displayInfo(message, duration = 4000) {
    displayNotification(message, NotificationType.INFO, duration);
}

// Function to show loading state
function showLoadingState(element, text = 'Loading...') {
    const originalText = element.textContent;
    const originalHtml = element.innerHTML;
    element.disabled = true;
    element.setAttribute('aria-disabled', 'true');
    element.innerHTML = `<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>${text}`;
    
    return {
        restore: () => {
            element.disabled = false;
            element.removeAttribute('aria-disabled');
            element.innerHTML = originalHtml;
            element.textContent = originalText;
        }
    };
}

// Function to update progress with better visual feedback
function updateProgressBar(progressBar, percent, text = null) {
    progressBar.style.width = percent + '%';
    progressBar.textContent = text || Math.round(percent) + '%';
    
    // Add visual feedback for progress
    if (percent >= 100) {
        progressBar.classList.add('progress-complete');
    } else {
        progressBar.classList.remove('progress-complete');
    }
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

    // Show loading state with better visual feedback
    const uploadLoading = showLoadingState(uploadButton, 'Uploading...');
    const selectLoading = showLoadingState(selectFileButton, 'Please wait...');

    const fileInput = document.getElementById('fileInput');
    const files = fileInput.files;
    const passwordInput = document.getElementById('password');
    const password = passwordInput ? passwordInput.value : null;
    const expiryDate = document.getElementById('expiryDate').value;
    const maxDownloads = document.getElementById('maxDownloads').value;

    if (!validateInputs(files, password, expiryDate, maxDownloads)) {
        isUploading = false;
        uploadLoading.restore();
        selectLoading.restore();
        return;
    }

    const statusMessage = document.getElementById('statusMessage');
    statusMessage.textContent = 'Preparing files...';
    statusMessage.setAttribute('aria-busy', 'true');

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
        statusMessage.textContent = 'Encrypting your file securely...';
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
        updateProgressBar(progressBar, 0, 'Starting upload...');
        statusMessage.textContent = 'Uploading your encrypted file...';
        statusMessage.setAttribute('aria-busy', 'true');

        const xhr = new XMLHttpRequest();
        xhr.open('POST', `${window.location.origin}/share/upload`, true);
        const startTime = new Date().getTime();

        // Optimized throttle function using requestAnimationFrame
        function createThrottledProgressHandler() {
            let lastUpdate = 0;
            let lastLoaded = 0;
            let lastTotal = 0;
            
            return (e) => {
                const now = Date.now();
                if (now - lastUpdate >= PROGRESS_UPDATE_INTERVAL && e.lengthComputable) {
                    lastUpdate = now;
                    
                    // Batch DOM updates
                    requestAnimationFrame(() => {
                        const percentComplete = (e.loaded / e.total) * 100;
                        updateProgressBar(progressBar, percentComplete);

                        // Optimized file size calculation
                        const formatSize = (bytes) => {
                            if (bytes < 1024) return `${bytes} bytes`;
                            if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
                            if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
                            return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
                        };

                        const fileSizeText = formatSize(e.total);
                        const upfileSizeText = formatSize(e.loaded);

                        // Calculate speed efficiently
                        const timeDiff = now - startTime;
                        const speed = timeDiff > 0 ? e.loaded / timeDiff : 0;
                        const speedText = `${(speed / 1024).toFixed(1)} KB/s`;

                        uploadedBytes.textContent = `${upfileSizeText} / ${fileSizeText} - ${speedText}`;
                    });
                }
            };
        }

        const throttledProgressHandler = createThrottledProgressHandler();

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
                    statusMessage.textContent = 'File uploaded successfully!';
                    statusMessage.removeAttribute('aria-busy');
                    isUploading = false;
                    uploadLoading.restore();
                    selectLoading.restore();
                    displaySuccess('File uploaded and encrypted successfully!');
                } else {
                    console.error(`Error: Server responded with status ${xhr.status}`);
                    console.error(`Response text: ${xhr.responseText}`);
                    displayError(`Error ${xhr.status}: ${xhr.statusText}. Please try again later or contact support if the problem persists.`);
                    progressContainer.classList.add('d-none');
                    statusMessage.removeAttribute('aria-busy');
                    isUploading = false;
                    uploadLoading.restore();
                    selectLoading.restore();
                }
            }
        };

        xhr.onerror = () => {
            displayError('An error occurred while uploading the file.');
            progressContainer.classList.add('d-none');
            statusMessage.removeAttribute('aria-busy');
            isUploading = false;
            uploadLoading.restore();
            selectLoading.restore();
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
        statusMessage.removeAttribute('aria-busy');
        isUploading = false;
        uploadLoading.restore();
        selectLoading.restore();
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

// Function to manage file selection with preview (optimized with better performance)
function handleFileSelect(event) {
    const fileInput = event.target;
    const selectedFileName = document.getElementById('selectedFileName');
    const filePreview = document.getElementById('filePreview');
    const uploadButton = document.getElementById('uploadButton');
    
    // Use requestAnimationFrame for smoother UI updates
    requestAnimationFrame(() => {
        if (fileInput.files.length > 0) {
            const fileNames = Array.from(fileInput.files).map(file => file.name).join(', ');
            selectedFileName.textContent = `Selected files: ${fileNames}`;

            // Enable upload button when at least one file is selected
            if (uploadButton) {
                uploadButton.disabled = false;
                uploadButton.removeAttribute('aria-disabled');
            }
            
            // Show preview for single file (optimized with debouncing and cancellation)
            if (fileInput.files.length === 1) {
                // Cancel any pending preview operations using AbortController
                if (window.previewController) {
                    window.previewController.abort();
                }
                
                // Create new AbortController for this preview operation
                window.previewController = new AbortController();
                const signal = window.previewController.signal;
                
                // Debounce preview to avoid rapid consecutive calls
                if (window.previewTimeout) {
                    clearTimeout(window.previewTimeout);
                }
                
                window.previewTimeout = setTimeout(() => {
                    if (!signal.aborted) {
                        showFilePreview(fileInput.files[0], signal);
                    }
                }, 150);
            } else {
                // Hide preview for multiple files and cancel any pending operations
                if (window.previewController) {
                    window.previewController.abort();
                }
                filePreview.classList.add('d-none');
            }
        } else {
            selectedFileName.textContent = '';
            filePreview.classList.add('d-none');

            // Disable upload button when no files are selected
            if (uploadButton) {
                uploadButton.disabled = true;
                uploadButton.setAttribute('aria-disabled', 'true');
            }

            // Cancel any pending preview operations
            if (window.previewController) {
                window.previewController.abort();
            }
        }
    });
}

// Function to show file preview (optimized with performance checks and abort support)
function showFilePreview(file, signal) {
    const filePreview = document.getElementById('filePreview');
    const imagePreview = document.getElementById('imagePreview');
    const textPreview = document.getElementById('textPreview');
    const genericPreview = document.getElementById('genericPreview');
    const fileNameElement = genericPreview.querySelector('.file-name');
    const fileSizeElement = genericPreview.querySelector('.file-size');
    const fileTypeElement = genericPreview.querySelector('.file-type');
    
    // Check if operation was aborted
    if (signal && signal.aborted) {
        return;
    }
    
    // Reset all preview types with optimized DOM operations
    requestAnimationFrame(() => {
        if (signal && signal.aborted) return;
        
        imagePreview.classList.add('d-none');
        textPreview.classList.add('d-none');
        genericPreview.classList.remove('d-none');
        
        // Set file info
        fileNameElement.textContent = file.name;
        fileSizeElement.textContent = formatFileSize(file.size);
        fileTypeElement.textContent = `Type: ${file.type || 'Unknown'}`;
        
        // Performance optimization: only process files under 5MB for preview (reduced from 10MB)
        const MAX_PREVIEW_SIZE = 5 * 1024 * 1024; // 5MB
        
        if (file.size > MAX_PREVIEW_SIZE) {
            // File too large for preview, show generic info only
            filePreview.classList.remove('d-none');
            return;
        }
        
        // Show appropriate preview based on file type with abort support
        if (file.type.startsWith('image/')) {
            const reader = new FileReader();
            
            // Check for abort before starting
            if (signal && signal.aborted) return;
            
            reader.onload = function(e) {
                if (signal && signal.aborted) return;
                requestAnimationFrame(() => {
                    if (signal && signal.aborted) return;
                    const img = imagePreview.querySelector('img');
                    img.src = e.target.result;
                    // Add loading attribute for lazy loading and decoding for better performance
                    img.loading = 'lazy';
                    img.decoding = 'async';
                    imagePreview.classList.remove('d-none');
                    genericPreview.classList.add('d-none');
                });
            };
            reader.onerror = function() {
                // Fallback to generic preview on error
                if (signal && signal.aborted) return;
                filePreview.classList.remove('d-none');
            };
            reader.onabort = function() {
                // Handle abort during file reading
                filePreview.classList.add('d-none');
            };
            reader.readAsDataURL(file);
        } else if (file.type.startsWith('text/') || file.type === 'application/json') {
            const reader = new FileReader();
            
            // Check for abort before starting
            if (signal && signal.aborted) return;
            
            reader.onload = function(e) {
                if (signal && signal.aborted) return;
                requestAnimationFrame(() => {
                    if (signal && signal.aborted) return;
                    const textContent = e.target.result;
                    // Limit preview to first 500 characters for better performance (reduced from 1000)
                    const previewText = textContent.length > 500 ?
                        textContent.substring(0, 500) + '...' : textContent;
                    textPreview.querySelector('pre').textContent = previewText;
                    textPreview.classList.remove('d-none');
                    genericPreview.classList.add('d-none');
                });
            };
            reader.onerror = function() {
                // Fallback to generic preview on error
                if (signal && signal.aborted) return;
                filePreview.classList.remove('d-none');
            };
            reader.onabort = function() {
                // Handle abort during file reading
                filePreview.classList.add('d-none');
            };
            reader.readAsText(file);
        } else {
            // Generic preview for other file types
            filePreview.classList.remove('d-none');
        }
    });
}

// Function to close file preview
function closePreview() {
    const filePreview = document.getElementById('filePreview');
    filePreview.classList.add('d-none');
}

// Function to format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Make functions available globally
window.closePreview = closePreview;

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


function base64UrlEncode(arrayBuffer) {
    // Convert the array buffer to a regular array of bytes
    const bytes = new Uint8Array(arrayBuffer);
    // Convert bytes to a binary string
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    // Base64 encode the binary string
    const base64 = btoa(binary);
    // Make the base64 string URL-safe
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(base64) {
    base64 = base64.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
        base64 += '=';
    }
    try {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    } catch (error) {
        console.error("Error decoding base64:", error);
        displayError("Error decoding the download link. The link may be corrupted.");
        throw error;
    }
}

// Function to download a file
let isDownloading = false;
async function downloadFile() {
    if (isDownloading) {
        return;
    }

    isDownloading = true;
    const downloadButton = document.getElementById('downloadButton');
    const downloadLoading = showLoadingState(downloadButton, 'Preparing download...');

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
            // Optimized password handling with proper cleanup
            const password = await new Promise((resolve, reject) => {
                let enterHandler = null;
                let clickHandler = null;
                
                // Handle Enter key press
                enterHandler = (event) => {
                    if (event.key === 'Enter') {
                        cleanup();
                        resolve(passwordInput.value);
                    }
                };
                
                // Handle submit button click
                clickHandler = async () => {
                    const password = passwordInput.value;
                    if (password === "") {
                        displayError("Password can't be empty.");
                        return;
                    }
                    cleanup();
                    resolve(password);
                };
                
                const submitPasswordButton = document.getElementById('submitPassword');
                passwordInput.addEventListener('keyup', enterHandler);
                submitPasswordButton.addEventListener('click', clickHandler);
                
                // Cleanup function to remove event listeners
                function cleanup() {
                    passwordInput.removeEventListener('keyup', enterHandler);
                    submitPasswordButton.removeEventListener('click', clickHandler);
                    passwordInputDiv.classList.add('d-none');
                }
            });
            
            if (password === "") {
                displayError("Password can't be empty.");
                return;
            }
            
            const decryptionKey = await generateKeyFromPassword(password, salt);
            await startFileDownload(fileID, decryptionKey.key, iv, filename, statusMessage, downloadedBytesElement, progressBar, progressContainer, downloadButton, downloadLoading);

        } catch (error) {
            displayError(`Error: ${error.message}`);
        } finally {
            isDownloading = false;
            downloadLoading.restore();
        }
    } else {
        const decryptionKey = await importKey(key);
        await startFileDownload(fileID, decryptionKey, iv, filename, statusMessage, downloadedBytesElement, progressBar, progressContainer, downloadButton, downloadLoading);
        isDownloading = false;
        downloadLoading.restore();
    }
}

// Optimized file download function with better error handling and performance
async function startFileDownload(fileID, decryptionKey, iv, filename, statusMessage, downloadedBytesElement, progressBar, progressContainer, downloadButton, downloadLoading) {
    try {
        // Remove console logs in production for better performance
        // console.log("Decryption Key:", decryptionKey);
        // console.log("IV:", iv);

        progressContainer.classList.remove('d-none');
        updateProgressBar(progressBar, 0, 'Starting download...');
        statusMessage.textContent = 'Downloading your file securely...';
        statusMessage.setAttribute('aria-busy', 'true');

        const xhr = new XMLHttpRequest();
        xhr.open('GET', `/share/download/${fileID}`, true);
        xhr.responseType = 'arraybuffer';

        const startTime = Date.now();
        let lastSpeedUpdate = startTime;
        let lastLoaded = 0;

        // Optimized download progress handler with better performance
        function createDownloadProgressHandler() {
            let lastUpdate = 0;
            
            return (e) => {
                const now = Date.now();
                if (now - lastUpdate >= PROGRESS_UPDATE_INTERVAL && e.lengthComputable) {
                    lastUpdate = now;
                    
                    // Use requestIdleCallback for non-critical UI updates
                    if ('requestIdleCallback' in window) {
                        requestIdleCallback(() => {
                            updateProgressUI(e, now, startTime, lastSpeedUpdate, lastLoaded);
                        }, { timeout: 100 });
                    } else {
                        requestAnimationFrame(() => {
                            updateProgressUI(e, now, startTime, lastSpeedUpdate, lastLoaded);
                        });
                    }
                }
            };
        }

        function updateProgressUI(e, now, startTime, lastSpeedUpdate, lastLoaded) {
            const percentComplete = (e.loaded / e.total) * 100;
            updateProgressBar(progressBar, percentComplete);

            // Cache format function for better performance
            const formatSize = (bytes) => {
                if (bytes < 1024) return `${bytes} bytes`;
                if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
                if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
                return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
            };

            const fileSizeText = formatSize(e.total);
            const downfileSizeText = formatSize(e.loaded);

            // Calculate speed more efficiently
            const timeDiff = now - startTime;
            const speed = timeDiff > 0 ? e.loaded / timeDiff : 0;
            const speedText = `${(speed / 1024).toFixed(1)} KB/s`;

            downloadedBytesElement.textContent = `${downfileSizeText} / ${fileSizeText} - ${speedText}`;
        }

        const throttledProgressHandler = createDownloadProgressHandler();

        xhr.onprogress = throttledProgressHandler;

        xhr.onload = async () => {
            try {
                if (xhr.status === 200) {
                    updateProgressBar(progressBar, 100, 'Complete!');
                    const encryptedContent = xhr.response;
                    
                    // Use requestIdleCallback for decryption to avoid blocking UI
                    if ('requestIdleCallback' in window) {
                        requestIdleCallback(async () => {
                            await processDownloadedFile(encryptedContent, decryptionKey, iv, filename, fileID, statusMessage, progressContainer, downloadLoading);
                        }, { timeout: 500 });
                    } else {
                        await processDownloadedFile(encryptedContent, decryptionKey, iv, filename, fileID, statusMessage, progressContainer, downloadLoading);
                    }
                } else {
                    handleDownloadError(xhr.status, 'File not found or server error', progressContainer, statusMessage, downloadLoading);
                }
            } catch (error) {
                console.error('Error during decryption or file processing:', error);
                handleDownloadError(0, 'An error occurred during file decryption or processing.', progressContainer, statusMessage, downloadLoading);
            } finally {
                isDownloading = false;
            }
        };

        xhr.onerror = () => {
            handleDownloadError(0, 'Network error occurred while downloading the file.', progressContainer, statusMessage, downloadLoading);
        };

        xhr.send();
    } catch (error) {
        console.error('Error during file download request:', error);
        handleDownloadError(0, 'An error occurred while preparing for file download.', progressContainer, statusMessage, downloadLoading);
    }
}

// Helper function to process downloaded file
async function processDownloadedFile(encryptedContent, decryptionKey, iv, filename, fileID, statusMessage, progressContainer, downloadLoading) {
    try {
        const file = await decryptFile(encryptedContent, decryptionKey, iv);
        const url = URL.createObjectURL(file);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename || 'decrypted_' + fileID;
        a.click();
        
        // Use setTimeout to ensure download starts before revoking URL
        setTimeout(() => {
            URL.revokeObjectURL(url);
        }, 100);
        
        statusMessage.textContent = 'File downloaded and decrypted successfully!';
        statusMessage.removeAttribute('aria-busy');
        progressContainer.classList.add('d-none');
        displaySuccess('File downloaded successfully!');
    } catch (error) {
        throw error;
    } finally {
        if (downloadLoading) downloadLoading.restore();
    }
}

// Helper function to handle download errors
function handleDownloadError(status, message, progressContainer, statusMessage, downloadLoading) {
    if (status === 404) {
        displayError('File not found. It may have expired or been deleted.');
    } else {
        displayError(message);
    }
    progressContainer.classList.add('d-none');
    statusMessage.removeAttribute('aria-busy');
    if (downloadLoading) downloadLoading.restore();
}

// Dark mode functionality
function initDarkMode() {
    const darkModeToggle = document.getElementById('darkModeToggle');
    const prefersDarkScheme = window.matchMedia('(prefers-color-scheme: dark)');
    
    // Check for saved theme preference or use system preference
    const savedTheme = localStorage.getItem('theme');
    const currentTheme = savedTheme || (prefersDarkScheme.matches ? 'dark' : 'light');
    
    // Apply initial theme
    if (currentTheme === 'dark') {
        document.documentElement.classList.add('dark-mode');
        darkModeToggle.innerHTML = '<i class="fas fa-sun"></i>';
        darkModeToggle.setAttribute('aria-label', 'Toggle light mode');
    }
    
    // Toggle dark mode
    darkModeToggle.addEventListener('click', () => {
        const isDarkMode = document.documentElement.classList.toggle('dark-mode');
        
        if (isDarkMode) {
            localStorage.setItem('theme', 'dark');
            darkModeToggle.innerHTML = '<i class="fas fa-sun"></i>';
            darkModeToggle.setAttribute('aria-label', 'Toggle light mode');
        } else {
            localStorage.setItem('theme', 'light');
            darkModeToggle.innerHTML = '<i class="fas fa-moon"></i>';
            darkModeToggle.setAttribute('aria-label', 'Toggle dark mode');
        }
    });
    
    // Listen for system theme changes
    prefersDarkScheme.addEventListener('change', (e) => {
        if (!localStorage.getItem('theme')) {
            if (e.matches) {
                document.documentElement.classList.add('dark-mode');
                darkModeToggle.innerHTML = '<i class="fas fa-sun"></i>';
                darkModeToggle.setAttribute('aria-label', 'Toggle light mode');
            } else {
                document.documentElement.classList.remove('dark-mode');
                darkModeToggle.innerHTML = '<i class="fas fa-moon"></i>';
                darkModeToggle.setAttribute('aria-label', 'Toggle dark mode');
            }
        }
    });
}


// Function to copy the link to the clipboard
function copyLink() {
    const fileLinkElement = document.getElementById('fileLink');
    const copyButton = document.querySelector('.btn-copy');
    const originalText = copyButton.innerHTML;
    
    // Show loading state
    copyButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Copying...';
    copyButton.disabled = true;
    
    navigator.clipboard.writeText(fileLinkElement.value)
        .then(() => {
            // Show success feedback
            copyButton.innerHTML = '<i class="fas fa-check"></i> Copied!';
            copyButton.classList.add('btn-success');
            copyButton.classList.remove('btn-copy');
            
            displaySuccess('Link copied to clipboard!', 3000);
            
            // Reset button after 2 seconds
            setTimeout(() => {
                copyButton.innerHTML = originalText;
                copyButton.classList.remove('btn-success');
                copyButton.classList.add('btn-copy');
                copyButton.disabled = false;
            }, 2000);
        })
        .catch(err => {
            displayError("Unable to copy the link to the clipboard");
            copyButton.innerHTML = originalText;
            copyButton.disabled = false;
        });
}

// Function to decrypt a file
async function decryptFile(encryptedContent, key, iv) {
    try {
        const decryptedContent = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            encryptedContent
        );

        if (!decryptedContent) {
            console.error("Decryption returned null or undefined content.");
            displayError("Decryption failed: The decrypted content is invalid.");
            throw new Error("Decryption failed: The decrypted content is invalid.");
        }

        return new Blob([decryptedContent]);
    } catch (error) {
        console.error("Decryption failed:", error);
        let errorMessage = "An error occurred during decryption.";

        if (error instanceof DOMException) {
            switch (error.name) {
                case "InvalidAccessError":
                    errorMessage = "Decryption failed: Invalid key or IV.";
                    break;
                case "OperationError":
                    errorMessage = "Decryption failed: Data integrity check failed (invalid password or corrupted data).";
                    break;
                default:
                    errorMessage = `Decryption failed: ${error.message}`;
            }
        }

        displayError(errorMessage);
        throw new Error("Decryption failed");
    }
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

// Single optimized DOMContentLoaded event listener
document.addEventListener("DOMContentLoaded", () => {
    // Initialize dark mode
    initDarkMode();
    
    // Drag and drop functionality
    const dragDropArea = document.getElementById('dragDropArea');
    if (dragDropArea) {
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
    }
    
    // Upload button event listener
    const uploadButton = document.getElementById('uploadButton');
    if (uploadButton) {
        uploadButton.addEventListener('click', uploadFile);
    }
    
    // File input change handler
    const fileInput = document.getElementById('fileInput');
    if (fileInput) {
        fileInput.addEventListener('change', (event) => {
            const fileNames = Array.from(event.target.files).map(file => file.name).join(', ');
            const selectedFileName = document.getElementById('selectedFileName');
            if (selectedFileName) {
                selectedFileName.textContent = fileNames;
            }
        });
    }
    
    // Download button event listener (if on download page)
    const downloadButton = document.getElementById('downloadButton');
    if (downloadButton) {
        downloadButton.addEventListener('click', downloadFile);
    }
    
    // Copy link button event listener
    const copyButton = document.querySelector('.btn-copy');
    if (copyButton) {
        copyButton.addEventListener('click', copyLink);
    }
    
    // Password submit button event listener
    const submitPasswordButton = document.getElementById('submitPassword');
    if (submitPasswordButton) {
        submitPasswordButton.addEventListener('click', async () => {
            const passwordInput = document.getElementById('password');
            const password = passwordInput.value;
            if (password === "") {
                displayError("Password can't be empty.");
                return;
            }
            // This will be handled by the downloadFile function
        });
    }
    
    // Performance optimization: Preload common resources when idle
    if ('requestIdleCallback' in window) {
        requestIdleCallback(() => {
            // Preload Font Awesome icons if not already loaded
            if (!document.querySelector('link[href*="font-awesome"]')) {
                const link = document.createElement('link');
                link.rel = 'stylesheet';
                link.href = 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css';
                link.crossOrigin = 'anonymous';
                document.head.appendChild(link);
            }
        }, { timeout: 2000 });
    }
    
    // Add performance monitoring for development
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
        console.log('Performance optimizations applied:');
        console.log('- Consolidated DOMContentLoaded listeners');
        console.log('- Optimized file preview with abort support');
        console.log('- Enhanced download performance with requestIdleCallback');
        console.log('- Improved encryption/decryption error handling');
    }
});
