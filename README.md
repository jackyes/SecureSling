# SecureSling
## Easy to Use

SecureSling makes file sharing simple and straightforward with an intuitive interface that's easy to use.  
  
## Secure E2E Encryption & zero-knowledge architecture
  
Files are encrypted with AES-GCM using a 256-bit key to ensure data privacy and security. This state-of-the-art encryption standard provides robust protection for your files.
  
## Flexible File Sharing
Enable one-time downloads to ensure your files are only accessible once  
Choose a maximum number of downloads  
Set an expiration date for your files  

## Client-Side Encryption

With SecureSling, your files are encrypted and decrypted directly on your device.  
This means that only you and the recipient can access the content of the files.  
Our server never has access to your unencrypted files, ensuring maximum privacy and security.  
  
How it Works

- Encryption:
  - Before uploading, your files are encrypted using AES-GCM with a 256-bit key, a state-of-the-art encryption standard.
- Upload:
  - Only the encrypted version of your files is uploaded to our server. Also filename and metadata are safe thank to the zero-knowledge architecture.
- Decryption:
  - When downloading, the encrypted files are decrypted on your device using the decryption key you provided (in the sharing link).

## Note:
Only a randomly generated identifier that refers to the shared file is sent to the server.  
The link parameters for the decryption key and original file name are never sent to the server, so no one other than the recipient and the sender can decrypt the file on their device.  
