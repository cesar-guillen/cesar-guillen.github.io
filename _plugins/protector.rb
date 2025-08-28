require 'base64'
require 'digest'
require 'openssl'

def aes256_encrypt(password, cleardata)
  digest = Digest::SHA256.new
  digest.update(password)
  key = digest.digest

  cipher = OpenSSL::Cipher::AES256.new(:CBC)
  cipher.encrypt
  cipher.key = key
  cipher.iv = iv = cipher.random_iv

  encrypted = cipher.update(cleardata) + cipher.final
  encoded_msg = Base64.encode64(encrypted).gsub(/\n/, '')
  encoded_iv = Base64.encode64(iv).gsub(/\n/, '')

  hmac = Base64.encode64(OpenSSL::HMAC.digest('sha256', key, encoded_msg)).strip
  "#{encoded_iv}|#{hmac}|#{encoded_msg}"
end

Dir.glob('_site/posts/*/index.html').each do |post_path|
  html = File.read(post_path)
  password = ENV['PROTECTOR_PASSWORD'] || 'changeme' # <--- set your password here
  encrypted = aes256_encrypt(password, html)

  protected_html = <<~HTML
    <!DOCTYPE html>
    <html>
      <head>
        <title>Protected Post</title>
        <meta charset="utf-8">
        <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
      </head>
      <body>
        <div id="content">
          <input id="password" type="password" placeholder="Enter password">
          <button onclick="decrypt()">Decrypt</button>
          <p id="errmsg" style="color: red;"></p>
        </div>
        <script>
          function decrypt() {
            var protectedContent = "#{encrypted}";
            var password = document.getElementById('password').value;
            var payload = protectedContent.split("|");
            var iv = payload[0];
            var hmac = payload[1];
            var cipherText = payload[2];
            var passphraseDgst = CryptoJS.SHA256(password).toString();
            var decryptedhmac = CryptoJS.HmacSHA256(cipherText, CryptoJS.enc.Hex.parse(passphraseDgst)).toString().trim();
            if(CryptoJS.enc.Base64.parse(hmac).toString() === decryptedhmac){
              var decrypted = CryptoJS.AES.decrypt(
                {ciphertext:CryptoJS.enc.Base64.parse(cipherText)},
                CryptoJS.enc.Hex.parse(passphraseDgst),
                {iv:CryptoJS.enc.Base64.parse(iv)}
              );
              var content = CryptoJS.enc.Utf8.stringify(decrypted);
              document.getElementById('content').innerHTML = content;
            } else {
              document.getElementById('errmsg').innerHTML = "Wrong password";
            }
          }
          var passwordInput = document.getElementById('password');
          passwordInput.addEventListener("keyup", function(event) {
            event.preventDefault();
            if (event.keyCode === 13) {
              decrypt();
            }
          });
        </script>
      </body>
    </html>
  HTML

  File.write(post_path, protected_html)
end