require 'base64'
require 'digest'
require 'openssl'
require 'nokogiri'

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

require 'nokogiri'
require 'json'

Dir.glob('_site/posts/*/index.html').each do |post_path|
  password = ENV['PROTECTOR_PASSWORD'] || 'changeme'

  html = File.read(post_path)
  doc = Nokogiri::HTML(html)

  content_node = doc.at_css('div.content')
  next unless content_node

  content_to_encrypt = content_node.inner_html
  encrypted = aes256_encrypt(password, content_to_encrypt)
  encrypted_js = encrypted.to_json  # safe for JS

  protected_block = <<~HTML
    <div class="content">
      <div id="protected">
        Insert password for decryption<br>
        <input id="password" type="password">
        <button onclick="decrypt()">Decrypt</button>
        <p id="errmsg" style="color: red;"></p>
      </div>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.9-1/crypto-js.min.js"></script>
      <script>
        function decrypt() {
          var protectedContent = #{encrypted_js};
          var password = document.getElementById('password').value;
          var payload = protectedContent.split("|");
          var iv = payload[0], hmac = payload[1], cipherText = payload[2];
          var passphraseDgst = CryptoJS.SHA256(password).toString();
          var decryptedhmac = CryptoJS.HmacSHA256(cipherText, CryptoJS.enc.Hex.parse(passphraseDgst)).toString().trim();

          if (decryptedhmac === CryptoJS.enc.Base64.parse(hmac).toString()) {
            var decrypted = CryptoJS.AES.decrypt(
              {ciphertext: CryptoJS.enc.Base64.parse(cipherText)},
              CryptoJS.enc.Hex.parse(passphraseDgst),
              {iv: CryptoJS.enc.Base64.parse(iv)}
            );
            var content = CryptoJS.enc.Utf8.stringify(decrypted);
            document.getElementById('protected').innerHTML = content;
          } else {
            document.getElementById('errmsg').innerText = "Wrong password";
          }
        }
      </script>
    </div>
  HTML

  fragment = Nokogiri::HTML::DocumentFragment.parse(protected_block)
  content_node.replace(fragment)

  File.write(post_path, doc.to_html)
end
