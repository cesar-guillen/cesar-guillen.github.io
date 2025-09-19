require 'base64'
require 'digest'
require 'openssl'
require 'nokogiri'
require 'json'

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
  password = ENV['PROTECTOR_PASSWORD'] || "debug"

  html = File.read(post_path)
  next unless html.include?('<a href="/categories/active/">Active</a>') # searching for protected category
  doc = Nokogiri::HTML(html)
  content_node = doc.at_css('div.content')
  next unless content_node

  content_to_encrypt = content_node.inner_html
  encrypted = aes256_encrypt(password, content_to_encrypt)
  encrypted_js = encrypted.to_json  # safe for JS

  protected_block = <<~HTML
    <div class="content">
      <div id="protected"></div>

      <!-- Modal -->
      <div id="decryptModal" class="modal">
        <div class="modal-content">
          <div class="lock-icon">🔒</div>
          <h2 class="modal-title">This post is locked</h2>
          <p class="explain-text">
            This machine is still active. Enter the correct password to unlock it.
          </p>
          <input id="password" type="password" placeholder="Enter password">
          <button id="decryptButton" class="decrypt-btn">Unlock</button>
          <p id="errmsg" style="color: red; margin-top: 10px;"></p>
        </div>
      </div>

      <script>
        const protectedContent = #{encrypted_js};

        function base64ToBytes(b64) {
          const bin = atob(b64);
          return new Uint8Array([...bin].map(c => c.charCodeAt(0)));
        }
        function bytesToBase64(bytes) {
          return btoa(String.fromCharCode(...new Uint8Array(bytes)));
        }

        async function decrypt() {
          const [ivB64, hmacB64, cipherB64] = protectedContent.split("|");
          const password = document.getElementById('password').value;

          // Hash password (SHA-256)
          const pwKey = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(password));

          // Verify HMAC
          const keyForHmac = await crypto.subtle.importKey("raw", pwKey, {name:"HMAC", hash:"SHA-256"}, false, ["sign"]);
          const computedHmac = await crypto.subtle.sign("HMAC", keyForHmac, new TextEncoder().encode(cipherB64));
          if (bytesToBase64(computedHmac).trim() !== hmacB64.trim()) {
            const errmsg = document.getElementById('errmsg');
            errmsg.innerText = "Wrong password";
            errmsg.classList.remove("shake");
            void errmsg.offsetWidth; 
            errmsg.classList.add("shake");
            return;
          }

          // Import AES key
          const aesKey = await crypto.subtle.importKey("raw", pwKey, {name:"AES-CBC"}, false, ["decrypt"]);

          // Decrypt
          const decrypted = await crypto.subtle.decrypt(
            {name: "AES-CBC", iv: base64ToBytes(ivB64)},
            aesKey,
            base64ToBytes(cipherB64)
          );

          const content = new TextDecoder().decode(decrypted);
          document.getElementById('protected').innerHTML = content;

          // Remove shimmer class
          document.querySelectorAll('#protected .shimmer').forEach(el => el.classList.remove('shimmer'));

          // Hide modal
          const modal = document.getElementById('decryptModal');
          modal.classList.add("hide");
          setTimeout(() => { modal.style.display = "none"; }, 800);
          
          // reload toc content
          if (window.tocbot) {
            tocbot.refresh();
            tocbot.collapseAll();
          }
        }

        document.getElementById("decryptButton").onclick = decrypt;
        document.getElementById("password").addEventListener("keyup", e => {
          if (e.key === "Enter") decrypt();
        });
      </script>
    </div>
  HTML

  fragment = Nokogiri::HTML::DocumentFragment.parse(protected_block)
  content_node.replace(fragment)

  File.write(post_path, doc.to_html)
end
