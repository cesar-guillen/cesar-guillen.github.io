require 'base64'
require 'openssl'
require 'yaml'

PASSWORD = ENV['PROTECTOR_PASSWORD'] || "debug"

def derive_key(password, salt)
  iter = 100_000
  OpenSSL::KDF.pbkdf2_hmac(password, salt: salt, iterations: iter, length: 32, hash: 'SHA256')
end

def aes_decrypt(password, enc)
  salt = Base64.decode64(enc['salt'])
  iv = Base64.decode64(enc['iv'])
  ciphertext = Base64.decode64(enc['ciphertext'])
  hmac = Base64.decode64(enc['hmac'])

  key = derive_key(password, salt)

  # verify hmac
  calc_hmac = OpenSSL::HMAC.digest('sha256', key, ciphertext)
  raise "HMAC mismatch – wrong password or corrupted file" unless calc_hmac == hmac

  cipher = OpenSSL::Cipher::AES.new(256, :CBC)
  cipher.decrypt
  cipher.key = key
  cipher.iv = iv

  plaintext = cipher.update(ciphertext) + cipher.final
  plaintext
end

Dir.glob("_posts/*.md").each do |path|
  first_line = File.open(path, &:readline).strip rescue ""
  next unless first_line.start_with?("ciphertext:")

  puts "Decrypting: #{path}"
  enc = YAML.load_file(path)
  decrypted = aes_decrypt(PASSWORD, enc)

  out_path = path
  File.write(out_path, decrypted)
  puts " → wrote #{out_path}"
end
