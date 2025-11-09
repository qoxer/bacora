#!/usr/bin/env ruby
require 'openssl'
require 'securerandom'
require 'yaml'
require 'fileutils'

CONFIG = YAML.load_file(File.join(__dir__, 'config.yaml'))

INPUT_DIR  = CONFIG['input_dir']  || 'input'
OUTPUT_DIR = CONFIG['output_dir'] || 'output'
EXTENSION  = CONFIG['container_ext'] || '.uni.crypto'

PBKDF2_ITER = CONFIG['pbkdf2_iterations'] || 200_000
SALT_LEN    = CONFIG['salt_len'] || 16
IV_LEN      = CONFIG['iv_len'] || 12
TAG_LEN     = CONFIG['tag_len'] || 16
KEY_LEN     = CONFIG['key_len'] || 32
KDF_DIGEST  = CONFIG['kdf_digest'] || 'sha256'
CIPHER_NAME = CONFIG['cipher'] || 'aes-256-gcm'

MAGIC = "RCNV2"

def derive_key(password, salt)
  OpenSSL::PKCS5.pbkdf2_hmac(password, salt, PBKDF2_ITER, KEY_LEN, KDF_DIGEST)
end

def build_payload(file_paths)
  buf = +""
  buf << [file_paths.size].pack("N")
  file_paths.each do |path|
    name = File.basename(path)
    data = File.binread(path)
    buf << [name.bytesize].pack("n") << name << [data.bytesize].pack("Q>") << data
  end
  buf
end

def parse_payload(payload, out_dir)
  idx = 0
  count = payload[idx,4].unpack1("N"); idx += 4
  count.times do
    name_len = payload[idx,2].unpack1("n"); idx += 2
    name = payload[idx, name_len]; idx += name_len
    data_len = payload[idx,8].unpack1("Q>"); idx += 8
    data = payload[idx, data_len]; idx += data_len
    File.binwrite(File.join(out_dir, name), data)
    puts "Decrypted file: #{name} (#{data_len} bytes)"
  end
end

def encrypt_files(password)
  files = Dir[File.join(INPUT_DIR, '*')].select { |f| File.file?(f) }
  raise "No files found in #{INPUT_DIR} directory" if files.empty?

  salt = SecureRandom.random_bytes(SALT_LEN)
  iv   = SecureRandom.random_bytes(IV_LEN)
  key  = derive_key(password, salt)

  cipher = OpenSSL::Cipher.new(CIPHER_NAME)
  cipher.encrypt
  cipher.key = key
  cipher.iv = iv

  payload = build_payload(files)
  encrypted = cipher.update(payload) + cipher.final
  tag = cipher.auth_tag(TAG_LEN)

  FileUtils.mkdir_p(OUTPUT_DIR)
  container_path = File.join(OUTPUT_DIR, "archive#{EXTENSION}")

  File.open(container_path, 'wb') do |f|
    f.write(MAGIC)
    f.write([SALT_LEN].pack('C'))
    f.write(salt)
    f.write([PBKDF2_ITER].pack('N'))
    f.write([IV_LEN].pack('C'))
    f.write(iv)
    f.write([TAG_LEN].pack('C'))
    f.write(tag)
    f.write([encrypted.bytesize].pack('Q>'))
    f.write(encrypted)
  end

  puts "Container created: #{container_path}"
  puts "Files encrypted: #{files.size}"
end

def decrypt_container(password, container_path)
  raise "Container file not found" unless File.file?(container_path)

  data = File.binread(container_path)
  idx = 0
  raise "Invalid container format" unless data[idx, MAGIC.bytesize] == MAGIC
  idx += MAGIC.bytesize

  salt_len = data[idx].ord; idx += 1
  salt = data[idx, salt_len]; idx += salt_len
  iter = data[idx,4].unpack1('N'); idx += 4
  iv_len = data[idx].ord; idx += 1
  iv = data[idx, iv_len]; idx += iv_len
  tag_len = data[idx].ord; idx += 1
  tag = data[idx, tag_len]; idx += tag_len
  enc_len = data[idx,8].unpack1('Q>'); idx += 8
  encrypted = data[idx, enc_len]

  key = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, iter, KEY_LEN, KDF_DIGEST)

  cipher = OpenSSL::Cipher.new(CIPHER_NAME)
  cipher.decrypt
  cipher.key = key
  cipher.iv = iv
  cipher.auth_tag = tag

  begin
    payload = cipher.update(encrypted) + cipher.final
  rescue OpenSSL::Cipher::CipherError
    abort "Decryption failed: invalid password or corrupted container."
  end

  out_dir = File.join(OUTPUT_DIR, 'decrypted')
  FileUtils.mkdir_p(out_dir)
  parse_payload(payload, out_dir)
  puts "Decrypted files saved to: #{out_dir}"
end

def print_help
  puts <<~HELP
    Ruby Cryptographic Container (AES-256-GCM)
    ------------------------------------------
    Encrypts or decrypts files using AES-256-GCM and a password-based key (PBKDF2-HMAC-SHA256).

    Usage:
      ruby bacora.rb encrypt <password>
          Encrypts all files from the input folder (see config.yaml).

      ruby bacora.rb decrypt <password> <container_file>
          Decrypts the given container file into the output folder.

      ruby bacora.rb help
          Show this help message.

    Example:
      ruby bacora.rb encrypt 123
      ruby bacora.rb decrypt 123 output/archive.uni.crypto

    Default directories:
      Input folder:  #{INPUT_DIR}
      Output folder: #{OUTPUT_DIR}
      Container ext: #{EXTENSION}

    Configuration file:
      config.yaml (you can adjust algorithm, iterations, salt length, etc.)
  HELP
end

if __FILE__ == $0
  cmd = ARGV.shift
  case cmd
  when 'encrypt'
    password = ARGV.shift or abort "Please specify a password."
    encrypt_files(password)
  when 'decrypt'
    password = ARGV.shift or abort "Please specify a password."
    file = ARGV.shift or abort "Please specify the container file."
    decrypt_container(password, file)
  when 'help', nil
    print_help
  else
    puts "Unknown command: #{cmd}"
    print_help
  end
end
