module NginxOmniauthAdapter
  module SessionParam
    CIPHER_ALGORITHM = 'aes-256-gcm'.freeze

    def self.decrypt(key, raw_data)
      data = JSON.parse(raw_data.unpack('m*')[0])

      cipher ||= OpenSSL::Cipher.new(SESSION_PASS_CIPHER_ALGORITHM).tap do |c|
        c.decrypt
        c.key = key
        c.iv = data['iv'].unpack('m*')[0]
        c.auth_data = ''
        c.auth_tag = data['tag'].unpack('m*')[0]
      end

      plaintext = cipher.update(data['data'].unpack('m*')[0])
      plaintext << cipher.final

      Marshal.load(plaintext)
    end

    def initialize(data={})
      @data = data
    end

    attr_reader :data

    def write_session(session)
      session.merge!(data)
    end

    def encrypt(key)
      iv = nil
      cipher ||= OpenSSL::Cipher.new(SESSION_PASS_CIPHER_ALGORITHM).tap do |c|
        c.encrypt
        c.key = secret_key
        c.iv = iv = c.random_iv
        c.auth_data = ''
      end

      plaintext = Marshal.dump(session_param)

      ciphertext = cipher.update(plaintext)
      ciphertext << cipher.final

      URI.encode_www_form_component([{
        "iv" => [iv].pack('m*'),
        "data" => [ciphertext].pack('m*'),
        "tag" => [cipher.auth_tag].pack('m*'),
      }.to_json].pack('m*'))
    end
  end
end
