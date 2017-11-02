require 'jwt'
require 'openssl'
require 'securerandom'

module NginxOmniauthAdapter
  class Token
    class InvalidAudience < StandardError; end
    class InvalidIssuer < StandardError; end

    DEFAULT_ALGO = 'HS256'
    ID_TIME_BASE = Time.utc(2016,1,1,0,0,0).to_i

    def self.decode(token_string, keys: nil, master: nil, domain: nil, algorithm: DEFAULT_ALGO, raise_error: false)
      options = {
        algorithm: algorithm,
        verify_jti: proc { |jti| true },
      }

      payload, header = JWT.decode(token_string, nil, true, options) do |header|
        keys[header['kid'] || :default] || keys[:default]
      end

      unless payload['ngxo']
        raise InvalidIssuer if raise_error
        return nil, :invalid_issuer
      end


      begin
        token = Token.new(
          id: payload['jti'],
          domain: payload['aud'],
          expiry: payload['exp'],
          master: payload['ngxo']['m'],
          context: payload['ngxo']['c'],
          user: payload['ngxo']['u'],
        )
      rescue ArgumentError
        raise if raise_error
        return nil, :invalid_token
      end

      unless token.valid_for_domain?(domain, master)
        raise InvalidAudience if raise_error
        return nil, :invalid_audience
      end

      return token, nil

    rescue JWT::VerificationError
      raise if raise_error
      return nil, :verification_error
    rescue JWT::ExpiredSignature
      raise if raise_error
      return nil, :expired
    end

    def self.issue(domain: nil, parent_id: nil, expires_in: 86400 * 2, master: , context: nil, user: , algorithm: DEFAULT_ALGO, key_id: nil, key: )
      token = new(
        domain: domain,
        parent_id: parent_id,
        expiry: Time.now.to_i + expires_in,
        master: master,
        context: context,
        user: user,
      )
      token_string = token.encode(
        key_id: key_id,
        key: key,
        algorithm: algorithm,
      )
      return token, token_string
    end

    def initialize(id: nil, parent_id: nil, expiry: , domain: nil, master: , context: nil, user: )
      @id = id || random_id(parent_id)
      @expiry = expiry.to_i
      @domain = domain

      @master = master == true || master == 1 ? true : false
      @user = symbolize_keys(user)
      @context = context && symbolize_keys(context)

      raise ArgumentError, ":domain can't be set when :master is true" if domain && master
    end

    attr_reader :id, :expiry, :domain, :context, :master, :user

    def valid_for_domain?(o_domain, o_master)
      if o_master
        return master
      end
      !master && ((domain && o_domain) ? domain == o_domain : true)
    end

    def payload
      {
        jti: id,
        exp: expiry,
        aud: domain,
        ngxo: {
          v: 1,
          m: master ? 1 : nil,
          u: user,
          c: context,
        }.select { |k,v| v },
      }.select { |k,v| v }
    end

    def encode(key_id: nil, key: , algorithm: DEFAULT_ALGO)
      header = {}
      header[:kid] = key_id if key_id
      JWT.encode(payload, key, DEFAULT_ALGO, header)
    end

    private

    def random_id(parent_id = nil)
      t = Time.now 
      id = "#{(t.to_i - ID_TIME_BASE).to_s(36)}-#{t.usec.to_s(36)}-#{SecureRandom.urlsafe_base64(1)}"
      if parent_id
        "#{parent_id}/#{id}"
      else
        "a-#{id}"
      end
    end

    def symbolize_keys(obj)
      case obj
      when Hash
        Hash[
          obj.map do |k, v|
            [k.to_sym, symbolize_keys(v)]
          end
        ]
      when Array
        obj.map { |_| symbolize_keys(_) }
      else
        obj
      end
    end


  end
end

