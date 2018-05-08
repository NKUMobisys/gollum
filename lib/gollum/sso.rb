require 'config'
# require 'pry'

module SSO
  def sso_login
    timestamp = Time.now.to_i.to_s
    token = gen_sso_token(current_host + timestamp + Settings.sso_token)
    sso_request = URI::HTTP.build(host: Settings.sso_host, port: (Settings.sso_port||80), path: "/users/sign_in",
      query: URI.encode_www_form({
        from: current_server,
        timestamp: timestamp,
        token: token
      })
    )
    redirect sso_request.to_s
  end

  def authenticate_user!
    return if current_user
    unless validate_sso_login
      sso_login
      return
    end
    session[:user] = sso_user_info
  end

  def current_user
    @current_user ||= session[:user]
  end

  def current_host
    @current_host ||= (request.host || Settings.server_host)
  end

  def current_server
    uri_opt = {}
    [:host, :port].each do |key|
      uri_opt[key] = request.send(key) || Settings["server_"+key.to_s]
    end
    @current_server ||= URI::HTTP.build(uri_opt).to_s
  end

  def validate_sso_login
    ["uid", "timestamp", "nonceStr", "uinfo", "token"].each do |sso_key|
      return false if params[sso_key].nil?
    end
    return false if Time.now.to_i - params["timestamp"].to_i > 30
    # TODO
    # return false if Rails.cache.read(params["token"])
    # Rails.cache.write(params["token"], expires_in: 10.minutes)
    params['token'] == gen_sso_token(params["timestamp"]+params["uid"]+params["nonceStr"]+Settings.sso_token+params["uinfo"])
  end

  def gen_sso_token(key)
    Digest::MD5.new.update(key).hexdigest
  end

  def sso_user_info
    JSON.parse(Base64.decode64(params["uinfo"])).merge({sso_id: params["uid"]})
  end
end
