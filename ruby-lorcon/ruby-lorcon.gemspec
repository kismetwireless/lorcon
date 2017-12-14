Gem::Specification.new do |s|
  s.licenses      = ['GPL-2.0']
  s.authors       = ['dragorn', 'Joshua Wright']
  s.email         = ['msfdev@metasploit.com']
  s.name          = 'ruby-lorcon'
  s.version       = '0.2.0'
  s.date          = '2017-12-13'
  s.summary       = 'This is an experimental interface for lorcon.'
  s.homepage      = 'https://github.com/kismetwireless/lorcon/tree/master/ruby-lorcon'
  s.metadata    = { "source_code_uri" => "https://github.com/kismetwireless/lorcon.git" }
  s.description   = 'This interface is only available on Linux and with lorcon-supported wireless drivers.'
  s.files         = [ 'README',
                      'extconf.rb',
                      'Lorcon2.c',
                      'Lorcon2.h' ]
  s.extensions    = [ 'extconf.rb' ]
end
