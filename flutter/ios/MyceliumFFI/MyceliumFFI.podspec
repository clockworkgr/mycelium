Pod::Spec.new do |s|
  s.name         = 'MyceliumFFI'
  s.version      = '0.1.0'
  s.summary      = 'Mycelium Rust FFI static library'
  s.homepage     = 'https://github.com/mycelium-mesh/mycelium'
  s.license      = { :type => 'MIT' }
  s.author       = 'Mycelium'
  s.source       = { :path => '.' }
  s.platform     = :ios, '15.5'
  s.static_framework = true

  s.vendored_libraries = 'Frameworks/libmycelium_ffi.a'
  s.source_files       = 'Frameworks/include/**/*.h'
  s.public_header_files = 'Frameworks/include/**/*.h'

  s.frameworks = 'Security', 'SystemConfiguration'
  s.libraries  = 'c++', 'resolv'

  # Do NOT use -force_load here — it pulls in bundled OpenSSL/SQLCipher
  # symbols that conflict with the Flutter/Dart engine and crash the VM.
  # Instead, we keep symbols alive via the exported_symbols file.
end
