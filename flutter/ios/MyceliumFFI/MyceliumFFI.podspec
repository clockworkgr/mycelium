Pod::Spec.new do |s|
  s.name         = 'MyceliumFFI'
  s.version      = '0.1.0'
  s.summary      = 'Mycelium Rust FFI static library'
  s.homepage     = 'https://github.com/mycelium-mesh/mycelium'
  s.license      = { :type => 'MIT' }
  s.author       = 'Mycelium'
  s.source       = { :path => '.' }
  s.platform     = :ios, '15.0'
  s.static_framework = true

  s.vendored_libraries = 'Frameworks/libmycelium_ffi.a'
  s.source_files       = 'Frameworks/include/**/*.h'
  s.public_header_files = 'Frameworks/include/**/*.h'

  s.frameworks = 'Security', 'SystemConfiguration'
  s.libraries  = 'c++', 'resolv'

  s.pod_target_xcconfig = {
    'OTHER_LDFLAGS' => '-force_load "${PODS_ROOT}/../MyceliumFFI/Frameworks/libmycelium_ffi.a"',
  }
end
