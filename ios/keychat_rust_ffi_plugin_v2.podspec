Pod::Spec.new do |s|
  s.name             = 'keychat_rust_ffi_plugin_v2'
  s.version          = '0.1.0'
  s.summary          = 'Keychat V2 protocol FFI plugin'
  s.homepage         = 'https://github.com/keychat-io/keychat_rust_ffi_plugin_v2'
  s.license          = { :type => 'MIT' }
  s.author           = { 'Keychat' => 'dev@keychat.io' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.ios.deployment_target = '15.0'
  s.dependency 'Flutter'
  s.script_phase = {
    :name => 'Build Rust library',
    :script => 'bash "${PODS_TARGET_SRCROOT}/../cargokit/build_pod.sh" ../rust keychat_rust_ffi_plugin_v2',
    :execution_position => :before_compile,
    :input_files => ['${BUILT_PRODUCTS_DIR}/cargokit_phony'],
    :output_files => ["${BUILT_PRODUCTS_DIR}/libkeychat_rust_ffi_plugin_v2.a"],
  }
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'IPHONEOS_DEPLOYMENT_TARGET' => '15.0',
    'EXCLUDED_ARCHS[sdk=iphone*]' => 'i386 x86_64',
    'OTHER_LDFLAGS' => '-force_load ${BUILT_PRODUCTS_DIR}/libkeychat_rust_ffi_plugin_v2.a',
  }
end
