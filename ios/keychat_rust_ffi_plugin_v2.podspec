Pod::Spec.new do |s|
  s.name             = 'keychat_rust_ffi_plugin_v2'
  s.version          = '0.1.0'
  s.summary          = 'Keychat V2 protocol FFI plugin'
  s.homepage         = 'https://github.com/keychat-io/keychat_rust_ffi_plugin_v2'
  s.license          = { :type => 'MIT' }
  s.author           = { 'Keychat' => 'dev@keychat.io' }
  s.source           = { :path => '.' }
  s.ios.deployment_target = '13.0'
  s.dependency 'Flutter'
  s.script_phase = {
    :name => 'Build Rust library',
    :script => 'bash "${PODS_TARGET_SRCROOT}/../cargokit/build_pod.sh" ../rust keychat_rust_ffi_plugin_v2',
    :execution_position => :before_compile,
    :input_files => ['${PODS_TARGET_SRCROOT}/../rust/**/*'],
  }
end
