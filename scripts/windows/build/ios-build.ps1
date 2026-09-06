param([ValidateSet('build','release','test')][string]$Mode='build')
throw "KasSee iOS requires macOS with Xcode. Run 'make ios', 'make ios-release', or 'make ios-test' on a macOS/Xcode host."
