# Native Windows facade for software-assurance.
& (Join-Path $PSScriptRoot '../lib/_invoke.ps1') -Target 'qa/windows/release/generate_software_assurance.ps1' -CommandArguments ([string[]]$args)
exit $LASTEXITCODE
