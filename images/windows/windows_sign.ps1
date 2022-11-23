[CmdletBinding()]

$ErrorActionPreference = 'Stop'

$paramsNeeded = 'TPP_AUTH_URL', 'TPP_HSM_URL', 'TPP_USERNAME', 'TPP_PASSWORD', 'SIGN_WITH', 'SIGN_ACTION', 'INPUT_PATH'
if ( $env:SIGN_WITH -eq 'signtool' ) {
    $paramsNeeded += 'CERTIFICATE_SUBJECT_NAME'
}

$envError = $paramsNeeded | foreach-object {
    $thisParam = $_
    try {
        $null = get-item -path env:$thisParam
    } catch {
        $thisParam
    }
}
if ( $envError ) {
    throw ('Environment variables not found: {0}' -f ($envError -join ', '))
}

# needed for signtool
Start-Process -FilePath 'regsvr32' -ArgumentList '/s', 'c:\windows\system32\venaficsp.dll' -Wait -NoNewWindow

# support concurrent runs
# https://docs.venafi.com/Docs/current/TopNav/Content/CodeSigning/t-codesigning-integration-multi-libhsm.php
$env:LIBHSMINSTANCE = [uri]::EscapeDataString((Get-Random))

$cspArgs = @{
    FilePath    = 'cspconfig.exe'
    NoNewWindow = $true
    Wait        = $true
}

if ( $DebugPreference -eq 'Continue' -or $env:VENAFI_CONTAINER_DEBUG_CSP -eq 'true' ) {
    Start-Process @cspArgs -ArgumentList 'trace', 'console', 'enable', 'out', 'stdout'
    $debugOn = $true
}

try {

    # getgrant
    $argList = @(
        'getgrant',
        '-force',
        ('-authurl:{0}' -f $env:TPP_AUTH_URL),
        ('-hsmurl:{0}' -f $env:TPP_HSM_URL),
        ('-username:{0}' -f $env:TPP_USERNAME),
        ('-password:{0}' -f $env:TPP_PASSWORD),
        '-machine'
    )
    Start-Process @cspArgs -ArgumentList $argList

    # sync
    Start-Process @cspArgs -ArgumentList 'sync', '--verbose', '-machine'

    # sign
    switch ($env:SIGN_WITH) {
        'signtool' {
            $params = @{
                FilePath    = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe'
                Wait        = $true
                NoNewWindow = $true
                # Verb        = 'RunAs'
                PassThru    = $true
            }

            switch ($env:SIGN_ACTION) {
                'sign' {
                    $algo = 'sha256'
                    if ( $env:DIGEST_ALGORITHM ) {
                        $algo = $env:DIGEST_ALGORITHM
                    }
                    # write-output "signtool sign /v /fd $algo /sm /n ""$env:CERTIFICATE_SUBJECT_NAME"" ""$env:INPUT_PATH"""
                    # $signToolPath = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\sign'
                    # $signToolPath\signtool.exe sign /v /fd $algo /n ""$env:CERTIFICATE_SUBJECT_NAME"" "$env:INPUT_PATH"

                    $params.ArgumentList = 'sign', '/v', '/fd', $algo, '/sm', "/n ""$env:CERTIFICATE_SUBJECT_NAME"""

                    if ( $env:TIMESTAMPING_SERVER ) {
                        $params.ArgumentList += '/tr', $env:TIMESTAMPING_SERVER, '/td', $algo
                    }

                    if ( $debugOn ) { $params.ArgumentList += '/debug' }

                    $params.ArgumentList += """$env:INPUT_PATH"""

                    if ( $debugOn ) { $params | ConvertTo-Json }

                    $result = Start-Process @params
                    switch ($result.ExitCode) {
                        0 {
                            'signing successful'
                        }

                        1 {
                            throw 'signing failed.'
                        }

                        2 {
                            Write-Warning 'signing succeeded with warnings'
                        }
                    }
                }

                'verify' {
                    $params.ArgumentList = 'verify', '/pa', $env:INPUT_PATH
                    $result = Start-Process @params

                    switch ($result.ExitCode) {
                        0 {
                            'signing verification successful'
                        }

                        1 {
                            throw 'verify failed'
                        }

                        2 {
                            Write-Warning 'verification succeeded with warnings'
                        }
                    }
                }

                Default {
                    throw "Invalid action $_.  'sign' and 'verify' are supported."
                }
            }
        }

        'powershell' {

            $signMe = if ( (Get-Item $env:INPUT_PATH) -is [System.IO.DirectoryInfo] ) {
                Get-ChildItem -path $env:INPUT_PATH -Recurse | Select-Object -ExpandProperty FullName
            } else {
                $env:INPUT_PATH
            }

            switch ($env:SIGN_ACTION) {
                'sign' {

                    $cert = Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert

                    if ( $env:CERTIFICATE_SUBJECT_NAME ) {
                        $cert = $cert | Where-Object { $_.Subject -like ('*{0}*' -f $env:CERTIFICATE_SUBJECT_NAME) }
                    }

                    if ( ($cert).Count -eq 0 ) {
                        throw 'no certificate found for signing'
                    } elseif ( ($cert).Count -gt 1 ) {
                        throw 'more than 1 certificate found for signing: ' + ($cert.Subject -join ', ')
                    }

                    $params = @{
                        Certificate = $cert
                        FilePath    = $signMe
                    }

                    if ( $env:TIMESTAMPING_SERVER ) {
                        $params.TimestampServer = $env:TIMESTAMPING_SERVER
                    }

                    Set-AuthenticodeSignature @params
                }

                'verify' {
                    $result = Get-AuthenticodeSignature -FilePath $signMe
                    if ( $result | Where-Object { $_.Status -ne 'Valid' } ) {
                        $result
                        throw 'One or more files are not signed'
                    } else {
                        'All files are signed'
                    }
                }

                Default {
                    throw "Invalid action $_.  'sign' and 'verify' are supported."
                }
            }
        }

        Default {
            throw ('Unknown "sign with" option {0}' -f $_)
        }
    }
} finally {

    $argList = @(
        'revokegrant',
        '-force',
        'clear',
        '-machine'
    )
    Start-Process @cspArgs -ArgumentList $argList
}


