[CmdletBinding()]

$envError = 'TPP_AUTH_URL', 'TPP_HSM_URL', 'TPP_USERNAME', 'TPP_PASSWORD', 'SIGN_WITH', 'SIGN_ACTION', 'INPUT_PATH' | foreach-object {
    try {
        $null = get-item -path env:$_
    } catch {
        $_
    }
}
if ( $envError ) {
    throw ('Environment variables not found: {0}' -f ($envError -join ', '))
}

$cspArgs = @{
    FilePath    = 'cspconfig.exe'
    NoNewWindow = $true
    Wait        = $true
}

if ( $DebugPreference -eq 'Continue' -or $env:VENAFI_CONTAINER_DEBUG_CSP -eq 'true' ) {
    Start-Process @cspArgs -ArgumentList 'trace', 'console', 'enable', 'out', 'stdout'
}

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

try {

    # sign
    switch ($env:SIGN_WITH) {
        'signtool' {
            switch ($env:SIGN_ACTION) {
                'sign' {

                }

                'verify' {
                    $result = Start-Process -FilePath signtool -ArgumentList 'verify', '/pa', $env:INPUT_PATH
                    switch ($result.ExitCode) {
                        1 {
                            throw 'verify failed'
                        }

                        2 {
                            Write-Warning 'verification succeeded with warnings'
                        }
                    }
                }

                Default {
                    throw "Invalid action $_"
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

                    # TODO: validate subject name

                    $params = @{
                        Certificate = $cert
                        FilePath    = $signMe
                    }

                    if ( $env:TIMESTAMPING_SERVERS ) {
                        $params.TimestampServer = $env:TIMESTAMPING_SERVERS
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
                    throw "Invalid action $_"
                }
            }
        }

        Default {
            throw ('Unknown sign with option {0}' -f $_)
        }
    }
} finally {
    # logout
    $argList = @(
        'revokegrant',
        '-force',
        'clear',
        '-machine'
    )
    Start-Process @cspArgs -ArgumentList $argList
}


