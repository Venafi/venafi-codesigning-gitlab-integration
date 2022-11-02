# escape=`

FROM mcr.microsoft.com/powershell:lts-windowsservercore-ltsc2022

ADD images/windows/windows_sign.ps1 /app/

ADD images/windows/winsdksetup.exe /
RUN pwsh -command Start-Process .\\winsdksetup.exe -ArgumentList '/features OptionId.SigningTools','/q','/ceip off','/norestart','/log .\winsdksetup.log' -NoNewWindow -Wait -verbose; setx /M PATH ('{0}{1}' -f $env:path, 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64');Remove-Item -Force \winsdksetup*

ADD VenafiCodeSigningClients.msi /
RUN pwsh -command Start-Process msiexec -ArgumentList '/i VenafiCodeSigningClients.msi','/passive' -NoNewWindow -Wait; setx /M PATH ('{0}{1}\Venafi CodeSign Protect' -f $env:path, $env:ProgramFiles); Remove-Item -Force \VenafiCodeSigningClients.msi

ENV VENAFICSPSilent=1

ENTRYPOINT ["pwsh", "-NoLogo", "-File", "/app/windows_sign.ps1"]

