; Inno Setup script for the Windows installer.
; Built by the release workflow:  ISCC.exe /DAppVersion=0.3.0 installer\ciphercheck.iss
; Expects release\ciphercheck.exe and release\ciphercheck-cli.exe (made by build.py).

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{6F0B7C58-2C1E-4A57-9D3B-5E1A8F2C94D7}
AppName=CipherCheck
AppVersion={#AppVersion}
AppPublisher=putridpunk
AppPublisherURL=https://github.com/putridpunk/CipherCheck
AppSupportURL=https://github.com/putridpunk/CipherCheck/issues
DefaultDirName={autopf}\CipherCheck
DefaultGroupName=CipherCheck
DisableProgramGroupPage=yes
; Installs for the current user without administrator rights (the user may choose all users).
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
LicenseFile=..\LICENSE
OutputDir=..\release
OutputBaseFilename=ciphercheck-setup
UninstallDisplayIcon={app}\ciphercheck.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; Flags: unchecked

[Files]
Source: "..\release\ciphercheck.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\release\ciphercheck-cli.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\CipherCheck"; Filename: "{app}\ciphercheck.exe"
Name: "{autodesktop}\CipherCheck"; Filename: "{app}\ciphercheck.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\ciphercheck.exe"; Description: "Launch CipherCheck"; Flags: nowait postinstall skipifsilent
