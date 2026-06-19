; Aegis Agent Windows Installer (Inno Setup)
; Place this file in scripts/ and run from project root:
;   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" scripts\installer_windows.iss

#define MyAppName "Aegis Agent"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Aegis Security"
#define MyAppURL "http://127.0.0.1:8000"
#define MyAppExeName "AegisAgent.exe"

[Setup]
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir=..\downloads
OutputBaseFilename=AegisAgent-Setup-{#MyAppVersion}
SetupIconFile=..\agent_app\icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
DisableProgramGroupPage=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "..\dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{autostart}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Aegis Agent"; Flags: postinstall nowait skipifsilent shellexec

[UninstallRun]
Filename: "taskkill"; Parameters: "/f /im AegisAgent.exe"; Flags: runhidden
