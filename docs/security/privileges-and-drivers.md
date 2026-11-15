# Privileges and drivers

The TUI currently runs in the same elevated process as the packet engine because WinDivert capture and runtime extraction require elevation. A future service split could reduce UI privilege, but it needs authenticated IPC and is not implemented.

Native WFP user-mode calls are policy administration through the Windows Filtering Platform API. They do not provide kernel packet interception. A future callout driver would require WDK build, INF installation, CAT/signing, IOCTL authorization, rollback and isolated Windows tests.

Never describe an Authenticode-signed EXE as a signed kernel driver. WinDivert and Wintun have their own distribution and signing requirements.
