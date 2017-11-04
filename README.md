# UAC-TokenDuplication
UAC Bypass via Token Duplication.

References:
https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/UAC-TokenMagic.ps1
https://github.com/enigma0x3/Misc-PowerShell-Stuff/blob/master/Invoke-TokenDuplication.ps1
https://tyranidslair.blogspot.ca/2017/05/reading-your-way-around-uac-part-1.html
https://tyranidslair.blogspot.ca/2017/05/reading-your-way-around-uac-part-2.html
https://tyranidslair.blogspot.ca/2017/05/reading-your-way-around-uac-part-3.html
https://github.com/rsmudge/ElevateKit

UAC-TokenDuplication is a reflective DLL that will bypass UAC on any Windows 7+ version on x86 and x64.  It uses the Token Duplication technique described in the references listed above, it especially draws from UAC-TokenMagic.ps1.  The Aggressor script uses the DLL files to make UAC bypass simple and straightforward in Cobalt Strike.  In conjunction with the Aggressor script, the DLLs need to be stored in a child folder named dll.  Further details can be found at https://ijustwannared.team
