# execute-multiple-assemblies

## What is this?
This project aims to provide a proof of concept for executing multiple .NET assemblies from an unmanaged process. The parent process will spawn and inject the child process, which handles the .NET loading and executing. The child process will poll for new assemblies over a named pipe, and the parent process will poll for user input. When a file path is provided, the parent process will read the file, base64 encode it, and send it along with arguments to the child process. It's important to note that in this POC the file provided must be readable by the parent process, but when implementing this into custom C2 tooling it should be trivial to modify this to work with your C2 framework. In my testing of this, it was easiest to have the C2 client base64 encode the assembly and the parent process will simply relay that base64 string to the child.

## Why?
My only frustration with Cobalt Strike's execute-assembly was when I would mistype an argument to SharpHound and have to run it twice, which involves spawning another sacrificial process and loading the CLR again. Obviously this is the result of user error, but it made me wonder if there was a simple way to leave the sacrificial process alive and have it run several assemblies from one CLR load.

To be clear, this isn't an implementation of this in Cobalt Strike, but rather the broken out functionality. However I found it easy to implement in my toy C2 framework.
## Usage
```parent-execute-assembly.exe block -p C:\Windows\System32\notepad.exe```
* The -p parameter denotes which local executable to launch and inject into
* If you include "block" as an argument then the child process will be launched with the PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON flag, so only Microsoft DLLs can be loaded into it. This is how Cobalt Strike's ```blockdll``` command works.
* After the program has launched it will prompt/wait for user input. You can provide input in the format: path-to-local-executable arguments

<b>IMPORTANT:</b> The size of the named pipe being sent/received is hardcoded in. By default it's set to 1.5MB. Keep in mind that the buffer will need to hold the BASE64 ENCODED version of the assembly plus the arguments. This means that an assembly smaller than 1.5MB may still not work if the Base64 encoding and arguments are larger. The parent process will throw a warning if the payload is larger than the buffer. You should be able to simply increase the buffer size, but I have not tested above 1.5MB. 

By default I've included the shellcode for the execute-assembly payload in the parent-execute-assembly file. However if you don't trust me (which you shouldn't!) then you can reproduce this by using [hasherezade's pe_to_shellcode](https://github.com/hasherezade/pe_to_shellcode) to convert execute-assembly to shellcode. I then used a small assembly which I've put [here](https://gist.github.com/passthehashbrowns/e860a590681484c0125520c696892a55) which will print out the shellcode that you can paste into the project. 

As mentioned earlier the path-to-local-executable only needs to be readable by the parent process. You can also load from a remote file share by simply passing in the UNC path, such as \\\attacker\seatbelt.exe. 

![execution](https://github.com/passthehashbrowns/passthehashbrowns.github.io/blob/master/images/seatbelt_executing.png)

## Opsec considerations
* You'll still be loading the CLR into a process, so consider using a process that would normally load the CLR.
* I haven't implemented any AMSI/ETW bypasses (yet) so keep that in mind while blasting away.
* Take parent/child relationships into account here. If the blue team sees notepad.exe spawned by rundll32.exe, that is sure to raise some eyebrows.

## Disclaimer
This code is bad and should be treated as such, I'm still trying to get familiar with C++. I'm sure there are some edge cases I haven't tested. Please feel free to submit pull requests with better solutions, or you can Tweet at me. Happy to fix (or try to fix) any bugs submitted.

## Future work
Some things I'd like to implement in the (near, hopefully) future:
* Commands to unload/reload the CLR, to allow for leaving the child process alive for longer operations but not having the telltale CLR in memory
* Alternate methods to fetch the assembly like HTTP/DNS
* Better method of injecting into child process, likely process hollowing
* Implement some evasion into the child process, such as AMSI/ETW patching
* Haven't tested if this will work yet with the named pipe stuff going on, but spoofing the PPID of the child

## Credits
https://teamhydra.blog/2020/10/12/in-process-execute-assembly-and-mail-slots/

https://github.com/b4rtik/metasploit-execute-assembly/blob/master/HostingCLR_inject/HostingCLR/HostingCLR.cpp

https://github.com/etormadiv/HostingCLR

https://blog.xpnsec.com/hiding-your-dotnet-etw/

https://www.ired.team/offensive-security/code-injection-process-injection/process-injection

https://docs.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output

https://stackoverflow.com/questions/180947/base64-decode-snippet-in-c
