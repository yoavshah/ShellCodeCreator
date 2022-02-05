# ShellCodeCreator

  ## ShellCodeCreator is a project which automate the creation of a shellcode from a C/CPP file based [on this article](https://www.ired.team/offensive-security/code-injection-process-injection/writing-and-compiling-shellcode-in-c)

  ## Usage
  
  * Create a C/CPP file like example.cpp.
  * Find VsDevCmd.bat path (This file should be located at VisualStudio folder).
  * Run the code :)
  
  ## Notes
  
  * The C/CPP file should not have constant variables (char[] is not allowed either).
  * The C/CPP file should find WinApi functions by iterating over the modules from PEB structure.

  ## Usage Example
  
  * Run the command "python ShellCodeCreator.py -s example\example.cpp -p <VsDevCmd.bat> -v".

<img align="center" src="https://raw.githubusercontent.com/yoavshah/ShellCodeCreator/master/images/command_example.png" />

  * The folder should now contain numerous files, example.text.cpp is the shellcode bytecode in cpp as a constant variable.

<img align="center" src="https://raw.githubusercontent.com/yoavshah/ShellCodeCreator/master/images/shellcode_cpp_example.png" />


  ## How does it works?
  
  * Just automating this [article](https://www.ired.team/offensive-security/code-injection-process-injection/writing-and-compiling-shellcode-in-c).


