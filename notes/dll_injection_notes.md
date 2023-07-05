Notes on DLL Injection

DLL injection is a technique where arbitrary code can be run within the memory of another process. The basic steps to performing DLL injection are as follows:

1. The target process is created with a call to `CreateProcess` which, amongst other things, is passed the path the the EXE and a `SUSPENDED` flag which puts the process into a suspended state. This function returns a `PROCESS_INFORMATION` struct from which we can obtain the PID, the thread ID, a handle to the process (`pi.hProcess`) or a handle to the main thread of the process (`pi.hThread`).
  
2. The size, in bytes, of the file path to the DLL to be injected is then passed to a call to `VirtualAllocEx`. In addition to the path size, the handle to the target process is also passed in. This function then allocates that many bytes into the address space of the target process. This function returns a pointer which is the base address of the allocated memory.
  
3. The path to the DLL is then written into the target process's address space starting at the base address of the allocated memory with a call to `WriteProcessMemory`.
  
4. Another thread is created in the target process with a call to `CreateRemoteThread`. Passed into this function is the address (in the address space of the target process) of the `LoadLibraryA` function, which is a function within the `kernel32.dll`. In addition to this function pointer, the base address of the allocated memory (now a pointer to the DLL path) is also passed in. `LoadLibraryA` is then run within this new thread and it performs the loading process on the DLL pointed to by the base address. This properly maps the full DLL into the address space of the target process.
  
5. Part of the steps which `LoadLibraryA` takes while loading the DLL into the target process is a call to the main function within the injected DLL (`DllMain`). This means that the injected DLL's main function is called automatically when it is getting loaded into the target process.
  

A note on architechture:

Careful inspection and treatment of system and process architechtures must be given during the injection. That is, for example, if the target process is a 32-bit process, then the injecting DLL must also be 32-bit since it will have been mapped into the 32-bit address space of the target process. Beyond that, the architechture of the injector process itself must match that of the target process. The reason for this is illustrated in the following example:

> During step 4, the address of `LoadLibraryA` must be obtained. This address can be obtained by first getting the base address of the `kernel32.dll` module which is loaded into the injector process (this DLL is loaded into every Windows process).
> 
> This can be accomplished with a call to `GetModuleHandleA` into which is passed the name of the module, "kernel32.dll". This returns the base address of the instance of `kernel32.dll` which was loaded into the calling process (the injector process).
> 
> From here, a call to `GetProcAddress` is made and the base address of the module as well as a pointer to the function name within the module (`LoadLibraryA`) is passed in as arguments. What is retunred is the relative address of the function within the module. Subtracting the base address from this relative address gives the "offset". Which is a value represent the number of bytes between the base address of the module and the function within the module.
> 
> Once this offset is obtained, one must then retrieve the base address of the copy of `kernel32.dll` which was loaded into the target process. Then adding the offset to the base address gives one the absolute address of the `LoadLibraryA` function within the target process.

In this example, we are heavily relying on the offset calculated from the `kernel32.dll` in the calling process (injector process). However, if the calling process is, say, 64-bit while the target process is 32-bit, then the offset between the base address of the module and the function will not necessarily correspond to the offset is a 32-bit version of the same module. Thus if the architechtures are different, you may end up treating some random address in the target process as a function pointer, which obviously will fail in many cases.

A note on loaded modules:

When a process is started, not all modules are loaded at the same time. This means that when the target process is created and immediately put into a suspended state, there is a chance that it has not loaded all of its modules yet. Thus during step 4, when we retreive the base address of `kernel32.dll` in the target process, this assumes this module has already been loaded. However, to make sure the module is loaded one can perform the following loop:

1. Enumerate all modules currently loaded in the target process: This can be done by calling `EnumProcessModulesEx` which takes the target process handle and populates a vector with the handles of all the modules loaded in the target process at that time.
  
2. Iterate through the handles: Pass each handle into `GetModuleBaseNameA` which returns a byte string representing the name of the module. Then this name is checked against the desired module name (`kernel32.dll` in this case).
  
3. If there were no matches, then the target process's main thread is taken out of the suspended state for a short period of time, say 1ms, and this will give the thread time to load more modules.
  
4. Repeat steps 1-3 until match is found: After a match is found, place the main thread back into a suspended state.

Notes on API hooking

In this example, I will be attempting to hook the `fwrite` function which is located in the `msvcrt.dll` module. To do this, I will be using the DLL injector described above and equipping it with a DllMain (which gets called automatically by LoadLibraryA) to modify the IAT (import address table) of `msvcrt.dll`. Specifically, I will need to locate the address in the IAT that points to `fwrite` and replace this address with the address of my hook function. The hook function will then receive the arguments which were intended for `fwrite`. 

However, it is not apparent in what order my DLL is loaded with respect to the other modules that are loaded by the target process. So to be able to successfully hook `fwrite`, I need to be sure that the `msvcrt.dll` has been loaded. How can one be certain of this? Well, since the DLL injector waits for `kernel32.dll` to be loaded before loading in my DLL, we can be certain that `kernel32.dll` is present at the time my DllMain is running. So what? So this means that any subsequent module loads will be done with `LoadLibrary` which is a funtion within `kernel32`. That means, we can hook `LoadLibrary` to see when the target module (`mscvrt.dll`) is loaded. 

So the first step is to check if the desired module has been loaded already. If it has, then jump to the function in DllMain which makes the IAT modification. Otherwise, hook `LoadLibrary` and write a hook function which calls the iat_mod function, then hands the given arguments back over to `LoadLibrary`. Technically, you would want to allow `LoadLibrary` to proceed first, then modify the IAT since the IAT will only be present after the module is loaded.  
