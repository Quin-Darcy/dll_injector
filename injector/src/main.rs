//extern crate winapi;

use std::ptr::null_mut;
use std::ffi::{OsStr, CString, CStr};
use std::iter::once;
use std::os::windows::ffi::OsStrExt;

use winapi::um::processthreadsapi::{CreateProcessW, CreateRemoteThread, ResumeThread, SuspendThread, STARTUPINFOW, PROCESS_INFORMATION};
use winapi::um::winbase::CREATE_SUSPENDED;
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory, MapViewOfFile, UnmapViewOfFile, FILE_MAP_ALL_ACCESS};
use winapi::shared::minwindef::{DWORD, HMODULE, FARPROC, LPVOID};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::ctypes::c_void;
use winapi::um::winbase::{OpenFileMappingA, WAIT_OBJECT_0};
use winapi::um::winnt::{LPCSTR, LPSTR, HANDLE, PAGE_READWRITE};
use winapi::um::psapi::{EnumProcessModulesEx, GetModuleBaseNameA, LIST_MODULES_ALL};

const WAIT_TIMEOUT: DWORD = 258;



// Convert a string to a wide string
fn to_wstring(string: &str) -> Vec<u16> {
    OsStr::new(string).encode_wide().chain(once(0)).collect()
}

// This function will create a process in a suspended state by using the CreateProcessW function
// The CreateProcessW function creates a new process and its primary thread. The new process runs
// in the security context of the calling process.
fn create_process(target_process: &str) -> Result<PROCESS_INFORMATION, DWORD> {
    // We will take the given target process path and convert it to a wide string
    // This is because many of the Windows API functions require wide strings
    let target_process_w = to_wstring(target_process);

    // Next, we will define a STARTUPINFO struct which will be used to store information
    // about the process we are about to create. It specifies the window station, desktop,
    // standard handles, and appearance of the main window for a process at creation time.
    // The std::mem::zeroed() function is used to initialize the struct to all zeros.
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };

    // Now, we will define a PROCESS_INFORMATION struct which will also be used to store
    // information about the process we are about to create. It contains the process's
    // handle, thread handle, and identification information.
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    println!("Creating process...");

    // Create the target process in a suspended state
    let success = unsafe {
        CreateProcessW(
            null_mut(),
            target_process_w.as_ptr() as *mut u16,
            null_mut(),
            null_mut(),
            0,
            CREATE_SUSPENDED,
            null_mut(),
            null_mut(),
            &mut si,
            &mut pi,
        )
    };

    if success == 0 {
        Err(unsafe { winapi::um::errhandlingapi::GetLastError() })
    } else {
        println!("    Process successfully created in suspended state!");
        println!("        Process ID: {}", pi.dwProcessId);
        println!("        Thread ID: {}\n", pi.dwThreadId);
        Ok(pi)
    }
}

// Next, we will use the VirtualAllocEx function to allocate memory within the process
// We will need the process handle to do this, which is stored in the PROCESS_INFORMATION struct
// We will need the amount of memory to allocate, which is the size (in bytes) of the DLL path
// We will need to specify the type of memory to allocate, which is read, write, and execute
// We will need to specify the type of memory protection to use, which is read, write, and execute
// The return value is the base address of the allocated region of pages
fn allocate_memory(pi: PROCESS_INFORMATION, dll_path: &str) -> Result<*mut c_void, DWORD> {
    println!("Allocating memory in target process...");
    let dll_path_c = CString::new(dll_path).unwrap();
    let dll_path_ptr = unsafe {
        VirtualAllocEx(
            pi.hProcess,
            null_mut(),
            dll_path_c.as_bytes_with_nul().len(),  // Allocate enough space for the DLL path
            winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE,
            winapi::um::winnt::PAGE_READWRITE,
        )
    };

    if dll_path_ptr.is_null() {
        Err(unsafe { winapi::um::errhandlingapi::GetLastError() })
    } else {
        println!("    Memory successfully allocated in target process!");
        println!("        Memory allocated at address: {:p}", dll_path_ptr);
        println!("        Memory allocated: {} bytes\n", dll_path_c.as_bytes_with_nul().len());
        Ok(dll_path_ptr)
    }
}

// This function will write the DLL path to the memory allocated in the target process
// It will accept the process handle, the base address of the allocated memory, and the DLL path
// It will return a boolean value indicating whether the DLL path was successfully written
fn write_memory(process_handle: HANDLE, dll_path_ptr: *mut c_void, dll_path: &str) -> Result<bool, DWORD> {
    println!("Writing DLL path to allocated memory...");
    let dll_path_c = CString::new(dll_path).unwrap();
    let mut bytes_written: usize = 0;

    let success = unsafe {
        WriteProcessMemory(
            process_handle,
            dll_path_ptr,
            dll_path_c.as_ptr() as *mut c_void,
            dll_path_c.as_bytes_with_nul().len(),
            &mut bytes_written,
        )
    };

    if success == 0 {
        Err(unsafe { winapi::um::errhandlingapi::GetLastError() })
    } else {
        println!("    DLL path successfully written to allocated memory!");
        println!("        Bytes written: {}\n", bytes_written);
        Ok(true)
    }
}

// This function will get the base address of the kernel32.dll module which has been 
// loaded by the calling process (this program) and use the GetProcAddress function
// to get the address (relative to the base address) of the LoadLibraryA function
// The function then subtracts the base address from the LoadLibraryA address to get the offset
fn get_loadlib_offset() -> Result<usize, DWORD> {
    println!("Getting offset of LoadLibraryA function...");
    let module_str = CString::new("kernel32.dll").unwrap();
    let loadlib_str = CString::new("LoadLibraryA").unwrap();
    let loadlib_offset: usize;

    unsafe {
        // First we need to get the kernel32.dll module handle
        let kernel32_handle = GetModuleHandleA(module_str.as_ptr());

        if kernel32_handle.is_null() {
            println!("    Failed to get kernel32.dll module handle!");
            return Err(winapi::um::errhandlingapi::GetLastError());
        }

        // Next we need to get the relative address of the LoadLibraryA function
        // We can do this by calling the GetProcAddress function
        let loadlib_ptr = GetProcAddress(kernel32_handle, loadlib_str.as_ptr());

        if loadlib_ptr.is_null() {
            println!("    Failed to get address of LoadLibraryA function!");
            return Err(winapi::um::errhandlingapi::GetLastError());
        }

        // Calculate the offset of LoadLibraryA in kernel32.dll
        loadlib_offset = loadlib_ptr as usize - kernel32_handle as usize;
    }

    println!("    Offset of LoadLibraryA function successfully retrieved!");
    println!("        Offset: 0x{:x}\n", loadlib_offset);
    Ok(loadlib_offset)
}

// This function will use the EnumProcessModulesEx function populate a vector with the
// handles of all the modules loaded by the target process. It then iterates through
// the vector and checks the name of each module against the name of the module we are
// looking for. If the module is found, the function returns the handle of the module.
// If the module is not found, the function returns an error code.
fn check_if_kernel32_loaded(process_handle: HANDLE) -> Result<HMODULE, DWORD> {
    // cb_needed is the number of bytes required to store all the module handles
    let mut cb_needed: DWORD = 0;

    // This first call to EnumProcessModulesEx will set cb_needed to the correct value
    let result = unsafe {
        EnumProcessModulesEx(
            process_handle,
            std::ptr::null_mut(),
            0,
            &mut cb_needed,
            LIST_MODULES_ALL,
        )
    };

    if result == 0 {
        return Err(unsafe { winapi::um::errhandlingapi::GetLastError() });
    }

    // Calculate the number of modules loaded by the target process by dividing
    // the number of bytes needed by the size of a module handle
    let module_count = cb_needed / std::mem::size_of::<HMODULE>() as DWORD;

    // Create a vector to store the module handles
    let mut h_mods: Vec<HMODULE> = vec![std::ptr::null_mut(); module_count as usize];

    // This second call to EnumProcessModulesEx will populate the vector with the module handles
    let result = unsafe {
        EnumProcessModulesEx(
            process_handle,
            h_mods.as_mut_ptr(),
            cb_needed,
            &mut cb_needed,
            LIST_MODULES_ALL,
        )
    };

    if result == 0 {
        return Err(unsafe { winapi::um::errhandlingapi::GetLastError() });
    }

    // Create a buffer to store the name of each module
    let mut module_name = vec![0u8; 256];

    // Iterate through the vector of module handles and check the name of each module
    // If the name matches the name of the module we are looking for, return the handle
    for i in 0..module_count {
        let result = unsafe {
            GetModuleBaseNameA(
                process_handle,
                h_mods[i as usize],
                module_name.as_mut_ptr() as LPSTR,
                256 as DWORD,
            )
        };

        if result == 0 {
            return Err(unsafe { winapi::um::errhandlingapi::GetLastError() });
        }

        let name = unsafe { CStr::from_ptr(module_name.as_ptr() as LPCSTR) }.to_string_lossy().into_owned();

        if name.eq_ignore_ascii_case("kernel32.dll") {
            return Ok(h_mods[i as usize]);
        }
    }

    Err(unsafe { winapi::um::errhandlingapi::GetLastError() })
}

// This is the main loop for checking if kernel32.dll has been loaded by the target process
fn suspend_and_check_kernel32(process_info: PROCESS_INFORMATION) -> Result<HMODULE, DWORD> {
    println!("Checking if kernel32.dll has been loaded...");

    // Check if kernel32.dll has been loaded by the target process
    // If it hasn't, then the function will return an error code
    let mut kernel32_base_addr = check_if_kernel32_loaded(process_info.hProcess);

    // If an error code is returned, then we need to unsuspend the target process to give
    // it a chance to load kernel32.dll. We then suspend the target process again and
    // check if kernel32.dll has been loaded. We repeat this process until kernel32.dll
    // has been loaded by the target process.
    while kernel32_base_addr.is_err() {
        // Unsuspend the target process
        let resume_result: DWORD = unsafe { ResumeThread(process_info.hThread) };

        if resume_result == DWORD::MAX {
            return Err(unsafe { winapi::um::errhandlingapi::GetLastError() });
        }

        // Sleep for 1 millisecond to give the target process a chance to load kernel32.dll
        std::thread::sleep(std::time::Duration::from_millis(1));
        
        // Suspend the target process again
        let suspend_result: DWORD = unsafe { SuspendThread(process_info.hThread) };

        if suspend_result == DWORD::MAX {
            return Err(unsafe { winapi::um::errhandlingapi::GetLastError() });
        }

        // Check if kernel32.dll has been loaded by the target process
        kernel32_base_addr = check_if_kernel32_loaded(process_info.hProcess);
    }

    println!("    kernel32.dll has been loaded into target process!");
    println!("        Base address: 0x{:x}\n", kernel32_base_addr.unwrap() as usize);
    kernel32_base_addr
}

// This function will calculate the address of the LoadLibraryA function in the target process
// by adding the offset of the LoadLibraryA function in kernel32.dll to the base address of kernel32.dll
fn get_loadlib_addr(kernel32_base_addr: HMODULE, offset: usize) -> Result<*const c_void, DWORD> {
    println!("Calculating address of LoadLibraryA function in target process...");
    let loadlib_addr_ptr = (kernel32_base_addr as usize + offset) as *const c_void;
    println!("    Address of LoadLibraryA function in target process successfully calculated!");
    println!("        Address: 0x{:x}\n", loadlib_addr_ptr as usize);
    Ok(loadlib_addr_ptr)
} 

// This function will create an Event object using CreateEventA and return the handle to the Event object
fn create_event() -> Result<HANDLE, DWORD> {
    println!("Creating Event object in target process...");

    let event_handle: *mut c_void = unsafe { winapi::um::synchapi::CreateEventA(null_mut(), 0, 0, null_mut()) };
    if event_handle.is_null() {
        return Err(unsafe { winapi::um::errhandlingapi::GetLastError() });
    }

    let last_error = unsafe { winapi::um::errhandlingapi::GetLastError() };
    if last_error != 0 {
        return Err(last_error);
    }

    println!("    Event object created successfully!");
    println!("        Event handle: {:?}\n", event_handle);

    Ok(event_handle)
}

// This function will create a file mapping object using CreateFileMappingA, then create a view of the file mapping
// in the current process using MapViewOfFile. It will then write the handle to the Event object into the file mapping.
// It then unmaps the view of the file mapping from the current process and then returns the handle to the file mapping object.
fn create_file_mapping(event_handle: HANDLE, file_mapping_name: &str) -> Result<HANDLE, DWORD> {
    println!("Creating file mapping object in current process...");
    let map_name: CString = std::ffi::CString::new(file_mapping_name).unwrap();
    unsafe {
        // Create a file mapping object
        let file_mapping_handle: *mut c_void = winapi::um::winbase::CreateFileMappingA(
            winapi::um::handleapi::INVALID_HANDLE_VALUE,
            std::ptr::null_mut(),
            PAGE_READWRITE,
            0,
            std::mem::size_of::<HANDLE>() as DWORD,
            map_name.as_ptr(),
        );

        if file_mapping_handle.is_null() {
            return Err(winapi::um::errhandlingapi::GetLastError());
        }

        // Create a view of the file mapping in the current process
        let file_view_ptr: *mut c_void = winapi::um::memoryapi::MapViewOfFile(
            file_mapping_handle,
            winapi::um::memoryapi::FILE_MAP_ALL_ACCESS,
            0,
            0,
            0,
        );

        if file_view_ptr.is_null() {
            return Err(winapi::um::errhandlingapi::GetLastError());
        }

        // Write the event handle into the file mapping
        *(file_view_ptr as *mut HANDLE) = event_handle;
        let last_error = winapi::um::errhandlingapi::GetLastError();
        if last_error != 0 {
            return Err(last_error);
        }
        winapi::um::memoryapi::UnmapViewOfFile(file_view_ptr);
        let last_error = winapi::um::errhandlingapi::GetLastError();
        if last_error != 0 {
            return Err(last_error);
        }

        // Unmap the view of the file mapping as it's no longer needed in this process
        winapi::um::memoryapi::UnmapViewOfFile(file_view_ptr);

        println!("    File mapping object created successfully!");
        println!("        File mapping handle: {:?}", file_mapping_handle);
        println!("        File mapping name: {:?}", file_mapping_name);
        println!("        Size of mapped file: {}\n", std::mem::size_of::<HANDLE>());        

        Ok(file_mapping_handle)
    }
}

// Now we will create a remote thread in the target process using CreateRemoteThread
// This thread will be responsible for loading the DLL into the target process
// using the LoadLibraryA function whose address we obtained above
// The return value is the handle to the newly created thread
fn create_remote_thread(process_info: PROCESS_INFORMATION, load_library: FARPROC, dll_path_ptr: LPVOID) -> Result<HANDLE, DWORD> {
    println!("Creating remote thread in target process...");
    let thread_id = unsafe {
        CreateRemoteThread(
            process_info.hProcess,
            null_mut(),
            0,
            Some(std::mem::transmute(load_library)),
            dll_path_ptr,  
            0,
            null_mut()
        )
    };
    if thread_id.is_null() {
        Err(unsafe { winapi::um::errhandlingapi::GetLastError() })
    } else {
        println!("    Remote thread created successfully!");
        println!("        Thread ID: {:?}\n", thread_id);
        Ok(thread_id)
    }
}

// This function will use WaitForSingleObject to wait for the Event object to be signaled
// It receives a timeout value as an argument which is the amount of time to wait for the Event object to be signaled
fn wait_for_event(event_handle: HANDLE, timeout: DWORD) -> Result<bool, DWORD> {
    println!("Waiting for DLL to signal event...");
    let wait_result = unsafe { winapi::um::synchapi::WaitForSingleObject(event_handle, timeout) };

    match wait_result {
        WAIT_OBJECT_0 => {
            println!("    DLL signaled event!");
            Ok(true)
        },
        WAIT_TIMEOUT => {
            println!("    Timeout while waiting for DLL to signal event.");
            Ok(false)
        },
        _ => Err(unsafe { winapi::um::errhandlingapi::GetLastError() }),
    }
}

// This function is for closing any open handles, deallocating any allocated memory, and terminating the process
fn cleanup(pi: Option<PROCESS_INFORMATION>, dll_path_ptr: Option<LPVOID>, event_handle: Option<HANDLE>, thread_id: Option<DWORD>) {
    println!("Press Enter to proceed with cleanup...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();

    // Free the allocated memory
    if let Some(dll_path_ptr) = dll_path_ptr {
        if let Some(pi) = pi {
            println!("Freeing allocated memory...");
            if !dll_path_ptr.is_null() {
                let success = unsafe { winapi::um::memoryapi::VirtualFreeEx(pi.hProcess, dll_path_ptr, 0, winapi::um::winnt::MEM_RELEASE) };
                if success == 0 {
                    println!("    Failed to free allocated memory!\n");
                } else {
                    println!("    Allocated memory freed successfully!\n");
                }
            }
        }
    }

    // Close the handle to the created thread
    if let Some(thread_id) = thread_id {
        println!("Closing handle to thread...");
        if thread_id != 0 {
            let thread_handle = thread_id as HANDLE;
            if thread_handle != winapi::um::handleapi::INVALID_HANDLE_VALUE {
                let success = unsafe { winapi::um::handleapi::CloseHandle(thread_handle) };
                if success == 0 {
                    println!("    Failed to close handle to thread!\n");
                } else {
                    println!("    Handle to thread closed successfully!\n");
                }
            }
        }
    }

    // Close the event handle
    if let Some(event_handle) = event_handle {
        println!("Closing handle to event...");

        // Check if the event is signaled before closing
        let wait_result = unsafe { winapi::um::synchapi::WaitForSingleObject(event_handle, 0) };

        match wait_result {
            WAIT_OBJECT_0 => {
                println!("    Event is already signaled!");
            },
            WAIT_TIMEOUT => {
                println!("    Event is not signaled yet.");
            },
            _ => println!("    An error occurred while checking the event state."),
        }

        if event_handle != winapi::um::handleapi::INVALID_HANDLE_VALUE {
            let success = unsafe { winapi::um::handleapi::CloseHandle(event_handle) };
            if success == 0 {
                println!("    Failed to close event handle!\n");
            } else {
                println!("    Event handle closed successfully!\n");
            }
        }
    }


    // Terminate the target process and close the handles to the process and its main thread
    if let Some(pi) = pi {
        //println!("Resuming target process...");
        //if pi.hProcess != winapi::um::handleapi::INVALID_HANDLE_VALUE {
        //    let process_status = unsafe { winapi::um::processthreadsapi::GetExitCodeProcess(pi.hProcess, std::ptr::null_mut()) };
            // if process_status == 259 { // PROCESS_STILL_ACTIVE
            //     let success = unsafe { winapi::um::processthreadsapi::ResumeThread(pi.hThread) };
            //     if success == u32::MAX {
            //         println!("    Failed to resume main thread of target process!");
            //         println!("        Error: {}\n", unsafe { winapi::um::errhandlingapi::GetLastError() });
            //     } else {
            //         println!("    Successfully resumed main thread of target process!\n");
            //     }
            // }

            println!("Closing handle to process...");
            let success = unsafe { winapi::um::handleapi::CloseHandle(pi.hProcess) };
            if success == 0 {
                println!("    Failed to close handle to process!\n");
            } else {
                println!("    Handle to process closed successfully!\n");
            }
        //}

        if pi.hThread != winapi::um::handleapi::INVALID_HANDLE_VALUE {
            println!("Closing handle to main thread...");
            let success = unsafe { winapi::um::handleapi::CloseHandle(pi.hThread) };
            if success == 0 {
                println!("    Failed to close handle to main thread!\n");
            } else {
                println!("    Handle to main thread closed successfully!\n");
            }
        }
    }
}

fn main() {
    // First, we will check if the user has provided the correct number of arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} <target_process> <dll_path>", args[0]);
        return;
    }
    
    // Next, we will store the target process and DLL path in variables
    let target_process = &args[1];
    let dll_path = &args[2];

    // Before sending this path to the CreateProcessW function, we will check to make sure the file exists
    if !std::path::Path::new(target_process).exists() {
        println!("The specified target file does not exist!\n");
        return;
    } 

    // We need to also check if the DLL file exists
    if !std::path::Path::new(dll_path).exists() {
        println!("The specified DLL file does not exist!\n");
        return;
    }

    // Next, we will create the process in a suspended state by calling the create_process function
    // This function will return a PROCESS_INFORMATION struct which we will use later
    let pi = match create_process(target_process) {
        Ok(pi) => pi,
        Err(e) => {
            println!("Failed to create process!");
            println!("    Error: {}\n", e);
            return;
        }
    };

    // Next, we will allocate memory in the process by calling the allocate_memory function
    // This function will return a pointer to the allocated memory which we will use later
    let dll_path_ptr = match allocate_memory(pi, dll_path) {
        Ok(ptr) => ptr,
        Err(e) => {
            println!("Failed to allocate memory in process!");
            println!("    Error: {}\n", e);
            cleanup(Some(pi), None, None, None);
            return;
        }
    };

    // Now we will write the DLL's bytes to the allocated memory using WriteProcessMemory
    // This function will return a boolean value indicating whether the DLL was successfully written
    let _success = match write_memory(pi.hProcess, dll_path_ptr, dll_path) {
        Ok(success) => success,
        Err(e) => {
            println!("Failed to write DLL path to allocated memory!");
            println!("    Error: {}\n", e);
            cleanup(Some(pi), Some(dll_path_ptr), None, None);
            return;
        }
    };

    // Next, we need to use LoadLibraryA to load the DLL into the process
    // We will get the address of the LoadLibraryA function by calling get_loadlib_addr
    // This function will get the base address of kernel32.dll that has been loaded into
    // the calling process (this program) and then find the relative offset of LoadLibraryA
    // which is what is returned by the function
    let loadlib_offset: usize = match get_loadlib_offset() {
        Ok(load_library_offset) => load_library_offset,
        Err(e) => {
            println!("Failed to get offset of LoadLibraryA function!");
            println!("    Error: {}\n", e);
            cleanup(Some(pi), Some(dll_path_ptr), None, None);
            return;
        }
    };

    // In order to call the LoadLibraryA function from the kernel32.dll of the target process, 
    // we need to make sure kernel32.dll is loaded into the target process first and then 
    // get its base address, to which we will add the offset of LoadLibraryA
    // We get the base address by calling suspend_and_check_kernel32 
    let kernel32_base_addr: HMODULE = match suspend_and_check_kernel32(pi) {
        Ok(kernel32_base_addr) => kernel32_base_addr,
        Err(e) => {
            println!("Failed to check if kernel32.dll is loaded into the process!");
            println!("    Error: {}\n", e);
            cleanup(Some(pi), Some(dll_path_ptr), None, None);
            return;
        }
    };

    // Now that kernel32.dll is loaded into the target process, we can get the address of LoadLibraryA
    // by adding the base address of kernel32.dll to the offset of LoadLibraryA
    let loadlib_addr: *const c_void = match get_loadlib_addr(kernel32_base_addr, loadlib_offset) {
        Ok(loadlib_addr) => loadlib_addr,
        Err(e) => {
            println!("Failed to calculate address of LoadLibraryA function!");
            println!("    Error: {}\n", e);
            cleanup(Some(pi), Some(dll_path_ptr), None, None);
            return;
        }
    };

    // At this point, we will create an Event object that will be used as a means to communicate between
    // the target process and this program. We will use this Event object to signal when the DLL has been
    // loaded into the process, finished its initialization, and hooking has been completed
    let event_handle: HANDLE = match create_event() {
        Ok(event_handle) => event_handle,
        Err(e) => {
            println!("Failed to create event object!");
            println!("    Error: {}\n", e);
            cleanup(Some(pi), Some(dll_path_ptr), None, None);
            return;
        }
    };

    // We will now create a file mapping object that will be used to share the Event object between
    // this program and the target process. 
    let file_mapping_name: &str = "Local\\__AA__AA__";
    let _file_mapping_handle: HANDLE = match create_file_mapping(event_handle, file_mapping_name) {
        Ok(file_mapping_handle) => file_mapping_handle,
        Err(e) => {
            println!("Failed to create file mapping object!");
            println!("    Error: {}\n", e);
            cleanup(Some(pi), Some(dll_path_ptr), Some(event_handle), None);
            return;
        }
    };

    //--------------------------------------------------------------------------------------------------
    println!("Testing file mapping object...");
    let mut event_handle_from_mapping: HANDLE = 0 as HANDLE;

    unsafe {
        // Open the file mapping
        let c_file_mapping_name = std::ffi::CString::new(file_mapping_name).unwrap();
        let file_mapping_handle = OpenFileMappingA(FILE_MAP_ALL_ACCESS, 0, c_file_mapping_name.as_ptr());

        if file_mapping_handle.is_null() {
            println!("    Failed to open file mapping object!\n");
            //cleanup(Some(pi), Some(dll_path_ptr), Some(event_handle), Some(file_mapping_handle));
            return;
        } else {
            println!("    Successfully opened file mapping object!");}

        // Create a view of the file mapping
        let file_view_ptr = MapViewOfFile(file_mapping_handle, FILE_MAP_ALL_ACCESS, 0, 0, 0);

        if file_view_ptr.is_null() {
            println!("    Failed to map view of file!\n");
            winapi::um::handleapi::CloseHandle(file_mapping_handle);
            //cleanup(Some(pi), Some(dll_path_ptr), Some(event_handle), Some(file_mapping_handle));
            return;
        } else {
            println!("    Successfully mapped view of file!");
        }

        // Read the event handle from the file mapping
        event_handle_from_mapping = *(file_view_ptr as *mut HANDLE);

        // Unmap view of file
        UnmapViewOfFile(file_view_ptr);

        // Close the handle to the file mapping
        winapi::um::handleapi::CloseHandle(file_mapping_handle);
    }

    println!("    The event handle read from the file mapping is: {:?}\n", event_handle_from_mapping);

    //--------------------------------------------------------------------------------------------------

    // Now that kernel32.dll is loaded into the process, we can call LoadLibraryA
    // We will do this by calling create_remote_thread
    let _thread_id = match create_remote_thread(pi, unsafe { std::mem::transmute(loadlib_addr) }, dll_path_ptr) {
        Ok(thread_id) => thread_id,
        Err(e) => {
            println!("Failed to create remote thread!");
            println!("    Error: {}\n", e);
            cleanup(Some(pi), Some(dll_path_ptr), Some(event_handle), None);
            return;
        }
    };

    println!("Press Enter to proceed with program...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();

    // Now we will wait for the event to be signaled by the DLL
    let timeout: DWORD = 10000; 
    let wait_result = match wait_for_event(event_handle, timeout) {
        Ok(wait_result) => wait_result,
        Err(e) => {
            println!("Failed to wait for event!");
            println!("    Error: {}\n", e);
            cleanup(Some(pi), Some(dll_path_ptr), Some(event_handle), Some(_thread_id as u32));
            return;
        }
    };

    // We now check if the event was signaled or if it timed out
    if wait_result {
        println!("DLL successfully loaded into process!\n");

        // We will now close the handle to the event object
        cleanup(None, None, Some(event_handle), None);

        println!("Resuming Target Process Main Thread...\n");

        // We will now resume the main thread of the target process
        let success = unsafe { winapi::um::processthreadsapi::ResumeThread(pi.hThread) };
        if success == u32::MAX {
            println!("    Failed to resume main thread of target process!");
            println!("        Error: {}\n", unsafe { winapi::um::errhandlingapi::GetLastError() });
            cleanup(Some(pi), Some(dll_path_ptr), Some(event_handle), Some(_thread_id as u32));
            return;
        } else {
            println!("    Successfully resumed main thread of target process!\n");
        }
    } else {
        println!("    DLL failed to load into process!\n");

        // We will now close the handle to the event object
        cleanup(Some(pi), Some(dll_path_ptr), Some(event_handle), Some(_thread_id as u32));
    }
}