//extern crate winapi;

use std::ptr::null_mut;
use std::ffi::{OsStr, CString, CStr, OsString};
use std::iter::once;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ptr;
use std::io::{self};

use winapi::um::processthreadsapi::{CreateProcessW, CreateRemoteThread, ResumeThread, SuspendThread, STARTUPINFOW, PROCESS_INFORMATION};
use winapi::um::winbase::CREATE_SUSPENDED;
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory, ReadProcessMemory, VirtualProtectEx};
use winapi::shared::minwindef::{DWORD, HMODULE, FARPROC, LPVOID, FALSE};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::ctypes::c_void;
use winapi::shared::basetsd::SIZE_T;
use winapi::um::winbase::WAIT_OBJECT_0;
use winapi::um::winnt::{LPCSTR, LPSTR, HANDLE, PAGE_READWRITE, DUPLICATE_SAME_ACCESS, PAGE_READONLY};
use winapi::um::psapi::{EnumProcessModulesEx, GetModuleBaseNameA, LIST_MODULES_ALL};
use winapi::um::errhandlingapi::GetLastError;

extern crate simplelog;
extern crate log;

use log::{info, warn, error};
use simplelog::*;
use std::fs::File;
use time::macros::format_description;


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

    info!("[{}] Creating target process in suspended state", "create_process");
    info!("[{}] Process path: {}", "create_process", target_process);

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
        error!("[{}] Failed to create target process", "create_process");
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "create_process", win_err);
        }
        Err(unsafe { winapi::um::errhandlingapi::GetLastError() })
    } else {
        info!("[{}] Successfully created target process in suspended state", "create_process");
        info!("[{}] Handle to target process: {:?}", "create_process", pi.hProcess);
        info!("[{}] Handle to target thread: {:?}", "create_process", pi.hThread);
        info!("[{}] Target process ID: {}", "create_process", pi.dwProcessId);
        info!("[{}] Target process main thread ID: {}", "create_process", pi.dwThreadId);

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
    info!("[{}] Converting {} to CString", "allocate_memory", dll_path);
    let dll_path_c = CString::new(dll_path).unwrap();
    info!("[{}] Converted DLL path: {:?}", "allocate_memory", dll_path_c);

    let dll_path_ptr = unsafe {
        info!("[{}] Allocating memory in target process", "allocate_memory");
        info!("[{}] Target process handle: {:?}", "allocate_memory", pi.hProcess);
        VirtualAllocEx(
            pi.hProcess,
            null_mut(),
            dll_path_c.as_bytes_with_nul().len(),  // Allocate enough space for the DLL path
            winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE,
            winapi::um::winnt::PAGE_READWRITE,
        )
    };

    if dll_path_ptr.is_null() {
        error!("[{}] Failed to allocate memory in target process", "allocate_memory");
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "allocate_memory", win_err);
        }
        Err(unsafe { winapi::um::errhandlingapi::GetLastError() })
    } else {
        info!("[{}] Successfully allocated memory into target process", "allocate_memory");
        info!("[{}] Base address of allocated memory: {:?}", "allocate_memory", dll_path_ptr);
        info!("[{}] Size of allocated memory: {} bytes", "allocate_memory", dll_path_c.as_bytes_with_nul().len());
        Ok(dll_path_ptr)
    }
}

// This function will write the DLL path to the memory allocated in the target process
// It will accept the process handle, the base address of the allocated memory, and the DLL path
// It will return a boolean value indicating whether the DLL path was successfully written
fn write_memory(process_handle: HANDLE, dll_path_ptr: *mut c_void, dll_path: &str) -> Result<bool, DWORD> {
    info!("[{}] Converting {} to CString", "write_memory", dll_path);
    let dll_path_c = CString::new(dll_path).unwrap();
    info!("[{}] Converted DLL path: {:?}", "write_memory", dll_path_c);

    let mut bytes_written: usize = 0;

    let success = unsafe {
        info!("[{}] Writing DLL path to allocated memory", "write_memory");
        info!("[{}] Handle to target process: {:?}", "write_memory", process_handle);
        info!("[{}] Base address of allocated memory: {:?}", "write_memory", dll_path_ptr);
        WriteProcessMemory(
            process_handle,
            dll_path_ptr,
            dll_path_c.as_ptr() as *mut c_void,
            dll_path_c.as_bytes_with_nul().len(),
            &mut bytes_written,
        )
    };

    if success == 0 {
        error!("[{}] Failed to write {:?} to allocated memory!", "write_memory", dll_path_c);
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "write_memory", win_err);
        }
        return Err(unsafe { winapi::um::errhandlingapi::GetLastError() })
    } else {
        info!("[{}] Successfully wrote {:?} to allocated memory!", "write_memory", dll_path_c);
        info!("[{}] Bytes written: {}", "write_memory", bytes_written);
    }

    // Now that the DLL path has been written to the allocated memory, we can change the memory protection back to read-only
    let mut old_protect: DWORD = 0;
    let success_protect = unsafe {
        VirtualProtectEx(
            process_handle,
            dll_path_ptr,
            dll_path_c.as_bytes_with_nul().len(),
            PAGE_READONLY,
            &mut old_protect
        )
    };

    if success_protect == 0 {
        error!("[{}] Failed to change memory protection back to read-only", "write_memory");
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "write_memory", win_err);
        }
        Err(unsafe { winapi::um::errhandlingapi::GetLastError() })
    } else {
        info!("[{}] Successfully changed memory protection back to read-only", "write_memory");
        Ok(true)
    }
}

// This function is used to validate that the DLL path was successfully written to the allocated memory
fn read_memory(process_handle: HANDLE, address: LPVOID, size: usize) -> Result<String, DWORD> {
    let mut buffer: Vec<u8> = vec![0; size];
    let mut bytes_read: SIZE_T = 0;

    info!("[{}] Calling ReadProcessMemory", "read_memory");
    info!("[{}] Handle to target process: {:?}", "read_memory", process_handle);
    info!("[{}] Address to read from: {:?}", "read_memory", address);
    info!("[{}] Size of buffer: {} bytes", "read_memory", buffer.len());

    let success = unsafe {
        ReadProcessMemory(
            process_handle,
            address,
            buffer.as_mut_ptr() as _,
            buffer.len(),
            &mut bytes_read
        )
    };

    if success == 0 {
        // If the function fails, the return value is 0 (FALSE).
        error!("[{}] Failed to read memory", "read_memory");
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "read_memory", win_err);
        }
        return Err(unsafe { GetLastError() });
    } else {
        info!("[{}] Successfully read memory", "read_memory");
    }

    // Resize buffer to actual bytes read
    buffer.resize(bytes_read, 0);

    // Convert buffer to a string
    info!("[{}] Converting read back data to string", "read_memory");
    let read_back_data = match String::from_utf8(buffer) {
        Ok(data) => {
            info!("[{}] Successfully converted read back data to string", "read_memory");
            info!("[{}] Contents of read back data: {}", "read_memory", data);
            data
        },
        Err(e) => {
            error!("[{}] Failed to convert read back data to string: {}", "read_memory", e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "read_memory", win_err);
            }
            return Err(unsafe { GetLastError() });
        }
    };

    Ok(read_back_data)
}

// This function will get the base address of the kernel32.dll module which has been 
// loaded by the calling process (this program) and use the GetProcAddress function
// to get the address (relative to the base address) of the LoadLibraryA function
// The function then subtracts the base address from the LoadLibraryA address to get the offset
fn get_loadlib_offset() -> Result<usize, DWORD> {
    info!("[{}] Converting 'kernel32.dll' name to CString", "get_loadlib_offset");
    let module_str = CString::new("kernel32.dll").unwrap();
    info!("[{}] Converted target module name: {:?}", "get_loadlib_offset", module_str);

    info!("[{}] Converting 'LoadLibraryA' function name to CString", "get_loadlib_offset");
    let loadlib_str = CString::new("LoadLibraryA").unwrap();
    info!("[{}] Converted target function name: {:?}", "get_loadlib_offset", loadlib_str);

    let loadlib_offset: usize;

    unsafe {
        // First we need to get the kernel32.dll module handle
        info!("[{}] Retrieving handle to {:?} module", "get_loadlib_offset", module_str);
        let kernel32_handle = GetModuleHandleA(module_str.as_ptr());

        if kernel32_handle.is_null() {
            error!("[{}] Failed to get {:?} module handle", "get_loadlib_offset", module_str);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "get_loadlib_offset", win_err);
            }
            return Err(winapi::um::errhandlingapi::GetLastError());
        } else {
            info!("[{}] Successfully retrieved handle to {:?} module", "get_loadlib_offset", module_str);
            info!("[{}] {:?} module handle: {:p}", "get_loadlib_offset", module_str, kernel32_handle);
        }

        // Next we need to get the relative address of the LoadLibraryA function
        // We can do this by calling the GetProcAddress function
        info!("[{}] Retrieving address of {:?} function", "get_loadlib_offset", loadlib_str);
        let loadlib_ptr = GetProcAddress(kernel32_handle, loadlib_str.as_ptr());

        if loadlib_ptr.is_null() {
            error!("[{}] Failed to get address of {:?} function", "get_loadlib_offset", loadlib_str);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "get_loadlib_offset", win_err);
            }
            return Err(winapi::um::errhandlingapi::GetLastError());
        } else {
            info!("[{}] Successfully retrieved address of {:?} function", "get_loadlib_offset", loadlib_str);
            info!("[{}] {:?} function address: {:p}", "get_loadlib_offset", loadlib_str, loadlib_ptr);
        }

        // Calculate the offset of LoadLibraryA in kernel32.dll
        loadlib_offset = loadlib_ptr as usize - kernel32_handle as usize;
    }
    info!("[{}] Calculated offset of {:?} function in {:?} module: 0x{:X}", "get_loadlib_offset", loadlib_str, module_str, loadlib_offset);

    Ok(loadlib_offset)
}

// This function will create a loop suspending and unsuspending the target process until all static libraries have been loaded
// We will unsuspend the target process for 5 milliseconds and then suspend it again. We will then enumerate all modules in the target process
// by calling check_number_of_modules which returns the number of modules currently loaded into the target process
// If the count exceeds the module_threshold we will break out of the loop and return
fn target_load_static_modules(process_info: PROCESS_INFORMATION, module_threshold: u32, delta: u32) -> Result<(), DWORD> {
    info!("[{}] Allowing target process to load static libraries", "target_load_static_modules");
    info!("[{}] Target process handle: {:?}", "target_load_static_modules", process_info.hProcess);

    loop {
        info!("[{}] Unsuspending target process", "target_load_static_modules");
        let resume_result: DWORD = unsafe { ResumeThread(process_info.hThread) };

        if resume_result == DWORD::MAX {
            error!("[{}] Failed to unsuspend target process", "target_load_static_modules");
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "target_load_static_modules", win_err);
            }
            return Err(unsafe { winapi::um::errhandlingapi::GetLastError() });
        } else {
            info!("[{}] Target process successfully unsuspended", "target_load_static_modules");
        }

        info!("[{}] Target process sleeping for 100 microseconds", "target_load_static_modules");
        std::thread::sleep(std::time::Duration::from_micros(delta as u64));
        
        info!("[{}] Suspending target process", "target_load_static_modules");
        let suspend_result: DWORD = unsafe { SuspendThread(process_info.hThread) };

        if suspend_result == DWORD::MAX {
            error!("[{}] Failed to suspend target process", "target_load_static_modules");
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "target_load_static_modules", win_err);
            }
            return Err(unsafe { winapi::um::errhandlingapi::GetLastError() });
        }

        info!("[{}] Checking number of modules loaded by target process", "target_load_static_modules");
        let module_count = check_number_of_modules(process_info.hProcess);

        match module_count {
            Ok(count) => {
                // If the number of modules loaded by the target process exceeds the module_threshold we will break out of the loop
                if count >= module_threshold {
                    break;
                }
            }
            Err(e) => {
                error!("[{}] Failed to retrieve number of modules loaded by target process", "target_load_static_modules");
                return Err(e);
            }
        }
    }

    info!("[{}] All static libraries loaded by the target process", "target_load_static_modules");

    Ok(())
}

// This function will check the number of modules loaded by the target process by calling EnumProcessModulesEx
fn check_number_of_modules(process_handle: HANDLE) -> Result<u32, DWORD> {
    let mut cb_needed: DWORD = 0;

    info!("[{}] Calculating number of modules loaded by target process", "check_number_of_modules");
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
        error!("[{}] Failed to calculate number of modules loaded by target process", "check_number_of_modules");
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "check_number_of_modules", win_err);
        }
        return Err(unsafe { winapi::um::errhandlingapi::GetLastError() });
    } else {
        info!("[{}] Successfully calculated number of modules loaded by target process", "check_number_of_modules");
    }

    let module_count = cb_needed / std::mem::size_of::<HMODULE>() as u32;
    info!("[{}] Number of modules loaded by target process: {}", "check_number_of_modules", module_count);

    Ok(module_count)
}

// This function retrieves the base address of a module loaded into a process specified by the process handle
fn get_module_base_address(process_handle: HANDLE, module_name: &str) -> Result<HMODULE, DWORD> {
    let mut cb_needed: DWORD = 0;

    info!("[{}] Getting module base address for: {}", "get_module_base_address", module_name);
    info!("[{}] Process handle: {:?}", "get_module_base_address", process_handle);

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
        error!("[{}] Failed to get module count", "get_module_base_address");
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "get_module_base_address", win_err);
        }
        return Err(unsafe { winapi::um::errhandlingapi::GetLastError() });
    }

    let module_count = cb_needed / std::mem::size_of::<HMODULE>() as DWORD;
    let mut h_mods: Vec<HMODULE> = vec![std::ptr::null_mut(); module_count as usize];

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
        error!("[{}] Failed to get module handles", "get_module_base_address");
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "get_module_base_address", win_err);
        }
        return Err(unsafe { winapi::um::errhandlingapi::GetLastError() });
    }

    let mut module_name_c = vec![0u8; 256];

    for i in 0..module_count {
        let result = unsafe {
            GetModuleBaseNameA(
                process_handle,
                h_mods[i as usize],
                module_name_c.as_mut_ptr() as LPSTR,
                256 as DWORD,
            )
        };

        if result == 0 {
            error!("[{}] Failed to get module name", "get_module_base_address");
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "get_module_base_address", win_err);
            }
            return Err(unsafe { winapi::um::errhandlingapi::GetLastError() });
        }

        let current_module_name = unsafe { CStr::from_ptr(module_name_c.as_ptr() as LPCSTR) }.to_string_lossy().into_owned();

        if current_module_name.eq_ignore_ascii_case(module_name) {
            info!("[{}] {} base address: {:?} found", "get_module_base_address", module_name, h_mods[i as usize]);
            return Ok(h_mods[i as usize]);
        }
    }
    error!("[{}] Module base address: {:?} not found", "get_module_base_address", module_name);
    Err(unsafe { winapi::um::errhandlingapi::GetLastError() })
}

// This function will calculate the address of the LoadLibraryA function in the target process
// by adding the offset of the LoadLibraryA function in kernel32.dll to the base address of kernel32.dll
fn get_loadlib_addr(kernel32_base_addr: HMODULE, offset: usize) -> Result<*const c_void, DWORD> {
    info!("[{}] Calculating address of LoadLibraryA function in target process", "get_loadlib_addr");
    let loadlib_addr_ptr = (kernel32_base_addr as usize + offset) as *const c_void;
    info!("[{}] Address of LoadLibraryA function in target process: 0x{:x}", "get_loadlib_addr", loadlib_addr_ptr as usize);

    Ok(loadlib_addr_ptr)
} 

// This function will create an Event object using CreateEventA and return the handle to the Event object
fn create_event() -> Result<HANDLE, DWORD> {
    info!("[{}] Creating Event object", "create_event");

    let event_handle: *mut c_void = unsafe { winapi::um::synchapi::CreateEventA(null_mut(), 0, 0, null_mut()) };
    if event_handle.is_null() {
        error!("[{}] Failed to create Event object", "create_event");
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "create_event", win_err);
        }
        return Err(unsafe { winapi::um::errhandlingapi::GetLastError() });
    } else {
        info!("[{}] Event object created successfully", "create_event");
        info!("[{}] Event handle: {:?}", "create_event", event_handle);
    }

    Ok(event_handle)
}

// This function will create a file mapping object using CreateFileMappingA, then create a view of the file mapping
// in the current process using MapViewOfFile. It will then write the handle to the Event object into the file mapping.
// It then unmaps the view of the file mapping from the current process and then returns the handle to the file mapping object.
fn create_file_mapping(event_handle: HANDLE, file_mapping_name: &str, source_process_handle: HANDLE, target_process_handle: HANDLE) -> Result<HANDLE, DWORD> {
    info!("[{}] Converting file mapping name to CString", "create_file_mapping");
    let map_name: CString = match std::ffi::CString::new(file_mapping_name) {
        Ok(map_name) => {
            info!("[{}] Successfully converted file mapping name: {:?} to CString", "create_file_mapping", map_name);
            map_name
        },
        Err(_) => {
            error!("[{}] Failed to convert file mapping name: {:?} to CString", "create_file_mapping", file_mapping_name);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "create_file_mapping", win_err);
            }
            return Err(unsafe { winapi::um::errhandlingapi::GetLastError() });
        }
    };

    // Duplicate the handle to the Event object so that it can be used in the target process
    let mut duplicated_handle: HANDLE = std::ptr::null_mut();

    unsafe {
        info!("[{}] Duplicating event handle", "create_file_mapping");
        info!("[{}] Source process handle: {:?}", "create_file_mapping", source_process_handle);
        info!("[{}] Event handle: {:?}", "create_file_mapping", event_handle);
        info!("[{}] Target process handle: {:?}", "create_file_mapping", target_process_handle);

        let duplication_success = winapi::um::handleapi::DuplicateHandle(
            source_process_handle,
            event_handle,
            target_process_handle,
            &mut duplicated_handle,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS,
        );

        if duplication_success == 0 {
            error!("[{}] Failed to duplicate event handle: {:?}", "create_file_mapping", event_handle);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "create_file_mapping", win_err);
            }
            return Err(winapi::um::errhandlingapi::GetLastError());
        } else {
            info!("[{}] Successfully duplicated event handle: {:?}", "create_file_mapping", event_handle);
            info!("[{}] Duplicated event handle: {:?}", "create_file_mapping", duplicated_handle);
        }

        // Create a file mapping object
        info!("[{}] Creating file mapping object", "create_file_mapping");

        let file_mapping_handle: *mut c_void = winapi::um::winbase::CreateFileMappingA(
            winapi::um::handleapi::INVALID_HANDLE_VALUE,
            std::ptr::null_mut(),
            PAGE_READWRITE,
            0,
            std::mem::size_of::<HANDLE>() as DWORD,
            map_name.as_ptr(),
        );

        if file_mapping_handle.is_null() {
            error!("[{}] Failed to create file mapping object", "create_file_mapping");
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "create_file_mapping", win_err);
            }
            return Err(winapi::um::errhandlingapi::GetLastError());
        } else {
            info!("[{}] Successfully created file mapping object", "create_file_mapping");
            info!("[{}] File mapping handle: {:?}", "create_file_mapping", file_mapping_handle);
        }

        // Create a view of the file mapping in the current process
        info!("[{}] Creating view of file mapping in current process", "create_file_mapping");

        let file_view_ptr: *mut c_void = winapi::um::memoryapi::MapViewOfFile(
            file_mapping_handle,
            winapi::um::memoryapi::FILE_MAP_ALL_ACCESS,
            0,
            0,
            0,
        );

        if file_view_ptr.is_null() {
            error!("[{}] Failed to create view of file mapping in current process", "create_file_mapping");
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "create_file_mapping", win_err);
            }
            return Err(winapi::um::errhandlingapi::GetLastError());
        } else {
            info!("[{}] Successfully created view of file mapping in current process", "create_file_mapping");
            info!("[{}] File view pointer: {:?}", "create_file_mapping", file_view_ptr);
        }

        // Write the duplicated event handle into the file mapping
        info!("[{}] Writing duplicated event handle into file mapping", "create_file_mapping");
        info!("[{}] Before writing, file view pointer: {:?}", "create_file_mapping", *(file_view_ptr as *mut HANDLE));

        *(file_view_ptr as *mut HANDLE) = duplicated_handle;
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "create_file_mapping", win_err);
            return Err(winapi::um::errhandlingapi::GetLastError());
        } else {
            info!("[{}] Successfully wrote duplicated event handle into file mapping", "create_file_mapping");
            info!("[{}] After writing, file view pointer: {:?}", "create_file_mapping", *(file_view_ptr as *mut HANDLE));
        }

        // Unmap the view of the file mapping as it's no longer needed in this process
        info!("[{}] Unmapping view of file mapping in current process", "create_file_mapping");

        let result = winapi::um::memoryapi::UnmapViewOfFile(file_view_ptr);
        if result == 0 {
            error!("[{}] Failed to unmap view of file mapping in current process", "create_file_mapping");
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "create_file_mapping", win_err);
            }
            return Err(winapi::um::errhandlingapi::GetLastError());
        } else {
            info!("[{}] Successfully unmapped view of file mapping in current process", "create_file_mapping");
        }
       
        Ok(file_mapping_handle)
    }
}


// Now we will create a remote thread in the target process using CreateRemoteThread
// This thread will be responsible for loading the DLL into the target process
// using the LoadLibraryA function whose address we obtained above
// The return value is the handle to the newly created thread
fn create_remote_thread(process_info: PROCESS_INFORMATION, load_library: FARPROC, dll_path_ptr: LPVOID) -> Result<HANDLE, DWORD> {
    info!("[{}] Creating remote thread in target process", "create_remote_thread");
    info!("[{}] Target process handle: {:?}", "create_remote_thread", process_info.hProcess);
    info!("[{}] Pointer to LoadLibraryA: {:?}", "create_remote_thread", load_library);
    info!("[{}] Pointer to DLL path: {:?}", "create_remote_thread", dll_path_ptr);

    let remote_thread_handle = unsafe {
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
    if remote_thread_handle.is_null() {
        error!("[{}] Remote thread handle is null", "create_remote_thread");
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "create_remote_thread", win_err);
        }
        return Err(unsafe { winapi::um::errhandlingapi::GetLastError() });
    } else {
        info!("[{}] Remote thread create successfully", "create_remote_thread");
        info!("[{}] Handle to remote thread: {:?}", "create_remote_thread", remote_thread_handle);
        return Ok(remote_thread_handle);
    }
}

// This function will use WaitForSingleObject to wait for the Event object to be signaled
// It receives a timeout value as an argument which is the amount of time to wait for the Event object to be signaled
fn wait_for_event(event_handle: HANDLE, timeout: DWORD, mut attempts: usize) -> Result<bool, DWORD> {
    info!("[{}] Waiting for DLL to signal event", "wait_for_event");
    info!("[{}] Event Handle: {:?}", "wait_for_event", event_handle);
    info!("[{}] Timeout: {}ms", "wait_for_event", timeout);
    info!("[{}] Max Attempts: {}", "wait_for_event", attempts);

    let max_attempts: usize = attempts;

    while attempts > 0 {
        let wait_result = unsafe { winapi::um::synchapi::WaitForSingleObject(event_handle, timeout) };
        match wait_result {
            WAIT_OBJECT_0 => {
                info!("[{}] DLL signaled event - Attempt: {}", "wait_for_event", max_attempts-attempts);
                return Ok(true)
            },
            WAIT_TIMEOUT => {
                attempts -= 1;
            },
            _ => {
                error!("[{}] Call to WaitForSingleObject failed - Attempt: {}", "wait_for_event", max_attempts-attempts);
                if let Some(win_err) = get_last_error() {
                    error!("[{}] Windows error: {}", "wait_for_event", win_err);
                }
                return Err(unsafe { winapi::um::errhandlingapi::GetLastError() });
            },
        }
    }
    warn!("[{}] Max attempts reached: {}", "wait_for_event", "Timed out");
    return Ok(false)
}

fn cleanup(
    pi: Option<PROCESS_INFORMATION>, 
    dll_path_ptr: Option<LPVOID>, 
    event_handle: Option<HANDLE>, 
    remote_thread_handle: Option<HANDLE>,
    file_mapping_handle: Option<HANDLE>,
    current_process_handle: Option<HANDLE>,
) {

    // Resume the target process and close the handles to the process and its main thread
    if let Some(pi) = pi {
        info!("[{}] Resuming target process", "cleanup");
    
        // Log some information about the PROCESS_INFORMATION struct
        info!("[{}] Target process handle: {:?}", "cleanup", pi.hProcess);
        info!("[{}] Target process main thread handle: {:?}", "cleanup", pi.hThread);
        info!("[{}] Target process ID: {:?}", "cleanup", pi.dwProcessId);
        info!("[{}] Target process main thread ID: {:?}", "cleanup", pi.dwThreadId);
    
        if pi.hProcess != winapi::um::handleapi::INVALID_HANDLE_VALUE {
            let mut suspend_count;
            loop {
                let result = unsafe { winapi::um::processthreadsapi::ResumeThread(pi.hThread) };
                if result == u32::MAX {
                    error!("[{}] Failed to resume main thread of target process", "cleanup");
                    if let Some(win_err) = get_last_error() {
                        error!("[{}] Windows error: {}", "cleanup", win_err);
                    }
                    break;
                } else {
                    suspend_count = result;
                    if suspend_count == 0 {
                        info!("[{}] Successfully resumed main thread of target process", "cleanup");
                        break;
                    }
                }
            }
        } else {
            warn!("[{}] Target process handle is invalid", "cleanup");
        }
    }
    

    // Free the allocated memory
    if let Some(dll_path_ptr) = dll_path_ptr {
        if let Some(pi) = pi {
            info!("[{}] Freeing allocated memory at address: {:?}", "cleanup", dll_path_ptr);
            if !dll_path_ptr.is_null() {
                let success = unsafe { winapi::um::memoryapi::VirtualFreeEx(pi.hProcess, dll_path_ptr, 0, winapi::um::winnt::MEM_RELEASE) };
                if success == 0 {
                    error!("[{}] Failed to free allocated memory at address: {:?}", "cleanup", dll_path_ptr);
                    if let Some(win_err) = get_last_error() {
                        error!("[{}] Windows error: {}", "cleanup", win_err);
                    }
                } else {
                    info!("[{}] Allocated memory at address: {:?} freed successfully", "cleanup", dll_path_ptr);
                }
            } else {
                warn!("[{}] DLL path pointer is null", "cleanup");
            }
        }
    }
    

    // Close the handle to the created thread
    if let Some(remote_thread_handle) = remote_thread_handle {
        info!("[{}] Closing handle to thread: {:?}", "cleanup", remote_thread_handle);
        if remote_thread_handle != winapi::um::handleapi::INVALID_HANDLE_VALUE {
            // Wait for the thread to finish execution
            info!("[{}] Waiting for thread: {:?} to finish execution", "cleanup", remote_thread_handle);
            let wait_result = unsafe { winapi::um::synchapi::WaitForSingleObject(remote_thread_handle, 0xFFFFFFFF) };
            match wait_result {
                WAIT_OBJECT_0 => info!("[{}] Thread with handle: {:?} has finished execution", "cleanup", remote_thread_handle),
                WAIT_TIMEOUT => warn!("[{}] Timed out waiting for thread with handle: {:?} to finish execution", "cleanup", remote_thread_handle),
                _ => {
                    error!("[{}] An error occurred while waiting for thread with handle: {:?} to finish execution", "cleanup", remote_thread_handle);
                    if let Some(win_err) = get_last_error() {
                        error!("[{}] Windows error: {}", "cleanup", win_err);
                    }
                },
            }
    
            let success = unsafe { winapi::um::handleapi::CloseHandle(remote_thread_handle) };
            if success == 0 {
                error!("[{}] Failed to close handle to thread: {:?}", "cleanup", remote_thread_handle);
                if let Some(win_err) = get_last_error() {
                    error!("[{}] Windows error: {}", "cleanup", win_err);
                }
            } else {
                info!("[{}] Handle to thread: {:?} closed successfully", "cleanup", remote_thread_handle);
            }
        } else {
            warn!("[{}] Thread handle: {:?} is invalid", "cleanup", remote_thread_handle);
        }
    }
    

    // Close the event handle
    if let Some(event_handle) = event_handle {
        info!("[{}] Closing event handle: {:?}", "cleanup", event_handle);

        // Check if the event is signaled before closing
        info!("[{}] Checking if event: {:?} is signaled before closing", "cleanup", event_handle);
        let wait_result = unsafe { winapi::um::synchapi::WaitForSingleObject(event_handle, 0) };

        match wait_result {
            WAIT_OBJECT_0 => {
                info!("[{}] Event: {:?} is signaled", "cleanup", event_handle)
            },
            WAIT_TIMEOUT => {
                warn!("[{}] Event: {:?} is not signaled yet", "cleanup", event_handle)
            },
            _ => {
                error!("[{}] An error occurred while checking event: {:?}", "cleanup", event_handle);
                if let Some(win_err) = get_last_error() {
                    error!("[{}] Windows error: {}", "cleanup", win_err);
                }
            }
        }

        if event_handle != winapi::um::handleapi::INVALID_HANDLE_VALUE {
            let success = unsafe { winapi::um::handleapi::CloseHandle(event_handle) };
            if success == 0 {
                error!("[{}] Failed to close event handle: {:?}", "cleanup", event_handle);
                if let Some(win_err) = get_last_error() {
                    error!("[{}] Windows error: {}", "cleanup", win_err);
                }
            } else {
                info!("[{}] Event handle: {:?} closed successfully", "cleanup", event_handle);
            }
        } else {
            warn!("[{}] Event handle: {:?} is invalid", "cleanup", event_handle);
        }
    }

    // Close the handle to the file mapping object
    if let Some(file_mapping_handle) = file_mapping_handle {
        info!("[{}] Closing file mapping object handle: {:?}", "cleanup", file_mapping_handle);
        if file_mapping_handle != winapi::um::handleapi::INVALID_HANDLE_VALUE {
            let success = unsafe { winapi::um::handleapi::CloseHandle(file_mapping_handle) };
            if success == 0 {
                error!("[{}] Failed to close file mapping object handle: {:?}", "cleanup", file_mapping_handle);
                if let Some(win_err) = get_last_error() {
                    error!("[{}] Windows error: {}", "cleanup", win_err);
                }
            } else {
                info!("[{}] File mapping object handle: {:?} closed successfully", "cleanup", file_mapping_handle);
            }
        } else {
            warn!("[{}] File mapping object handle: {:?} is invalid", "cleanup", file_mapping_handle);
        }
    }

    // Close the handle to the current process
    if let Some(current_process_handle) = current_process_handle {
        info!("[{}] Closing current process handle: {:?}", "cleanup", current_process_handle);
        if current_process_handle != winapi::um::handleapi::INVALID_HANDLE_VALUE {
            let success = unsafe { winapi::um::handleapi::CloseHandle(current_process_handle) };
            if success == 0 {
                error!("[{}] Failed to close current process handle: {:?}", "cleanup", current_process_handle);
                if let Some(win_err) = get_last_error() {
                    error!("[{}] Windows error: {}", "cleanup", win_err);
                }
            } else {
                info!("[{}] Current process handle: {:?} closed successfully", "cleanup", current_process_handle);
            }
        } else {
            warn!("[{}] Current process handle: {:?} is invalid", "cleanup", current_process_handle);
        }
    }

    // Close the handle to the target process
    if let Some(pi) = pi {
        info!("[{}] Closing target process handle: {:?}", "cleanup", pi.hProcess);
        if pi.hProcess != winapi::um::handleapi::INVALID_HANDLE_VALUE {
            let success = unsafe { winapi::um::handleapi::CloseHandle(pi.hProcess) };
            if success == 0 {
                error!("[{}] Failed to close target process handle: {:?}", "cleanup", pi.hProcess);
                if let Some(win_err) = get_last_error() {
                    error!("[{}] Windows error: {}", "cleanup", win_err);
                }
            } else {
                info!("[{}] Target process handle: {:?} closed successfully", "cleanup", pi.hProcess);
            }
        } else {
            warn!("[{}] Target process handle: {:?} is invalid", "cleanup", pi.hProcess);
        }
    }

    // Close the handle to the main thread of the target process
    if let Some(pi) = pi {
        info!("[{}] Closing target process main thread handle: {:?}", "cleanup", pi.hThread);
        if pi.hThread != winapi::um::handleapi::INVALID_HANDLE_VALUE {
            let success = unsafe { winapi::um::handleapi::CloseHandle(pi.hThread) };
            if success == 0 {
                error!("[{}] Failed to close target process main thread handle: {:?}", "cleanup", pi.hThread);
                if let Some(win_err) = get_last_error() {
                    error!("[{}] Windows error: {}", "cleanup", win_err);
                }
            } else {
                info!("[{}] Target process main thread handle: {:?} closed successfully", "cleanup", pi.hThread);
            }
        } else {
            warn!("[{}] Target process main thread handle: {:?} is invalid", "cleanup", pi.hThread);
        }
    }
}

fn get_last_error() -> Option<String> {
    let error_code = unsafe { GetLastError() };

    if error_code == 0 {
        None
    } else {
        let mut buffer: Vec<u16> = Vec::with_capacity(256);
        buffer.resize(buffer.capacity(), 0);
        let len = unsafe {
            winapi::um::winbase::FormatMessageW(
                winapi::um::winbase::FORMAT_MESSAGE_FROM_SYSTEM
                    | winapi::um::winbase::FORMAT_MESSAGE_IGNORE_INSERTS,
                ptr::null(),
                error_code,
                0,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                ptr::null_mut(),
            )
        };
        buffer.resize(len as usize, 0);
        Some(OsString::from_wide(&buffer).to_string_lossy().into_owned())
    }
}

fn main() {
    // Initialize the logger
    let config = ConfigBuilder::new()
        .set_time_format_custom(format_description!("[hour]:[minute]:[second].[subsecond]"))
        .build();

    let _ = WriteLogger::init(LevelFilter::Info, config, File::create("injector.log").expect("Failed to initialize logger"));

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
        error!("[{}] The specified target process file does not exist: {}", "main", target_process);
        return;
    } 

    // We need to also check if the DLL file exists
    if !std::path::Path::new(dll_path).exists() {
        error!("[{}] The specified dll file does not exist: {}", "main", dll_path);
        return;
    }

    // Next, we will create the process in a suspended state by calling the create_process function
    // This function will return a PROCESS_INFORMATION struct which we will use later
    let pi = match create_process(target_process) {
        Ok(pi) => pi,
        Err(e) => {
            error!("[{}] Failed to create process: {}", "main", e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "main", win_err);
            }
            return;
        }
    };

    // Next, we will allocate memory in the process by calling the allocate_memory function
    // This function will return a pointer to the allocated memory which we will use later
    let dll_path_ptr = match allocate_memory(pi, dll_path) {
        Ok(ptr) => ptr,
        Err(e) => {
            error!("[{}] Failed to allocate memory in process: {}", "main", e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "main", win_err);
            }
            cleanup(Some(pi), None, None, None, None, None);
            return;
        }
    };

    // We will check if the pointer to the allocated memory is null
    info!("[{}] Checking if the pointer to the allocated memory is null", "main");
    if dll_path_ptr.is_null() {
        error!("[{}] The pointer to DLL path is null after allocation", "main");
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "main", win_err);
        }
        cleanup(Some(pi), None, None, None, None, None);
        return;
    } else {
        info!("[{}] The pointer to DLL path is not null after allocation", "main");
    }

    // Now we will write the DLL's bytes to the allocated memory using WriteProcessMemory
    // This function will return a boolean value indicating whether the DLL was successfully written
    let _success = match write_memory(pi.hProcess, dll_path_ptr, dll_path) {
        Ok(success) => success,
        Err(e) => {
            error!("[{}] Failed to write DLL path to allocated memory: {}", "main", e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "main", win_err);
            }
            cleanup(Some(pi), Some(dll_path_ptr), None, None, None, None);
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
            error!("[{}] Failed to get offset of LoadLibraryA function: {}", "main", e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "main", win_err);
            }
            cleanup(Some(pi), Some(dll_path_ptr), None, None, None, None);
            return;
        }
    };

    // We will allow the remaining time needed for the target process to finish loading all static modules
    // before we attempt to inject our DLL into the process
    let module_threshold = 30; // This is the number of modules that we will wait for before we inject our DLL
    let delta = 1; // This is the number of microseconds that we will wait between each check
    let _result = match target_load_static_modules(pi, module_threshold, delta) {
        Ok(result) => result,
        Err(e) => {
            error!("[{}] Failed to wait for target process to finish loading static modules: {}", "main", e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "main", win_err);
            }
            cleanup(Some(pi), Some(dll_path_ptr), None, None, None, None);
            return;
        }
    };

    // We will get the base address of kernel32.dll by calling get_module_base_address
    // This function will return the base address of kernel32.dll in the target process
    let target_module_name = "kernel32.dll";
    let target_mod_base_addr: HMODULE = match get_module_base_address(pi.hProcess, target_module_name) {
        Ok(target_mod_base_addr) => target_mod_base_addr,
        Err(e) => {
            error!("[{}] Failed to get base address of {}: {}", "main", target_module_name, e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "main", win_err);
            }
            cleanup(Some(pi), Some(dll_path_ptr), None, None, None, None);
            return;
        }
    };

    // Now that kernel32.dll is loaded into the target process, we can get the address of LoadLibraryA
    // by adding the base address of kernel32.dll to the offset of LoadLibraryA
    let loadlib_addr: *const c_void = match get_loadlib_addr(target_mod_base_addr, loadlib_offset) {
        Ok(loadlib_addr) => loadlib_addr,
        Err(e) => {
            error!("[{}] Failed to calculate address of LoadLibraryA function: {}", "main", e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "main", win_err);
            }
            cleanup(Some(pi), Some(dll_path_ptr), None, None, None, None);
            return;
        }
    };

    // At this point, we will create an Event object that will be used as a means to communicate between
    // the target process and this program. We will use this Event object to signal when the DLL has been
    // loaded into the process, finished its initialization, and hooking has been completed
    let event_handle: HANDLE = match create_event() {
        Ok(event_handle) => event_handle,
        Err(e) => {
            error!("[{}] Failed to create event object: {}", "main", e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "main", win_err);
            }

            cleanup(Some(pi), Some(dll_path_ptr), None, None, None, None);
            return;
        }
    };

    // Get handle to current process
    let current_process_handle: HANDLE = unsafe { winapi::um::processthreadsapi::GetCurrentProcess() };
    if current_process_handle == std::ptr::null_mut() {
        error!("[{}] Failed to get handle of current process", "main");
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "main", win_err);
        }

        cleanup(Some(pi), Some(dll_path_ptr), Some(event_handle), None, None, Some(current_process_handle));
        return;
    }

    // We will now create a file mapping object that will be used to share the Event object between
    // this program and the target process. This function creates a duplicate of the Event object
    // and writes it to the file mapping object
    let file_mapping_name: &str = "Local\\__AA__AA__";
    let _file_mapping_handle: HANDLE = match create_file_mapping(event_handle, file_mapping_name, current_process_handle, pi.hProcess) {
        Ok(file_mapping_handle) => file_mapping_handle,
        Err(e) => {
            error!("[{}] Failed to create file mapping object: {}", "main", e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "main", win_err);
            }

            cleanup(Some(pi), Some(dll_path_ptr), Some(event_handle), None, None, Some(current_process_handle));
            return;
        }
    };
    
    // Read back the written data for validation
    info!("[{}] Reading back the written DLL path from allocated memory for validation", "main");
    let read_back_data = match read_memory(pi.hProcess, dll_path_ptr, dll_path.len()) {
        Ok(data) => {
            info!("[{}] Successfully read back the DLL path from allocated memory", "main");
            data
        },
        Err(e) => {
            error!("[{}] Failed to read back the DLL path from allocated memory: {}", "main", e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "main", win_err);
            }
            cleanup(Some(pi), Some(dll_path_ptr), Some(event_handle), None, Some(_file_mapping_handle), Some(current_process_handle));
            return;
        }
    };

    // Confirm that the read back data matches the original DLL path
    info!("[{}] Confirming that the read back data matches the original DLL path", "main");
    if &read_back_data != dll_path {
        error!("[{}] The written DLL path {} doesn't match with the original DLL path", "main", read_back_data);
        cleanup(Some(pi), Some(dll_path_ptr), Some(event_handle), None, Some(_file_mapping_handle), Some(current_process_handle));
        return;
    } else {
        info!("[{}] The written DLL path {} matches with the original DLL path", "main", read_back_data);

    }

    // Pause before creating remote thread
    info!("[{}] Waiting for user input to continue program", "main");

    println!("Press Enter to continue...");
    let mut buffer = String::new();
    match io::stdin().read_line(&mut buffer) {
        Ok(_) => {
            println!("Continuing the execution...");
            // Insert the rest of your code here
        },
        Err(e) => println!("Error: {}", e),
    }

    // Now that kernel32.dll is loaded into the process, we can call LoadLibraryA
    // We will do this by calling create_remote_thread
    let remote_thread_handle = match create_remote_thread(pi, unsafe { std::mem::transmute(loadlib_addr) }, dll_path_ptr) {
        Ok(thread_id) => thread_id,
        Err(e) => {
            error!("[{}] Failed to create remote thread: {}", "main", e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "main", win_err);
            }

            cleanup(Some(pi), Some(dll_path_ptr), Some(event_handle), None, Some(_file_mapping_handle), Some(current_process_handle));
            return;
        }
    };

    // Now we will wait for the event to be signaled by the DLL
    let timeout: DWORD = 1000; 
    let attempts: usize = 5;
    let wait_result = match wait_for_event(event_handle, timeout, attempts) {
        Ok(wait_result) => wait_result,
        Err(e) => {
            error!("[{}] Failed to wait for event: {}", "main", e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "main", win_err);
            }

            cleanup(Some(pi), Some(dll_path_ptr), Some(event_handle), Some(remote_thread_handle), Some(_file_mapping_handle), Some(current_process_handle));
            return;
        }
    };

    // We now check if the event was signaled or if it timed out
    if wait_result {
        info!("[{}] DLL successfully set event", "main");

        // We will now resume the main thread of the target process
        info!("[{}] Resuming Target Process Main Thread", "main");
        let success = unsafe { winapi::um::processthreadsapi::ResumeThread(pi.hThread) };
        if success == u32::MAX {
            error!("[{}] Failed to resume main thread of target process", "main");
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "main", win_err);
            }

            cleanup(Some(pi), Some(dll_path_ptr), Some(event_handle), Some(remote_thread_handle), Some(_file_mapping_handle), Some(current_process_handle));
            return;
        } else {
            info!("[{}] Successfully resumed main thread of target process", "main");
            cleanup(Some(pi), Some(dll_path_ptr), Some(event_handle), Some(remote_thread_handle), Some(_file_mapping_handle), Some(current_process_handle));
        }
    } else {
        warn!("[{}] DLL did not set event: {}", "main", "Timed out");
        cleanup(Some(pi), Some(dll_path_ptr), Some(event_handle), Some(remote_thread_handle), Some(_file_mapping_handle), Some(current_process_handle));
    }
}