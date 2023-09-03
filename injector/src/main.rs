#![allow(unused_imports)]
#![allow(non_snake_case)]

use std::ptr::null_mut;
use std::ffi::{OsStr, CString, CStr, OsString};
use std::iter::once;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ptr;
use std::io::{self, Read};
use std::process::Command;
use std::fs::File;
use std::error::Error;

use winapi::um::processthreadsapi::{CreateProcessW, CreateRemoteThread, ResumeThread, SuspendThread, OpenProcess, STARTUPINFOW, PROCESS_INFORMATION};
use winapi::um::winbase::CREATE_SUSPENDED;
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory, ReadProcessMemory, VirtualProtectEx};
use winapi::shared::minwindef::{DWORD, HMODULE, FARPROC, LPVOID, FALSE};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::ctypes::c_void;
use winapi::shared::basetsd::SIZE_T;
use winapi::um::winbase::WAIT_OBJECT_0;
use winapi::um::winnt::{
    LPCSTR, 
    LPSTR, 
    HANDLE, 
    PAGE_READWRITE, 
    DUPLICATE_SAME_ACCESS, 
    PAGE_READONLY, 
    PROCESS_QUERY_INFORMATION, 
    PROCESS_VM_READ,
    PROCESS_VM_WRITE,
    PROCESS_VM_OPERATION,
    PROCESS_CREATE_THREAD,
};
use winapi::um::psapi::{EnumProcessModulesEx, EnumProcesses, GetModuleBaseNameA, LIST_MODULES_ALL};
use winapi::um::wow64apiset::IsWow64Process;
use winapi::um::errhandlingapi::GetLastError;

extern crate simplelog;
extern crate log;

use log::{info, warn, error};
use simplelog::*;
use time::macros::format_description;

const PID_ARRAY_SIZE: usize = 1024;
const PROCESS_NAME_SIZE: usize = 512;

const WAIT_TIMEOUT: DWORD = 258;


// Utility function to get the last error
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

// This function will clean up any allocated memory and close any open handles or threads
fn cleanup(
    target_proc_handle: Option<HANDLE>,
    dll_path_ptr: Option<LPVOID>,
    remote_thread_handle: Option<HANDLE>,
) {
    // Free the allocated memory
    if let Some(dll_path_ptr) = dll_path_ptr {
        if let Some(target_proc_handle) = target_proc_handle {
            if !dll_path_ptr.is_null() {
                let success = unsafe { winapi::um::memoryapi::VirtualFreeEx(target_proc_handle, dll_path_ptr, 0, winapi::um::winnt::MEM_RELEASE) };
                if success == 0 {
                    error!("[{}] Failed to free allocated memory at address: {:?}", "cleanup", dll_path_ptr);
                    if let Some(win_err) = get_last_error() {
                        error!("[{}] Windows error: {}", "cleanup", win_err.trim());
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

    // Close the handle to the target process
    if let Some(target_proc_handle) = target_proc_handle {
        if target_proc_handle != winapi::um::handleapi::INVALID_HANDLE_VALUE {
            let success = unsafe { winapi::um::handleapi::CloseHandle(target_proc_handle) };
            if success == 0 {
                error!("[{}] Failed to close target process handle: {:?}", "cleanup", target_proc_handle);
                if let Some(win_err) = get_last_error() {
                    error!("[{}] Windows error: {}", "cleanup", win_err.trim());
                }
            } else {
                info!("[{}] Target process handle: {:?} closed successfully", "cleanup", target_proc_handle);
            }
        } else {
            warn!("[{}] Target process handle: {:?} is invalid", "cleanup", target_proc_handle);
        }
    }
}

// This function will return a list of tuples containing the process ID and name of each running process
fn get_running_procs() -> Result<Vec<(u32, String)>, DWORD> {
    // Initialize the process info vector
    let mut proc_info: Vec<(u32, String)> = Vec::new();

    // Initialize the process ID array which will be used to store the process IDs
    // Initialize the variable which will be used to store the number of bytes returned
    let mut process_ids: [u32; PID_ARRAY_SIZE] = [0; PID_ARRAY_SIZE];
    let mut cb_needed: u32 = 0;
    let num_processes: usize;

    // Attempt to enumerate process IDs
    let result = unsafe {
        info!("[{}] Enumerating processes", "get_running_procs");
        EnumProcesses(
            process_ids.as_mut_ptr(),
            (PID_ARRAY_SIZE * std::mem::size_of::<u32>()) as u32,
            &mut cb_needed,
        )
    };

    if result == 0 {
        if let Some(win_err) = get_last_error() {
            error!("[{}] Failed to enumerate processes: {}", "get_running_procs", win_err.trim());
        }
        return Err(unsafe { winapi::um::errhandlingapi::GetLastError() });
    } else {
        num_processes = cb_needed as usize / std::mem::size_of::<u32>();
        info!("[{}] Bytes returned: {} bytes", "get_running_procs", cb_needed);
        info!("[{}] Number of processes enumerated: {}", "get_running_procs", num_processes);
    }

    // Iterate through the process IDs and get the name of each process
    info!("[{}] Iterating through process ID and retrieving module base name", "get_running_procs");

    // Keep count of the number of processes which failed to open
    let mut num_failed = 0;

    // Create a variable to store the last reason for failure
    let mut last_err: String = String::new();

    for i in 0..num_processes {
        let process_id = process_ids[i];

        // Check if the process ID is 0. If it is, skip it as this means the process is not valid
        if process_id != 0 {
            // Initialize the handle which will be used to store the process handle
            let handle: HANDLE = unsafe {
                OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, process_id)
            };

            // Check if the handle is null. If it is, skip it as this means the process is not valid
            if handle.is_null() {
                if let Some(win_err) = get_last_error() {
                    last_err = win_err.trim().to_string();
                }
                num_failed += 1;
                continue;
            }

            // Initialize the process name array which will be used to store the process name
            let mut process_name = [0u8; PROCESS_NAME_SIZE];
            let name_len = unsafe {
                GetModuleBaseNameA(handle, null_mut(), process_name.as_mut_ptr() as *mut i8, PROCESS_NAME_SIZE as u32)
            };

            // Check if the name length is 0. If it is, skip it as this means the process is not valid
            if name_len == 0 {
                if let Some(win_err) = get_last_error() {
                    error!("[{}] Failed to get module base name: {}", "get_running_procs", win_err.trim());
                }
                continue;
            }

            // Convert the process name to a string
            let name = String::from_utf8_lossy(&process_name[0..name_len as usize]).to_string();

            // Push the process ID and name to the process info vector
            proc_info.push((process_id, name.clone()));

            // Close the process handle
            let success = unsafe { winapi::um::handleapi::CloseHandle(handle) };

            // Check if the handle was successfully closed
            if success == 0 {
                if let Some(win_err) = get_last_error() {
                    error!("[{}] Failed to close handle to {} ({}): {}", "get_running_procs", name, process_id, win_err.trim());
                }
            }
        }
    }

    info!("[{}] Processes opened: {}", "get_running_procs", proc_info.len());
    info!("[{}] Processes not opened: {}", "get_running_procs", num_failed);
    info!("[{}] Last error: {}", "get_running_procs", last_err);

    return Ok(proc_info);
}

// This function will check if the target process is running and return the process ID if it is
fn is_target_running(proc_info: &Vec<(u32, String)>, target_proc_name: &String) -> Option<u32> {
    info!("[{}] Checking if target process ({}) is running", "is_target_running", target_proc_name);

    // Iterate through the process info vector and check if the target process is running
    for (proc_id, proc_name) in proc_info {
        // Convert both process names to lowercase
        let proc_name_lower = proc_name.to_lowercase();
        let target_proc_name_lower = target_proc_name.to_lowercase();

        // If either string is a substring of the other, return the process ID
        if proc_name_lower.contains(&target_proc_name_lower) || target_proc_name_lower.contains(&proc_name_lower) {
            info!("[{}] Target process is running: {} ({})", "is_target_running", proc_name, proc_id);
            return Some(*proc_id);
        }
    }

    // If the target process is not running, return None
    return None;
}

// This function will return a handle to the target process
fn get_target_proc_handle(target_proc_id: u32) -> Result<HANDLE, DWORD> {
    info!("[{}] Getting handle to target process ({})", "get_target_proc_handle", target_proc_id);

    // Initialize the handle which will be used to store the process handle
    let handle: HANDLE = unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD,
            0,
            target_proc_id
        )
    };

    // Check if the handle is null. If it is, return an error
    if handle.is_null() {
        if let Some(win_err) = get_last_error() {
            error!("[{}] Failed to open target process ({}): {}", "get_target_proc_handle", target_proc_id, win_err.trim());
        }
        return Err(unsafe { winapi::um::errhandlingapi::GetLastError() });
    }

    info!("[{}] Successfully opened target process ({}) with handle {:?}", "get_target_proc_handle", target_proc_id, handle);

    // Return the process handle
    return Ok(handle);
}


// This function will determine the size of the dll_path and allocate memory in the target process
// It returns a pointer to the allocated memory
fn allocate_memory(target_proc_handle: HANDLE, dll_path: &str) -> Result<*mut c_void, DWORD> {
    let dll_path_c = CString::new(dll_path).unwrap();

    let dll_path_ptr = unsafe {
        info!("[{}] Allocating memory in target process with handle {:?}", "allocate_memory", target_proc_handle);
        VirtualAllocEx(
            target_proc_handle,
            null_mut(),
            dll_path_c.as_bytes_with_nul().len(),  // Allocate enough space for the DLL path
            winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE,
            winapi::um::winnt::PAGE_READWRITE,
        )
    };

    if dll_path_ptr.is_null() {
        error!("[{}] Failed to allocate memory in target process", "allocate_memory");
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "allocate_memory", win_err.trim());
        }
        Err(unsafe { winapi::um::errhandlingapi::GetLastError() })
    } else {
        info!("[{}] Successfully allocated memory into target process with handle {:?}", "allocate_memory", target_proc_handle);
        info!("[{}] Base address of allocated memory: {:?}", "allocate_memory", dll_path_ptr);
        info!("[{}] Size of allocated memory: {} bytes", "allocate_memory", dll_path_c.as_bytes_with_nul().len());
        Ok(dll_path_ptr)
    }
}

// This function will write the DLL path to the memory allocated in the target process
// It will accept the process handle, the base address of the allocated memory, and the DLL path
// It will return a boolean value indicating whether the DLL path was successfully written
fn write_memory(target_proc_handle: HANDLE, dll_path_ptr: *mut c_void, dll_path: &str) -> Result<bool, DWORD> {
    let dll_path_c = CString::new(dll_path).unwrap();

    let mut bytes_written: usize = 0;

    let success = unsafe {
        info!("[{}] Writing {:?} to allocated memory at base address {:?}", "write_memory", dll_path_c, dll_path_ptr);
        WriteProcessMemory(
            target_proc_handle,
            dll_path_ptr,
            dll_path_c.as_ptr() as *mut c_void,
            dll_path_c.as_bytes_with_nul().len(),
            &mut bytes_written,
        )
    };

    if success == 0 {
        error!("[{}] Failed to write {:?} to allocated memory at base address {:?}", "write_memory", dll_path_c, dll_path_ptr);
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "write_memory", win_err.trim());
        }
        return Err(unsafe { winapi::um::errhandlingapi::GetLastError() })
    } else {
        info!("[{}] Bytes written: {}", "write_memory", bytes_written);
    }

    // Now that the DLL path has been written to the allocated memory, we can change the memory protection back to read-only
    let mut old_protect: DWORD = 0;
    let success_protect = unsafe {
        VirtualProtectEx(
            target_proc_handle,
            dll_path_ptr,
            dll_path_c.as_bytes_with_nul().len(),
            PAGE_READONLY,
            &mut old_protect
        )
    };

    if success_protect == 0 {
        error!("[{}] Failed to change memory protection back to read-only", "write_memory");
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "write_memory", win_err.trim());
        }
        Err(unsafe { winapi::um::errhandlingapi::GetLastError() })
    } else {
        Ok(true)
    }
}

// This function is used to validate that the DLL path was successfully written to the allocated memory
fn read_memory(target_proc_handle: HANDLE, dll_path_ptr: LPVOID, dll_path_len: usize) -> Result<String, DWORD> {
    let mut buffer: Vec<u8> = vec![0; dll_path_len];
    let mut bytes_read: SIZE_T = 0;

    let success = unsafe {
        ReadProcessMemory(
            target_proc_handle,
            dll_path_ptr,
            buffer.as_mut_ptr() as _,
            buffer.len(),
            &mut bytes_read
        )
    };

    if success == 0 {
        // If the function fails, the return value is 0 (FALSE).
        error!("[{}] Failed to read memory", "read_memory");
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "read_memory", win_err.trim());
        }
        return Err(unsafe { GetLastError() });
    }

    // Resize buffer to actual bytes read
    buffer.resize(bytes_read, 0);

    // Convert buffer to a string
    let read_back_data = match String::from_utf8(buffer) {
        Ok(data) => {
            info!("[{}] Contents of read back data: {}", "read_memory", data);
            data
        },
        Err(e) => {
            error!("[{}] Failed to convert read back data to string: {}", "read_memory", e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "read_memory", win_err.trim());
            }
            return Err(unsafe { GetLastError() });
        }
    };

    Ok(read_back_data)
}

// This function retrieves the base address of a module loaded into a process specified by the process handle
fn get_module_base_address(target_proc_handle: HANDLE, module_name: &str) -> Result<HMODULE, DWORD> {
    info!("[{}] Getting module base address for: {}", "get_module_base_address", module_name);
    let mut cb_needed: DWORD = 0;

    let result = unsafe {
        EnumProcessModulesEx(
            target_proc_handle,
            std::ptr::null_mut(),
            0,
            &mut cb_needed,
            LIST_MODULES_ALL,
        )
    };

    if result == 0 {
        error!("[{}] Failed to get module count", "get_module_base_address");
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "get_module_base_address", win_err.trim());
        }
        return Err(unsafe { winapi::um::errhandlingapi::GetLastError() });
    }

    let module_count = cb_needed / std::mem::size_of::<HMODULE>() as DWORD;
    let mut h_mods: Vec<HMODULE> = vec![std::ptr::null_mut(); module_count as usize];

    let result = unsafe {
        EnumProcessModulesEx(
            target_proc_handle,
            h_mods.as_mut_ptr(),
            cb_needed,
            &mut cb_needed,
            LIST_MODULES_ALL,
        )
    };

    if result == 0 {
        error!("[{}] Failed to get module handles", "get_module_base_address");
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "get_module_base_address", win_err.trim());
        }
        return Err(unsafe { winapi::um::errhandlingapi::GetLastError() });
    }

    let mut module_name_c = vec![0u8; 256];

    for i in 0..module_count {
        let result = unsafe {
            GetModuleBaseNameA(
                target_proc_handle,
                h_mods[i as usize],
                module_name_c.as_mut_ptr() as LPSTR,
                256 as DWORD,
            )
        };

        if result == 0 {
            error!("[{}] Failed to get module name", "get_module_base_address");
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "get_module_base_address", win_err.trim());
            }
            return Err(unsafe { winapi::um::errhandlingapi::GetLastError() });
        }

        let current_module_name = unsafe { CStr::from_ptr(module_name_c.as_ptr() as LPCSTR) }.to_string_lossy().into_owned();

        if current_module_name.eq_ignore_ascii_case(module_name) {
            info!("[{}] {} base address: {:?}", "get_module_base_address", module_name, h_mods[i as usize]);
            return Ok(h_mods[i as usize]);
        }
    }
    error!("[{}] {} base address not found", "get_module_base_address", module_name);
    Err(unsafe { winapi::um::errhandlingapi::GetLastError() })
}

// This function will get the base address of the kernel32.dll module which has been 
// loaded by the calling process (this program) and use the GetProcAddress function
// to get the address (relative to the base address) of the LoadLibraryA function
// The function then subtracts the base address from the LoadLibraryA address to get the offset
fn get_loadlib_offset() -> Result<usize, DWORD> {
    let module_str = CString::new("kernel32.dll").unwrap();
    let loadlib_str = CString::new("LoadLibraryA").unwrap();
    let loadlib_offset: usize;

    unsafe {
        // First we need to get the kernel32.dll module handle
        info!("[{}] Retrieving handle to {:?} module", "get_loadlib_offset", module_str);
        let kernel32_handle = GetModuleHandleA(module_str.as_ptr());

        if kernel32_handle.is_null() {
            error!("[{}] Failed to get {:?} module handle", "get_loadlib_offset", module_str);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "get_loadlib_offset", win_err.trim());
            }
            return Err(winapi::um::errhandlingapi::GetLastError());
        } else {
            info!("[{}] {:?} module handle: {:p}", "get_loadlib_offset", module_str, kernel32_handle);
        }

        // Next we need to get the relative address of the LoadLibraryA function
        // We can do this by calling the GetProcAddress function
        info!("[{}] Retrieving address of {:?} function", "get_loadlib_offset", loadlib_str);
        let loadlib_ptr = GetProcAddress(kernel32_handle, loadlib_str.as_ptr());

        if loadlib_ptr.is_null() {
            error!("[{}] Failed to get address of {:?} function", "get_loadlib_offset", loadlib_str);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "get_loadlib_offset", win_err.trim());
            }
            return Err(winapi::um::errhandlingapi::GetLastError());
        } else {
            info!("[{}] {:?} function address: {:p}", "get_loadlib_offset", loadlib_str, loadlib_ptr);
        }

        // Calculate the offset of LoadLibraryA in kernel32.dll
        loadlib_offset = loadlib_ptr as usize - kernel32_handle as usize;
    }
    info!("[{}] Calculated offset of {:?} function in {:?} module: 0x{:X}", "get_loadlib_offset", loadlib_str, module_str, loadlib_offset);

    Ok(loadlib_offset)
}

// This function will calculate the address of the LoadLibraryA function in the target process
// by adding the offset of the LoadLibraryA function in kernel32.dll to the base address of kernel32.dll
fn get_loadlib_addr(kernel32_base_addr: HMODULE, loadlib_offset: usize) -> Result<*const c_void, DWORD> {
    info!("[{}] Calculating address of LoadLibraryA function in target process", "get_loadlib_addr");
    let loadlib_addr_ptr = (kernel32_base_addr as usize + loadlib_offset) as *const c_void;
    info!("[{}] Address of LoadLibraryA function in target process: 0x{:x}", "get_loadlib_addr", loadlib_addr_ptr as usize);

    Ok(loadlib_addr_ptr)
} 

// Now we will create a remote thread in the target process using CreateRemoteThread
// This thread will be responsible for loading the DLL into the target process
// using the LoadLibraryA function whose address we obtained above
// The return value is the handle to the newly created thread
fn create_remote_thread(target_proc_handle: HANDLE, load_library: FARPROC, dll_path_ptr: LPVOID) -> Result<HANDLE, DWORD> {
    info!("[{}] Creating remote thread in target process ({:?})", "create_remote_thread", target_proc_handle);

    let remote_thread_handle = unsafe {
        CreateRemoteThread(
            target_proc_handle,
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
            error!("[{}] Windows error: {}", "create_remote_thread", win_err.trim());
        }
        return Err(unsafe { winapi::um::errhandlingapi::GetLastError() });
    } else {
        info!("[{}] Handle to remote thread: {:?}", "create_remote_thread", remote_thread_handle);
        return Ok(remote_thread_handle);
    }
}


fn main() {
    // Initialize the logger
    let config = ConfigBuilder::new()
        .set_time_format_custom(format_description!("[hour]:[minute]:[second].[subsecond]"))
        .build();

    let _ = WriteLogger::init(LevelFilter::Info, config, File::create("injector.log").expect("Failed to initialize logger"));

    // Check if user has provided the correct number of arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        error!("[{}] Invalid number of arguments supplied to injector", "main");
        return;
    }

    // Store the target process name
    let target_proc_name = args[1].clone();
    let dll32_path = args[2].clone();
    let dll64_path = args[3].clone();
    
    // This will be the default DLL path
    let mut dll_path: String = dll64_path;

    // Get the list of running processes
    let proc_info: Vec<(u32, String)> = match get_running_procs() {
        Ok(info) => info,
        Err(err) => {
            error!("[{}] Failed to get running processes: {}", "main", err);
            return;
        }
    };

    // Check if the target process is running
    let target_proc_id: u32 = match is_target_running(&proc_info, &target_proc_name) {
        Some(id) => id,
        None => {
            error!("[{}] Target process is not running", "main");
            return;
        }
    };

    // Get a handle to the target process
    let target_proc_handle: HANDLE = match get_target_proc_handle(target_proc_id) {
        Ok(handle) => handle,
        Err(err) => {
            error!("[{}] Failed to get handle to target process: {}", "main", err);
            return;
        }
    };

    // Check if target process is 32-bit or 64-bit
    let mut is_wow64: i32 = 0;
    unsafe {
        if IsWow64Process(target_proc_handle, &mut is_wow64) != 0 {
            if is_wow64 != 0 {
                dll_path = dll32_path;
            }
        } else {
            error!("[{}] Failed to determine bitness of target process", "main");
            return;
        }
    }

    // Next, we will allocate memory in the process by calling the allocate_memory function
    // This function will return a pointer to the allocated memory which we will use later
    let dll_path_ptr = match allocate_memory(target_proc_handle, &dll_path) {
        Ok(ptr) => ptr,
        Err(e) => {
            error!("[{}] Failed to allocate memory in process: {}", "main", e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "main", win_err.trim());
            }
            cleanup(Some(target_proc_handle), None, None);
            return;
        }
    };

    // We will check if the pointer to the allocated memory is null
    if dll_path_ptr.is_null() {
        error!("[{}] The pointer to DLL path is null after allocation", "main");
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "main", win_err.trim());
        }
        cleanup(Some(target_proc_handle), None, None);
        return;
    }

    // Now we will write the DLL's bytes to the allocated memory using WriteProcessMemory
    // This function will return a boolean value indicating whether the DLL was successfully written
    let _success = match write_memory(target_proc_handle, dll_path_ptr, &dll_path) {
        Ok(success) => success,
        Err(e) => {
            error!("[{}] Failed to write DLL path to allocated memory: {}", "main", e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "main", win_err.trim());
            }
            cleanup(Some(target_proc_handle), Some(dll_path_ptr), None);
            return;
        }
    };

    // Read back the written data for validation
    info!("[{}] Reading back the written DLL path from allocated memory for validation", "main");
    let read_back_data = match read_memory(target_proc_handle, dll_path_ptr, dll_path.len()) {
        Ok(data) => {
            data
        },
        Err(e) => {
            error!("[{}] Failed to read back the DLL path from allocated memory: {}", "main", e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "main", win_err.trim());
            }
            cleanup(Some(target_proc_handle), Some(dll_path_ptr), None);
            return;
        }
    };

    // Confirm that the read back data matches the original DLL path
    if &read_back_data != &dll_path {
        error!("[{}] The written DLL path {} doesn't match with the original DLL path", "main", read_back_data);
        cleanup(Some(target_proc_handle), Some(dll_path_ptr), None);
        return;
    } else {
        info!("[{}] The written DLL path {} matches with the original DLL path", "main", read_back_data);

    }

    // We will get the base address of kernel32.dll by calling get_module_base_address
    // This function will return the base address of kernel32.dll in the target process
    let target_module_name = "kernel32.dll";
    let target_mod_base_addr: HMODULE = match get_module_base_address(target_proc_handle, target_module_name) {
        Ok(target_mod_base_addr) => target_mod_base_addr,
        Err(e) => {
            error!("[{}] Failed to get base address of {}: {}", "main", target_module_name, e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "main", win_err.trim());
            }
            cleanup(Some(target_proc_handle), Some(dll_path_ptr), None);
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
                error!("[{}] Windows error: {}", "main", win_err.trim());
            }
            cleanup(Some(target_proc_handle), Some(dll_path_ptr), None);
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
                error!("[{}] Windows error: {}", "main", win_err.trim());
            }
            cleanup(Some(target_proc_handle), Some(dll_path_ptr), None);
            return;
        }
    };

    // Now that we have the address of LoadLibraryA, we can call CreateRemoteThread to execute LoadLibraryA
    let remote_thread_handle = match create_remote_thread(target_proc_handle, unsafe { std::mem::transmute(loadlib_addr) }, dll_path_ptr) {
        Ok(thread_id) => thread_id,
        Err(e) => {
            error!("[{}] Failed to create remote thread: {}", "main", e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "main", win_err.trim());
            }

            cleanup(Some(target_proc_handle), Some(dll_path_ptr), None);
            return;
        }
    };

    // Pause before creating remote thread
    info!("[{}] Waiting for user input to continue program", "main");

    println!("Press Enter to continue...");
    let mut buffer = String::new();
    match io::stdin().read_line(&mut buffer) {
        Ok(_) => {
            info!("[{}] User input received", "main");
        },
        Err(e) => println!("Error: {}", e),
    }

    cleanup(Some(target_proc_handle), Some(dll_path_ptr), Some(remote_thread_handle));
}
