#![allow(unused_imports)]
#![allow(non_snake_case)]
#![allow(unused_assignments)]
#![allow(unused_variables)]

use std::fs;
use std::ptr::null_mut;
use std::ffi::{OsStr, CString, CStr, OsString};
use std::iter::once;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ptr;
use std::io::{self, Read, Seek, SeekFrom};
use std::process::Command;
use std::fs::File;
use std::error::Error;
use std::thread;
use std::time::Duration;
use std::path::Path;

use winapi::um::processthreadsapi::{CreateProcessW, CreateRemoteThread, ResumeThread, SuspendThread, OpenProcess, GetExitCodeThread, STARTUPINFOW, PROCESS_INFORMATION};
use winapi::um::winbase::CREATE_SUSPENDED;
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory, ReadProcessMemory, VirtualProtectEx};
use winapi::shared::minwindef::{DWORD, HMODULE, FARPROC, LPVOID, FALSE};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress, FreeLibrary};
use winapi::ctypes::c_void;
use winapi::shared::basetsd::SIZE_T;
use winapi::um::winbase::WAIT_OBJECT_0;
use winapi::um::synchapi::WaitForSingleObject;
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
use clap::{Parser, CommandFactory};

const PID_ARRAY_SIZE: usize = 1024;
const PROCESS_NAME_SIZE: usize = 512;
const WAIT_TIMEOUT: DWORD = 258;

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // MZ
const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // PE\0\0

// Offsets to various fields in the PE header
const OFFSET_PE_SIGNATURE: u64 = 0x3C;
const OFFSET_MACHINE: u64 = 0x4;

// Machine types
const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;


#[derive(Parser, Default, Debug)]
#[command(name = "injector")]
#[command(author = "Quin Darcy")]
#[command(version = "0.1.0")]
#[command(
    help_template = "\n{name}\n{author}\nVersion: {version}\n{about}\n\n{usage-heading} {usage} \n\n {all-args} {tab}\n\n"
)]
#[command(about, long_about = None)]
/// A classic DLL injector written in Rust
struct Cli {
    #[arg(short = 'n', long = "process_name")]
    /// The name of the process to inject into
    process_name: Option<String>, 
    
    #[arg(short, long)]
    /// The PID of the process to inject into
    pid: Option<u32>,

    #[arg(short, long)]
    /// The path to the DLL to inject
    dll_path: Option<String>,

    #[arg(short, long)]
    /// The path to the log file
    log_path: Option<String>,
}

impl Cli {
    pub fn validate_process_args(&mut self) -> Result<(), String> {
        // Check if the user has specified both a process name and a PID
        if self.process_name.is_some() && self.pid.is_some() {
            let err_type = "ArgumentConflict";
            let err_msg = "You cannot specify both a process name and a PID.";
            return Err(format!("{}: {}", err_type, err_msg));
        }
        
        // Check if the user has specified neither a process name nor a PID
        if self.process_name.is_none() && self.pid.is_none() {
            let err_type = "MissingArguments";
            let err_msg = "Either a process name or a PID must be specified.";
            return Err(format!("{}: {}", err_type, err_msg));
        }

        // Check if the user has specified a DLL path
        if self.dll_path.is_none() {
            let err_type = "MissingArguments";
            let err_msg = "The path to the DLL must be specified.";
            return Err(format!("{}: {}", err_type, err_msg));
        }

         // Check if the PID exists
        if self.pid.is_some() {
            unsafe {
                let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, 0, self.pid.unwrap());
                if process_handle.is_null() {
                    let err_type = "InvalidArgument";
                    let err_msg = format!("The PID '{}' does not exist.", self.pid.unwrap());
                    return Err(format!("{}: {}", err_type, err_msg));
                } else {
                    // Close the handle
                    winapi::um::handleapi::CloseHandle(process_handle);
                }
            }
        }

        // Check if the DLL path exists
        if let Some(dll_path) = &self.dll_path {
            if !Path::new(dll_path).exists() {
                let err_type = "InvalidArgument";
                let err_msg = format!("The DLL path '{}' does not exist.", dll_path);
                return Err(format!("{}: {}", err_type, err_msg));
            }
        }

        // Check if a log file has been specified, if not set default to the current directory
        if self.log_path.is_none() {
            self.log_path = Some("injector.log".to_string());
        } 
        
        // If a log path was specified, verify that the path is valid
        if let Some(log_path) = &self.log_path {
            // Check if the parent directory exists
            if let Some(parent_dir) = Path::new(log_path).parent() {
                if !parent_dir.exists() {
                    // Attempt to create the parent directory
                    match fs::create_dir_all(parent_dir) {
                        Ok(_) => {},
                        Err(e) => {
                            let err_type = "InvalidArgument";
                            let err_msg = format!("The parent directory for the log file '{}' does not exist and could not be created: {}", log_path, e);
                            return Err(format!("{}: {}", err_type, err_msg));
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

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
    loadlib_remote_thread_handle: Option<HANDLE>,
    freelib_remote_thread_handle: Option<HANDLE>,
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

    // Close the handle to the remote thread created in the target process to load the DLL
    if let Some(loadlib_remote_thread_handle) = loadlib_remote_thread_handle {
        info!("[{}] Closing handle to thread: {:?}", "cleanup", loadlib_remote_thread_handle);
        if loadlib_remote_thread_handle != winapi::um::handleapi::INVALID_HANDLE_VALUE {
            // Wait for the thread to finish execution
            info!("[{}] Waiting for thread: {:?} to finish execution", "cleanup", loadlib_remote_thread_handle);
            let wait_result = unsafe { winapi::um::synchapi::WaitForSingleObject(loadlib_remote_thread_handle, 0xFFFFFFFF) };
            match wait_result {
                WAIT_OBJECT_0 => info!("[{}] Thread with handle: {:?} has finished execution", "cleanup", loadlib_remote_thread_handle),
                WAIT_TIMEOUT => warn!("[{}] Timed out waiting for thread with handle: {:?} to finish execution", "cleanup", loadlib_remote_thread_handle),
                _ => {
                    error!("[{}] An error occurred while waiting for thread with handle: {:?} to finish execution", "cleanup", loadlib_remote_thread_handle);
                    if let Some(win_err) = get_last_error() {
                        error!("[{}] Windows error: {}", "cleanup", win_err);
                    }
                },
            }
    
            let success = unsafe { winapi::um::handleapi::CloseHandle(loadlib_remote_thread_handle) };
            if success == 0 {
                error!("[{}] Failed to close handle to thread: {:?}", "cleanup", loadlib_remote_thread_handle);
                if let Some(win_err) = get_last_error() {
                    error!("[{}] Windows error: {}", "cleanup", win_err);
                }
            } else {
                info!("[{}] Handle to thread: {:?} closed successfully", "cleanup", loadlib_remote_thread_handle);
            }
        } else {
            warn!("[{}] Thread handle: {:?} is invalid", "cleanup", loadlib_remote_thread_handle);
        }
    }

    // Close the handle to the remote thread created in the target process to unload the DLL
    if let Some(freelib_remote_thread_handle) = freelib_remote_thread_handle {
        info!("[{}] Closing handle to thread: {:?}", "cleanup", freelib_remote_thread_handle);
        if freelib_remote_thread_handle != winapi::um::handleapi::INVALID_HANDLE_VALUE {
            // Wait for the thread to finish execution
            info!("[{}] Waiting for thread: {:?} to finish execution", "cleanup", freelib_remote_thread_handle);
            let wait_result = unsafe { winapi::um::synchapi::WaitForSingleObject(freelib_remote_thread_handle, 0xFFFFFFFF) };
            match wait_result {
                WAIT_OBJECT_0 => info!("[{}] Thread with handle: {:?} has finished execution", "cleanup", freelib_remote_thread_handle),
                WAIT_TIMEOUT => warn!("[{}] Timed out waiting for thread with handle: {:?} to finish execution", "cleanup", freelib_remote_thread_handle),
                _ => {
                    error!("[{}] An error occurred while waiting for thread with handle: {:?} to finish execution", "cleanup", freelib_remote_thread_handle);
                    if let Some(win_err) = get_last_error() {
                        error!("[{}] Windows error: {}", "cleanup", win_err);
                    }
                },
            }
    
            let success = unsafe { winapi::um::handleapi::CloseHandle(freelib_remote_thread_handle) };
            if success == 0 {
                error!("[{}] Failed to close handle to thread: {:?}", "cleanup", freelib_remote_thread_handle);
                if let Some(win_err) = get_last_error() {
                    error!("[{}] Windows error: {}", "cleanup", win_err);
                }
            } else {
                info!("[{}] Handle to thread: {:?} closed successfully", "cleanup", freelib_remote_thread_handle);
            }
        } else {
            warn!("[{}] Thread handle: {:?} is invalid", "cleanup", freelib_remote_thread_handle);
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

// Determine if DLL is 32-bit or 64-bit or invalid
fn get_dll_bitness(path: &str) -> io::Result<String> {
    let mut file = File::open(path)?;

    // Read DOS header and check its signature
    let mut dos_sig_buf = [0u8; 2];
    file.read_exact(&mut dos_sig_buf)?;
    let dos_sig = u16::from_le_bytes(dos_sig_buf);
    if dos_sig != IMAGE_DOS_SIGNATURE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid DOS signature"));
    }

    // Read the PE header offset from the DOS header and seek to it
    file.seek(SeekFrom::Start(OFFSET_PE_SIGNATURE))?;
    let mut pe_offset_buf = [0u8; 4];
    file.read_exact(&mut pe_offset_buf)?;
    let pe_offset = u32::from_le_bytes(pe_offset_buf);

    // Read and check the PE signature
    file.seek(SeekFrom::Start(u64::from(pe_offset)))?;
    let mut pe_sig_buf = [0u8; 4];
    file.read_exact(&mut pe_sig_buf)?;
    let pe_sig = u32::from_le_bytes(pe_sig_buf);
    if pe_sig != IMAGE_NT_SIGNATURE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid PE signature"));
    }

    // Read the Machine field from the PE header
    file.seek(SeekFrom::Start(u64::from(pe_offset) + OFFSET_MACHINE))?;
    let mut machine_buf = [0u8; 2];
    file.read_exact(&mut machine_buf)?;
    let machine = u16::from_le_bytes(machine_buf);

    match machine {
        IMAGE_FILE_MACHINE_I386 => Ok("32-bit".to_string()),
        IMAGE_FILE_MACHINE_AMD64 => Ok("64-bit".to_string()),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "Unknown machine type")),
    }
}

// This function will return the name of a process given its process ID
fn get_proc_name(process_id: u32) -> Result<String, String> {
    // Initialize variable to store reason for failure
    let mut err_msg: String = String::new();

    // Check if the process ID is 0. If it is, skip it as this means the process is not valid
    if process_id != 0 {
        // Initialize the handle which will be used to store the process handle
        let handle: HANDLE = unsafe {
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, process_id)
        };

        // Check if the handle is null. If it is, skip it as this means the process is not valid
        if handle.is_null() {
            if let Some(win_err) = get_last_error() {
                err_msg = win_err.trim().to_string();
            }
            return Err(err_msg);
        }

        // Initialize the process name array which will be used to store the process name
        let mut process_name = [0u8; PROCESS_NAME_SIZE];
        let name_len = unsafe {
            GetModuleBaseNameA(handle, null_mut(), process_name.as_mut_ptr() as *mut i8, PROCESS_NAME_SIZE as u32)
        };

        // Check if the name length is 0. If it is, skip it as this means the process is not valid
        if name_len == 0 {
            if let Some(win_err) = get_last_error() {
                err_msg = win_err.trim().to_string();
                error!("[{}] Failed to get module base name: {}", "get_proc_name", win_err.trim());
            }
            return Err(err_msg);
        }

        // Convert the process name to a string
        let name = String::from_utf8_lossy(&process_name[0..name_len as usize]).to_string();

        // Close the process handle
        let success = unsafe { winapi::um::handleapi::CloseHandle(handle) };

        // Check if the handle was successfully closed
        if success == 0 {
            if let Some(win_err) = get_last_error() {
                err_msg = win_err.trim().to_string();
                error!("[{}] Failed to close handle to {} ({}): {}", "get_proc_name", name, process_id, win_err.trim());
            }
            return Err(err_msg);
        }

        // Return the process name
        return Ok(name);
    } else {
        return Err("Process ID is 0".to_string());
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
        return Err(0);
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

        // Attempt to get the name of the process
        match get_proc_name(process_id) {
            Ok(name) => {
                // If the name is not empty, add it to the process info vector
                if !name.is_empty() {
                    proc_info.push((process_id, name));
                }
            },
            Err(e) => {
                num_failed += 1;
                last_err = e;
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
    info!("[{}] Getting {} base address in target process", "get_module_base_address", module_name);
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
            info!("[{}] {} base address: {:?} in target process", "get_module_base_address", module_name, h_mods[i as usize]);
            return Ok(h_mods[i as usize]);
        }
    }
    warn!("[{}] {} base address not found", "get_module_base_address", module_name);
    Err(404 as DWORD)
}

// This function will get the base address of the given module which has been 
// loaded by the calling process (this program) and use the GetProcAddress function
// to get the address (relative to the base address) of the given function
// The function then subtracts the base address from the function address to get the offset
fn get_function_offset(module_name: &str, freelib_str: &str) -> Result<usize, DWORD> {
    let module_str = CString::new(module_name).unwrap();
    let function_str = CString::new(freelib_str).unwrap();
    let function_offset: usize;

    unsafe {
        // First we need to get a handle to the module
        info!("[{}] Retrieving handle to {:?} module loaded in current process", "get_function_offset", module_str);
        let module_handle = GetModuleHandleA(module_str.as_ptr());

        if module_handle.is_null() {
            error!("[{}] Failed to get {:?} module handle", "get_function_offset", module_str);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "get_function_offset", win_err.trim());
            }
            return Err(winapi::um::errhandlingapi::GetLastError());
        } else {
            info!("[{}] {:?} module handle: {:p} in current_process", "get_function_offset", module_str, module_handle);
        }

        // Next we need to get the relative address of the LoadLibraryA function
        // We can do this by calling the GetProcAddress function
        info!("[{}] Retrieving address of {:?} function in current process", "get_function_offset", function_str);
        let function_ptr = GetProcAddress(module_handle, function_str.as_ptr());

        if function_ptr.is_null() {
            error!("[{}] Failed to get address of {:?} function", "get_function_offset", function_str);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "get_function_offset", win_err.trim());
            }
            return Err(winapi::um::errhandlingapi::GetLastError());
        } else {
            info!("[{}] {:?} function address: {:p} in current process", "get_function_offset", function_str, function_ptr);
        }

        // Calculate the offset of the function in the module
        function_offset = function_ptr as usize - module_handle as usize;
    }

    info!("[{}] Calculated offset of {:?} function in {:?} module: 0x{:X}", "get_function_offset", function_str, module_str, function_offset);

    Ok(function_offset)
}

// This function will calculate the address of the function in the target process
// by adding the offset of the function in the module to the base address of the module
fn get_function_addr(module_base_addr: HMODULE, function_offset: usize, function_name: &str) -> Result<*const c_void, DWORD> {
    let function_str = CString::new(function_name).unwrap();
    info!("[{}] Calculating address of {:?} in target process", "get_function_addr", function_str);
    let function_addr_ptr = (module_base_addr as usize + function_offset) as *const c_void;
    info!("[{}] Address of {:?} in target process: 0x{:x}", "get_function_addr", function_str, function_addr_ptr as usize);

    Ok(function_addr_ptr)
} 

// Now we will create a remote thread in the target process using CreateRemoteThread
// This thread will be responsible for loading and unloading the DLL into/from the target process
// using the LoadLibraryA and FreeLibrary function whose addresses we obtained above
// The return value is the handle to the newly created thread
fn create_remote_thread(target_proc_handle: HANDLE, function_ptr: FARPROC, lp_parameter: LPVOID) -> Result<HANDLE, DWORD> {
    info!("[{}] Creating remote thread in target process ({:?})", "create_remote_thread", target_proc_handle);

    let remote_thread_handle = unsafe {
        CreateRemoteThread(
            target_proc_handle,
            null_mut(),
            0,
            Some(std::mem::transmute(function_ptr)),
            lp_parameter,  
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

    // Get the command line arguments
    let mut args = Cli::parse();

    // =================== BEGIN INPUT VALIDATION ===================

    // Perform some basic validation on the arguments
    let _result = match args.validate_process_args() {
        Ok(_) => (),
        Err(err) => {
            println!("\n{}\n", err);
            println!("{}\n     {}\n", "Usage:", "injector.exe [OPTIONS]");
            println!("For more information try -h or --help");
            return;
        }
    };

    // Get the bitness of the DLL and store the path
    let mut dll_bitness: u32 = 0;
    let mut dll_path: String = String::new();
    if let Some(path) = args.dll_path {
        dll_path = path;
        match get_dll_bitness(&dll_path) {
            Ok(bitness) => {
                if bitness == "32-bit" {
                    info!("[{}] DLL is 32-bit", "main");
                    dll_bitness = 32;
                } else if bitness == "64-bit" {
                    info!("[{}] DLL is 64-bit", "main");
                    dll_bitness = 64;
                } else {
                    error!("[{}] Invalid DLL bitness: {}", "main", bitness);
                    return;
                }
            },
            Err(e) => {
                error!("[{}] Failed to get DLL bitness: {}", "main", e);
                return;
            }
        }
    }

    // Convert the DLL path to an absolute file path
    let dll_pathbuf = match fs::canonicalize(dll_path) {
        Ok(pathbuf) => pathbuf,
        Err(e) => {
            error!("[{}] Failed to convert DLL path to absolute path: {}", "main", e);
            return;
        }
    };

    // Get the file name from the path
    let dll_file_name = match dll_pathbuf.file_name() {
        Some(name) => name.to_str().unwrap_or(""),
        None => {
            error!("[{}] Failed to get the file name from the path", "main");
            return;
        }
    };

    // Convert the DLL path to a string
    if let Some(path_str) = dll_pathbuf.to_str() {
        dll_path = path_str.to_string();
    } else {
        error!("[{}] Failed to convert DLL path to string", "main");
        return;
    }

    // Remove the "\\?\" prefix from the DLL path if it exists
    dll_path = if dll_path.starts_with("\\\\?\\") {
        dll_path[4..].to_string()
    } else {
        dll_path.to_string()
    };

    // Get target process information (name and PID)
    let mut target_proc_id: u32 = 0;
    let mut target_proc_name: String = String::new();
    if let Some(proc_name) = args.process_name {
        // Store the target process name
        target_proc_name = proc_name.clone();

        // Get the list of running processes
        let proc_info: Vec<(u32, String)> = match get_running_procs() {
            Ok(info) => info,
            Err(err) => {
                error!("[{}] Failed to get running processes: {}", "main", err);
                return;
            }
        };

        // Check if the target process is running and get the process ID
        target_proc_id = match is_target_running(&proc_info, &proc_name) {
            Some(id) => id,
            None => {
                error!("[{}] {} is not running", "main", proc_name);
                return;
            }
        };
    } else if let Some(proc_id) = args.pid {
        // Store the target process ID
        target_proc_id = proc_id;

        // Get the name of the target process
        target_proc_name = match get_proc_name(proc_id) {
            Ok(name) => name,
            Err(err) => {
                error!("[{}] Failed to get process name: {}", "main", err);
                return;
            }
        };
    }

    // Get a handle to the target process
    let target_proc_handle: HANDLE = match get_target_proc_handle(target_proc_id) {
        Ok(handle) => handle,
        Err(err) => {
            error!("[{}] Failed to get handle to target process: {}", "main", err);
            return;
        }
    };

    // Get bitness of target process
    let mut is_wow64: i32 = 0;
    let mut target_proc_bitness: u32 = 0;
    unsafe {
        if IsWow64Process(target_proc_handle, &mut is_wow64) != 0 {
            if is_wow64 != 0 {
                info!("[{}] Target process is 32-bit", "main");
                target_proc_bitness = 32;
            } else {
                info!("[{}] Target process is 64-bit", "main");
                target_proc_bitness = 64;
            }
        } else {
            error!("[{}] Failed to determine bitness of target process", "main");
            cleanup(Some(target_proc_handle), None, None, None);
            return;
        }
    }

    // Check if the bitness of the DLL and target process match
    if dll_bitness != target_proc_bitness {
        error!("[{}] DLL bitness ({}) does not match target process bitness ({})", "main", dll_bitness, target_proc_bitness);
        cleanup(Some(target_proc_handle), None, None, None);
        return;
    }

    // =================== END INPUT VALIDATION ===================

    // At this point we have aquired and validated the following information:
    // - Process name
    // - Process ID
    // - Process handle
    // - Process bitness
    // - DLL path
    // - DLL bitness

    
    // Next, we will allocate memory in the process by calling the allocate_memory function
    // This function will return a pointer to the allocated memory which we will use later
    let dll_path_ptr = match allocate_memory(target_proc_handle, &dll_path) {
        Ok(ptr) => ptr,
        Err(e) => {
            error!("[{}] Failed to allocate memory in process: {}", "main", e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "main", win_err.trim());
            }
            cleanup(Some(target_proc_handle), None, None, None);
            return;
        }
    };

    // We will check if the pointer to the allocated memory is null
    if dll_path_ptr.is_null() {
        error!("[{}] The pointer to DLL path is null after allocation", "main");
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "main", win_err.trim());
        }
        cleanup(Some(target_proc_handle), None, None, None);
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
            cleanup(Some(target_proc_handle), Some(dll_path_ptr), None, None);
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
            cleanup(Some(target_proc_handle), Some(dll_path_ptr), None, None);
            return;
        }
    };

    // Confirm that the read back data matches the original DLL path
    if &read_back_data != &dll_path {
        error!("[{}] The written DLL path {} doesn't match with the original DLL path", "main", read_back_data);
        cleanup(Some(target_proc_handle), Some(dll_path_ptr), None, None);
        return;
    } else {
        info!("[{}] The written DLL path {} matches with the original DLL path", "main", read_back_data);

    }

    // We will get the base address of kernel32.dll by calling get_module_base_address
    // This function will return the base address of kernel32.dll in the target process
    let kernel32_str = "kernel32.dll";
    let target_kernel32_base_addr: HMODULE = match get_module_base_address(target_proc_handle, kernel32_str) {
        Ok(target_kernel32_base_addr) => target_kernel32_base_addr,
        Err(e) => {
            error!("[{}] Failed to get base address of {}: {}", "main", kernel32_str, e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "main", win_err.trim());
            }
            cleanup(Some(target_proc_handle), Some(dll_path_ptr), None, None);
            return;
        }
    };

    // Next, we need to use LoadLibraryA to load the DLL into the process
    // We will get the address of the LoadLibraryA function by calling get_function_addr
    // This function will get the base address of kernel32.dll that has been loaded into
    // the calling process (this program) and then find the relative offset of LoadLibraryA
    // which is what is returned by the function
    let loadlib_str: &str = "LoadLibraryA";
    let loadlib_offset: usize = match get_function_offset(kernel32_str, loadlib_str) {
        Ok(loadlib_offset) => loadlib_offset,
        Err(e) => {
            error!("[{}] Failed to get offset of {:?} function: {}", "main", loadlib_str, e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "main", win_err.trim());
            }
            cleanup(Some(target_proc_handle), Some(dll_path_ptr), None, None);
            return;
        }
    };

    // Now that kernel32.dll is loaded into the target process, we can get the address of LoadLibraryA
    // by adding the base address of kernel32.dll to the offset of LoadLibraryA
    let loadlib_addr: *const c_void = match get_function_addr(target_kernel32_base_addr, loadlib_offset, loadlib_str) {
        Ok(loadlib_addr) => loadlib_addr,
        Err(e) => {
            error!("[{}] Failed to calculate address of {:?}: {}", "main", loadlib_str, e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "main", win_err.trim());
            }
            cleanup(Some(target_proc_handle), Some(dll_path_ptr), None, None);
            return;
        }
    };

    // Now that we have the address of LoadLibraryA, we can call CreateRemoteThread to execute LoadLibraryA
    let loadlib_remote_thread_handle = match create_remote_thread(target_proc_handle, unsafe { std::mem::transmute(loadlib_addr) }, dll_path_ptr) {
        Ok(thread_id) => thread_id,
        Err(e) => {
            error!("[{}] Failed to create remote thread: {}", "main", e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "main", win_err.trim());
            }
            cleanup(Some(target_proc_handle), Some(dll_path_ptr), None, None);
            return;
        }
    };

    // Here we need to wait for the remote thread to finish its execution of LoadLibraryA
    info!("[{}] Waiting for remote thread to finish execution of {}", "main", loadlib_str);
    let wait_result = unsafe { WaitForSingleObject(loadlib_remote_thread_handle, winapi::um::winbase::INFINITE) };
    if wait_result != WAIT_OBJECT_0 {
        error!("[{}] Failed to wait for remote thread to finish", "main");
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "main", win_err.trim());
        }
        cleanup(Some(target_proc_handle), Some(dll_path_ptr), Some(loadlib_remote_thread_handle), None);
        return;
    }
    info!("[{}] Remote thread finished execution of {}", "main", loadlib_str);

    let injected_dll_base_addr: HMODULE = match get_module_base_address(target_proc_handle, dll_file_name) {
        Ok(injected_dll_base_addr) => injected_dll_base_addr,
        Err(e) => {
            error!("[{}] Failed to get base address of {}: {}", "main", dll_file_name, e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "main", win_err.trim());
            }
            cleanup(Some(target_proc_handle), Some(dll_path_ptr), Some(loadlib_remote_thread_handle), None);
            return;
        }
    };

    // Validate the handle to the DLL that was loaded
    info!("[{}] Validating handle to DLL that was loaded", "main");
    let mut dos_header: winapi::um::winnt::IMAGE_DOS_HEADER = unsafe { std::mem::zeroed() };
    let mut bytes_read: SIZE_T = 0;
    
    let success = unsafe {
        ReadProcessMemory(
            target_proc_handle,
            injected_dll_base_addr as winapi::shared::minwindef::LPCVOID,
            &mut dos_header as *mut _ as LPVOID,
            std::mem::size_of::<winapi::um::winnt::IMAGE_DOS_HEADER>(),
            &mut bytes_read,
        )
    };
    
    if success == 0 {
        error!("[{}] Failed to read memory", "main");
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "main", win_err.trim());
            cleanup(Some(target_proc_handle), Some(dll_path_ptr), Some(loadlib_remote_thread_handle), None);
            return;
        }
    } else {
        // Check magic number in dos_header to make sure it's 'MZ'
        if dos_header.e_magic == 0x5A4D {
            info!("[{}] Valid DLL handle", "main");
        } else {
            error!("[{}] Invalid DLL handle", "main");
            cleanup(Some(target_proc_handle), Some(dll_path_ptr), Some(loadlib_remote_thread_handle), None);
            return;
        }
    }
    cleanup(Some(target_proc_handle), Some(dll_path_ptr), Some(loadlib_remote_thread_handle), None);
}
