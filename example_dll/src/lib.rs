#![allow(unused_assignments)]
#[cfg(target_os = "windows")]
extern crate winapi;

use winapi::um::winuser::{MessageBoxW, MB_OK};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ffi::{OsStr, CString, CStr, OsString};
use std::fmt;
use std::ptr;
use std::iter::once;
use std::ptr::null_mut;
use winapi::shared::windef::HWND;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::winbase::OpenFileMappingA;
use winapi::um::memoryapi::{MapViewOfFile, UnmapViewOfFile, FILE_MAP_ALL_ACCESS};
use winapi::shared::minwindef::{UINT, HINSTANCE__};
use winapi::um::winnt::{
    IMAGE_DOS_HEADER, 
    IMAGE_NT_HEADERS, 
    IMAGE_IMPORT_DESCRIPTOR, 
    LPCSTR, 
    IMAGE_OPTIONAL_HEADER,
    IMAGE_DATA_DIRECTORY,
    IMAGE_IMPORT_BY_NAME,
};

extern crate simplelog;
extern crate log;

use log::{info, warn, error};
use simplelog::*;
use std::fs::File;


#[derive(Debug)]
enum ParseError {
    GetModuleNameError(std::str::Utf8Error),
    _GetFuncNameError(std::str::Utf8Error),
    ModuleNotFoundError,
    FunctionNotFoundError,
    _UnknownError(winapi::shared::minwindef::DWORD),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ParseError::GetModuleNameError(ref e) => write!(f, "Unable to get module name: {}", e),
            ParseError::_GetFuncNameError(ref e) => write!(f, "Unable to get function name: {}", e),
            ParseError::ModuleNotFoundError => write!(f, "Module not found"),
            ParseError::FunctionNotFoundError => write!(f, "Function not found"),
            ParseError::_UnknownError(e) => write!(f, "Unknown error occurred: {}", e),
        }
    }
}

#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "system" fn DllMain(_hinst_dll: usize, fdw_reason: u32, _: usize) -> bool {
    if fdw_reason == winapi::um::winnt::DLL_PROCESS_ATTACH {
        // Initialize the logger
        let _ = WriteLogger::init(LevelFilter::Info, Config::default(), File::create("dll.log").expect("Failed to initialize logger"));

        let target_module_name: &str = "USER32.dll";
        let target_function_name: &str = "MessageBoxA";
        let file_mapping_name: &str = "Local\\__AA__AA__";
        info!("[{}] fwd_reason: {}", "DllMain", "DLL_PROCESS_ATTACH");
        info!("[{}] Beginning hooking", "DllMain");
        info!("[{}] Target module: {}", "DllMain", target_module_name);
        info!("[{}] Target function: {}", "DllMain", target_function_name);
        info!("[{}] File mapping name: {}", "DllMain", file_mapping_name);
        begin_hooking(target_module_name, target_function_name, file_mapping_name);
    }
    true
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

fn begin_hooking(target_module_name: &str, target_function_name: &str, file_mapping_name: &str) {
    // This will store the base address of the currently running EXE
    // That is, the process which this DLL has been injected into
    info!("[{}] Getting EXE base address", "begin_hooking");
    let exe_base_addr: usize = match get_exe_base_address() {
        Ok(addr) => {
            info!("[{}] Successfully retrieved EXE base address", "begin_hooking");
            addr
        }
        Err(e) => {
            error!("[{}] Failed to get EXE base address: {}", "begin_hooking", e);
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "begin_hooking", win_err);
            }
            return;
        },
    };

    // If module has been loaded, perform the hook
    if exe_base_addr != 0 {
        // To perform the hook, we need to parse the PE file of the target module
        // to identify the address of the IAT. This starts with getting the address
        // of the import directory
        info!("[{}] Getting import directory address", "begin_hooking");
        let import_directory_addr: usize = get_import_directory_addr(exe_base_addr);

        // The Import Directory contains a list of IMAGE_IMPORT_DESCRIPTOR structures
        // which contain the following members: OriginalFirstThunk and FirstThunk
        //
        // OriginalFirstThunk is a pointer to an array of IMAGE_THUNK_DATA structures.
        // This array is often called the Import Name Table (INT) and is used to store 
        // the names of the imported functions. 
        //
        // FirstThunk is also a pointer to an array of IMAGE_THUNK_DATA structures. 
        // This array is often called the Import Address Table (IAT) and is used to
        // store the addresses of the imported functions. Which is exactly what we need

        // This function will use the import directory address to locate the IAT of the target module
        info!("[{}] Locating addresses of IAT and INT in target module", "begin_hooking");
        let iat_int_addrs: (usize, usize) = match locate_iat_and_int(import_directory_addr, exe_base_addr, target_module_name) {
            Ok(addrs) => {
                info!("[{}] Successfully located IAT and INT in target module", "begin_hooking");
                addrs
            },
            Err(e) => { 
                error!("[{}] Failed to locate IAT and INT: {}", "begin_hooking", e);
                if let Some(win_err) = get_last_error() {
                    error!("[{}] Windows error: {}", "begin_hooking", win_err);
                }
                return;
            },
        };

        // Store the addresses of the INT and IAT
        let int_addr: usize = iat_int_addrs.0;
        let iat_addr: usize = iat_int_addrs.1;

        // Now that we have the address of the INT and IAT, we need the address of the target function
        info!("[{}] Getting address of target function", "begin_hooking");
        let target_func_data: (usize, *mut usize) = match get_func_address_in_iat(int_addr, iat_addr, exe_base_addr, target_function_name) {
            Ok(data) => {
                info!("[{}] Successfully retrieved address of target function", "begin_hooking");
                data
            },
            Err(e) => {
                error!("[{}] Failed to get address of target function: {}", "begin_hooking", e);
                if let Some(win_err) = get_last_error() {
                    error!("[{}] Windows error: {}", "begin_hooking", win_err);
                }
                return;
            },
        };

        let  _target_func_addr: usize = target_func_data.0;
        let target_func_addr_ptr: *mut usize = target_func_data.1;

        // Finally, we need the address of the hook function
        let hook_func_addr: usize = hook_func as usize;

        // Now that we have all the addresses we need, we can perform the hook
        info!("[{}] Performing hook", "begin_hooking");
        perform_hook(target_func_addr_ptr, hook_func_addr);

        // Open the file mapping, create a view of it, and signal the event
        info!("[{}] Signalling event", "begin_hooking");
        let _file_mapping_handle: () = match set_event(file_mapping_name) {
            Ok(handle) => {
                info!("[{}] Successfully signalled event", "begin_hooking");
                handle
            },
            Err(e) => {
                error!("[{}] Failed to signal event: {}", "begin_hooking", e);
                if let Some(win_err) = get_last_error() {
                    error!("[{}] Windows error: {}", "begin_hooking", win_err);
                }
                return;
            },
        };
    }
}

fn test_msgbox(arg1: &str, arg2: &str) {
    let message: String = format!("{}: {}", arg1, arg2);
    let title: &str = "DLL Message";

    let wide_message: Vec<u16> = OsStr::new(message.as_str()).encode_wide().chain(once(0)).collect();
    let wide_title: Vec<u16> = OsStr::new(title).encode_wide().chain(once(0)).collect();

    unsafe {
        MessageBoxW(null_mut(), wide_message.as_ptr(), wide_title.as_ptr(), MB_OK);
    };
}

// This function will return the base address of the EXE which this DLL has been injected into
fn get_exe_base_address() -> Result<usize, winapi::shared::minwindef::DWORD> {
    // We can get the base address of the EXE by passing a null value to GetModuleHandleA
    info!("[{}] Calling GetModuleHandleA with null argument", "get_exe_base_address");
    let exe_handle: *mut HINSTANCE__ = unsafe { winapi::um::libloaderapi::GetModuleHandleA(std::ptr::null()) };

    // If the handle is null, the function failed
    if exe_handle.is_null() {
        error!("[{}] Returned handle is null", "get_exe_base_address");
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "get_exe_base_address", win_err);
        }
        Err(unsafe { winapi::um::errhandlingapi::GetLastError() })
    } else {
        info!("[{}] Successfully retrieved handle", "get_exe_base_address");
        info!("[{}] EXE base address: 0x{:X}", "get_exe_base_address", exe_handle as usize);
        Ok(exe_handle as usize)
    }
}

// This function will return the address of the Import Directory of the EXE
fn get_import_directory_addr(base_addr: usize) -> usize {
    info!("[{}] Getting address of Import Directory", "get_import_directory_addr");
    info!("[{}] Base address: 0x{:X}", "get_import_directory_addr", base_addr);
    unsafe {
        // The base address is set to a pointer to an IMAGE_DOS_HEADER structure 
        let dos_header: *const IMAGE_DOS_HEADER = base_addr as *const IMAGE_DOS_HEADER;
        info!("[{}] Address of IMAGE_DOS_HEADER: 0x{:X}", "get_import_directory_addr", dos_header as usize);

        // The first 64 bytes of the PE file is the IMAGE_DOS_HEADER structure
        // which has a member called e_lfanew which is the offset to the PE header
        let pe_header: usize = base_addr + (*dos_header).e_lfanew as usize;
        info!("[{}] Address of PE header: 0x{:X}", "get_import_directory_addr", pe_header);

        // The PE header is set as a pointer to an IMAGE_NT_HEADERS structure
        let nt_headers: *const IMAGE_NT_HEADERS = pe_header as *const IMAGE_NT_HEADERS;
        info!("[{}] Address of IMAGE_NT_HEADERS: 0x{:X}", "get_import_directory_addr", nt_headers as usize);

        // The Optional Header is a member of the IMAGE_NT_HEADERS structure
        let optional_header: &IMAGE_OPTIONAL_HEADER = &(*nt_headers).OptionalHeader;
        info!("[{}] Address of IMAGE_OPTIONAL_HEADER: 0x{:X}", "get_import_directory_addr", optional_header as *const IMAGE_OPTIONAL_HEADER as usize);

        // The Import Directory is one of the data directories in the Optional Header
        let import_directory: &IMAGE_DATA_DIRECTORY = &optional_header.DataDirectory[winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
        info!("[{}] Address of IMAGE_DATA_DIRECTORY: 0x{:X}", "get_import_directory_addr", import_directory as *const IMAGE_DATA_DIRECTORY as usize);

        // The address of the Import Directory is its relative virtual address (RVA) added to the base address
        let import_directory_addr: usize = base_addr + import_directory.VirtualAddress as usize;
        info!("[{}] Address of Import Directory: 0x{:X}", "get_import_directory_addr", import_directory_addr);

        import_directory_addr
    }
}

// This function iterates through the IMAGE_IMPORT_DESCRIPTOR structures by looking at the OriginalFirstThunk member
// which is a pointer to an array of IMAGE_THUNK_DATA structures. This array is often called the Import Name Table (INT)
// and is used to store the names of the imported functions. Once the target module is found, the FirstThunk member
// is used to get the address of the IAT
fn locate_iat_and_int(import_directory_addr: usize, exe_base_addr: usize, target_module: &str) -> Result<(usize, usize), ParseError> {
    info!("[{}] Import Directory address: 0x{:X}", "locate_iat_and_int", import_directory_addr);
    info!("[{}] EXE base address: 0x{:X}", "locate_iat_and_int", exe_base_addr);
    info!("[{}] Target module: {}", "locate_iat_and_int", target_module);

    let mut import_descriptor: *mut IMAGE_IMPORT_DESCRIPTOR = import_directory_addr as *mut IMAGE_IMPORT_DESCRIPTOR;
    // The Name member of the IMAGE_IMPORT_DESCRIPTOR structure stores an RVA to the name of the imported module
    // relative to the base address of the EXE. We can get the address of the module name by adding the RVA to the
    // base address
    unsafe {  
        info!("[{}] Iterating through IMAGE_IMPORT_DESCRIPTOR structures", "locate_iat_and_int");
        while (*import_descriptor).FirstThunk != 0 {
            let module_name_rva: u32 = (*import_descriptor).Name;
            let module_name_va: *const u8 = (exe_base_addr as isize + module_name_rva as isize) as *const u8;
            let module_name_ptr: *const u8 = module_name_va as *const u8;
            let module_name_c: &CStr = CStr::from_ptr(module_name_ptr as *const i8);

            let module_name_str: &str = match module_name_c.to_str() {
                Ok(name) => {
                    info!("[{}] Module name: {}", "locate_iat_and_int", name);
                    name
                },
                Err(e) => {
                    error!("[{}] Error getting module name: {}", "locate_iat_and_int", e);
                    if let Some(win_err) = get_last_error() {
                        error!("[{}] Windows error: {}", "locate_iat_and_int", win_err);
                    }
                    return Err(ParseError::GetModuleNameError(e))
                },
            };
    
            // If the module name matches the target module, we return the addresses of both the IAT and the INT
            if module_name_str == target_module {
                info!("[{}] Target module found", "locate_iat_and_int");
                let iat_addr: usize = (exe_base_addr  + (*import_descriptor).FirstThunk as usize) as usize;
                let int_addr: usize = (exe_base_addr  + *(*import_descriptor).u.OriginalFirstThunk_mut() as usize) as usize;
                info!("[{}] Address of Import Name Table (INT): 0x{:X}", "locate_iat_and_int", int_addr);
                info!("[{}] Address of Import Address Table (IAT): 0x{:X}", "locate_iat_and_int", iat_addr);
                return Ok((int_addr, iat_addr));
            }
    
            import_descriptor = import_descriptor.offset(1);
        }
    }

    error!("[{}] Target module not found", "locate_iat_and_int");
    Err(ParseError::ModuleNotFoundError)
}

// Function to get the address of a specific function in the Import Address Table (IAT)
fn get_func_address_in_iat(int_addr: usize, iat_addr: usize, exe_base_addr: usize, target_function: &str) -> Result<(usize, *mut usize), ParseError> {
    // Cast the addresses as mutable pointers to usize. These pointers are referring to the Import Name Table (INT) and Import Address Table (IAT).
    let mut int_ptr: *mut usize = int_addr as *mut usize;
    let mut iat_ptr: *mut usize = iat_addr as *mut usize;

    info!("[{}] Retrieving address of function: {}", "get_func_address_in_iat", target_function);
    info!("[{}] Address of Import Name Table (INT): 0x{:X}", "get_func_address_in_iat", int_addr);
    info!("[{}] Address of Import Address Table (IAT): 0x{:X}", "get_func_address_in_iat", iat_addr);
    info!("[{}] EXE base address: 0x{:X}", "get_func_address_in_iat", exe_base_addr);

    unsafe {
        // Iterate over the INT and IAT together
        info!("[{}] Iterating through Import Name Table (INT) and Import Address Table (IAT)", "get_func_address_in_iat");
        while *int_ptr != 0 {
            // Check if the entry is imported by name or ordinal. If the highest bit is set, the function is imported by ordinal.
            if *int_ptr & 0x80000000 == 0 {
                // When the entry is imported by name, the value at the INT pointer is a Relative Virtual Address (RVA). This RVA points to an 
                // IMAGE_IMPORT_BY_NAME structure that contains the name of the function.
                let import_by_name_rva: usize = *int_ptr;

                // Convert the RVA to a Virtual Address (VA) by adding it to the base address of the executable. Cast the result to a pointer to the
                // IMAGE_IMPORT_BY_NAME structure.
                let import_by_name_va: *mut IMAGE_IMPORT_BY_NAME = (exe_base_addr as isize + import_by_name_rva as isize) as *mut IMAGE_IMPORT_BY_NAME;

                // The Name member of the IMAGE_IMPORT_BY_NAME structure is a pointer to a null-terminated string. This string is the name of the imported function.
                let func_name_c: &CStr = CStr::from_ptr((*import_by_name_va).Name.as_ptr());
                let func_name_str: std::borrow::Cow<'_, str> = func_name_c.to_string_lossy();

                // If the function name matches the target function, return the corresponding address from the IAT. This address is where the application
                // will jump to when the imported function is called. Also, return the mutable pointer to the function address in the IAT.
                if func_name_str == target_function {
                    info!("[{}] Target function found: {}", "get_func_address_in_iat", func_name_str);
                    info!("[{}] Function address: 0x{:X}", "get_func_address_in_iat", *iat_ptr);
                    return Ok((*iat_ptr, iat_ptr));
                }
            } else {
                warn!("[{}] Function imported by ordinal, skipping.", "get_func_address_in_iat");
            }

            // If this isn't the function we're looking for, increment the pointers to the next entries in the INT and IAT
            int_ptr = int_ptr.offset(1);
            iat_ptr = iat_ptr.offset(1);
        }
    }

    // If we've checked all entries in the INT and IAT and haven't found the target function, return an error.
    error!("[{}] Target function not found", "get_func_address_in_iat");
    Err(ParseError::FunctionNotFoundError)
}

// Overwrite the address being pointed to by target_func_addr_ptr with the address of hook_func_addr
fn perform_hook(target_func_addr: *mut usize, hook_func_addr: usize) {
    info!("[{}] Performing hook", "perform_hook");
    info!("[{}] Address of target function: 0x{:X}", "perform_hook", target_func_addr as usize);
    info!("[{}] Address of hook function: 0x{:X}", "perform_hook", hook_func_addr);
    info!("[{}] Value of target function address before hook: 0x{:X}", "perform_hook", unsafe { *target_func_addr });
    unsafe {
        *target_func_addr = hook_func_addr;   
    }
    info!("[{}] Value of target function address after hook: 0x{:X}", "perform_hook", unsafe { *target_func_addr });
}

// This function will open the file mapping created by the injector process
// It will create a view of the file mapping, retrieve the pointer to the Event object, and set the Event
fn set_event(file_mapping_name: &str) -> std::io::Result<()> {
    // To store error messages
    let err_msg: String;

    info!("[{}] Setting event", "set_event");
    info!("[{}] File mapping name: {}", "set_event", file_mapping_name);

    // Check if the file mapping name is valid
    if file_mapping_name.is_empty() || file_mapping_name.contains('\0') {
        error!("[{}] Invalid file mapping name: name is null terminated or empty", "set_event");
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid file mapping name."));
    }

    unsafe {
        // Convert the file mapping name to a C-style string
        let c_file_mapping_name = std::ffi::CString::new(file_mapping_name).unwrap();

        // Open the file mapping
        info!("[{}] Calling OpenFileMappingA", "set_event");
        let mut file_mapping_handle = OpenFileMappingA(FILE_MAP_ALL_ACCESS, 0, c_file_mapping_name.as_ptr());
        if file_mapping_handle.is_null() {
            error!("[{}] Failed to open file mapping", "set_event");
            if let Some(win_err) = get_last_error() {
                error!("Windows error: {}", win_err);
            }
            err_msg = format!("Failed to open file mapping. Windows error code: {}", GetLastError());
            return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg.as_str()));
        } else {
            info!("[{}] File mapping opened successfully", "set_event");
            info!("[{}] File mapping handle: 0x{:X}", "set_event", file_mapping_handle as usize);
        }

        // Create a view of the file mapping
        info!("[{}] Calling MapViewOfFile", "set_event");
        let file_view_ptr = MapViewOfFile(file_mapping_handle, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if file_view_ptr.is_null() {
            // If the view creation fails, close the file mapping handle and return an error
            error!("[{}] Failed to create view of file mapping", "set_event");
            if let Some(win_err) = get_last_error() {
                error!("Windows error: {}", win_err);
            }

            info!("[{}] Closing file mapping handle", "set_event");
            let result = winapi::um::handleapi::CloseHandle(file_mapping_handle);
            if result == 0 {
                error!("[{}] Failed to close file mapping handle", "set_event");
                if let Some(win_err) = get_last_error() {
                    error!("Windows error: {}", win_err);
                }
            } else {
                info!("[{}] File mapping handle closed successfully", "set_event");
            }

            info!("[{}] Setting file mapping handle to INVALID_HANDLE_VALUE", "set_event");
            file_mapping_handle = winapi::um::handleapi::INVALID_HANDLE_VALUE;

            err_msg = format!("Failed to create view of file mapping. Windows error code: {}", GetLastError());
            return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg));
        } else {
            info!("[{}] View of file mapping created successfully", "set_event");
            info!("[{}] View of file mapping address: 0x{:X}", "set_event", file_view_ptr as usize);
        }

        // Retrieve the Event handle from the file mapping
        info!("[{}] Retrieving Event handle from file mapping", "set_event");
        let mut event_handle = *(file_view_ptr as *mut winapi::um::winnt::HANDLE);
        info!("[{}] Event handle: 0x{:X}", "set_event", event_handle as usize);

        // Unmap the view of the file mapping
        info!("[{}] Calling UnmapViewOfFile", "set_event");
        let result = UnmapViewOfFile(file_view_ptr);
        if result == 0 {
            // If the unmap fails, close the file mapping handle and return an error
            error!("[{}] Failed to unmap view of file mapping", "set_event");
            if let Some(win_err) = get_last_error() {
                error!("Windows error: {}", win_err);
            }

            info!("[{}] Closing file mapping handle", "set_event");
            let result = winapi::um::handleapi::CloseHandle(file_mapping_handle);
            if result == 0 {
                error!("[{}] Failed to close file mapping handle", "set_event");
                if let Some(win_err) = get_last_error() {
                    error!("Windows error: {}", win_err);
                }
            } else {
                info!("[{}] File mapping handle closed successfully", "set_event");
            }

            info!("[{}] Setting file mapping handle to INVALID_HANDLE_VALUE", "set_event");
            file_mapping_handle = winapi::um::handleapi::INVALID_HANDLE_VALUE;

            err_msg = format!("Failed to unmap view of file mapping. Windows error code: {}", GetLastError());
            return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg));
        } else {
            info!("[{}] View of file mapping unmapped successfully", "set_event");
        }

        if event_handle.is_null() {
            // If the Event handle is null, close the file mapping handle and return an error
            error!("[{}] Event handle retrieved from file mapping is null", "set_event");
            info!("[{}] Closing file mapping handle", "set_event");
            let result = winapi::um::handleapi::CloseHandle(file_mapping_handle);
            if result == 0 {
                error!("[{}] Failed to close file mapping handle", "set_event");
                if let Some(win_err) = get_last_error() {
                    error!("Windows error: {}", win_err);
                }
            } else {
                info!("[{}] File mapping handle closed successfully", "set_event");
            }

            info!("[{}] Setting file mapping handle to INVALID_HANDLE_VALUE", "set_event");
            file_mapping_handle = winapi::um::handleapi::INVALID_HANDLE_VALUE;
            err_msg = format!("Event handle retrieved from file mapping is null.");
            return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg.as_str()));
        } 

        // Close the file mapping handle
        info!("[{}] Closing file mapping handle", "set_event");
        let result = winapi::um::handleapi::CloseHandle(file_mapping_handle);
        if result == 0 {
            // If the close fails, return an error
            error!("[{}] Failed to close file mapping handle", "set_event");
            if let Some(win_err) = get_last_error() {
                error!("Windows error: {}", win_err);
            }

            info!("[{}] Setting file mapping handle to INVALID_HANDLE_VALUE", "set_event");
            file_mapping_handle = winapi::um::handleapi::INVALID_HANDLE_VALUE;
            err_msg = format!("Failed to close file mapping handle. Windows error code: {}", GetLastError());
            return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg.as_str()));
        } else {
            // If the close succeeds, set the file mapping handle to INVALID_HANDLE_VALUE
            info!("[{}] File mapping handle closed successfully", "set_event");
            info!("[{}] Setting file mapping handle to INVALID_HANDLE_VALUE", "set_event");
            file_mapping_handle = winapi::um::handleapi::INVALID_HANDLE_VALUE;
        }

        // Set the Event
        info!("[{}] Calling SetEvent", "set_event");
        if winapi::um::synchapi::SetEvent(event_handle) == 0 {
            error!("[{}] Failed to set event", "set_event");
            if let Some(win_err) = get_last_error() {
                error!("Windows error: {}", win_err);
            }
            err_msg = format!("Failed to set event. Windows error code: {}", GetLastError());
            return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg.as_str()));
        } else {
            info!("[{}] Event set successfully", "set_event");
        }

        // Close the Event handle
        info!("[{}] Closing Event handle", "set_event");
        let result = winapi::um::handleapi::CloseHandle(event_handle);
        if result == 0 {
            // If the close fails, return an error
            error!("[{}] Failed to close event handle", "set_event");
            if let Some(win_err) = get_last_error() {
                error!("Windows error: {}", win_err);
            }

            info!("[{}] Setting event handle to INVALID_HANDLE_VALUE", "set_event");
            event_handle = winapi::um::handleapi::INVALID_HANDLE_VALUE;
            err_msg = format!("Failed to close event handle. Windows error code: {}", GetLastError());
            return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg.as_str()));
        } else {
            // If the close succeeds, set the event handle to INVALID_HANDLE_VALUE
            info!("[{}] Event handle closed successfully", "set_event");
            info!("[{}] Setting event handle to INVALID_HANDLE_VALUE", "set_event");
            event_handle = winapi::um::handleapi::INVALID_HANDLE_VALUE;
        }
    }

    Ok(())
}



#[no_mangle]
pub unsafe extern "system" fn hook_func(h_wnd: HWND, lp_text: LPCSTR, lp_caption: LPCSTR, u_type: UINT) -> winapi::ctypes::c_int {
    // Convert the LPCSTR to a Rust string
    let c_str: &CStr = CStr::from_ptr(lp_text);
    let str_slice: &str = c_str.to_str().unwrap();
    
    // Your custom message
    let custom_message: String = format!("This is what the next message box will say: {}", str_slice);
    
    // Display your custom message
    winapi::um::winuser::MessageBoxA(h_wnd, custom_message.as_ptr() as LPCSTR, "Pre-alert".as_ptr() as LPCSTR, u_type);
    
    // Display the original MessageBox
    winapi::um::winuser::MessageBoxA(h_wnd, lp_text, lp_caption, u_type)
}








