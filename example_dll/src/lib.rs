#[cfg(target_os = "windows")]
extern crate winapi;

use winapi::um::winuser::{MessageBoxW, MB_OK};
use core::panic;
use std::os::windows::ffi::OsStrExt;
use std::ffi::{OsStr, CStr};
use std::fmt;
use std::iter::once;
use std::ptr::null_mut;
use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_IMPORT_DESCRIPTOR};


#[derive(Debug)]
enum ParseError {
    GetModuleNameError(std::str::Utf8Error),
    ModuleNotFoundError,
    UnknownError(winapi::shared::minwindef::DWORD),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ParseError::GetModuleNameError(ref e) => write!(f, "Unable to get module name: {}", e),
            ParseError::ModuleNotFoundError => write!(f, "Module not found"),
            ParseError::UnknownError(e) => write!(f, "Unknown error occurred: {}", e),
        }
    }
}


#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "system" fn DllMain(_hinst_dll: usize, _fdw_reason: u32, _: usize) -> bool {
    // This is the name of the DLL which contains the function we want to hook
    // followed by the name of the function itself
    let target_module_name: &str = "msvcrt.dll";
    let target_function_name: &str = "fwrite";

    // The following function will test if the target module has been loaded
    // If it has, it will perform the hook. Otherwisem, it will hook LoadLibraryA
    perform_hook_if_module_loaded(target_module_name);

    true
}


fn perform_hook_if_module_loaded(target_module_name: &str) {
    // This will store the base address of the currently running EXE
    // That is, the process which this DLL has been injected into
    let exe_base_addr: usize = match get_exe_base_address() {
        Ok(addr) => {
            addr
        }
        Err(e) => {
            test_msgbox("Failed to get EXE base address", format!("{}", e).as_str());
            panic!("Failed to get EXE base address: {}", e)
        },
    };

    // If module has been loaded, perform the hook
    if exe_base_addr != 0 {
        // To perform the hook, we need to parse the PE file of the target module
        // to identify the address of the IAT. This starts with getting the address
        // of the import directory
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

        // This function will use the import directory address to locate the IAT
        let iat_addr: usize = match locate_iat(import_directory_addr, exe_base_addr, target_module_name) {
            Ok(addr) => {
                addr
            },
            Err(e) => { 
                test_msgbox("Failed to locate IAT", format!("{}", e).as_str());
                panic!("Failed to locate IAT: {}", e) 
            },
        };

        test_msgbox("IAT Address", format!("{:X}", iat_addr).as_str());

        // Now that we have the address of the IAT, we can perform the hook
        // by calling the perform_hook function which will return the address
        // of the original function
        //let original_function: usize = perform_hook(iat_addr);
    }
}

fn test_msgbox(arg1: &str, arg2: &str) {
    let message = format!("{}: {}", arg1, arg2);
    let title = "DLL Message";

    let wide_message: Vec<u16> = OsStr::new(message.as_str()).encode_wide().chain(once(0)).collect();
    let wide_title: Vec<u16> = OsStr::new(title).encode_wide().chain(once(0)).collect();

    unsafe {
        MessageBoxW(null_mut(), wide_message.as_ptr(), wide_title.as_ptr(), MB_OK);
    };
}

// This function will return the base address of the EXE which this DLL has been injected into
fn get_exe_base_address() -> Result<usize, winapi::shared::minwindef::DWORD> {
    // We can get the base address of the EXE by passing a null value to GetModuleHandleA
    let exe_handle = unsafe { winapi::um::libloaderapi::GetModuleHandleA(std::ptr::null()) };

    // If the handle is null, the function failed
    if exe_handle.is_null() {
        Err(unsafe { winapi::um::errhandlingapi::GetLastError() })
    } else {
        Ok(exe_handle as usize)
    }
}

// This function will return the address of the Import Directory of the EXE
fn get_import_directory_addr(base_addr: usize) -> usize {
    unsafe {
        // The base address is set to a pointer to an IMAGE_DOS_HEADER structure 
        let dos_header = base_addr as *const IMAGE_DOS_HEADER;

        // The first 64 bytes of the PE file is the IMAGE_DOS_HEADER structure
        // which has a member called e_lfanew which is the offset to the PE header
        let pe_header = base_addr + (*dos_header).e_lfanew as usize;

        // The PE header is set as a pointer to an IMAGE_NT_HEADERS structure
        let nt_headers = pe_header as *const IMAGE_NT_HEADERS;

        // The Optional Header is a member of the IMAGE_NT_HEADERS structure
        let optional_header = &(*nt_headers).OptionalHeader;

        // The Import Directory is one of the data directories in the Optional Header
        let import_directory = &optional_header.DataDirectory[winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_IMPORT as usize];

        // The address of the Import Directory is its relative virtual address (RVA) added to the base address
        let import_directory_addr = base_addr + import_directory.VirtualAddress as usize;

        import_directory_addr
    }
}

// This function iterates through the IMAGE_IMPORT_DESCRIPTOR structures by looking at the OriginalFirstThunk member
// which is a pointer to an array of IMAGE_THUNK_DATA structures. This array is often called the Import Name Table (INT)
// and is used to store the names of the imported functions. Once the target module is found, the FirstThunk member
// is used to get the address of the IAT
fn locate_iat(import_directory_addr: usize, exe_base_addr: usize, target_module: &str) -> Result<usize, ParseError> {
    let mut import_descriptor: *mut IMAGE_IMPORT_DESCRIPTOR = import_directory_addr as *mut IMAGE_IMPORT_DESCRIPTOR;
    unsafe {  
        while *(*import_descriptor).u.OriginalFirstThunk_mut() != 0 { 
            // The Name member of the IMAGE_IMPORT_DESCRIPTOR structure stores an RVA to the name of the imported module
            // relative to the base address of the EXE. We can get the address of the module name by adding the RVA to the
            // base address
            let module_name_rva = (*import_descriptor).Name;
            let module_name_va = (exe_base_addr as isize + module_name_rva as isize) as *const u8;
            let module_name_ptr = module_name_va as *const u8;
            let module_name_c = CStr::from_ptr(module_name_ptr as *const i8);

            let module_name_str = match module_name_c.to_str() {
                Ok(name) => name,
                Err(e) => return Err(ParseError::GetModuleNameError(e)),
            };
    
            // If the module name matches the target module, we can return the address of the IAT
            if module_name_str == target_module {
                return Ok((exe_base_addr  + (*import_descriptor).FirstThunk as usize) as usize);
            }
    
            import_descriptor = import_descriptor.offset(1);
        }
    }

    Err(ParseError::ModuleNotFoundError)
}




// Placeholder function
fn perform_hook(iat: usize) -> usize {
    // Hook the function and return the address of the original function
    0 // Placeholder return
}

fn hook_function(arg: usize, ) -> usize {
    // Perform the process on arg

    // Retrieve the address of the original function

    // Call the original function
    // original_function(arg)
    0 // Placeholder return
}

fn hook_loadlib() {
    // Hook LoadLibraryA
}

fn loadlib_hook_function(module_name: &str) {
    // Let the original function do its thing

    // Check if the loaded module is the one we're interested in
    if module_name == "msvcrt.dll" {
        perform_hook_if_module_loaded(module_name);
    }
}







