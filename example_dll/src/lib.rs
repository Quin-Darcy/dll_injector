#[cfg(target_os = "windows")]
extern crate winapi;

use winapi::um::winuser::{MessageBoxW, MB_OK};
use std::os::windows::ffi::OsStrExt;
use std::ffi::OsStr;
use std::iter::once;
use std::ptr::null_mut;
use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_IMPORT_DESCRIPTOR};

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

// This function initially checks if the target module has been loaded
fn perform_hook_if_module_loaded(module_name: &str) {
    // If the target module has been loaded, its base address will be returned
    let module_base_addr: usize = get_module_base_address(module_name);

    // If module has been loaded, perform the hook
    if module_base_addr != 0 {
        // To perform the hook, we need to parse the PE file of the target module
        // to identify the address of the IAT. This starts with getting the address
        // of the import directory
        let import_directory_addr: usize = get_import_directory_addr(module_base_addr);

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
        let iat: usize = locate_iat(import_directory_addr);

        // Now that we have the address of the IAT, we can perform the hook
        // by calling the perform_hook function which will return the address
        // of the original function
        let original_function: usize = perform_hook(iat);
    }
}

fn test_msgbox(arg1: usize) {
    let message = format!("{}", arg1);
    let title = "DLL Message";

    let wide_message: Vec<u16> = OsStr::new(message.as_str()).encode_wide().chain(once(0)).collect();
    let wide_title: Vec<u16> = OsStr::new(title).encode_wide().chain(once(0)).collect();

    unsafe {
        MessageBoxW(null_mut(), wide_message.as_ptr(), wide_title.as_ptr(), MB_OK);
    };
}

// This function will return the base address of the target module, if it has been loaded
fn get_module_base_address(module_name: &str) -> usize {
    // We first check to see if the module has already been loaded
    // by calling GetModuleHandleA with the name of the target module
    let module_name_c = std::ffi::CString::new(module_name).unwrap();
    let module_handle = unsafe { winapi::um::libloaderapi::GetModuleHandleA(module_name_c.as_ptr()) };

    // If module_handle contains a null value, then the module has not been loaded
    if module_handle == null_mut() {
        // In this case, we need to hook LoadLibraryA 
        hook_loadlib();
        0
    } else {
        module_handle as usize
    }
}

// This function will return the address of the Import Directory
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

// As described above, this function will return the address of the IAT
fn locate_iat(import_directory_addr: usize) -> usize {
    // The Import Directory is an array of IMAGE_IMPORT_DESCRIPTOR structures
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







