// pub: This keyword makes the function public, meaning it can be accessed from outside the current module. 
// This is necessary when creating a DLL because the function needs to be accessible to other code that uses the DLL.
//
// extern: This keyword is used to create an interface with C code. It's used for both importing functions 
// from C and exporting functions to C.
//
// "system": This defines which ABI the function should use. ABIs are conventions for things like how functions should be called, 
// how data should be passed around, and how the call stack should be managed. The "system" ABI will use the appropriate ABI 
// for the target operating system, which is usually the C ABI. On Windows, it's equivalent to the "C" ABI but can account for 
// differences between Windows and Unix-like platforms.
//
// _hinst_dll: This is the handle to the DLL instance. It's not used in this example, so we'll just ignore it.
//
// fdw_reason: This is the reason the function was called. It will be 1 (DLL_PROCESS_ATTACH) when the DLL is loaded and 0 (DLL_PROCESS_DETACH) when it's unloaded.
extern crate winapi;

use winapi::um::winuser::{MessageBoxW, MB_OK};
use winapi::shared::minwindef::HINSTANCE__;

use std::os::windows::ffi::OsStrExt;
use std::ffi::OsStr;
use std::iter::once;
use std::ptr::null_mut;

extern crate simplelog;
extern crate log;

use log::{info, warn, error};
use simplelog::*;
use time::macros::format_description;
use std::fs::File;

#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "system" fn DllMain(hinst_dll: *mut HINSTANCE__, fdw_reason: u32, _: usize) -> bool {
    if fdw_reason == winapi::um::winnt::DLL_PROCESS_ATTACH {
        // Initialize the logger
        let config = ConfigBuilder::new()
            .set_time_format_custom(format_description!("[hour]:[minute]:[second].[subsecond]"))
            .build();
        
        let _ = WriteLogger::init(LevelFilter::Trace, config, File::create("C:\\Users\\User\\Documents\\rust\\binaries\\dll_injector\\injector\\dll.log").expect("Failed to initialize logger"));

        info!("[{}] fwd_reason: {}", "DllMain", "DLL_PROCESS_ATTACH");
        info!("[{}] Base address of the DLL: {:?}", "DllMain", hinst_dll);
    } 
    true
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