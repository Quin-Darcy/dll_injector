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
use std::f32::consts::E;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ffi::{OsStr, CString, CStr, OsString};
use std::fmt;
use std::ptr;
use std::iter::once;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, Ordering};

use winapi::shared::windef::HWND;
use winapi::shared::minwindef::{DWORD, HINSTANCE, FARPROC, BOOL};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};
use winapi::shared::minwindef::{UINT, HINSTANCE__};
use winapi::um::winnt::{MEM_COMMIT, PAGE_EXECUTE_READWRITE};
use winapi::um::winuser::LPMSG;

extern crate simplelog;
extern crate log;

use log::{info, warn, error};
use simplelog::*;
use time::macros::format_description;
use std::fs::File;

const NUM_STOLEN_BYTES: usize = 18;

static TRAMPOLINE_FUNC: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());

#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "system" fn DllMain(hinst_dll: *mut HINSTANCE__, fdw_reason: u32, _: usize) -> bool {
    if fdw_reason == winapi::um::winnt::DLL_PROCESS_ATTACH {
        // Initialize the logger
        let config = ConfigBuilder::new()
            .set_time_format_custom(format_description!("[hour]:[minute]:[second].[subsecond]"))
            .build();
        
        let _ = WriteLogger::init(LevelFilter::Trace, config, File::create("C:\\Users\\User\\Documents\\rust\\binaries\\dll_injector\\injector\\dll.log").expect("Failed to initialize logger"));

        let target_module_name: &str = "USER32.dll";
        let target_function_name: &str = "GetMessageW";

        info!("[{}] fwd_reason: {}", "DllMain", "DLL_PROCESS_ATTACH");
        info!("[{}] Base address of the DLL: {:?}", "DllMain", hinst_dll);
        info!("[{}] Target module name: {}", "DllMain", target_module_name);
        info!("[{}] Target function name: {}", "DllMain", target_function_name);

        begin_hooking(target_module_name, target_function_name);
    } 
    true
}

fn begin_hooking(target_module_str: &str, target_function_name: &str) {
    // Get the address of the target function
    let target_func_addr: *const u8 = match get_target_func_addr(target_module_str, target_function_name) {
        Ok(addr) => addr,
        Err(_) => {
            error!("[{}] Failed to get address of {}", "begin_hooking", target_function_name);
            return;
        }
    };

    // Allocate buffer for stolen bytes
    let mut stolen_bytes: [u8; NUM_STOLEN_BYTES] = [0; NUM_STOLEN_BYTES];

    // Copy the stolen bytes into the buffer
    unsafe {
        ptr::copy(target_func_addr, stolen_bytes.as_mut_ptr(), NUM_STOLEN_BYTES);
    }

    // Log the stolen bytes
    let hex_bytes: Vec<String> = stolen_bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    let hex_str = hex_bytes.join(" ");

    info!("[{}] {} bytes stolen from {}: {}", "begin_hooking", NUM_STOLEN_BYTES, target_function_name, hex_str);

    // Now we create the trampline function
    let trampoline: *mut u8 = match create_trampoline(&stolen_bytes, target_func_addr) {
        Ok(trampoline) => trampoline,
        Err(_) => {
            error!("[{}] Failed to create trampoline function", "begin_hooking");
            return;
        }
    };

    // Set the trampoline function in the global variable
    TRAMPOLINE_FUNC.store(trampoline as *mut _, Ordering::SeqCst);

    // Get the address of the hook function
    let hook_func_addr = hook_func as *const () as *mut u8;

    // Now we actually hook the function
    match set_hook(target_func_addr, hook_func_addr) {
        Ok(_) => {
            info!("[{}] Hooked {} successfully", "begin_hooking", target_function_name);
            info!("[{}] Trampoline function address: 0x{:X}", "begin_hooking", trampoline as usize);
            info!("[{}] Hook function address: 0x{:X}", "begin_hooking", hook_func_addr as usize);
        },
        Err(_) => {
            error!("[{}] Failed to hook {}", "begin_hooking", target_function_name);
            return;
        }
    }
}

fn get_target_func_addr(target_module_str: &str, target_function_name: &str) -> Result<*const u8, DWORD> {
    // Convert the target module name to a CString
    let target_module_cstr: CString = match CString::new(target_module_str) {
        Ok(cstr) => cstr,
        Err(_) => {
            error!("[{}] Failed to convert target module name to CString", "get_target_func_addr");
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "get_target_func_addr", win_err);
            }
            return Err(0);
        }
    };
    // Convert the target function name to a CString
    let target_function_cstr: CString = match CString::new(target_function_name) {
        Ok(cstr) => cstr,
        Err(_) => {
            error!("[{}] Failed to convert target function name to CString", "get_target_func_addr");
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "get_target_func_addr", win_err);
            }
            return Err(0);
        }
    };
    
    // Call GetModuleHandleA to get the base address of the target module
    let mod_handle: *mut HINSTANCE__ = unsafe { winapi::um::libloaderapi::GetModuleHandleA(target_module_cstr.as_ptr()) };

    // If the handle is null, the function failed
    if mod_handle.is_null() {
        error!("[{}] Returned handle to {:?} is null", "get_target_func_addr", target_module_cstr);
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "get_target_func_addr", win_err);
        }
        return Err(0);
    } else {
        info!("[{}] {:?} base address: 0x{:X}", "get_exe_base_address", target_module_cstr, mod_handle as usize);
    }

    // Get the address of the target function
    let target_func_addr: FARPROC = unsafe { winapi::um::libloaderapi::GetProcAddress(mod_handle, target_function_cstr.as_ptr()) };

    // If the address is null, the function failed
    if target_func_addr.is_null() {
        error!("[{}] Returned address to {:?} is null", "get_target_func_addr", target_function_cstr);
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "get_target_func_addr", win_err);
        }
        return Err(0);
    } else {
        info!("[{}] {:?} address: 0x{:X}", "get_target_func_addr", target_function_cstr, target_func_addr as usize);
    }
    Ok(target_func_addr as *const u8)
}

// This function will create the trampoline function
fn create_trampoline(stolen_bytes: &[u8; NUM_STOLEN_BYTES], target_func_addr: *const u8) -> Result<*mut u8, DWORD> {
    // Set the JMP instruction size depending on the target architecture
    #[cfg(target_pointer_width = "64")]
    const JMP_INSTRUCTION_SIZE: usize = 14;

    #[cfg(target_pointer_width = "32")]
    const JMP_INSTRUCTION_SIZE: usize = 5;

    // Allocate memory for the trampoline function
    let trampoline = unsafe {
        VirtualAlloc(
            ptr::null_mut(),
            NUM_STOLEN_BYTES+JMP_INSTRUCTION_SIZE,
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        ) as *mut u8
    };

    // If the allocation failed, return an error
    if trampoline.is_null() {
        error!("[{}] Failed to allocate memory for trampoline function", "create_trampoline");
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "create_trampoline", win_err);
        }
        return Err(0);
    } else {
        info!("[{}] Trampoline function allocated at 0x{:X}", "create_trampoline", trampoline as usize);
    }

    // Copy the stolen bytes into the trampoline function
    unsafe {
        ptr::copy(stolen_bytes.as_ptr(), trampoline, NUM_STOLEN_BYTES);
    }

    // Create the JMP instruction back to the original function
    unsafe {
        // Depending on the target architecture, we'll need to create a different JMP instruction
        #[cfg(target_pointer_width = "64")]
        {
            // 64-bit JMP instruction 
            // Assemble the machine code for:
            // mov rax, target_address
            // jmp rax

            // MOV RAX, IMM64 = 48 B8 [IMM64]
            // 0x48 is a prefix indicating that the operation is using 64-bit operands
            // 0xB8 is essentially telling the CPU that the next 8 bytes after the opcode are 
            // the immediate value to be moved into RAX
            let mov_rax = [0x48, 0xB8];

            // JMP RAX = FF E0
            let jmp_rax = [0xFF, 0xE0];

            // Calculate the target address for the jump back
            let target_address = (target_func_addr as usize) + NUM_STOLEN_BYTES;
            
            // Prepare the buffer for our instruction set
            let mut instruction_set: [u8; 14] = [0; 14]; // 2 for MOV, 8 for target_address, 2 for JMP
            
            // Copy the machine code into the buffer
            instruction_set[0..2].copy_from_slice(&mov_rax);
            instruction_set[2..10].copy_from_slice(&target_address.to_le_bytes());
            instruction_set[10..12].copy_from_slice(&jmp_rax);

            // Write the instruction set to the trampoline
            ptr::copy(instruction_set.as_ptr(), trampoline.add(NUM_STOLEN_BYTES), instruction_set.len());
        }

        #[cfg(target_pointer_width = "32")]
        {
            // Offset for the JMP in 32-bit
            let offset: i32 = (target_func_addr as i32 + NUM_STOLEN_BYTES as i32) - (trampoline as i32 + NUM_STOLEN_BYTES as i32 + JMP_INSTRUCTION_SIZE as i32);
            
            // JMP opcode for near jump is 0xE9 in 32-bit
            let jmp_opcode: u8 = 0xE9;

            // Write the JMP opcode to the trampoline
            ptr::write(trampoline.add(NUM_STOLEN_BYTES), jmp_opcode);

            // Write the offset for the JMP
            ptr::copy(&offset as *const i32 as *const u8, trampoline.add(NUM_STOLEN_BYTES + 1), JMP_INSTRUCTION_SIZE - 1);
        }
    }

    // Change the protection of the stolen bytes to PAGE_EXECUTE_READWRITE
    let mut old_protect: DWORD = 0;
    let success = unsafe {
        VirtualProtect( 
            trampoline as _,
            (NUM_STOLEN_BYTES+JMP_INSTRUCTION_SIZE) as _,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect as *mut u32,
        ) != 0
    };

    // If the protection change failed, return an error
    if !success {
        error!("[{}] Failed to change protection of trampoline function", "create_trampoline");
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "create_trampoline", win_err);
        }
        return Err(0);
    } else {
        info!("[{}] Trampoline function protection changed to PAGE_EXECUTE_READWRITE", "create_trampoline");
    }

    // Log the trampoline function
    let hex_bytes: Vec<String> = unsafe {
        (0..NUM_STOLEN_BYTES+JMP_INSTRUCTION_SIZE).map(|i| format!("{:02x}", *trampoline.add(i))).collect()
    };
    let hex_str = hex_bytes.join(" ");

    info!("[{}] Trampoline function: {}", "create_trampoline", hex_str);

    Ok(trampoline)
}

pub fn set_hook(target_func_addr: *const u8, hook_func_addr: *mut u8) -> Result<(), DWORD> {
    #[cfg(target_pointer_width = "64")]
    const JMP_INSTRUCTION_SIZE: usize = 14;

    #[cfg(target_pointer_width = "32")]
    const JMP_INSTRUCTION_SIZE: usize = 5;

    let mut old_protect: DWORD = 0;
    if unsafe {
        VirtualProtect(
            target_func_addr as *mut _,
            JMP_INSTRUCTION_SIZE,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect as *mut _
        )
    } == 0 {
        error!("[{}] Failed to change protection of target function", "set_hook");
        if let Some(win_err) = get_last_error() {
            error!("[{}] Windows error: {}", "set_hook", win_err);
        }
        return Err(0);
    }

    let mut jmp_instr: [u8; JMP_INSTRUCTION_SIZE] = [0; JMP_INSTRUCTION_SIZE];
    
    unsafe {
        #[cfg(target_pointer_width = "64")]
        {
            let mov_rax = [0x48, 0xB8];
            let jmp_rax = [0xFF, 0xE0];
            let target_address = hook_func_addr as usize;
    
            let mut instruction_set: [u8; 14] = [0; 14];
            
            instruction_set[0..2].copy_from_slice(&mov_rax);
            instruction_set[2..10].copy_from_slice(&target_address.to_le_bytes());
            instruction_set[10..12].copy_from_slice(&jmp_rax);
    
            ptr::copy(instruction_set.as_ptr(), jmp_instr.as_mut_ptr(), instruction_set.len());
        }
    
        #[cfg(target_pointer_width = "32")]
        {
            let offset: i32 = (hook_func_addr as i32 + JMP_INSTRUCTION_SIZE as i32) - (target_func_addr as i32 + JMP_INSTRUCTION_SIZE as i32);
            
            let jmp_opcode: u8 = 0xE9;
            
            ptr::write(jmp_instr.as_mut_ptr(), jmp_opcode);
            
            ptr::copy(&offset as *const i32 as *const u8, jmp_instr.as_mut_ptr().add(1), 4);
        }
    
        ptr::copy(jmp_instr.as_ptr(), target_func_addr as *mut u8, JMP_INSTRUCTION_SIZE);

        // Log the JMP instruction as a hex string
        let hex_bytes: Vec<String> = jmp_instr.iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        let hex_str = hex_bytes.join(" ");

        info!("[{}] Bytes written to target function: {:?}", "set_hook", hex_str);
        
        let result = VirtualProtect(
            target_func_addr as *mut _,
            JMP_INSTRUCTION_SIZE,
            old_protect,
            &mut old_protect as *mut _
        );

        if result == 0 {
            error!("[{}] Failed to change protection of target function", "set_hook");
            if let Some(win_err) = get_last_error() {
                error!("[{}] Windows error: {}", "set_hook", win_err);
            }
            return Err(0);
        }
    }    

    Ok(())
}


#[no_mangle]
pub extern "system" fn hook_func(
    lpMsg: LPMSG,
    hWnd: HWND,
    wMsgFilterMin: UINT,
    wMsgFilterMax: UINT
) -> BOOL {
    // Log the hook function
    // info!("[{}] lpMsg: {:?}", "hook_func", lpMsg);

    // Fetch the trampoline function from the global variable
    let trampoline: extern "system" fn(LPMSG, HWND, UINT, UINT) -> BOOL = unsafe {
        std::mem::transmute(TRAMPOLINE_FUNC.load(Ordering::SeqCst))
    };

    // Call the trampoline function
    info!("[{}] Calling trampoline function: {:?}", "hook_func", TRAMPOLINE_FUNC);
    trampoline(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax)
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