use std::process::Command;
use std::fs::File;
use std::io::Read;
use goblin::pe::PE;
use std::error::Error;


fn main() {
    let target_exe = "C:\\Users\\User\\Documents\\rust\\binaries\\dll_injector\\dll_injector\\bin\\file_writer.exe";
    let dll32 = "C:\\Users\\User\\Documents\\rust\\binaries\\dll_injector\\dll_injector\\bin\\dll32.dll";
    let dll64 = "C:\\Users\\User\\Documents\\rust\\binaries\\dll_injector\\dll_injector\\bin\\dll64.dll";
    
    let is_64bit = is_target_64_bit(target_exe).unwrap();
    
    if is_64bit {
        Command::new("cmd")
            .args(&["/C", "start", "C:\\Users\\User\\Documents\\rust\\binaries\\dll_injector\\dll_injector\\target\\x86_64-pc-windows-msvc\\debug\\dll_injector.exe", target_exe, dll64])
            .spawn()
            .expect("failed to start 64 bit injector");
    } else {
        Command::new("cmd")
            .args(&["/C", "start", "C:\\Users\\User\\Documents\\rust\\binaries\\dll_injector\\dll_injector\\target\\i686-pc-windows-msvc\\debug\\dll_injector.exe", target_exe, dll32])
            .spawn()
            .expect("failed to start 32 bit injector");
    }
}

fn is_target_64_bit(exe_path: &str) -> Result<bool, Box<dyn Error>> {
    // Read the file data
    let mut file = File::open(exe_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Parse as a PE file
    let pe = PE::parse(&buffer)?;

    // Check the machine type in the COFF header
    let machine = pe.header.coff_header.machine;

    // IMAGE_FILE_MACHINE_AMD64 is 0x8664
    Ok(machine == 0x8664)
}

