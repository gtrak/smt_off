use std::ffi::c_void;
use std::mem;
use clap::arg;
use clap::Command;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HMODULE};
use windows::Win32::System::ProcessStatus::{
    EnumProcesses, K32EnumProcessModulesEx, K32GetModuleBaseNameW,
};
use windows::Win32::System::SystemInformation::{
    GetSystemCpuSetInformation, SYSTEM_CPU_SET_INFORMATION,
};
use windows::Win32::System::Threading::{
    OpenProcess, SetProcessDefaultCpuSets, PROCESS_QUERY_INFORMATION,
    PROCESS_SET_LIMITED_INFORMATION, PROCESS_VM_READ,
};

fn cpu_ids() -> Vec<u32> {
    let mut buffer_size = 0u32;
    let mut cpu_ids: Vec<u32> = Vec::new();

    // Get the required buffer size and allocate it
    unsafe {
        let _ = GetSystemCpuSetInformation(None, 0, &mut buffer_size, None, 0);
    }

    if buffer_size == 0 {
        panic!("Failed to get the required buffer size for SYSTEM_CPU_SET_INFORMATION.");
    }

    let mut buffer: Vec<u8> = Vec::with_capacity(buffer_size as usize);
    let buffer_ptr = buffer.as_mut_ptr() as *mut SYSTEM_CPU_SET_INFORMATION;

    unsafe {
        GetSystemCpuSetInformation(Some(buffer_ptr), buffer_size, &mut buffer_size, None, 0)
            .expect("Failed to retrieve CPU set information.")
    };

    let num_entries = buffer_size as usize / size_of::<SYSTEM_CPU_SET_INFORMATION>();

    for i in 0..num_entries {
        unsafe {
            let cpu_set_info = buffer_ptr.add(i).as_ref().unwrap();
            cpu_ids.push(cpu_set_info.Anonymous.CpuSet.Id);
        }
    }
    return cpu_ids;
}

fn smt_off(process: HANDLE) -> bool {
    let cpus = cpu_ids()
        .iter()
        .filter_map(|x| if x % 2 == 1 { Some(*x) } else { None })
        .collect::<Vec<u32>>();
    unsafe {
        return SetProcessDefaultCpuSets(process, Some(&cpus)).as_bool();
    }
}

fn _smt_on(process: HANDLE) -> bool {
    unsafe {
        return SetProcessDefaultCpuSets(process, None).as_bool();
    }
}

fn find_process(search_name: &str, process_id: u32) {
    let mut process_name: [u16; 260] = [0; 260];

    // Open process with the required access flags
    let h_process: HANDLE = unsafe {
        match OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_SET_LIMITED_INFORMATION,
            false,
            process_id,
        ) {
            Err(_e) => return,
            Ok(handle) => handle,
        }
    };
    let mut num_modules_returned: u32 = 0;
    let mut modules: Vec<*mut c_void> = Vec::with_capacity(1024);
    let modules_uninit = modules.spare_capacity_mut();

    // Get the process modules
    unsafe {
        if K32EnumProcessModulesEx(
            h_process,
            modules_uninit.as_mut_ptr().cast(),
            modules_uninit.len() as u32,
            &mut num_modules_returned,
            0x03,
        )
        .as_bool()
        {
            // https://users.rust-lang.org/t/ffi-how-to-pass-a-array-with-structs-to-a-c-func-that-fills-the-array-out-pointer-and-then-how-to-access-the-items-after-in-my-rust-code/83798/2
            modules.set_len(num_modules_returned as usize);
            for module in modules {
                // Get process base name
                let length = K32GetModuleBaseNameW(
                    h_process,
                    HMODULE(module), // HMODULE(modules.as_mut_ptr().cast()),
                    &mut process_name,
                );

                let process_name = String::from_utf16_lossy(&process_name[..length as usize]);
                // if process_name.contains("EpicGamesLauncher.exe") {
                if process_name.contains(search_name) {
                    println!("Disabling SMT: {}, PID: {}", process_name, process_id);
                    println!("Result: {}", smt_off(h_process));
                    return;
                }
            }
        }
        // Close the process handle, not actually necessary in this case
        let _ = CloseHandle(h_process);
    }
}

fn main() {
  let matches = Command::new("smt_off") // requires `cargo` feature
  .arg(arg!([name] "Process name to search and disable SMT").required(true))
  .get_matches();

  let search_name: &String = matches.get_one("name").unwrap();

  let mut a_processes: [u32; 1024] = [0; 1024];
    let mut cb_needed = 0;

    // Enumerate processes
    unsafe {
        EnumProcesses(
            a_processes.as_mut_ptr(),
            mem::size_of_val(&a_processes) as u32,
            &mut cb_needed,
        )
        .expect("Failed to enumerate processes")
    };

    let c_processes = cb_needed / mem::size_of::<u32>() as u32;
    // Print each process name and ID
    for &process_id in &a_processes[..c_processes as usize] {
        if process_id != 0 {
            find_process(search_name, process_id);
        }
    }
}
