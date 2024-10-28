use clap::arg;
use clap::Command;
use std::mem;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::SystemInformation::{
    GetSystemCpuSetInformation, SYSTEM_CPU_SET_INFORMATION,
};
use windows::Win32::System::Threading::{
    OpenProcess, SetProcessDefaultCpuSets, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SET_LIMITED_INFORMATION,
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

fn revert_cpusets(process: HANDLE) -> bool {
    unsafe {
        return SetProcessDefaultCpuSets(process, None).as_bool();
    }
}

fn open_by_pid(process_id: u32, process_name: &str) -> Option<HANDLE> {
    unsafe {
        match OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_LIMITED_INFORMATION,
            false,
            process_id,
        ) {
            Err(e) => {
                println!("Error opening process: {}", e);
                return None;
            }
            Ok(handle) => {
                println!("Opened process {}, pid {}", process_name, process_id);
                Some(handle)
            }
        }
    }
}

fn get_process(search_name: Option<&String>, search_pid: Option<u32>) -> Option<HANDLE> {
    let snapshot = unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).expect("Failed to get process snapshot.")
    };
    let mut process: PROCESSENTRY32W = Default::default();
    process.dwSize = mem::size_of_val(&process) as u32;

    if unsafe { Process32FirstW(snapshot, &mut process).is_ok() } {
        loop {
            if unsafe { Process32NextW(snapshot, &mut process).is_err() } {
                break;
            } else {
                let process_name =
                    String::from_utf16(&process.szExeFile.into_iter().collect::<Vec<_>>()).unwrap();
                let process_id = process.th32ProcessID as u32;

                if let Some(search_name) = search_name {
                    if process_name.contains(search_name) {
                        return open_by_pid(process_id, &process_name);
                    }
                };
                if let Some(search_pid) = search_pid {
                    if process_id == search_pid {
                        return open_by_pid(process_id, &process_name);
                    }
                };
            }
        }
    }
    None
}

fn main() {
    let matches = Command::new("smt_off") // requires `cargo` feature
        .arg(arg!(-n --name <NAME> "Process name to search and disable SMT"))
        .arg(arg!(-p --PID <PID> "PID of the process"))
        .arg(arg!(-r --revert "Revert CPU Sets back to original"))
        .get_matches();

    let search_name: Option<&String> = matches.get_one("name");
    let search_pid: Option<u32> = matches
        .get_one("PID")
        .map(|x: &String| x.parse::<u32>().expect("PID invalid"));
    let revert = matches.get_flag("revert");

    if let Some(handle) = get_process(search_name, search_pid) {
        if revert {
            println!("Reverting CPU Sets back to original");
            println!("Result: {}", revert_cpusets(handle));
        } else {
            println!("Disabling SMT");
            println!("Result: {}", smt_off(handle));
        }
        unsafe {
            let _ = CloseHandle(handle);
        };
    } else {
        println!("Process not found");
    }
}
