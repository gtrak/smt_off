use clap::arg;
use clap::Command;
use windows::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot;
use windows::Win32::System::Diagnostics::ToolHelp::Process32FirstW;
use windows::Win32::System::Diagnostics::ToolHelp::Process32NextW;
use windows::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W;
use windows::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS;

use std::ffi::c_void;
use std::mem;

use std::ptr::null_mut;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::Foundation::LUID;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HMODULE};
use windows::Win32::Security::AdjustTokenPrivileges;
use windows::Win32::Security::LookupPrivilegeValueW;
use windows::Win32::Security::LUID_AND_ATTRIBUTES;
use windows::Win32::Security::SE_INC_BASE_PRIORITY_NAME;
use windows::Win32::Security::SE_PRIVILEGE_ENABLED;
use windows::Win32::Security::TOKEN_ALL_ACCESS;
use windows::Win32::Security::TOKEN_PRIVILEGES;
use windows::Win32::System::ProcessStatus::LIST_MODULES_DEFAULT;
use windows::Win32::System::ProcessStatus::{
    EnumProcesses, K32EnumProcessModulesEx, K32GetModuleBaseNameW,
};
use windows::Win32::System::SystemInformation::{
    GetSystemCpuSetInformation, SYSTEM_CPU_SET_INFORMATION,
};
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::Win32::System::Threading::OpenProcessToken;
use windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;
use windows::Win32::System::Threading::PROCESS_SET_LIMITED_INFORMATION;
use windows::Win32::System::Threading::{OpenProcess, SetProcessDefaultCpuSets};

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

fn module_matches(h_process: HANDLE, search_name: Option<&String>) -> Option<HANDLE> {
    let mut num_modules_returned: u32 = 0;
    let mut modules: Vec<*mut c_void> = Vec::with_capacity(1024);
    let modules_uninit = modules.spare_capacity_mut();
    let mut process_name: [u16; 260] = [0; 260];

    unsafe {
        if K32EnumProcessModulesEx(
            h_process,
            modules_uninit.as_mut_ptr().cast(),
            modules_uninit.len() as u32,
            &mut num_modules_returned,
            LIST_MODULES_DEFAULT.0,
        )
        .as_bool()
        {
            // https://users.rust-lang.org/t/ffi-how-to-pass-a-array-with-structs-to-a-c-func-that-fills-the-array-out-pointer-and-then-how-to-access-the-items-after-in-my-rust-code/83798/2
            modules.set_len(num_modules_returned as usize);
            for _module in modules {
                // Get process base name
                let length = K32GetModuleBaseNameW(
                    h_process,
                    HMODULE(null_mut()), // HMODULE(module),
                    &mut process_name,
                );

                let process_name = String::from_utf16_lossy(&process_name[..length as usize]);
                println!("{}", process_name);

                if let Some(search_name) = search_name {
                    if process_name.contains(search_name) {
                        return Some(h_process);
                    }
                }
            }
        } else {
            println!("Enumerating modules failed, {:?}", GetLastError());
        }
        // Close the process handle if it wasn't returned, not actually necessary in this case
        let _ = CloseHandle(h_process);
    }
    return None;
}

fn open_by_pid(process_id: u32) -> Option<HANDLE> {
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
            println!("Process opened: {}", process_id);
            Some(handle)
        }
    }
  }
}

fn process_module_matches(
    search_name: Option<&String>,
    search_pid: Option<u32>,
    process_id: u32,
) -> Option<HANDLE> {
    // Open process with the required access flags
    let h_process = open_by_pid(process_id);

    if let Some(h_process) = h_process {

    if let Some(search_pid) = search_pid {
        if search_pid == process_id {
            return Some(h_process);
        }
    }

    return module_matches(h_process, search_name);
  }
  None
}

pub fn get_process_old(search_name: Option<&String>, search_pid: Option<u32>) {
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
            if let Some(handle) = process_module_matches(search_name, search_pid, process_id) {
                println!("Disabling SMT, PID: {}", process_id);
                println!("Result: {}", smt_off(handle));
                unsafe {
                    let _ = CloseHandle(handle);
                };
                break;
            }
        }
    }
}

pub fn get_process(search_name: Option<&String>, search_pid: Option<u32>) {
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
              let process_name = String::from_utf16(&process.szExeFile.into_iter().collect::<Vec<_>>()).unwrap();
              let process_id = process.th32ProcessID as u32;
              let handle = (|| {
                if let Some(search_name) = search_name {
                  if process_name.contains(search_name) {
                    return open_by_pid(process_id);
                  }
                };
                if let Some(search_pid) = search_pid {
                  if process_id == search_pid {
                    return open_by_pid(process_id);
                  }
                };
                None
              })();
              if let Some(handle) = handle {
                println!("Disabling SMT, PROCESS: {}, PID: {}", process_name, process_id);
                println!("Result: {}", smt_off(handle));
                return;
              }
        }
      };
    }
    println!("No matching processes found.");
}

fn escalate() {
    unsafe {
        let process = GetCurrentProcess();
        let mut token: HANDLE = HANDLE(null_mut());
        OpenProcessToken(process, TOKEN_ALL_ACCESS, &mut token)
            .expect("Cannot escalate privileges");
        let mut luid: LUID = Default::default();

        LookupPrivilegeValueW(None, SE_INC_BASE_PRIORITY_NAME, &mut luid)
            .expect("Could not lookup privilege");

        let tp = TOKEN_PRIVILEGES {
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
            PrivilegeCount: 1,
        };
        AdjustTokenPrivileges(
            token,
            false,
            Some(&tp),
            mem::size_of_val(&tp) as u32,
            None,
            None,
        )
        .expect("Access denied. Try running from an elevated command prompt.\n");
        println!("Succesfully escalated privileges");
        let _ = CloseHandle(token);
        let _ = CloseHandle(process);
    }
}
fn main() {
    let matches = Command::new("smt_off") // requires `cargo` feature
        .arg(arg!(-n --name <NAME> "Process name to search and disable SMT"))
        .arg(arg!(-p --PID <PID> "PID of the process"))
        .get_matches();

    let search_name: Option<&String> = matches.get_one("name");
    let search_pid: Option<u32> = matches
        .get_one("PID")
        .map(|x: &String| x.parse::<u32>().expect("PID invalid"));

    escalate();
    // get_process_old(search_name, search_pid);
    get_process(search_name, search_pid);
}
