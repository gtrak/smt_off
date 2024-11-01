# SMT Off Utility

A command-line tool to manage CPU sets for specific processes on Windows, allowing users to quickly disable Symmetric Multi-Threading (SMT) for specific processes or revert to the original CPU sets, allowing the process to schedule itself
on any logical core.

## Rationale
Newer games these days tend to use all cores on your system, often wastefully. SMT cores are not independent phsyical cores, but they share resources with another logical core.  When a game schedules work on both of a pair of SMT cores, those threads might stall and run unpredictably. SMT is a tool for increasing the throughput of total work done, but it comes at the cost of reliable timings.

Additionally, SMT thread utilization might increase power requirements and actually cause your CPU to run at lower frequencies.

You can disable SMT on your system in the BIOS to prevent this from happening, but by doing so, you reduce the overall
performance when SMT could have been a clear win, sometimes by as much as 30%.  It's impractical to turn it on and off globally. You
can set process affinities in Task Manager, but that's not always practical either, and sometimes the game prevents you
from doing so.

CPUSets are a windows API for more softly setting affinities to a process. In my testing, disabling SMT threads helped a particularly 
poorly-optimized game run around 15% faster.  Gains elsewhere should be modest or possibly negative depending on your hardware and the game itself. 

I took some implementation guidance from the [WindowsInternals/CpuSet](https://github.com/zodiacon/WindowsInternals/tree/master/CpuSet) example and wanted a CLI-driven alternative to ProcessLasso for this configuration.

## Features

- **Disable SMT**: Limits a process to every second core, effectively disabling SMT for the process, with some caveats:
  - This tool has been tested only on an AMD 5900x processor. **Compatibility with Intel CPUs, particularly those with Efficiency cores (E-cores), is unknown** and may require adjustments. I welcome collaboration with those users.
  - This only works as intended if SMT or hyperthreading is enabled.  If SMT is disabled, you've effectively limited the process to half of your physical cores, which is likely not what you wanted.

- **Revert CPU Sets**: Restores the original CPU set configuration for the specified process. There's no need to run this unless you are just testing the effect, since every new process launch starts with fresh default settings. 

## Development Requirements

- **Rust**: Ensure that Rust is installed. You can download it from [rust-lang.org](https://www.rust-lang.org/).
- **Windows**: This tool relies on Windows-specific APIs and is intended for Windows systems.  I have successfully run it with msvc and mingw rust toolchains.

## Installation

Download a release zip from [github.com](https://github.com/gtrak/smt_off/releases) and extract it to a location of your choice.

To build it yourself: 

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/smt_off.git
   cd smt_off
   ```

2. Build the project:
   ```
   cargo build --release
   ```

3. The executable will be located at `target/release/smt_off.exe`.

## Usage

```
smt_off [OPTIONS]
```

### Options

- `-n, --name <NAME>`: Specify the name of the process to search and disable SMT.
- `-p, --PID <PID>`: Specify the PID of the process.
- `-r, --revert`: Revert CPU Sets to the original configuration for the specified process.

### Examples

- Disable SMT for a process by name:
  ```bash
  smt_off --name "ProcessName"
  ```

- Disable SMT for a process by PID:
  ```
  smt_off --PID 1234
  ```

- Revert the CPU Sets to the original configuration:
  ```
  smt_off --name "ProcessName" --revert
  ```
