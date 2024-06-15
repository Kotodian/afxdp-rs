use std::ffi::CString;

pub fn link_fd_xdp(link_name: String) {
    let link_name_c = CString::new(link_name).unwrap();
    let link_index: libc::c_uint;
    unsafe {
        link_index = libc::if_nametoindex(link_name_c.as_ptr());
    }

    if link_index > 0 {
        unsafe {
            libbpf_sys::bpf_set_link_xdp_fd(link_index as i32, -1, 0);
        }
    }
}
