pub fn gethostname() -> String {
    let mut name = Vec::<u8>::with_capacity(255);
    let name_ptr = name.as_mut_ptr() as *mut libc::c_char;
    unsafe {
        libc::gethostname(name_ptr, 255);
        name.set_len(255);
        String::from_utf8_unchecked(name)
    }
}