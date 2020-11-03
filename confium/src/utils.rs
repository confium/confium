#[macro_escape]
macro_rules! cstring {
    ($str:ident) => {{
        if ($str.is_null()) {
            return u32::from(Error::NullPointer);
        }
        unsafe {
            match CStr::from_ptr($str).to_str() {
                Ok(s) => s,
                Err(_) => {
                    return u32::from(Error::InvalidUTF8);
                }
            }
        }
    }};
}
