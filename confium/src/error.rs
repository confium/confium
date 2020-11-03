use std::convert::From;

#[derive(Debug, PartialEq)]
pub struct Error(ErrorCode);

impl std::error::Error for Error {
    fn description(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

macro_rules! error_codes {
    (
        $(
            $(#[$docs:meta])*
            ($code:expr, $codename:ident, $errname:ident, $desc:expr);
        )+
    ) => {
        #[allow(non_camel_case_types)]
        #[repr(u32)]
        #[derive(Debug, PartialEq, Copy, Clone)]
        enum ErrorCode {
        $(
            $(#[$docs])*
            $codename = $code,
        )+
        }

        impl ErrorCode {
            fn as_str(&self) -> &str {
                match *self {
                $(
                    ErrorCode::$codename => $desc,
                )+
                }
            }
        }

        #[allow(non_upper_case_globals)]
        impl Error {
            $(
                $(#[$docs])*
                pub const $errname: Error = Error(ErrorCode::$codename);
            )+
        }
    }
}

error_codes! {
    (1, UNKNOWN, Unknown, "Unknown error");
    (2, NULL_POINTER, NullPointer, "NULL pointer");
    (3, INVALID_UTF8, InvalidUTF8, "Invalid UTF-8");
    (4, PLUGIN_LOAD_ERROR, PluginLoadError, "Failed to load plugin");
}

impl From<Error> for u32 {
    #[inline]
    fn from(err: Error) -> u32 {
        err.0 as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test(i: i8) -> Result<(), Error> {
        match i {
            0 => Ok(()),
            1 => Err(Error::NullPointer),
            _ => Err(Error::Unknown),
        }
    }

    #[test]
    fn test_success() {
        assert_eq!(test(0), Ok(()));
    }

    #[test]
    fn test_nullpointer() {
        assert_eq!(test(1), Err(Error::NullPointer));
    }

    #[test]
    fn test_unknown() {
        assert_eq!(test(2), Err(Error::Unknown));
        assert_eq!(test(100), Err(Error::Unknown));
    }

    #[test]
    fn test_errcode() {
        assert_eq!(test(1).err().unwrap().0 as u32, 2);
        assert_eq!(test(100).err().unwrap().0 as u32, 1);
        assert_eq!(u32::from(test(100).err().unwrap()), 1);
    }
}
