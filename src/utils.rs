#[macro_escape]
macro_rules! check_not_null {
    ($param:ident) => {{
        if $param.is_null() {
            return Err($crate::error::NullPointer {
                param: stringify!($param),
            }
            .build());
        }
    }};
}
