use std::collections::HashMap;

pub type Options = HashMap<String, OptionValue>;

#[derive(PartialEq, Clone)]
pub enum OptionValue {
    String(String),
    U32(u32),
    Options(Box<Options>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_values() {
        let mut opts = Options::new();
        opts.insert("key".to_string(), OptionValue::String("value".to_string()));
        assert!(opts[&"key".to_string()] == OptionValue::String("value".to_string()));
    }

    #[test]
    fn u32_values() {
        let mut opts = Options::new();
        opts.insert("num".to_string(), OptionValue::U32(5));
        assert!(opts[&"num".to_string()] == OptionValue::U32(5));
    }

    #[test]
    fn options_values() {
        let mut opts = Options::new();
        let mut inner = Options::new();
        inner.insert("num".to_string(), OptionValue::U32(3535));
        opts.insert("opts".to_string(), OptionValue::Options(Box::new(inner)));
        // TODO: probably a better way
        if let OptionValue::Options(value) = &opts[&"opts".to_string()] {
            assert!(value[&"num".to_string()] == OptionValue::U32(3535));
        } else {
            assert!(false);
        }
    }
}
