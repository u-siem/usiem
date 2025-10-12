use crate::event::field::FieldValue;

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    fn create_str_field(s: &str) -> FieldValue {
        FieldValue::Str(Cow::Owned(s.to_string()))
    }

    fn create_array_field(items: Vec<&str>) -> FieldValue {
        FieldValue::Array(
            items
                .into_iter()
                .map(|s| FieldValue::Str(Cow::Owned(s.to_string())))
                .collect(),
        )
    }

    #[test]
    fn test_array_contains_str() {
        let array_field = create_array_field(vec!["apple", "banana", "cherry"]);

        assert!(array_field.array_contains_str("apple"));
        assert!(array_field.array_contains_str("banana"));
        assert!(!array_field.array_contains_str("grape"));
        assert!(!array_field.array_contains_str("APPLE")); // case sensitive
    }

    #[test]
    fn test_array_contains_str_ignore_case() {
        let array_field = create_array_field(vec!["Apple", "BANANA", "cherry"]);

        assert!(array_field.array_contains_str_ignore_case("apple"));
        assert!(array_field.array_contains_str_ignore_case("APPLE"));
        assert!(array_field.array_contains_str_ignore_case("banana"));
        assert!(array_field.array_contains_str_ignore_case("Cherry"));
        assert!(!array_field.array_contains_str_ignore_case("grape"));
    }

    #[test]
    fn test_array_contains_any_str() {
        let array_field = create_array_field(vec!["red", "green", "blue"]);

        assert!(array_field.array_contains_any_str(&["red", "yellow"]));
        assert!(array_field.array_contains_any_str(&["purple", "green"]));
        assert!(!array_field.array_contains_any_str(&["yellow", "purple"]));
    }

    #[test]
    fn test_array_contains_any_str_ignore_case() {
        let array_field = create_array_field(vec!["RED", "Green", "blue"]);

        assert!(array_field.array_contains_any_str_ignore_case(&["red", "yellow"]));
        assert!(array_field.array_contains_any_str_ignore_case(&["purple", "GREEN"]));
        assert!(!array_field.array_contains_any_str_ignore_case(&["yellow", "purple"]));
    }

    #[test]
    fn test_array_contains_all_str() {
        let array_field = create_array_field(vec!["red", "green", "blue"]);

        assert!(array_field.array_contains_all_str(&["red", "green"]));
        assert!(array_field.array_contains_all_str(&["blue"]));
        assert!(!array_field.array_contains_all_str(&["red", "yellow"]));
        assert!(!array_field.array_contains_all_str(&["red", "green", "blue", "purple"]));
    }

    #[test]
    fn test_array_intersection_str() {
        let array_field = create_array_field(vec!["apple", "banana", "cherry"]);

        let intersection = array_field.array_intersection_str(&["apple", "grape", "banana"]);
        assert_eq!(intersection, vec!["apple", "banana"]);

        let empty_intersection = array_field.array_intersection_str(&["grape", "orange"]);
        assert!(empty_intersection.is_empty());
    }

    #[test]
    fn test_array_intersection_str_ignore_case() {
        let array_field = create_array_field(vec!["Apple", "BANANA", "cherry"]);

        let intersection =
            array_field.array_intersection_str_ignore_case(&["apple", "grape", "CHERRY"]);
        assert_eq!(intersection, vec!["apple", "CHERRY"]);
    }

    #[test]
    fn test_non_array_fields() {
        let str_field = create_str_field("test");
        let int_field = FieldValue::Int(42);

        // Non-array fields should return false/empty for array operations
        assert!(!str_field.array_contains_str("test"));
        assert!(!int_field.array_contains_str("42"));
        assert!(str_field.array_intersection_str(&["test"]).is_empty());
    }

    #[test]
    fn test_command_line_parsing_from_string() {
        let cmd_field = create_str_field("ls -la /home/user");
        let cmd_line = cmd_field.as_command_line().unwrap();

        assert_eq!(cmd_line.program(), "ls");
        // -la is parsed as parameter with value "/home/user"
        assert_eq!(cmd_line.get_parameter("la"), Some("/home/user"));
        assert!(cmd_line.is_combined_flags("la"));
    }

    #[test]
    fn test_command_line_parsing_from_array() {
        let cmd_array = create_array_field(vec!["gcc", "-o", "output", "main.c"]);
        let cmd_line = cmd_array.as_command_line().unwrap();

        assert_eq!(cmd_line.program(), "gcc");
        assert_eq!(cmd_line.get_parameter("o"), Some("output"));
        // main.c is ignored since we don't track positional args
    }

    #[test]
    fn test_powershell_command_parsing() {
        let ps_cmd = create_str_field("powershell.exe -enc SGVsbG8gV29ybGQ=");
        let cmd_line = ps_cmd.as_command_line().unwrap();

        assert_eq!(cmd_line.program(), "powershell.exe");
        assert_eq!(cmd_line.get_parameter("enc"), Some("SGVsbG8gV29ybGQ="));
    }

    #[test]
    fn test_require_command_line_error() {
        let int_field = FieldValue::Int(42);
        assert!(int_field.require_command_line().is_err());
    }
}
