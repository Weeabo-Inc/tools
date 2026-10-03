pub fn add(a: i32, b: i32) -> i32 { a + b }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds() { assert_eq!(add(2, 2), 4); }

    #[test]
    fn adds_negatives() { assert_eq!(add(-1, 1), 0); }

    #[test]
    #[ignore]
    fn deliberately_ignored() { panic!("must never run by default"); }
}