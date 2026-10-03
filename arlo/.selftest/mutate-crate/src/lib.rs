pub fn ok() -> bool { true }

#[cfg(test)]
mod tests {
    #[test]
    fn ok_test() { assert!(super::ok()); }

    /// Rewrites a file under src/ while the test command is running. The gate
    /// must refuse to report success.
    #[test]
    fn rewrites_its_own_source() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("mutated.txt");
        let mut s = std::fs::read_to_string(&p).unwrap_or_default();
        s.push('x');
        std::fs::write(&p, s).unwrap();
    }
}