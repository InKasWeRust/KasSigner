    use super::confirmation_phrase_valid;

    #[test]
    fn accepts_documented_pop_it_forms() {
        for phrase in [
            b"pop it".as_slice(),
            b"popit",
            b"PopIt!",
            b"POP IT!",
            b"pop-it",
            b"  Pop-It!  ",
            b"pop   it",
            b"pop - it!",
        ] {
            assert!(confirmation_phrase_valid(phrase), "rejected {:?}", phrase);
        }
    }

    #[test]
    fn rejects_near_misses() {
        for phrase in [
            b"pop it!!".as_slice(),
            b"pop it now",
            b"pop_it",
            b"pop",
            b"pop it-",
            b"pop-it -!",
        ] {
            assert!(!confirmation_phrase_valid(phrase), "accepted {:?}", phrase);
        }
    }

