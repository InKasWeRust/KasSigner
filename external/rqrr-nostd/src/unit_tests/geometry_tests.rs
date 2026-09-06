use super::*;

    #[test]
    fn test_bresenham_straight() {
        let middle = Point { x: 100, y: 100 };

        let up = Point { x: 100, y: 200 };

        let right = Point { x: 300, y: 100 };

        let scan_up = BresenhamScan::new(&middle, &up);
        for (i, p) in scan_up.enumerate() {
            assert_eq!(100 + i as i32, p.y);
            assert_eq!(100, p.x);
        }

        let scan_down = BresenhamScan::new(&up, &middle);
        for (i, p) in scan_down.enumerate() {
            assert_eq!(200 - i as i32, p.y);
            assert_eq!(100, p.x);
        }

        let scan_right = BresenhamScan::new(&middle, &right);
        for (i, p) in scan_right.enumerate() {
            assert_eq!(100, p.y);
            assert_eq!(100 + i as i32, p.x);
        }

        let scan_right = BresenhamScan::new(&right, &middle);
        for (i, p) in scan_right.enumerate() {
            assert_eq!(100, p.y);
            assert_eq!(300 - i as i32, p.x);
        }
    }

    #[test]
    fn test_bresenham_zero() {
        let start = Point { x: 37, y: 45 };

        let mut scan = BresenhamScan::new(&start, &start);
        assert_eq!(scan.next(), Some(Point { x: 37, y: 45 }));
        assert_eq!(scan.next(), None)
    }

    #[test]
    fn test_bresenham_major_x() {
        // Taken from https://en.wikipedia.org/wiki/Bresenham%27s_line_algorithm

        let start = Point { x: 1, y: 1 };
        let end = Point { x: 11, y: 5 };

        let mut scan = BresenhamScan::new(&start, &end);

        assert_eq!(scan.next(), Some(Point { x: 1, y: 1 }));
        assert_eq!(scan.next(), Some(Point { x: 2, y: 1 }));
        assert_eq!(scan.next(), Some(Point { x: 3, y: 2 }));
        assert_eq!(scan.next(), Some(Point { x: 4, y: 2 }));
        assert_eq!(scan.next(), Some(Point { x: 5, y: 3 }));
        assert_eq!(scan.next(), Some(Point { x: 6, y: 3 }));
        assert_eq!(scan.next(), Some(Point { x: 7, y: 3 }));
        assert_eq!(scan.next(), Some(Point { x: 8, y: 4 }));
        assert_eq!(scan.next(), Some(Point { x: 9, y: 4 }));
        assert_eq!(scan.next(), Some(Point { x: 10, y: 5 }));
        assert_eq!(scan.next(), Some(Point { x: 11, y: 5 }));
        assert_eq!(scan.next(), None);
    }

    #[test]
    fn test_bresenham_major_y() {
        // Taken from https://en.wikipedia.org/wiki/Bresenham%27s_line_algorithm

        let start = Point { x: 5, y: 11 };
        let end = Point { x: 1, y: 1 };

        let mut scan = BresenhamScan::new(&start, &end);

        assert_eq!(scan.next(), Some(Point { x: 5, y: 11 }));
        assert_eq!(scan.next(), Some(Point { x: 5, y: 10 }));
        assert_eq!(scan.next(), Some(Point { x: 4, y: 9 }));
        assert_eq!(scan.next(), Some(Point { x: 4, y: 8 }));
        assert_eq!(scan.next(), Some(Point { x: 3, y: 7 }));
        assert_eq!(scan.next(), Some(Point { x: 3, y: 6 }));
        assert_eq!(scan.next(), Some(Point { x: 3, y: 5 }));
        assert_eq!(scan.next(), Some(Point { x: 2, y: 4 }));
        assert_eq!(scan.next(), Some(Point { x: 2, y: 3 }));
        assert_eq!(scan.next(), Some(Point { x: 1, y: 2 }));
        assert_eq!(scan.next(), Some(Point { x: 1, y: 1 }));
        assert_eq!(scan.next(), None);
    }

    #[test]
    fn test_line_intersect_parallel() {
        let p0 = Point { x: 0, y: 0 };

        let p1 = Point { x: 0, y: 10 };

        let q0 = Point { x: 1, y: 1 };

        let q1 = Point { x: 1, y: -9 };

        assert_eq!(line_intersect(&p0, &p1, &q0, &q1), None)
    }

    #[test]
    fn test_line_intersect_values() {
        let p0 = Point { x: 0, y: 0 };

        let p1 = Point { x: 0, y: 10 };

        let q0 = Point { x: 1, y: 1 };

        let q1 = Point { x: 10, y: -9 };

        // Check that all permutations produce same result
        assert_eq!(
            line_intersect(&p0, &p1, &q0, &q1),
            Some(Point { x: 0, y: 2 })
        );
        assert_eq!(
            line_intersect(&p0, &p1, &q1, &q0),
            Some(Point { x: 0, y: 2 })
        );
        assert_eq!(
            line_intersect(&p1, &p0, &q0, &q1),
            Some(Point { x: 0, y: 2 })
        );
        assert_eq!(
            line_intersect(&p1, &p0, &q1, &q0),
            Some(Point { x: 0, y: 2 })
        );
    }
