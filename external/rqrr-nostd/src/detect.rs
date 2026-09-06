use alloc::vec::Vec;

use crate::prepare::{AreaFiller, ImageBuffer, PixelColor};
use crate::{
    geometry::Perspective,
    identify::Point,
    prepare::{ColoredRegion, PreparedImage, Row},
};

/// A locator pattern of a QR grid
///
/// One of 3 corner patterns of a QR code. Can be found using a distinctive
/// 1:1:3:1:1 pattern of black-white zones.
///
/// Stores information about the corners of the capstone (NOT the grid), the
/// center point and the local `perspective` i.e. in which direction the grid is
/// likely skewed.
#[derive(Debug, Clone)]
pub struct CapStone {
    /// The 4 corners of the capstone
    pub corners: [Point; 4],
    /// The center point of the capstone
    pub center: Point,
    /// The local perspective of the capstone, i.e. in which direction(s) the
    /// capstone is skewed.
    pub c: Perspective,
}

/// Find all 'capstones' in a given image.
///
/// A Capstones is the locator pattern of a QR code. Every QR code has 3 of
/// these in 3 corners. This function finds these patterns by scanning the image
/// line by line for a distinctive 1:1:3:1:1 pattern of
/// black-white-black-white-black zones.
///
/// Returns a vector of [CapStones](struct.CapStone.html)
pub fn capstones_from_image<S>(img: &mut PreparedImage<S>) -> Vec<CapStone>
where
    S: ImageBuffer,
{
    let mut res = Vec::new();

    for y in 0..img.height() {
        let mut finder = LineScanner::new(img.get_pixel_at(0, y));
        for x in 1..img.width() {
            let linepos = match finder.advance(img.get_pixel_at(x, y)) {
                Some(l) => l,
                None => continue,
            };

            if !is_capstone(img, &linepos, y) {
                continue;
            }

            let cap = match create_capstone(img, &linepos, y) {
                Some(c) => c,
                None => continue,
            };

            res.push(cap);
        }

        // Insert a virtual white pixel at the end to trigger a re-check. Necessary when
        // the capstone lies right on the corner of an image
        if let Some(linepos) = finder.advance(PixelColor::White) {
            if !is_capstone(img, &linepos, y) {
                continue;
            }

            let cap = match create_capstone(img, &linepos, y) {
                Some(c) => c,
                None => continue,
            };

            res.push(cap);
        }
    }
    res
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct LinePosition {
    left: usize,
    stone: usize,
    right: usize,
}

/// Find a possible capstone based on black/white transitions
///
/// A capstone has a distinctive pattern of 1:1:3:1:1 of black-white
/// transitions. So a run of black is followed by a run of white of equal
/// length, followed by black with 3 times the length and so on.
///
/// This struct is meant to operate on a single line, with the first value in
/// the line given to `LineScanner::new` and any following values given to
/// `LineScanner::advance`
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct LineScanner {
    lookbehind_buf: [usize; 5],
    last_color: PixelColor,
    run_length: usize,
    color_changes: usize,
    current_position: usize,
}

impl LineScanner {
    /// Initialize a new LineScanner with the value of the first pixel in a
    /// line
    fn new(initial_col: PixelColor) -> Self {
        LineScanner {
            lookbehind_buf: [0; 5],
            last_color: initial_col,
            run_length: 1,
            color_changes: 0,
            current_position: 0,
        }
    }

    /// Advance the position of the finder with the given color.
    ///
    /// This will return `None` if no pattern matching a CapStone was recently
    /// observed. It will return `Some(position)` if the last added pixel
    /// completes a 1:1:3:1:1 pattern of black/white runs. This is a
    /// candidate for capstones.
    fn advance(&mut self, color: PixelColor) -> Option<LinePosition> {
        self.current_position += 1;

        // If we did not observe a color change, we have not reached the boundary of a
        // capstone
        if self.last_color == color {
            self.run_length += 1;
            return None;
        }

        self.last_color = color;
        self.lookbehind_buf.rotate_left(1);
        self.lookbehind_buf[4] = self.run_length;
        self.run_length = 1;
        self.color_changes += 1;

        if self.test_for_capstone() {
            Some(LinePosition {
                left: self.current_position - self.lookbehind_buf.iter().sum::<usize>(),
                stone: self.current_position - self.lookbehind_buf[2..].iter().sum::<usize>(),
                right: self.current_position - self.lookbehind_buf[4],
            })
        } else {
            None
        }
    }

    /// Test if the observed pattern matches that of a capstone.
    ///
    /// Capstones have a distinct pattern of 1:1:3:1:1 of
    /// black->white->black->white->black transitions.
    fn test_for_capstone(&self) -> bool {
        // A capstone should look like > x xxx x < so we have to check after 5 color
        // changes and only if the newly observed color is white
        if PixelColor::White == self.last_color && self.color_changes >= 5 {
            const CHECK: [usize; 5] = [1, 1, 3, 1, 1];
            let avg = (self.lookbehind_buf[0]
                + self.lookbehind_buf[1]
                + self.lookbehind_buf[3]
                + self.lookbehind_buf[4])
                / 4;
            let err = avg * 3 / 4;
            #[allow(clippy::needless_range_loop)]
            for i in 0..5 {
                if self.lookbehind_buf[i] < CHECK[i] * avg - err
                    || self.lookbehind_buf[i] > CHECK[i] * avg + err
                {
                    return false;
                }
            }

            true
        } else {
            false
        }
    }
}

/// Determine if the given position is an unobserved capstone
fn is_capstone<S>(img: &mut PreparedImage<S>, linepos: &LinePosition, y: usize) -> bool
where
    S: ImageBuffer,
{
    let ring_reg = img.get_region((linepos.right, y));
    let stone_reg = img.get_region((linepos.stone, y));

    if img.get_pixel_at(linepos.left, y) != img.get_pixel_at(linepos.right, y) {
        return false;
    }

    match (ring_reg, stone_reg) {
        (
            ColoredRegion::Unclaimed {
                color: ring_color,
                pixel_count: ring_count,
                ..
            },
            ColoredRegion::Unclaimed {
                color: stone_color,
                pixel_count: stone_count,
                ..
            },
        ) => {
            let ratio = stone_count * 100 / ring_count;
            // Verify that left is connected to right, and that stone is not connected
            // Also that the pixel counts roughly respect the 37.5% ratio
            ring_color != stone_color && 10 < ratio && ratio < 70
        }
        _ => false,
    }
}

/// Create a capstone at the given position
fn create_capstone<S>(
    img: &mut PreparedImage<S>,
    linepos: &LinePosition,
    y: usize,
) -> Option<CapStone>
where
    S: ImageBuffer,
{
    /* Find the corners of the ring */
    let start_point = Point {
        x: linepos.right as i32,
        y: y as i32,
    };
    let first_corner_finder = FirstCornerFinder::new(start_point);
    let first_corner_finder =
        img.repaint_and_apply((linepos.right, y), PixelColor::Tmp1, first_corner_finder);
    let all_corner_finder = AllCornerFinder::new(start_point, first_corner_finder.best());
    let all_corner_finder =
        img.repaint_and_apply((linepos.right, y), PixelColor::CapStone, all_corner_finder);
    let corners = all_corner_finder.best();

    /* Set up the perspective transform and find the center */
    let c = Perspective::create(&corners, 7.0, 7.0)?;
    let center = c.map(3.5, 3.5);

    Some(CapStone { c, corners, center })
}

/// Find the a corner of a sheared rectangle.
#[derive(Debug, Eq, PartialEq, Clone)]
struct FirstCornerFinder {
    initial: Point,
    best: Point,
    score: i32,
}

impl FirstCornerFinder {
    pub fn new(initial: Point) -> Self {
        FirstCornerFinder {
            initial,
            best: Default::default(),
            score: -1,
        }
    }

    pub fn best(self) -> Point {
        self.best
    }
}

impl AreaFiller for FirstCornerFinder {
    fn update(&mut self, row: Row) {
        let dy = (row.y as i32) - self.initial.y;
        let l_dx = (row.left as i32) - self.initial.x;
        let r_dx = (row.right as i32) - self.initial.x;

        let l_dist = l_dx * l_dx + dy * dy;
        let r_dist = r_dx * r_dx + dy * dy;

        if l_dist > self.score {
            self.score = l_dist;
            self.best = Point {
                x: row.left as i32,
                y: row.y as i32,
            }
        }

        if r_dist > self.score {
            self.score = r_dist;
            self.best = Point {
                x: row.right as i32,
                y: row.y as i32,
            }
        }
    }
}

/// Find the 4 corners of a rectangle
#[derive(Debug, Eq, PartialEq, Clone)]
struct AllCornerFinder {
    baseline: Point,
    best: [Point; 4],
    scores: [i32; 4],
}

impl AllCornerFinder {
    pub fn new(initial: Point, corner: Point) -> Self {
        let baseline = Point {
            x: corner.x - initial.x,
            y: corner.y - initial.y,
        };

        let parallel_score = initial.x * baseline.x + initial.y * baseline.y;
        let orthogonal_score = -initial.x * baseline.y + initial.y * baseline.x;

        AllCornerFinder {
            baseline,
            best: [initial; 4],
            scores: [
                parallel_score,
                orthogonal_score,
                -parallel_score,
                -orthogonal_score,
            ],
        }
    }

    pub fn best(self) -> [Point; 4] {
        self.best
    }
}

impl AreaFiller for AllCornerFinder {
    fn update(&mut self, row: Row) {
        let l_par_score = (row.left as i32) * self.baseline.x + (row.y as i32) * self.baseline.y;
        let l_ort_score = -(row.left as i32) * self.baseline.y + (row.y as i32) * self.baseline.x;
        let l_scores = [l_par_score, l_ort_score, -l_par_score, -l_ort_score];

        let r_par_score = (row.right as i32) * self.baseline.x + (row.y as i32) * self.baseline.y;
        let r_ort_score = -(row.right as i32) * self.baseline.y + (row.y as i32) * self.baseline.x;
        let r_scores = [r_par_score, r_ort_score, -r_par_score, -r_ort_score];

        for j in 0..4 {
            if l_scores[j] > self.scores[j] {
                self.scores[j] = l_scores[j];
                self.best[j] = Point {
                    x: row.left as i32,
                    y: row.y as i32,
                }
            }

            if r_scores[j] > self.scores[j] {
                self.scores[j] = r_scores[j];
                self.best[j] = Point {
                    x: row.right as i32,
                    y: row.y as i32,
                }
            }
        }
    }
}
