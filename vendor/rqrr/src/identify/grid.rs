use core::{cmp, mem};

use crate::{
    geometry,
    identify::match_capstones::CapStoneGroup,
    prepare::PreparedImage,
    prepare::{AreaFiller, ColoredRegion, ImageBuffer, PixelColor, Row},
    version_db::VERSION_DATA_BASE,
    BitGrid, CapStone, Point,
};

/// Location of a skewed square in an image
///
/// A skewed square formed by 3 [CapStones](struct.CapStone.html) and possibly
/// an alignment pattern located in the 4th corner. This can be converted into a
/// normal [Grid](trait.Grid.html) that can be decoded.
#[derive(Debug, Clone)]
pub struct SkewedGridLocation {
    pub grid_size: usize,
    pub c: geometry::Perspective,
}

impl SkewedGridLocation {
    /// Create a SkewedGridLocation from corners
    ///
    /// Given 3 corners of a grid, this tries to match the expected features of
    /// a QR code such that the SkewedGridLocation maps onto those features.
    ///
    /// For all grids this includes searching for timing patterns between
    /// capstones to determine the grid size.
    ///
    /// For bigger grids this includes searching for an alignment pattern in the
    /// 4 corner.
    ///
    /// If no sufficient match could be produces, return `None` instead.
    pub fn from_group<S>(img: &mut PreparedImage<S>, mut group: CapStoneGroup) -> Option<Self>
    where
        S: ImageBuffer,
    {
        /* Construct the hypotenuse line from A to C. B should be to
         * the left of this line.
         */
        let h0 = group.0.center;
        let mut hd = Point {
            x: group.2.center.x - group.0.center.x,
            y: group.2.center.y - group.0.center.y,
        };

        /* Make sure A-B-C is clockwise */
        if (group.1.center.x - h0.x) * -hd.y + (group.1.center.y - h0.y) * hd.x > 0 {
            mem::swap(&mut group.0, &mut group.2);
            hd.x = -hd.x;
            hd.y = -hd.y
        }

        /* Rotate each capstone so that corner 0 is top-left with respect
         * to the grid.
         */
        rotate_capstone(&mut group.0, &h0, &hd)?;
        rotate_capstone(&mut group.1, &h0, &hd)?;
        rotate_capstone(&mut group.2, &h0, &hd)?;

        /* Check the timing pattern. This doesn't require a perspective
         * transform.
         */
        let grid_size = measure_timing_pattern(img, &group)?;

        // KASSIGNER: 21 (version 1) to 69 (version 13). Below 21 the timing
        // scan misread the pattern. Every code a unit shows or kassigner.org
        // draws is V9 at most (`kassigner-qr`'s `MAX_VERSION`), and past V13
        // is beyond what this camera resolves. Above 21 the alignment search
        // runs, so a misread claiming version 40 would start it for nothing.
        const MIN_PLAUSIBLE_GRID: usize = 21;
        const MAX_PLAUSIBLE_GRID: usize = 69;
        if !(MIN_PLAUSIBLE_GRID..=MAX_PLAUSIBLE_GRID).contains(&grid_size) {
            return None;
        }

        /* Make an estimate based for the alignment pattern based on extending
         * lines from capstones A and C.
         */

        let mut align = geometry::line_intersect(
            &group.0.corners[0],
            &group.0.corners[1],
            &group.2.corners[0],
            &group.2.corners[3],
        )?;

        /* On V2+ grids, we should use the alignment pattern. */
        if grid_size > 21 {
            /* Try to find the actual location of the alignment pattern. */
            align = find_alignment_pattern(img, align, &group.0, &group.2)?;
            let score = -hd.y * align.x + hd.x * align.y;
            let finder = LeftMostFinder {
                line_p: hd,
                best: align,
                score,
            };
            let found = img.repaint_and_apply(
                (align.x as usize, align.y as usize),
                PixelColor::Alignment,
                finder,
            );
            align = found.best;
        }

        if version_from_grid_size(grid_size) >= VERSION_DATA_BASE.len() {
            return None;
        }

        let c = setup_perspective(img, &group, align, grid_size)?;

        Some(SkewedGridLocation { grid_size, c })
    }

    /// Convert into a grid referencing the underlying image as source
    pub fn into_grid_image<'a, S>(self, img: &'a PreparedImage<S>) -> RefGridImage<'a, S> {
        RefGridImage { grid: self, img }
    }
}

/// Get the version for a given grid size.
///
/// The returned version can be used to fetch the VersionInfo for the given grid
/// size.
fn version_from_grid_size(grid_size: usize) -> usize {
    (grid_size - 17) / 4
}

/// A Grid that references a bigger image
///
/// Given a grid location and an image, implement the [Grid
/// trait](trait.Grid.html) so that it may be decoded by
/// [decode](fn.decode.html)
pub struct RefGridImage<'a, S> {
    grid: SkewedGridLocation,
    img: &'a PreparedImage<S>,
}

impl<S> BitGrid for RefGridImage<'_, S>
where
    S: ImageBuffer,
{
    fn size(&self) -> usize {
        self.grid.grid_size
    }

    fn bit(&self, y: usize, x: usize) -> bool {
        let p = self.grid.c.map(x as f32 + 0.5, y as f32 + 0.5);
        PixelColor::White != self.img.get_pixel_at_point(p)
    }
}

fn setup_perspective<S>(
    img: &PreparedImage<S>,
    caps: &CapStoneGroup,
    align: Point,
    grid_size: usize,
) -> Option<geometry::Perspective>
where
    S: ImageBuffer,
{
    let initial = geometry::Perspective::create(
        &[
            caps.1.corners[0],
            caps.2.corners[0],
            align,
            caps.0.corners[0],
        ],
        (grid_size - 7) as f32,
        (grid_size - 7) as f32,
    )?;

    Some(jiggle_perspective(img, initial, grid_size))
}

/// Rotate a capstone's corners so that corner 0 is top-left with respect to
/// the grid, and map it again in that order.
///
/// KASSIGNER: `None` when the rotated corners cannot be mapped: not a QR
/// code. Upstream's `expect` here ("rotated perspective can't fail") would
/// panic, and on the device a panic wipes and halts. It can fail: the corners
/// are the ring's extreme points, which may coincide or line up, and
/// detection mapped them in one order only. Never seen in the sweep in
/// `kassigner-qr/tests/robust.rs`; refused anyway.
fn rotate_capstone(cap: &mut CapStone, h0: &Point, hd: &Point) -> Option<()> {
    let (best_idx, _) = cap
        .corners
        .iter()
        .enumerate()
        .min_by_key(|(_, a)| (a.x - h0.x) * (-hd.y) + (a.y - h0.y) * hd.x)?;

    /* Rotate the capstone */
    cap.corners.rotate_left(best_idx);
    cap.c = geometry::Perspective::create(&cap.corners, 7.0, 7.0)?;
    Some(())
}

//* Try the measure the timing pattern for a given QR code. This does
// * not require the global perspective to have been set up, but it
// * does require that the capstone corners have been set to their
// * canonical rotation.
// *
// * For each capstone, we find a point in the middle of the ring band
// * which is nearest the centre of the code. Using these points, we do
// * a horizontal and a vertical timing scan.
// */
//
// KASSIGNER: `None` when neither scan crosses an edge: no timing pattern, so
// not a QR code, where upstream's assert `scan >= 1` would wipe and halt the
// device. Three finder patterns turned about 19 to 66 degrees, rings almost
// touching, reach it (cases in `kassigner-qr/tests/robust.rs`).
fn measure_timing_pattern<S>(img: &PreparedImage<S>, caps: &CapStoneGroup) -> Option<usize>
where
    S: ImageBuffer,
{
    const US: [f32; 3] = [6.5f32, 6.5f32, 0.5f32];
    const VS: [f32; 3] = [0.5f32, 6.5f32, 6.5f32];
    let tpet0 = caps.0.c.map(US[0], VS[0]);
    let tpet1 = caps.1.c.map(US[1], VS[1]);
    let tpet2 = caps.2.c.map(US[2], VS[2]);

    let hscan = timing_scan(img, &tpet1, &tpet2);
    let vscan = timing_scan(img, &tpet1, &tpet0);

    let scan = cmp::max(hscan, vscan);
    if scan == 0 {
        return None;
    }

    /* Choose the nearest allowable grid size */
    let size = scan + 13;
    let ver = ((size as f32 - 15.0) as usize) / 4;
    Some(ver * 4 + 17)
}

fn timing_scan<S>(img: &PreparedImage<S>, p0: &Point, p1: &Point) -> usize
where
    S: ImageBuffer,
{
    let mut count = 0;
    let mut previous = None;
    for p in geometry::BresenhamScan::new(p0, p1) {
        let pixel = img.get_pixel_at_point(p);
        if let Some(previous) = previous {
            if previous != pixel {
                count += 1;
            }
        }
        previous = Some(pixel);
    }

    count
}

/// Expected pixel area of the alignment pattern: twice the triangle area
/// spanned by the seed and the two guessed corners, as a cross product.
///
/// KASSIGNER: saturating, since this i32 arithmetic runs before the call
/// site's clamp, and with `overflow-checks` on in the release profile (which
/// governs this crate through `kassigner-qr`) an overflow is a panic: on the
/// device, wipe and halt. A seed from `line_intersect`, whose determinant can
/// be 1, may lie far outside the image, and `Perspective::map` saturates to
/// the i32 bounds on a near-degenerate perspective; two differences of
/// 46,341 already multiply past i32. A saturated and a merely huge value
/// meet the same clamp; i64 would not do, since two full-range differences
/// multiply past it too. Split out to be tested without a `PreparedImage`.
fn alignment_size_estimate(a: &Point, c: &Point, seed: &Point) -> usize {
    let dx_a = a.x.saturating_sub(seed.x);
    let dy_a = a.y.saturating_sub(seed.y);
    let dx_c = c.x.saturating_sub(seed.x);
    let dy_c = c.y.saturating_sub(seed.y);
    dx_a.saturating_mul(dy_c.saturating_neg())
        .saturating_add(dy_a.saturating_mul(dx_c))
        .unsigned_abs() as usize
}

/// KASSIGNER: the pixel counts a blob may have and be taken for the
/// alignment pattern's centre module: upstream's half to twice a module's
/// area, widened to a pixel less or more than a module each way, as drawing
/// in whole pixels can make it. The module is measured unrounded along each
/// finder pattern's axes at the seed: upstream's area from two rounded
/// points failed every code with an alignment pattern under about 2.7 pixels
/// a module, refusing the centre (so the spiral took a data module and half
/// the code read wrong) or finding nothing.
///
/// Upstream's band, on `size_estimate`, when a module's length is not one a
/// frame can hold (a near-degenerate perspective).
fn module_band(c0: &CapStone, c2: &CapStone, seed: &Point, size_estimate: usize) -> (usize, usize) {
    let upstream = (size_estimate / 2, size_estimate.saturating_mul(2));
    let (u, v) = c0.c.unmap(seed);
    let a = module_length(c0.c.map_f(u, v), c0.c.map_f(u, v + 1.0));
    let (u, v) = c2.c.unmap(seed);
    let c = module_length(c2.c.map_f(u, v), c2.c.map_f(u + 1.0, v));
    let (Some(a), Some(c)) = (a, c) else {
        return upstream;
    };
    let area = a * c;
    let least = (area / 2.0).min((a - 1.0).max(0.0) * (c - 1.0).max(0.0));
    let most = (area * 2.0).max((a + 1.0) * (c + 1.0));
    // Whole pixels: the least rounded up, the most down. A module is at most
    // 4,096 pixels, so both fit a usize and the casts only round.
    let up = least as usize + usize::from((least as usize as f32) < least);
    (up, most as usize)
}

/// The distance from `p` to `q`, one module's length, when it is one a frame
/// can hold: over zero and at most 4,096 pixels. `None` otherwise, NaN
/// included. Newton's method, since `core` has no square root.
fn module_length(p: (f32, f32), q: (f32, f32)) -> Option<f32> {
    let (dx, dy) = (q.0 - p.0, q.1 - p.1);
    let square = dx * dx + dy * dy;
    if square.is_nan() || square <= 0.0 || square > 4096.0 * 4096.0 {
        return None;
    }
    // From above the root; 32 steps settle anything under 4,096 squared.
    let mut root = square.max(1.0);
    for _ in 0..32 {
        root = 0.5 * (root + square / root);
    }
    Some(root)
}

fn find_alignment_pattern<S>(
    img: &mut PreparedImage<S>,
    mut align_seed: Point,
    c0: &CapStone,
    c2: &CapStone,
) -> Option<Point>
where
    S: ImageBuffer,
{
    /* Guess another two corners of the alignment pattern so that we
     * can estimate its size.
     */
    let (u, v) = c0.c.unmap(&align_seed);
    let a = c0.c.map(u, v + 1.0);
    let (u, v) = c2.c.unmap(&align_seed);
    let c = c2.c.map(u + 1.0, v);
    // Saturating, then clamped below.
    let size_estimate = alignment_size_estimate(&a, &c, &align_seed);

    /* Spiral outwards from the estimate point until we find something
     * roughly the right size. Don't look too far from the estimate
     * point.
     */
    // KASSIGNER: bound the spiral to the image. Nothing else bounds
    // `size_estimate`, which near-degenerate geometry makes enormous, and the
    // spiral's work is quadratic in `step_size`: one fuzzed 480x480 frame ran
    // it to a step of 12,616, a stall of seconds. The estimate is clamped to
    // the square of width plus height and the step to width plus height, both
    // over the diagonal; an alignment pattern lies inside the frame, so
    // neither can reject a real one.
    let diag = img.width().saturating_add(img.height());
    let size_estimate = size_estimate.min(diag.saturating_mul(diag));
    let (least, most) = module_band(c0, c2, &align_seed, size_estimate);

    let mut dir = 0;
    let mut step_size = 1;

    while step_size * step_size < size_estimate * 100 && step_size <= diag {
        const DX_MAP: [i32; 4] = [1, 0, -1, 0];
        const DY_MAP: [i32; 4] = [0, -1, 0, 1];
        for _pass in 0..step_size {
            let x = align_seed.x as usize;
            let y = align_seed.y as usize;

            // Alignment pattern should not be white
            if x < img.width() && y < img.height() && PixelColor::White != img.get_pixel_at(x, y) {
                let region = img.get_region((x, y));
                let count = match region {
                    ColoredRegion::Unclaimed { pixel_count, .. } => pixel_count,
                    _ => continue,
                };

                // Matches expected size of alignment pattern
                if count >= least && count <= most {
                    return Some(align_seed);
                }
            }

            align_seed.x += DX_MAP[dir];
            align_seed.y += DY_MAP[dir];
        }

        // Cycle directions
        dir = (dir + 1) % 4;
        if dir & 1 == 0 {
            step_size += 1
        }
    }
    None
}

struct LeftMostFinder {
    line_p: Point,
    best: Point,
    score: i32,
}

impl AreaFiller for LeftMostFinder {
    fn update(&mut self, row: Row) {
        let left_d = -self.line_p.y * (row.left as i32) + self.line_p.x * row.y as i32;
        let right_d = -self.line_p.y * (row.right as i32) + self.line_p.x * row.y as i32;

        if left_d < self.score {
            self.score = left_d;
            self.best.x = row.left as i32;
            self.best.y = row.y as i32;
        }

        if right_d < self.score {
            self.score = right_d;
            self.best.x = row.right as i32;
            self.best.y = row.y as i32;
        }
    }
}

fn jiggle_perspective<S>(
    img: &PreparedImage<S>,
    mut perspective: geometry::Perspective,
    grid_size: usize,
) -> geometry::Perspective
where
    S: ImageBuffer,
{
    let mut best = fitness_all(img, &perspective, grid_size);
    let mut adjustments: [f32; 8] = [
        perspective.0[0] * 0.02f32,
        perspective.0[1] * 0.02f32,
        perspective.0[2] * 0.02f32,
        perspective.0[3] * 0.02f32,
        perspective.0[4] * 0.02f32,
        perspective.0[5] * 0.02f32,
        perspective.0[6] * 0.02f32,
        perspective.0[7] * 0.02f32,
    ];

    for _pass in 0..2 {
        for i in 0..16 {
            let j = i >> 1;
            let old = perspective.0[j];
            let step = adjustments[j];

            let new = if i & 1 != 0 { old + step } else { old - step };

            perspective.0[j] = new;
            let test = fitness_all(img, &perspective, grid_size);
            if test > best {
                best = test
            } else {
                perspective.0[j] = old
            }
        }

        #[allow(clippy::needless_range_loop)]
        for i in 0..8 {
            adjustments[i] *= 0.5f32;
        }
    }
    perspective
}
/* Compute a fitness score for the currently configured perspective
 * transform, using the features we expect to find by scanning the
 * grid.
 */
fn fitness_all<S>(
    img: &PreparedImage<S>,
    perspective: &geometry::Perspective,
    grid_size: usize,
) -> i32
where
    S: ImageBuffer,
{
    let version = version_from_grid_size(grid_size);
    let info = &VERSION_DATA_BASE[version];
    let mut score = 0;

    /* Check the timing pattern */
    for i in 0..(grid_size as i32 - 14) {
        let expect = if 0 != i & 1 { 1 } else { -1 };
        score += fitness_cell(img, perspective, i + 7, 6) * expect;
        score += fitness_cell(img, perspective, 6, i + 7) * expect;
    }

    /* Check capstones */
    score += fitness_capstone(img, perspective, 0, 0);
    score += fitness_capstone(img, perspective, grid_size as i32 - 7, 0);
    score += fitness_capstone(img, perspective, 0, grid_size as i32 - 7);

    /* Check alignment patterns */
    let mut ap_count = 0;
    while ap_count < 7 && info.apat[ap_count] != 0 {
        ap_count += 1
    }
    for i in 1..(ap_count.saturating_sub(1)) {
        score += fitness_apat(img, perspective, 6, info.apat[i] as i32);
        score += fitness_apat(img, perspective, info.apat[i] as i32, 6);
    }
    for i in 1..ap_count {
        for j in 1..ap_count {
            score += fitness_apat(img, perspective, info.apat[i] as i32, info.apat[j] as i32);
        }
    }
    score
}

fn fitness_apat<S>(
    img: &PreparedImage<S>,
    perspective: &geometry::Perspective,
    cx: i32,
    cy: i32,
) -> i32
where
    S: ImageBuffer,
{
    fitness_cell(img, perspective, cx, cy) - fitness_ring(img, perspective, cx, cy, 1)
        + fitness_ring(img, perspective, cx, cy, 2)
}

fn fitness_ring<S>(
    img: &PreparedImage<S>,
    perspective: &geometry::Perspective,
    cx: i32,
    cy: i32,
    radius: i32,
) -> i32
where
    S: ImageBuffer,
{
    let mut score = 0;
    for i in 0..(radius * 2) {
        score += fitness_cell(img, perspective, cx - radius + i, cy - radius);
        score += fitness_cell(img, perspective, cx - radius, cy + radius - i);
        score += fitness_cell(img, perspective, cx + radius, cy - radius + i);
        score += fitness_cell(img, perspective, cx + radius - i, cy + radius);
    }
    score
}

fn fitness_cell<S>(
    img: &PreparedImage<S>,
    perspective: &geometry::Perspective,
    x: i32,
    y: i32,
) -> i32
where
    S: ImageBuffer,
{
    const OFFSETS: [f32; 3] = [0.3f32, 0.5f32, 0.7f32];
    let mut score = 0;
    #[allow(clippy::needless_range_loop)]
    for v in 0..3 {
        for u in 0..3 {
            let p = perspective.map(x as f32 + OFFSETS[u], y as f32 + OFFSETS[v]);
            if !(p.y < 0 || p.y as usize >= img.height() || p.x < 0 || p.x as usize >= img.width())
            {
                if PixelColor::White != img.get_pixel_at_point(p) {
                    score += 1
                } else {
                    score -= 1
                }
            }
        }
    }
    score
}

fn fitness_capstone<S>(
    img: &PreparedImage<S>,
    perspective: &geometry::Perspective,
    x: i32,
    y: i32,
) -> i32
where
    S: ImageBuffer,
{
    fitness_cell(img, perspective, x + 3, y + 3) + fitness_ring(img, perspective, x + 3, y + 3, 1)
        - fitness_ring(img, perspective, x + 3, y + 3, 2)
        + fitness_ring(img, perspective, x + 3, y + 3, 3)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact value, in i64, which these inputs cannot overflow.
    fn reference(a: &Point, c: &Point, seed: &Point) -> i64 {
        let dx_a = a.x as i64 - seed.x as i64;
        let dy_a = a.y as i64 - seed.y as i64;
        let dx_c = c.x as i64 - seed.x as i64;
        let dy_c = c.y as i64 - seed.y as i64;
        dx_a * -dy_c + dy_a * dx_c
    }

    fn p(x: i32, y: i32) -> Point {
        Point { x, y }
    }

    /// Deterministic coordinates inside a 480x480 frame. A free function, not
    /// a closure, so the sweep below borrows nothing across its calls.
    fn lcg(st: &mut u32) -> i32 {
        *st = st.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        ((*st >> 16) % 481) as i32
    }

    #[test]
    fn size_estimate_agrees_on_camera_geometry() {
        // Saturation must not change a real decode: inside a 480x480 frame
        // nothing overflows, so the answer must be exact.
        let mut st: u32 = 0x0E30_1234;
        let mut checked = 0u32;
        for _ in 0..20_000 {
            let a = p(lcg(&mut st), lcg(&mut st));
            let c = p(lcg(&mut st), lcg(&mut st));
            let s = p(lcg(&mut st), lcg(&mut st));
            let want = reference(&a, &c, &s).unsigned_abs() as usize;
            assert_eq!(
                alignment_size_estimate(&a, &c, &s),
                want,
                "a {:?} c {:?} s {:?}",
                a,
                c,
                s
            );
            checked += 1;
        }
        assert_eq!(checked, 20_000);
    }

    #[test]
    fn size_estimate_does_not_trap() {
        // Each of these overflows unsaturated arithmetic, and the dev profile
        // checks overflow, so reaching the end is the assertion. i32::MAX and
        // i32::MIN are corners `Perspective::map` can saturate to; 46,341
        // squared is the smallest ordinary-looking product past i32;
        // 200,000,000 is the scale `line_intersect` reaches with a
        // determinant of 1.
        let cases = [
            (p(i32::MAX, 0), p(0, 0), p(-1, 0)),
            (p(46_341, 0), p(0, 46_341), p(0, 0)),
            (p(0, 0), p(0, 11), p(200_000_000, 0)),
            // A difference of exactly i32::MIN: negating it traps on its
            // own, apart from either multiply.
            (p(0, 0), p(0, i32::MIN), p(0, 0)),
            (p(i32::MAX, i32::MAX), p(i32::MIN, i32::MIN), p(0, 0)),
            (
                p(i32::MIN, i32::MIN),
                p(i32::MAX, i32::MAX),
                p(i32::MAX, i32::MIN),
            ),
        ];
        for (a, c, s) in cases.iter() {
            let _ = alignment_size_estimate(a, c, s);
        }
    }

    #[test]
    fn size_estimate_is_orientation_independent() {
        // A cross product changes sign with the winding order; the estimate,
        // its magnitude, must not.
        let a = p(300, 120);
        let c = p(140, 260);
        let s = p(100, 100);
        assert_eq!(
            alignment_size_estimate(&a, &c, &s),
            alignment_size_estimate(&c, &a, &s)
        );
    }
}
