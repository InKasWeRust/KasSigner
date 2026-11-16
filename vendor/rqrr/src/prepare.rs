use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cmp;

use crate::identify::match_capstones::CapStoneGroup;
use crate::identify::Point;

/// KASSIGNER: a fixed-size LRU for no_std, in place of lru::LruCache, with
/// upstream's capacity (251) and u8 keys; the oldest entry is evicted.
const LRU_CAPACITY: usize = 251;

struct FixedLru {
    keys: [u8; LRU_CAPACITY],
    values: [ColoredRegion; LRU_CAPACITY],
    ages: [u32; LRU_CAPACITY],
    len: usize,
    tick: u32,
}

impl FixedLru {
    fn new() -> Self {
        FixedLru {
            keys: [0; LRU_CAPACITY],
            values: [ColoredRegion::Tmp1; LRU_CAPACITY],
            ages: [0; LRU_CAPACITY],
            len: 0,
            tick: 0,
        }
    }

    fn cap(&self) -> usize {
        LRU_CAPACITY
    }

    fn len(&self) -> usize {
        self.len
    }

    fn get(&mut self, key: &u8) -> Option<&ColoredRegion> {
        for i in 0..self.len {
            if self.keys[i] == *key {
                self.tick += 1;
                self.ages[i] = self.tick;
                return Some(&self.values[i]);
            }
        }
        None
    }

    fn put(&mut self, key: u8, value: ColoredRegion) {
        for i in 0..self.len {
            if self.keys[i] == key {
                self.values[i] = value;
                self.tick += 1;
                self.ages[i] = self.tick;
                return;
            }
        }

        if self.len < LRU_CAPACITY {
            self.keys[self.len] = key;
            self.values[self.len] = value;
            self.tick += 1;
            self.ages[self.len] = self.tick;
            self.len += 1;
        }
        // When full the entry is dropped; the caller evicts first, so it
        // never is.
    }

    /// Pop the least recently used entry. Returns (key, value).
    fn pop_lru(&mut self) -> Option<(u8, ColoredRegion)> {
        if self.len == 0 {
            return None;
        }
        let mut oldest_idx = 0;
        let mut oldest_age = self.ages[0];
        for i in 1..self.len {
            if self.ages[i] < oldest_age {
                oldest_age = self.ages[i];
                oldest_idx = i;
            }
        }
        let key = self.keys[oldest_idx];
        let value = self.values[oldest_idx];

        // Swap-remove: move last element into the hole
        self.len -= 1;
        if oldest_idx < self.len {
            self.keys[oldest_idx] = self.keys[self.len];
            self.values[oldest_idx] = self.values[self.len];
            self.ages[oldest_idx] = self.ages[self.len];
        }

        Some((key, value))
    }
}

impl Clone for FixedLru {
    fn clone(&self) -> Self {
        FixedLru {
            keys: self.keys,
            values: self.values,
            ages: self.ages,
            len: self.len,
            tick: self.tick,
        }
    }
}

/// An black-and-white image that can be mutated on search for QR codes
///
/// During search for QR codes, some black zones will be recolored in
/// 'different' shades of black. This is done to speed up the search and
/// mitigate the impact of a huge zones.
pub struct PreparedImage<S> {
    buffer: S,
    cache: FixedLru,
}

impl<S> Clone for PreparedImage<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        PreparedImage {
            buffer: self.buffer.clone(),
            cache: self.cache.clone(),
        }
    }
}

/// An image over caller-owned grayscale pixels, thresholded in place, so the
/// decode's working set can sit in internal SRAM, not in the PSRAM heap
/// whose bandwidth the display and camera DMA share (detect times varied
/// tenfold).
pub struct BorrowedImageBuffer<'b> {
    w: usize,
    h: usize,
    pixels: &'b mut [u8],
}

impl<'b> BorrowedImageBuffer<'b> {
    pub fn new(w: usize, h: usize, pixels: &'b mut [u8]) -> Self {
        assert!(pixels.len() >= w * h);
        BorrowedImageBuffer { w, h, pixels }
    }
}

impl ImageBuffer for BorrowedImageBuffer<'_> {
    fn width(&self) -> usize {
        self.w
    }

    fn height(&self) -> usize {
        self.h
    }

    fn get_pixel(&self, x: usize, y: usize) -> u8 {
        self.pixels[(y * self.w) + x]
    }

    fn set_pixel(&mut self, x: usize, y: usize, val: u8) {
        self.pixels[(y * self.w) + x] = val
    }

    fn raw_contiguous(&mut self) -> Option<&mut [u8]> {
        Some(&mut self.pixels[..self.w * self.h])
    }
}

pub trait ImageBuffer {
    fn width(&self) -> usize;
    fn height(&self) -> usize;

    fn get_pixel(&self, x: usize, y: usize) -> u8;
    fn set_pixel(&mut self, x: usize, y: usize, val: u8);

    /// The pixels, if one contiguous row-major width*height slab, for the
    /// binarizer to walk rows as slices (tens of ms instead of about 90 for a
    /// 240x240 prepare on Xtensa). `None` keeps the generic path.
    fn raw_contiguous(&mut self) -> Option<&mut [u8]> {
        None
    }
}

#[derive(Clone, Debug)]
pub struct BasicImageBuffer {
    w: usize,
    h: usize,
    pixels: Box<[u8]>,
}

impl ImageBuffer for BasicImageBuffer {
    fn width(&self) -> usize {
        self.w
    }

    fn height(&self) -> usize {
        self.h
    }

    fn get_pixel(&self, x: usize, y: usize) -> u8 {
        let w = self.width();
        self.pixels[(y * w) + x]
    }

    fn set_pixel(&mut self, x: usize, y: usize, val: u8) {
        let w = self.width();
        self.pixels[(y * w) + x] = val
    }

    fn raw_contiguous(&mut self) -> Option<&mut [u8]> {
        Some(&mut self.pixels[..self.w * self.h])
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Row {
    pub left: usize,
    pub right: usize,
    pub y: usize,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PixelColor {
    White,
    Black,
    CapStone,
    Alignment,
    Tmp1,
    Discarded(u8),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ColoredRegion {
    Unclaimed {
        color: PixelColor,
        src_x: usize,
        src_y: usize,
        pixel_count: usize,
    },
    CapStone,
    Alignment,
    Tmp1,
}

impl From<u8> for PixelColor {
    fn from(x: u8) -> Self {
        match x {
            0 => PixelColor::White,
            1 => PixelColor::Black,
            2 => PixelColor::CapStone,
            3 => PixelColor::Alignment,
            4 => PixelColor::Tmp1,
            x => PixelColor::Discarded(x - 5),
        }
    }
}

impl From<PixelColor> for u8 {
    fn from(c: PixelColor) -> Self {
        match c {
            PixelColor::White => 0,
            PixelColor::Black => 1,
            PixelColor::CapStone => 2,
            PixelColor::Alignment => 3,
            PixelColor::Tmp1 => 4,
            PixelColor::Discarded(x) => x + 5,
        }
    }
}

impl PartialEq<u8> for PixelColor {
    fn eq(&self, other: &u8) -> bool {
        let rep: u8 = (*self).into();
        rep == *other
    }
}

/// The widest row a [`crate::Scratch`]'s accumulator takes.
pub const ROW_MAX: usize = 1024;

/// One step of a running average over `s = 1 << shift` pixels:
/// avg * (s-1) / s, as avg - ceil(avg / s), plus the pixel. A function, not
/// a closure: at `opt-level = "z"` a closure called per pixel is not inlined;
/// a function's `inline(always)` is.
#[inline(always)]
fn step(avg: usize, p: u8, threshold_s: usize, shift: usize) -> usize {
    avg - ((avg + threshold_s - 1) >> shift) + p as usize
}

/// KASSIGNER: the binarizer over a contiguous slab, row by row as slices,
/// bit-identical to the generic path. The two zig-zag averages share one
/// pass and never read each other, so both stay in flight on an in-order
/// core. Each index is bounded by its loop, so the compiler drops the bounds
/// checks (34 instructions a pixel on the P4 at `opt-level = "z"`); a zip of
/// the four slice iterators would add three end checks.
#[allow(clippy::needless_range_loop)]
fn binarize_rows(pixels: &mut [u8], w: usize, h: usize, shift: usize, acc: &mut [usize]) {
    let threshold_s = 1usize << shift;
    let black: u8 = PixelColor::Black.into();
    let white: u8 = PixelColor::White.into();
    let mut avg_v = 0usize;
    let mut avg_u = 0usize;
    for (y, row) in pixels.chunks_exact_mut(w).take(h).enumerate() {
        acc.fill(0);
        // v runs right-to-left on even rows and u left-to-right; the other
        // way round on odd rows.
        let n = row.len();
        let acc = &mut acc[..n];
        if y % 2 == 0 {
            for x in 0..n {
                avg_v = step(avg_v, row[n - 1 - x], threshold_s, shift);
                avg_u = step(avg_u, row[x], threshold_s, shift);
                acc[n - 1 - x] += avg_v;
                acc[x] += avg_u;
            }
        } else {
            for x in 0..n {
                avg_v = step(avg_v, row[x], threshold_s, shift);
                avg_u = step(avg_u, row[n - 1 - x], threshold_s, shift);
                acc[x] += avg_v;
                acc[n - 1 - x] += avg_u;
            }
        }
        for (p, a) in row.iter_mut().zip(acc.iter()) {
            // floor(a/(200*s)) == floor(floor(a/200)/s), s = 1<<shift
            let thresh = (a * (100 - 5) / 200) >> shift;
            *p = if (*p as usize) < thresh { black } else { white };
        }
    }
}

pub trait AreaFiller {
    fn update(&mut self, row: Row);
}

impl<F> AreaFiller for F
where
    F: FnMut(Row),
{
    fn update(&mut self, row: Row) {
        self(row)
    }
}

struct AreaCounter(usize);

impl AreaFiller for AreaCounter {
    fn update(&mut self, row: Row) {
        self.0 += row.right - row.left + 1;
    }
}

impl<S> PreparedImage<S>
where
    S: ImageBuffer,
{
    pub fn prepare(buf: S) -> Self {
        Self::prepare_with_denom(buf, 8)
    }

    /// Like [prepare], with the threshold window's denominator: the binarizer
    /// averages over about w/denom pixels (quirc's default is 8). A wider
    /// window keeps very large modules from washing out to white inside.
    ///
    /// The window is rounded to a power of two so the average and threshold
    /// are shifts, not upstream's three divides a pixel (each a multi-cycle
    /// `quou` on Xtensa); for a smoothing length, 30 -> 32 changes nothing.
    pub fn prepare_with_denom(buf: S, denom: usize) -> Self {
        let mut rows = alloc::vec![0usize; buf.width()];
        Self::prepare_with_rows(buf, denom, &mut rows)
    }

    /// [prepare_with_denom] with the row accumulator in `rows`, at least the
    /// image's width, which it leaves zeroed.
    ///
    /// KASSIGNER: the accumulator is the caller's [`crate::Scratch`] (on the
    /// boards, internal SRAM), not a heap Vec in PSRAM: touched four times a
    /// pixel, it missed the cache the other core's display traffic churns and
    /// dominated prepare time. Not a static: two prepares at once would mix
    /// their rows, and a guard flag would stay set after one that trapped, as
    /// in a browser.
    pub fn prepare_with_rows(mut buf: S, denom: usize, rows: &mut [usize]) -> Self {
        let w = buf.width();
        let h = buf.height();
        assert!(w <= rows.len(), "prepare: width exceeds row accumulator");
        let row_average = &mut rows[..w];
        let mut avg_v = 0;
        let mut avg_u = 0;

        // Nearest power of two to w/denom, at least 1.
        let target = cmp::max(w / cmp::max(denom, 1), 1);
        let mut shift = 0usize;
        while (1usize << (shift + 1)) <= target {
            shift += 1;
        }
        if (target - (1usize << shift)) > ((1usize << (shift + 1)) - target) {
            shift += 1;
        }
        let threshold_s = 1usize << shift;

        let fast = match buf.raw_contiguous() {
            Some(pixels) => {
                binarize_rows(pixels, w, h, shift, row_average);
                true
            }
            None => false,
        };
        if !fast {
            for y in 0..h {
                row_average.fill(0);

                for x in 0..w {
                    let (v, u) = if y % 2 == 0 {
                        (w - 1 - x, x)
                    } else {
                        (x, w - 1 - x)
                    };
                    // avg * (s-1) / s == avg - ceil(avg / s) for s = 1 << shift
                    avg_v =
                        avg_v - ((avg_v + threshold_s - 1) >> shift) + buf.get_pixel(v, y) as usize;
                    avg_u =
                        avg_u - ((avg_u + threshold_s - 1) >> shift) + buf.get_pixel(u, y) as usize;
                    row_average[v] += avg_v;
                    row_average[u] += avg_u;
                }

                #[allow(clippy::needless_range_loop)]
                for x in 0..w {
                    // Bit-identical to the divide form, as floor(a / (200 * s))
                    // == floor(floor(a / 200) / s), with 200 a literal the
                    // compiler turns into a multiply.
                    let thresh = (row_average[x] * (100 - 5) / 200) >> shift;
                    let fill = if (buf.get_pixel(x, y) as usize) < thresh {
                        PixelColor::Black
                    } else {
                        PixelColor::White
                    };
                    buf.set_pixel(x, y, fill.into());
                }
            }
        }
        // KASSIGNER: the accumulator left zeroed, as it was lent: the last
        // row's averages are a trace of the picture.
        row_average.fill(0);

        PreparedImage {
            buffer: buf,
            cache: FixedLru::new(),
        }
    }

    /// Group [CapStones](struct.CapStone.html) into [Grids](struct.Grid.html)
    /// that are likely QR codes
    ///
    /// Return a vector of Grids
    pub fn detect_grids<'a>(
        &'a mut self,
    ) -> Vec<crate::Grid<crate::identify::grid::RefGridImage<'a, S>>> {
        let mut res = Vec::new();
        let stones = crate::capstones_from_image(self);
        let groups = self.find_groupings(stones);
        let locations: Vec<_> = groups
            .into_iter()
            .filter_map(|v| crate::SkewedGridLocation::from_group(self, v))
            .collect();
        for grid_location in locations {
            let bounds = [
                grid_location.c.map(0.0, 0.0),
                grid_location
                    .c
                    .map(grid_location.grid_size as f32 + 1.0, 0.0),
                grid_location.c.map(
                    grid_location.grid_size as f32 + 1.0,
                    grid_location.grid_size as f32 + 1.0,
                ),
                grid_location
                    .c
                    .map(0.0, grid_location.grid_size as f32 + 1.0),
            ];
            let grid = grid_location.into_grid_image(self);
            res.push(crate::Grid { grid, bounds });
        }

        res
    }

    /// Find CapStones that form a grid
    ///
    /// KASSIGNER: takes the first plausible group, without upstream's check
    /// on a clone of the image (57 KB+ of PSRAM per candidate). Where codes
    /// overlap, or noise looks like a finder pattern, it may pick a wrong
    /// group, and a code may then not be found.
    fn find_groupings(&mut self, capstones: Vec<crate::CapStone>) -> Vec<CapStoneGroup> {
        let mut used_capstones = Vec::new();
        let mut groups = Vec::new();
        for idx in 0..capstones.len() {
            if used_capstones.contains(&idx) {
                continue;
            }
            let pairs = crate::identify::find_and_rank_possible_neighbors(&capstones, idx);
            for pair in pairs {
                if used_capstones.contains(&pair.0) || used_capstones.contains(&pair.1) {
                    continue;
                }
                let group_under_test = CapStoneGroup(
                    capstones[pair.0].clone(),
                    capstones[idx].clone(),
                    capstones[pair.1].clone(),
                );
                // The first plausible group, with no validation clone.
                groups.push(group_under_test);
                used_capstones.push(pair.0);
                used_capstones.push(idx);
                used_capstones.push(pair.1);
                break; // first group found, stop searching
            }
        }
        groups
    }

    pub fn without_preparation(buf: S) -> Self {
        for y in 0..buf.height() {
            for x in 0..buf.width() {
                assert!(buf.get_pixel(x, y) < 2);
            }
        }

        PreparedImage {
            buffer: buf,
            cache: FixedLru::new(),
        }
    }

    /// Return the width of the image
    pub fn width(&self) -> usize {
        self.buffer.width()
    }

    /// Return the height of the image
    pub fn height(&self) -> usize {
        self.buffer.height()
    }

    pub(crate) fn get_region(&mut self, (x, y): (usize, usize)) -> ColoredRegion {
        let color: PixelColor = self.buffer.get_pixel(x, y).into();
        match color {
            PixelColor::Discarded(r) => *self.cache.get(&r).unwrap(),
            PixelColor::Black => {
                let cache_fill = self.cache.len();
                let reg_idx = if cache_fill == self.cache.cap() {
                    let (c, reg) = self.cache.pop_lru().expect("fill is at capacity (251)");
                    #[allow(clippy::single_match)]
                    match reg {
                        ColoredRegion::Unclaimed {
                            src_x,
                            src_y,
                            color,
                            ..
                        } => {
                            let _ = self.flood_fill(
                                src_x,
                                src_y,
                                color.into(),
                                PixelColor::Black.into(),
                                |_| (),
                            );
                        }
                        _ => (),
                    }
                    c
                } else {
                    cache_fill as u8
                };
                let next_reg_color = PixelColor::Discarded(reg_idx);
                // Fill at most 5000 pixels: background regions, 10,000 and
                // more, dominate decode time. A capped count is a lower bound,
                // and what the fill did not reach is counted later as a region
                // of its own. Real finder rings (about 3,000 when a code fills
                // the frame) and alignment patterns stay well under the cap.
                let counter =
                    self.repaint_and_apply_max((x, y), next_reg_color, AreaCounter(0), 5000);
                let new_reg = ColoredRegion::Unclaimed {
                    color: next_reg_color,
                    src_x: x,
                    src_y: y,
                    pixel_count: counter.0,
                };
                self.cache.put(reg_idx, new_reg);
                new_reg
            }
            PixelColor::Tmp1 => ColoredRegion::Tmp1,
            PixelColor::Alignment => ColoredRegion::Alignment,
            PixelColor::CapStone => ColoredRegion::CapStone,
            PixelColor::White => panic!("Tried to color white patch"),
        }
    }

    pub(crate) fn repaint_and_apply<F>(
        &mut self,
        (x, y): (usize, usize),
        target_color: PixelColor,
        fill: F,
    ) -> F
    where
        F: AreaFiller,
    {
        let src = self.buffer.get_pixel(x, y);
        if PixelColor::White == src || target_color == src {
            panic!("Cannot repaint with white or same color");
        }

        self.flood_fill(x, y, src, target_color.into(), fill)
    }

    pub(crate) fn repaint_and_apply_max<F>(
        &mut self,
        (x, y): (usize, usize),
        target_color: PixelColor,
        fill: F,
        max_pixels: usize,
    ) -> F
    where
        F: AreaFiller,
    {
        let src = self.buffer.get_pixel(x, y);
        if PixelColor::White == src || target_color == src {
            panic!("Cannot repaint with white or same color");
        }

        self.flood_fill_max(x, y, src, target_color.into(), fill, max_pixels)
    }

    pub fn get_pixel_at_point(&self, p: Point) -> PixelColor {
        let x = cmp::max(0, cmp::min((self.width() - 1) as i32, p.x));
        let y = cmp::max(0, cmp::min((self.height() - 1) as i32, p.y));
        self.buffer.get_pixel(x as usize, y as usize).into()
    }

    pub fn get_pixel_at(&self, x: usize, y: usize) -> PixelColor {
        self.buffer.get_pixel(x, y).into()
    }

    fn flood_fill<F>(&mut self, x: usize, y: usize, from: u8, to: u8, fill: F) -> F
    where
        F: AreaFiller,
    {
        self.flood_fill_max(x, y, from, to, fill, usize::MAX)
    }

    fn flood_fill_max<F>(
        &mut self,
        x: usize,
        y: usize,
        from: u8,
        to: u8,
        mut fill: F,
        max_pixels: usize,
    ) -> F
    where
        F: AreaFiller,
    {
        assert_ne!(from, to);
        let w = self.width();
        let mut queue = Vec::with_capacity(256);
        queue.push((x, y));
        let mut total_filled: usize = 0;

        while let Some((x, y)) = queue.pop() {
            // Bail early in case there is nothing to fill
            if self.buffer.get_pixel(x, y) == to || self.buffer.get_pixel(x, y) != from {
                continue;
            }

            let mut left = x;
            let mut right = x;

            while left > 0 && self.buffer.get_pixel(left - 1, y) == from {
                left -= 1;
            }
            while right < w - 1 && self.buffer.get_pixel(right + 1, y) == from {
                right += 1
            }

            /* Fill the extent */
            let span = right - left + 1;
            for idx in left..=right {
                self.buffer.set_pixel(idx, y, to);
            }

            fill.update(Row { left, right, y });
            total_filled += span;

            // Early termination for large regions
            if total_filled >= max_pixels {
                break;
            }

            // Cap the queue: past 2,048 pending seeds no more are added, so a
            // ragged region (noise) may be painted only in part.
            if queue.len() >= 2048 {
                continue;
            }

            /* Seed new flood-fills */
            if y > 0 {
                let mut seeded_previous = false;
                for x in left..=right {
                    let p = self.buffer.get_pixel(x, y - 1);
                    if p == from {
                        if !seeded_previous {
                            queue.push((x, y - 1));
                        }
                        seeded_previous = true;
                    } else {
                        seeded_previous = false;
                    }
                }
            }
            if y < self.height() - 1 {
                let mut seeded_previous = false;
                for x in left..=right {
                    let p = self.buffer.get_pixel(x, y + 1);
                    if p == from {
                        if !seeded_previous {
                            queue.push((x, y + 1));
                        }
                        seeded_previous = true;
                    } else {
                        seeded_previous = false;
                    }
                }
            }
        }
        fill
    }
}

impl PreparedImage<BasicImageBuffer> {
    /// Given a function with binary output, generate a searchable image
    ///
    /// If the given function returns `true` the matching pixel will be 'black'.
    pub fn prepare_from_bitmap<F>(w: usize, h: usize, mut fill: F) -> Self
    where
        F: FnMut(usize, usize) -> bool,
    {
        let capacity = w.checked_mul(h).expect("Image dimensions caused overflow");
        let mut pixels = Vec::with_capacity(capacity);

        for y in 0..h {
            for x in 0..w {
                let col = if fill(x, y) {
                    PixelColor::Black
                } else {
                    PixelColor::White
                };
                pixels.push(col.into())
            }
        }
        let pixels = pixels.into_boxed_slice();
        let buffer = BasicImageBuffer { w, h, pixels };
        PreparedImage::without_preparation(buffer)
    }

    /// Given a byte valued function, generate a searchable image
    ///
    /// The values returned by the function are interpreted as luminance. i.e. a
    /// value of 0 is black, 255 is white.
    pub fn prepare_from_greyscale<F>(w: usize, h: usize, fill: F) -> Self
    where
        F: FnMut(usize, usize) -> u8,
    {
        Self::prepare_from_greyscale_with_denom(w, h, 8, fill)
    }

    /// Prepare over a caller-owned grayscale buffer, thresholded in place:
    /// the slice is the working image for detect and decode.
    pub fn prepare_borrowed_with_denom(
        w: usize,
        h: usize,
        denom: usize,
        pixels: &mut [u8],
    ) -> PreparedImage<BorrowedImageBuffer<'_>> {
        PreparedImage::prepare_with_denom(BorrowedImageBuffer::new(w, h, pixels), denom)
    }

    /// KASSIGNER: [prepare_borrowed_with_denom] with the row accumulator in
    /// `scratch`, not on the heap.
    pub fn prepare_borrowed_in<'a>(
        w: usize,
        h: usize,
        denom: usize,
        pixels: &'a mut [u8],
        scratch: &mut crate::Scratch,
    ) -> PreparedImage<BorrowedImageBuffer<'a>> {
        PreparedImage::prepare_with_rows(
            BorrowedImageBuffer::new(w, h, pixels),
            denom,
            scratch.rows(),
        )
    }

    /// Like [prepare_from_greyscale], with an explicit threshold-window
    /// denominator (see [prepare_with_denom]).
    pub fn prepare_from_greyscale_with_denom<F>(
        w: usize,
        h: usize,
        denom: usize,
        mut fill: F,
    ) -> Self
    where
        F: FnMut(usize, usize) -> u8,
    {
        let capacity = w.checked_mul(h).expect("Image dimensions caused overflow");
        let mut data = Vec::with_capacity(capacity);
        for y in 0..h {
            for x in 0..w {
                data.push(fill(x, y));
            }
        }
        let pixels = data.into_boxed_slice();
        let buffer = BasicImageBuffer { w, h, pixels };
        PreparedImage::prepare_with_denom(buffer, denom)
    }
}
