use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cmp;

use crate::identify::match_capstones::CapStoneGroup;
use crate::identify::Point;

/// Fixed-size LRU cache (251 entries max) replacing lru::LruCache for no_std.
/// Uses a simple array with age tracking. On eviction, the oldest entry is removed.
/// This matches the original rqrr behavior: capacity 251, keyed by u8.
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
        // Check if key already exists
        for i in 0..self.len {
            if self.keys[i] == key {
                self.values[i] = value;
                self.tick += 1;
                self.ages[i] = self.tick;
                return;
            }
        }

        // If not full, append
        if self.len < LRU_CAPACITY {
            self.keys[self.len] = key;
            self.values[self.len] = value;
            self.tick += 1;
            self.ages[self.len] = self.tick;
            self.len += 1;
        }
        // Should not happen — caller evicts before inserting when full
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

/// An image buffer over caller-owned memory. Exists so the decode working
/// set can live in internal SRAM on device: the heap (and therefore
/// BasicImageBuffer) is PSRAM, and PSRAM bandwidth is shared with the
/// display path and the camera DMA, which is what made detect times on
/// core 1 vary by 10x. The caller pre-fills the slice with grayscale;
/// prepare thresholds it in place, so there is no copy at all.
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

    fn raw_contiguous(&mut self) -> Option<*mut u8> {
        Some(self.pixels.as_mut_ptr())
    }
}

pub trait ImageBuffer {
    fn width(&self) -> usize;
    fn height(&self) -> usize;

    fn get_pixel(&self, x: usize, y: usize) -> u8;
    fn set_pixel(&mut self, x: usize, y: usize, val: u8);

    /// Base pointer for buffers whose pixels are one contiguous
    /// width*height u8 slab, row-major. Lets the binarizer run raw-pointer
    /// row loops (no per-pixel bounds checks, no y*w multiplies), which on
    /// the in-order Xtensa is the difference between ~90ms and tens of ms
    /// per 240x240 prepare. Default None keeps exotic buffers on the
    /// generic path.
    fn raw_contiguous(&mut self) -> Option<*mut u8> {
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

    fn raw_contiguous(&mut self) -> Option<*mut u8> {
        Some(self.pixels.as_mut_ptr())
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

    /// Like [prepare], but with an explicit threshold-window denominator.
    /// The adaptive binarizer averages over ~w/denom pixels. denom=8 is the
    /// quirc default. Smaller denom = wider window, which keeps the interior
    /// of very large QR modules (low versions rendered big) from washing out
    /// to white once the moving average adapts inside them.
    ///
    /// The window is rounded to the nearest power of two so the moving average
    /// and the threshold reduce to shifts. Upstream divides by a runtime value
    /// three times per pixel, which on Xtensa is a multi-cycle `quou` each and
    /// dominates this pass on a 240x240 image. The window is a smoothing
    /// length, so 30 -> 32 or 80 -> 64 changes nothing that matters.
    pub fn prepare_with_denom(mut buf: S, denom: usize) -> Self {
        let w = buf.width();
        let h = buf.height();
        // Static accumulator instead of a heap Vec. On device the heap is
        // PSRAM and this accumulator is touched four times per pixel; with
        // the shared data cache churned by the other core's display traffic,
        // those touches were mostly cache misses and dominated prepare time.
        // A static lands in .bss = internal SRAM. (A stack array was measured
        // to inflate the thread's stack floor by >20KB on the host, so
        // static it is.)
        //
        // SAFETY / invariant: prepare must not run on two cores at once. In
        // KasSigner that holds by construction — when the core-1 worker is
        // active, core 0 never calls into rqrr (the synchronous path is gated
        // off), and single-core builds are single-threaded.
        assert!(w <= 1024, "prepare: width exceeds row accumulator");
        static mut ROW_AVERAGE: [usize; 1024] = [0; 1024];
        let row_average: &mut [usize] = unsafe {
            core::slice::from_raw_parts_mut(
                core::ptr::addr_of_mut!(ROW_AVERAGE) as *mut usize, w)
        };
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

        let raw = buf.raw_contiguous();
        if let Some(base) = raw {
            // ── Raw-pointer fast path — bit-identical math ──
            // The generic path pays a y*w multiply plus a bounds check on
            // every access; at 4 accesses per pixel that overhead, not the
            // memory, dominated prepare on the in-order Xtensa. Row base is
            // hoisted, both zig-zag streams walk raw offsets.
            let black: u8 = PixelColor::Black.into();
            let white: u8 = PixelColor::White.into();
            for y in 0..h {
                row_average.fill(0);
                let row = unsafe { base.add(y * w) };
                if y % 2 == 0 {
                    // v runs right-to-left, u left-to-right
                    for x in 0..w {
                        let pv = unsafe { *row.add(w - 1 - x) } as usize;
                        let pu = unsafe { *row.add(x) } as usize;
                        avg_v = avg_v - ((avg_v + threshold_s - 1) >> shift) + pv;
                        avg_u = avg_u - ((avg_u + threshold_s - 1) >> shift) + pu;
                        unsafe {
                            *row_average.get_unchecked_mut(w - 1 - x) += avg_v;
                            *row_average.get_unchecked_mut(x) += avg_u;
                        }
                    }
                } else {
                    for x in 0..w {
                        let pv = unsafe { *row.add(x) } as usize;
                        let pu = unsafe { *row.add(w - 1 - x) } as usize;
                        avg_v = avg_v - ((avg_v + threshold_s - 1) >> shift) + pv;
                        avg_u = avg_u - ((avg_u + threshold_s - 1) >> shift) + pu;
                        unsafe {
                            *row_average.get_unchecked_mut(x) += avg_v;
                            *row_average.get_unchecked_mut(w - 1 - x) += avg_u;
                        }
                    }
                }
                for x in 0..w {
                    // floor(a/(200*s)) == floor(floor(a/200)/s), s = 1<<shift
                    let thresh = (unsafe { *row_average.get_unchecked(x) } * (100 - 5) / 200) >> shift;
                    unsafe {
                        let p = row.add(x);
                        *p = if (*p as usize) < thresh { black } else { white };
                    }
                }
            }
        } else {
            for y in 0..h {
                row_average.fill(0);

                for x in 0..w {
                    let (v, u) = if y % 2 == 0 {
                        (w - 1 - x, x)
                    } else {
                        (x, w - 1 - x)
                    };
                    // avg * (s-1) / s == avg - ceil(avg / s) for s = 1 << shift
                    avg_v = avg_v - ((avg_v + threshold_s - 1) >> shift) + buf.get_pixel(v, y) as usize;
                    avg_u = avg_u - ((avg_u + threshold_s - 1) >> shift) + buf.get_pixel(u, y) as usize;
                    row_average[v] += avg_v;
                    row_average[u] += avg_u;
                }

                #[allow(clippy::needless_range_loop)]
                for x in 0..w {
                    // floor(a / (200 * s)) == floor(floor(a / 200) / s) for s a
                    // power of two, so this stays bit-identical to the divide form
                    // while 200 is a literal the compiler turns into a multiply.
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
    /// Optimized for camera QR scanning: accepts the first plausible group
    /// without cloning the image for validation. This eliminates a 57KB+
    /// PSRAM allocation per candidate group.
    ///
    /// Trade-off: if multiple QR codes overlap, may pick wrong group.
    /// For single-QR camera frames this is always correct.
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
                // Accept first plausible group — skip validation clone
                // (saves 57KB+ PSRAM alloc + flood fill per candidate)
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
                // Cap flood fill at 5000 pixels — capstones are <2000,
                // background regions are 10000+ and dominate decode time
                let counter = self.repaint_and_apply_max((x, y), next_reg_color, AreaCounter(0), 5000);
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

    fn flood_fill_max<F>(&mut self, x: usize, y: usize, from: u8, to: u8, mut fill: F, max_pixels: usize) -> F
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
            if total_filled >= max_pixels { break; }

            // Cap queue size
            if queue.len() >= 2048 { continue; }

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

    /// Prepare over a caller-owned grayscale buffer, thresholding in place.
    /// No copy: the pixels slice IS the working image for detect and decode.
    pub fn prepare_borrowed_with_denom(
        w: usize,
        h: usize,
        denom: usize,
        pixels: &mut [u8],
    ) -> PreparedImage<BorrowedImageBuffer<'_>> {
        PreparedImage::prepare_with_denom(BorrowedImageBuffer::new(w, h, pixels), denom)
    }

    /// Like [prepare_from_greyscale], with an explicit threshold-window
    /// denominator (see [prepare_with_denom]).
    pub fn prepare_from_greyscale_with_denom<F>(w: usize, h: usize, denom: usize, mut fill: F) -> Self
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
