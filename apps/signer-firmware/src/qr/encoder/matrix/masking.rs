use super::matrix::QrCode;

impl QrCode {
    pub(super) fn apply_best_mask(&mut self) {
        let saved_modules = self.modules;
        let mut best_mask = 0u8;
        let mut best_penalty = u32::MAX;

        for mask in 0..8u8 {
            self.modules = saved_modules;
            self.apply_mask(mask);
            self.write_format_info(mask);
            let penalty = self.penalty_score();
            if penalty < best_penalty {
                best_penalty = penalty;
                best_mask = mask;
            }
        }

        self.modules = saved_modules;
        self.apply_mask(best_mask);
        self.write_format_info(best_mask);
    }

    fn apply_mask(&mut self, mask: u8) {
        for y in 0..self.size {
            for x in 0..self.size {
                if self.is_function(x, y) {
                    continue;
                }
                let product = y as u16 * x as u16;
                let invert = match mask {
                    0 => (y + x) % 2 == 0,
                    1 => y % 2 == 0,
                    2 => x % 3 == 0,
                    3 => (y + x) % 3 == 0,
                    4 => (y / 2 + x / 3) % 2 == 0,
                    5 => product % 2 + product % 3 == 0,
                    6 => (product % 2 + product % 3) % 2 == 0,
                    7 => ((y + x) as u16 % 2 + product % 3) % 2 == 0,
                    _ => false,
                };
                if invert {
                    let index = self.index(x, y);
                    self.modules[index / 8] ^= 1 << (index % 8);
                }
            }
        }
    }

    fn penalty_score(&self) -> u32 {
        let size = self.size as usize;
        let mut penalty = 0u32;

        for y in 0..size {
            penalty += line_run_penalty((0..size).map(|x| self.get(x as u8, y as u8)));
        }
        for x in 0..size {
            penalty += line_run_penalty((0..size).map(|y| self.get(x as u8, y as u8)));
        }

        for y in 0..size - 1 {
            for x in 0..size - 1 {
                let value = self.get(x as u8, y as u8);
                if value == self.get(x as u8 + 1, y as u8)
                    && value == self.get(x as u8, y as u8 + 1)
                    && value == self.get(x as u8 + 1, y as u8 + 1)
                {
                    penalty += 3;
                }
            }
        }

        let mut dark_count = 0u32;
        for y in 0..size {
            for x in 0..size {
                dark_count += self.get(x as u8, y as u8) as u32;
            }
        }
        let percentage = dark_count * 100 / (size * size) as u32;
        penalty + (percentage.abs_diff(50) / 5) * 10
    }
}

fn line_run_penalty(values: impl Iterator<Item = bool>) -> u32 {
    let mut penalty = 0u32;
    let mut previous = false;
    let mut run_length = 0u32;
    for (index, value) in values.enumerate() {
        if index == 0 || value != previous {
            previous = value;
            run_length = 1;
        } else {
            run_length += 1;
            penalty += match run_length {
                5 => 3,
                6.. => 1,
                _ => 0,
            };
        }
    }
    penalty
}
