// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use embedded_graphics::{
    pixelcolor::{raw::RawU16, Rgb565},
    prelude::*,
    primitives::Rectangle,
};

pub struct TeeDisplay<D> {
    pub(crate) real: D,
    shadow_active: bool,
}

impl<D> TeeDisplay<D> {
    pub fn new(real: D) -> Self {
        Self {
            real,
            shadow_active: false,
        }
    }

    pub fn enable_shadow(&mut self) {
        self.shadow_active = crate::hw::screenshot::with_framebuffer_mut(|_| ()).is_some();
    }
}

fn write_shadow_pixel(framebuffer: &mut [u8], x: i32, y: i32, color: Rgb565) {
    if !(0..320).contains(&x) || !(0..240).contains(&y) {
        return;
    }
    let index = (y as usize * 320 + x as usize) * 2;
    let raw = RawU16::from(color).into_inner();
    framebuffer[index] = (raw >> 8) as u8;
    framebuffer[index + 1] = raw as u8;
}

impl<D> DrawTarget for TeeDisplay<D>
where
    D: DrawTarget<Color = Rgb565> + OriginDimensions,
{
    type Color = Rgb565;
    type Error = D::Error;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        let pixels: alloc::vec::Vec<Pixel<Rgb565>> = pixels.into_iter().collect();
        if self.shadow_active {
            let _ = crate::hw::screenshot::with_framebuffer_mut(|framebuffer| {
                for &Pixel(point, color) in &pixels {
                    write_shadow_pixel(framebuffer, point.x, point.y, color);
                }
            });
        }
        self.real.draw_iter(pixels)
    }

    fn fill_contiguous<I>(&mut self, area: &Rectangle, colors: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Self::Color>,
    {
        let colors: alloc::vec::Vec<Rgb565> = colors.into_iter().collect();
        if self.shadow_active {
            let _ = crate::hw::screenshot::with_framebuffer_mut(|framebuffer| {
                let mut x = area.top_left.x;
                let mut y = area.top_left.y;
                let x_end = area.top_left.x + area.size.width as i32;
                for &color in &colors {
                    write_shadow_pixel(framebuffer, x, y, color);
                    x += 1;
                    if x >= x_end {
                        x = area.top_left.x;
                        y += 1;
                    }
                }
            });
        }
        self.real.fill_contiguous(area, colors)
    }

    fn fill_solid(&mut self, area: &Rectangle, color: Self::Color) -> Result<(), Self::Error> {
        if self.shadow_active {
            let _ = crate::hw::screenshot::with_framebuffer_mut(|framebuffer| {
                let x_start = area.top_left.x.max(0) as usize;
                let y_start = area.top_left.y.max(0) as usize;
                let x_end = (area.top_left.x + area.size.width as i32).min(320).max(0) as usize;
                let y_end = (area.top_left.y + area.size.height as i32).min(240).max(0) as usize;
                for y in y_start..y_end {
                    for x in x_start..x_end {
                        write_shadow_pixel(framebuffer, x as i32, y as i32, color);
                    }
                }
            });
        }
        self.real.fill_solid(area, color)
    }

    fn clear(&mut self, color: Self::Color) -> Result<(), Self::Error> {
        if self.shadow_active {
            let raw = RawU16::from(color).into_inner();
            let _ = crate::hw::screenshot::with_framebuffer_mut(|framebuffer| {
                for pixel in framebuffer.chunks_exact_mut(2) {
                    pixel[0] = (raw >> 8) as u8;
                    pixel[1] = raw as u8;
                }
            });
        }
        self.real.clear(color)
    }

}

impl<D> OriginDimensions for TeeDisplay<D>
where
    D: OriginDimensions,
{
    fn size(&self) -> Size {
        self.real.size()
    }
}
