// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! M5Stack CoreS3 platform initialization facade.
//!
//! Each hardware concern owns a named initialization phase. The macro retains
//! only ESP-HAL singleton moves and inferred peripheral lifetimes that cannot be
//! expressed more cleanly outside the crate entry point.
pub(crate) mod audio;
pub(crate) mod camera;
pub(crate) mod display;
pub(crate) mod entropy;
pub(crate) mod kpub_worker;
pub(crate) mod power;
pub(crate) mod sd;
macro_rules! initialize {
    ($peripherals:ident, $delay:ident) => {{
        log!("Initializing Display (CoreS3)");
        log!("──────────────────────────────────────────");

        // Shared CoreS3 control bus: PMU, IO expander, touch, camera SCCB.
        let mut i2c = I2c::new(
            $peripherals.I2C0,
            $crate::boot::m5stack::power::control_bus_config(),
        )
        .expect("I2C0 init failed — hardware fault")
        .with_sda($peripherals.GPIO12)
        .with_scl($peripherals.GPIO11);
        $crate::boot::m5stack::power::initialize(&mut i2c, &mut $delay);
        // One HAL-owned SPI2 bus serves both CoreS3 devices for the lifetime of
        // the firmware. GPIO35 is attached as MISO and becomes LCD D/C only
        // while the LCD chip-select is active.
        let spi = Spi::new(
            $peripherals.SPI2,
            SpiConfig::default()
                .with_frequency(Rate::from_mhz(40))
                .with_mode(SpiMode::_0),
        )
        .expect("SPI2 init failed — hardware fault")
        .with_sck($peripherals.GPIO36)
        .with_mosi($peripherals.GPIO37)
        .with_miso($peripherals.GPIO35);
        let sd_cs = Output::new($peripherals.GPIO4, Level::High, OutputConfig::default());
        $crate::hw::initialize_cores3_spi(spi, sd_cs)
            .expect("CoreS3 shared SPI2 init failed — hardware fault");

        // Connected CoreS3 workflow E2E intentionally exercises the real SD
        // transport. Audio/entropy/camera remain deferred outside HIL, but
        // removable-storage detection must never be faked as absent.
        let sd_card_type = $crate::boot::m5stack::sd::initialize(&mut i2c, &mut $delay);
        // Bring up the visible liveness surface.
        let cs_pin = Output::new($peripherals.GPIO3, Level::High, OutputConfig::default());
        let reset_pin = Output::new($peripherals.GPIO14, Level::High, OutputConfig::default());
        let boot_display = $crate::boot::m5stack::display::initialize(
            cs_pin, reset_pin, &mut i2c, &mut $delay,
        );
        #[cfg(all(feature = "workflow-test-auto", not(feature = "workflow-runtime-auto")))]
        {
            log!("KASSIGNER_WORKFLOW_TESTS: OPTIONAL AUDIO/ENTROPY/CAMERA SKIPPED; SD PROBED");
            log!("KASSIGNER_WORKFLOW_TESTS: BOARD PHASES COMPLETE");
            (i2c, boot_display, None::<DvpCamera<'_>>, None::<esp_hal::dma::DmaRxBuf>,
             hw::camera::CameraStatus::Error, sd_card_type, None::<$crate::hw::sound::RuntimeAudio>)
        }
        #[cfg(any(not(feature = "workflow-test-auto"), feature = "workflow-runtime-auto"))]
        {
            // Audio ownership: construct HAL objects here; phase logic lives in audio.rs.
            log!("   I2S1 hardware peripheral init...");
            let (_, _, tx_buffer, tx_descriptors) = esp_hal::dma_buffers!(0, 4 * 4092);
            use esp_hal::i2s::master::{Channels, Config as I2sConfig2, DataFormat, I2s};
            let i2s_config = I2sConfig2::new_tdm_philips()
                .with_sample_rate(Rate::from_hz(48000))
                .with_data_format(DataFormat::Data16Channel16)
                .with_channels(Channels::STEREO);
            let runtime_audio = if let Ok(i2s) = I2s::new($peripherals.I2S1, $peripherals.DMA_CH1, i2s_config) {
                let i2s_tx = i2s.i2s_tx.with_bclk($peripherals.GPIO34).with_ws($peripherals.GPIO33)
                    .with_dout($peripherals.GPIO13).build(tx_descriptors);
                $crate::boot::m5stack::audio::initialize(&mut i2c, &mut $delay, i2s_tx, tx_buffer)
            } else { log!("   I2S1 config failed"); None };
            $crate::boot::m5stack::entropy::initialize(&mut i2c, &mut $delay);
            // Camera ownership is HAL-exclusive: LCD_CAM owns MCLK and every DVP pin.
            $crate::boot::m5stack::camera::begin_phase();
            log!("   LCD_CAM DVP init (HAL-owned clock + pins)...");
            let cam_config = CamConfig::default().with_frequency(Rate::from_mhz(20));
            let lcd_cam = LcdCam::new($peripherals.LCD_CAM);
            let (rx_buffer, rx_descriptors, _, _) = esp_hal::dma_buffers!(76800, 0);
            let cam_dma_buf = esp_hal::dma::DmaRxBuf::new(rx_descriptors, rx_buffer)
                .expect("DMA buffer allocation failed");
            let cam_dma_buf_opt = Some(cam_dma_buf);
            let cam_build = DvpCamera::new(lcd_cam.cam, $peripherals.DMA_CH0, cam_config);
            let mut cam_status = hw::camera::CameraStatus::Error;
            let mut dvp_camera_opt: Option<DvpCamera<'_>> = None;
            match cam_build {
                Ok(camera) => {
                    let camera = camera.with_master_clock($peripherals.GPIO2)
                        .with_pixel_clock($peripherals.GPIO45).with_vsync($peripherals.GPIO46)
                        .with_h_enable($peripherals.GPIO38).with_data0($peripherals.GPIO39)
                        .with_data1($peripherals.GPIO40).with_data2($peripherals.GPIO41)
                        .with_data3($peripherals.GPIO42).with_data4($peripherals.GPIO15)
                        .with_data5($peripherals.GPIO16).with_data6($peripherals.GPIO48)
                        .with_data7($peripherals.GPIO47);
                    cam_status = $crate::boot::m5stack::camera::initialize_sensor(&mut i2c, &mut $delay);
                    dvp_camera_opt = Some($crate::boot::m5stack::camera::finish_dvp(camera));
                }
                Err(_) => log!("   LCD_CAM DVP FAILED — config error"),
            }
            $crate::boot::m5stack::camera::finish_sensor_status(cam_status);
            #[cfg(feature = "workflow-runtime-auto")]
            {
                log!(
                    "KASSIGNER_WORKFLOW_RUNTIME: PERIPHERALS READY sd={} audio={} camera={:?}",
                    sd_card_type.is_some(), runtime_audio.is_some(), cam_status
                );
                log!("KASSIGNER_WORKFLOW_RUNTIME: REAL PMU/TOUCH/ENTROPY/CAMERA INIT PATH EXECUTED");
                #[cfg(feature = "workflow-hil-auto")]
                log!("KASSIGNER_WORKFLOW_HIL: DESTRUCTIVE MEDIA PROFILE ENABLED");
                log!("KASSIGNER_WORKFLOW_TESTS: BOARD PHASES COMPLETE");
            }
            (i2c, boot_display, dvp_camera_opt, cam_dma_buf_opt, cam_status, sd_card_type, runtime_audio)
        }
    }}
}

pub(crate) use initialize;
