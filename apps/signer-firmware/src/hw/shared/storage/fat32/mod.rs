// Real FAT32 modules with a focused façade.

mod types;
pub use types::{DirEntry, Fat32Info, SdCardType, format_83_display};
use crate::hw::sdcard::{
    fast_read_multi_block, fast_write_multi_block, sd_read_block, sd_sector_count, sd_write_block,
};
use esp_hal::delay::Delay;

mod policy;
pub use policy::{read_fat_entry, read_file_progress, to_83_name};

mod allocation;
pub use allocation::{allocate_chain, allocate_cluster, write_fat_entry};

mod directory;
pub use directory::{find_file_in_root, list_root_dir, mount_fat32};


mod files;
pub use files::{create_file, delete_file, overwrite_file, read_file};

mod lfn;
pub use lfn::{list_root_dir_lfn};

mod format;
pub use format::{format_fat32};

