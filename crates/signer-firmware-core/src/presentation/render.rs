//! Pure render models for address and wallet screens.

pub const RECEIVE_CACHE_SIZE: usize = 20;
pub const CHANGE_CACHE_SIZE: usize = 5;

#[derive(Clone, Copy)]
pub struct AddressRenderInput<'a> {
    pub receive_cache: &'a [[u8; 32]; RECEIVE_CACHE_SIZE],
    pub change_cache: &'a [[u8; 32]; CHANGE_CACHE_SIZE],
    pub extra_receive: [u8; 32],
    pub extra_receive_index: u16,
    pub extra_change: [u8; 32],
    pub extra_change_index: u16,
    pub current_index: u16,
    pub is_change: bool,
    pub raw_key: bool,
    pub partial_redraw: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressRenderModel {
    pub public_key: [u8; 32],
    pub index: Option<u16>,
    pub is_change: bool,
    pub partial_update: bool,
}

pub fn address_render_model(input: AddressRenderInput<'_>) -> Option<AddressRenderModel> {
    let public_key = select_public_key(&input)?;
    Some(AddressRenderModel {
        public_key,
        index: (!input.raw_key).then_some(input.current_index),
        is_change: input.is_change,
        partial_update: input.partial_redraw && !input.raw_key,
    })
}

pub fn select_public_key(input: &AddressRenderInput<'_>) -> Option<[u8; 32]> {
    let key = if input.is_change {
        select_branch_key(
            input.change_cache,
            input.extra_change,
            input.extra_change_index,
            input.current_index,
        )
    } else {
        select_branch_key(
            input.receive_cache,
            input.extra_receive,
            input.extra_receive_index,
            input.current_index,
        )
    }?;
    (key != [0; 32]).then_some(key)
}

fn select_branch_key<const N: usize>(
    cache: &[[u8; 32]; N],
    extra: [u8; 32],
    extra_index: u16,
    current_index: u16,
) -> Option<[u8; 32]> {
    cache
        .get(current_index as usize)
        .copied()
        .or_else(|| (extra_index == current_index).then_some(extra))
}

pub fn word_count_title(action: u8) -> &'static str {
    match action {
        0 => "New Seed",
        1 => "New Seed (Dice)",
        2 => "Import Words",
        3 => "Calc Last Word",
        4 => "BIP85 Child",
        5 => "New Seed (Touch)",
        _ => "Choose",
    }
}
