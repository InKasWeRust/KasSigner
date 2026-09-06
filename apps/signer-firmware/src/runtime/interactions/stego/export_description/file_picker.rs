use crate::{
    runtime::interactions::text_files::{self, TextFileSelectionContext, TextFileSelectionWorkflow},
    runtime::data::AppData,
};

pub(super) fn handle(context: TextFileSelectionContext<'_, '_, '_>) -> bool {
    text_files::handle_selection::<256>(
        context,
        TextFileSelectionWorkflow {
            back_state: crate::runtime::navigation::continuation!(StegoJpegDescChoice),
            read_error_message: "Read failed",
        },
        accept_content,
    )
}

fn accept_content(ad: &mut AppData, content: &[u8]) -> Result<(), &'static str> {
    if content.is_empty() {
        return Err("Description required");
    }
    if content.len() > 96 {
        return Err("Description too large");
    }
    ad.stego.export_flow.jpeg_desc_buf.fill(0);
    ad.stego.export_flow.jpeg_desc_buf[..content.len()].copy_from_slice(content);
    ad.stego.export_flow.jpeg_desc_len = content.len();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoJpegDescPreview));
    Ok(())
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_accept_content(ad: &mut AppData, content: &[u8]) -> Result<(), &'static str> {
    accept_content(ad, content)
}
