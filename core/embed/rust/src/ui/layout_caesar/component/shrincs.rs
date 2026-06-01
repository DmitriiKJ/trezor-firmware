use crate::{
    strutil::TString,
    translations::TR,
    ui::{
        component::{Child, Component, Event, EventCtx, Label},
        display::Icon,
        geometry::{Alignment2D, Offset, Rect},
        shape::{self, Renderer},
    },
};

use super::{
    super::{constant, theme},
    ButtonController, ButtonControllerMsg, ButtonLayout, ButtonPos, CancelConfirmMsg,
};

pub struct ShrincsSignConfirm {
    title: Child<Label<'static>>,
    icon: Icon,
    buttons: Child<ButtonController>,
}

impl ShrincsSignConfirm {
    pub fn new(title: TString<'static>, icon: Icon) -> Self {
        let btn_layout = ButtonLayout::cancel_none_text(TR::buttons__confirm.into());
        Self {
            title: Child::new(Label::centered(title, theme::TEXT_BOLD_UPPER)),
            icon,
            buttons: Child::new(ButtonController::new(btn_layout)),
        }
    }
}

impl Component for ShrincsSignConfirm {
    type Msg = CancelConfirmMsg;

    fn place(&mut self, bounds: Rect) -> Rect {
        let (content_area, button_area) = bounds.split_bottom(theme::BUTTON_HEIGHT);
        let title_height = theme::TEXT_BOLD_UPPER.text_font.line_height();
        let (title_area, _) = content_area.split_top(title_height);
        self.title.place(title_area);
        self.buttons.place(button_area);
        bounds
    }

    fn event(&mut self, ctx: &mut EventCtx, event: Event) -> Option<Self::Msg> {
        if let Some(ButtonControllerMsg::Triggered(pos, _)) = self.buttons.event(ctx, event) {
            match pos {
                ButtonPos::Left => return Some(CancelConfirmMsg::Cancelled),
                ButtonPos::Right => return Some(CancelConfirmMsg::Confirmed),
                _ => {}
            }
        }
        None
    }

    fn render<'s>(&'s self, target: &mut impl Renderer<'s>) {
        self.title.render(target);
        // center icon in the content area (above buttons)
        let screen = constant::screen();
        let icon_center = screen.center() + Offset::y(-theme::BUTTON_HEIGHT / 2);
        shape::ToifImage::new(icon_center, self.icon.toif)
            .with_align(Alignment2D::CENTER)
            .with_fg(theme::FG)
            .render(target);
        self.buttons.render(target);
    }
}

#[cfg(feature = "ui_debug")]
impl crate::trace::Trace for ShrincsSignConfirm {
    fn trace(&self, t: &mut dyn crate::trace::Tracer) {
        t.component("ShrincsSignConfirm");
    }
}
