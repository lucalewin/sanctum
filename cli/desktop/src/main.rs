use cli::{
    crypto::VaultKeys,
    login,
    record::{Entry, list_records},
    vault::{create_vault, list_vaults},
};
use gpui::{
    App, Application, Bounds, Context, ElementId, Entity, FontWeight, SharedString, Size,
    UpdateGlobal, Window, WindowBounds, WindowOptions, auto, div, prelude::*, px, rgb, size,
};
use gpui_component::{
    ActiveTheme, Root, Theme, WindowExt,
    button::{Button, ButtonVariants},
    clipboard::Clipboard,
    input::{Input, InputState},
    v_flex,
};

struct HelloWorld {
    conn: rusqlite::Connection,
    keys: VaultKeys,
    vaults: Vec<cli::vault::EncryptedVault>,
    items: Vec<cli::record::Item>,
    selected_vault_id: Option<usize>,
    selected_item_id: Option<usize>,
    new_vault_name: Entity<InputState>,
}

impl Render for HelloWorld {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let dialog_layer = Root::render_dialog_layer(window, cx);

        div()
            .flex()
            // .gap_3()
            .w_full()
            .h_full()
            // left sidebar with vaults
            .child(self.vault_sidebar(cx))
            // middle item list
            .child(self.item_list(cx))
            // right item details
            .when(self.selected_item_id.is_some(), |container| {
                let item = &&self.items.get(self.selected_item_id.unwrap()).unwrap();
                let Entry::Password {
                    ref title,
                    ref username,
                    ref password,
                    ref url,
                } = item.data;

                let a = cx.new(|cx| InputState::new(window, cx).default_value(username));
                let b = cx.new(|cx| InputState::new(window, cx).default_value(password));
                let c = cx.new(|cx| InputState::new(window, cx).default_value(url));

                container.child(
                    div()
                        .flex_1()
                        .h_full()
                        .flex()
                        .flex_col()
                        .p_6()
                        .gap_4()
                        .child(
                            div()
                                .text_xl()
                                .font_weight(FontWeight::BOLD)
                                .child(title.clone()),
                        )
                        .child(detail_row("Username".to_string(), a))
                        .child(detail_row("Password".to_string(), b))
                        .child(detail_row("Website".to_string(), c)),
                )
            })
            .when(self.selected_item_id.is_none(), |container| {
                container.child("Select an item to view details")
            })
            .children(dialog_layer)
    }
}

fn detail_row(label: String, value: Entity<InputState>) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .child(
            div()
                .text_sm()
                .text_color(rgb(0x888888))
                .child(label.clone()),
        )
        .child(
            div()
                .p_3()
                .rounded_md()
                .flex()
                .border_1()
                .border_color(rgb(0xcccccc))
                .child(Input::new(&value).suffix(
                    Clipboard::new(ElementId::Name(SharedString::from(label))).value_fn({
                        let state = value.clone();
                        move |_, cx| state.read(cx).value()
                    }),
                )),
        )
}

impl HelloWorld {
    fn switch_vault(&mut self, vault_id: usize, cx: &mut Context<Self>) {
        self.selected_vault_id = Some(vault_id);
        let id = self.vaults[vault_id].decrypt_name(&self.keys).unwrap();
        self.items = list_records(&self.conn, &id, &self.keys).unwrap();
        self.selected_item_id = None;
        cx.notify();
    }

    fn select_item(&mut self, item_id: usize, cx: &mut Context<Self>) {
        println!("Selected item id: {}", item_id);
        self.selected_item_id = Some(item_id);
        cx.notify();
    }

    fn vault_sidebar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .w(px(220.0))
            .p_3()
            .h_full()
            .flex()
            .flex_col()
            .border_r_1()
            .border_color(rgb(0xaaaaaa))
            .child(
                div()
                    .text_lg()
                    .font_weight(FontWeight::BOLD)
                    .child("Vaults"),
            )
            .children(self.vaults.iter().enumerate().map(|(idx, vault)| {
                let is_selected = self.selected_vault_id.unwrap_or(0) == idx;
                let vault_id = idx.clone();
                let name = vault.decrypt_name(&self.keys).unwrap();

                div()
                    .id(vault.id)
                    .mb_1()
                    .px_3()
                    .py_2()
                    .rounded_md()
                    .bg(if is_selected {
                        rgb(0xcccccc)
                    } else {
                        rgb(0xeeeeee)
                    })
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.switch_vault(vault_id, cx);
                    }))
                    .child(name)
            }))
            .child(div().flex_1())
            .child(
                Button::new("create-vault")
                    .primary()
                    .w_full()
                    .child("Create Vault")
                    .on_click(cx.listener(|this, _, window, cx| {
                        // let input = cx.new(|cx| InputState::new(window, cx));
                        let input = this.new_vault_name.clone();

                        window.open_dialog(cx, move |dialog, _, cx| {
                            dialog
                                .title("Create a new vault")
                                .child(
                                    v_flex()
                                        .gap_3()
                                        .child("Vault Name:")
                                        .child(Input::new(&input)),
                                )
                                .child(div().h_10())
                                .footer(|_, _, _, _| {
                                    vec![
                                        Button::new("ok").primary().label("Create").on_click(
                                            |_, window, cx| {
                                                // let t = input.read(cx).value().to_string();
                                                // create_vault(&this.conn, &t, &this.keys).unwrap();

                                                window.close_dialog(cx);
                                            },
                                        ),
                                        Button::new("cancel").label("Cancel").on_click(
                                            |_, window, cx| {
                                                window.close_dialog(cx);
                                            },
                                        ),
                                    ]
                                })
                        })
                    })),
            )
    }

    fn item_list(&self, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .w(px(320.))
            .p_3()
            .h_full()
            .border_r_1()
            .border_color(rgb(0x3c3c3c))
            .flex()
            .flex_col()
            .child(div().text_lg().font_weight(FontWeight::BOLD).child("Items"))
            .children(self.items.iter().enumerate().map(|(i, item)| {
                let is_selected = i == self.selected_item_id.unwrap_or(0);

                let Entry::Password {
                    ref title,
                    ref username,
                    ..
                } = item.data;

                div()
                    .id(item.id)
                    // .mx_2()
                    .mb_1()
                    .p_3()
                    .rounded_md()
                    .bg(if is_selected {
                        rgb(0xcccccc)
                    } else {
                        rgb(0xeeeeee)
                    })
                    .child(div().child(title.clone()))
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(0x555555))
                            .child(username.clone()),
                    )
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.select_item(i, cx);
                    }))
            }))
            .child(div().flex_1())
            .child(
                Button::new("create-item")
                    .primary()
                    .w_full()
                    .child("Create Item"),
            )
    }
}

fn main() {
    Application::new().run(move |cx| {
        // This must be called before using any GPUI Component features.
        gpui_component::init(cx);

        cx.spawn(async move |cx| {
            cx.open_window(WindowOptions::default(), |window, cx| {
                let view = cx.new(|cx| {
                    let (conn, keys) = login();
                    let vaults = list_vaults(&conn).unwrap();
                    let s = vaults.first().unwrap().decrypt_name(&keys).unwrap();
                    let items = list_records(&conn, &s, &keys).unwrap();
                    HelloWorld {
                        conn,
                        keys,
                        vaults,
                        items,
                        selected_vault_id: None,
                        selected_item_id: None,
                        new_vault_name: cx.new(|cx| InputState::new(window, cx)),
                    }
                });
                // This first level on the window, should be a Root.
                cx.new(|cx| Root::new(view, window, cx))
            })
            .expect("Failed to open window");
        })
        .detach();
    });
}
