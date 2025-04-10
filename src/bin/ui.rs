use ratatui::prelude::*;
use ratatui::widgets::*;
use crate::network::get_network_interfaces;

pub fn draw_ui(f: &mut Frame) {
    let size = f.size(); // Get the terminal screen size

    // Retrieve the list of network interfaces
    let interfaces = get_network_interfaces();

    // Convert each interface into a table row
    let rows: Vec<Row> = interfaces.iter().map(|iface| {
        Row::new(vec![
            iface.name.clone(),
            iface.ip_address.clone(),
            iface.mac_address.clone(),
            iface.status.clone(),
        ])
    }).collect();

    // Build the table with headers and layout constraints
    let table = Table::new(rows)
        .header(Row::new(vec![
            "Interface", 
            "IP Address", 
            "MAC Address", 
            "Status"
        ]))
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().title("Network Interfaces").borders(Borders::ALL))
        .widths(&[Constraint::Length(15), Constraint::Length(20), Constraint::Length(20), Constraint::Length(10)]);

    f.render_widget(table, size); // Render the table to the terminal
}
