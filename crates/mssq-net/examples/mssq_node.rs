//! Live MSSQ node dashboard.
//!
//! Run:
//! `cargo run -p mssq-net --example mssq_node`

use std::io;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use mssq_net::{start_node, NodeConfig, NodeSnapshot};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Terminal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = NodeConfig::default();
    let handle = start_node(cfg).await?;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let res = run_ui(&mut terminal, handle).await;
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    res
}

async fn run_ui(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    handle: mssq_net::NodeHandle,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let snap = handle.snapshot.lock().await.clone();
        terminal.draw(|f| draw_dashboard(f, &snap))?;
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') || key.code == KeyCode::Esc {
                    handle.shutdown().await;
                    break;
                }
            }
        }
    }
    Ok(())
}

fn draw_dashboard(frame: &mut ratatui::Frame<'_>, snap: &NodeSnapshot) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(4),
            Constraint::Length(4),
            Constraint::Length(6),
            Constraint::Min(6),
        ])
        .split(frame.area());

    let status = Paragraph::new(format!(
        "Network: {}\nPeerID: {}\nNAT/Public: {} / {}",
        snap.network_label,
        snap.peer_id,
        snap.nat_status,
        snap.public_addr
            .clone()
            .unwrap_or_else(|| "-".to_string())
    ))
    .block(Block::default().title("PeerID & Status").borders(Borders::ALL));
    frame.render_widget(status, chunks[0]);

    let transports = Paragraph::new(snap.active_transports.join(", "))
        .block(Block::default().title("Transports Active").borders(Borders::ALL));
    frame.render_widget(transports, chunks[1]);

    let mesh = Paragraph::new(format!(
        "Connected Peers: {}\nActive Relays: {}",
        snap.connected_peers, snap.active_relays
    ))
    .block(Block::default().title("Mesh").borders(Borders::ALL));
    frame.render_widget(mesh, chunks[2]);

    let immune_top = if snap.top_deficit_peers.is_empty() {
        "-".to_string()
    } else {
        snap.top_deficit_peers.join(" | ")
    };
    let immune = Paragraph::new(format!(
        "Global Density Avg: {}.{:03}\nCurrent T_min: {}.{:03}\nTop Deficit Peers: {}",
        snap.global_density_avg_milli / 1000,
        (snap.global_density_avg_milli.abs() % 1000),
        snap.current_t_min_milli / 1000,
        (snap.current_t_min_milli.abs() % 1000),
        immune_top
    ))
    .block(Block::default().title("Immune System").borders(Borders::ALL));
    frame.render_widget(immune, chunks[3]);

    let pulse_items: Vec<ListItem<'_>> = snap
        .pulses
        .iter()
        .map(|s| ListItem::new(s.clone()))
        .collect();
    let pulse = List::new(pulse_items).block(
        Block::default()
            .title("The Pulse (verified hardware signatures)")
            .borders(Borders::ALL),
    );
    frame.render_widget(pulse, chunks[4]);
}
