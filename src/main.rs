use chrono::Local;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use getrandom::getrandom;
use sha2::{Digest, Sha256};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Terminal,
};
use std::{
    fs::File,
    io::{self, Write},
    time::{Duration, Instant},
};

struct AppState {
    bits: Vec<u8>,
    alternate: bool,
    status_text: String,
    is_halted: bool,
    last_time_str: String,
    decimal_representation: String,
}

impl AppState {
    fn new() -> Self {
        // Securely initialize 360 bits using OS-level CSPRNG entropy
        let mut bytes = [0u8; 45]; // 45 bytes * 8 bits = 360 bits
        getrandom(&mut bytes).expect("Failed to secure random entropy from OS");

        let mut bits = Vec::with_capacity(360);
        for byte in bytes.iter() {
            for i in (0..8).rev() {
                bits.push((byte >> i) & 1);
            }
        }

        Self {
            bits,
            alternate: false,
            status_text: String::from("SECURELY INITIALIZED"),
            is_halted: false,
            last_time_str: String::from("00:00:00"),
            decimal_representation: String::new(),
        }
    }

    fn update(&mut self) {
        let now = Local::now();
        let hours = now.format("%H").to_string();
        let minutes = now.format("%M").to_string();
        let seconds = now.format("%S").to_string();
        let millis = now.format("%3f").to_string().parse::<u32>().unwrap_or(0);

        self.last_time_str = format!("{}:{}:{}", hours, minutes, seconds);

        self.alternate = !self.alternate;

        // --- CRYPTOGRAPHICALLY SECURE ENTROPY MIXING ---
        // 1. Fetch fresh cryptographic random bytes from the OS kernel
        let mut kernel_entropy = [0u8; 32];
        getrandom(&mut kernel_entropy).expect("CSPRNG entropy failure");

        // 2. Hash the kernel entropy together with high-precision time to prevent timing attacks
        let mut hasher = Sha256::new();
        hasher.update(&kernel_entropy);
        hasher.update(millis.to_le_bytes());
        hasher.update(now.timestamp_nanos_opt().unwrap_or(0).to_le_bytes());
        let secure_hash = hasher.finalize();

        // Determine halt state securely using the first byte of the SHA-256 digest
        let secure_metric = (secure_hash[0] as f64) / 255.0;
        let success = secure_metric > 0.45;
        self.is_halted = success && self.alternate;

        if self.is_halted {
            self.status_text = format!("YES (SECURE HALT @ {})", self.last_time_str);
        } else {
            self.status_text = format!("NO (SECURE LOOP @ {})", self.last_time_str);
        }

        // Mutate bits using cryptographically derived indexes
        let mutate_index = (secure_hash[1] as usize * 256 + secure_hash[2] as usize) % self.bits.len();
        self.bits[mutate_index] = if self.is_halted { 1 } else { 0 };

        // Rotate safely
        if let Some(first) = self.bits.first().copied() {
            self.bits.rotate_left(1);
            *self.bits.last_mut().unwrap() = first;
        }

        let _ = self.export_and_convert_stream();
    }

    fn export_and_convert_stream(&mut self) -> io::Result<()> {
        let mut bytes = Vec::new();
        for chunk in self.bits.chunks(8) {
            let mut byte: u8 = 0;
            for (i, &bit) in chunk.iter().enumerate() {
                if bit == 1 {
                    byte |= 1 << (7 - i);
                }
            }
            bytes.push(byte);
        }

        // Write secure binary file
        let file_path = "active_stream.bin";
        let mut file = File::create(file_path)?;
        file.write_all(&bytes)?;

        // Compute decimal representation across chunks
        let mut dec_string = String::new();
        for chunk in self.bits.chunks(64) {
            let mut val: u64 = 0;
            for &bit in chunk {
                val = val.wrapping_shl(1) | (bit as u64);
            }
            dec_string.push_str(&format!("{} ", val));
        }
        self.decimal_representation = dec_string;

        Ok(())
    }
}

fn main() -> Result<(), io::Error> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = AppState::new();
    let tick_rate = Duration::from_millis(1000);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|f| {
            let size = f.size();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Length(15),
                    Constraint::Min(4),
                    Constraint::Length(1),
                ])
                .split(size);

            let middle_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(34), Constraint::Min(45)])
                .split(chunks[1]);

            // Status header
            let status_color = if app.is_halted { Color::Green } else { Color::Red };
            let header_text = vec![Line::from(vec![
                Span::styled("STATUS: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    &app.status_text,
                    Style::default().fg(status_color).add_modifier(Modifier::BOLD),
                ),
            ])];
            let header_widget = Paragraph::new(header_text)
                .block(Block::default().borders(Borders::ALL).title(" Secure MCHP State Machine "));
            f.render_widget(header_widget, chunks[0]);

            // Clock face
            let sec_val: f64 = app.last_time_str[6..].parse().unwrap_or(0.0);
            let min_val: f64 = app.last_time_str[3..5].parse().unwrap_or(0.0);
            let hr_val: f64 = app.last_time_str[0..2].parse().unwrap_or(0.0);
            let minute_deg = min_val * 6.0 + sec_val * 0.1;
            let hour_deg = ((hr_val % 12.0) * 30.0) + (min_val * 0.5);

            let clock_art = format!(
                " .-----\"-----. \n\
                 ┌ /         \\ ┐ \n\
                 │|   (•)    |│ \n\
                 │ \\         / │ \n\
                 └  '-----.-----' \n\
                 H:{:.1}° M:{:.1}°",
                hour_deg, minute_deg
            );
            let clock_widget = Paragraph::new(clock_art)
                .block(Block::default().borders(Borders::ALL).title(" Clock "));
            f.render_widget(clock_widget, middle_chunks[0]);

            // Circle Grid
            let width = 41;
            let height = 13;
            let center_x = (width / 2) as f64;
            let center_y = (height / 2) as f64;
            let radius_x = 18.0;
            let radius_y = 5.5;
            let mut grid = vec![vec![' '; width]; height];

            for (angle_deg, &bit) in app.bits.iter().enumerate() {
                let rad = (angle_deg as f64).to_radians();
                let x = (center_x + radius_x * rad.cos()).round() as isize;
                let y = (center_y + radius_y * rad.sin()).round() as isize;

                if x >= 0 && x < width as isize && y >= 0 && y < height as isize {
                    grid[y as usize][x as usize] = if bit == 1 { '1' } else { '0' };
                }
            }

            let circle_art: String = grid
                .iter()
                .map(|row| row.iter().collect::<String>())
                .collect::<Vec<String>>()
                .join("\n");

            let circle_widget = Paragraph::new(circle_art)
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().borders(Borders::ALL).title(" Secure 360-Digit Circular Orbit Ring "));
            f.render_widget(circle_widget, middle_chunks[1]);

            // Decimal Stream View
            let decimal_widget = Paragraph::new(app.decimal_representation.clone())
                .block(Block::default().borders(Borders::ALL).title(" Secure Bin2Dec Stream "))
                .style(Style::default().fg(Color::Green))
                .wrap(Wrap { trim: true });
            f.render_widget(decimal_widget, chunks[2]);

            // Footer
            let footer = Paragraph::new(" Press [ESC] or [Q] to exit.")
                .style(Style::default().fg(Color::DarkGray));
            f.render_widget(footer, chunks[3]);
        })?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if let KeyCode::Char('q' | 'Q') | KeyCode::Esc = key.code {
                    break;
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            app.update();
            last_tick = Instant::now();
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}