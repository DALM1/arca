use std::io::Read;

use indicatif::{ProgressBar, ProgressStyle};

pub fn byte_progress(label: &str, total_bytes: u64) -> ProgressBar {
    let progress = ProgressBar::new(total_bytes);
    progress.set_style(
        ProgressStyle::with_template(
            "{prefix:.bold} [{bar:40.cyan/blue}] {percent:>3}% {bytes}/{total_bytes} {bytes_per_sec} ETA {eta_precise}",
        )
        .expect("progress style")
        .progress_chars("=>-"),
    );
    progress.set_prefix(label.to_string());
    progress.enable_steady_tick(std::time::Duration::from_millis(100));
    progress
}

pub fn spinner_progress(label: &str) -> ProgressBar {
    let progress = ProgressBar::new_spinner();
    progress.set_style(
        ProgressStyle::with_template(
            "{prefix:.bold} {spinner} {bytes} {bytes_per_sec} elapsed {elapsed_precise} {msg}",
        )
            .expect("progress style"),
    );
    progress.set_prefix(label.to_string());
    progress.enable_steady_tick(std::time::Duration::from_millis(120));
    progress
}

pub fn download_progress(label: &str, total_bytes: Option<u64>) -> ProgressBar {
    let progress = match total_bytes {
        Some(total) if total > 0 => byte_progress(label, total),
        _ => spinner_progress(label),
    };

    if total_bytes.is_none() {
        progress.set_message("taille distante inconnue".to_string());
    }
    progress
}

pub struct ProgressReader<R> {
    inner: R,
    progress: ProgressBar,
}

impl<R> ProgressReader<R> {
    pub fn new(inner: R, progress: ProgressBar) -> Self {
        Self { inner, progress }
    }
}

impl<R: Read> Read for ProgressReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        if read > 0 {
            self.progress.inc(read as u64);
        }
        Ok(read)
    }
}
