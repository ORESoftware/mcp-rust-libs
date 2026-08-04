//! Bounded subprocess execution for diagnostic and build-only MCP tools.
//!
//! `std::process::Command::output` and Tokio's `wait_with_output` buffer entire
//! stdout/stderr streams before callers can truncate them. This crate instead
//! drains both pipes concurrently and kills timed-out children. Callers choose
//! between two explicit overflow policies:
//!
//! - [`run_bounded`] fails closed on the first byte beyond either stream limit;
//! - [`run_truncating`] keeps a bounded prefix, counts dropped bytes, and keeps
//!   draining both pipes so tools can return useful diagnostics without risking
//!   a pipe deadlock or an unbounded allocation.

#![forbid(unsafe_code)]

use std::{fmt, path::Path, process::ExitStatus, time::Duration};

use ore_mcp_safety::BoundedBytes;
use tokio::{io::AsyncReadExt, process::Command, time::timeout};

/// Resource limits for one subprocess invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessLimits {
    /// Wall-clock deadline for the child and both output drains.
    pub timeout: Duration,
    /// Maximum stdout bytes accepted or retained, depending on capture policy.
    pub max_stdout_bytes: usize,
    /// Maximum stderr bytes accepted or retained, depending on capture policy.
    pub max_stderr_bytes: usize,
}

impl ProcessLimits {
    /// Conservative defaults for diagnostic MCP tools.
    pub const DEFAULT: Self = Self {
        timeout: Duration::from_secs(60),
        max_stdout_bytes: 1024 * 1024,
        max_stderr_bytes: 256 * 1024,
    };

    /// Validates explicit limits.
    ///
    /// # Errors
    ///
    /// Rejects zero timeouts and output limits outside 1 KiB through 16 MiB.
    pub fn new(
        timeout: Duration,
        max_stdout_bytes: usize,
        max_stderr_bytes: usize,
    ) -> Result<Self, ProcessError> {
        const MIN: usize = 1024;
        const MAX: usize = 16 * 1024 * 1024;
        if timeout.is_zero() {
            return Err(ProcessError::InvalidLimits);
        }
        if !(MIN..=MAX).contains(&max_stdout_bytes) || !(MIN..=MAX).contains(&max_stderr_bytes) {
            return Err(ProcessError::InvalidLimits);
        }
        Ok(Self {
            timeout,
            max_stdout_bytes,
            max_stderr_bytes,
        })
    }
}

impl Default for ProcessLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Complete bounded output from one fail-fast child process.
#[derive(Debug)]
pub struct ProcessOutput {
    /// Child exit status.
    pub status: ExitStatus,
    /// Bounded raw stdout bytes.
    pub stdout: Vec<u8>,
    /// Bounded raw stderr bytes.
    pub stderr: Vec<u8>,
}

impl ProcessOutput {
    /// Returns whether the child exited successfully.
    #[must_use]
    pub fn success(&self) -> bool {
        self.status.success()
    }

    /// Converts stdout with replacement for malformed UTF-8.
    #[must_use]
    pub fn stdout_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// Converts stderr with replacement for malformed UTF-8.
    #[must_use]
    pub fn stderr_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

/// One retained stream from a truncating subprocess capture.
#[derive(Debug, Eq, PartialEq)]
pub struct TruncatedStream {
    /// Retained prefix, never larger than the configured stream limit.
    pub bytes: Vec<u8>,
    /// Number of bytes drained after the retained prefix reached its limit.
    pub dropped_bytes: usize,
}

impl TruncatedStream {
    /// Returns whether this stream exceeded its configured retained prefix.
    #[must_use]
    pub fn was_truncated(&self) -> bool {
        self.dropped_bytes > 0
    }

    /// Converts the retained prefix with replacement for malformed UTF-8.
    #[must_use]
    pub fn lossy(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }
}

/// Complete output from a child whose streams were drained with bounded prefixes.
#[derive(Debug)]
pub struct TruncatedProcessOutput {
    /// Child exit status.
    pub status: ExitStatus,
    /// Retained stdout prefix and the number of discarded stdout bytes.
    pub stdout: TruncatedStream,
    /// Retained stderr prefix and the number of discarded stderr bytes.
    pub stderr: TruncatedStream,
}

impl TruncatedProcessOutput {
    /// Returns whether the child exited successfully.
    #[must_use]
    pub fn success(&self) -> bool {
        self.status.success()
    }

    /// Converts the retained stdout prefix with replacement for malformed UTF-8.
    #[must_use]
    pub fn stdout_lossy(&self) -> String {
        self.stdout.lossy()
    }

    /// Converts the retained stderr prefix with replacement for malformed UTF-8.
    #[must_use]
    pub fn stderr_lossy(&self) -> String {
        self.stderr.lossy()
    }
}

/// Fail-closed subprocess errors. Arguments are deliberately omitted because
/// they can contain private repository paths or operator-supplied values.
#[derive(Debug)]
pub enum ProcessError {
    /// Limits were zero or outside the supported range.
    InvalidLimits,
    /// The child could not be spawned.
    Spawn(std::io::Error),
    /// A configured pipe was unexpectedly absent.
    MissingPipe(&'static str),
    /// Waiting for the child failed.
    Wait(std::io::Error),
    /// Reading one of the pipes failed.
    Read(std::io::Error),
    /// Stdout exceeded its configured limit under fail-fast capture.
    StdoutTooLarge,
    /// Stderr exceeded its configured limit under fail-fast capture.
    StderrTooLarge,
    /// The wall-clock deadline elapsed.
    TimedOut,
}

impl fmt::Display for ProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("invalid subprocess resource limits"),
            Self::Spawn(error) => write!(formatter, "failed to spawn subprocess: {error}"),
            Self::MissingPipe(pipe) => write!(formatter, "subprocess {pipe} pipe is unavailable"),
            Self::Wait(error) => write!(formatter, "failed to wait for subprocess: {error}"),
            Self::Read(error) => write!(formatter, "failed to read subprocess output: {error}"),
            Self::StdoutTooLarge => {
                formatter.write_str("subprocess stdout exceeded its byte limit")
            }
            Self::StderrTooLarge => {
                formatter.write_str("subprocess stderr exceeded its byte limit")
            }
            Self::TimedOut => formatter.write_str("subprocess exceeded its wall-clock deadline"),
        }
    }
}

impl std::error::Error for ProcessError {}

/// Runs one program directly with an argv vector and fail-fast bounded capture.
///
/// No shell is involved. On timeout or output overflow, the child is killed and
/// reaped before the error is returned.
///
/// # Errors
///
/// Returns [`ProcessError`] for invalid limits, spawn/wait/read failures,
/// output overflow, or timeout.
pub async fn run_bounded(
    current_dir: Option<&Path>,
    program: &str,
    arguments: &[&str],
    limits: ProcessLimits,
) -> Result<ProcessOutput, ProcessError> {
    validate_limits(limits)?;

    let mut child = spawn_child(current_dir, program, arguments)?;
    let stdout = child
        .stdout
        .take()
        .ok_or(ProcessError::MissingPipe("stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or(ProcessError::MissingPipe("stderr"))?;

    let operation = async {
        let wait = async { child.wait().await.map_err(ProcessError::Wait) };
        let stdout = read_pipe_bounded(
            stdout,
            limits.max_stdout_bytes,
            ProcessError::StdoutTooLarge,
        );
        let stderr = read_pipe_bounded(
            stderr,
            limits.max_stderr_bytes,
            ProcessError::StderrTooLarge,
        );
        tokio::try_join!(wait, stdout, stderr)
    };

    match timeout(limits.timeout, operation).await {
        Ok(Ok((status, stdout, stderr))) => Ok(ProcessOutput {
            status,
            stdout,
            stderr,
        }),
        Ok(Err(error)) => {
            kill_and_reap(&mut child).await;
            Err(error)
        }
        Err(_) => {
            kill_and_reap(&mut child).await;
            Err(ProcessError::TimedOut)
        }
    }
}

/// Runs one program directly while retaining bounded prefixes of both streams.
///
/// After a retained prefix reaches its configured limit, the remaining bytes
/// are counted and discarded while the pipe continues to be drained. This mode
/// is appropriate for diagnostic tools that should return a truncation marker
/// instead of failing the entire call. A timeout still kills and reaps the child.
///
/// # Errors
///
/// Returns [`ProcessError`] for invalid limits, spawn/wait/read failures, or
/// timeout. Stream overflow is represented by each [`TruncatedStream`]'s
/// `dropped_bytes` count rather than an error.
pub async fn run_truncating(
    current_dir: Option<&Path>,
    program: &str,
    arguments: &[&str],
    limits: ProcessLimits,
) -> Result<TruncatedProcessOutput, ProcessError> {
    validate_limits(limits)?;

    let mut child = spawn_child(current_dir, program, arguments)?;
    let stdout = child
        .stdout
        .take()
        .ok_or(ProcessError::MissingPipe("stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or(ProcessError::MissingPipe("stderr"))?;

    let operation = async {
        let wait = async { child.wait().await.map_err(ProcessError::Wait) };
        let stdout = read_pipe_truncating(stdout, limits.max_stdout_bytes);
        let stderr = read_pipe_truncating(stderr, limits.max_stderr_bytes);
        tokio::try_join!(wait, stdout, stderr)
    };

    match timeout(limits.timeout, operation).await {
        Ok(Ok((status, stdout, stderr))) => Ok(TruncatedProcessOutput {
            status,
            stdout,
            stderr,
        }),
        Ok(Err(error)) => {
            kill_and_reap(&mut child).await;
            Err(error)
        }
        Err(_) => {
            kill_and_reap(&mut child).await;
            Err(ProcessError::TimedOut)
        }
    }
}

fn validate_limits(limits: ProcessLimits) -> Result<(), ProcessError> {
    ProcessLimits::new(
        limits.timeout,
        limits.max_stdout_bytes,
        limits.max_stderr_bytes,
    )?;
    Ok(())
}

fn spawn_child(
    current_dir: Option<&Path>,
    program: &str,
    arguments: &[&str],
) -> Result<tokio::process::Child, ProcessError> {
    let mut command = Command::new(program);
    command
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    if let Some(directory) = current_dir {
        command.current_dir(directory);
    }
    command.spawn().map_err(ProcessError::Spawn)
}

async fn kill_and_reap(child: &mut tokio::process::Child) {
    let _ = child.kill().await;
    let _ = child.wait().await;
}

async fn read_pipe_bounded<R>(
    mut reader: R,
    max_bytes: usize,
    too_large: ProcessError,
) -> Result<Vec<u8>, ProcessError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut output = BoundedBytes::new(max_bytes).map_err(|_| ProcessError::InvalidLimits)?;
    let mut chunk = [0_u8; 8192];
    loop {
        let read = reader.read(&mut chunk).await.map_err(ProcessError::Read)?;
        if read == 0 {
            return Ok(output.into_inner());
        }
        if output.extend_from_slice(&chunk[..read]).is_err() {
            return Err(too_large);
        }
    }
}

async fn read_pipe_truncating<R>(
    mut reader: R,
    max_bytes: usize,
) -> Result<TruncatedStream, ProcessError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut bytes = Vec::with_capacity(max_bytes.min(8192));
    let mut dropped_bytes = 0usize;
    let mut chunk = [0_u8; 8192];
    loop {
        let read = reader.read(&mut chunk).await.map_err(ProcessError::Read)?;
        if read == 0 {
            return Ok(TruncatedStream {
                bytes,
                dropped_bytes,
            });
        }
        let retained = max_bytes.saturating_sub(bytes.len()).min(read);
        bytes.extend_from_slice(&chunk[..retained]);
        dropped_bytes = dropped_bytes.saturating_add(read - retained);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn captures_stdout_and_stderr_without_a_shell_in_product_code() {
        let output = run_bounded(
            None,
            "/bin/sh",
            &["-c", "printf 'hello'; printf 'warning' >&2"],
            ProcessLimits::default(),
        )
        .await
        .expect("bounded command succeeds");
        assert!(output.success());
        assert_eq!(output.stdout, b"hello");
        assert_eq!(output.stderr, b"warning");
    }

    #[tokio::test]
    async fn kills_a_child_at_the_first_stdout_byte_over_the_limit() {
        let limits = ProcessLimits::new(Duration::from_secs(5), 1024, 1024).expect("valid limits");
        let error = run_bounded(None, "/bin/sh", &["-c", "head -c 2048 /dev/zero"], limits)
            .await
            .expect_err("overflow must fail");
        assert!(matches!(error, ProcessError::StdoutTooLarge));
    }

    #[tokio::test]
    async fn truncating_capture_drains_both_streams_and_counts_dropped_bytes() {
        let limits = ProcessLimits::new(Duration::from_secs(5), 1024, 1024).expect("valid limits");
        let output = run_truncating(
            None,
            "/bin/sh",
            &[
                "-c",
                "head -c 2048 /dev/zero; head -c 3072 /dev/zero >&2",
            ],
            limits,
        )
        .await
        .expect("truncating capture succeeds");
        assert!(output.success());
        assert_eq!(output.stdout.bytes.len(), 1024);
        assert_eq!(output.stdout.dropped_bytes, 1024);
        assert_eq!(output.stderr.bytes.len(), 1024);
        assert_eq!(output.stderr.dropped_bytes, 2048);
        assert!(output.stdout.was_truncated());
        assert!(output.stderr.was_truncated());
    }

    #[tokio::test]
    async fn truncating_capture_preserves_small_streams_without_marking_them() {
        let output = run_truncating(
            None,
            "/bin/sh",
            &["-c", "printf 'hello'; printf 'warning' >&2"],
            ProcessLimits::default(),
        )
        .await
        .expect("truncating capture succeeds");
        assert_eq!(output.stdout.lossy(), "hello");
        assert_eq!(output.stderr.lossy(), "warning");
        assert!(!output.stdout.was_truncated());
        assert!(!output.stderr.was_truncated());
    }

    #[tokio::test]
    async fn kills_a_timed_out_child() {
        let limits =
            ProcessLimits::new(Duration::from_millis(50), 1024, 1024).expect("valid limits");
        let error = run_bounded(None, "/bin/sh", &["-c", "sleep 2"], limits)
            .await
            .expect_err("timeout must fail");
        assert!(matches!(error, ProcessError::TimedOut));

        let error = run_truncating(None, "/bin/sh", &["-c", "sleep 2"], limits)
            .await
            .expect_err("truncating timeout must fail");
        assert!(matches!(error, ProcessError::TimedOut));
    }
}
