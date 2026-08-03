//! Bounded subprocess execution for diagnostic and build-only MCP tools.
//!
//! `std::process::Command::output` and Tokio's `wait_with_output` buffer entire
//! stdout/stderr streams before callers can truncate them. This crate instead
//! drains both pipes concurrently, aborts on the first byte beyond each bound,
//! and kills timed-out or over-producing children.

#![forbid(unsafe_code)]

use std::{fmt, path::Path, process::ExitStatus, time::Duration};

use ore_mcp_safety::BoundedBytes;
use tokio::{io::AsyncReadExt, process::Command, time::timeout};

/// Resource limits for one subprocess invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessLimits {
    /// Wall-clock deadline for the child and both output drains.
    pub timeout: Duration,
    /// Maximum stdout bytes accepted before the child is terminated.
    pub max_stdout_bytes: usize,
    /// Maximum stderr bytes accepted before the child is terminated.
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
        if !(MIN..=MAX).contains(&max_stdout_bytes)
            || !(MIN..=MAX).contains(&max_stderr_bytes)
        {
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

/// Complete bounded output from one child process.
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
    /// Stdout exceeded its configured limit.
    StdoutTooLarge,
    /// Stderr exceeded its configured limit.
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
            Self::StdoutTooLarge => formatter.write_str("subprocess stdout exceeded its byte limit"),
            Self::StderrTooLarge => formatter.write_str("subprocess stderr exceeded its byte limit"),
            Self::TimedOut => formatter.write_str("subprocess exceeded its wall-clock deadline"),
        }
    }
}

impl std::error::Error for ProcessError {}

/// Runs one program directly with an argv vector and bounded output capture.
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
    ProcessLimits::new(
        limits.timeout,
        limits.max_stdout_bytes,
        limits.max_stderr_bytes,
    )?;

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

    let mut child = command.spawn().map_err(ProcessError::Spawn)?;
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
        let stdout = read_pipe(stdout, limits.max_stdout_bytes, ProcessError::StdoutTooLarge);
        let stderr = read_pipe(stderr, limits.max_stderr_bytes, ProcessError::StderrTooLarge);
        tokio::try_join!(wait, stdout, stderr)
    };

    match timeout(limits.timeout, operation).await {
        Ok(Ok((status, stdout, stderr))) => Ok(ProcessOutput {
            status,
            stdout,
            stderr,
        }),
        Ok(Err(error)) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(error)
        }
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(ProcessError::TimedOut)
        }
    }
}

async fn read_pipe<R>(
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
        let limits = ProcessLimits::new(Duration::from_secs(5), 1024, 1024)
            .expect("valid limits");
        let error = run_bounded(
            None,
            "/bin/sh",
            &["-c", "head -c 2048 /dev/zero"],
            limits,
        )
        .await
        .expect_err("overflow must fail");
        assert!(matches!(error, ProcessError::StdoutTooLarge));
    }

    #[tokio::test]
    async fn kills_a_timed_out_child() {
        let limits = ProcessLimits::new(Duration::from_millis(50), 1024, 1024)
            .expect("valid limits");
        let error = run_bounded(None, "/bin/sh", &["-c", "sleep 2"], limits)
            .await
            .expect_err("timeout must fail");
        assert!(matches!(error, ProcessError::TimedOut));
    }
}
