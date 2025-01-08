use thiserror::Error;

#[derive(Error, Debug)]
#[error(transparent)]
pub struct AppError(Box<ErrorKind>);

#[derive(Error, Debug)]
#[error(transparent)]
pub enum ErrorKind {
    #[error("IoError: {0}")]
    IoError(#[from] std::io::Error),
    #[error("SetMemLockLimitError: {0}")]
    SetMemLockLimitError(#[source] std::io::Error),
    #[error("BpfError: {0}")]
    BpfError(#[from] libbpf_rs::Error),
    #[error("MetricError: {0}")]
    MetricError(#[from] opentelemetry_sdk::metrics::MetricError),
    #[error("LibNotFoundError: {0}")]
    LibNotFoundError(String),
    #[error("FuncNotFoundError: {0}")]
    FuncNotFoundError(String),
    #[error("ObjectError: {0}")]
    ObjectError(#[from] object::read::Error),
    #[error("JoinError: {0}")]
    JoinError(#[from] tokio::task::JoinError),
    #[error("NixErrno: {0}")]
    NixErrno(#[from] nix::Error),
    #[error("ParseIntError: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("SerdeJsonError: {0}")]
    SerdeJsonError(#[from] serde_json::Error),
}

impl<E> From<E> for AppError
where
    ErrorKind: From<E>,
{
    fn from(err: E) -> Self {
        AppError(Box::new(ErrorKind::from(err)))
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
